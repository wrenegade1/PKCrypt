"""PKCrypt command line interface.

Author: Warren Zajac

Two logical apps in one command:

  * ``pkcrypt encrypt <recipient.pub> <file>``  -- anything, run anywhere, needs
    only the recipient's PUBLIC key.
  * ``pkcrypt decrypt <private.key> <file.pkcrypt>``  -- runs on the recipient's
    machine with their PRIVATE key.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tempfile
import zipfile

from cryptography.exceptions import InvalidTag

from . import __version__
from . import archive, core, files, keys

# Exit codes (the same in the C++ binary).
EXIT_OK = 0
EXIT_FAILURE = 1        # runtime/security error: nothing was produced
EXIT_USAGE = 2          # bad arguments, or an unusable key file
EXIT_PARTIAL = 3        # --salvage recovered only part of the input


def _display_safe(text) -> str:
    """Make a string safe to print to a terminal: escape C0 control bytes and
    DEL as \\xHH (so a crafted archive filename can't inject terminal escape
    sequences), leaving printable and UTF-8 bytes intact, and neutralize any
    un-encodable/surrogate-escaped bytes so print() cannot raise."""
    out = "".join(c if (0x20 <= ord(c) != 0x7F) else f"\\x{ord(c):02x}"
                  for c in str(text))
    enc = sys.stdout.encoding or "utf-8"
    return out.encode(enc, "backslashreplace").decode(enc, "replace")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkcrypt",
        description=(
            "Encrypt files so only the holder of an Ed25519 SSH private key can "
            "decrypt them (public/private key model, like SSH)."
        ),
        epilog=(
            "examples:\n"
            "  pkcrypt encrypt alice_id_ed25519.pub secret.tgz\n"
            "         -> secret.tgz.pkcrypt   (needs only alice's PUBLIC key)\n"
            "  pkcrypt decrypt ~/.ssh/id_ed25519 secret.tgz.pkcrypt\n"
            "         -> secret.tgz           (run on alice's Mac with her PRIVATE key)\n"
            "  pkcrypt encrypt alice_id_ed25519.pub photos/\n"
            "         -> photos.pkcrypt       (a folder is zipped, then encrypted)\n"
            "  pkcrypt decrypt ~/.ssh/id_ed25519 photos.pkcrypt\n"
            "         -> photos/              (and recreated as a folder)\n"
            "\n"
            "exit status: 0 success, 1 failed (nothing written), 2 usage or key\n"
            "error, 3 partial result (decrypt --salvage)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"pkcrypt {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a file or folder for a recipient")
    enc.add_argument("recipient_public_key",
                     help="recipient's OpenSSH public key (id_ed25519.pub)")
    enc.add_argument("input_file", help="file or folder to encrypt")
    enc.add_argument("output_file", nargs="?", default=None,
                     help="output path (default: <input>.pkcrypt)")

    dec = sub.add_parser("decrypt", help="decrypt a file with your private key")
    dec.add_argument("private_key",
                     help="your OpenSSH private key (~/.ssh/id_ed25519)")
    dec.add_argument("input_file", help="the .pkcrypt file to decrypt")
    dec.add_argument("output_file", nargs="?", default=None,
                     help="output path (default: strips .pkcrypt)")
    dec.add_argument("--passphrase", action="store_true",
                     help="prompt for the private key passphrase")
    dec.add_argument("--salvage", action="store_true",
                     help="recover what still verifies from a damaged file (every "
                          "intact file of a folder, or the verified start of a "
                          "file) instead of refusing it; a partial result goes to "
                          "<name>.partial and exits with status 3")
    return parser


def cmd_encrypt(args) -> int:
    recipient_pub = keys.load_public_key(args.recipient_public_key)
    rsa_pub = recipient_pub.key if recipient_pub.type == "rsa" else None
    pub_bytes = None if rsa_pub else recipient_pub.key.public_bytes_raw()

    is_dir = os.path.isdir(args.input_file)
    if is_dir and not args.output_file and not archive.has_usable_name(args.input_file):
        print(f"error: give an output path when encrypting {args.input_file!r}",
              file=sys.stderr)
        return EXIT_USAGE
    out_path = args.output_file or files.encrypted_output_path(args.input_file)
    stats = archive.ArchiveStats()
    # Stream chunk-by-chunk so large inputs never load into memory. A folder
    # is zipped straight into the encryptor; no plaintext archive touches disk.
    with files.AtomicOutput(out_path) as out:
        if is_dir:
            writer = (core.RSAStreamEncryptor(out.write, rsa_pub,
                                              payload_type=core.PAYLOAD_ARCHIVE)
                      if rsa_pub else
                      core.StreamEncryptor(out.write, pub_bytes,
                                           payload_type=core.PAYLOAD_ARCHIVE))
            try:
                archive.pack_directory(args.input_file, writer, stats)
                writer.close()
            finally:
                writer.abort()
        else:
            with open(args.input_file, "rb") as src:
                iterable = (core.encrypt_stream_rsa(src, rsa_pub) if rsa_pub
                            else core.encrypt_stream(src, pub_bytes))
                for piece in iterable:
                    out.write(piece)
    container_size = os.path.getsize(out_path)

    for path in stats.skipped:
        print(f"warning: skipped {_display_safe(path)} (symbolic link or special file)",
              file=sys.stderr)
    print(f"Encrypted {args.input_file} -> {out_path}")
    print(f"  recipient : {args.recipient_public_key}")
    if is_dir:
        print(f"  contents  : {stats.files} files, {stats.directories} folders, "
              f"{stats.bytes} bytes before compression")
    print(f"  size      : {container_size} bytes")
    print(f"Send {out_path} to the recipient. Only they can decrypt it.")
    return 0


def cmd_decrypt(args) -> int:
    password = None
    if args.passphrase:
        password = getpass.getpass("Private key passphrase: ").encode()
    private_key = keys.load_private_key(args.private_key, password=password)

    out_path = args.output_file or files.decrypted_output_path(args.input_file)
    # Where a partial (salvaged) result goes: never the real name by default.
    partial_path = args.output_file or files.unused_path(
        (out_path.rstrip("/") or out_path) + ".partial")

    with open(args.input_file, "rb") as src:
        kind = core.peek_container_kind(src)
        # A stream decryptor for this container + key (yields plaintext chunks,
        # with optional salvage). Matches the container scheme to the key type.
        if kind == "rsa":
            if private_key.type != "rsa":
                raise keys.KeyError_(
                    f"this file is RSA-encrypted; the key provided is "
                    f"{private_key.type} - supply the matching RSA private key")
            ds = lambda s, sv=False: core.decrypt_stream_rsa(s, private_key.key, salvage=sv)
        elif kind == "ed25519":
            if private_key.type != "ed25519":
                raise keys.KeyError_(
                    f"this file is Ed25519-encrypted; the key provided is "
                    f"{private_key.type} - supply the matching Ed25519 private key")
            seed = private_key.key.private_bytes_raw()
            public = private_key.key.public_key().public_bytes_raw()
            ds = lambda s, sv=False: core.decrypt_stream(s, seed, public, salvage=sv)
        else:
            raise ValueError("not a PKCrypt file (bad header)")

        if core.peek_payload_type(src) == core.PAYLOAD_ARCHIVE:
            return _decrypt_folder(args.input_file, src, ds, out_path,
                                   args.salvage, partial_path)
        if args.salvage:
            return _salvage_file(args.input_file, src, ds, out_path, partial_path)
        # Stream the container chunk-by-chunk so large files never load into memory.
        with files.AtomicOutput(out_path) as out:
            for piece in ds(src):
                out.write(piece)
    plaintext_size = os.path.getsize(out_path)
    print(f"Decrypted {args.input_file} -> {out_path}")
    print(f"  size: {plaintext_size} bytes")
    return EXIT_OK


def _decrypt_error(exc: Exception) -> str:
    return core.DECRYPT_FAILED if isinstance(exc, InvalidTag) else str(exc)


def _salvage_file(in_path: str, src, ds, out_path: str, partial_path: str) -> int:
    """Decrypt a single file, publishing its verified start as a partial
    result if the rest fails to verify."""
    out = files.AtomicOutput(out_path)
    written = 0
    try:
        for piece in ds(src, sv=True):
            out.write(piece)
            written += len(piece)
    except (InvalidTag, ValueError) as exc:
        if not written:
            out.abort()
            raise
        out.retarget(partial_path)
        out.close()
        print(f"Salvaged {in_path} -> {partial_path}")
        print(f"  recovered: the first {written} bytes (verified)")
        print(f"warning: the rest of the file is lost: {_display_safe(_decrypt_error(exc))}\n"
              "warning: this is a PARTIAL result", file=sys.stderr)
        return EXIT_PARTIAL
    except BaseException:
        out.abort()
        raise
    out.close()
    print(f"Decrypted {in_path} -> {out_path}")
    print(f"  size: {written} bytes")
    return EXIT_OK


def _decrypt_folder(in_path: str, src, ds, out_path: str,
                    salvage: bool = False, partial_path: str = "") -> int:
    """Decrypt an archive container and recreate the folder at ``out_path``.

    ZIP needs random access (its index is at the end), so the decrypted archive
    goes to a private 0600 temp file beside the destination, which is always
    removed afterwards. Nothing is extracted unless every chunk verified -
    or, with ``salvage``, whatever verified is recovered as a partial result.
    """
    if os.path.lexists(out_path):
        raise FileExistsError(f"refusing to overwrite existing path: {out_path}")
    parent = os.path.dirname(os.path.abspath(out_path))
    fd, tmp_zip = tempfile.mkstemp(prefix=".pkcrypt-", suffix=".zip", dir=parent)
    try:
        failure = None
        with os.fdopen(fd, "wb") as tmp:
            try:
                for piece in ds(src, sv=salvage):
                    tmp.write(piece)
            except (InvalidTag, ValueError) as exc:
                if not salvage:
                    raise
                failure = exc
            salvaged_bytes = tmp.tell()
        if not salvage:
            stats = archive.ArchiveStats()
            archive.extract_archive(tmp_zip, out_path, stats)
            print(f"Decrypted {in_path} -> {out_path}/")
            print(f"  contents: {stats.files} files, {stats.directories} folders, "
                  f"{stats.bytes} bytes")
            return EXIT_OK
        if failure is not None and not salvaged_bytes:
            raise failure                       # nothing authenticated to salvage
        report = archive.salvage_archive(tmp_zip, failure is None, out_path, partial_path)
    finally:
        os.unlink(tmp_zip)
    _print_salvage_report(in_path, out_path if report.complete else partial_path, report,
                          "" if failure is None else _decrypt_error(failure))
    return EXIT_OK if report.complete else EXIT_PARTIAL


def _print_salvage_report(in_path: str, dest: str, report: archive.SalvageReport,
                          decrypt_error: str) -> None:
    """What --salvage recovered and lost, in the same format as the C++ CLI."""
    s = report.stats
    if report.complete:
        print(f"Decrypted {in_path} -> {dest}/")
        print(f"  contents: {s.files} files, {s.directories} folders, {s.bytes} bytes")
        return
    print(f"Salvaged {in_path} -> {dest}/")
    print(f"  recovered: {s.files} files, {s.directories} folders, {s.bytes} bytes")
    if not report.verified_whole:
        print(f"warning: the encrypted file is damaged: {_display_safe(decrypt_error)}", file=sys.stderr)
    for name, why in report.lost:
        # Most reasons already start with the name.
        why = why[len(name) + 2:] if why.startswith(f"{name}: ") else why
        print(f"lost: {_display_safe(name)} ({_display_safe(why)})", file=sys.stderr)
    if report.tail_problem:
        print(f"lost: everything after that point ({_display_safe(report.tail_problem)})", file=sys.stderr)
    print("warning: this is a PARTIAL result", file=sys.stderr)


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "encrypt":
            return cmd_encrypt(args)
        if args.command == "decrypt":
            return cmd_decrypt(args)
    except keys.KeyError_ as exc:
        print(f"error: {_display_safe(exc)}", file=sys.stderr)
        return EXIT_USAGE
    except InvalidTag:
        print(f"error: {core.DECRYPT_FAILED}", file=sys.stderr)
        return EXIT_FAILURE
    except ValueError as exc:
        print(f"error: {_display_safe(exc)}", file=sys.stderr)
        return EXIT_FAILURE
    except zipfile.BadZipFile as exc:
        print(f"error: corrupt archive: {_display_safe(exc)}", file=sys.stderr)
        return EXIT_FAILURE
    except OSError as exc:
        print(f"error: {_display_safe(exc)}", file=sys.stderr)
        return EXIT_FAILURE
    parser.error(f"unknown command: {args.command}")
    return EXIT_USAGE  # unreachable


if __name__ == "__main__":
    sys.exit(main())

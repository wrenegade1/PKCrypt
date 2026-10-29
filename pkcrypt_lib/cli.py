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
import sys

from cryptography.exceptions import InvalidTag

from . import __version__
from . import core, files, keys


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
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"pkcrypt {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a file for a recipient")
    enc.add_argument("recipient_public_key",
                     help="recipient's OpenSSH public key (id_ed25519.pub)")
    enc.add_argument("input_file", help="file to encrypt")
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
    return parser


def cmd_encrypt(args) -> int:
    recipient_pub = keys.load_public_key(args.recipient_public_key)
    pub_bytes = recipient_pub.public_bytes_raw()
    plaintext = files.read_bytes(args.input_file)
    container = core.encrypt_bytes(plaintext, pub_bytes)
    del plaintext

    out_path = args.output_file or files.encrypted_output_path(args.input_file)
    files.write_bytes(out_path, container)

    print(f"Encrypted {args.input_file} -> {out_path}")
    print(f"  recipient : {args.recipient_public_key}")
    print(f"  size      : {len(container)} bytes")
    print(f"Send {out_path} to the recipient. Only they can decrypt it.")
    return 0


def cmd_decrypt(args) -> int:
    password = None
    if args.passphrase:
        password = getpass.getpass("Private key passphrase: ").encode()
    private_key = keys.load_private_key(args.private_key, password=password)

    seed = private_key.private_bytes_raw()
    public = private_key.public_key().public_bytes_raw()

    container = files.read_bytes(args.input_file)
    plaintext = core.decrypt_bytes(container, seed, public)
    del container, seed

    out_path = args.output_file or files.decrypted_output_path(args.input_file)
    files.write_bytes(out_path, plaintext)
    print(f"Decrypted {args.input_file} -> {out_path}")
    print(f"  size: {len(plaintext)} bytes")
    return 0


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "encrypt":
            return cmd_encrypt(args)
        if args.command == "decrypt":
            return cmd_decrypt(args)
    except keys.KeyError_ as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except InvalidTag:
        print(
            "error: decryption failed - the file is not for this private key, "
            "or the file was tampered with.",
            file=sys.stderr,
        )
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError,) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command: {args.command}")
    return 2  # unreachable


if __name__ == "__main__":
    sys.exit(main())

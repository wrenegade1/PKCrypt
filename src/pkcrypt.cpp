//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pkcrypt/version.h"
#include "pkcrypt/ssh_key.h"
#include "pkcrypt/crypto.h"
#include "pkcrypt/fileio.h"
#include "pkcrypt/archive.h"

using namespace pkcrypt;

namespace {

// Exit codes (the same in the Python CLI). Not EXIT_*: <cstdlib> defines
// EXIT_SUCCESS/EXIT_FAILURE as macros.
constexpr int RC_OK = 0;
constexpr int RC_FAILURE = 1;       // runtime/security error: nothing was produced
constexpr int RC_USAGE = 2;         // bad arguments, or an unusable key file
constexpr int RC_PARTIAL = 3;       // --salvage recovered only part of the input

void usage(const char* prog) {
    std::cout
        << "PKCrypt " << PKCRYPT_VERSION_STRING
        << " - encrypt files so that only the holder of a private key can decrypt them.\n\n"
        << "Uses the holder's existing Ed25519 SSH keypair (~/.ssh/id_ed25519).\n\n"
        << "USAGE\n"
        << "  " << prog << " encrypt <recipient_pubkey> <file|folder> [out.pkcrypt]\n"
        << "  " << prog << " decrypt [--salvage] <private_key> <file.pkcrypt> [out]\n"
        << "  " << prog << " decrypt --passphrase [--salvage] <private_key> <file.pkcrypt> [out]\n"
        << "  " << prog << " version\n\n"
        << "EXAMPLES\n"
        << "  # Encrypt a file for someone using only their public key:\n"
        << "  " << prog << " encrypt alice_id_ed25519.pub secrets.tgz\n\n"
        << "  # Alice decrypts it on her Mac using her private key:\n"
        << "  " << prog << " decrypt ~/.ssh/id_ed25519 secrets.tgz.pkcrypt\n\n"
        << "  # A whole folder: compressed (ZIP) and encrypted into one file,\n"
        << "  # and recreated as a folder when decrypted:\n"
        << "  " << prog << " encrypt alice_id_ed25519.pub photos/\n"
        << "  " << prog << " decrypt ~/.ssh/id_ed25519 photos.pkcrypt\n\n"
        << "SALVAGE\n"
        << "  decrypt --salvage recovers what it can from a damaged file instead of\n"
        << "  refusing it: every file inside that still verifies, or the verified\n"
        << "  start of a single file. Only authenticated data is ever written. A\n"
        << "  partial result goes to <name>.partial (unless an output path is given)\n"
        << "  and exits with status 3.\n\n"
        << "EXIT STATUS\n"
        << "  0 success   1 failed (nothing written)   2 usage or key error\n"
        << "  3 partial result (--salvage)\n\n"
        << "NOTES\n"
        << "  - Passphrase-protected private keys are supported: pass --passphrase to be\n"
        << "    prompted for the passphrase at a terminal (the passphrase is never echoed\n"
        << "    and never stored). Without it, an unencrypted key is used as-is.\n"
        << "  - For a passphrase-protected key with the Python CLI:\n"
        << "        python3 -m pkcrypt_lib decrypt --passphrase <key> <file>\n"
        << "    Do not empty your key's passphrase just to use either tool.\n"
        << "  - Encrypting needs only the recipient's PUBLIC key. No secret\n"
        << "    material ever leaves your machine when encrypting.\n";
}

std::string strip_slashes(std::string path) {
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    return path;
}

// What --salvage recovered and lost, in the same format as the Python CLI.
void print_salvage_report(const std::string& in_path, const std::string& dest,
                          const SalvageReport& r, const std::string& decrypt_error) {
    if (r.complete()) {
        std::cout << "Decrypted " << in_path << " -> " << dest << "/\n"
                  << "  contents: " << r.stats.files << " files, " << r.stats.directories
                  << " folders, " << r.stats.bytes << " bytes\n";
        return;
    }
    std::cout << "Salvaged " << in_path << " -> " << dest << "/\n"
              << "  recovered: " << r.stats.files << " files, " << r.stats.directories
              << " folders, " << r.stats.bytes << " bytes\n";
    if (!r.verified_whole) {
        std::cerr << "warning: the encrypted file is damaged: " << display_safe(decrypt_error) << "\n";
    }
    for (const auto& [name, why] : r.lost) {
        // Most reasons already start with the name.
        const std::string prefix = name + ": ";
        const bool repeats = why.compare(0, prefix.size(), prefix) == 0;
        std::cerr << "lost: " << display_safe(name) << " ("
                  << display_safe(repeats ? why.substr(prefix.size()) : why) << ")\n";
    }
    if (!r.tail_problem.empty()) {
        std::cerr << "lost: everything after that point (" << display_safe(r.tail_problem) << ")\n";
    }
    std::cerr << "warning: this is a PARTIAL result\n";
}

// Stream the file at `path` into `out` in 1 MiB pieces.
bool stream_file(const std::string& path, ByteSink& out, std::string& error) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        error = "cannot open file: " + path;
        return false;
    }
    FdSource src(fd);
    std::vector<unsigned char> buf(1024 * 1024);
    bool ok = true;
    for (;;) {
        long long n = src.read(buf.data(), buf.size(), error);
        if (n <= 0) {
            ok = n == 0;
            break;
        }
        if (!(ok = out.write(buf.data(), static_cast<size_t>(n), error))) break;
    }
    sodium_memzero(buf.data(), buf.size());
    ::close(fd);
    return ok;
}

// A folder path whose last component can name the output (not "", ".", "..").
bool has_usable_name(std::string path) {
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    std::string::size_type slash = path.find_last_of('/');
    std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    return !name.empty() && name != "." && name != "..";
}

// The first whitespace-delimited token of a file (OpenSSH key type, e.g.
// "ssh-ed25519" or "ssh-rsa"); "" if the file can't be read.
std::string first_token(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string tok;
    f >> tok;
    return tok;
}

// Container scheme implied by a file's 8-byte magic: "ed25519", "rsa", or "".
std::string container_kind_of(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    char magic[8] = {0};
    f.read(magic, 8);
    if (f.gcount() < 8) return "";
    if (std::memcmp(magic, "PKCRYPT\x02", 8) == 0) return "ed25519";
    if (std::memcmp(magic, "PKCRYPT\x03", 8) == 0) return "rsa";
    return "";
}

int cmd_encrypt(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "usage: pkcrypt encrypt <recipient_pubkey> <file|folder> [out.pkcrypt]\n";
        return RC_USAGE;
    }
    std::string pub_path = args[0], in_path = args[1];
    struct stat in_st;
    const bool is_dir = ::stat(in_path.c_str(), &in_st) == 0 && S_ISDIR(in_st.st_mode);
    if (is_dir && args.size() < 3 && !has_usable_name(in_path)) {
        std::cerr << "error: give an output path when encrypting '" << in_path << "'\n";
        return RC_USAGE;
    }
    std::string out_path = args.size() >= 3 ? args[2] : encrypted_output_path(in_path);

    // Sniff the recipient key type from the first whitespace token.
    std::string type = first_token(pub_path);
    const bool rsa = (type == "ssh-rsa");

    std::string error;
    AtomicFile out;
    ArchiveStats stats;
    bool ok = out.open(out_path, error);

    if (rsa) {
        auto key = parse_ssh_rsa_public_key_file(pub_path, error);
        if (!key) { std::cerr << "error: " << display_safe(error) << "\n"; return RC_USAGE; }
        RSAStreamEncryptor enc;
        ok = ok && enc.begin(out, key->n.data(), key->n.size(), key->e.data(), key->e.size(),
                             key->modulus_bytes(), is_dir ? PAYLOAD_ARCHIVE : PAYLOAD_FILE,
                             error);
        if (ok && is_dir) ok = pack_directory(in_path, enc, stats, error);
        else if (ok) ok = stream_file(in_path, enc, error);
        ok = ok && enc.finish(error) && out.commit(error);
    } else {
        auto key = parse_ssh_public_key_file(pub_path, error);
        if (!key) { std::cerr << "error: " << display_safe(error) << "\n"; return RC_USAGE; }
        StreamEncryptor enc;
        ok = ok && enc.begin(out, key->public_key, is_dir ? PAYLOAD_ARCHIVE : PAYLOAD_FILE, error);
        if (ok && is_dir) ok = pack_directory(in_path, enc, stats, error);
        else if (ok) ok = stream_file(in_path, enc, error);
        ok = ok && enc.finish(error) && out.commit(error);
    }

    if (!ok) {
        std::cerr << "error: " << display_safe(error) << "\n";
        return RC_FAILURE;
    }
    for (const std::string& s : stats.skipped) {
        std::cerr << "warning: skipped " << display_safe(s) << " (symbolic link or special file)\n";
    }

    std::cout << "Encrypted " << in_path << " -> " << out_path << "\n"
              << "  recipient: " << pub_path << "\n";
    if (is_dir) {
        std::cout << "  contents : " << stats.files << " files, " << stats.directories
                  << " folders, " << stats.bytes << " bytes before compression\n";
    }
    std::cout << "  size: " << out.size() << " bytes\n"
              << "Hand " << out_path << " to the recipient; only they can decrypt it.\n";
    return RC_OK;
}

int cmd_decrypt(std::vector<std::string> args) {
    const auto flag = std::find(args.begin(), args.end(), "--salvage");
    const bool salvage = flag != args.end();
    if (salvage) args.erase(flag);
    const auto flagp = std::find(args.begin(), args.end(), "--passphrase");
    const bool want_pass = flagp != args.end();
    if (want_pass) args.erase(flagp);
    if (args.size() < 2) {
        std::cerr << "usage: pkcrypt decrypt [--salvage] [--passphrase] "
                     "<private_key> <file.pkcrypt> [out]\n";
        return RC_USAGE;
    }
    std::string priv_path = args[0], in_path = args[1];
    const bool explicit_out = args.size() >= 3;
    std::string out_path = explicit_out ? args[2] : decrypted_output_path(in_path);
    // Where a partial (salvaged) result goes: never the real name by default.
    const std::string partial_path =
        explicit_out ? out_path : unused_path(strip_slashes(out_path) + ".partial");

    std::string error;
    // If a passphrase is wanted, prompt for it at the terminal (no echo).
    // The passphrase is only used to unlock the private key and is not stored.
    const char* passphrase = nullptr;
    std::string pass_buf;
    if (want_pass) {
        const char* p = getpass("Enter passphrase for the private key: ");
        if (p == nullptr) {
            std::cerr << "error: failed to read passphrase from terminal\n";
            return RC_USAGE;
        }
        pass_buf = p;
        passphrase = pass_buf.c_str();
    }
    // Route by container kind (Ed25519 vs RSA).
    std::string kind = container_kind_of(in_path);          // ed25519 | rsa | ""

    int in_fd = ::open(in_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        std::cerr << "error: cannot open file: " << in_path << "\n";
        return RC_FAILURE;
    }
    FdSource in(in_fd);

    std::function<unsigned char()> payload_of;
    std::function<bool(ByteSink&, std::string&, bool)> run_of;
    RSAStreamDecryptor rdec;
    StreamDecryptor edec;
    if (kind == "rsa") {
        auto rkey = parse_ssh_rsa_private_key_file(priv_path, error, passphrase);
        if (!rkey) {
            std::cerr << "error: " << display_safe(error) << "\n";
            ::close(in_fd);
            return RC_USAGE;
        }
        if (!rdec.begin(in, rkey->n.data(), rkey->n.size(), rkey->e.data(), rkey->e.size(),
                        rkey->d.data(), rkey->d.size(), rkey->p.data(), rkey->p.size(),
                        rkey->q.data(), rkey->q.size(), error)) {
            std::cerr << "error: " << display_safe(error) << "\n";
            ::close(in_fd);
            return RC_FAILURE;
        }
        payload_of = [&] { return rdec.payload_type(); };
        run_of = [&](ByteSink& o, std::string& e, bool s) { return rdec.run(o, e, s); };
    } else if (kind == "ed25519") {
        auto edkey = parse_ssh_private_key_file(priv_path, error, passphrase);
        if (!edkey) {
            std::cerr << "error: " << display_safe(error) << "\n";
            ::close(in_fd);
            return RC_USAGE;
        }
        if (!edec.begin(in, edkey->private_key, edkey->public_key, error)) {
            std::cerr << "error: " << display_safe(error) << "\n";
            ::close(in_fd);
            return RC_FAILURE;
        }
        payload_of = [&] { return edec.payload_type(); };
        run_of = [&](ByteSink& o, std::string& e, bool s) { return edec.run(o, e, s); };
    } else {
        std::cerr << "error: not a PKCrypt file (bad header)\n";
        ::close(in_fd);
        return RC_FAILURE;
    }
    if (!pass_buf.empty()) sodium_memzero(pass_buf.data(), pass_buf.size());

    // Plaintext streams to a temporary file and is only published (linked
    // into place, or extracted) once every chunk has verified - or, with
    // --salvage, whatever verified is published as a partial result.
    bool ok;
    bool partial = false;
    std::string decrypt_error;
    ArchiveStats stats;
    if (payload_of() == PAYLOAD_ARCHIVE) {
        // ZIP needs random access (its index is at the end), so the archive
        // goes to a private 0600 scratch file beside the destination, removed
        // when `scratch` goes out of scope.
        TempFile scratch;
        struct stat st;
        ok = ::lstat(out_path.c_str(), &st) != 0;
        if (!ok) error = "refusing to overwrite existing path: " + out_path;
        ok = ok && scratch.create(parent_dir(out_path), error);
        const bool verified = ok && run_of(scratch, decrypt_error, salvage);
        if (ok && !salvage) {
            ok = verified;
            if (!ok) error = decrypt_error;
            ok = ok && extract_archive(scratch.fd(), scratch.size(), out_path, stats, error);
        } else if (ok && !verified && scratch.size() == 0) {
            ok = false;                     // nothing authenticated to salvage
            error = decrypt_error;
        } else if (ok) {
            SalvageReport report;
            ok = salvage_archive(scratch.fd(), scratch.size(), verified, out_path, partial_path,
                                 report, error);
            if (ok) {
                partial = !report.complete();
                print_salvage_report(in_path, partial ? partial_path : out_path, report,
                                     decrypt_error);
            }
        }
        if (ok && !salvage) {
            std::cout << "Decrypted " << in_path << " -> " << out_path << "/\n"
                      << "  contents: " << stats.files << " files, " << stats.directories
                      << " folders, " << stats.bytes << " bytes\n";
        }
    } else {
        AtomicFile out;
        ok = out.open(out_path, error);
        if (ok && !run_of(out, decrypt_error, salvage)) {
            if (salvage && out.size() > 0) {
                partial = true;             // keep the verified start of the file
                out.set_destination(partial_path);
            } else {
                ok = false;
                error = decrypt_error;
            }
        }
        const uint64_t size = out.size();
        ok = ok && out.commit(error);
        if (ok && partial) {
            std::cout << "Salvaged " << in_path << " -> " << partial_path << "\n"
                      << "  recovered: the first " << size << " bytes (verified)\n";
            std::cerr << "warning: the rest of the file is lost: " << display_safe(decrypt_error) << "\n"
                      << "warning: this is a PARTIAL result\n";
        } else if (ok) {
            std::cout << "Decrypted " << in_path << " -> " << out_path << "\n"
                      << "  size: " << size << " bytes\n";
        }
    }
    ::close(in_fd);
    if (!ok) {
        std::cerr << "error: " << display_safe(error) << "\n";
        return RC_FAILURE;
    }
    return partial ? RC_PARTIAL : RC_OK;
}

} // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "fatal: libsodium failed to initialize\n";
        return RC_FAILURE;
    }

    if (argc < 2) {
        usage(argv[0]);
        return RC_USAGE;
    }
    std::string cmd = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);

    if (cmd == "encrypt")    return cmd_encrypt(args);
    if (cmd == "decrypt")    return cmd_decrypt(args);
    if (cmd == "version") {
        std::cout << "PKCrypt " << PKCRYPT_VERSION_STRING << "\n";
        return RC_OK;
    }
    if (cmd == "help" || cmd == "--help" || cmd == "-h") { usage(argv[0]); return RC_OK; }

    std::cerr << "unknown command: " << cmd << "\n\n";
    usage(argv[0]);
    return RC_USAGE;
}

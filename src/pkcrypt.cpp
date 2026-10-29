//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <sodium.h>

#include "pkcrypt/version.h"
#include "pkcrypt/ssh_key.h"
#include "pkcrypt/crypto.h"
#include "pkcrypt/fileio.h"

using namespace pkcrypt;

namespace {

void usage(const char* prog) {
    std::cout
        << "PKCrypt " << PKCRYPT_VERSION_STRING
        << " - encrypt files so that only the holder of a private key can decrypt them.\n\n"
        << "Uses the holder's existing Ed25519 SSH keypair (~/.ssh/id_ed25519).\n\n"
        << "USAGE\n"
        << "  " << prog << " encrypt <recipient_pubkey> <file> [out.pkcrypt]\n"
        << "  " << prog << " decrypt <private_key> <file.pkcrypt> [out]\n"
        << "  " << prog << " version\n\n"
        << "EXAMPLES\n"
        << "  # Encrypt a file for someone using only their public key:\n"
        << "  " << prog << " encrypt alice_id_ed25519.pub secrets.tgz\n\n"
        << "  # Alice decrypts it on her Mac using her private key:\n"
        << "  " << prog << " decrypt ~/.ssh/id_ed25519 secrets.tgz.pkcrypt\n\n"
        << "NOTES\n"
        << "  - Private keys must be unencrypted (no passphrase). If yours is\n"
        << "    protected, decrypt it once first:\n"
        << "        ssh-keygen -p -f ~/.ssh/id_ed25519 -N \"\"\n"
        << "  - Encrypting needs only the recipient's PUBLIC key. No secret\n"
        << "    material ever leaves your machine when encrypting.\n";
}

int cmd_encrypt(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "usage: pkcrypt encrypt <recipient_pubkey> <file> [out.pkcrypt]\n";
        return 2;
    }
    std::string pub_path = args[0], in_path = args[1];
    std::string out_path = args.size() >= 3 ? args[2] : encrypted_output_path(in_path);

    std::string error;
    auto key = parse_ssh_public_key_file(pub_path, error);
    if (!key) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    std::vector<unsigned char> plaintext;
    if (!read_file(in_path, plaintext, error)) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    // encrypt_bytes() returns the full container (magic already prepended).
    auto container = encrypt_bytes(plaintext, key->public_key, error);
    // Wipe plaintext from memory as soon as possible.
    sodium_memzero(plaintext.data(), plaintext.size());
    if (container.empty() && !error.empty()) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    if (!write_file(out_path, container.data(), container.size(), error)) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    std::cout << "Encrypted " << in_path << " -> " << out_path << "\n"
              << "  recipient: " << pub_path << "\n"
              << "  size: " << container.size() << " bytes\n"
              << "Hand " << out_path << " to the recipient; only they can decrypt it.\n";
    return 0;
}

int cmd_decrypt(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "usage: pkcrypt decrypt <private_key> <file.pkcrypt> [out]\n";
        return 2;
    }
    std::string priv_path = args[0], in_path = args[1];
    std::string out_path = args.size() >= 3 ? args[2] : decrypted_output_path(in_path);

    std::string error;
    auto key = parse_ssh_private_key_file(priv_path, error);
    if (!key) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    std::vector<unsigned char> container;
    if (!read_file(in_path, container, error)) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    // decrypt_bytes() expects the full container (magic included) and the
    // recipient's seed + public key.
    auto plaintext = decrypt_bytes(container, key->private_key, key->public_key, error);
    if (plaintext.empty() && !error.empty()) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    if (!write_file(out_path, plaintext.data(), plaintext.size(), error)) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    std::cout << "Decrypted " << in_path << " -> " << out_path << "\n"
              << "  size: " << plaintext.size() << " bytes\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "fatal: libsodium failed to initialize\n";
        return 1;
    }

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    std::string cmd = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);

    if (cmd == "encrypt")    return cmd_encrypt(args);
    if (cmd == "decrypt")    return cmd_decrypt(args);
    if (cmd == "version") {
        std::cout << "PKCrypt " << PKCRYPT_VERSION_STRING << "\n";
        return 0;
    }
    if (cmd == "help" || cmd == "--help" || cmd == "-h") { usage(argv[0]); return 0; }

    std::cerr << "unknown command: " << cmd << "\n\n";
    usage(argv[0]);
    return 2;
}

#ifndef PKCRYPT_SSH_KEY_H
#define PKCRYPT_SSH_KEY_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//

#include <string>
#include <optional>

namespace pkcrypt {

// Raw key material after parsing.
struct Ed25519Key {
    unsigned char public_key[32] = {0};   // Ed25519 public key (32 bytes)
    unsigned char private_key[32] = {0};  // Ed25519 secret scalar / seed (32 bytes)
    bool has_private = false;             // true if a private key was parsed
};

// Parse an OpenSSH public key file ("ssh-ed25519 <b64> <comment>") into raw
// Ed25519 key material. Only the public portion is populated.
// Returns the parsed key, or std::nullopt on any parse/format error.
std::optional<Ed25519Key> parse_ssh_public_key_file(const std::string& path,
                                                     std::string& error);

// Parse an unencrypted OpenSSH private key file ("openssh-key-v1" format, the
// default produced by `ssh-keygen -t ed25519` without a passphrase) into raw
// Ed25519 key material. Both public and private portions are populated.
//
// NOTE: Password-protected keys ("aes256-ctr" cipher) are NOT supported directly.
// The OpenSSH KDF (bcrypt_pbkdf) is intentionally out of scope. For a
// passphrase-protected key, use the Python CLI's `decrypt --passphrase`; do not
// empty the key's passphrase (that weakens your SSH key) just to use the C++
// binary.
std::optional<Ed25519Key> parse_ssh_private_key_file(const std::string& path,
                                                      std::string& error);

} // namespace pkcrypt

#endif // PKCRYPT_SSH_KEY_H

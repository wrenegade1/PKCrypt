#ifndef PKCRYPT_SSH_KEY_H
#define PKCRYPT_SSH_KEY_H

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
// The OpenSSH KDF (bcrypt_pbkdf) is intentionally out of scope; such keys should
// first be decrypted with `ssh-keygen -p -f key -N ""`, or kept unencrypted.
std::optional<Ed25519Key> parse_ssh_private_key_file(const std::string& path,
                                                      std::string& error);

} // namespace pkcrypt

#endif // PKCRYPT_SSH_KEY_H

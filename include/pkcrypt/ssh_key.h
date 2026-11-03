#ifndef PKCRYPT_SSH_KEY_H
#define PKCRYPT_SSH_KEY_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//

#include <string>
#include <optional>
#include <vector>

namespace pkcrypt {

// Raw key material after parsing.
struct Ed25519Key {
    unsigned char public_key[32] = {0};   // Ed25519 public key (32 bytes)
    unsigned char private_key[32] = {0};  // Ed25519 secret scalar / seed (32 bytes)
    bool has_private = false;             // true if a private key was parsed
};

// RSA key material (mpint byte components, sign byte already stripped).
struct RsaKey {
    std::vector<unsigned char> n;   // modulus
    std::vector<unsigned char> e;   // exponent
    std::vector<unsigned char> d;   // private exponent (empty if public only)
    std::vector<unsigned char> p;   // prime p (empty if public only)
    std::vector<unsigned char> q;   // prime q (empty if public only)
    bool has_private = false;

    size_t modulus_bytes() const { return n.size(); }
};

// Parse an OpenSSH public key file ("ssh-ed25519 <b64> <comment>" or
// "ssh-rsa <b64> <comment>"). Returns the parsed key with an empty `error`, or
// std::nullopt with `error` set on failure. RSA detection is by type prefix.
std::optional<Ed25519Key> parse_ssh_public_key_file(const std::string& path,
                                                     std::string& error);

// Parse an OpenSSH private key file ("openssh-key-v1" format). Returns the
// parsed key, or std::nullopt with `error` set. For an Ed25519 key both public
// and private portions are populated. The key may be protected by a passphrase;
// if `passphrase` is non-null it is used to decrypt such a key, otherwise an
// encrypted key is rejected with an error.
std::optional<Ed25519Key> parse_ssh_private_key_file(const std::string& path,
                                                     std::string& error,
                                                     const char* passphrase = nullptr);

// True if (n, e) are well-formed RSA public numbers: n odd, e odd, 3 <= e < n
// (big-endian; leading zeros ignored). Otherwise sets `error`. These are the
// checks Python's `cryptography` applies when it loads a key.
bool rsa_public_numbers_ok(const unsigned char* n, size_t n_len,
                           const unsigned char* e, size_t e_len, std::string& error);

// Parse an OpenSSH RSA *public* key file ("ssh-rsa <b64> <comment>") into the
// raw modulus/exponent. Returns the key, or std::nullopt on failure.
std::optional<RsaKey> parse_ssh_rsa_public_key_file(const std::string& path,
                                                    std::string& error);

// Parse an OpenSSH RSA *private* key file (the "openssh-key-v1" container with
// an "ssh-rsa" key). Supports passphrase-protected keys via `passphrase`.
// Returns the key (n/e/d/p/q populated), or std::nullopt on failure.
std::optional<RsaKey> parse_ssh_rsa_private_key_file(const std::string& path,
                                                     std::string& error,
                                                     const char* passphrase = nullptr);

} // namespace pkcrypt

#endif // PKCRYPT_SSH_KEY_H

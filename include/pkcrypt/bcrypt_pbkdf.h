#ifndef PKCRYPT_BCRYPT_PBKDF_H
#define PKCRYPT_BCRYPT_PBKDF_H

//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//
// bcrypt_pbkdf: the password-based key derivation function OpenSSH uses to
// derive the AES / ChaCha20-Poly1305 key (and IV) that encrypts a
// passphrase-protected private key. It is OpenBSD's "bcrypt" hash (the
// password hashing function) re-spun as a PBKDF2-style KDF:
//
//   1. input password and salt are preprocessed with SHA-512,
//   2. output length is expanded to 256 bits (BCRYPT_HASHSIZE),
//   3. the magic "OxychromaticBlowfishSwatDynamite" is encrypted,
//   4. the hash runs 64 rounds of initial expansion (iterated by the KDF),
//   5. output bytes are shuffled non-linearly (the pbkdf2-deviation) so
//      computing any sub-key requires the whole output.
//
// This reimplements OpenBSD's lib/libutil/bcrypt_pbkdf.c and its bundled
// Blowfish (lib/libc/crypt/blowfish.c) in plain C++ with no third-party code,
// so passphrase-protected OpenSSH keys can be decrypted without libsodium or
// OpenSSL. It is byte-for-byte compatible with OpenSSH.
//

#include <cstddef>
#include <cstdint>

namespace pkcrypt {

// Derive `key_len` bytes of key material from `passphrase` and `salt`.
// Mirrors OpenBSD's bcrypt_pbkdf(). Returns false (writing nothing valid)
// on invalid parameters; `rounds` must be >= 1 and `key_len` bounded.
bool bcrypt_pbkdf(const char* passphrase, size_t pass_len,
                  const std::uint8_t* salt, size_t salt_len,
                  std::uint8_t* key, size_t key_len,
                  unsigned int rounds);

} // namespace pkcrypt

#endif // PKCRYPT_BCRYPT_PBKDF_H

#ifndef PKCRYPT_AES_CTR_H
#define PKCRYPT_AES_CTR_H

//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//
// AES in CTR mode, used to decrypt the payload of passphrase-protected
// OpenSSH private keys (cipher "aes128-ctr" / "aes192-ctr" / "aes256-ctr").
//
// When OpenSSL is available this uses its EVP interface (hardware-accelerated
// and side-channel hardened). Otherwise it falls back to a self-contained
// implementation of AES (FIPS-197) and CTR mode, so the C++ binary still works
// on systems without OpenSSL. Both paths are validated against the same known
// vectors and OpenSSH-generated keys.
//

#include <cstddef>
#include <cstdint>

namespace pkcrypt {

// Decrypt (== encrypt, CTR is symmetric) `len` bytes of `in` under AES-CTR
// with the given key (16/24/32 bytes) and 16-byte initial counter block.
// Returns false on an invalid key length.
bool aes_ctr_crypt(const std::uint8_t* key, size_t key_len,
                   const std::uint8_t iv[16],
                   const std::uint8_t* in, std::uint8_t* out, size_t len);

} // namespace pkcrypt

#endif // PKCRYPT_AES_CTR_H

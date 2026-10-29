#ifndef PKCRYPT_CRYPTO_H
#define PKCRYPT_CRYPTO_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//

#include <vector>
#include <cstdint>
#include <string>

#include <sodium.h>
#include "pkcrypt/ssh_key.h"

namespace pkcrypt {

// ---------------------------------------------------------------------------
// On-disk container format (interoperable with the Python pkcrypt_lib):  *
//                                                                         *
//   magic       8 bytes   b"PKCRYPT\x01"                                  *
//   eph_pub    32 bytes   sender's ephemeral X25519 public key            *
//   nonce      12 bytes   AES-256-GCM nonce                               *
//   ciphertext  n bytes   encrypted file + 16-byte GCM authentication tag *
// ---------------------------------------------------------------------------
// This is a hybrid scheme: Ed25519 SSH keys are converted to X25519, an
// ephemeral X25519 keypair performs ECDH with the recipient's public key, and
// the resulting shared secret is expanded with HKDF-SHA256 into an AES-256-GCM
// key. Only the holder of the recipient's private key can recompute it.
// ---------------------------------------------------------------------------

constexpr char PKCRYPT_MAGIC[8] = { 'P','K','C','R','Y','P','T', 0x01 };
constexpr size_t MAGIC_BYTES    = sizeof(PKCRYPT_MAGIC);        // 8
constexpr size_t EPH_PUB_BYTES  = crypto_box_PUBLICKEYBYTES;    // 32 (X25519)
constexpr size_t NONCE_BYTES    = crypto_aead_aes256gcm_NPUBBYTES; // 12
constexpr size_t GCM_TAG_BYTES  = crypto_aead_aes256gcm_ABYTES;    // 16
constexpr size_t KEY_BYTES      = crypto_aead_aes256gcm_KEYBYTES;  // 32

// HKDF-SHA256 parameters (must match pkcrypt_lib/core.py exactly).
//   salt = b"PKCrypt"                    (7 bytes)
//   info = b"PKCrypt/v1/x25519-ecdh+aes-256-gcm" || eph_pub || recipient_x_pub
constexpr char HKDF_SALT_BYTES[7] = { 'P','K','C','r','y','p','t' };
constexpr char HKDF_INFO_STR[]  = "PKCrypt/v1/x25519-ecdh+aes-256-gcm";

// Convert a parsed Ed25519 key into X25519 (curve25519) material using
// libsodium's reference OpenSSH-compatible conversions.
//   * public:  crypto_sign_ed25519_pk_to_curve25519
//   * private: crypto_sign_ed25519_sk_to_curve25519 (over the 64-byte seed||pub)
// Either output pointer may be nullptr if that half is not needed.
bool to_curve25519(const Ed25519Key& key, unsigned char curve_pk[32],
                   unsigned char curve_sk[32], std::string& error);

// Encrypt `plaintext` for the holder of `recipient_ed25519_public`.
// Returns the full on-disk container (magic | eph_pub | nonce | ciphertext),
// or an empty vector with `error` set on failure.
std::vector<unsigned char> encrypt_bytes(const std::vector<unsigned char>& plaintext,
                                         const unsigned char recipient_ed25519_public[32],
                                         std::string& error);

// Decrypt a container produced by encrypt_bytes(). Requires the recipient's
// Ed25519 seed + public key. On success returns the plaintext; on any failure
// (wrong key, tampered data, bad header) returns an empty vector with `error`.
std::vector<unsigned char> decrypt_bytes(const std::vector<unsigned char>& container,
                                         const unsigned char recipient_ed25519_seed[32],
                                         const unsigned char recipient_ed25519_public[32],
                                         std::string& error);

} // namespace pkcrypt

#endif // PKCRYPT_CRYPTO_H

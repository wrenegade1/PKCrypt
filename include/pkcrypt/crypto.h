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
// On-disk container format v2 (interoperable with the Python pkcrypt_lib):
//
//   header (AAD for every chunk):
//     magic      8 bytes   "PKCRYPT\x02"
//     cipher     1 byte    0x00 = AES-256-GCM | 0x01 = XChaCha20-Poly1305
//     eph_pub   32 bytes   sender's ephemeral X25519 public key
//     nonce     12|24 B    base AEAD nonce (12 GSM / 24 XChaCha20)
//     chunk_len  4 bytes   max plaintext bytes per chunk, big-endian
//   payload:
//     chunks     each AEAD ciphertext = (chunk bytes + 16-byte auth tag)
//
// The plaintext is split into chunk_len-byte chunks (last may be short). Each
// chunk uses the SAME key but a per-chunk nonce = base nonce with its final 4
// bytes set to the big-endian chunk index. The header is passed as associated
// data (AAD) to every chunk, so tampering with the header fails the tag.
//
// v1 containers ("PKCRYPT\x01") remain readable for backwards compatibility;
// encrypt always writes v2.
// ---------------------------------------------------------------------------

constexpr char PKCRYPT_MAGIC_V1[8] = { 'P','K','C','R','Y','P','T', 0x01 };
constexpr char PKCRYPT_MAGIC_V2[8] = { 'P','K','C','R','Y','P','T', 0x02 };
constexpr size_t MAGIC_BYTES    = 8;
constexpr size_t CIPHER_BYTES   = 1;
constexpr size_t EPH_PUB_BYTES  = crypto_box_PUBLICKEYBYTES;  // 32 (X25519)
constexpr size_t CHUNK_LEN_BYTES = 4;
constexpr size_t TAG_BYTES      = crypto_aead_aes256gcm_ABYTES;   // 16
constexpr size_t KEY_BYTES      = crypto_aead_aes256gcm_KEYBYTES; // 32

// Cipher identifiers (cipher byte).
constexpr unsigned char CIPHER_AES        = 0x00;
constexpr unsigned char CIPHER_XCHACHA20  = 0x01;

// Nonce lengths per cipher.
constexpr size_t NONCE_BYTES_AES = crypto_aead_aes256gcm_NPUBBYTES;         // 12
constexpr size_t NONCE_BYTES_XC  = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24

// Default plaintext bytes per chunk (1 MiB) and the max chunk index (4 bytes).
constexpr size_t DEFAULT_CHUNK_LEN = 1024 * 1024;   // 1 MiB
constexpr size_t MAX_CHUNKS = 0xFFFFFFFFu;          // 4-byte BE index

// HKDF-SHA256 parameters (must match pkcrypt_lib/core.py exactly).
//   salt = b"PKCrypt"
//   info = versioned label || eph_pub(32) || recipient_x_pub(32)
constexpr char HKDF_SALT_BYTES[7] = { 'P','K','C','r','y','p','t' };
constexpr char HKDF_INFO_V2[] = "PKCrypt/v2/x25519-ecdh+aead";
constexpr char HKDF_INFO_V1[] = "PKCrypt/v1/x25519-ecdh+aes-256-gcm";

// Per-chunk nonce: base nonce with its final 4 bytes set to the big-endian
// chunk index. `nonce_len` is the cipher's base nonce length.
void chunk_nonce(const unsigned char* base_nonce, size_t nonce_len,
                 uint32_t index, unsigned char* out);

// Convert a parsed Ed25519 key into X25519 (curve25519) material using
// libsodium's reference OpenSSH-compatible conversions.
bool to_curve25519(const Ed25519Key& key, unsigned char curve_pk[32],
                   unsigned char curve_sk[32], std::string& error);

// Encrypt `plaintext` for the holder of `recipient_ed25519_public`.
// Writes a v2 chunked container; `cipher` selects AES-256-GCM (0x00) or
// XChaCha20-Poly1305 (0x01). Returns the container, or empty with `error`.
std::vector<unsigned char> encrypt_bytes(const std::vector<unsigned char>& plaintext,
                                         const unsigned char recipient_ed25519_public[32],
                                         unsigned char cipher,
                                         size_t chunk_len,
                                         std::string& error);

// Convenience overload: AES-256-GCM, default chunk size.
std::vector<unsigned char> encrypt_bytes(const std::vector<unsigned char>& plaintext,
                                         const unsigned char recipient_ed25519_public[32],
                                         std::string& error);

// Decrypt a v2 or v1 container produced by this program. Returns plaintext on
// success, or empty with `error` on failure (wrong key, tampered data, header).
std::vector<unsigned char> decrypt_bytes(const std::vector<unsigned char>& container,
                                         const unsigned char recipient_ed25519_seed[32],
                                         const unsigned char recipient_ed25519_public[32],
                                         std::string& error);

} // namespace pkcrypt

#endif // PKCRYPT_CRYPTO_H

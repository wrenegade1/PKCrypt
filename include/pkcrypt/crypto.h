// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
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
#include "pkcrypt/stream.h"

namespace pkcrypt {

// ---------------------------------------------------------------------------
// On-disk container format v2 (interoperable with the Python pkcrypt_lib):
//
//   header:
//     magic      8 bytes   "PKCRYPT\x02"
//     cipher     1 byte    0x00 = AES-256-GCM | 0x01 = XChaCha20-Poly1305
//     payload    1 byte    0x00 = single file | 0x01 = ZIP archive (a folder)
//     eph_pub   32 bytes   sender's ephemeral X25519 public key
//     nonce     12|24 B    base AEAD nonce (12 GSM / 24 XChaCha20)
//     chunk_len  4 bytes   max plaintext bytes per chunk, big-endian
//   payload:
//     chunks     each AEAD ciphertext = (chunk bytes + 16-byte auth tag)
//
// The plaintext is split into chunk_len-byte chunks. Every chunk but the last
// is exactly chunk_len bytes; the last holds the remaining 0..chunk_len bytes,
// so there is always at least one chunk (an empty file is one empty chunk).
// Each chunk uses the SAME key but a per-chunk nonce = base nonce with its
// final 4 bytes set to the big-endian chunk index. Each chunk's associated
// data (AAD) is the header followed by one flag byte: 0x01 for the last chunk,
// 0x00 otherwise. Tampering with the header fails the tag, and so does
// truncating or extending the payload at a chunk boundary.
// ---------------------------------------------------------------------------

constexpr char PKCRYPT_MAGIC_V2[8] = { 'P','K','C','R','Y','P','T', 0x02 };
constexpr size_t MAGIC_BYTES    = 8;
constexpr size_t CIPHER_BYTES   = 1;
constexpr size_t PAYLOAD_BYTES  = 1;
constexpr size_t EPH_PUB_BYTES  = crypto_box_PUBLICKEYBYTES;  // 32 (X25519)
constexpr size_t CHUNK_LEN_BYTES = 4;
constexpr size_t TAG_BYTES      = crypto_aead_aes256gcm_ABYTES;   // 16
constexpr size_t KEY_BYTES      = crypto_aead_aes256gcm_KEYBYTES; // 32

// Cipher identifiers (cipher byte).
constexpr unsigned char CIPHER_AES        = 0x00;
constexpr unsigned char CIPHER_XCHACHA20  = 0x01;

// Payload type identifiers (payload byte): what the plaintext is.
constexpr unsigned char PAYLOAD_FILE    = 0x00;  // one file's bytes
constexpr unsigned char PAYLOAD_ARCHIVE = 0x01;  // ZIP archive of a folder

// Final-chunk flag appended to the header to form each chunk's AAD.
constexpr unsigned char FLAG_MORE  = 0x00;
constexpr unsigned char FLAG_FINAL = 0x01;

// Nonce lengths per cipher.
constexpr size_t NONCE_BYTES_AES = crypto_aead_aes256gcm_NPUBBYTES;         // 12
constexpr size_t NONCE_BYTES_XC  = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24

// Default plaintext bytes per chunk (1 MiB) and the max chunk index (4 bytes).
constexpr size_t DEFAULT_CHUNK_LEN = 1024 * 1024;   // 1 MiB
constexpr uint64_t MAX_CHUNKS = 0x100000000ull;     // 4-byte BE index
constexpr uint64_t MAX_CHUNK_LEN = 0xFFFFFFFFull;   // 4-byte chunk_len field

// HKDF-SHA256 parameters (must match pkcrypt_lib/core.py exactly).
//   salt = b"PKCrypt"
//   info = versioned label || eph_pub(32) || recipient_x_pub(32)
constexpr char HKDF_SALT_BYTES[7] = { 'P','K','C','r','y','p','t' };
constexpr char HKDF_INFO_V2[] = "PKCrypt/v2/x25519-ecdh+aead";

// Per-chunk nonce: base nonce with its final 4 bytes set to the big-endian
// chunk index. `nonce_len` is the cipher's base nonce length.
void chunk_nonce(const unsigned char* base_nonce, size_t nonce_len,
                 uint32_t index, unsigned char* out);

// Convert a parsed Ed25519 key into X25519 (curve25519) material using
// libsodium's reference OpenSSH-compatible conversions.
bool to_curve25519(const Ed25519Key& key, unsigned char curve_pk[32],
                   unsigned char curve_sk[32], std::string& error);

// Largest chunk_len accepted when encrypting or decrypting. The decryptor
// buffers one chunk, and chunk_len comes from the (untrusted) header, so a
// larger value is rejected rather than allocated. PKCrypt writes 1 MiB chunks.
constexpr size_t MAX_ACCEPTED_CHUNK_LEN = 16 * 1024 * 1024;

// Streaming encryption for the holder of `recipient_ed25519_public`.
// begin() writes the header to `out`; write() takes plaintext in pieces of any
// size and passes sealed chunks to `out` as they fill; finish() seals the final
// chunk. Until finish(), up to chunk_len bytes are held back, because only the
// chunk at the very end of the input may be sealed as final. `payload_type`
// records what the plaintext is (PAYLOAD_FILE or PAYLOAD_ARCHIVE). The key is
// wiped by finish() and by the destructor.
class StreamEncryptor : public ByteSink {
public:
    StreamEncryptor() = default;
    StreamEncryptor(const StreamEncryptor&) = delete;
    StreamEncryptor& operator=(const StreamEncryptor&) = delete;
    ~StreamEncryptor() override;

    bool begin(ByteSink& out, const unsigned char recipient_ed25519_public[32],
               unsigned char payload_type, std::string& error,
               unsigned char cipher = CIPHER_AES, size_t chunk_len = DEFAULT_CHUNK_LEN);
    bool write(const unsigned char* data, size_t n, std::string& error) override;
    bool finish(std::string& error);

private:
    bool seal(bool final, std::string& error);
    void wipe();

    ByteSink* out_ = nullptr;
    bool active_ = false;
    bool is_aes_ = true;
    unsigned char key_[KEY_BYTES] = {0};
    unsigned char base_nonce_[NONCE_BYTES_XC] = {0};
    size_t nonce_len_ = 0;
    size_t chunk_len_ = 0;
    uint64_t index_ = 0;
    std::vector<unsigned char> aad_;        // header || final flag
    std::vector<unsigned char> pending_;    // plaintext not yet sealed
    std::vector<unsigned char> sealed_;     // ciphertext scratch
};

// Streaming decryption. begin() reads and validates the header from `in` and
// derives the key; run() then decrypts every chunk into `out`.
//
// run() succeeds only if every chunk verified, the last one was sealed as
// final, and nothing follows it. Chunks are written to `out` as they verify,
// so on failure `out` holds the authenticated prefix of the plaintext: callers
// must write to a temporary destination and publish it only after run()
// returns true (or, when salvaging, publish the prefix as a partial result).
// With `salvage`, a cut-off stream's last full chunk - which fails as final -
// is also kept if it verifies as the non-final chunk it really is.
class StreamDecryptor {
public:
    StreamDecryptor() = default;
    StreamDecryptor(const StreamDecryptor&) = delete;
    StreamDecryptor& operator=(const StreamDecryptor&) = delete;
    ~StreamDecryptor();

    bool begin(ByteSource& in, const unsigned char recipient_ed25519_seed[32],
               const unsigned char recipient_ed25519_public[32], std::string& error);

    // The header's payload type. Like the rest of the header it is part of
    // every chunk's AAD, so it is only authenticated once run() succeeds.
    unsigned char payload_type() const { return payload_type_; }

    bool run(ByteSink& out, std::string& error, bool salvage = false);

private:
    bool open(const std::vector<unsigned char>& ct, bool final, ByteSink& out,
              std::string& error);
    void wipe();

    ByteSource* in_ = nullptr;
    bool is_aes_ = true;
    unsigned char payload_type_ = PAYLOAD_FILE;
    unsigned char key_[KEY_BYTES] = {0};
    unsigned char base_nonce_[NONCE_BYTES_XC] = {0};
    size_t nonce_len_ = 0;
    size_t chunk_len_ = 0;
    uint64_t index_ = 0;
    std::vector<unsigned char> aad_;        // header || final flag
    std::vector<unsigned char> plain_;      // plaintext scratch
};

// ---------------------------------------------------------------------------
// RSA recipient-key container (interoperable with the Python pkcrypt_lib).
//
//   header:
//     magic       8 bytes   "PKCRYPT\x03"
//     cipher      1 byte    0x00 = AES-256-GCM | 0x01 = XChaCha20-Poly1305
//     payload     1 byte    0x00 = single file | 0x01 = ZIP archive (a folder)
//     alg         1 byte    0x00 = rsa-oaep-sha256
//     wrapped_key N bytes   RSA-OAEP(SHA-256) of a random 32-byte session key
//                           (N = the RSA modulus size: 256 for 2048-bit, 512
//                           for 4096-bit)
//     base_nonce  12|24 B   AEAD base nonce
//     chunk_len   4 bytes   max plaintext bytes per chunk, big-endian
//   payload:
//     chunks     each AEAD ciphertext = (chunk bytes + 16-byte auth tag)
//
// The file payload uses the same chunked/AAD scheme as the Ed25519 container
// (per-chunk nonces, final-chunk flag, header as AAD), with the AEAD key being
// the fresh 32-byte session key. Encrypting needs only the recipient's RSA
// *public* key; only the matching RSA *private* key can unwrap the session key
// and decrypt. C++ requires OpenSSL's libcrypto; without it RSA is unsupported
// (Ed25519 still works via libsodium).
// ---------------------------------------------------------------------------

constexpr char PKCRYPT_MAGIC_RSA[8]  = { 'P','K','C','R','Y','P','T', 0x03 };
constexpr size_t RSA_ALG_BYTES       = 1;
constexpr unsigned char RSA_ALG_OAEP_SHA256 = 0x00;

// Streaming RSA encryption (mirrors StreamEncryptor's chunk behaviour).
class RSAStreamEncryptor : public ByteSink {
public:
    RSAStreamEncryptor() = default;
    RSAStreamEncryptor(const RSAStreamEncryptor&) = delete;
    RSAStreamEncryptor& operator=(const RSAStreamEncryptor&) = delete;
    ~RSAStreamEncryptor() override;

    // `rsa_n`/`rsa_e` are the recipient's RSA modulus and exponent (public key).
    // `modulus_bytes` == the byte length of `rsa_n`. Wraps a fresh session key
    // via RSA-OAEP and writes the header to `out`.
    bool begin(ByteSink& out, const unsigned char* rsa_n, size_t n_len,
               const unsigned char* rsa_e, size_t e_len, size_t modulus_bytes,
               unsigned char payload_type, std::string& error,
               unsigned char cipher = CIPHER_AES, size_t chunk_len = DEFAULT_CHUNK_LEN);
    bool write(const unsigned char* data, size_t n, std::string& error) override;
    bool finish(std::string& error);

private:
    bool seal(bool final, std::string& error);
    void wipe();

    ByteSink* out_ = nullptr;
    bool active_ = false;
    bool is_aes_ = true;
    std::vector<unsigned char> wrapped_key_;
    unsigned char key_[KEY_BYTES] = {0};
    unsigned char base_nonce_[NONCE_BYTES_XC] = {0};
    size_t nonce_len_ = 0;
    size_t chunk_len_ = 0;
    uint64_t index_ = 0;
    std::vector<unsigned char> aad_;        // header || final flag
    std::vector<unsigned char> pending_;    // plaintext not yet sealed
    std::vector<unsigned char> sealed_;     // ciphertext scratch
};

// Streaming RSA decryption. begin() reads the header and unwraps the session
// key with the RSA private key; run() decrypts every chunk into `out`. Callers
// must publish `out` only after run() returns true (see StreamDecryptor).
class RSAStreamDecryptor {
public:
    RSAStreamDecryptor() = default;
    RSAStreamDecryptor(const RSAStreamDecryptor&) = delete;
    RSAStreamDecryptor& operator=(const RSAStreamDecryptor&) = delete;
    ~RSAStreamDecryptor();

    bool begin(ByteSource& in,
               const unsigned char* rsa_n, size_t n_len,
               const unsigned char* rsa_e, size_t e_len,
               const unsigned char* rsa_d, size_t d_len,
               const unsigned char* rsa_p, size_t p_len,
               const unsigned char* rsa_q, size_t q_len,
               std::string& error);

    unsigned char payload_type() const { return payload_type_; }

    bool run(ByteSink& out, std::string& error, bool salvage = false);

private:
    bool open(const std::vector<unsigned char>& ct, bool final, ByteSink& out,
              std::string& error);
    void wipe();

    ByteSource* in_ = nullptr;
    bool is_aes_ = true;
    unsigned char payload_type_ = PAYLOAD_FILE;
    unsigned char key_[KEY_BYTES] = {0};
    unsigned char base_nonce_[NONCE_BYTES_XC] = {0};
    size_t nonce_len_ = 0;
    size_t chunk_len_ = 0;
    uint64_t index_ = 0;
    std::vector<unsigned char> aad_;        // header || final flag
    std::vector<unsigned char> plain_;      // plaintext scratch
};

} // namespace pkcrypt

#endif // PKCRYPT_CRYPTO_H

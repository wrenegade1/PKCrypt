//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//

#include "pkcrypt/crypto.h"

#include <cstring>
#include <algorithm>

namespace pkcrypt {

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) using libsodium primitives.
//   Extract:  PRK = HMAC-SHA256(salt, IKM)
//   Expand:   OKM  = T(1) || T(2) || ... where T(i) = HMAC(PRK, T(i-1)||info||i)
// Since our OKM length == HMAC output length (32 bytes), only one iteration is
// needed. This matches cryptography's HKDF with length=32 and SHA256.
// ---------------------------------------------------------------------------

static void hmac_sha256(unsigned char out[32], const unsigned char* key,
                        size_t key_len, const unsigned char* msg, size_t msg_len) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, msg, static_cast<unsigned long long>(msg_len));
    crypto_auth_hmacsha256_final(&st, out);
}

static bool hkdf_sha256(unsigned char out[32],
                        const unsigned char* salt, size_t salt_len,
                        const unsigned char* ikm, size_t ikm_len,
                        const unsigned char* info, size_t info_len) {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    unsigned char prk[32];
    hmac_sha256(prk, salt, salt_len, ikm, ikm_len);

    // Expand: OKM = HMAC(PRK, info || 0x01)  (single block)
    if (info_len + 1 > 256) { sodium_memzero(prk, sizeof prk); return false; }
    unsigned char expand_msg[1 + 256];
    std::memcpy(expand_msg, info, info_len);
    expand_msg[info_len] = 0x01;
    hmac_sha256(out, prk, sizeof prk, expand_msg, info_len + 1);

    sodium_memzero(prk, sizeof prk);
    return true;
}

// Derive the 32-byte AEAD key from the ECDH shared secret, binding the label,
// ephemeral and recipient public keys into the HKDF info string.
// `info15` counts the label bytes (must fit with the two 32-byte keys).
static bool derive_key(const unsigned char* shared,
                       const unsigned char* eph_pub,
                       const unsigned char* recipient_x_pub,
                       const char* label, size_t label_len,
                       unsigned char key[32]) {
    unsigned char info[64 + 64];
    size_t info_len = label_len + 32 + 32;
    std::memcpy(info, label, label_len);
    std::memcpy(info + label_len, eph_pub, 32);
    std::memcpy(info + label_len + 32, recipient_x_pub, 32);
    return hkdf_sha256(key,
                       reinterpret_cast<const unsigned char*>(HKDF_SALT_BYTES),
                       sizeof(HKDF_SALT_BYTES), shared,
                       crypto_scalarmult_curve25519_BYTES, info, info_len);
}

// ---------------------------------------------------------------------------
// Ed25519 -> X25519 conversion (libsodium reference, OpenSSH-compatible)
// ---------------------------------------------------------------------------

bool to_curve25519(const Ed25519Key& key, unsigned char curve_pk[32],
                   unsigned char curve_sk[32], std::string& error) {
    if (curve_pk) {
        if (crypto_sign_ed25519_pk_to_curve25519(curve_pk, key.public_key) != 0) {
            error = "failed to convert ed25519 public key to curve25519";
            return false;
        }
    }
    if (curve_sk) {
        if (!key.has_private) {
            error = "key has no private half; cannot derive decryption key";
            return false;
        }
        // Reconstruct libsodium's 64-byte secret key: seed(32) || public(32).
        unsigned char ed_sk64[crypto_sign_ed25519_SECRETKEYBYTES];
        std::memcpy(ed_sk64, key.private_key, 32);
        std::memcpy(ed_sk64 + 32, key.public_key, 32);
        int rc = crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk64);
        sodium_memzero(ed_sk64, sizeof ed_sk64);
        if (rc != 0) {
            error = "failed to convert ed25519 private key to curve25519";
            return false;
        }
    }
    return true;
}

void chunk_nonce(const unsigned char* base_nonce, size_t nonce_len,
                 uint32_t index, unsigned char* out) {
    std::memcpy(out, base_nonce, nonce_len);
    // Set final 4 bytes to the big-endian chunk index.
    out[nonce_len - 4] = static_cast<unsigned char>((index >> 24) & 0xFF);
    out[nonce_len - 3] = static_cast<unsigned char>((index >> 16) & 0xFF);
    out[nonce_len - 2] = static_cast<unsigned char>((index >> 8) & 0xFF);
    out[nonce_len - 1] = static_cast<unsigned char>(index & 0xFF);
}

// Append the big-endian 32-bit `v` to `dst`.
static void push_be32(std::vector<unsigned char>& dst, uint32_t v) {
    dst.push_back(static_cast<unsigned char>((v >> 24) & 0xFF));
    dst.push_back(static_cast<unsigned char>((v >> 16) & 0xFF));
    dst.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
    dst.push_back(static_cast<unsigned char>(v & 0xFF));
}

static bool read_be32(const unsigned char* p, uint32_t& out) {
    out = (static_cast<uint32_t>(p[0]) << 24) |
          (static_cast<uint32_t>(p[1]) << 16) |
          (static_cast<uint32_t>(p[2]) << 8) |
          (static_cast<uint32_t>(p[3]));
    return true;
}

namespace {

bool aes256gcm_ready(std::string& error) {
    if (sodium_init() < 0) { error = "sodium_init failed"; return false; }
    if (!crypto_aead_aes256gcm_is_available()) {
        error = "AES-256-GCM is not available on this CPU (requires AES-NI); "
                "use cipher 0x01 (XChaCha20-Poly1305) instead";
        return false;
    }
    return true;
}

} // namespace

std::vector<unsigned char> encrypt_bytes(
    const std::vector<unsigned char>& plaintext,
    const unsigned char recipient_ed25519_public[32],
    unsigned char cipher, size_t chunk_len, std::string& error) {

    if (cipher != CIPHER_AES && cipher != CIPHER_XCHACHA20) {
        error = "unsupported cipher";
        return {};
    }
    if (chunk_len == 0) { error = "chunk_len must be positive"; return {}; }

    if (cipher == CIPHER_AES && !aes256gcm_ready(error)) return {};

    size_t nonce_len = (cipher == CIPHER_AES) ? NONCE_BYTES_AES : NONCE_BYTES_XC;

    // 1. Convert recipient's Ed25519 public key to X25519.
    unsigned char recipient_x_pub[32];
    Ed25519Key recipient;
    std::memcpy(recipient.public_key, recipient_ed25519_public, 32);
    recipient.has_private = false;
    if (!to_curve25519(recipient, recipient_x_pub, nullptr, error)) return {};

    // 2. Fresh ephemeral X25519 keypair (forward secrecy + sender anonymity).
    unsigned char eph_pk[32], eph_sk[32];
    crypto_box_keypair(eph_pk, eph_sk);

    // 3. ECDH: shared = eph_sk * recipient_x_pub.
    unsigned char shared[32];
    if (crypto_scalarmult(shared, eph_sk, recipient_x_pub) != 0) {
        error = "X25519 ECDH failed";
        sodium_memzero(eph_sk, sizeof eph_sk);
        return {};
    }
    sodium_memzero(eph_sk, sizeof eph_sk);

    // 4. Derive the AEAD key via HKDF-SHA256 (v2 label).
    unsigned char key[KEY_BYTES];
    if (!derive_key(shared, eph_pk, recipient_x_pub, HKDF_INFO_V2,
                    sizeof(HKDF_INFO_V2) - 1, key)) {
        error = "key derivation failed";
        sodium_memzero(shared, sizeof shared);
        return {};
    }
    sodium_memzero(shared, sizeof shared);

    // 5. Random base nonce.
    unsigned char base_nonce[NONCE_BYTES_XC];
    randombytes_buf(base_nonce, nonce_len);

    // 6. Build the standalone header; it is the AAD for every chunk. Building
    // it as its own vector (that never grows) keeps the AAD pointer stable for
    // the whole chunk loop.
    std::vector<unsigned char> header;
    header.reserve(MAGIC_BYTES + CIPHER_BYTES + EPH_PUB_BYTES + nonce_len + CHUNK_LEN_BYTES);
    header.insert(header.end(), reinterpret_cast<const unsigned char*>(PKCRYPT_MAGIC_V2),
                  reinterpret_cast<const unsigned char*>(PKCRYPT_MAGIC_V2) + MAGIC_BYTES);
    header.push_back(cipher);
    header.insert(header.end(), eph_pk, eph_pk + EPH_PUB_BYTES);
    header.insert(header.end(), base_nonce, base_nonce + nonce_len);
    push_be32(header, static_cast<uint32_t>(chunk_len));
    const size_t header_len = header.size();
    const unsigned char* aad = header.data();  // header never grows -> stable

    // 7. Encrypt each chunk with the header as AAD and a per-chunk nonce.
    uint32_t index = 0;
    size_t pos = 0;
    std::vector<unsigned char> out;
    out.reserve(header_len + plaintext.size() + TAG_BYTES);
    std::vector<unsigned char> chunk_ct;
    while (pos < plaintext.size()) {
        size_t chunk_plain = std::min(chunk_len, plaintext.size() - pos);
        if (index >= MAX_CHUNKS) { error = "too many chunks"; sodium_memzero(key, sizeof key); return {}; }
        unsigned char nonce[NONCE_BYTES_XC];
        chunk_nonce(base_nonce, nonce_len, index, nonce);

        chunk_ct.resize(chunk_plain + TAG_BYTES);
        unsigned long long ct_len = 0;
        int rc;
        if (cipher == CIPHER_AES) {
            rc = crypto_aead_aes256gcm_encrypt(
                chunk_ct.data(), &ct_len, plaintext.data() + pos,
                static_cast<unsigned long long>(chunk_plain),
                aad, static_cast<unsigned long long>(header_len),
                nullptr, nonce, key);
        } else {
            rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
                chunk_ct.data(), &ct_len, plaintext.data() + pos,
                static_cast<unsigned long long>(chunk_plain),
                aad, static_cast<unsigned long long>(header_len),
                nullptr, nonce, key);
        }
        if (rc != 0) { error = (cipher == CIPHER_AES) ? "AES-GCM encryption failed" : "XChaCha20 encryption failed"; sodium_memzero(key, sizeof key); return {}; }
        out.insert(out.end(), chunk_ct.begin(), chunk_ct.end());
        pos += chunk_plain;
        ++index;
    }
    // Prepend the header.
    out.insert(out.begin(), header.begin(), header.end());
    sodium_memzero(key, sizeof key);
    return out;
}

std::vector<unsigned char> encrypt_bytes(
    const std::vector<unsigned char>& plaintext,
    const unsigned char recipient_ed25519_public[32], std::string& error) {
    return encrypt_bytes(plaintext, recipient_ed25519_public,
                         CIPHER_AES, DEFAULT_CHUNK_LEN, error);
}

std::vector<unsigned char> decrypt_bytes(
    const std::vector<unsigned char>& container,
    const unsigned char recipient_ed25519_seed[32],
    const unsigned char recipient_ed25519_public[32], std::string& error) {

    if (container.size() < MAGIC_BYTES) { error = "not a PKCrypt file (bad header)"; return {}; }

    bool is_v2 = std::memcmp(container.data(), PKCRYPT_MAGIC_V2, MAGIC_BYTES) == 0;
    bool is_v1 = std::memcmp(container.data(), PKCRYPT_MAGIC_V1, MAGIC_BYTES) == 0;
    if (!is_v2 && !is_v1) { error = "not a PKCrypt file (bad header)"; return {}; }

    // Convert the recipient's Ed25519 key to the X25519 keypair.
    unsigned char recipient_x_pub[32], recipient_x_sk[32];
    Ed25519Key recipient;
    std::memcpy(recipient.public_key, recipient_ed25519_public, 32);
    std::memcpy(recipient.private_key, recipient_ed25519_seed, 32);
    recipient.has_private = true;
    if (to_curve25519(recipient, recipient_x_pub, recipient_x_sk, error) == false) return {};

    // ============================ v1 (legacy) ==============================
    if (is_v1) {
        if (container.size() < MAGIC_BYTES + EPH_PUB_BYTES + NONCE_BYTES_AES + TAG_BYTES) {
            error = "encrypted payload too short or corrupt";
            sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);
            return {};
        }
        const unsigned char* eph_pub = container.data() + MAGIC_BYTES;
        const unsigned char* nonce   = container.data() + MAGIC_BYTES + EPH_PUB_BYTES;
        const unsigned char* ct      = container.data() + MAGIC_BYTES + EPH_PUB_BYTES + NONCE_BYTES_AES;
        size_t ct_len = container.size() - (MAGIC_BYTES + EPH_PUB_BYTES + NONCE_BYTES_AES);

        unsigned char shared[32];
        if (crypto_scalarmult(shared, recipient_x_sk, eph_pub) != 0) {
            error = "X25519 ECDH failed";
            sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);
            return {};
        }
        sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);

        unsigned char key[KEY_BYTES];
        if (!derive_key(shared, eph_pub, recipient_x_pub, HKDF_INFO_V1,
                        sizeof(HKDF_INFO_V1) - 1, key)) {
            error = "key derivation failed";
            sodium_memzero(shared, sizeof shared);
            return {};
        }
        sodium_memzero(shared, sizeof shared);

        if (!aes256gcm_ready(error)) { sodium_memzero(key, sizeof key); return {}; }

        std::vector<unsigned char> pt(ct_len - TAG_BYTES);
        unsigned long long pt_len = 0;
        if (crypto_aead_aes256gcm_decrypt(
                pt.data(), &pt_len, nullptr, ct, static_cast<unsigned long long>(ct_len),
                nullptr, 0, nonce, key) != 0) {
            sodium_memzero(key, sizeof key);
            error = "decryption failed: file is not for this private key, or it was tampered with";
            return {};
        }
        sodium_memzero(key, sizeof key);
        pt.resize(pt_len);
        return pt;
    }

    // ============================ v2 (current) =============================
    size_t off = MAGIC_BYTES;
    unsigned char cipher = container[off]; off += CIPHER_BYTES;
    const unsigned char* eph_pub = container.data() + off; off += EPH_PUB_BYTES;

    bool is_aes;
    size_t nonce_len;
    if (cipher == CIPHER_AES) { is_aes = true;  nonce_len = NONCE_BYTES_AES; }
    else if (cipher == CIPHER_XCHACHA20) { is_aes = false; nonce_len = NONCE_BYTES_XC; }
    else { error = "unsupported cipher"; sodium_memzero(recipient_x_sk, sizeof recipient_x_sk); return {}; }

    if (container.size() < off + nonce_len + CHUNK_LEN_BYTES + TAG_BYTES) {
        error = "encrypted payload too short or corrupt";
        sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);
        return {};
    }
    const unsigned char* base_nonce = container.data() + off; off += nonce_len;

    uint32_t chunk_len;
    read_be32(container.data() + off, chunk_len); off += CHUNK_LEN_BYTES;
    if (chunk_len == 0) { error = "invalid chunk size in header"; sodium_memzero(recipient_x_sk, sizeof recipient_x_sk); return {}; }

    // Header = all bytes up to and including chunk_len (used as AAD).
    std::vector<unsigned char> header(container.begin(), container.begin() + off);

    if (is_aes && !aes256gcm_ready(error)) { sodium_memzero(recipient_x_sk, sizeof recipient_x_sk); return {}; }

    unsigned char shared[32];
    if (crypto_scalarmult(shared, recipient_x_sk, eph_pub) != 0) {
        error = "X25519 ECDH failed";
        sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);
        return {};
    }
    sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);

    unsigned char key[KEY_BYTES];
    if (!derive_key(shared, eph_pub, recipient_x_pub, HKDF_INFO_V2,
                    sizeof(HKDF_INFO_V2) - 1, key)) {
        error = "key derivation failed";
        sodium_memzero(shared, sizeof shared);
        return {};
    }
    sodium_memzero(shared, sizeof shared);

    // Decrypt chunks. Each chunk is exactly chunk_len plaintext + tag, except
    // the final one (>= tag bytes). Cumulative sizing keeps us aligned.
    std::vector<unsigned char> pt;
    uint32_t index = 0;
    size_t pos = off;
    while (pos < container.size()) {
        size_t remaining = container.size() - pos;
        if (remaining < TAG_BYTES) {
            error = "encrypted payload too short or corrupt";
            sodium_memzero(key, sizeof key);
            return {};
        }
        size_t ct_len = std::min(static_cast<size_t>(chunk_len) + TAG_BYTES, remaining);

        unsigned char nonce[NONCE_BYTES_XC];
        chunk_nonce(base_nonce, nonce_len, index, nonce);

        std::vector<unsigned char> chunk_pt(ct_len - TAG_BYTES);
        unsigned long long pt_len = 0;
        int rc;
        if (is_aes) {
            rc = crypto_aead_aes256gcm_decrypt(
                chunk_pt.data(), &pt_len, nullptr,
                container.data() + pos, static_cast<unsigned long long>(ct_len),
                header.data(), static_cast<unsigned long long>(header.size()),
                nonce, key);
        } else {
            rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
                chunk_pt.data(), &pt_len, nullptr,
                container.data() + pos, static_cast<unsigned long long>(ct_len),
                header.data(), static_cast<unsigned long long>(header.size()),
                nonce, key);
        }
        if (rc != 0) {
            sodium_memzero(key, sizeof key);
            error = "decryption failed: file is not for this private key, or it was tampered with";
            return {};
        }
        chunk_pt.resize(pt_len);
        pt.insert(pt.end(), chunk_pt.begin(), chunk_pt.end());
        pos += ct_len;
        ++index;
    }
    sodium_memzero(key, sizeof key);
    return pt;
}

} // namespace pkcrypt

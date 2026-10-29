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

static void hkdf_sha256(unsigned char out[32],
                        const unsigned char* salt, size_t salt_len,
                        const unsigned char* ikm, size_t ikm_len,
                        const unsigned char* info, size_t info_len) {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    unsigned char prk[32];
    hmac_sha256(prk, salt, salt_len, ikm, ikm_len);

    // Expand: OKM = HMAC(PRK, info || 0x01)  (single block)
    unsigned char expand_msg[1 + 256];
    size_t expand_len = info_len + 1;
    std::memcpy(expand_msg, info, info_len);
    expand_msg[info_len] = 0x01;
    hmac_sha256(out, prk, sizeof prk, expand_msg, expand_len);

    sodium_memzero(prk, sizeof prk);
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

// ---------------------------------------------------------------------------
// Hybrid encryption / decryption
// ---------------------------------------------------------------------------

namespace {

bool aes256gcm_ready(std::string& error) {
    if (sodium_init() < 0) { error = "sodium_init failed"; return false; }
    if (!crypto_aead_aes256gcm_is_available()) {
        error = "AES-256-GCM is not available on this CPU (requires AES-NI)";
        return false;
    }
    return true;
}

} // namespace

std::vector<unsigned char> encrypt_bytes(
    const std::vector<unsigned char>& plaintext,
    const unsigned char recipient_ed25519_public[32], std::string& error) {

    if (!aes256gcm_ready(error)) return {};

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

    // 4. Derive symmetric key via HKDF-SHA256.
    unsigned char key[KEY_BYTES];
    {
        // info = HKDF_INFO_STR || eph_pub(32) || recipient_x_pub(32)
        unsigned char info[256];
        size_t info_len = 0;
        std::memcpy(info, HKDF_INFO_STR, sizeof(HKDF_INFO_STR) - 1);
        info_len += sizeof(HKDF_INFO_STR) - 1;
        std::memcpy(info + info_len, eph_pk, 32);            info_len += 32;
        std::memcpy(info + info_len, recipient_x_pub, 32);   info_len += 32;
        hkdf_sha256(key, reinterpret_cast<const unsigned char*>(HKDF_SALT_BYTES),
                    sizeof(HKDF_SALT_BYTES), shared, sizeof shared,
                    info, info_len);
    }
    sodium_memzero(shared, sizeof shared);
    sodium_memzero(eph_sk, sizeof eph_sk);

    // 5. Random nonce + AES-256-GCM (no AAD, matching Python).
    unsigned char nonce[NONCE_BYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> out;
    out.reserve(MAGIC_BYTES + EPH_PUB_BYTES + NONCE_BYTES +
                plaintext.size() + GCM_TAG_BYTES);
    out.insert(out.end(), reinterpret_cast<const unsigned char*>(PKCRYPT_MAGIC),
               reinterpret_cast<const unsigned char*>(PKCRYPT_MAGIC) + MAGIC_BYTES);
    out.insert(out.end(), eph_pk, eph_pk + EPH_PUB_BYTES);
    out.insert(out.end(), nonce, nonce + NONCE_BYTES);

    size_t ct_offset = out.size();
    out.resize(out.size() + plaintext.size() + GCM_TAG_BYTES);

    unsigned long long ct_len = 0;
    if (crypto_aead_aes256gcm_encrypt(
            out.data() + ct_offset, &ct_len,
            plaintext.data(), static_cast<unsigned long long>(plaintext.size()),
            nullptr, 0, nullptr, nonce, key) != 0) {
        error = "AES-GCM encryption failed";
        sodium_memzero(key, sizeof key);
        return {};
    }
    sodium_memzero(key, sizeof key);
    out.resize(ct_offset + ct_len);
    return out;
}

std::vector<unsigned char> decrypt_bytes(
    const std::vector<unsigned char>& container,
    const unsigned char recipient_ed25519_seed[32],
    const unsigned char recipient_ed25519_public[32], std::string& error) {

    if (!aes256gcm_ready(error)) return {};

    if (container.size() < MAGIC_BYTES + EPH_PUB_BYTES + NONCE_BYTES + GCM_TAG_BYTES) {
        error = "encrypted payload too short or corrupt";
        return {};
    }
    if (std::memcmp(container.data(), PKCRYPT_MAGIC, MAGIC_BYTES) != 0) {
        error = "not a PKCrypt file (bad header)";
        return {};
    }

    const unsigned char* eph_pub = container.data() + MAGIC_BYTES;
    const unsigned char* nonce   = container.data() + MAGIC_BYTES + EPH_PUB_BYTES;
    const unsigned char* ct      = container.data() + MAGIC_BYTES + EPH_PUB_BYTES + NONCE_BYTES;
    size_t ct_len = container.size() - (MAGIC_BYTES + EPH_PUB_BYTES + NONCE_BYTES);

    // 1. Convert recipient's Ed25519 key to the X25519 keypair.
    unsigned char recipient_x_pub[32], recipient_x_sk[32];
    Ed25519Key recipient;
    std::memcpy(recipient.public_key, recipient_ed25519_public, 32);
    std::memcpy(recipient.private_key, recipient_ed25519_seed, 32);
    recipient.has_private = true;
    if (!to_curve25519(recipient, recipient_x_pub, recipient_x_sk, error)) return {};

    // 2. ECDH: shared = recipient_x_sk * eph_pub.
    unsigned char shared[32];
    if (crypto_scalarmult(shared, recipient_x_sk, eph_pub) != 0) {
        error = "X25519 ECDH failed";
        sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);
        return {};
    }
    sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);

    // 3. Derive symmetric key via HKDF-SHA256 (same constants as encrypt).
    unsigned char key[KEY_BYTES];
    {
        unsigned char info[256];
        size_t info_len = 0;
        std::memcpy(info, HKDF_INFO_STR, sizeof(HKDF_INFO_STR) - 1);
        info_len += sizeof(HKDF_INFO_STR) - 1;
        std::memcpy(info + info_len, eph_pub, 32);           info_len += 32;
        std::memcpy(info + info_len, recipient_x_pub, 32);   info_len += 32;
        hkdf_sha256(key, reinterpret_cast<const unsigned char*>(HKDF_SALT_BYTES),
                    sizeof(HKDF_SALT_BYTES), shared, sizeof shared,
                    info, info_len);
    }
    sodium_memzero(shared, sizeof shared);

    // 4. AES-256-GCM decrypt (authenticates => rejects wrong key / tampering).
    std::vector<unsigned char> pt(ct_len - GCM_TAG_BYTES);
    unsigned long long pt_len = 0;
    if (crypto_aead_aes256gcm_decrypt(
            pt.data(), &pt_len, nullptr,
            ct, static_cast<unsigned long long>(ct_len),
            nullptr, 0, nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        error = "decryption failed: file is not for this private key, or it was tampered with";
        return {};
    }
    sodium_memzero(key, sizeof key);
    pt.resize(pt_len);
    return pt;
}

} // namespace pkcrypt

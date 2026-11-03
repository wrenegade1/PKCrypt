//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//

#include "pkcrypt/crypto.h"

#include <cstring>
#include <algorithm>

#ifdef PKCRYPT_HAS_OPENSSL
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

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

namespace {

constexpr char DECRYPT_FAILED[] =
    "decryption failed: file is not for this private key, or it was tampered with or truncated";

// AEAD seal/open of one chunk with the cipher selected by `is_aes`.
int aead_encrypt(bool is_aes, unsigned char* c, unsigned long long* clen,
                 const unsigned char* m, size_t mlen, const std::vector<unsigned char>& aad,
                 const unsigned char* nonce, const unsigned char* key) {
    return is_aes
        ? crypto_aead_aes256gcm_encrypt(c, clen, m, mlen, aad.data(), aad.size(),
                                        nullptr, nonce, key)
        : crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen, m, mlen, aad.data(), aad.size(),
                                                     nullptr, nonce, key);
}

int aead_decrypt(bool is_aes, unsigned char* m, unsigned long long* mlen,
                 const unsigned char* c, size_t clen, const std::vector<unsigned char>& aad,
                 const unsigned char* nonce, const unsigned char* key) {
    return is_aes
        ? crypto_aead_aes256gcm_decrypt(m, mlen, nullptr, c, clen, aad.data(), aad.size(),
                                        nonce, key)
        : crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen, nullptr, c, clen, aad.data(),
                                                     aad.size(), nonce, key);
}

} // namespace

// ---------------------------------------------------------------------------
// StreamEncryptor
// ---------------------------------------------------------------------------

StreamEncryptor::~StreamEncryptor() { wipe(); }

void StreamEncryptor::wipe() {
    sodium_memzero(key_, sizeof key_);
    if (!pending_.empty()) sodium_memzero(pending_.data(), pending_.size());
    pending_.clear();
    active_ = false;
}

bool StreamEncryptor::begin(ByteSink& out, const unsigned char recipient_ed25519_public[32],
                            unsigned char payload_type, std::string& error,
                            unsigned char cipher, size_t chunk_len) {
    wipe();
    if (cipher != CIPHER_AES && cipher != CIPHER_XCHACHA20) {
        error = "unsupported cipher";
        return false;
    }
    if (payload_type != PAYLOAD_FILE && payload_type != PAYLOAD_ARCHIVE) {
        error = "unsupported payload type";
        return false;
    }
    if (chunk_len == 0 || chunk_len > MAX_ACCEPTED_CHUNK_LEN) {
        error = "chunk_len must be between 1 and 16 MiB";
        return false;
    }
    if (cipher == CIPHER_AES && !aes256gcm_ready(error)) return false;
    is_aes_ = (cipher == CIPHER_AES);
    nonce_len_ = is_aes_ ? NONCE_BYTES_AES : NONCE_BYTES_XC;
    chunk_len_ = chunk_len;
    index_ = 0;

    // 1. Convert recipient's Ed25519 public key to X25519.
    unsigned char recipient_x_pub[32];
    Ed25519Key recipient;
    std::memcpy(recipient.public_key, recipient_ed25519_public, 32);
    recipient.has_private = false;
    if (!to_curve25519(recipient, recipient_x_pub, nullptr, error)) return false;

    // 2. Fresh ephemeral X25519 keypair (forward secrecy + sender anonymity).
    unsigned char eph_pk[32], eph_sk[32];
    crypto_box_keypair(eph_pk, eph_sk);

    // 3. ECDH: shared = eph_sk * recipient_x_pub.
    unsigned char shared[32];
    int rc = crypto_scalarmult(shared, eph_sk, recipient_x_pub);
    sodium_memzero(eph_sk, sizeof eph_sk);
    if (rc != 0) {
        error = "X25519 ECDH failed";
        return false;
    }

    // 4. Derive the AEAD key via HKDF-SHA256 (v2 label).
    bool derived = derive_key(shared, eph_pk, recipient_x_pub, HKDF_INFO_V2,
                              sizeof(HKDF_INFO_V2) - 1, key_);
    sodium_memzero(shared, sizeof shared);
    if (!derived) {
        error = "key derivation failed";
        return false;
    }

    // 5. Random base nonce, then the header. Each chunk's AAD is
    // header || final_flag, so aad_ is the header plus one flag byte.
    randombytes_buf(base_nonce_, nonce_len_);
    aad_.clear();
    aad_.insert(aad_.end(), reinterpret_cast<const unsigned char*>(PKCRYPT_MAGIC_V2),
                reinterpret_cast<const unsigned char*>(PKCRYPT_MAGIC_V2) + MAGIC_BYTES);
    aad_.push_back(cipher);
    aad_.push_back(payload_type);
    aad_.insert(aad_.end(), eph_pk, eph_pk + EPH_PUB_BYTES);
    aad_.insert(aad_.end(), base_nonce_, base_nonce_ + nonce_len_);
    push_be32(aad_, static_cast<uint32_t>(chunk_len));
    if (!out.write(aad_.data(), aad_.size(), error)) {
        sodium_memzero(key_, sizeof key_);
        return false;
    }
    aad_.push_back(FLAG_MORE);

    out_ = &out;
    pending_.clear();
    pending_.reserve(chunk_len);
    sealed_.resize(chunk_len + TAG_BYTES);
    active_ = true;
    return true;
}

bool StreamEncryptor::write(const unsigned char* data, size_t n, std::string& error) {
    if (!active_) {
        error = "encryptor is not active";
        return false;
    }
    while (n > 0) {
        // A full buffer is sealed only now that more data has arrived: the
        // chunk at the end of the input must be sealed as final instead.
        if (pending_.size() == chunk_len_ && !seal(false, error)) return false;
        size_t take = std::min(n, chunk_len_ - pending_.size());
        pending_.insert(pending_.end(), data, data + take);
        data += take;
        n -= take;
    }
    return true;
}

bool StreamEncryptor::finish(std::string& error) {
    if (!active_) {
        error = "encryptor is not active";
        return false;
    }
    bool ok = seal(true, error);
    wipe();
    return ok;
}

bool StreamEncryptor::seal(bool final, std::string& error) {
    if (index_ >= MAX_CHUNKS) {
        error = "too many chunks";
        wipe();
        return false;
    }
    unsigned char nonce[NONCE_BYTES_XC];
    chunk_nonce(base_nonce_, nonce_len_, static_cast<uint32_t>(index_), nonce);
    aad_.back() = final ? FLAG_FINAL : FLAG_MORE;
    unsigned long long ct_len = 0;
    if (aead_encrypt(is_aes_, sealed_.data(), &ct_len, pending_.data(), pending_.size(), aad_,
                     nonce, key_) != 0) {
        error = is_aes_ ? "AES-GCM encryption failed" : "XChaCha20 encryption failed";
        wipe();
        return false;
    }
    sodium_memzero(pending_.data(), pending_.size());
    pending_.clear();
    ++index_;
    if (!out_->write(sealed_.data(), static_cast<size_t>(ct_len), error)) {
        wipe();
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// StreamDecryptor
// ---------------------------------------------------------------------------

StreamDecryptor::~StreamDecryptor() { wipe(); }

void StreamDecryptor::wipe() {
    sodium_memzero(key_, sizeof key_);
    if (!plain_.empty()) sodium_memzero(plain_.data(), plain_.size());
}

bool StreamDecryptor::begin(ByteSource& in, const unsigned char recipient_ed25519_seed[32],
                            const unsigned char recipient_ed25519_public[32],
                            std::string& error) {
    // magic | cipher | payload, then eph_pub | base_nonce | chunk_len.
    unsigned char prefix[MAGIC_BYTES + CIPHER_BYTES + PAYLOAD_BYTES];
    long long got = read_full(in, prefix, sizeof prefix, error);
    if (got < 0) return false;
    if (got < static_cast<long long>(MAGIC_BYTES) ||
        std::memcmp(prefix, PKCRYPT_MAGIC_V2, MAGIC_BYTES) != 0) {
        error = "not a PKCrypt file (bad header)";
        return false;
    }
    if (got < static_cast<long long>(sizeof prefix)) {
        error = "encrypted payload too short or corrupt";
        return false;
    }
    const unsigned char cipher = prefix[MAGIC_BYTES];
    payload_type_ = prefix[MAGIC_BYTES + CIPHER_BYTES];
    if (cipher == CIPHER_AES) { is_aes_ = true; nonce_len_ = NONCE_BYTES_AES; }
    else if (cipher == CIPHER_XCHACHA20) { is_aes_ = false; nonce_len_ = NONCE_BYTES_XC; }
    else { error = "unsupported cipher"; return false; }
    if (payload_type_ != PAYLOAD_FILE && payload_type_ != PAYLOAD_ARCHIVE) {
        error = "unsupported payload type";
        return false;
    }

    unsigned char rest[EPH_PUB_BYTES + NONCE_BYTES_XC + CHUNK_LEN_BYTES];
    const size_t rest_len = EPH_PUB_BYTES + nonce_len_ + CHUNK_LEN_BYTES;
    got = read_full(in, rest, rest_len, error);
    if (got < 0) return false;
    if (got < static_cast<long long>(rest_len)) {
        error = "encrypted payload too short or corrupt";
        return false;
    }
    const unsigned char* eph_pub = rest;
    std::memcpy(base_nonce_, rest + EPH_PUB_BYTES, nonce_len_);
    uint32_t chunk_len;
    read_be32(rest + EPH_PUB_BYTES + nonce_len_, chunk_len);
    if (chunk_len == 0) { error = "invalid chunk size in header"; return false; }
    if (chunk_len > MAX_ACCEPTED_CHUNK_LEN) {
        error = "chunk size in header too large (limit 16 MiB)";
        return false;
    }
    chunk_len_ = chunk_len;

    if (is_aes_ && !aes256gcm_ready(error)) return false;

    // Convert the recipient's Ed25519 key to the X25519 keypair.
    unsigned char recipient_x_pub[32], recipient_x_sk[32];
    Ed25519Key recipient;
    std::memcpy(recipient.public_key, recipient_ed25519_public, 32);
    std::memcpy(recipient.private_key, recipient_ed25519_seed, 32);
    recipient.has_private = true;
    if (!to_curve25519(recipient, recipient_x_pub, recipient_x_sk, error)) return false;

    unsigned char shared[32];
    int rc = crypto_scalarmult(shared, recipient_x_sk, eph_pub);
    sodium_memzero(recipient_x_sk, sizeof recipient_x_sk);
    if (rc != 0) {
        error = "X25519 ECDH failed";
        return false;
    }
    bool derived = derive_key(shared, eph_pub, recipient_x_pub, HKDF_INFO_V2,
                              sizeof(HKDF_INFO_V2) - 1, key_);
    sodium_memzero(shared, sizeof shared);
    if (!derived) {
        error = "key derivation failed";
        return false;
    }

    aad_.assign(prefix, prefix + sizeof prefix);
    aad_.insert(aad_.end(), rest, rest + rest_len);
    aad_.push_back(FLAG_MORE);
    in_ = &in;
    index_ = 0;
    return true;
}

bool StreamDecryptor::run(ByteSink& out, std::string& error, bool salvage) {
    if (!in_) {
        error = "decryptor is not active";
        return false;
    }
    // Every chunk but the last is exactly one full block; the last holds the
    // rest. A full block is only known not to be last once the next one has
    // been read, so one block of lookahead is kept.
    const size_t block = chunk_len_ + TAG_BYTES;
    plain_.resize(chunk_len_ + 1);      // +1 so data() is never null
    auto read_block = [&](std::vector<unsigned char>& buf) {
        buf.resize(block);
        long long got = read_full(*in_, buf.data(), block, error);
        if (got < 0) return false;
        buf.resize(static_cast<size_t>(got));
        return true;
    };

    std::vector<unsigned char> cur, next;
    bool ok = read_block(cur);
    while (ok) {
        if (cur.size() < block) break;                  // short: must be final
        if (!(ok = read_block(next))) break;
        if (next.empty()) break;                        // full block at EOF: final
        if (!(ok = open(cur, false, out, error))) break;
        cur.swap(next);
    }
    if (ok) {
        ok = open(cur, true, out, error);
        if (!ok && salvage && cur.size() == block) {
            // Cut off at a chunk boundary: this chunk was sealed as non-final.
            // Keep it if it verifies as such; the stream is still incomplete.
            std::string ignored;
            open(cur, false, out, ignored);
        }
    }
    in_ = nullptr;
    wipe();
    return ok;
}

bool StreamDecryptor::open(const std::vector<unsigned char>& ct, bool final, ByteSink& out,
                           std::string& error) {
    if (ct.size() < TAG_BYTES) {
        error = "encrypted payload truncated or corrupt";
        return false;
    }
    if (index_ >= MAX_CHUNKS) {
        error = "encrypted payload has too many chunks";
        return false;
    }
    unsigned char nonce[NONCE_BYTES_XC];
    chunk_nonce(base_nonce_, nonce_len_, static_cast<uint32_t>(index_), nonce);
    aad_.back() = final ? FLAG_FINAL : FLAG_MORE;
    unsigned long long pt_len = 0;
    if (aead_decrypt(is_aes_, plain_.data(), &pt_len, ct.data(), ct.size(), aad_, nonce,
                     key_) != 0) {
        error = DECRYPT_FAILED;
        return false;
    }
    ++index_;
    bool ok = out.write(plain_.data(), static_cast<size_t>(pt_len), error);
    sodium_memzero(plain_.data(), static_cast<size_t>(pt_len));
    return ok;
}

// ---------------------------------------------------------------------------
// RSA (PKCRYPT\x03 container)
// ---------------------------------------------------------------------------

#ifdef PKCRYPT_HAS_OPENSSL
namespace {

// Build an RSA EVP_PKEY from mpint byte components. For a public key pass
// (n, e) and nulls for the rest; for a private key pass (n, e, d, p, q).
// Uses OpenSSL 3's EVP_PKEY_fromdata. Returns nullptr on failure.
EVP_PKEY* rsa_pkey_from_components(const unsigned char* n, size_t n_len,
                                   const unsigned char* e, size_t e_len,
                                   const unsigned char* d, size_t d_len,
                                   const unsigned char* p, size_t p_len,
                                   const unsigned char* q, size_t q_len) {
    BIGNUM *bn_n = BN_bin2bn(n, static_cast<int>(n_len), nullptr);
    BIGNUM *bn_e = BN_bin2bn(e, static_cast<int>(e_len), nullptr);
    BIGNUM *bn_d = d ? BN_bin2bn(d, static_cast<int>(d_len), nullptr) : nullptr;
    BIGNUM *bn_p = p ? BN_bin2bn(p, static_cast<int>(p_len), nullptr) : nullptr;
    BIGNUM *bn_q = q ? BN_bin2bn(q, static_cast<int>(q_len), nullptr) : nullptr;
    if (!bn_n || !bn_e) goto fail;

    {
        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        EVP_PKEY_CTX* ctx = nullptr;
        EVP_PKEY* pkey = nullptr;
        if (!bld) goto fail_bn;
        OSSL_PARAM_BLD_push_utf8_string(bld, "rsa", "", 0);
        OSSL_PARAM_BLD_push_BN(bld, "n", bn_n);
        OSSL_PARAM_BLD_push_BN(bld, "e", bn_e);
        if (bn_d) OSSL_PARAM_BLD_push_BN(bld, "d", bn_d);
        if (bn_p) OSSL_PARAM_BLD_push_BN(bld, "p", bn_p);
        if (bn_q) OSSL_PARAM_BLD_push_BN(bld, "q", bn_q);
        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        if (!params) { OSSL_PARAM_BLD_free(bld); goto fail_bn; }
        ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        EVP_PKEY_fromdata_init(ctx);
        int selection = d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
        int ok = EVP_PKEY_fromdata(ctx, &pkey, selection, params);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        if (ok && pkey) { BN_free(bn_n); BN_free(bn_e); if (bn_d) BN_free(bn_d); if (bn_p) BN_free(bn_p); if (bn_q) BN_free(bn_q); return pkey; }
        goto fail_bn;
    }

fail_bn:
    if (bn_n) BN_free(bn_n);
    if (bn_e) BN_free(bn_e);
    if (bn_d) BN_free(bn_d);
    if (bn_p) BN_free(bn_p);
    if (bn_q) BN_free(bn_q);
    return nullptr;
fail:
    if (bn_n) BN_free(bn_n);
    if (bn_e) BN_free(bn_e);
    return nullptr;
}

// RSA-OAEP(SHA-256) encrypt `inlen` bytes of `in` to the public part of
// `key`; returns ciphertext of modulus length, or empty list on failure.
std::vector<unsigned char> rsa_oaep_encrypt(EVP_PKEY* key,
                                            const unsigned char* in, size_t inlen) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!ctx) return {};
    std::vector<unsigned char> out;
    size_t outlen = 0;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto done;
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, in, inlen) <= 0) goto done;
    out.resize(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, in, inlen) <= 0) { out.clear(); goto done; }
    out.resize(outlen);
done:
    EVP_PKEY_CTX_free(ctx);
    return out;
}

// RSA-OAEP(SHA-256) decrypt: reverses rsa_oaep_encrypt. Returns the plaintext
// (the wrapped session key) or empty on failure (wrong key / bad data).
std::vector<unsigned char> rsa_oaep_decrypt(EVP_PKEY* key,
                                            const unsigned char* in, size_t inlen) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!ctx) return {};
    std::vector<unsigned char> out;
    size_t outlen = 0;
    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto done;
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, in, inlen) <= 0) goto done;
    out.resize(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, in, inlen) <= 0) { out.clear(); goto done; }
    out.resize(outlen);
done:
    EVP_PKEY_CTX_free(ctx);
    return out;
}

} // namespace
#endif // PKCRYPT_HAS_OPENSSL

RSAStreamEncryptor::~RSAStreamEncryptor() { wipe(); }

void RSAStreamEncryptor::wipe() {
    sodium_memzero(key_, sizeof key_);
    if (!pending_.empty()) sodium_memzero(pending_.data(), pending_.size());
    pending_.clear();
    active_ = false;
}

bool RSAStreamEncryptor::begin(ByteSink& out, const unsigned char* rsa_n, size_t n_len,
                               const unsigned char* rsa_e, size_t e_len, size_t modulus_bytes,
                               unsigned char payload_type, std::string& error,
                               unsigned char cipher, size_t chunk_len) {
#ifndef PKCRYPT_HAS_OPENSSL
    (void)rsa_n; (void)n_len; (void)rsa_e; (void)e_len; (void)modulus_bytes;
    (void)payload_type; (void)cipher; (void)chunk_len;
    error = "this build lacks OpenSSL; RSA recipient keys are unsupported in the "
            "C++ binary (the Python CLI supports them, and Ed25519 still works)";
    return false;
#else
    wipe();
    if (modulus_bytes < 256) { error = "RSA key too small (need at least 2048 bits)"; return false; }
    if (cipher != CIPHER_AES && cipher != CIPHER_XCHACHA20) { error = "unsupported cipher"; return false; }
    if (payload_type != PAYLOAD_FILE && payload_type != PAYLOAD_ARCHIVE) { error = "unsupported payload type"; return false; }
    if (chunk_len == 0 || chunk_len > MAX_ACCEPTED_CHUNK_LEN) { error = "chunk_len must be between 1 and 16 MiB"; return false; }
    if (cipher == CIPHER_AES && !aes256gcm_ready(error)) return false;
    is_aes_ = (cipher == CIPHER_AES);
    nonce_len_ = is_aes_ ? NONCE_BYTES_AES : NONCE_BYTES_XC;
    chunk_len_ = chunk_len;
    index_ = 0;

    EVP_PKEY* pubkey = rsa_pkey_from_components(rsa_n, n_len, rsa_e, e_len,
                                                nullptr, 0, nullptr, 0, nullptr, 0);
    if (!pubkey) { error = "malformed RSA public key"; return false; }
    // A fresh 32-byte session key, OAEP-wrapped with the recipient's public key.
    std::vector<unsigned char> sess(KEY_BYTES);
    randombytes_buf(sess.data(), sess.size());
    wrapped_key_ = rsa_oaep_encrypt(pubkey, sess.data(), sess.size());
    EVP_PKEY_free(pubkey);
    if (wrapped_key_.size() != modulus_bytes) {
        sodium_memzero(sess.data(), sess.size());
        error = "RSA-OAEP wrap failed";
        return false;
    }

    randombytes_buf(base_nonce_, nonce_len_);
    aad_.clear();
    aad_.insert(aad_.end(), PKCRYPT_MAGIC_RSA, PKCRYPT_MAGIC_RSA + MAGIC_BYTES);
    aad_.push_back(cipher);
    aad_.push_back(payload_type);
    aad_.push_back(RSA_ALG_OAEP_SHA256);
    aad_.insert(aad_.end(), wrapped_key_.begin(), wrapped_key_.end());
    aad_.insert(aad_.end(), base_nonce_, base_nonce_ + nonce_len_);
    push_be32(aad_, static_cast<uint32_t>(chunk_len));
    if (!out.write(aad_.data(), aad_.size(), error)) { sodium_memzero(sess.data(), sess.size()); return false; }
    aad_.push_back(FLAG_MORE);

    std::memcpy(key_, sess.data(), KEY_BYTES);
    sodium_memzero(sess.data(), sess.size());
    out_ = &out;
    pending_.clear();
    pending_.reserve(chunk_len);
    sealed_.resize(chunk_len + TAG_BYTES);
    active_ = true;
    return true;
#endif
}

bool RSAStreamEncryptor::write(const unsigned char* data, size_t n, std::string& error) {
    if (!active_) { error = "encryptor is not active"; return false; }
    while (n > 0) {
        if (pending_.size() == chunk_len_ && !seal(false, error)) return false;
        size_t take = std::min(n, chunk_len_ - pending_.size());
        pending_.insert(pending_.end(), data, data + take);
        data += take;
        n -= take;
    }
    return true;
}

bool RSAStreamEncryptor::finish(std::string& error) {
    if (!active_) { error = "encryptor is not active"; return false; }
    bool ok = seal(true, error);
    wipe();
    return ok;
}

bool RSAStreamEncryptor::seal(bool final, std::string& error) {
    if (index_ >= MAX_CHUNKS) { error = "too many chunks"; wipe(); return false; }
    unsigned char nonce[NONCE_BYTES_XC];
    chunk_nonce(base_nonce_, nonce_len_, static_cast<uint32_t>(index_), nonce);
    aad_.back() = final ? FLAG_FINAL : FLAG_MORE;
    unsigned long long ct_len = 0;
    if (aead_encrypt(is_aes_, sealed_.data(), &ct_len, pending_.data(), pending_.size(), aad_,
                     nonce, key_) != 0) {
        error = "encryption failed"; wipe(); return false;
    }
    sodium_memzero(pending_.data(), pending_.size());
    pending_.clear();
    ++index_;
    if (!out_->write(sealed_.data(), static_cast<size_t>(ct_len), error)) { wipe(); return false; }
    return true;
}

RSAStreamDecryptor::~RSAStreamDecryptor() { wipe(); }

void RSAStreamDecryptor::wipe() {
    sodium_memzero(key_, sizeof key_);
    if (!plain_.empty()) sodium_memzero(plain_.data(), plain_.size());
}

bool RSAStreamDecryptor::begin(ByteSource& in,
                               const unsigned char* rsa_n, size_t n_len,
                               const unsigned char* rsa_e, size_t e_len,
                               const unsigned char* rsa_d, size_t d_len,
                               const unsigned char* rsa_p, size_t p_len,
                               const unsigned char* rsa_q, size_t q_len,
                               std::string& error) {
#ifndef PKCRYPT_HAS_OPENSSL
    (void)in; (void)rsa_n; (void)n_len; (void)rsa_e; (void)e_len;
    (void)rsa_d; (void)d_len; (void)rsa_p; (void)p_len; (void)rsa_q; (void)q_len;
    error = "this build lacks OpenSSL; RSA recipient keys are unsupported in the "
            "C++ binary (the Python CLI supports them, and Ed25519 still works)";
    return false;
#else
    unsigned char prefix[MAGIC_BYTES + CIPHER_BYTES + PAYLOAD_BYTES + RSA_ALG_BYTES];
    long long got = read_full(in, prefix, sizeof prefix, error);
    if (got < 0) return false;
    if (got < static_cast<long long>(MAGIC_BYTES) ||
        std::memcmp(prefix, PKCRYPT_MAGIC_RSA, MAGIC_BYTES) != 0) {
        error = "not an RSA PKCrypt file (bad header)";
        return false;
    }
    if (got < static_cast<long long>(sizeof prefix)) { error = "encrypted payload too short or corrupt"; return false; }
    const unsigned char cipher = prefix[MAGIC_BYTES];
    payload_type_ = prefix[MAGIC_BYTES + CIPHER_BYTES];
    const unsigned char alg = prefix[MAGIC_BYTES + CIPHER_BYTES + PAYLOAD_BYTES];
    if (alg != RSA_ALG_OAEP_SHA256) { error = "unsupported RSA algorithm"; return false; }
    if (cipher == CIPHER_AES) { is_aes_ = true; nonce_len_ = NONCE_BYTES_AES; }
    else if (cipher == CIPHER_XCHACHA20) { is_aes_ = false; nonce_len_ = NONCE_BYTES_XC; }
    else { error = "unsupported cipher"; return false; }
    if (payload_type_ != PAYLOAD_FILE && payload_type_ != PAYLOAD_ARCHIVE) { error = "unsupported payload type"; return false; }

    const size_t modulus_bytes = n_len;   // the encrypting key's modulus size
    unsigned char rest[4096 / 8 * 2 + NONCE_BYTES_XC + CHUNK_LEN_BYTES];
    if (modulus_bytes > sizeof rest) { error = "RSA key too large"; return false; }
    const size_t rest_len = modulus_bytes + nonce_len_ + CHUNK_LEN_BYTES;
    got = read_full(in, rest, rest_len, error);
    if (got < 0) return false;
    if (got < static_cast<long long>(rest_len)) { error = "encrypted payload too short or corrupt"; return false; }
    const unsigned char* wrapped = rest;
    const unsigned char* base_nonce = rest + modulus_bytes;
    uint32_t chunk_len;
    read_be32(rest + modulus_bytes + nonce_len_, chunk_len);
    if (chunk_len == 0) { error = "invalid chunk size in header"; return false; }
    if (chunk_len > MAX_ACCEPTED_CHUNK_LEN) { error = "chunk size in header too large (limit 16 MiB)"; return false; }
    chunk_len_ = chunk_len;
    if (is_aes_ && !aes256gcm_ready(error)) return false;

    EVP_PKEY* privkey = rsa_pkey_from_components(rsa_n, n_len, rsa_e, e_len,
                                                 rsa_d, d_len, rsa_p, p_len, rsa_q, q_len);
    if (!privkey) { error = "malformed RSA private key"; return false; }
    std::vector<unsigned char> sess = rsa_oaep_decrypt(privkey, wrapped, modulus_bytes);
    EVP_PKEY_free(privkey);
    if (sess.size() != KEY_BYTES) { error = DECRYPT_FAILED; return false; }

    std::memcpy(key_, sess.data(), KEY_BYTES);
    sodium_memzero(sess.data(), sess.size());
    std::memcpy(base_nonce_, base_nonce, nonce_len_);
    aad_.assign(prefix, prefix + sizeof prefix);
    aad_.insert(aad_.end(), rest, rest + rest_len);
    aad_.push_back(FLAG_MORE);
    in_ = &in;
    index_ = 0;
    return true;
#endif
}

bool RSAStreamDecryptor::run(ByteSink& out, std::string& error, bool salvage) {
    if (!in_) { error = "decryptor is not active"; return false; }
    const size_t block = chunk_len_ + TAG_BYTES;
    plain_.resize(chunk_len_ + 1);
    auto read_block = [&](std::vector<unsigned char>& buf) {
        buf.resize(block);
        long long got = read_full(*in_, buf.data(), block, error);
        if (got < 0) return false;
        buf.resize(static_cast<size_t>(got));
        return true;
    };

    std::vector<unsigned char> cur, next;
    bool ok = read_block(cur);
    while (ok) {
        if (cur.size() < block) break;
        if (!(ok = read_block(next))) break;
        if (next.empty()) break;
        if (!(ok = open(cur, false, out, error))) break;
        cur.swap(next);
    }
    if (ok) {
        ok = open(cur, true, out, error);
        if (!ok && salvage && cur.size() == block) {
            std::string ignored;
            open(cur, false, out, ignored);
        }
    }
    in_ = nullptr;
    wipe();
    return ok;
}

bool RSAStreamDecryptor::open(const std::vector<unsigned char>& ct, bool final, ByteSink& out,
                              std::string& error) {
    if (ct.size() < TAG_BYTES) { error = "encrypted payload truncated or corrupt"; return false; }
    if (index_ >= MAX_CHUNKS) { error = "encrypted payload has too many chunks"; return false; }
    unsigned char nonce[NONCE_BYTES_XC];
    chunk_nonce(base_nonce_, nonce_len_, static_cast<uint32_t>(index_), nonce);
    aad_.back() = final ? FLAG_FINAL : FLAG_MORE;
    unsigned long long pt_len = 0;
    if (aead_decrypt(is_aes_, plain_.data(), &pt_len, ct.data(), ct.size(), aad_, nonce,
                     key_) != 0) {
        error = DECRYPT_FAILED;
        return false;
    }
    ++index_;
    bool ok = out.write(plain_.data(), static_cast<size_t>(pt_len), error);
    sodium_memzero(plain_.data(), static_cast<size_t>(pt_len));
    return ok;
}

} // namespace pkcrypt

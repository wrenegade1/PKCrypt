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

} // namespace pkcrypt

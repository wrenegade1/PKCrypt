// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//

#include "pkcrypt/ssh_key.h"

#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <cstring>
#include <cstdint>
#include <algorithm>

// Own base64 decoder (see base64.cpp), verified against the reference.
#include "pkcrypt/base64.h"
// bcrypt_pbkdf (OpenSSH's private-key KDF) and AES-CTR, for decrypting
// passphrase-protected keys.
#include "pkcrypt/bcrypt_pbkdf.h"
#include "pkcrypt/aes_ctr.h"

#include <sodium.h>

namespace pkcrypt {

namespace {

// ---- Minimal byte helpers for reading OpenSSH wire-format fields -----------

class Reader {
public:
    explicit Reader(std::vector<unsigned char> data) : data_(std::move(data)) {}

    // Read from an existing buffer (no copy); the buffer must outlive this.
    Reader(const unsigned char* data, size_t len)
        : data_(data, data + len) {}

    // Read a big-endian 4-byte integer.
    bool read_u32(uint32_t& out) {
        if (pos_ + 4 > data_.size()) return false;
        out = (static_cast<uint32_t>(data_[pos_]) << 24) |
              (static_cast<uint32_t>(data_[pos_+1]) << 16) |
              (static_cast<uint32_t>(data_[pos_+2]) << 8) |
              (static_cast<uint32_t>(data_[pos_+3]));
        pos_ += 4;
        return true;
    }

    // Reads a length-prefixed byte string.
    bool read_string(std::vector<unsigned char>& out) {
        uint32_t len;
        if (!read_u32(len)) return false;
        if (pos_ + len > data_.size()) return false;
        out.assign(data_.begin() + pos_, data_.begin() + pos_ + len);
        pos_ += len;
        return true;
    }

    // Reads exactly n bytes into dst.
    bool read_bytes(unsigned char* dst, size_t n) {
        if (pos_ + n > data_.size()) return false;
        std::memcpy(dst, data_.data() + pos_, n);
        pos_ += n;
        return true;
    }

    // Reads an OpenSSH "mpint" (length-prefixed signed big-endian integer),
    // returning the raw bytes (sign byte, if any, included).
    bool read_mpint(std::vector<unsigned char>& out) {
        return read_string(out);
    }

    // Remaining bytes (used to sanity-check trailing data).
    bool has_left(size_t n = 1) const { return pos_ + n <= data_.size(); }

private:
    std::vector<unsigned char> data_;
    size_t pos_ = 0;
};

// OpenSSH keys use the standard base64 alphabet. The public key token has no
// newlines; the private key armor may be wrapped across lines. pkcrypt::base64_decode
// handles whitespace stripping internally, so we call it directly.

// Extract the base64 token and the "ssh-ed25519" type from an OpenSSH public key line.
bool parse_public_line(const std::string& line, std::vector<unsigned char>& raw,
                       std::string& error) {
    std::istringstream iss(line);
    std::string type, b64;
    iss >> type >> b64;
    if (b64.empty()) {
        error = "public key file did not contain an ssh-ed25519 key line";
        return false;
    }
    if (!base64_decode(b64, raw) || raw.empty()) {
        error = "public key base64 data is malformed";
        return false;
    }
    return true;
}

bool decode_public_blob(const std::vector<unsigned char>& raw, unsigned char pk[32],
                        std::string& error) {
    Reader r(raw);
    std::vector<unsigned char> type_str;
    if (!r.read_string(type_str)) { error = "public key blob too short"; return false; }
    std::string type(type_str.begin(), type_str.end());
    if (type != "ssh-ed25519") {
        error = "unsupported key type '" + type + "' (expected ssh-ed25519)";
        return false;
    }
    std::vector<unsigned char> pk_blob;
    if (!r.read_string(pk_blob)) { error = "public key blob missing key material"; return false; }
    if (pk_blob.size() != 32) { error = "ed25519 public key must be 32 bytes"; return false; }
    std::memcpy(pk, pk_blob.data(), 32);
    return true;
}

bool parse_private_pem(const std::string& content, std::vector<unsigned char>& raw,
                       std::string& error) {
    const std::string begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const std::string end   = "-----END OPENSSH PRIVATE KEY-----";
    size_t s = content.find(begin);
    if (s == std::string::npos) {
        error = "not an OpenSSH private key (missing BEGIN marker; PEM/RSA keys are unsupported)";
        return false;
    }
    size_t e = content.find(end, s + begin.size());
    if (e == std::string::npos) {
        error = "malformed OpenSSH private key (missing END marker)";
        return false;
    }
    std::string b64 = content.substr(s + begin.size(), e - (s + begin.size()));
    return base64_decode(b64, raw);
}

// The cipher's key and IV lengths; -1 for an unsupported symmetric cipher.
// (the modern `ssh-keygen` default is aes256-ctr).
int cipher_key_len(const std::string& name) {
    if (name == "aes128-ctr") return 16;
    if (name == "aes192-ctr") return 24;
    if (name == "aes256-ctr") return 32;
    return -1;
}

// Decrypt an OpenSSH private blob encrypted with a passphrase (OpenSSH's
// "openssh-key-v1" format: cipher + bcrypt KDF + encrypted private blob).
// `cipher` and `kdf` (with its bytes) and `kdfopts` were read from the header.
// On success the private blob is decrypted into `plain` and returns true.
//
// Currently supports cipher "aes128-ctr"/"aes192-ctr"/"aes256-ctr" with the
// "bcrypt" KDF (the modern default for `ssh-keygen -t ed25519`). Returns false
// with `error` otherwise. The recovered plaintext is what OpenSSH stores
// unencrypted for a non-passphrase key, and is wiped before returning.
bool decrypt_encrypted_blob(const std::string& cipher_name,
                            const std::string& kdf_name,
                            const std::vector<unsigned char>& kdfopts,
                            const char* passphrase,
                            const std::vector<unsigned char>& priv_blob,
                            std::vector<unsigned char>& plain, std::string& error) {
    const int key_len = cipher_key_len(cipher_name);
    if (key_len < 0) {
        error = "unsupported key cipher '" + cipher_name + "' (this build supports "
                "aes128/192/256-ctr from OpenSSH; the Python CLI handles other ciphers)";
        return false;
    }
    if (kdf_name != "bcrypt") {
        error = "unsupported key KDF '" + kdf_name + "'";
        return false;
    }
    if (passphrase == nullptr) {
        error = "private key is passphrase protected; supply --passphrase";
        return false;
    }
    // kdfopts for bcrypt: a length-prefixed 16-byte salt, then 4-byte rounds.
    Reader kr(kdfopts);
    std::vector<unsigned char> salt;
    if (!kr.read_string(salt) || salt.size() != 16) {
        error = "malformed key: bcrypt KDF options";
        return false;
    }
    uint32_t rounds_u32;
    if (!kr.read_u32(rounds_u32)) {
        error = "malformed key: bcrypt KDF options";
        return false;
    }

    // Derive key+iv: bcrypt_pbkdf(passphrase, salt, key_len + iv_len, rounds).
    // IV is 16 bytes for every AES-CTR variant.
    const size_t iv_len = 16;
    std::vector<unsigned char> ky(key_len + iv_len);
    if (!bcrypt_pbkdf(passphrase, std::strlen(passphrase), salt.data(), salt.size(),
                      ky.data(), ky.size(), rounds_u32)) {
        sodium_memzero(ky.data(), ky.size());
        error = "bcrypt KDF failed";
        return false;
    }

    std::vector<unsigned char> out(priv_blob.size());
    const bool ok = aes_ctr_crypt(ky.data(), static_cast<size_t>(key_len),
                                  ky.data() + key_len, priv_blob.data(),
                                  out.data(), priv_blob.size());
    sodium_memzero(ky.data(), ky.size());
    if (!ok) {
        error = "AES decryption of private key failed";
        return false;
    }
    plain = std::move(out);
    return true;
}

} // namespace

std::optional<Ed25519Key> parse_ssh_public_key_file(const std::string& path,
                                                    std::string& error) {
    std::ifstream f(path);
    if (!f.is_open()) { error = "cannot open public key file: " + path; return std::nullopt; }
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());

    // The public key is normally a single line; take everything up to the first newline.
    size_t nl = content.find_first_of("\r\n");
    std::string line = (nl == std::string::npos) ? content : content.substr(0, nl);

    std::vector<unsigned char> raw;
    if (!parse_public_line(line, raw, error)) return std::nullopt;

    Ed25519Key key;
    if (!decode_public_blob(raw, key.public_key, error)) return std::nullopt;
    key.has_private = false;
    return key;
}

std::optional<Ed25519Key> parse_ssh_private_key_file(const std::string& path,
                                                     std::string& error,
                                                     const char* passphrase) {
    std::ifstream f(path);
    if (!f.is_open()) { error = "cannot open private key file: " + path; return std::nullopt; }
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());

    std::vector<unsigned char> raw;
    if (!parse_private_pem(content, raw, error)) return std::nullopt;

    Reader r(raw);

    // Magic is a fixed 15-byte string: "openssh-key-v1\0".
    unsigned char magic_buf[15];
    if (!r.read_bytes(magic_buf, 15)) { error = "private key blob too short"; return std::nullopt; }
    if (std::memcmp(magic_buf, "openssh-key-v1", 15) != 0) {
        error = "unrecognized key header (not openssh-key-v1)";
        return std::nullopt;
    }

    std::vector<unsigned char> cipher, kdf, kdfopts;
    if (!r.read_string(cipher)) { error = "malformed key: ciphername"; return std::nullopt; }
    if (!r.read_string(kdf))    { error = "malformed key: kdfname";    return std::nullopt; }
    if (!r.read_string(kdfopts)){ error = "malformed key: kdf options";return std::nullopt; }
    std::string cipher_name(cipher.begin(), cipher.end());
    std::string kdf_name(kdf.begin(), kdf.end());

    uint32_t nkeys;
    if (!r.read_u32(nkeys)) { error = "malformed key: key count"; return std::nullopt; }
    if (nkeys != 1) {
        error = "expected exactly 1 key in file (found " + std::to_string(nkeys) + ")";
        return std::nullopt;
    }

    // Public key blob (top-level; skip, but we can validate type from it).
    std::vector<unsigned char> pub_blob;
    if (!r.read_string(pub_blob)) { error = "malformed key: public blob"; return std::nullopt; }

    // Private key blob. With a passphrase this is encrypted; decrypt it (and
    // wipe the encrypted buffer) before parsing.
    std::vector<unsigned char> priv_blob;
    if (!r.read_string(priv_blob)) { error = "malformed key: private blob"; return std::nullopt; }
    std::vector<unsigned char> priv_plain;
    const unsigned char* priv_data = priv_blob.data();
    size_t priv_size = priv_blob.size();
    if (cipher_name != "none" || kdf_name != "none") {
        if (!decrypt_encrypted_blob(cipher_name, kdf_name, kdfopts, passphrase,
                                    priv_blob, priv_plain, error)) {
            sodium_memzero(priv_blob.data(), priv_blob.size());
            return std::nullopt;
        }
        priv_data = priv_plain.data();
        priv_size = priv_plain.size();
        sodium_memzero(priv_blob.data(), priv_blob.size());
    }

    Reader pr(priv_data, priv_size);
    uint32_t check1, check2;
    if (!pr.read_u32(check1)) { error = "malformed private key"; return std::nullopt; }
    if (!pr.read_u32(check2)) { error = "malformed private key"; return std::nullopt; }
    if (check1 != check2) {
        error = "private key integrity check failed (passphrase encrypted?)";
        return std::nullopt;
    }

    // The private key blob is: checkint1, checkint2, keytype, publickey,
    // privatekey(seed||pub), comment, padding. Read and verify keytype first.
    std::vector<unsigned char> keytype;
    if (!pr.read_string(keytype)) { error = "malformed private key: keytype"; return std::nullopt; }
    std::string keytype_str(keytype.begin(), keytype.end());
    if (keytype_str != "ssh-ed25519") {
        error = "unsupported private key type '" + keytype_str + "' (expected ssh-ed25519)";
        return std::nullopt;
    }

    // Read the embedded public key. It is stored as the raw 32-byte Ed25519
    // public key (not a full "ssh-ed25519" blob) in modern OpenSSH, so copy
    // the bytes directly.
    std::vector<unsigned char> embedded_pub;
    if (!pr.read_string(embedded_pub)) { error = "malformed private key: embedded pub"; return std::nullopt; }
    if (embedded_pub.size() != 32) {
        error = "embedded public key must be 32 bytes (got " +
                std::to_string(embedded_pub.size()) + ")";
        return std::nullopt;
    }

    Ed25519Key key;
    std::memcpy(key.public_key, embedded_pub.data(), 32);

    // Now the private key seed. OpenSSH stores a 64-byte field consisting of a
    // 32-byte seed followed by a redundant 32-byte copy of the public key.
    std::vector<unsigned char> priv_raw;
    if (!pr.read_string(priv_raw)) { error = "malformed private key: seed"; return std::nullopt; }
    if (priv_raw.size() != 64) {
        error = "ed25519 private key field must be 64 bytes (got " +
                std::to_string(priv_raw.size()) + ")";
        return std::nullopt;
    }

    // Consistency check: the redundant public-key copy stored alongside the
    // seed must match the embedded public key. This confirms the key file is
    // internally consistent (the seed belongs to this public key).
    if (std::memcmp(priv_raw.data() + 32, embedded_pub.data(), 32) != 0) {
        error = "private key is inconsistent (seed does not match public key)";
        return std::nullopt;
    }

    std::memcpy(key.private_key, priv_raw.data(), 32);
    key.has_private = true;

    // Wipe the raw seed/key material from temporary buffers before returning.
    sodium_memzero(priv_raw.data(), priv_raw.size());
    if (!priv_plain.empty()) sodium_memzero(priv_plain.data(), priv_plain.size());
    sodium_memzero(raw.data(), raw.size());
    return key;
}

// ---------------------------------------------------------------------------
// RSA keys
// ---------------------------------------------------------------------------

// Strip the mpint sign byte (a leading 0x00 OpenSSH prepends when the most
// significant bit is set, which is always true of an RSA modulus).
void strip_sign(std::vector<unsigned char>& v) {
    size_t i = 0;
    while (i < v.size() && v[i] == 0) ++i;
    if (i == 0) return;
    if (i == v.size()) { v.clear(); return; }
    v.erase(v.begin(), v.begin() + i);
}

// Reject malformed RSA public numbers before encrypting to them - the same
// checks Python's `cryptography` applies when loading a key: n odd, e odd,
// 3 <= e < n. A bogus key such as e = 1 makes RSA-OAEP the identity, so the
// "wrapped" session key would be readable by anyone. Inputs are big-endian.
bool rsa_public_numbers_ok(const unsigned char* n, size_t n_len,
                           const unsigned char* e, size_t e_len, std::string& error) {
    while (n_len > 0 && n[0] == 0) { ++n; --n_len; }
    while (e_len > 0 && e[0] == 0) { ++e; --e_len; }
    const auto bad = [&] { error = "invalid RSA public key (bad exponent or modulus)"; return false; };
    if (n_len == 0 || e_len == 0) return bad();
    if ((n[n_len - 1] & 1) == 0 || (e[e_len - 1] & 1) == 0) return bad();     // both odd
    if (e_len == 1 && e[0] < 3) return bad();                                   // e >= 3
    if (e_len > n_len || (e_len == n_len && std::memcmp(e, n, n_len) >= 0)) return bad();  // e < n
    return true;
}

std::optional<RsaKey> parse_ssh_rsa_public_key_file(const std::string& path,
                                                    std::string& error) {
    std::ifstream f(path);
    if (!f.is_open()) { error = "cannot open public key file: " + path; return std::nullopt; }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t nl = content.find_first_of("\r\n");
    std::string line = (nl == std::string::npos) ? content : content.substr(0, nl);
    std::istringstream iss(line);
    std::string type, b64;
    iss >> type >> b64;
    if (type != "ssh-rsa") {
        error = "expected an ssh-rsa public key (got '" + type + "')";
        return std::nullopt;
    }
    std::vector<unsigned char> raw;
    if (!base64_decode(b64, raw) || raw.empty()) {
        error = "public key base64 data is malformed";
        return std::nullopt;
    }
    Reader r(raw);
    std::vector<unsigned char> type_str;
    if (!r.read_string(type_str) || std::string(type_str.begin(), type_str.end()) != "ssh-rsa") {
        error = "malformed RSA public key (bad type)";
        return std::nullopt;
    }
    RsaKey key;
    if (!r.read_mpint(key.e) || !r.read_mpint(key.n)) {
        error = "malformed RSA public key";
        return std::nullopt;
    }
    strip_sign(key.e);
    strip_sign(key.n);
    if (key.n.empty() || key.n.size() < 256) {
        error = "RSA public key too small (need at least 2048 bits)";
        return std::nullopt;
    }
    if (!rsa_public_numbers_ok(key.n.data(), key.n.size(), key.e.data(), key.e.size(), error)) {
        return std::nullopt;
    }
    return key;
}

std::optional<RsaKey> parse_ssh_rsa_private_key_file(const std::string& path,
                                                     std::string& error,
                                                     const char* passphrase) {
    std::ifstream f(path);
    if (!f.is_open()) { error = "cannot open private key file: " + path; return std::nullopt; }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::vector<unsigned char> raw;
    if (!parse_private_pem(content, raw, error)) return std::nullopt;

    Reader r(raw);
    unsigned char magic_buf[15];
    if (!r.read_bytes(magic_buf, 15) || std::memcmp(magic_buf, "openssh-key-v1", 15) != 0) {
        sodium_memzero(raw.data(), raw.size());
        error = "unrecognized key header (not openssh-key-v1)";
        return std::nullopt;
    }
    std::vector<unsigned char> cipher, kdf, kdfopts;
    if (!r.read_string(cipher) || !r.read_string(kdf) || !r.read_string(kdfopts)) {
        sodium_memzero(raw.data(), raw.size());
        error = "malformed key header";
        return std::nullopt;
    }
    std::string cipher_name(cipher.begin(), cipher.end());
    std::string kdf_name(kdf.begin(), kdf.end());
    uint32_t nkeys;
    if (!r.read_u32(nkeys) || nkeys != 1) {
        sodium_memzero(raw.data(), raw.size());
        error = "expected exactly 1 key in file";
        return std::nullopt;
    }
    std::vector<unsigned char> pub_blob, priv_blob;
    if (!r.read_string(pub_blob) || !r.read_string(priv_blob)) {
        sodium_memzero(raw.data(), raw.size());
        error = "malformed key: key blob";
        return std::nullopt;
    }
    (void)pub_blob;

    std::vector<unsigned char> priv_plain;
    const unsigned char* priv_data = priv_blob.data();
    size_t priv_size = priv_blob.size();
    if (cipher_name != "none" || kdf_name != "none") {
        if (!decrypt_encrypted_blob(cipher_name, kdf_name, kdfopts, passphrase,
                                    priv_blob, priv_plain, error)) {
            sodium_memzero(priv_blob.data(), priv_blob.size());
            sodium_memzero(raw.data(), raw.size());
            return std::nullopt;
        }
        priv_data = priv_plain.data();
        priv_size = priv_plain.size();
        sodium_memzero(priv_blob.data(), priv_blob.size());
    }

    Reader pr(priv_data, priv_size);
    uint32_t check1, check2;
    if (!pr.read_u32(check1) || !pr.read_u32(check2) || check1 != check2) {
        if (!priv_plain.empty()) sodium_memzero(priv_plain.data(), priv_plain.size());
        sodium_memzero(raw.data(), raw.size());
        error = "private key integrity check failed (passphrase encrypted?)";
        return std::nullopt;
    }
    std::vector<unsigned char> keytype;
    if (!pr.read_string(keytype) || std::string(keytype.begin(), keytype.end()) != "ssh-rsa") {
        if (!priv_plain.empty()) sodium_memzero(priv_plain.data(), priv_plain.size());
        sodium_memzero(raw.data(), raw.size());
        error = "unsupported private key type (expected ssh-rsa)";
        return std::nullopt;
    }

    RsaKey key;
    std::vector<unsigned char> iqmp;
    if (!pr.read_mpint(key.n) || !pr.read_mpint(key.e) || !pr.read_mpint(key.d) ||
        !pr.read_mpint(iqmp) || !pr.read_mpint(key.p) || !pr.read_mpint(key.q)) {
        if (!priv_plain.empty()) sodium_memzero(priv_plain.data(), priv_plain.size());
        sodium_memzero(raw.data(), raw.size());
        error = "malformed RSA private key material";
        return std::nullopt;
    }
    strip_sign(key.n); strip_sign(key.e); strip_sign(key.d);
    strip_sign(key.p); strip_sign(key.q); strip_sign(iqmp);
    key.has_private = true;
    sodium_memzero(iqmp.data(), iqmp.size());

    if (!priv_plain.empty()) sodium_memzero(priv_plain.data(), priv_plain.size());
    sodium_memzero(raw.data(), raw.size());
    return key;
}

} // namespace pkcrypt

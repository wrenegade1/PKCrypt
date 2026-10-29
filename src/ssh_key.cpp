#include "pkcrypt/ssh_key.h"

#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <cstring>
#include <cstdint>
#include <algorithm>

// Base64 decoding: see base64.h.
#include "pkcrypt/base64.hpp"

namespace pkcrypt {

namespace {

// ---- Minimal byte helpers for reading OpenSSH wire-format fields -----------

class Reader {
public:
    explicit Reader(std::vector<unsigned char> data) : data_(std::move(data)) {}

    // Reads a big-endian 4-byte integer.
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

private:
    std::vector<unsigned char> data_;
    size_t pos_ = 0;
};

// OpenSSH keys have base64 with standard alphabet. The public key token has no
// newlines; the private key armor may be wrapped across lines, so strip ASCII
// whitespace before decoding.
bool base64_decode(const std::string& in, std::vector<unsigned char>& out) {
    std::string compact;
    compact.reserve(in.size());
    for (char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        compact.push_back(c);
    }
    try {
        std::string decoded = base64::from_base64(compact);
        out.assign(decoded.begin(), decoded.end());
        return true;
    } catch (const std::runtime_error&) {
        return false;
    }
}

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
                                                     std::string& error) {
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
    if (cipher_name != "none" || kdf_name != "none") {
        error = "encrypted/passphrase-protected private keys are not supported; "
                "decrypt first with: ssh-keygen -p -f <keyfile> -N \"\"";
        return std::nullopt;
    }

    uint32_t nkeys;
    if (!r.read_u32(nkeys)) { error = "malformed key: key count"; return std::nullopt; }
    if (nkeys != 1) {
        error = "expected exactly 1 key in file (found " + std::to_string(nkeys) + ")";
        return std::nullopt;
    }

    // Public key blob (top-level; skip, but we can validate type from it).
    std::vector<unsigned char> pub_blob;
    if (!r.read_string(pub_blob)) { error = "malformed key: public blob"; return std::nullopt; }

    // Private key blob.
    std::vector<unsigned char> priv_blob;
    if (!r.read_string(priv_blob)) { error = "malformed key: private blob"; return std::nullopt; }

    Reader pr(priv_blob);
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
    std::memcpy(key.private_key, priv_raw.data(), 32);

    key.has_private = true;
    return key;
}

} // namespace pkcrypt

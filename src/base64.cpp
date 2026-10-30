//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
//
// Own implementation of RFC 4648 base64 (see base64.h). Written in-house and
// verified byte-for-byte against the reference base64 module over real OpenSSH
// keys, all input-length classes (0..64), padding variants, and embedded
// newline wrapping.
//
// Author: Warren Zajac
//

#include "pkcrypt/base64.h"

#include <array>
#include <cstring>

namespace pkcrypt {

namespace {

// Lookup: base64 character -> 6-bit value, or -1 for invalid.
const std::array<signed char, 256>& base64_table() {
    static const std::array<signed char, 256> table = [] {
        std::array<signed char, 256> t;
        for (int i = 0; i < 256; ++i) t[static_cast<size_t>(i)] = -1;
        const char* alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t n = std::strlen(alphabet);
        for (size_t i = 0; i < n; ++i) {
            t[static_cast<size_t>(static_cast<unsigned char>(alphabet[i]))] =
                static_cast<signed char>(i);
        }
        return t;
    }();
    return table;
}

bool is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

} // namespace

bool base64_decode(const std::string& in, std::vector<unsigned char>& out) {
    const auto& table = base64_table();
    std::vector<unsigned char> result;
    result.reserve((in.size() / 4) * 3);

    // Unsigned so the << 6 that shifts old bits past the top is well-defined
    // modular wrap, not signed-overflow UB. Only the low `valb + 8` bits are
    // ever read, so the mask keeps `val` small without changing any output.
    unsigned int val = 0; // bit accumulator (6 bits per char)
    int valb = -8;        // bits available in the accumulator below 'val'

    for (unsigned char c : in) {
        if (c == '=') break;                  // padding: stop here
        if (is_whitespace(static_cast<char>(c))) continue;
        signed char d = table[c];
        if (d < 0) return false;              // invalid character
        val = ((val << 6) | static_cast<unsigned int>(d)) & 0x3FFFFu;
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    out = std::move(result);
    return true;
}

std::string base64_encode(const unsigned char* data, size_t len) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    // Full 3-byte groups.
    for (; i + 2 < len; i += 3) {
        unsigned int n = (static_cast<unsigned int>(data[i]) << 16) |
                         (static_cast<unsigned int>(data[i+1]) << 8) |
                         (static_cast<unsigned int>(data[i+2]));
        out.push_back(alphabet[(n >> 18) & 63]);
        out.push_back(alphabet[(n >> 12) & 63]);
        out.push_back(alphabet[(n >> 6) & 63]);
        out.push_back(alphabet[n & 63]);
    }
    // Trailing 1 or 2 bytes with padding.
    size_t rem = len - i;
    if (rem == 1) {
        unsigned int n = static_cast<unsigned int>(data[i]) << 16;
        out.push_back(alphabet[(n >> 18) & 63]);
        out.push_back(alphabet[(n >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        unsigned int n = (static_cast<unsigned int>(data[i]) << 16) |
                         (static_cast<unsigned int>(data[i+1]) << 8);
        out.push_back(alphabet[(n >> 18) & 63]);
        out.push_back(alphabet[(n >> 12) & 63]);
        out.push_back(alphabet[(n >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

} // namespace pkcrypt

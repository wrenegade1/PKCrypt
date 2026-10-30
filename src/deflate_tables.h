#ifndef PKCRYPT_DEFLATE_TABLES_H
#define PKCRYPT_DEFLATE_TABLES_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//
// Constants from RFC 1951 shared by the DEFLATE compressor and decompressor.
// Internal to src/; not part of the public headers.
//

#include <cstdint>

namespace pkcrypt {
namespace deflate_tables {

constexpr int NUM_LITLEN = 286;     // literal/length symbols actually used
constexpr int NUM_DIST = 30;        // distance symbols actually used
constexpr int NUM_CODELEN = 19;     // code-length alphabet
constexpr int MAX_BITS = 15;        // longest literal/length or distance code
constexpr int MAX_CL_BITS = 7;      // longest code-length code
constexpr int END_OF_BLOCK = 256;

// Length symbols 257..285: base match length and number of extra bits.
constexpr uint16_t LEN_BASE[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr uint8_t LEN_EXTRA[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};

// Distance symbols 0..29: base distance and number of extra bits.
constexpr uint16_t DIST_BASE[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
    16385, 24577};
constexpr uint8_t DIST_EXTRA[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

// Order in which code-length code lengths are transmitted.
constexpr uint8_t CODELEN_ORDER[NUM_CODELEN] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// Fixed Huffman code lengths (block type 01) for literal/length symbol `sym`.
constexpr uint8_t fixed_litlen_length(int sym) {
    return sym < 144 ? 8 : sym < 256 ? 9 : sym < 280 ? 7 : 8;
}
constexpr uint8_t FIXED_DIST_LENGTH = 5;

// Reverse the low `len` bits of `code`: Huffman codes are defined MSB-first
// but DEFLATE packs bits LSB-first.
inline uint32_t reverse_bits(uint32_t code, int len) {
    uint32_t r = 0;
    for (int i = 0; i < len; ++i) {
        r = (r << 1) | (code & 1);
        code >>= 1;
    }
    return r;
}

} // namespace deflate_tables
} // namespace pkcrypt

#endif // PKCRYPT_DEFLATE_TABLES_H

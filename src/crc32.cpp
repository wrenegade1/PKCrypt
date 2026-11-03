// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//
// CRC-32 (IEEE 802.3) with the reflected polynomial 0xEDB88320, computed a
// byte at a time from a 256-entry table built on first use.
//

#include "pkcrypt/deflate.h"

#include <array>

namespace pkcrypt {

namespace {

std::array<uint32_t, 256> make_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t n = 0; n < 256; ++n) {
        uint32_t c = n;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        table[n] = c;
    }
    return table;
}

} // namespace

uint32_t crc32(const unsigned char* data, size_t len, uint32_t crc) {
    static const std::array<uint32_t, 256> table = make_table();
    crc = ~crc;
    for (size_t i = 0; i < len; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

} // namespace pkcrypt

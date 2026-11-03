// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
#ifndef PKCRYPT_DEFLATE_H
#define PKCRYPT_DEFLATE_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//
// In-house implementations of CRC-32 and raw DEFLATE (RFC 1951), as used by
// the ZIP format. No third-party code: written from the published specs.
//

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "pkcrypt/stream.h"

namespace pkcrypt {

// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), as used by ZIP and
// zlib. Pass the previous result as `crc` to continue a running checksum.
uint32_t crc32(const unsigned char* data, size_t len, uint32_t crc = 0);

// Streaming raw DEFLATE compressor (no zlib/gzip wrapper). Uses LZ77 with
// hash chains and lazy matching, and chooses per block between dynamic
// Huffman, fixed Huffman, and stored encoding, whichever is smallest. Memory
// use is bounded (a few MiB) however much input is written.
class DeflateStream {
public:
    DeflateStream();
    ~DeflateStream();
    DeflateStream(const DeflateStream&) = delete;
    DeflateStream& operator=(const DeflateStream&) = delete;

    // Compress `n` more input bytes; compressed output is appended to `out`.
    void write(const unsigned char* data, size_t n, std::vector<unsigned char>& out);
    // End the stream: compress what remains and append the final block.
    void finish(std::vector<unsigned char>& out);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Compress `len` bytes in one call.
std::vector<unsigned char> deflate_compress(const unsigned char* data, size_t len);

// Decompress a raw DEFLATE stream read from `in`, writing the output to `out`
// as it is produced (memory use is bounded by the 32 KiB window plus small
// buffers). Fails (returns false, sets `error`) if the stream is malformed or
// truncated, if it would produce more than `max_out` bytes, or if `in` holds
// anything after the final block - unless `consumed` is given: then data after
// the stream is allowed (some may have been read ahead) and `*consumed` is set
// to the stream's exact length in bytes, so a caller can find what follows.
bool inflate_stream(ByteSource& in, uint64_t max_out, ByteSink& out, std::string& error,
                    uint64_t* consumed = nullptr);

// Decompress an in-memory stream in one call.
bool inflate(const unsigned char* in, size_t in_len, size_t max_out,
             std::vector<unsigned char>& out, std::string& error);

} // namespace pkcrypt

#endif // PKCRYPT_DEFLATE_H

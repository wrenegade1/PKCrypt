// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//
// Streaming raw DEFLATE decompressor (RFC 1951). Input is treated as hostile:
// every read is bounds-checked, back-references may not reach before the start
// of the output, and output may not grow past the caller's `max_out` limit.
//

#include "pkcrypt/deflate.h"
#include "deflate_tables.h"

#include <algorithm>
#include <cstring>

namespace pkcrypt {

using namespace deflate_tables;

namespace {

// LSB-first bit reader pulling input from a ByteSource in buffered blocks.
struct BitReader {
    explicit BitReader(ByteSource& src) : src_(src), in_(64 * 1024) {}

    uint64_t buf = 0;   // loaded bits, next bit in the LSB
    int count = 0;      // number of valid bits in `buf`

    void refill() {
        while (count <= 56) {
            if (pos_ == len_ && !fill()) break;
            buf |= static_cast<uint64_t>(in_[pos_++]) << count;
            count += 8;
        }
    }

    // Read `n` (<= 32) bits. Returns false if the input is exhausted.
    bool bits(int n, uint32_t& value) {
        if (count < n) refill();
        if (count < n) return false;
        value = static_cast<uint32_t>(buf & ((uint64_t{1} << n) - 1));
        buf >>= n;
        count -= n;
        return true;
    }

    // Discard bits up to the next byte boundary (whole bytes stay buffered).
    void align_to_byte() {
        int drop = count % 8;
        buf >>= drop;
        count -= drop;
    }

    // Read `n` whole bytes (call align_to_byte() first): buffered bits first,
    // then straight from the input.
    bool read_bytes(unsigned char* dst, size_t n) {
        while (n > 0 && count >= 8) {
            *dst++ = static_cast<unsigned char>(buf);
            buf >>= 8;
            count -= 8;
            --n;
        }
        while (n > 0) {
            if (pos_ == len_ && !fill()) return false;
            size_t k = std::min(n, len_ - pos_);
            std::memcpy(dst, in_.data() + pos_, k);
            pos_ += k;
            dst += k;
            n -= k;
        }
        return true;
    }

    // After the final block: is any whole byte of input left?
    bool has_trailing_bytes() {
        align_to_byte();
        return count >= 8 || pos_ < len_ || fill();
    }

    const std::string& source_error() const { return src_error_; }

    // Input bytes used so far, up to the current byte boundary (call
    // align_to_byte() first); bytes read ahead into buffers don't count.
    uint64_t bytes_consumed() const {
        return total_read_ - (len_ - pos_) - static_cast<uint64_t>(count / 8);
    }

private:
    ByteSource& src_;
    std::vector<unsigned char> in_;
    size_t pos_ = 0, len_ = 0;
    uint64_t total_read_ = 0;
    bool eof_ = false;
    std::string src_error_;

    bool fill() {
        if (eof_) return false;
        long long r = src_.read(in_.data(), in_.size(), src_error_);
        if (r <= 0) {
            eof_ = true;
            return false;
        }
        pos_ = 0;
        len_ = static_cast<size_t>(r);
        total_read_ += len_;
        return true;
    }
};

// Output with the 32 KiB history that back-references need. Older bytes are
// flushed to the sink in batches.
class Window {
public:
    Window(ByteSink& sink, uint64_t max_out) : sink_(sink), max_out_(max_out) {
        w_.reserve(FLUSH_AT + 258);
    }

    uint64_t total() const { return total_; }
    bool room_for(uint64_t n) const { return n <= max_out_ - total_; }

    void put(unsigned char c) {
        w_.push_back(c);
        ++total_;
    }

    void put_bytes(const unsigned char* p, size_t n) {
        w_.insert(w_.end(), p, p + n);
        total_ += n;
    }

    // Copy `length` bytes from `distance` back (<= total(), checked by caller).
    // Byte-by-byte: the source may overlap the bytes being written (e.g.
    // distance 1 repeats the previous byte `length` times).
    void copy(size_t distance, size_t length) {
        size_t start = w_.size();
        w_.resize(start + length);
        for (size_t k = 0; k < length; ++k) w_[start + k] = w_[start - distance + k];
        total_ += length;
    }

    bool maybe_flush(std::string& error) {
        return w_.size() < FLUSH_AT || flush_keeping(WINDOW_SIZE, error);
    }

    bool flush_all(std::string& error) { return flush_keeping(0, error); }

private:
    static constexpr size_t WINDOW_SIZE = 32768;
    static constexpr size_t FLUSH_AT = 4 * WINDOW_SIZE;

    ByteSink& sink_;
    uint64_t max_out_;
    uint64_t total_ = 0;
    std::vector<unsigned char> w_;

    bool flush_keeping(size_t keep, std::string& error) {
        if (w_.size() <= keep) return true;
        size_t n = w_.size() - keep;
        if (!sink_.write(w_.data(), n, error)) return false;
        w_.erase(w_.begin(), w_.begin() + static_cast<std::ptrdiff_t>(n));
        return true;
    }
};

// How strictly a code's completeness is checked when building its table.
enum class Completeness {
    Any,            // fixed codes, which are incomplete by definition
    AllowSingle,    // literal/length and distance codes: complete, or exactly
                    // one 1-bit code (RFC 1951 3.2.7 allows a lone distance code)
    Required,       // the code-length code must be complete
};

// Canonical Huffman decoding table: 2^max_len entries, each holding
// (symbol << 4) | code_length. A code_length of 0 marks an unused slot, so a
// bit pattern the code does not define is rejected when decoded.
struct Huffman {
    std::vector<uint16_t> table;
    int max_len = 0;

    // Build from per-symbol code lengths (0 = symbol unused). Returns false for
    // an over-subscribed code, or an incomplete one that `rule` forbids. The
    // rules match zlib's, so both accept and reject exactly the same streams.
    bool build(const uint8_t* lengths, int num_symbols, Completeness rule) {
        int count[MAX_BITS + 1] = {0};
        for (int s = 0; s < num_symbols; ++s) count[lengths[s]]++;
        count[0] = 0;

        max_len = 0;
        int left = 1;
        for (int len = 1; len <= MAX_BITS; ++len) {
            left = (left << 1) - count[len];
            if (left < 0) return false;
            if (count[len]) max_len = len;
        }
        if (left > 0 && max_len > 0 && rule != Completeness::Any &&
            (rule == Completeness::Required || max_len != 1)) {
            return false;
        }

        int next_code[MAX_BITS + 1] = {0};
        int code = 0;
        for (int len = 1; len <= MAX_BITS; ++len) {
            code = (code + count[len - 1]) << 1;
            next_code[len] = code;
        }

        table.assign(size_t{1} << max_len, 0);
        for (int s = 0; s < num_symbols; ++s) {
            int len = lengths[s];
            if (len == 0) continue;
            uint32_t rev = reverse_bits(static_cast<uint32_t>(next_code[len]++), len);
            for (size_t i = rev; i < table.size(); i += size_t{1} << len) {
                table[i] = static_cast<uint16_t>((s << 4) | len);
            }
        }
        return true;
    }

    // Decode one symbol. Returns false on an undefined code or truncated input.
    bool decode(BitReader& br, int& symbol) const {
        br.refill();
        uint16_t entry = table[br.buf & ((uint64_t{1} << max_len) - 1)];
        int len = entry & 15;
        if (len == 0 || len > br.count) return false;
        br.buf >>= len;
        br.count -= len;
        symbol = entry >> 4;
        return true;
    }
};

struct FixedCodes {
    Huffman litlen, dist;
    FixedCodes() {
        uint8_t lens[288];
        for (int s = 0; s < 288; ++s) lens[s] = fixed_litlen_length(s);
        litlen.build(lens, 288, Completeness::Any);
        uint8_t dlens[NUM_DIST];
        std::memset(dlens, FIXED_DIST_LENGTH, sizeof dlens);
        dist.build(dlens, NUM_DIST, Completeness::Any);
    }
};

class Inflater {
public:
    Inflater(ByteSource& in, uint64_t max_out, ByteSink& out, uint64_t* consumed)
        : br_(in), out_(out, max_out), consumed_(consumed) {}

    bool run(std::string& error) {
        static const FixedCodes fixed;
        bool final = false;
        while (!final) {
            uint32_t header;
            if (!br_.bits(3, header)) return fail(error, "truncated block header");
            final = header & 1;
            switch (header >> 1) {
            case 0:
                if (!stored(error)) return false;
                break;
            case 1:
                if (!codes(fixed.litlen, fixed.dist, error)) return false;
                break;
            case 2: {
                Huffman litlen, dist;
                if (!dynamic_tables(litlen, dist, error)) return false;
                if (!codes(litlen, dist, error)) return false;
                break;
            }
            default:
                return fail(error, "invalid block type");
            }
        }
        if (consumed_) {
            br_.align_to_byte();
            *consumed_ = br_.bytes_consumed();
        } else if (br_.has_trailing_bytes()) {
            return fail(error, "trailing data after final block");
        }
        if (!br_.source_error().empty()) return fail(error, "");
        return out_.flush_all(error);
    }

private:
    BitReader br_;
    Window out_;
    uint64_t* consumed_;
    std::string sink_error_;

    // A read error from the source takes precedence over the decoding error
    // it caused (e.g. "truncated").
    bool fail(std::string& error, const char* what) {
        if (!br_.source_error().empty()) {
            error = br_.source_error();
        } else if (!sink_error_.empty()) {
            error = sink_error_;
        } else {
            error = std::string("corrupt compressed data: ") + what;
        }
        return false;
    }

    bool stored(std::string& error) {
        br_.align_to_byte();
        unsigned char hdr[4];
        if (!br_.read_bytes(hdr, 4)) return fail(error, "truncated stored block");
        uint32_t len = hdr[0] | (hdr[1] << 8);
        uint32_t nlen = hdr[2] | (hdr[3] << 8);
        if (len != (~nlen & 0xFFFF)) return fail(error, "stored block length mismatch");
        if (!out_.room_for(len)) return fail(error, "output larger than declared size");
        unsigned char tmp[4096];
        while (len > 0) {
            uint32_t k = std::min<uint32_t>(len, sizeof tmp);
            if (!br_.read_bytes(tmp, k)) return fail(error, "truncated stored block");
            out_.put_bytes(tmp, k);
            len -= k;
            if (!out_.maybe_flush(sink_error_)) return fail(error, "");
        }
        return true;
    }

    bool dynamic_tables(Huffman& litlen, Huffman& dist, std::string& error) {
        uint32_t hlit, hdist, hclen;
        if (!br_.bits(5, hlit) || !br_.bits(5, hdist) || !br_.bits(4, hclen)) {
            return fail(error, "truncated dynamic block header");
        }
        hlit += 257;
        hdist += 1;
        hclen += 4;
        if (hlit > NUM_LITLEN || hdist > NUM_DIST) {
            return fail(error, "too many literal/length or distance codes");
        }

        uint8_t cl_lens[NUM_CODELEN] = {0};
        for (uint32_t i = 0; i < hclen; ++i) {
            uint32_t v;
            if (!br_.bits(3, v)) return fail(error, "truncated code lengths");
            cl_lens[CODELEN_ORDER[i]] = static_cast<uint8_t>(v);
        }
        Huffman cl;
        if (!cl.build(cl_lens, NUM_CODELEN, Completeness::Required)) {
            return fail(error, "invalid code-length code");
        }

        uint8_t lens[NUM_LITLEN + NUM_DIST] = {0};
        const uint32_t total = hlit + hdist;
        uint32_t i = 0;
        while (i < total) {
            int sym;
            if (!cl.decode(br_, sym)) return fail(error, "invalid code-length symbol");
            if (sym < 16) {
                lens[i++] = static_cast<uint8_t>(sym);
                continue;
            }
            uint8_t value = 0;
            uint32_t extra, repeat;
            if (sym == 16) {
                if (i == 0) return fail(error, "repeat with no previous length");
                value = lens[i - 1];
                if (!br_.bits(2, extra)) return fail(error, "truncated code lengths");
                repeat = 3 + extra;
            } else if (sym == 17) {
                if (!br_.bits(3, extra)) return fail(error, "truncated code lengths");
                repeat = 3 + extra;
            } else {
                if (!br_.bits(7, extra)) return fail(error, "truncated code lengths");
                repeat = 11 + extra;
            }
            if (repeat > total - i) return fail(error, "code lengths overflow");
            std::memset(lens + i, value, repeat);
            i += repeat;
        }
        if (lens[END_OF_BLOCK] == 0) return fail(error, "missing end-of-block code");
        if (!litlen.build(lens, static_cast<int>(hlit), Completeness::AllowSingle)) {
            return fail(error, "invalid literal/length code");
        }
        if (!dist.build(lens + hlit, static_cast<int>(hdist), Completeness::AllowSingle)) {
            return fail(error, "invalid distance code");
        }
        return true;
    }

    bool codes(const Huffman& litlen, const Huffman& dist, std::string& error) {
        for (;;) {
            int sym;
            if (!litlen.decode(br_, sym)) return fail(error, "invalid literal/length code");
            if (sym < 256) {
                if (!out_.room_for(1)) return fail(error, "output larger than declared size");
                out_.put(static_cast<unsigned char>(sym));
            } else if (sym == END_OF_BLOCK) {
                return true;
            } else {
                sym -= 257;
                if (sym >= 29) return fail(error, "invalid length symbol");
                uint32_t extra;
                if (!br_.bits(LEN_EXTRA[sym], extra)) return fail(error, "truncated length");
                size_t length = LEN_BASE[sym] + extra;

                int dsym;
                if (!dist.decode(br_, dsym)) return fail(error, "invalid distance code");
                if (dsym >= NUM_DIST) return fail(error, "invalid distance symbol");
                if (!br_.bits(DIST_EXTRA[dsym], extra)) return fail(error, "truncated distance");
                size_t distance = DIST_BASE[dsym] + extra;

                if (distance > out_.total()) return fail(error, "distance too far back");
                if (!out_.room_for(length)) return fail(error, "output larger than declared size");
                out_.copy(distance, length);
            }
            if (!out_.maybe_flush(sink_error_)) return fail(error, "");
        }
    }
};

} // namespace

bool inflate_stream(ByteSource& in, uint64_t max_out, ByteSink& out, std::string& error,
                    uint64_t* consumed) {
    return Inflater(in, max_out, out, consumed).run(error);
}

bool inflate(const unsigned char* in, size_t in_len, size_t max_out,
             std::vector<unsigned char>& out, std::string& error) {
    out.clear();
    MemorySource src(in, in_len);
    VectorSink sink(out);
    return inflate_stream(src, max_out, sink, error);
}

} // namespace pkcrypt

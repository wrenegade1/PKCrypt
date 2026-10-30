//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//
// Raw DEFLATE compressor (RFC 1951).
//
//   * LZ77: a 32 KiB sliding window searched through hash chains keyed on the
//     next 3 bytes, with one step of lazy matching.
//   * Each block of tokens is written with whichever of dynamic Huffman, fixed
//     Huffman, or stored encoding is smallest (exact bit costs are computed).
//   * Huffman code lengths are limited to the format's maximums by halving the
//     symbol frequencies and rebuilding until the tree is shallow enough.
//

#include "pkcrypt/deflate.h"
#include "deflate_tables.h"

#include <algorithm>
#include <queue>
#include <utility>

namespace pkcrypt {

using namespace deflate_tables;

namespace {

constexpr size_t WINDOW = 32768;            // max back-reference distance
constexpr size_t WINDOW_MASK = WINDOW - 1;
constexpr int HASH_BITS = 15;
constexpr size_t HASH_SIZE = size_t{1} << HASH_BITS;
constexpr size_t MIN_MATCH = 3;
constexpr size_t MAX_MATCH = 258;
constexpr int MAX_CHAIN = 128;              // hash-chain entries searched
constexpr size_t NICE_MATCH = 128;          // stop searching at this length
constexpr size_t LAZY_LIMIT = 32;           // don't try lazy beyond this length
constexpr size_t TOO_FAR = 4096;            // length-3 matches beyond: not worth it
constexpr size_t BLOCK_TOKENS = 16384;      // tokens per DEFLATE block
constexpr size_t MAX_STORED = 65535;        // bytes per stored block

// A literal (dist == 0, value = byte) or a match (value = length 3..258,
// dist = 1..32768, which fits in 16 bits).
struct Token {
    uint16_t value;
    uint16_t dist;
};

int length_symbol(size_t length) {     // 3..258 -> index into LEN_BASE
    int s = 28;
    while (LEN_BASE[s] > length) --s;
    return s;
}

int distance_symbol(size_t dist) {     // 1..32768 -> index into DIST_BASE
    const uint16_t* it = std::upper_bound(DIST_BASE, DIST_BASE + NUM_DIST, dist);
    return static_cast<int>(it - DIST_BASE) - 1;
}

// LSB-first bit writer appending to a byte vector.
class BitWriter {
public:
    explicit BitWriter(std::vector<unsigned char>& out) : out_(out) {}

    void put(uint32_t value, int nbits) {
        buf_ |= static_cast<uint64_t>(value) << count_;
        count_ += nbits;
        while (count_ >= 8) {
            out_.push_back(static_cast<unsigned char>(buf_));
            buf_ >>= 8;
            count_ -= 8;
        }
    }

    void align_to_byte() {
        if (count_ > 0) put(0, 8 - count_);
    }

    void put_bytes(const unsigned char* p, size_t n) {   // must be aligned
        out_.insert(out_.end(), p, p + n);
    }

private:
    std::vector<unsigned char>& out_;
    uint64_t buf_ = 0;
    int count_ = 0;
};

// Huffman code lengths (each <= max_bits) for the given symbol frequencies.
// Symbols with zero frequency get length 0. At least two symbols always get a
// code, so the result is a complete prefix code that every decoder accepts.
std::vector<uint8_t> code_lengths(std::vector<uint32_t> freq, int max_bits) {
    const int n = static_cast<int>(freq.size());
    int used = 0;
    for (uint32_t f : freq) used += (f > 0);
    for (int s = 0; used < 2 && s < n; ++s) {
        if (freq[s] == 0) { freq[s] = 1; ++used; }
    }

    std::vector<uint8_t> lengths(n, 0);
    for (;;) {
        // Nodes 0..n-1 are leaves; internal nodes are appended. Ties break on
        // node index so output is deterministic.
        std::vector<uint64_t> weight(freq.begin(), freq.end());
        std::vector<int> parent(n, -1);
        using Item = std::pair<uint64_t, int>;
        std::priority_queue<Item, std::vector<Item>, std::greater<Item>> heap;
        for (int s = 0; s < n; ++s) if (freq[s]) heap.push({freq[s], s});
        while (heap.size() > 1) {
            Item a = heap.top(); heap.pop();
            Item b = heap.top(); heap.pop();
            int node = static_cast<int>(weight.size());
            weight.push_back(a.first + b.first);
            parent.push_back(-1);
            parent[a.second] = node;
            parent[b.second] = node;
            heap.push({a.first + b.first, node});
        }

        // Depth of each node: parents are always created after their
        // children, so walk from the root (last node) downwards.
        std::vector<int> depth(weight.size(), 0);
        for (int v = static_cast<int>(weight.size()) - 2; v >= 0; --v) {
            if (parent[v] >= 0) depth[v] = depth[parent[v]] + 1;
        }
        int deepest = 0;
        for (int s = 0; s < n; ++s) {
            lengths[s] = freq[s] ? static_cast<uint8_t>(depth[s]) : 0;
            deepest = std::max(deepest, static_cast<int>(lengths[s]));
        }
        if (deepest <= max_bits) return lengths;

        // Too deep: flatten the distribution and try again. Terminates, since
        // all-ones frequencies give a balanced tree.
        for (uint32_t& f : freq) if (f) f = (f >> 1) | 1;
    }
}

// Canonical codes for the given lengths, bit-reversed for LSB-first output.
std::vector<uint16_t> canonical_codes(const std::vector<uint8_t>& lengths) {
    int count[MAX_BITS + 1] = {0};
    for (uint8_t l : lengths) count[l]++;
    count[0] = 0;
    int next[MAX_BITS + 1] = {0};
    int code = 0;
    for (int len = 1; len <= MAX_BITS; ++len) {
        code = (code + count[len - 1]) << 1;
        next[len] = code;
    }
    std::vector<uint16_t> codes(lengths.size(), 0);
    for (size_t s = 0; s < lengths.size(); ++s) {
        if (lengths[s]) {
            codes[s] = static_cast<uint16_t>(reverse_bits(next[lengths[s]]++, lengths[s]));
        }
    }
    return codes;
}

// The code-length sequence of a dynamic block, run-length encoded with
// symbols 16 (repeat previous), 17 (short zero run) and 18 (long zero run).
struct CodeLenSymbol {
    uint8_t symbol;
    uint8_t extra;      // value of the symbol's extra bits
};

std::vector<CodeLenSymbol> rle_code_lengths(const std::vector<uint8_t>& lens) {
    std::vector<CodeLenSymbol> out;
    size_t i = 0;
    while (i < lens.size()) {
        uint8_t v = lens[i];
        size_t run = 1;
        while (i + run < lens.size() && lens[i + run] == v) ++run;
        i += run;
        if (v == 0) {
            while (run >= 11) {
                size_t k = std::min<size_t>(run, 138);
                out.push_back({18, static_cast<uint8_t>(k - 11)});
                run -= k;
            }
            if (run >= 3) {
                out.push_back({17, static_cast<uint8_t>(run - 3)});
                run = 0;
            }
        } else {
            out.push_back({v, 0});
            --run;
            while (run >= 3) {
                size_t k = std::min<size_t>(run, 6);
                out.push_back({16, static_cast<uint8_t>(k - 3)});
                run -= k;
            }
        }
        while (run-- > 0) out.push_back({v, 0});
    }
    return out;
}

int codelen_extra_bits(int symbol) {
    return symbol == 16 ? 2 : symbol == 17 ? 3 : symbol == 18 ? 7 : 0;
}

} // namespace

// LZ77 over a sliding buffer. Positions are absolute offsets into the whole
// input; buf_ holds input from base_ onwards: everything still needed for the
// 32 KiB window, the current block's raw bytes (for the stored fallback), and
// the lookahead a match search needs.
class DeflateStream::Impl {
public:
    Impl() : bw_(out_), head_(HASH_SIZE, -1), prev_(WINDOW, -1) {
        tokens_.reserve(BLOCK_TOKENS);
    }

    void write(const unsigned char* data, size_t n, std::vector<unsigned char>& out) {
        // Feed bounded pieces so a large write never grows the buffer much.
        while (n > 0) {
            size_t take = std::min(n, FEED_SIZE);
            buf_.insert(buf_.end(), data, data + take);
            end_ += take;
            data += take;
            n -= take;
            process(false);
            compact();
        }
        drain(out);
    }

    void finish(std::vector<unsigned char>& out) {
        process(true);
        // A pending match always ends at or before end_, so process() resolves
        // it; this is just a guard.
        if (pending_) match(pending_len_, pending_dist_);
        write_block(true);
        bw_.align_to_byte();
        drain(out);
    }

private:
    static constexpr size_t FEED_SIZE = 256 * 1024;
    static constexpr size_t COMPACT_SLACK = 1024 * 1024;

    std::vector<unsigned char> out_;    // compressed bytes not yet handed out
    BitWriter bw_;
    std::vector<unsigned char> buf_;
    uint64_t base_ = 0;                 // absolute position of buf_[0]
    uint64_t end_ = 0;                  // absolute end of input received
    uint64_t pos_ = 0;                  // next position to process
    bool pending_ = false;              // a match found at pos_-1, not yet emitted
    size_t pending_len_ = 0, pending_dist_ = 0;
    std::vector<int64_t> head_;         // hash -> most recent position
    std::vector<int64_t> prev_;         // position & WINDOW_MASK -> previous position
    std::vector<Token> tokens_;
    uint64_t block_start_ = 0;          // first input byte covered by tokens_
    uint64_t emitted_ = 0;              // input bytes covered by emitted tokens

    unsigned char at(uint64_t i) const { return buf_[static_cast<size_t>(i - base_)]; }

    void drain(std::vector<unsigned char>& out) {
        out.insert(out.end(), out_.begin(), out_.end());
        out_.clear();
    }

    // Drop input no longer needed: before the window, the current block, and
    // a pending match.
    void compact() {
        uint64_t keep = std::min(block_start_, pos_ > WINDOW ? pos_ - WINDOW : 0);
        if (keep - base_ < COMPACT_SLACK) return;
        buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(keep - base_));
        base_ = keep;
    }

    // Process input positions. Unless `final`, stop while too little lookahead
    // remains: a match search reads up to MAX_MATCH bytes ahead, and hashing
    // the positions inside the longest match reads MIN_MATCH - 1 more. With
    // less, a search could be cut short or a position never get hashed by
    // data that simply has not arrived yet, so output would depend on how the
    // input was split into writes.
    static constexpr uint64_t LOOKAHEAD = MAX_MATCH + MIN_MATCH;

    void process(bool final) {
        while (pos_ < end_ && (final || end_ - pos_ >= LOOKAHEAD)) {
            const uint64_t i = pos_;
            size_t len = 0, dist = 0;
            if (!pending_ || pending_len_ < LAZY_LIMIT) find_match(i, len, dist);
            insert(i);

            if (pending_) {
                if (len > pending_len_) {
                    // Better match one byte later: emit i-1 as a literal.
                    literal(at(i - 1));
                    pending_len_ = len;
                    pending_dist_ = dist;
                    pos_ = i + 1;
                    continue;
                }
                match(pending_len_, pending_dist_);
                uint64_t end = i - 1 + pending_len_;
                for (uint64_t j = i + 1; j < end; ++j) insert(j);
                pos_ = end;
                pending_ = false;
                continue;
            }

            if (len >= MIN_MATCH) {
                if (len >= LAZY_LIMIT) {
                    match(len, dist);
                    for (uint64_t j = i + 1; j < i + len; ++j) insert(j);
                    pos_ = i + len;
                } else {
                    pending_ = true;
                    pending_len_ = len;
                    pending_dist_ = dist;
                    pos_ = i + 1;
                }
                continue;
            }
            literal(at(i));
            pos_ = i + 1;
        }
    }

    size_t hash_at(uint64_t i) const {
        return ((static_cast<size_t>(at(i)) << 10) ^
                (static_cast<size_t>(at(i + 1)) << 5) ^ at(i + 2)) &
               (HASH_SIZE - 1);
    }

    void insert(uint64_t i) {
        if (i + MIN_MATCH > end_) return;
        size_t h = hash_at(i);
        prev_[i & WINDOW_MASK] = head_[h];
        head_[h] = static_cast<int64_t>(i);
    }

    // Longest earlier match for position i (searched before i is inserted).
    void find_match(uint64_t i, size_t& best_len, size_t& best_dist) const {
        best_len = 0;
        best_dist = 0;
        if (i + MIN_MATCH > end_) return;
        const size_t max_len = static_cast<size_t>(std::min<uint64_t>(MAX_MATCH, end_ - i));
        const unsigned char* here = &buf_[static_cast<size_t>(i - base_)];
        int64_t cand = head_[hash_at(i)];
        for (int chain = 0; cand >= 0 && chain < MAX_CHAIN; ++chain) {
            uint64_t c = static_cast<uint64_t>(cand);
            if (i - c > WINDOW || c < base_) break;
            const unsigned char* there = &buf_[static_cast<size_t>(c - base_)];
            // Cheap rejection: a longer match must differ from the best so far
            // at its last byte.
            if (best_len == 0 || there[best_len] == here[best_len]) {
                size_t l = 0;
                while (l < max_len && there[l] == here[l]) ++l;
                if (l > best_len) {
                    best_len = l;
                    best_dist = static_cast<size_t>(i - c);
                    if (l >= NICE_MATCH || l == max_len) break;
                }
            }
            cand = prev_[c & WINDOW_MASK];
        }
        if (best_len < MIN_MATCH || (best_len == MIN_MATCH && best_dist > TOO_FAR)) {
            best_len = 0;
            best_dist = 0;
        }
    }

    void literal(unsigned char byte) {
        tokens_.push_back({byte, 0});
        emitted_ += 1;
        if (tokens_.size() == BLOCK_TOKENS) write_block(false);
    }

    void match(size_t length, size_t dist) {
        tokens_.push_back({static_cast<uint16_t>(length), static_cast<uint16_t>(dist)});
        emitted_ += length;
        if (tokens_.size() == BLOCK_TOKENS) write_block(false);
    }

    void write_block(bool final);
};

// Write the buffered tokens as one block, choosing the cheapest encoding.
void DeflateStream::Impl::write_block(bool final) {
    // Symbol frequencies (the end-of-block symbol occurs once).
    std::vector<uint32_t> lit_freq(NUM_LITLEN, 0), dist_freq(NUM_DIST, 0);
    lit_freq[END_OF_BLOCK] = 1;
    uint64_t extra_bits = 0;            // length/distance extra bits, any code
    for (const Token& t : tokens_) {
        if (t.dist == 0) {
            lit_freq[t.value]++;
        } else {
            int ls = length_symbol(t.value), ds = distance_symbol(t.dist);
            lit_freq[257 + ls]++;
            dist_freq[ds]++;
            extra_bits += LEN_EXTRA[ls] + DIST_EXTRA[ds];
        }
    }

    // Dynamic Huffman: code lengths, then their run-length encoding.
    std::vector<uint8_t> lit_len = code_lengths(lit_freq, MAX_BITS);
    std::vector<uint8_t> dist_len = code_lengths(dist_freq, MAX_BITS);
    int hlit = NUM_LITLEN, hdist = NUM_DIST;
    while (hlit > 257 && lit_len[hlit - 1] == 0) --hlit;
    while (hdist > 1 && dist_len[hdist - 1] == 0) --hdist;
    std::vector<uint8_t> all_lens(lit_len.begin(), lit_len.begin() + hlit);
    all_lens.insert(all_lens.end(), dist_len.begin(), dist_len.begin() + hdist);
    std::vector<CodeLenSymbol> cl_syms = rle_code_lengths(all_lens);
    std::vector<uint32_t> cl_freq(NUM_CODELEN, 0);
    for (const CodeLenSymbol& c : cl_syms) cl_freq[c.symbol]++;
    std::vector<uint8_t> cl_len = code_lengths(cl_freq, MAX_CL_BITS);
    int hclen = NUM_CODELEN;
    while (hclen > 4 && cl_len[CODELEN_ORDER[hclen - 1]] == 0) --hclen;

    uint64_t dynamic_bits = 3 + 5 + 5 + 4 + 3 * static_cast<uint64_t>(hclen) + extra_bits;
    for (const CodeLenSymbol& c : cl_syms) {
        dynamic_bits += cl_len[c.symbol] + codelen_extra_bits(c.symbol);
    }
    uint64_t fixed_bits = 3 + extra_bits;
    for (int s = 0; s < NUM_LITLEN; ++s) {
        dynamic_bits += static_cast<uint64_t>(lit_freq[s]) * lit_len[s];
        fixed_bits += static_cast<uint64_t>(lit_freq[s]) * fixed_litlen_length(s);
    }
    for (int s = 0; s < NUM_DIST; ++s) {
        dynamic_bits += static_cast<uint64_t>(dist_freq[s]) * dist_len[s];
        fixed_bits += static_cast<uint64_t>(dist_freq[s]) * FIXED_DIST_LENGTH;
    }
    // Stored: per block a 3-bit header, up to 7 bits of padding, LEN + NLEN.
    const size_t raw_len = static_cast<size_t>(emitted_ - block_start_);
    const uint64_t stored_blocks = std::max<uint64_t>(1, (raw_len + MAX_STORED - 1) / MAX_STORED);
    const uint64_t stored_bits = stored_blocks * (3 + 7 + 32) + 8 * static_cast<uint64_t>(raw_len);

    if (stored_bits < dynamic_bits && stored_bits < fixed_bits) {
        const unsigned char* p = &buf_[static_cast<size_t>(block_start_ - base_)];
        size_t left = raw_len;
        do {
            size_t n = std::min(left, MAX_STORED);
            left -= n;
            bw_.put(final && left == 0 ? 1 : 0, 1);
            bw_.put(0, 2);
            bw_.align_to_byte();
            bw_.put(static_cast<uint32_t>(n), 16);
            bw_.put(static_cast<uint32_t>(~n & 0xFFFF), 16);
            bw_.put_bytes(p, n);
            p += n;
        } while (left > 0);
    } else {
        std::vector<uint8_t> use_lit, use_dist;
        if (fixed_bits <= dynamic_bits) {
            // The fixed code is defined over all 288 symbols; 286 and 287
            // never occur but must be counted, or the canonical 9-bit codes
            // (literals 144..255) come out shifted.
            use_lit.resize(288);
            for (int s = 0; s < 288; ++s) use_lit[s] = fixed_litlen_length(s);
            use_dist.assign(NUM_DIST, FIXED_DIST_LENGTH);
            bw_.put(final ? 1 : 0, 1);
            bw_.put(1, 2);
        } else {
            use_lit = lit_len;
            use_dist = dist_len;
            bw_.put(final ? 1 : 0, 1);
            bw_.put(2, 2);
            bw_.put(static_cast<uint32_t>(hlit - 257), 5);
            bw_.put(static_cast<uint32_t>(hdist - 1), 5);
            bw_.put(static_cast<uint32_t>(hclen - 4), 4);
            for (int i = 0; i < hclen; ++i) bw_.put(cl_len[CODELEN_ORDER[i]], 3);
            std::vector<uint16_t> cl_code = canonical_codes(cl_len);
            for (const CodeLenSymbol& c : cl_syms) {
                bw_.put(cl_code[c.symbol], cl_len[c.symbol]);
                if (int eb = codelen_extra_bits(c.symbol)) bw_.put(c.extra, eb);
            }
        }
        std::vector<uint16_t> lit_code = canonical_codes(use_lit);
        std::vector<uint16_t> dist_code = canonical_codes(use_dist);
        for (const Token& t : tokens_) {
            if (t.dist == 0) {
                bw_.put(lit_code[t.value], use_lit[t.value]);
                continue;
            }
            int ls = length_symbol(t.value), ds = distance_symbol(t.dist);
            bw_.put(lit_code[257 + ls], use_lit[257 + ls]);
            if (LEN_EXTRA[ls]) bw_.put(t.value - LEN_BASE[ls], LEN_EXTRA[ls]);
            bw_.put(dist_code[ds], use_dist[ds]);
            if (DIST_EXTRA[ds]) bw_.put(t.dist - DIST_BASE[ds], DIST_EXTRA[ds]);
        }
        bw_.put(lit_code[END_OF_BLOCK], use_lit[END_OF_BLOCK]);
    }

    tokens_.clear();
    block_start_ = emitted_;
}

DeflateStream::DeflateStream() : impl_(new Impl) {}
DeflateStream::~DeflateStream() = default;

void DeflateStream::write(const unsigned char* data, size_t n, std::vector<unsigned char>& out) {
    impl_->write(data, n, out);
}

void DeflateStream::finish(std::vector<unsigned char>& out) { impl_->finish(out); }

std::vector<unsigned char> deflate_compress(const unsigned char* data, size_t len) {
    std::vector<unsigned char> out;
    DeflateStream stream;
    stream.write(data, len, out);
    stream.finish(out);
    return out;
}

} // namespace pkcrypt

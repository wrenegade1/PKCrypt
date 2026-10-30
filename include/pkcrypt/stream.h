#ifndef PKCRYPT_STREAM_H
#define PKCRYPT_STREAM_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//
// Minimal byte-stream interfaces. Every stage (file I/O, ZIP, DEFLATE,
// encryption) passes data through these in bounded pieces, so memory use stays
// flat however large the input is.
//

#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace pkcrypt {

// Somewhere to write bytes.
class ByteSink {
public:
    virtual ~ByteSink() = default;
    // Consume `n` bytes. Returns false and sets `error` on failure.
    virtual bool write(const unsigned char* data, size_t n, std::string& error) = 0;
};

// Somewhere to read bytes from.
class ByteSource {
public:
    virtual ~ByteSource() = default;
    // Read up to `n` bytes into `buf`. Returns the number read (0 at end of
    // input), or -1 with `error` set on failure.
    virtual long long read(unsigned char* buf, size_t n, std::string& error) = 0;
};

// Read until `n` bytes arrive or the input ends; returns the count read, or -1.
inline long long read_full(ByteSource& in, unsigned char* buf, size_t n, std::string& error) {
    size_t got = 0;
    while (got < n) {
        long long r = in.read(buf + got, n - got, error);
        if (r < 0) return -1;
        if (r == 0) break;
        got += static_cast<size_t>(r);
    }
    return static_cast<long long>(got);
}

// Appends to a vector.
class VectorSink : public ByteSink {
public:
    explicit VectorSink(std::vector<unsigned char>& out) : out_(out) {}
    bool write(const unsigned char* data, size_t n, std::string&) override {
        out_.insert(out_.end(), data, data + n);
        return true;
    }

private:
    std::vector<unsigned char>& out_;
};

// Reads from memory, at most `max_read` bytes per call (small values let the
// tests exercise every buffer boundary).
class MemorySource : public ByteSource {
public:
    MemorySource(const unsigned char* data, size_t len, size_t max_read = static_cast<size_t>(-1))
        : data_(data), len_(len), max_read_(max_read) {}
    long long read(unsigned char* buf, size_t n, std::string&) override {
        size_t k = n < len_ - pos_ ? n : len_ - pos_;
        if (k > max_read_) k = max_read_;
        if (k) std::memcpy(buf, data_ + pos_, k);
        pos_ += k;
        return static_cast<long long>(k);
    }

private:
    const unsigned char* data_;
    size_t len_;
    size_t max_read_;
    size_t pos_ = 0;
};

} // namespace pkcrypt

#endif // PKCRYPT_STREAM_H

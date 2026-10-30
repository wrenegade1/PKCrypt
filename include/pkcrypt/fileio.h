#ifndef PKCRYPT_FILEIO_H
#define PKCRYPT_FILEIO_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//

#include <cstdint>
#include <string>

#include "pkcrypt/stream.h"

namespace pkcrypt {

// Reads a file descriptor sequentially. Does not own the descriptor.
class FdSource : public ByteSource {
public:
    explicit FdSource(int fd) : fd_(fd) {}
    long long read(unsigned char* buf, size_t n, std::string& error) override;

private:
    int fd_;
};

// Reads the byte range [offset, offset + length) of a file with pread, so
// several ranges of one file can be read independently. Does not own the fd.
class FdRangeSource : public ByteSource {
public:
    FdRangeSource(int fd, uint64_t offset, uint64_t length)
        : fd_(fd), offset_(offset), left_(length) {}
    long long read(unsigned char* buf, size_t n, std::string& error) override;

private:
    int fd_;
    uint64_t offset_;
    uint64_t left_;
};

// Read exactly `n` bytes at `offset`. Returns false (setting `error`) on a
// short read.
bool pread_exact(int fd, uint64_t offset, unsigned char* buf, size_t n, std::string& error);

// Write all of `n` bytes to `fd`, retrying short writes.
bool write_all(int fd, const unsigned char* data, size_t n);

// An output file that is written incrementally but published atomically with
// 0600 permissions, never overwriting an existing file: data goes to a temp
// file in the destination's directory, which is linked into place by commit()
// (link fails if the destination exists). Anything not committed - after an
// error, or when the object is destroyed - is removed, so a crash or failure
// never leaves a partial file behind.
class AtomicFile : public ByteSink {
public:
    AtomicFile() = default;
    AtomicFile(const AtomicFile&) = delete;
    AtomicFile& operator=(const AtomicFile&) = delete;
    ~AtomicFile() override { abort(); }

    bool open(const std::string& path, std::string& error);
    bool write(const unsigned char* data, size_t n, std::string& error) override;
    bool commit(std::string& error);
    void abort();
    uint64_t size() const { return written_; }
    // Publish to `path` instead of the path given to open().
    void set_destination(const std::string& path) { path_ = path; }

private:
    int fd_ = -1;
    std::string path_, tmp_;
    uint64_t written_ = 0;
};

// A private (0600) scratch file in a given directory, unlinked and closed when
// destroyed. Written as a sink, then read back through fd().
class TempFile : public ByteSink {
public:
    TempFile() = default;
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    ~TempFile() override;

    bool create(const std::string& dir, std::string& error);
    bool write(const unsigned char* data, size_t n, std::string& error) override;
    int fd() const { return fd_; }
    uint64_t size() const { return written_; }

private:
    int fd_ = -1;
    std::string path_;
    uint64_t written_ = 0;
};

// Directory part of `path` ("." if none).
std::string parent_dir(const std::string& path);

// Make a string safe to print to a terminal: escape C0 control bytes and DEL
// as \xHH, leaving bytes >= 0x80 intact so UTF-8 filenames display normally.
// Used on every archive- or file-derived name/message, so a crafted archive
// filename can't inject terminal escape sequences.
std::string display_safe(const std::string& s);

// `base` if nothing exists there, else the first of base.1, base.2, ... free.
std::string unused_path(const std::string& base);

// Derive an encrypted output path: <input>.pkcrypt  (unless it would collide).
std::string encrypted_output_path(const std::string& input_path);

// Derive a decrypted output path: strips a trailing ".pkcrypt", or appends
// ".decrypted" otherwise (never overwrites an existing file).
std::string decrypted_output_path(const std::string& input_path);

} // namespace pkcrypt

#endif // PKCRYPT_FILEIO_H

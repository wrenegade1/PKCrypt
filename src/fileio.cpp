//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//

#include "pkcrypt/fileio.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

namespace pkcrypt {

std::string display_safe(const std::string& in) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        if (c < 0x20 || c == 0x7f) {
            out += "\\x";
            out += hex[c >> 4];
            out += hex[c & 0xf];
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string parent_dir(const std::string& path) {
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

long long FdSource::read(unsigned char* buf, size_t n, std::string& error) {
    for (;;) {
        ssize_t r = ::read(fd_, buf, n);
        if (r >= 0) return r;
        if (errno != EINTR) {
            error = std::string("read error: ") + std::strerror(errno);
            return -1;
        }
    }
}

long long FdRangeSource::read(unsigned char* buf, size_t n, std::string& error) {
    if (n > left_) n = static_cast<size_t>(left_);
    if (n == 0) return 0;
    for (;;) {
        ssize_t r = ::pread(fd_, buf, n, static_cast<off_t>(offset_));
        if (r > 0) {
            offset_ += static_cast<uint64_t>(r);
            left_ -= static_cast<uint64_t>(r);
            return r;
        }
        if (r == 0) {
            error = "unexpected end of file";
            return -1;
        }
        if (errno != EINTR) {
            error = std::string("read error: ") + std::strerror(errno);
            return -1;
        }
    }
}

bool pread_exact(int fd, uint64_t offset, unsigned char* buf, size_t n, std::string& error) {
    FdRangeSource src(fd, offset, n);
    long long got = read_full(src, buf, n, error);
    if (got != static_cast<long long>(n)) {
        if (got >= 0) error = "unexpected end of file";
        return false;
    }
    return true;
}

bool write_all(int fd, const unsigned char* data, size_t n) {
    while (n > 0) {
        ssize_t w = ::write(fd, data, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

// mkstemp in `dir`; mkstemp creates the file 0600.
static int make_temp(const std::string& dir, const std::string& prefix, std::string& path) {
    std::string tmpl = dir + "/" + prefix + "XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    int fd = ::mkstemp(buf.data());
    if (fd >= 0) path = buf.data();
    return fd;
}

bool AtomicFile::open(const std::string& path, std::string& error) {
    abort();
    struct stat st;
    if (::lstat(path.c_str(), &st) == 0) {
        error = "refusing to overwrite existing file: " + path;
        return false;
    }
    fd_ = make_temp(parent_dir(path), ".pkcrypt-", tmp_);
    if (fd_ < 0) {
        error = "cannot create temp file in " + parent_dir(path);
        return false;
    }
    path_ = path;
    written_ = 0;
    return true;
}

bool AtomicFile::write(const unsigned char* data, size_t n, std::string& error) {
    if (fd_ < 0 || !write_all(fd_, data, n)) {
        error = "write error: " + path_;
        return false;
    }
    written_ += n;
    return true;
}

bool AtomicFile::commit(std::string& error) {
    if (fd_ < 0) { error = "output not open"; return false; }
    bool ok = false;
    if (::fsync(fd_) != 0) {
        error = "fsync failed: " + path_;
    } else {
        // Restrictive perms: mkstemp already gives 0600, but set it explicitly
        // in case umask/tooling relaxed it.
        ::fchmod(fd_, S_IRUSR | S_IWUSR);
        // Atomic no-clobber publish: link() fails if `path_` already exists,
        // so the destination is never silently overwritten or half-written.
        if (::link(tmp_.c_str(), path_.c_str()) == 0) {
            ok = true;
        } else if (errno == EEXIST) {
            error = "refusing to overwrite existing file: " + path_;
        } else {
            error = "cannot link output into place: " + path_;
        }
    }
    abort();    // close, and remove the temp name (the link, if any, stays)
    return ok;
}

void AtomicFile::abort() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
        ::unlink(tmp_.c_str());
    }
}

TempFile::~TempFile() {
    if (fd_ >= 0) {
        ::close(fd_);
        ::unlink(path_.c_str());
    }
}

bool TempFile::create(const std::string& dir, std::string& error) {
    fd_ = make_temp(dir, ".pkcrypt-", path_);
    if (fd_ < 0) {
        error = "cannot create temp file in " + dir;
        return false;
    }
    return true;
}

bool TempFile::write(const unsigned char* data, size_t n, std::string& error) {
    if (fd_ < 0 || !write_all(fd_, data, n)) {
        error = "write error: temporary file";
        return false;
    }
    written_ += n;
    return true;
}

static bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

std::string encrypted_output_path(const std::string& input_path) {
    // "photos/" -> "photos.pkcrypt", not "photos/.pkcrypt".
    std::string base = input_path;
    while (base.size() > 1 && base.back() == '/') base.pop_back();
    return base + ".pkcrypt";
}

std::string decrypted_output_path(const std::string& input_path) {
    // If the input ends in .pkcrypt, strip it; otherwise append ".decrypted".
    const std::string suffix = ".pkcrypt";
    std::string cand;
    if (input_path.size() >= suffix.size() &&
        input_path.compare(input_path.size() - suffix.size(), suffix.size(),
                           suffix) == 0) {
        cand = input_path.substr(0, input_path.size() - suffix.size());
        if (!cand.empty() && !file_exists(cand)) return cand;
        cand = input_path + ".decrypted";
    } else {
        cand = input_path + ".decrypted";
    }
    // Avoid clobbering by appending a numeric suffix if needed.
    return unused_path(cand);
}

std::string unused_path(const std::string& base) {
    std::string cand = base;
    int i = 1;
    while (file_exists(cand)) cand = base + "." + std::to_string(i++);
    return cand;
}

} // namespace pkcrypt

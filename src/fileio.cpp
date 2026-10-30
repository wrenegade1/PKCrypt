//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//

#include "pkcrypt/fileio.h"

#include <fstream>
#include <sys/stat.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace pkcrypt {

namespace {
// Return the directory portion of `path` (empty if none). Used so the temp file
// lives in the same directory as the destination (required for atomic link).
std::string parent_dir(const std::string& path) {
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}
} // namespace

bool read_file(const std::string& path, std::vector<unsigned char>& out,
               std::string& error) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) { error = "cannot open file: " + path; return false; }
    std::streamsize size = f.tellg();
    if (size < 0) { error = "cannot determine file size: " + path; return false; }
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (size > 0 && !f.read(reinterpret_cast<char*>(out.data()), size)) {
        error = "read error: " + path;
        return false;
    }
    return true;
}

bool write_file(const std::string& path, const unsigned char* data, size_t len,
                std::string& error) {
    // Refuse to overwrite an existing file (matches the "never overwrites"
    // contract) and write atomically + with 0600 perms.
    const std::string dir = parent_dir(path);

    // mkstemp creates a 0600 file with a unique name in the same directory.
    std::string tmpl = dir + "/.pkcrypt-XXXXXX";
    std::vector<char> tbuf(tmpl.begin(), tmpl.end());
    tbuf.push_back('\0');
    int fd = ::mkstemp(tbuf.data());
    if (fd < 0) { error = "cannot create temp file in " + dir; return false; }
    const std::string tmp(tbuf.data());

    bool ok = false;
    do {
        // Write the full buffer. Handle short writes (EINTR / partial I/O).
        size_t written = 0;
        while (written < len) {
            ssize_t n = ::write(fd, data + written, len - written);
            if (n < 0) {
                if (errno == EINTR) continue;
                error = "write error: " + path;
                break;
            }
            written += static_cast<size_t>(n);
        }
        if (written < len) break;  // a write error already set `error`

        if (::fsync(fd) != 0) { error = "fsync failed: " + path; break; }
        ::close(fd); fd = -1;

        // Restrictive perms on a fresh file: mkstemp already gives 0600, but
        // set it explicitly in case umask/tooling relaxed it.
        ::chmod(tmp.c_str(), S_IRUSR | S_IWUSR);

        // Atomic no-clobber publish: link() fails if `path` already exists, so
        // the destination is never silently overwritten and never half-written.
        if (::link(tmp.c_str(), path.c_str()) != 0) {
            if (errno == EEXIST) {
                error = "refusing to overwrite existing file: " + path;
            } else {
                error = "cannot link output into place: " + path;
            }
            break;
        }
        ::unlink(tmp.c_str());
        ok = true;
    } while (false);

    if (fd >= 0) ::close(fd);
    if (!ok) ::unlink(tmp.c_str());  // never leave a partial temp behind
    return ok;
}

static bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

std::string encrypted_output_path(const std::string& input_path) {
    return input_path + ".pkcrypt";
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
    std::string base = cand;
    int i = 1;
    while (file_exists(cand)) {
        cand = base + "." + std::to_string(i++);
    }
    return cand;
}

} // namespace pkcrypt

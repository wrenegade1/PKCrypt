//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//
// Folder <-> ZIP archive, streamed. Packing walks the folder without following
// symbolic links, streaming one file at a time; extraction validates the whole
// archive first, streams each entry into a private temporary directory, and
// renames that into place only on complete success.
//

#include "pkcrypt/archive.h"
#include "pkcrypt/fileio.h"
#include "pkcrypt/zip.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
#endif

namespace fs = std::filesystem;

namespace pkcrypt {

namespace {

using Losses = std::vector<std::pair<std::string, std::string>>;

bool fail(std::string& error, const std::string& what) {
    error = what;
    return false;
}

std::string strip_trailing_slashes(std::string p) {
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

// Rename `from` to `to` only if `to` does not exist (atomically where the OS
// supports it; rename(2) alone would replace an existing empty directory).
int rename_no_replace(const std::string& from, const std::string& to) {
#if defined(__APPLE__)
    return renamex_np(from.c_str(), to.c_str(), RENAME_EXCL);
#else
#if defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(),
                RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno != ENOSYS && errno != EINVAL) return -1;
#endif
    struct stat st;
    if (::lstat(to.c_str(), &st) == 0) { errno = EEXIST; return -1; }
    return ::rename(from.c_str(), to.c_str());
#endif
}

// Writes to an open file descriptor (not owned).
class FdSink : public ByteSink {
public:
    explicit FdSink(int fd) : fd_(fd) {}
    bool write(const unsigned char* data, size_t n, std::string& error) override {
        if (write_all(fd_, data, n)) return true;
        error = std::string("write error: ") + std::strerror(errno);
        return false;
    }

private:
    int fd_;
};

// Create each missing parent directory of member `name` under `root`.
bool make_parents(const std::string& root, const std::string& name, std::string& error) {
    size_t slash = 0;
    while ((slash = name.find('/', slash)) != std::string::npos && slash + 1 < name.size()) {
        const std::string dir = root + "/" + name.substr(0, slash);
        if (::mkdir(dir.c_str(), 0700) != 0) {
            struct stat st;
            if (errno != EEXIST || ::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
                return fail(error, "cannot create directory for " + name +
                                       " (a file in the archive has the same name?)");
            }
        }
        ++slash;
    }
    return true;
}

// Extract `members` under `root`. A failing member fails the whole
// extraction - unless `lost` is given (salvage): then it is recorded there,
// any partial file is removed, and extraction continues.
bool extract_into(const std::string& root, int archive_fd,
                  const std::vector<ZipMember>& members, ArchiveStats& stats,
                  std::string& error, Losses* lost = nullptr) {
    std::vector<std::pair<std::string, std::time_t>> dir_times;
    for (const ZipMember& m : members) {
        auto give_up = [&](const std::string& why) {
            if (!lost) {
                error = why;
                return false;
            }
            lost->push_back({m.name, why});
            return true;
        };
        std::string why;
        if (!make_parents(root, m.name, why)) {
            if (!give_up(why)) return false;
            continue;
        }
        const std::string path = root + "/" + strip_trailing_slashes(m.name);

        if (m.is_dir) {
            struct stat st;
            if (::mkdir(path.c_str(), 0700) != 0 &&
                (errno != EEXIST || ::lstat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))) {
                if (!give_up("cannot create directory " + m.name)) return false;
                continue;
            }
            dir_times.push_back({path, m.mtime});
            stats.directories++;
            continue;
        }

        const mode_t mode = (m.mode & S_IXUSR) ? 0700 : 0600;
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
        if (fd < 0) {
            why = errno == EEXIST ? "two archive entries map to the same file "
                                    "(names differing only in case?): " + m.name
                                  : "cannot create " + m.name + ": " + std::strerror(errno);
            if (!give_up(why)) return false;
            continue;
        }
        // Streamed straight to the file. If verification fails part-way, the
        // partial file is removed (and in normal mode the caller removes the
        // whole temporary tree).
        FdSink sink(fd);
        bool ok = zip_extract_member(archive_fd, m, sink, why);
        if (ok && (::fchmod(fd, mode) != 0 || ::fsync(fd) != 0)) {
            ok = false;
            why = "write error: " + m.name;
        }
        if (ok && m.mtime > 0) {
            struct timespec times[2] = {{m.mtime, 0}, {m.mtime, 0}};
            ::futimens(fd, times);
        }
        ::close(fd);
        if (!ok) {
            ::unlink(path.c_str());
            if (!give_up(why)) return false;
            continue;
        }
        stats.files++;
        stats.bytes += m.size;
    }

    // Directory times last (creating entries inside a directory changes its
    // mtime), deepest first.
    std::sort(dir_times.begin(), dir_times.end(),
              [](const auto& a, const auto& b) { return a.first.size() > b.first.size(); });
    for (const auto& [path, mtime] : dir_times) {
        if (mtime <= 0) continue;
        struct timespec times[2] = {{mtime, 0}, {mtime, 0}};
        ::utimensat(AT_FDCWD, path.c_str(), times, AT_SYMLINK_NOFOLLOW);
    }
    return true;
}

} // namespace

bool pack_directory(const std::string& dir_arg, ByteSink& out, ArchiveStats& stats,
                    std::string& error, const struct stat* exclude, bool skip_large) {
    const std::string dir = strip_trailing_slashes(dir_arg);
    struct stat root_st;
    if (::stat(dir.c_str(), &root_st) != 0 || !S_ISDIR(root_st.st_mode)) {
        return fail(error, "not a directory: " + dir_arg);
    }

    struct Item {
        std::string name;       // archive name ('/'-terminated for directories)
        std::string path;       // filesystem path
        bool is_dir;
        struct stat st;
    };
    std::vector<Item> items;

    std::error_code ec;
    fs::recursive_directory_iterator it(dir, fs::directory_options::none, ec), end;
    if (ec) return fail(error, "cannot read directory " + dir + ": " + ec.message());
    while (it != end) {
        const fs::path& p = it->path();
        const std::string rel = p.lexically_relative(dir).generic_string();
        struct stat st;
        if (::lstat(p.c_str(), &st) != 0) {
            return fail(error, "cannot stat " + p.string() + ": " + std::strerror(errno));
        }
        if (S_ISDIR(st.st_mode)) {
            items.push_back({rel + "/", p.string(), true, st});
        } else if (S_ISREG(st.st_mode)) {
            const bool own_output = exclude && st.st_dev == exclude->st_dev &&
                                    st.st_ino == exclude->st_ino;
            if (!own_output) items.push_back({rel, p.string(), false, st});
        } else {
            stats.skipped.push_back(rel);           // symlink, socket, device...
        }
        it.increment(ec);
        if (ec) return fail(error, "cannot read directory under " + dir + ": " + ec.message());
    }
    std::sort(items.begin(), items.end(),
              [](const Item& a, const Item& b) { return a.name < b.name; });

    // Pre-flight the classic-ZIP limits from the sizes already stat'ed, so an
    // oversized folder fails at once instead of after compressing 4 GiB. The
    // writer still enforces them while streaming (a file may grow meanwhile),
    // and the 4 GiB whole-archive limit, which depends on compression, is
    // only knowable there.
    std::vector<Item> kept;
    kept.reserve(items.size());
    for (Item& item : items) {
        const auto size = static_cast<uint64_t>(item.st.st_size);
        if (!item.is_dir && size > ZIP_MAX_FILE_SIZE) {
            if (!skip_large) {
                return fail(error, "file too large for a ZIP archive (limit 4 GiB; "
                                   "ZIP64 is not supported): " + item.name);
            }
            stats.too_large.emplace_back(item.name, size);
            continue;
        }
        kept.push_back(std::move(item));
    }
    items.swap(kept);
    if (items.size() > ZIP_MAX_ENTRIES) {
        return fail(error, "too many files and folders for a ZIP archive (" +
                           std::to_string(items.size()) +
                           "; limit 65534; ZIP64 is not supported)");
    }

    ZipWriter writer(out);
    for (const Item& item : items) {
        const uint32_t mode = item.st.st_mode & 07777;
        if (item.is_dir) {
            if (!writer.add_directory(item.name, mode, item.st.st_mtime, error)) return false;
            stats.directories++;
            continue;
        }
        int fd = ::open(item.path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            return fail(error, "cannot open " + item.path + ": " + std::strerror(errno));
        }
        FdSource src(fd);
        bool ok = writer.add_file(item.name, mode, item.st.st_mtime, src, error);
        ::close(fd);
        if (!ok) return false;
        stats.files++;
        stats.bytes += static_cast<unsigned long long>(item.st.st_size);
    }
    return writer.finish(error);
}

namespace {

// Free bytes on the filesystem holding `dir` (unknown: as large as possible).
unsigned long long free_space(const std::string& dir) {
    struct statvfs vfs;
    if (::statvfs(dir.c_str(), &vfs) != 0) return ~0ull;
    return static_cast<unsigned long long>(vfs.f_bavail) * vfs.f_frsize;
}

std::string parent_of(const std::string& dest) {
    std::string parent = fs::path(dest).parent_path().string();
    return parent.empty() ? "." : parent;
}

// Run `extract` into a private temporary directory beside `dest`, then rename
// it to the path `choose_dest()` returns (evaluated afterwards, so the result
// can decide the name), never over an existing path. On any failure the
// temporary tree is removed.
template <typename Extract, typename ChooseDest>
bool extract_atomically(const std::string& dest, Extract extract, ChooseDest choose_dest,
                        std::string& error) {
    const std::string parent = parent_of(dest);
    std::string tmpl = parent + "/." + fs::path(dest).filename().string() + ".pkcrypt-XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (!::mkdtemp(buf.data())) {
        return fail(error, "cannot create temporary directory in " + parent + ": " +
                               std::strerror(errno));
    }
    const std::string tmp(buf.data());

    bool ok = extract(tmp);
    if (ok) {
        const std::string final_dest = choose_dest();
        if (rename_no_replace(tmp, final_dest) != 0) {
            error = errno == EEXIST ? "refusing to overwrite existing path: " + final_dest
                                    : "cannot move extracted folder into place: " + final_dest;
            ok = false;
        }
    }
    if (!ok) {
        std::error_code ec;
        fs::remove_all(tmp, ec);
    }
    return ok;
}

} // namespace

bool extract_archive(int archive_fd, uint64_t archive_size, const std::string& dest_arg,
                     ArchiveStats& stats, std::string& error) {
    std::vector<ZipMember> members;
    if (!zip_list(archive_fd, archive_size, members, error)) return false;

    const std::string dest = strip_trailing_slashes(dest_arg);
    struct stat st;
    if (::lstat(dest.c_str(), &st) == 0) {
        return fail(error, "refusing to overwrite existing path: " + dest);
    }
    // Refuse up front if the archive cannot fit, rather than filling the disk.
    unsigned long long total = 0;
    for (const ZipMember& m : members) total += m.size;
    const unsigned long long avail = free_space(parent_of(dest));
    if (total > avail) {
        return fail(error, "not enough disk space: the folder needs " + std::to_string(total) +
                               " bytes, " + std::to_string(avail) + " available");
    }
    return extract_atomically(
        dest,
        [&](const std::string& tmp) {
            return extract_into(tmp, archive_fd, members, stats, error);
        },
        [&] { return dest; }, error);
}

bool salvage_archive(int archive_fd, uint64_t archive_size, bool verified_whole,
                     const std::string& dest_arg, const std::string& partial_dest_arg,
                     SalvageReport& report, std::string& error) {
    const std::string dest = strip_trailing_slashes(dest_arg);
    const std::string partial_dest = strip_trailing_slashes(partial_dest_arg);
    struct stat st;
    if (::lstat(dest.c_str(), &st) == 0) {
        return fail(error, "refusing to overwrite existing path: " + dest);
    }

    // With the whole archive verified, its central directory is usable: list
    // leniently so one bad member loses only itself. Otherwise (or if the
    // directory itself is broken), scan the readable prefix in order.
    std::vector<ZipMember> members;
    std::string why;
    report = SalvageReport{};
    report.verified_whole = verified_whole;
    if (!verified_whole || !zip_list(archive_fd, archive_size, members, why, &report.lost)) {
        report.lost.clear();
        if (verified_whole) report.lost.push_back({"(archive index)", why});
        const unsigned long long max_entry = std::min<unsigned long long>(
            free_space(parent_of(dest)), 0xFFFFFFFFull);
        if (!zip_scan(archive_fd, archive_size, max_entry, members, report.lost,
                      report.tail_problem, error)) {
            return false;
        }
    }

    return extract_atomically(
        dest,
        [&](const std::string& tmp) {
            if (!extract_into(tmp, archive_fd, members, report.stats, error, &report.lost)) {
                return false;
            }
            // An empty "partial" result would only mislead: fail instead.
            if (report.stats.files == 0 && report.stats.directories == 0 && !report.complete()) {
                const std::string why = !report.tail_problem.empty() ? report.tail_problem
                                        : !report.lost.empty() ? report.lost.front().second
                                                               : "no entries";
                return fail(error, "nothing could be recovered (" + why + ")");
            }
            return true;
        },
        [&] { return report.complete() ? dest : partial_dest; }, error);
}

} // namespace pkcrypt

//
// PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
// key can decrypt them (same public/private key model as SSH).
//
// Author: Warren Zajac
//
// Streaming ZIP writer and reader (PKWARE APPNOTE 6.3.x, classic non-ZIP64
// records):
//
//   [local header + data (+ data descriptor)] ...  [central directory] [end]
//
// All multi-byte fields are little-endian.
//

#include "pkcrypt/zip.h"
#include "pkcrypt/deflate.h"
#include "pkcrypt/fileio.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <sodium.h>
#include <sys/stat.h>

namespace pkcrypt {

namespace {

constexpr uint32_t SIG_LOCAL = 0x04034b50;
constexpr uint32_t SIG_CENTRAL = 0x02014b50;
constexpr uint32_t SIG_EOCD = 0x06054b50;
constexpr uint32_t SIG_DATA_DESCRIPTOR = 0x08074b50;
constexpr uint32_t SIG_ZIP64_LOCATOR = 0x07064b50;
constexpr size_t LOCAL_LEN = 30;
constexpr size_t CENTRAL_LEN = 46;
constexpr size_t EOCD_LEN = 22;
constexpr uint16_t VERSION_NEEDED = 20;            // 2.0: deflate, directories
constexpr uint16_t VERSION_MADE_BY = (3 << 8) | 20; // host 3 = Unix
constexpr uint16_t FLAG_ENCRYPTED = 0x0001;
constexpr uint16_t FLAG_DATA_DESCRIPTOR = 0x0008;
constexpr uint16_t FLAG_STRONG_ENCRYPTION = 0x0040;
constexpr uint16_t FLAG_UTF8 = 0x0800;
constexpr uint16_t METHOD_STORED = 0;
constexpr uint16_t METHOD_DEFLATE = 8;
constexpr uint32_t MAX_32 = 0xFFFFFFFFu;
constexpr uint16_t MAX_16 = 0xFFFF;
constexpr uint32_t DOS_DIRECTORY = 0x10;
// Generous cap on the central directory read into memory (65535 entries with
// long names fit easily), so a corrupt size can't demand a huge allocation.
constexpr uint32_t MAX_CENTRAL_DIRECTORY = 64u * 1024 * 1024;

void put16(std::vector<unsigned char>& v, uint16_t x) {
    v.push_back(static_cast<unsigned char>(x));
    v.push_back(static_cast<unsigned char>(x >> 8));
}

void put32(std::vector<unsigned char>& v, uint32_t x) {
    put16(v, static_cast<uint16_t>(x));
    put16(v, static_cast<uint16_t>(x >> 16));
}

uint16_t get16(const unsigned char* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t get32(const unsigned char* p) {
    return static_cast<uint32_t>(get16(p)) | (static_cast<uint32_t>(get16(p + 2)) << 16);
}

// MS-DOS date/time (local time, 2-second resolution, years 1980..2107).
void to_dos_time(std::time_t t, uint16_t& dos_time, uint16_t& dos_date) {
    std::tm tm{};
    if (!localtime_r(&t, &tm) || tm.tm_year < 80) {
        dos_time = 0;
        dos_date = (1 << 5) | 1;                   // 1980-01-01 00:00:00
        return;
    }
    if (tm.tm_year > 207) {                         // clamp to 2107-12-31
        dos_time = (23 << 11) | (59 << 5) | 29;
        dos_date = static_cast<uint16_t>((127 << 9) | (12 << 5) | 31);
        return;
    }
    dos_time = static_cast<uint16_t>((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
    dos_date = static_cast<uint16_t>(((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
}

std::time_t from_dos_time(uint16_t dos_time, uint16_t dos_date) {
    std::tm tm{};
    tm.tm_year = ((dos_date >> 9) & 0x7F) + 80;
    tm.tm_mon = std::max(((dos_date >> 5) & 0x0F) - 1, 0);
    tm.tm_mday = std::max(dos_date & 0x1F, 1);
    tm.tm_hour = (dos_time >> 11) & 0x1F;
    tm.tm_min = (dos_time >> 5) & 0x3F;
    tm.tm_sec = (dos_time & 0x1F) * 2;
    tm.tm_isdst = -1;
    std::time_t t = std::mktime(&tm);
    return t == static_cast<std::time_t>(-1) ? 0 : t;
}

bool fail(std::string& error, const std::string& what) {
    error = what;
    return false;
}

} // namespace

bool zip_name_is_safe(const std::string& name, std::string& why) {
    if (name.empty()) { why = "empty name"; return false; }
    // Reject C0 control bytes (incl. NUL) and DEL: they are never needed in a
    // real path and are the vehicle for terminal-escape injection when a name
    // is displayed. Bytes >= 0x80 are left alone so UTF-8 names stay valid.
    for (unsigned char c : name) {
        if (c < 0x20 || c == 0x7f) {
            static const char hex[] = "0123456789abcdef";
            why = "control character \\x";
            why += hex[c >> 4];
            why += hex[c & 0xf];
            why += " in name";
            return false;
        }
    }
    if (name[0] == '/') { why = "absolute path"; return false; }
    // Components between '/'s; a single trailing '/' marks a directory.
    const size_t end = name.back() == '/' ? name.size() - 1 : name.size();
    size_t start = 0;
    for (;;) {
        size_t slash = name.find('/', start);
        if (slash == std::string::npos || slash > end) slash = end;
        const std::string part = name.substr(start, slash - start);
        if (part.empty()) { why = "empty path component"; return false; }
        if (part == "." || part == "..") { why = "'.' or '..' path component"; return false; }
        if (slash == end) return true;
        start = slash + 1;
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

bool ZipWriter::emit(const std::vector<unsigned char>& bytes, std::string& error) {
    if (bytes.empty()) return true;
    if (bytes.size() >= MAX_32 - offset_ || offset_ >= MAX_32) {
        return fail(error, "archive too large (limit 4 GiB; ZIP64 is not supported)");
    }
    if (!out_.write(bytes.data(), bytes.size(), error)) return false;
    offset_ += bytes.size();
    return true;
}

// Validate the entry and write its local header.
bool ZipWriter::begin_entry(Central& c, std::string& error) {
    std::string why;
    if (!zip_name_is_safe(c.name, why)) {
        return fail(error, "cannot archive '" + c.name + "': " + why);
    }
    if (c.name.size() > MAX_16) return fail(error, "file name too long for ZIP: " + c.name);
    // An entry count of 0xFFFF is the ZIP64 sentinel the reader refuses.
    if (central_.size() >= ZIP_MAX_ENTRIES) {
        return fail(error, "too many files for a ZIP archive (limit 65534; ZIP64 is not supported)");
    }
    c.offset = static_cast<uint32_t>(offset_);

    std::vector<unsigned char> h;
    put32(h, SIG_LOCAL);
    put16(h, VERSION_NEEDED);
    put16(h, c.flags);
    put16(h, c.method);
    put16(h, c.dos_time);
    put16(h, c.dos_date);
    // With a data descriptor these are zero here and follow the data.
    const bool deferred = c.flags & FLAG_DATA_DESCRIPTOR;
    put32(h, deferred ? 0 : c.crc);
    put32(h, deferred ? 0 : c.comp_size);
    put32(h, deferred ? 0 : c.size);
    put16(h, static_cast<uint16_t>(c.name.size()));
    put16(h, 0);                                    // extra field length
    h.insert(h.end(), c.name.begin(), c.name.end());
    return emit(h, error);
}

bool ZipWriter::add_directory(const std::string& name, uint32_t mode, std::time_t mtime,
                              std::string& error) {
    if (name.empty() || name.back() != '/') {
        return fail(error, "directory names must end in '/': " + name);
    }
    Central c{};
    c.name = name;
    c.flags = FLAG_UTF8;
    c.method = METHOD_STORED;
    c.external_attr = ((S_IFDIR | (mode & 07777)) << 16) | DOS_DIRECTORY;
    to_dos_time(mtime, c.dos_time, c.dos_date);
    if (!begin_entry(c, error)) return false;
    central_.push_back(std::move(c));
    return true;
}

bool ZipWriter::add_file(const std::string& name, uint32_t mode, std::time_t mtime,
                         ByteSource& in, std::string& error) {
    if (!name.empty() && name.back() == '/') {
        return fail(error, "file names must not end in '/': " + name);
    }
    Central c{};
    c.name = name;
    c.flags = FLAG_UTF8 | FLAG_DATA_DESCRIPTOR;
    c.method = METHOD_DEFLATE;     // stored-block fallback bounds any growth
    c.external_attr = (S_IFREG | (mode & 07777)) << 16;
    to_dos_time(mtime, c.dos_time, c.dos_date);
    if (!begin_entry(c, error)) return false;

    DeflateStream deflate;
    std::vector<unsigned char> buf(1024 * 1024), compressed;
    uint64_t size = 0, comp_size = 0;
    uint32_t crc = 0;
    bool done = false;
    while (!done) {
        long long n = in.read(buf.data(), buf.size(), error);
        if (n < 0) {
            error = name + ": " + error;
            return false;
        }
        compressed.clear();
        if (n == 0) {
            deflate.finish(compressed);
            done = true;
        } else {
            crc = crc32(buf.data(), static_cast<size_t>(n), crc);
            size += static_cast<uint64_t>(n);
            if (size > ZIP_MAX_FILE_SIZE) {     // the file grew after pre-flight
                return fail(error, "file too large for a ZIP archive (limit 4 GiB; "
                                   "ZIP64 is not supported): " + name);
            }
            deflate.write(buf.data(), static_cast<size_t>(n), compressed);
        }
        comp_size += compressed.size();
        if (!emit(compressed, error)) return false;
    }
    sodium_memzero(buf.data(), buf.size());

    c.crc = crc;
    c.size = static_cast<uint32_t>(size);
    c.comp_size = static_cast<uint32_t>(comp_size);
    std::vector<unsigned char> d;
    put32(d, SIG_DATA_DESCRIPTOR);
    put32(d, c.crc);
    put32(d, c.comp_size);
    put32(d, c.size);
    if (!emit(d, error)) return false;
    central_.push_back(std::move(c));
    return true;
}

bool ZipWriter::finish(std::string& error) {
    const uint64_t cd_offset = offset_;
    std::vector<unsigned char> b;
    for (const Central& c : central_) {
        b.clear();
        put32(b, SIG_CENTRAL);
        put16(b, VERSION_MADE_BY);
        put16(b, VERSION_NEEDED);
        put16(b, c.flags);
        put16(b, c.method);
        put16(b, c.dos_time);
        put16(b, c.dos_date);
        put32(b, c.crc);
        put32(b, c.comp_size);
        put32(b, c.size);
        put16(b, static_cast<uint16_t>(c.name.size()));
        put16(b, 0);                                // extra field length
        put16(b, 0);                                // comment length
        put16(b, 0);                                // disk number start
        put16(b, 0);                                // internal attributes
        put32(b, c.external_attr);
        put32(b, c.offset);
        b.insert(b.end(), c.name.begin(), c.name.end());
        if (!emit(b, error)) return false;
    }
    const uint64_t cd_size = offset_ - cd_offset;
    b.clear();
    put32(b, SIG_EOCD);
    put16(b, 0);                                    // this disk
    put16(b, 0);                                    // disk with central directory
    put16(b, static_cast<uint16_t>(central_.size()));
    put16(b, static_cast<uint16_t>(central_.size()));
    put32(b, static_cast<uint32_t>(cd_size));
    put32(b, static_cast<uint32_t>(cd_offset));
    put16(b, 0);                                    // comment length
    return emit(b, error);
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

bool zip_list(int fd, uint64_t size, std::vector<ZipMember>& members, std::string& error,
              std::vector<std::pair<std::string, std::string>>* lost) {
    members.clear();
    if (size < EOCD_LEN) return fail(error, "not a ZIP archive (too short)");

    // The end-of-central-directory record is the last thing in the file,
    // followed only by its own comment (at most 65535 bytes).
    const size_t tail_len = static_cast<size_t>(std::min<uint64_t>(size, EOCD_LEN + MAX_16));
    const uint64_t tail_start = size - tail_len;
    std::vector<unsigned char> tail(tail_len);
    if (!pread_exact(fd, tail_start, tail.data(), tail_len, error)) return false;
    size_t idx = 0;
    bool found = false;
    for (size_t pos = tail_len - EOCD_LEN + 1; pos-- > 0;) {
        if (get32(&tail[pos]) == SIG_EOCD && pos + EOCD_LEN + get16(&tail[pos + 20]) == tail_len) {
            idx = pos;
            found = true;
            break;
        }
    }
    if (!found) return fail(error, "not a ZIP archive (no end-of-central-directory record)");
    const uint64_t eocd = tail_start + idx;
    if (eocd >= 20) {
        unsigned char loc[4];
        if (!pread_exact(fd, eocd - 20, loc, 4, error)) return false;
        if (get32(loc) == SIG_ZIP64_LOCATOR) return fail(error, "ZIP64 archives are not supported");
    }
    const unsigned char* e = &tail[idx];
    const uint16_t disk = get16(e + 4), cd_disk = get16(e + 6);
    const uint16_t count_disk = get16(e + 8), count = get16(e + 10);
    const uint32_t cd_size = get32(e + 12), cd_offset = get32(e + 16);
    if (count == MAX_16 || cd_size == MAX_32 || cd_offset == MAX_32) {
        return fail(error, "ZIP64 archives are not supported");
    }
    if (disk != 0 || cd_disk != 0 || count_disk != count) {
        return fail(error, "multi-disk ZIP archives are not supported");
    }
    if (cd_offset > eocd || cd_size > eocd - cd_offset) {
        return fail(error, "corrupt ZIP archive (central directory out of range)");
    }
    if (cd_size > MAX_CENTRAL_DIRECTORY) {
        return fail(error, "ZIP central directory too large");
    }
    std::vector<unsigned char> cd(cd_size);
    if (!pread_exact(fd, cd_offset, cd.data(), cd_size, error)) return false;

    std::set<std::string> names;
    // ([local header, data end), index into members)
    std::vector<std::pair<std::pair<uint64_t, uint64_t>, size_t>> ranges;
    size_t pos = 0;
    for (uint16_t i = 0; i < count; ++i) {
        if (cd_size - pos < CENTRAL_LEN || get32(&cd[pos]) != SIG_CENTRAL) {
            return fail(error, "corrupt ZIP archive (bad central directory entry)");
        }
        const unsigned char* c = &cd[pos];
        const uint16_t made_by = get16(c + 4);
        const uint16_t flags = get16(c + 8);
        ZipMember m;
        m.method = get16(c + 10);
        const uint16_t dos_time = get16(c + 12), dos_date = get16(c + 14);
        m.crc = get32(c + 16);
        m.comp_size = get32(c + 20);
        m.size = get32(c + 24);
        const size_t name_len = get16(c + 28), extra_len = get16(c + 30), comment_len = get16(c + 32);
        const uint16_t start_disk = get16(c + 34);
        const uint32_t external_attr = get32(c + 38);
        const uint32_t local_offset = get32(c + 42);
        if (cd_size - pos - CENTRAL_LEN < name_len + extra_len + comment_len) {
            return fail(error, "corrupt ZIP archive (central directory entry overruns)");
        }
        m.name.assign(reinterpret_cast<const char*>(c + CENTRAL_LEN), name_len);
        pos += CENTRAL_LEN + name_len + extra_len + comment_len;

        // A per-member problem rejects the whole archive, or in lenient mode
        // (`lost` given) just that member.
        auto reject = [&](const std::string& why) {
            if (!lost) {
                error = why;
                return false;
            }
            lost->push_back({m.name, why});
            return true;
        };
        std::string why;
        if (!zip_name_is_safe(m.name, why)) {
            if (!reject("unsafe path in archive '" + m.name + "': " + why)) return false;
            continue;
        }
        if (!names.insert(m.name).second) {
            if (!reject("duplicate path in archive: " + m.name)) return false;
            continue;
        }
        if (flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION)) {
            if (!reject("encrypted ZIP entries are not supported: " + m.name)) return false;
            continue;
        }
        if (m.method != METHOD_STORED && m.method != METHOD_DEFLATE) {
            if (!reject("unsupported compression method " + std::to_string(m.method) + ": " +
                        m.name)) {
                return false;
            }
            continue;
        }
        if (m.comp_size == MAX_32 || m.size == MAX_32 || local_offset == MAX_32) {
            if (!reject("ZIP64 archives are not supported")) return false;
            continue;
        }
        if (start_disk != 0) {
            if (!reject("multi-disk ZIP archives are not supported")) return false;
            continue;
        }
        if (m.method == METHOD_STORED && m.comp_size != m.size) {
            if (!reject("corrupt ZIP archive (stored size mismatch): " + m.name)) return false;
            continue;
        }

        // Entry type: only regular files and directories, from the Unix mode
        // when the archive was made on Unix.
        m.is_dir = m.name.back() == '/';
        const uint32_t unix_mode = external_attr >> 16;
        const uint32_t type = unix_mode & S_IFMT;
        if ((made_by >> 8) == 3 && type != 0) {
            if (type == S_IFLNK) {
                if (!reject("symbolic links are not supported: " + m.name)) return false;
                continue;
            }
            if (type != S_IFREG && type != S_IFDIR) {
                if (!reject("special files are not supported: " + m.name)) return false;
                continue;
            }
            if ((type == S_IFDIR) != m.is_dir) {
                if (!reject("corrupt ZIP archive (directory flag mismatch): " + m.name)) return false;
                continue;
            }
            m.mode = unix_mode & 07777;
        }
        if (m.is_dir && m.size != 0) {
            if (!reject("corrupt ZIP archive (directory with data): " + m.name)) return false;
            continue;
        }
        m.mtime = from_dos_time(dos_time, dos_date);

        // The local header must agree with the central directory, and the
        // data must lie before the central directory.
        unsigned char l[LOCAL_LEN];
        if (local_offset > cd_offset || cd_offset - local_offset < LOCAL_LEN ||
            !pread_exact(fd, local_offset, l, LOCAL_LEN, error) || get32(l) != SIG_LOCAL) {
            if (!reject("corrupt ZIP archive (bad local header): " + m.name)) return false;
            continue;
        }
        const size_t l_name_len = get16(l + 26), l_extra_len = get16(l + 28);
        const uint64_t data_start = uint64_t{local_offset} + LOCAL_LEN + l_name_len + l_extra_len;
        std::string l_name(l_name_len, '\0');
        if (get16(l + 8) != m.method || l_name_len != name_len || data_start > cd_offset ||
            !pread_exact(fd, uint64_t{local_offset} + LOCAL_LEN,
                         reinterpret_cast<unsigned char*>(&l_name[0]), l_name_len, error) ||
            l_name != m.name) {
            if (!reject("corrupt ZIP archive (local header disagrees): " + m.name)) return false;
            continue;
        }
        if (m.comp_size > cd_offset - data_start) {
            if (!reject("corrupt ZIP archive (entry data out of range): " + m.name)) return false;
            continue;
        }
        m.data_offset = data_start;
        ranges.push_back({{local_offset, data_start + m.comp_size}, members.size()});
        members.push_back(std::move(m));
    }
    if (pos != cd_size) return fail(error, "corrupt ZIP archive (central directory size mismatch)");

    // Each entry's bytes must be its own: overlapping entries are how the
    // most efficient zip bombs reuse one compressed stream many times.
    std::sort(ranges.begin(), ranges.end());
    std::vector<bool> overlapping(members.size(), false);
    bool any_overlap = false;
    uint64_t furthest = 0;
    size_t furthest_member = 0;
    for (size_t i = 0; i < ranges.size(); ++i) {
        if (i > 0 && ranges[i].first.first < furthest) {
            overlapping[ranges[i].second] = overlapping[furthest_member] = true;
            any_overlap = true;
        }
        if (ranges[i].first.second > furthest) {
            furthest = ranges[i].first.second;
            furthest_member = ranges[i].second;
        }
    }
    if (any_overlap) {
        if (!lost) return fail(error, "corrupt ZIP archive (overlapping entries)");
        std::vector<ZipMember> kept;
        for (size_t i = 0; i < members.size(); ++i) {
            if (overlapping[i]) {
                lost->push_back({members[i].name, "corrupt ZIP archive (overlapping entries)"});
            } else {
                kept.push_back(std::move(members[i]));
            }
        }
        members.swap(kept);
    }
    return true;
}

namespace {

// Forwards to another sink while counting bytes and computing their CRC-32.
class CheckedSink : public ByteSink {
public:
    explicit CheckedSink(ByteSink& out) : out_(out) {}
    bool write(const unsigned char* data, size_t n, std::string& error) override {
        crc_ = crc32(data, n, crc_);
        count_ += n;
        return out_.write(data, n, error);
    }
    uint32_t crc() const { return crc_; }
    uint64_t count() const { return count_; }

private:
    ByteSink& out_;
    uint32_t crc_ = 0;
    uint64_t count_ = 0;
};

// Discards bytes (used to verify entries during a salvage scan before
// anything is written).
class NullSink : public ByteSink {
public:
    bool write(const unsigned char*, size_t, std::string&) override { return true; }
};

} // namespace

bool zip_scan(int fd, uint64_t limit, uint64_t max_entry_size, std::vector<ZipMember>& members,
              std::vector<std::pair<std::string, std::string>>& lost, std::string& tail_problem,
              std::string& error) {
    members.clear();
    tail_problem.clear();
    std::set<std::string> names;
    uint64_t pos = 0;
    // The scan can't continue past this point; everything after is lost.
    auto stop = [&](const std::string& why) {
        tail_problem = why;
        return true;
    };
    for (;;) {
        unsigned char l[LOCAL_LEN];
        if (limit - pos < 4) return stop("the archive is cut off");
        if (!pread_exact(fd, pos, l, 4, error)) return false;
        const uint32_t sig = get32(l);
        if (sig == SIG_CENTRAL || sig == SIG_EOCD) return true;     // every entry seen
        if (sig != SIG_LOCAL) return stop("unrecognized data at offset " + std::to_string(pos));
        if (limit - pos < LOCAL_LEN) return stop("the archive is cut off inside an entry header");
        if (!pread_exact(fd, pos, l, LOCAL_LEN, error)) return false;

        const uint16_t flags = get16(l + 6);
        ZipMember m;
        m.method = get16(l + 8);
        m.mtime = from_dos_time(get16(l + 10), get16(l + 12));
        m.crc = get32(l + 14);
        m.comp_size = get32(l + 18);
        m.size = get32(l + 22);
        const size_t name_len = get16(l + 26), extra_len = get16(l + 28);
        if (limit - pos - LOCAL_LEN < name_len + extra_len) {
            return stop("the archive is cut off inside an entry header");
        }
        m.name.assign(name_len, '\0');
        if (name_len && !pread_exact(fd, pos + LOCAL_LEN,
                                     reinterpret_cast<unsigned char*>(&m.name[0]), name_len, error)) {
            return false;
        }
        m.is_dir = !m.name.empty() && m.name.back() == '/';
        m.data_offset = pos + LOCAL_LEN + name_len + extra_len;
        const std::string label = m.name.empty() ? "(unnamed entry)" : m.name;
        if (flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION)) {
            return stop(label + ": encrypted ZIP entries are not supported");
        }

        // Where the entry ends: from the header, or - with a data descriptor -
        // by decompressing until the DEFLATE stream ends and reading the
        // descriptor after it.
        std::string why;
        uint64_t next;
        if (!(flags & FLAG_DATA_DESCRIPTOR)) {
            if (m.comp_size == MAX_32 || m.size == MAX_32) {
                return stop(label + ": ZIP64 entries are not supported");
            }
            if (m.comp_size > limit - m.data_offset) {
                return stop(label + ": the archive is cut off inside this entry");
            }
            next = m.data_offset + m.comp_size;
        } else {
            if (m.method != METHOD_DEFLATE) return stop(label + ": cannot find the end of this entry");
            FdRangeSource src(fd, m.data_offset, limit - m.data_offset);
            NullSink discard;
            CheckedSink counter(discard);
            uint64_t consumed = 0;
            if (!inflate_stream(src, max_entry_size, counter, why, &consumed)) {
                return stop(label + ": " + why);
            }
            const uint64_t d = m.data_offset + consumed;
            unsigned char desc[12];
            if (limit - d < 12) return stop(label + ": the archive is cut off inside this entry");
            if (!pread_exact(fd, d, desc, 4, error)) return false;
            const size_t sig_len = get32(desc) == SIG_DATA_DESCRIPTOR ? 4 : 0;   // optional
            if (limit - d < 12 + sig_len) {
                return stop(label + ": the archive is cut off inside this entry");
            }
            if (!pread_exact(fd, d + sig_len, desc, 12, error)) return false;
            m.crc = get32(desc);
            m.comp_size = get32(desc + 4);
            m.size = get32(desc + 8);
            if (m.comp_size != consumed || m.size != counter.count() || m.crc != counter.crc()) {
                return stop(label + ": data descriptor does not match the data");
            }
            next = d + sig_len + 12;
        }

        // The entry's bounds are known, so a problem with this entry alone
        // loses just this entry.
        std::string problem;
        if (!zip_name_is_safe(m.name, why)) {
            problem = "unsafe path: " + why;
        } else if (!names.insert(m.name).second) {
            problem = "duplicate path in archive";
        } else if (m.method != METHOD_STORED && m.method != METHOD_DEFLATE) {
            problem = "unsupported compression method " + std::to_string(m.method);
        } else if (m.method == METHOD_STORED && m.comp_size != m.size) {
            problem = "stored size mismatch";
        } else if (m.is_dir && m.size != 0) {
            problem = "directory with data";
        } else if (m.size > max_entry_size) {
            problem = "larger than the free disk space";
        } else if (!m.is_dir) {
            NullSink discard;
            if (!zip_extract_member(fd, m, discard, why)) problem = why;
        }
        if (problem.empty()) {
            members.push_back(std::move(m));
        } else {
            lost.push_back({label, problem});
        }
        pos = next;
    }
}

bool zip_extract_member(int fd, const ZipMember& m, ByteSink& out, std::string& error) {
    FdRangeSource src(fd, m.data_offset, m.comp_size);
    CheckedSink checked(out);
    if (m.method == METHOD_STORED) {
        std::vector<unsigned char> buf(64 * 1024);
        for (;;) {
            long long n = src.read(buf.data(), buf.size(), error);
            if (n < 0) return fail(error, m.name + ": " + error);
            if (n == 0) break;
            if (!checked.write(buf.data(), static_cast<size_t>(n), error)) return false;
        }
        sodium_memzero(buf.data(), buf.size());
    } else {
        std::string why;
        if (!inflate_stream(src, m.size, checked, why)) return fail(error, m.name + ": " + why);
    }
    if (checked.count() != m.size) {
        return fail(error, m.name + ": size does not match archive directory");
    }
    if (checked.crc() != m.crc) return fail(error, m.name + ": CRC-32 mismatch");
    return true;
}

} // namespace pkcrypt

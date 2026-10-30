#ifndef PKCRYPT_ZIP_H
#define PKCRYPT_ZIP_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//
// In-house streaming ZIP archive writer and reader (PKWARE APPNOTE), using
// the in-house DEFLATE in deflate.h. Supports the classic (non-ZIP64) format: up to 65535
// entries and 4 GiB per file/archive, methods 0 (stored) and 8 (deflate).
//
// The reader treats its input as hostile: it validates every name, rejects
// symlinks and special files, rejects encrypted/ZIP64/multi-disk archives,
// requires every entry's data to occupy its own non-overlapping byte range,
// and enforces each entry's declared size and CRC-32 when decompressing.
//

#include <cstdint>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

#include "pkcrypt/stream.h"

namespace pkcrypt {

// Writes a ZIP archive to a sink as entries are added. File contents are
// streamed through the DEFLATE compressor, so nothing is held in memory
// beyond small buffers. Because sizes and CRCs are only known afterwards, each
// file's local header is followed by its data and then a data descriptor
// (general-purpose flag bit 3); the central directory carries the real values.
class ZipWriter {
public:
    explicit ZipWriter(ByteSink& out) : out_(out) {}

    // Add a directory (`name` must end in '/'). `mode` holds Unix permission bits.
    bool add_directory(const std::string& name, uint32_t mode, std::time_t mtime,
                       std::string& error);

    // Add a file whose contents are read from `in` until it ends.
    bool add_file(const std::string& name, uint32_t mode, std::time_t mtime, ByteSource& in,
                  std::string& error);

    // Write the central directory and end record.
    bool finish(std::string& error);

private:
    struct Central {
        std::string name;
        uint16_t flags, method, dos_time, dos_date;
        uint32_t crc, comp_size, size, external_attr, offset;
    };
    bool emit(const std::vector<unsigned char>& bytes, std::string& error);
    bool begin_entry(Central& c, std::string& error);

    ByteSink& out_;
    uint64_t offset_ = 0;
    std::vector<Central> central_;
};

// One validated archive member, as described by the central directory.
struct ZipMember {
    std::string name;           // validated relative path, '/' separators
    bool is_dir = false;        // name ends in '/'
    uint32_t mode = 0;          // Unix permission bits, if recorded (else 0)
    std::time_t mtime = 0;
    uint16_t method = 0;        // 0 = stored, 8 = deflate
    uint32_t crc = 0;
    uint32_t comp_size = 0;
    uint32_t size = 0;          // declared uncompressed size
    uint64_t data_offset = 0;   // start of compressed data in the archive
};

// Parse and validate the central directory of the archive in file `fd`
// (`size` bytes long). On success `members` lists every entry in
// central-directory order. Any problem fails the whole archive - unless
// `lost` is given (salvage): then a problem confined to one member (unsafe
// name, symlink, overlap, bad local header, ...) drops just that member,
// recorded in `lost` as (name, reason). Problems with the central directory
// itself still fail.
bool zip_list(int fd, uint64_t size, std::vector<ZipMember>& members, std::string& error,
              std::vector<std::pair<std::string, std::string>>* lost = nullptr);

// Salvage scan for an archive whose central directory is missing or unusable,
// e.g. the readable prefix of a damaged file: walk the local headers in order
// over the first `limit` bytes, fully verifying each entry (data, CRC-32,
// sizes; with a data descriptor, the DEFLATE stream's end locates it).
// Verified entries go to `members`; an entry whose bounds are known but whose
// content is bad goes to `lost` and the scan continues. When an entry's end
// can't be determined (cut off, corrupt stream), the scan stops and
// `tail_problem` says why: later entries are unrecoverable. It is empty when
// the scan reached the central directory. No entry may expand past
// `max_entry_size`. Returns false only on an I/O error.
bool zip_scan(int fd, uint64_t limit, uint64_t max_entry_size, std::vector<ZipMember>& members,
              std::vector<std::pair<std::string, std::string>>& lost, std::string& tail_problem,
              std::string& error);

// Decompress one member into `out`, enforcing its declared size and CRC-32.
// Output is streamed, so on failure `out` may have received part of it.
bool zip_extract_member(int fd, const ZipMember& member, ByteSink& out, std::string& error);

// True if `name` is a safe relative member path: not empty, no NUL, not
// absolute, and no empty, "." or ".." components (a trailing '/' marks a
// directory). Sets `why` otherwise.
bool zip_name_is_safe(const std::string& name, std::string& why);

} // namespace pkcrypt

#endif // PKCRYPT_ZIP_H

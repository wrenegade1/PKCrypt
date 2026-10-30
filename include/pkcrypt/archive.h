#ifndef PKCRYPT_ARCHIVE_H
#define PKCRYPT_ARCHIVE_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
// Author: Warren Zajac
//
// Folder <-> ZIP archive, for encrypting a whole folder into one .pkcrypt.
//

#include <cstdint>
#include <string>
#include <vector>

#include "pkcrypt/stream.h"

namespace pkcrypt {

struct ArchiveStats {
    size_t files = 0;
    size_t directories = 0;
    unsigned long long bytes = 0;           // total uncompressed file bytes
    std::vector<std::string> skipped;       // symlinks / special files (pack)
};

// Stream a ZIP archive of the contents of `dir` (paths relative to it, in
// sorted order) into `out`, one file at a time. Symbolic links and special
// files are not followed or stored; their relative paths are listed in
// `stats.skipped`.
bool pack_directory(const std::string& dir, ByteSink& out, ArchiveStats& stats,
                    std::string& error);

// Extract the ZIP archive in file `fd` (`size` bytes) into the new directory
// `dest`, which must not exist. The archive is validated first; entries are
// then streamed into a private temporary directory beside `dest`, which is
// renamed into place only once every entry has been extracted and verified,
// so a failure leaves nothing behind. Files are created 0600 (0700 if
// owner-executable in the archive), directories 0700.
bool extract_archive(int fd, uint64_t size, const std::string& dest, ArchiveStats& stats,
                     std::string& error);

// Result of a salvage: what was recovered and what was lost.
struct SalvageReport {
    bool verified_whole = false;    // the whole encrypted file authenticated
    ArchiveStats stats;                                     // recovered
    std::vector<std::pair<std::string, std::string>> lost;  // (name, reason)
    std::string tail_problem;   // non-empty: the archive is unreadable from some
                                // point on, so later entries (names unknown)
                                // are lost too; this says why
    // Nothing lost. Never true if decryption failed part-way, even if every
    // entry seen was recovered.
    bool complete() const { return verified_whole && lost.empty() && tail_problem.empty(); }
};

// Salvage-mode extraction: recover every entry that can be fully verified
// from the archive in file `fd` (`size` bytes), skipping the rest. With
// `verified_whole` (the whole archive decrypted and authenticated), the
// central directory is used and a bad entry loses only itself; otherwise
// `fd` holds just the readable prefix of a damaged archive, which is scanned
// entry by entry up to the first entry whose end can't be found. Every
// extraction safety rule still applies to each entry. The result goes to
// `dest` if nothing was lost, else to `partial_dest`; neither may exist.
// Returns false (with `error`), writing nothing, if no entry could be
// recovered at all.
bool salvage_archive(int fd, uint64_t size, bool verified_whole, const std::string& dest,
                     const std::string& partial_dest, SalvageReport& report, std::string& error);

} // namespace pkcrypt

#endif // PKCRYPT_ARCHIVE_H

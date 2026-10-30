//
// PKCrypt - test harness exposing the in-house DEFLATE, CRC-32 and ZIP code to
// the Python test suite, which checks it against independent implementations
// (Python's zlib/zipfile) and feeds it hostile input. Built with sanitizers by
// `make test`; not shipped.
//
// Author: Warren Zajac
//
// Usage (data on stdin, result on stdout):
//   deflate_harness compress           raw DEFLATE stream
//   deflate_harness compress-stream <piece>
//                                      same, fed to DeflateStream <piece> bytes
//                                      at a time
//   deflate_harness inflate <max_out>  decompressed bytes (exit 1 on error)
//   deflate_harness inflate-stream <max_out> <piece>
//                                      same, through inflate_stream with a
//                                      source returning <= <piece> bytes a read
//   deflate_harness crc32              CRC-32 as 8 hex digits
//   deflate_harness base64-encode    raw bytes -> base64 text
//   deflate_harness base64-decode    base64 text -> raw bytes (exit 1 if invalid)
//   deflate_harness inflate-batch <max_out>
//       stdin: repeated [u32 little-endian length][stream]; stdout: one line
//       per stream, "ok <crc32> <length>" or "err". Lets the fuzz tests run
//       thousands of cases in one process.
//   deflate_harness zip-extract <dest> ZIP archive -> extracted into <dest>
//                                      (exit 1 with the error on failure)
//   deflate_harness zip-pack <dir>     ZIP archive of <dir> on stdout (no stdin)
//   deflate_harness zip-salvage <dest> <whole>
//                                      salvage-extract stdin into <dest>, as the
//                                      verified whole archive (<whole> = 1) or a
//                                      damaged prefix (0); exit 0 complete,
//                                      3 partial, 1 nothing recovered
//

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include "pkcrypt/archive.h"
#include "pkcrypt/base64.h"
#include "pkcrypt/deflate.h"
#include "pkcrypt/fileio.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: deflate_harness compress|inflate <max>|crc32\n";
        return 2;
    }
    const std::string mode = argv[1];
    std::vector<unsigned char> out;
    std::string error;

    if (mode == "zip-pack" && argc >= 3) {
        pkcrypt::VectorSink sink(out);
        pkcrypt::ArchiveStats stats;
        if (!pkcrypt::pack_directory(argv[2], sink, stats, error)) {
            std::cerr << error << "\n";
            return 1;
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
        return 0;
    }

    std::freopen(nullptr, "rb", stdin);
    std::vector<unsigned char> in((std::istreambuf_iterator<char>(std::cin)),
                                  std::istreambuf_iterator<char>());

    if (mode == "compress") {
        out = pkcrypt::deflate_compress(in.data(), in.size());
    } else if (mode == "compress-stream" && argc >= 3) {
        size_t piece = std::strtoull(argv[2], nullptr, 10);
        pkcrypt::DeflateStream stream;
        for (size_t pos = 0; pos < in.size(); pos += piece) {
            stream.write(in.data() + pos, std::min(piece, in.size() - pos), out);
        }
        stream.finish(out);
    } else if (mode == "inflate-stream" && argc >= 4) {
        size_t max_out = std::strtoull(argv[2], nullptr, 10);
        pkcrypt::MemorySource src(in.data(), in.size(), std::strtoull(argv[3], nullptr, 10));
        pkcrypt::VectorSink sink(out);
        if (!pkcrypt::inflate_stream(src, max_out, sink, error)) {
            std::cerr << error << "\n";
            return 1;
        }
    } else if (mode == "inflate" && argc >= 3) {
        size_t max_out = std::strtoull(argv[2], nullptr, 10);
        if (!pkcrypt::inflate(in.data(), in.size(), max_out, out, error)) {
            std::cerr << error << "\n";
            return 1;
        }
    } else if (mode == "inflate-batch" && argc >= 3) {
        size_t max_out = std::strtoull(argv[2], nullptr, 10);
        size_t pos = 0;
        while (pos + 4 <= in.size()) {
            size_t n = in[pos] | (in[pos + 1] << 8) | (in[pos + 2] << 16) |
                       (static_cast<size_t>(in[pos + 3]) << 24);
            pos += 4;
            if (n > in.size() - pos) { std::cerr << "bad batch framing\n"; return 2; }
            if (pkcrypt::inflate(in.data() + pos, n, max_out, out, error)) {
                std::printf("ok %08x %zu\n", pkcrypt::crc32(out.data(), out.size()), out.size());
            } else {
                std::printf("err\n");
            }
            pos += n;
        }
        return 0;
    } else if (mode == "zip-extract" && argc >= 3) {
        // Through a real file, as the CLI does.
        pkcrypt::TempFile tmp;
        pkcrypt::ArchiveStats stats;
        if (!tmp.create(pkcrypt::parent_dir(argv[2]), error) ||
            !tmp.write(in.data(), in.size(), error) ||
            !pkcrypt::extract_archive(tmp.fd(), tmp.size(), argv[2], stats, error)) {
            std::cerr << error << "\n";
            return 1;
        }
        return 0;
    } else if (mode == "zip-salvage" && argc >= 4) {
        pkcrypt::TempFile tmp;
        pkcrypt::SalvageReport report;
        const std::string dest = argv[2];
        if (!tmp.create(pkcrypt::parent_dir(dest), error) ||
            !tmp.write(in.data(), in.size(), error) ||
            !pkcrypt::salvage_archive(tmp.fd(), tmp.size(), std::string(argv[3]) == "1", dest,
                                      dest + ".partial", report, error)) {
            std::cerr << error << "\n";
            return 1;
        }
        return report.complete() ? 0 : 3;
    } else if (mode == "crc32") {
        std::printf("%08x\n", pkcrypt::crc32(in.data(), in.size()));
        return 0;
    } else if (mode == "base64-encode") {
        std::string e = pkcrypt::base64_encode(in.data(), in.size());
        std::fwrite(e.data(), 1, e.size(), stdout);
        return 0;
    } else if (mode == "base64-decode") {
        std::string text(in.begin(), in.end());
        if (!pkcrypt::base64_decode(text, out)) {
            std::cerr << "invalid base64\n";
            return 1;
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
        return 0;
    } else {
        std::cerr << "unknown mode: " << mode << "\n";
        return 2;
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}

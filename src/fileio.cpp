#include "pkcrypt/fileio.h"

#include <fstream>
#include <sys/stat.h>

namespace pkcrypt {

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
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) { error = "cannot write file: " + path; return false; }
    if (len > 0 && !f.write(reinterpret_cast<const char*>(data),
                            static_cast<std::streamsize>(len))) {
        error = "write error: " + path;
        return false;
    }
    return true;
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

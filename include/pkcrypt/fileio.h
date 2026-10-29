#ifndef PKCRYPT_FILEIO_H
#define PKCRYPT_FILEIO_H

#include <string>
#include <vector>

namespace pkcrypt {

// Read an entire file into memory. Returns false and sets `error` on failure.
bool read_file(const std::string& path, std::vector<unsigned char>& out,
               std::string& error);

// Write bytes to a file (truncating any existing content).
// Returns false and sets `error` on failure.
bool write_file(const std::string& path, const unsigned char* data, size_t len,
                std::string& error);

// Derive an encrypted output path: <input>.pkcrypt  (unless it would collide).
std::string encrypted_output_path(const std::string& input_path);

// Derive a decrypted output path: strips a trailing ".pkcrypt", or appends
// ".decrypted" otherwise (never overwrites an existing file).
std::string decrypted_output_path(const std::string& input_path);

} // namespace pkcrypt

#endif // PKCRYPT_FILEIO_H

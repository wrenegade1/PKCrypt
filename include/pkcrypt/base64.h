#ifndef PKCRYPT_BASE64_H
#define PKCRYPT_BASE64_H

//
// PKCrypt - encrypt files so only the holder of an Ed25519 SSH private key
// can decrypt them (same public/private key model as SSH).
//
// Own implementation of RFC 4648 base64, written in-house and verified against
// the standard library / Python base64 for correctness.
//
// Author: Warren Zajac
//

#include <cstddef>
#include <string>
#include <vector>

namespace pkcrypt {

// Decode a base64 string ("standard" alphabet, optional '=' padding).
// ASCII whitespace (space, tab, CR, LF) anywhere in the input is ignored, which
// tolerates the newline-wrapped armor used by OpenSSH private keys.
// Returns false (and leaves `out` untouched) on any invalid character.
bool base64_decode(const std::string& in, std::vector<unsigned char>& out);

// Encode a byte buffer to base64 with standard padding. Uses the same alphabet
// as decoding.
std::string base64_encode(const unsigned char* data, size_t len);

} // namespace pkcrypt

#endif // PKCRYPT_BASE64_H

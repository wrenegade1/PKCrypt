//
// PKCrypt - test harness exposing the OpenSSH private-key parser (including
// passphrase-protected key decryption) to the Python test suite. Built by
// `make test`; not shipped.
//
// Author: Warren Zajac
//
// Usage:
//   ssh_harness parse <keyfile> <passphrase|"">
//       Parse the key. With a non-empty passphrase it is used to decrypt a
//       passphrase-protected key. On success prints:
//           pub=<32-byte hex> seed=<32-byte hex>
//       and exits 0; on any failure prints the error to stderr and exits 1.
//

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "pkcrypt/ssh_key.h"

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: ssh_harness parse <keyfile> <passphrase|empty>\n";
        return 2;
    }
    const std::string path = argv[2];
    const std::string pass = argv[3];
    const char* passphrase = pass.empty() ? nullptr : pass.c_str();

    std::string error;
    auto key = pkcrypt::parse_ssh_private_key_file(path, error, passphrase);
    if (!key) {
        std::cerr << error << "\n";
        return 1;
    }
    printf("pub=");
    for (int i = 0; i < 32; i++) printf("%02x", key->public_key[i]);
    printf(" seed=");
    for (int i = 0; i < 32; i++) printf("%02x", key->private_key[i]);
    printf("\n");
    return 0;
}

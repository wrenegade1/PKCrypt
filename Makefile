# PKCrypt - encrypt files so that only the holder of an Ed25519 SSH private
# key can decrypt them (same public/private key model as SSH).
#
# Author: Warren Zajac
#
# Requires: libsodium (brew install libsodium)
#   and cryptography (pip install cryptography), used by tests/ for interop.

CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude
LDLIBS    = -lsodium

LIBSODIUM_PREFIX := /opt/homebrew/opt/libsodium

# Prefer Homebrew libsodium if present, else fall back to system paths.
ifneq ($(wildcard $(LIBSODIUM_PREFIX)/lib/libsodium.dylib),)
  CXXFLAGS += -I$(LIBSODIUM_PREFIX)/include
  LDFLAGS  += -L$(LIBSODIUM_PREFIX)/lib
else
  LDFLAGS  +=
endif

SRCS = src/pkcrypt.cpp src/ssh_key.cpp src/crypto.cpp src/fileio.cpp src/base64.cpp \
       src/crc32.cpp src/deflate.cpp src/inflate.cpp src/zip.cpp src/archive.cpp \
       src/bcrypt_pbkdf.cpp src/aes_ctr.cpp
HDRS = $(wildcard include/pkcrypt/*.h include/pkcrypt/*.hpp src/*.h)
OBJS = $(SRCS:.cpp=.o)

BIN = pkcrypt

# Optional OpenSSL (for AES-CTR when decrypting passphrase-protected keys).
# Enabled when `pkg-config openssl` succeeds; the in-house AES fallback is used
# otherwise, so the binary still builds and works without OpenSSL.
HAS_OPENSSL := $(shell pkg-config --exists openssl && echo 1 || echo 0)
ifeq ($(HAS_OPENSSL),1)
  CXXFLAGS += -DPKCRYPT_HAS_OPENSSL $(shell pkg-config --cflags openssl)
  LDFLAGS  += $(shell pkg-config --libs openssl)
endif

# Test-only harness exposing the DEFLATE/CRC-32/ZIP code to the Python tests.
# Built with AddressSanitizer + UBSan so malformed-input tests catch memory
# errors, not just wrong answers.
HARNESS = tests/deflate_harness
HARNESS_SRCS = tests/deflate_harness.cpp src/crc32.cpp src/deflate.cpp src/inflate.cpp src/base64.cpp \
               src/zip.cpp src/archive.cpp src/fileio.cpp
SANITIZE = -fsanitize=address,undefined -fno-sanitize-recover=undefined

# Test-only harness exposing the OpenSSH private-key parser (incl.
# passphrase-protected key decryption + the in-house bcrypt_pbkdf / AES-CTR) to
# the Python tests. Also sanitized.
SSH_HARNESS = tests/ssh_harness
SSH_HARNESS_SRCS = tests/ssh_harness.cpp src/ssh_key.cpp src/base64.cpp \
                   src/bcrypt_pbkdf.cpp src/aes_ctr.cpp

all: $(BIN)

# Rebuild if any source or header changes.
$(OBJS): $(HDRS)

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(HARNESS): $(HARNESS_SRCS) $(HDRS)
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -Iinclude $(filter -I%,$(CXXFLAGS)) $(SANITIZE) \
	    $(HARNESS_SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

$(SSH_HARNESS): $(SSH_HARNESS_SRCS) $(HDRS)
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -Iinclude $(filter -I% -D%,$(CXXFLAGS)) $(SANITIZE) \
	    $(SSH_HARNESS_SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

# Build, then run BOTH test suites (Python unit tests + C++ interop).
test: $(BIN) $(HARNESS) $(SSH_HARNESS)
	python3 -m pytest tests/ -q
	python3 tests/test_cpp_interop.py

# Opt-in large-input tests: 1 GiB of repeating patterns through every
# encryptor/decryptor combination (set PKCRYPT_LARGE_MIB to change the size).
test-large: $(BIN)
	PKCRYPT_LARGE_TESTS=1 python3 -m pytest tests/test_large.py -s -q

clean:
	rm -f $(OBJS) $(BIN) $(HARNESS) $(SSH_HARNESS)
	rm -rf $(HARNESS).dSYM $(SSH_HARNESS).dSYM

.PHONY: all clean test test-large

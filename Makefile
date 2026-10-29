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

SRCS = src/pkcrypt.cpp src/ssh_key.cpp src/crypto.cpp src/fileio.cpp src/base64.cpp
HDRS = $(wildcard include/pkcrypt/*.h include/pkcrypt/*.hpp)
OBJS = $(SRCS:.cpp=.o)

BIN = pkcrypt

all: $(BIN)

# Rebuild if any source or header changes.
$(OBJS): $(HDRS)

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Build, then run the cross-language interop + unit test script.
test: $(BIN)
	python3 tests/test_cpp_interop.py

clean:
	rm -f $(OBJS) $(BIN)

.PHONY: all clean test

# PKCrypt - encrypt files with a recipient's Ed25519 SSH public key.
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

SRCS = src/pkcrypt.cpp src/ssh_key.cpp src/crypto.cpp src/fileio.cpp
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

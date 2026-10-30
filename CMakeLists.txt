cmake_minimum_required(VERSION 3.16)
project(PKCrypt CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra)

# Emit a compile_commands.json into the build directory, so editors using clangd
# (VSCode, CLion, Neovim, ...) resolve headers correctly. The file is generated
# per-machine into the build dir and is NOT committed to the repo.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- libsodium -------------------------------------------------------------
# PKCrypt requires libsodium for Ed25519<->X25519 key conversion and the
# X25519 / HKDF / AES-GCM primitives. Find it in standard locations, including
# the macOS Homebrew prefix (brew install libsodium) and Linux distro paths.
find_path(SODIUM_INCLUDE_DIR
  NAMES sodium.h
  PATHS /opt/homebrew/opt/libsodium/include /usr/local/opt/libsodium/include /usr/include /usr/local/include
)
find_library(SODIUM_LIBRARY
  NAMES sodium
  PATHS /opt/homebrew/opt/libsodium/lib /usr/local/opt/libsodium/lib /usr/lib /usr/local/lib
)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
  message(FATAL_ERROR "libsodium not found. Install it first (macOS: 'brew install libsodium'; Debian/Ubuntu: 'sudo apt install libsodium-dev').")
endif()

# --- Sources ---------------------------------------------------------------
set(PKCRYPT_SOURCES
  src/pkcrypt.cpp
  src/ssh_key.cpp
  src/crypto.cpp
  src/fileio.cpp
  src/base64.cpp
)

# --- CLI binary ------------------------------------------------------------
add_executable(pkcrypt ${PKCRYPT_SOURCES})
target_include_directories(pkcrypt PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SODIUM_INCLUDE_DIR}
)
target_link_libraries(pkcrypt PRIVATE ${SODIUM_LIBRARY})

# --- Tests -----------------------------------------------------------------
# Mirrors `make test`: build the binary, then run the cross-language interop
# + unit-test script with Python.
enable_testing()
add_test(
  NAME cpp_interop
  COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}
          python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cpp_interop.py
)
set_tests_properties(cpp_interop PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

# Make `make check` (or `ninja check`) a convenience alias in the build tree.
# `cmake --build . --target check` builds then runs the tests.
add_custom_target(check
  COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
  DEPENDS pkcrypt
)

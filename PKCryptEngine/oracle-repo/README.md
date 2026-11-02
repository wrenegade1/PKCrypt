# oracle-repo/ — test-time PKCrypt oracle checkout (D-04)

This directory is the **test-time-only** access point for the Python and C++
reference oracles that the COMP-03 differential interop matrix shells out against.

## What this is (D-04)

The engine's production library **never** depends on this directory or on the
oracle CLIs. It is used exclusively by the `PKCryptEngineTests` test target to:

- read committed container fixtures,
- invoke `python3 -m pkcrypt_lib` (Python oracle), and
- invoke `./pkcrypt` (C++ oracle, after `make`).

Per D-04 this is a **git submodule** of the upstream PKCrypt repository (declared in
`../.gitmodules`). In this single-repo plan-execution tree, where the engine and the
oracle share one working tree, this directory is a **documented dev checkout stand-in**:
the oracle source is the sibling repo root (`pkcrypt_lib/`, `src/`, `pkcrypt`), and the
test wrappers resolve it in this order:

1. `PKCRYPT_ORACLE_REPO` environment variable,
2. `PKCryptEngine/oracle-repo/` (this submodule / dev checkout), or
3. the sibling repo root derived from the test source file.

## Required manual step (user_setup, Open Question 3)

Before the full suite (`swift test`) can run the live interop matrix, initialize the
submodule (or dev checkout) and build the C++ binary:

```bash
git submodule update --init   # populate oracle-repo/ (D-04)
cd oracle-repo && make        # build ./pkcrypt for the C++ oracle cells
```

If the C++ binary is absent, C++ cells are recorded **UNAVAILABLE** (like
`tests/test_cpp_interop.py`'s `if not BIN.exists()` guard), not failed and never counted
as a pass.

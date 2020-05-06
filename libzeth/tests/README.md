# Zeth tests

## Adding Tests

The directory structure here should match that in libzeth, where files are named `<original_basename>_test.cpp`.

Tests are built as individual executables, so must contain a minimal `main` function which invokes the tests. (See existing tests for details.)

## Run the tests

Execute these commands from the `build` directory:

```console
# Build and run all tests.
$ cmake ..
$ make check
```

Other operations can be performed as follows:

```console
# Build (but do not run) all tests
$ make build_tests
# Build a single test
$ make utils_test
# Execute a single test
$ libzeth/tests/utils_test
# Invoke tests, with verbose output on failure
$ CTEST_OUTPUT_ON_FAILURE=1 make check
```

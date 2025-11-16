# Ada Development Guide for Claude

This guide provides instructions for building, testing, and benchmarking the Ada URL parser library using CMake.

## Quick Reference

```bash
# Build library only (no tests, no benchmarks)
cmake -B build && cmake --build build

# Build with tests (development checks ENABLED)
cmake -B build -DADA_TESTING=ON && cmake --build build
ctest --output-on-failure --test-dir build

# Build with benchmarks (development checks DISABLED for accurate performance)
cmake -B build -DADA_BENCHMARKS=ON -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build
./build/benchmarks/benchdata  # Run main benchmark

# FASTER BUILDS: Use Ninja instead of Make
cmake -B build -G Ninja -DADA_TESTING=ON && cmake --build build
cmake -B build -G Ninja -DADA_BENCHMARKS=ON -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build
```

## Requirements

- C++20 compatible compiler (GCC 12+, LLVM 14+, MSVC 2022+)
- CMake 3.15+
- Git (for fetching test dependencies)
- Ninja (optional, for faster builds): `sudo apt install ninja-build` on Ubuntu

## Building the Library

### Basic Build (Library Only)

For a minimal build with just the library:

```bash
cmake -B build
cmake --build build
```

This creates the Ada library without tests or benchmarks.

### Build with Tests

To build with tests enabled:

```bash
cmake -B build -DADA_TESTING=ON
cmake --build build
```

**Important:** When `ADA_TESTING=ON`, development checks are automatically enabled unless you explicitly build in Release mode with `NDEBUG` defined. Development checks include assertions (`ADA_ASSERT_TRUE`, `ADA_ASSERT_EQUAL`) that validate internal state.

### Build with Benchmarks

To build benchmarks for performance testing:

```bash
cmake -B build -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**Critical:** Always build benchmarks in Release mode (`-DCMAKE_BUILD_TYPE=Release`) to disable development checks. Development assertions significantly impact performance and will give misleading benchmark results.

### Using Local Packages

If you have dependencies (like GoogleTest, Google Benchmark) already installed locally:

```bash
cmake -B build -DADA_TESTING=ON -DCPM_USE_LOCAL_PACKAGES=ON
cmake --build build
```

## CMake Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_TESTING` | OFF | Enable building tests |
| `ADA_BENCHMARKS` | OFF | Enable building benchmarks (requires 64-bit) |
| `ADA_TOOLS` | OFF | Enable building command-line tools |
| `ADA_BUILD_SINGLE_HEADER_LIB` | OFF | Build from single-header amalgamated files |
| `ADA_USE_SIMDUTF` | OFF | Enable SIMD-accelerated Unicode via simdutf |
| `CMAKE_BUILD_TYPE` | - | Set to `Release` for optimized builds, `Debug` for development |

## Running Tests

After building with `-DADA_TESTING=ON`:

```bash
# Run all tests
ctest --output-on-failure --test-dir build

# Run specific test executable
./build/tests/basic_tests

# Run tests with verbose output
ctest --verbose --test-dir build
```

### Development Checks in Tests

Tests run with development checks **enabled by default** (unless built with `-DCMAKE_BUILD_TYPE=Release -DNDEBUG`). This means:

- Assertions are active (`ADA_ASSERT_TRUE`, `ADA_ASSERT_EQUAL`)
- Internal state validation occurs
- Performance is slower but catches bugs early

This is the **recommended mode for development**.

## Running Benchmarks

After building with `-DADA_BENCHMARKS=ON`:

```bash
# Main benchmark comparing against competitors
./build/benchmarks/benchdata

# Specific benchmarks
./build/benchmarks/bench          # Basic URL parsing benchmarks
./build/benchmarks/bbc_bench      # BBC URLs benchmark
./build/benchmarks/wpt_bench      # Web Platform Tests benchmark
./build/benchmarks/percent_encode # Percent encoding benchmarks
```

### Development Checks in Benchmarks

**Always disable development checks for benchmarks** by building in Release mode:

```bash
# CORRECT: Benchmarks with development checks disabled
cmake -B build -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/benchmarks/benchdata

# WRONG: Don't benchmark with development checks enabled
cmake -B build -DADA_BENCHMARKS=ON  # Missing Release mode!
```

Development checks add significant overhead that skews performance measurements. The `ADA_DEVELOPMENT_CHECKS` macro is automatically disabled when:
- Building with `-DCMAKE_BUILD_TYPE=Release`
- `NDEBUG` is defined
- Explicitly set `ADA_DEVELOPMENT_CHECKS=0`

## Complete Development Workflow

### 1. Initial Setup

```bash
# Clone and enter directory
cd /path/to/ada

# Create build directory for tests
cmake -B build -DADA_TESTING=ON
cmake --build build
```

### 2. Development Cycle (with tests)

```bash
# Make code changes...

# Rebuild (only rebuilds changed files)
cmake --build build

# Run tests to verify correctness
ctest --output-on-failure --test-dir build

# Or run specific test
./build/tests/basic_tests
```

### 3. Performance Validation (with benchmarks)

```bash
# Create separate benchmark build
cmake -B build-release -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release

# Run benchmarks
./build-release/benchmarks/benchdata

# Compare before/after optimizations
# (stash changes, rebuild, run benchmark, restore, rebuild, run again)
```

### 4. Clean Rebuild

```bash
# Remove build directory and start fresh
rm -rf build
cmake -B build -DADA_TESTING=ON
cmake --build build
```

## Understanding Development Checks

### What are Development Checks?

Development checks are compile-time assertions that validate:
- Function preconditions and postconditions
- Internal invariants (e.g., `validate()` on URL objects)
- Argument validity

### When are they Enabled?

Automatically enabled when:
- `ADA_TESTING=ON` (unless overridden with Release mode)
- Debug build (`CMAKE_BUILD_TYPE=Debug`)
- `NDEBUG` is not defined

Automatically disabled when:
- `CMAKE_BUILD_TYPE=Release`
- `NDEBUG` is defined
- Production builds

### Manual Control

```bash
# Force enable development checks (even in Release)
cmake -B build -DADA_DEVELOPMENT_CHECKS=1

# Force disable development checks (even in Debug)
cmake -B build -DNDEBUG=1
```

## Platform-Specific Notes

### Windows

Specify configuration during build:

```bash
cmake -B build -DADA_TESTING=ON
cmake --build build --config Release
ctest --output-on-failure --test-dir build --config Release
```

### macOS/Linux

Standard commands work as documented above.

## Troubleshooting

### Benchmarks are unexpectedly slow

**Cause:** Development checks are enabled.

**Solution:** Rebuild with Release mode:
```bash
cmake -B build -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Tests are failing with assertion errors

**Expected behavior** - development checks are catching bugs. Review the assertion message and fix the underlying issue.

### Can't find benchmark executable

**Cause:** Benchmarks not built (32-bit system or not enabled).

**Solution:**
```bash
cmake -B build -DADA_BENCHMARKS=ON
cmake --build build
ls build/benchmarks/  # Check what was built
```

## Additional Resources

- **README.md**: General project overview and API usage
- **docs/cli.md**: Command-line interface documentation
- **benchmarks/**: Benchmark source code
- **tests/**: Test source code
- **include/ada/**: Library headers

## Summary

| Task | Command | Development Checks |
|------|---------|-------------------|
| Library only | `cmake -B build && cmake --build build` | N/A |
| Testing | `cmake -B build -DADA_TESTING=ON && cmake --build build` | ✅ Enabled |
| Benchmarking | `cmake -B build -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build` | ❌ Disabled |
| Development | `cmake -B build -DADA_TESTING=ON -DCMAKE_BUILD_TYPE=Debug && cmake --build build` | ✅ Enabled |

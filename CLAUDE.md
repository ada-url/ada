# Ada Development Guide for Claude

This guide provides instructions for building, testing, and benchmarking the Ada URL parser library using CMake.

**Ada now uses modern CMake presets for simplified building!** See [CMAKE_BEST_PRACTICES.md](docs/CMAKE_BEST_PRACTICES.md) for comprehensive documentation.

## Quick Reference (Presets - Recommended)

```bash
# Development build (tests + quality checks)
cmake --preset dev
cmake --build build/dev
ctest --test-dir build/dev --output-on-failure

# Release build (library only, optimized)
cmake --preset release
cmake --build build/release

# Benchmarks (optimized, development checks disabled)
cmake --preset benchmark
cmake --build build/benchmark
./build/benchmark/benchmarks/benchdata

# With Ninja for faster builds (recommended)
cmake --preset dev-ninja
cmake --build build/dev-ninja

# Address Sanitizer (memory error detection)
cmake --preset sanitize-address
cmake --build build/sanitize-address
ctest --test-dir build/sanitize-address
```

## Quick Reference (Traditional CMake - Still Supported)

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
- CMake 3.19+ (for presets support; 3.15+ for traditional approach)
- Git (for fetching test dependencies)
- Ninja (optional, for faster builds): `sudo apt install ninja-build` on Ubuntu

## Available CMake Presets

Ada provides standardized CMake presets for common workflows:

| Preset | Purpose | Developer Mode | Build Type |
|--------|---------|----------------|------------|
| `dev` / `dev-ninja` | Development with all quality checks | ON | Debug |
| `test` / `test-ninja` | Testing configuration | ON | Debug |
| `release` / `release-ninja` | Optimized production build | OFF | Release |
| `benchmark` / `benchmark-ninja` | Performance benchmarking | OFF | Release |
| `sanitize-address` | Memory error detection | ON | Debug |
| `sanitize-undefined` | Undefined behavior detection | ON | Debug |
| `sanitize-all` | All sanitizers | ON | Debug |
| `coverage` | Code coverage analysis | ON | Debug |
| `ci` | Continuous integration | ON | RelWithDebInfo |

**Presets with `-ninja` suffix use the Ninja generator for faster builds.**

See full preset details: `cmake --list-presets` or [CMAKE_BEST_PRACTICES.md](docs/CMAKE_BEST_PRACTICES.md)

## Building the Library

### Basic Build (Library Only)

**With presets (recommended):**
```bash
cmake --preset release
cmake --build build/release
```

**Traditional approach:**
```bash
cmake -B build
cmake --build build
```

This creates the Ada library without tests or benchmarks.

### Build with Tests

**With presets (recommended):**
```bash
cmake --preset test
cmake --build build/test
ctest --test-dir build/test --output-on-failure
```

**Traditional approach:**
```bash
cmake -B build -DADA_TESTING=ON
cmake --build build
ctest --output-on-failure --test-dir build
```

**Important:** When `ADA_TESTING=ON` or using test presets, development checks are automatically enabled unless you explicitly build in Release mode. Development checks include assertions (`ADA_ASSERT_TRUE`, `ADA_ASSERT_EQUAL`) that validate internal state.

### Build with Benchmarks

**With presets (recommended):**
```bash
cmake --preset benchmark
cmake --build build/benchmark
./build/benchmark/benchmarks/benchdata
```

**Traditional approach:**
```bash
cmake -B build -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/benchmarks/benchdata
```

**Critical:** Always build benchmarks in Release mode to disable development checks. The `benchmark` preset handles this automatically. Development assertions significantly impact performance and will give misleading benchmark results.

### Using Local Packages

If you have dependencies (like GoogleTest, Google Benchmark) already installed locally:

```bash
cmake -B build -DADA_TESTING=ON -DCPM_USE_LOCAL_PACKAGES=ON
cmake --build build
```

## CMake Build Options

### Build Features

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_TESTING` | OFF | Enable building tests |
| `ADA_BENCHMARKS` | OFF | Enable building benchmarks (requires 64-bit) |
| `ADA_TOOLS` | OFF | Enable building command-line tools (adaparse) |
| `ADA_BUILD_SINGLE_HEADER_LIB` | OFF | Build from single-header amalgamated files |
| `ADA_USE_SIMDUTF` | OFF | Enable SIMD-accelerated Unicode via simdutf |

### Quality & Analysis (New!)

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_DEVELOPER_MODE` | OFF | Enable all quality checks (warnings as errors, static analyzers, dev checks) |
| `ADA_WARNINGS_AS_ERRORS` | OFF | Treat compiler warnings as errors |
| `ADA_DEVELOPMENT_CHECKS` | OFF | Enable internal assertions and validation |
| `ADA_LOGGING` | OFF | Enable verbose logging for debugging |
| `ADA_ENABLE_CLANG_TIDY` | OFF | Enable clang-tidy static analysis |
| `ADA_ENABLE_CPPCHECK` | OFF | Enable cppcheck static analysis |

### Sanitizers & Testing

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_SANITIZE` | OFF | Enable Address Sanitizer (memory errors) |
| `ADA_SANITIZE_UNDEFINED` | OFF | Enable Undefined Behavior Sanitizer |
| `ADA_SANITIZE_BOUNDS_STRICT` | OFF | Enable strict bounds checking (GCC only) |
| `ADA_COVERAGE` | OFF | Enable code coverage instrumentation (requires gcovr) |

### General CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | Release* | Set to `Release`, `Debug`, `RelWithDebInfo`, or `MinSizeRel` |
| `BUILD_SHARED_LIBS` | OFF | Build shared libraries instead of static |

*Auto-defaults to Release (or Debug if sanitizers/coverage enabled)

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

### Recommended Workflow (Using Presets)

#### 1. Initial Setup

```bash
# Clone and enter directory
cd /path/to/ada

# Configure development build with all quality checks
cmake --preset dev-ninja
```

#### 2. Development Cycle (with tests)

```bash
# Make code changes...

# Rebuild (only rebuilds changed files)
cmake --build build/dev-ninja

# Run tests to verify correctness
ctest --test-dir build/dev-ninja --output-on-failure

# Or run specific test
./build/dev-ninja/tests/basic_tests
```

#### 3. Performance Validation (with benchmarks)

```bash
# Configure and build benchmarks (separate from dev build)
cmake --preset benchmark-ninja
cmake --build build/benchmark-ninja

# Run benchmarks
./build/benchmark-ninja/benchmarks/benchdata

# Compare before/after optimizations
# (stash changes, rebuild, run benchmark, restore, rebuild, run again)
```

#### 4. Quality Checks (Static Analysis)

```bash
# Run with clang-tidy and cppcheck (if installed)
cmake --preset dev -DADA_ENABLE_CLANG_TIDY=ON -DADA_ENABLE_CPPCHECK=ON
cmake --build build/dev

# Or use Developer Mode (enables all checks automatically)
cmake --preset dev  # Developer Mode is ON by default in dev preset
cmake --build build/dev
```

#### 5. Clean Rebuild

```bash
# Remove build directory and start fresh
rm -rf build/dev-ninja
cmake --preset dev-ninja
cmake --build build/dev-ninja
```

### Traditional Workflow (Still Supported)

#### 1. Initial Setup

```bash
# Clone and enter directory
cd /path/to/ada

# Create build directory for tests
cmake -B build -DADA_TESTING=ON
cmake --build build
```

#### 2. Development Cycle (with tests)

```bash
# Make code changes...

# Rebuild (only rebuilds changed files)
cmake --build build

# Run tests to verify correctness
ctest --output-on-failure --test-dir build

# Or run specific test
./build/tests/basic_tests
```

#### 3. Performance Validation (with benchmarks)

```bash
# Create separate benchmark build
cmake -B build-release -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release

# Run benchmarks
./build-release/benchmarks/benchdata
```

#### 4. Clean Rebuild

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

## Running Clang-Tidy

Clang-tidy is used for static analysis. There are two ways to run it:

### During Build (Recommended)

Run clang-tidy automatically during compilation:

```bash
cmake -B build -DADA_TESTING=ON \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_CLANG_TIDY=clang-tidy \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
```

**Important:** You must use clang++ as the compiler when running clang-tidy during build. Using GCC will cause errors because clang-tidy doesn't understand GCC-specific flags like `-mno-avx256-split-unaligned-load`.

### Standalone with compile_commands.json

First, generate the compilation database:

```bash
cmake -B build -DADA_TESTING=ON \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
```

Then run clang-tidy on specific files:

```bash
clang-tidy -p build src/ada.cpp
clang-tidy -p build src/ada_idna.cpp
```

The `-p build` flag tells clang-tidy to use the `compile_commands.json` from the build directory.

### Clang-Tidy Configuration

The `.clang-tidy` file in the project root configures which checks are enabled. Current configuration enables:
- `bugprone-*` checks (with some exclusions)
- `clang-analyzer-*` checks

All warnings are treated as errors (`WarningsAsErrors: '*'`).

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
- **docs/CMAKE_BEST_PRACTICES.md**: Comprehensive CMake presets and best practices guide
- **docs/cli.md**: Command-line interface documentation
- **benchmarks/**: Benchmark source code
- **tests/**: Test source code
- **include/ada/**: Library headers
- **CMakePresets.json**: CMake preset definitions (run `cmake --list-presets` to view)

## Summary

### With Presets (Recommended)

| Task | Command | Development Checks | Build Type |
|------|---------|-------------------|------------|
| Library only | `cmake --preset release && cmake --build build/release` | ❌ Disabled | Release |
| Testing | `cmake --preset test && cmake --build build/test` | ✅ Enabled | Debug |
| Development | `cmake --preset dev && cmake --build build/dev` | ✅ Enabled + Quality Checks | Debug |
| Benchmarking | `cmake --preset benchmark && cmake --build build/benchmark` | ❌ Disabled | Release |
| Sanitizer | `cmake --preset sanitize-address && cmake --build build/sanitize-address` | ✅ Enabled + ASan | Debug |

### Traditional Approach (Still Supported)

| Task | Command | Development Checks | Build Type |
|------|---------|-------------------|------------|
| Library only | `cmake -B build && cmake --build build` | N/A | Auto (Release) |
| Testing | `cmake -B build -DADA_TESTING=ON && cmake --build build` | ✅ Enabled | Auto (Release) |
| Benchmarking | `cmake -B build -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build` | ❌ Disabled | Release |
| Development | `cmake -B build -DADA_TESTING=ON -DCMAKE_BUILD_TYPE=Debug && cmake --build build` | ✅ Enabled | Debug |

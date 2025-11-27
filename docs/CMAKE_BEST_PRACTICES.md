# CMake Best Practices Implementation

This document describes the modern CMake best practices that have been applied to the Ada URL Parser project, inspired by [cpp-best-practices/cmake_template](https://github.com/cpp-best-practices/cmake_template).

## Overview of Changes

The Ada project's CMake configuration has been modernized with the following improvements:

1. **CMakePresets.json** - Standardized build configurations
2. **Modular CMake files** - Better organization and maintainability
3. **Developer Mode** - Integrated quality checks
4. **Static Analyzers** - clang-tidy and cppcheck support
5. **Systematic Warnings** - Compiler warning management
6. **Better Documentation** - Clear structure and comments

## Quick Start with Presets

The easiest way to build Ada is now using CMake presets:

```bash
# Development build (with tests and quality checks)
cmake --preset dev
cmake --build build/dev
ctest --test-dir build/dev

# Release build (optimized, library only)
cmake --preset release
cmake --build build/release

# Benchmarks build
cmake --preset benchmark
cmake --build build/benchmark
./build/benchmark/benchmarks/benchdata

# With Ninja generator (faster builds)
cmake --preset dev-ninja
cmake --build build/dev-ninja
```

### Available Presets

| Preset | Description | Developer Mode | Build Type | Features |
|--------|-------------|----------------|------------|----------|
| `dev` | Development build | ON | Debug | Tests, warnings as errors, clang-tidy |
| `dev-ninja` | Development with Ninja | ON | Debug | Same as dev, faster builds |
| `release` | Production build | OFF | Release | Library only, optimized |
| `release-ninja` | Release with Ninja | OFF | Release | Same as release, faster |
| `test` | Testing build | ON | Debug | Tests with quality checks |
| `test-ninja` | Testing with Ninja | ON | Debug | Same as test, faster |
| `benchmark` | Benchmark build | OFF | Release | Benchmarks, optimized |
| `benchmark-ninja` | Benchmark with Ninja | OFF | Release | Same as benchmark, faster |
| `sanitize-address` | Address Sanitizer | ON | Debug | ASan for memory errors |
| `sanitize-undefined` | UB Sanitizer | ON | Debug | UBSan for undefined behavior |
| `sanitize-all` | All Sanitizers | ON | Debug | ASan + UBSan |
| `coverage` | Code Coverage | ON | Debug | Coverage instrumentation |
| `tools` | CLI Tools | OFF | Release | Build adaparse tool |
| `single-header` | Single Header | OFF | Release | Amalgamated build |
| `ci` | CI Build | ON | RelWithDebInfo | All checks for CI |

## Developer Mode

Developer Mode is a new feature that automatically enables multiple quality checks:

- **Compiler warnings as errors** - Catch issues early
- **Development assertions** - Internal validation
- **clang-tidy** - Static analysis (if available)
- **cppcheck** - Additional static analysis (if available)

Enable Developer Mode:

```bash
# Via preset (recommended)
cmake --preset dev

# Via command line
cmake -B build -DADA_DEVELOPER_MODE=ON

# Disable specific checks while keeping Developer Mode
cmake -B build -DADA_DEVELOPER_MODE=ON -DADA_ENABLE_CLANG_TIDY=OFF
```

## New CMake Modules

### cmake/ProjectOptions.cmake

Centralized configuration for all build options. Defines:

- All `ADA_*` options
- Developer Mode behavior
- Build type defaults
- Validation and warnings
- Feature summary display

### cmake/CompilerWarnings.cmake

Systematic compiler warning management with functions:

**`ada_set_project_warnings(target)`**
- Applies comprehensive warnings to a target
- Supports MSVC, GCC, Clang, and AppleClang
- Includes platform-specific optimizations (e.g., GCC AVX workaround)
- Can treat warnings as errors

**`ada_set_sanitizer_flags(target)`**
- Applies sanitizer flags (ASan, UBSan, bounds checking)
- Configures both compile and link flags
- Sets appropriate environment variables

**`ada_set_standard_settings(target)`**
- Applies standard C++20 requirement
- Sets development checks, logging, testing flags
- Configures feature macros

### cmake/StaticAnalyzers.cmake

Integration with static analysis tools:

**`ada_enable_clang_tidy(target)`**
- Enables clang-tidy for the target
- Uses `.clang-tidy` configuration
- Can treat warnings as errors

**`ada_enable_cppcheck(target)`**
- Enables cppcheck for the target
- Configures appropriate flags for C++20
- Suppresses noisy warnings

**`ada_enable_static_analyzers(target)`**
- Convenience function to enable all analyzers
- Only enables if tools are found

## Build Options Reference

### Build Features

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_TESTING` | OFF | Enable building tests |
| `ADA_BENCHMARKS` | OFF | Enable building benchmarks |
| `ADA_TOOLS` | OFF | Enable building CLI tools |
| `ADA_BUILD_SINGLE_HEADER_LIB` | OFF | Build from single-header files |

### Library Features

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_USE_SIMDUTF` | OFF | Enable SIMD Unicode processing |
| `ADA_INCLUDE_URL_PATTERN` | ON | Include URL pattern implementation |
| `ADA_USE_UNSAFE_STD_REGEX_PROVIDER` | OFF | Use std::regex (security-sensitive) |

### Quality & Analysis

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_DEVELOPER_MODE` | OFF | Enable developer mode (auto-enables below) |
| `ADA_WARNINGS_AS_ERRORS` | OFF | Treat compiler warnings as errors |
| `ADA_DEVELOPMENT_CHECKS` | OFF | Enable internal assertions |
| `ADA_LOGGING` | OFF | Enable verbose logging |
| `ADA_ENABLE_CLANG_TIDY` | OFF | Enable clang-tidy analysis |
| `ADA_ENABLE_CPPCHECK` | OFF | Enable cppcheck analysis |

### Sanitizers & Testing

| Option | Default | Description |
|--------|---------|-------------|
| `ADA_SANITIZE` | OFF | Enable Address Sanitizer |
| `ADA_SANITIZE_UNDEFINED` | OFF | Enable UB Sanitizer |
| `ADA_SANITIZE_BOUNDS_STRICT` | OFF | Strict bounds (GCC only) |
| `ADA_COVERAGE` | OFF | Enable code coverage |

## Migration Guide

### Old Approach

```bash
# Old way (still works)
cmake -B build -DADA_TESTING=ON
cmake --build build
ctest --output-on-failure --test-dir build
```

### New Approach (Recommended)

```bash
# New way with presets
cmake --preset test
cmake --build build/test
ctest --test-dir build/test --output-on-failure

# Or even simpler with test preset
cmake --preset test
cmake --build --preset test
ctest --preset test
```

### For Benchmarks

```bash
# Old way
cmake -B build -DADA_BENCHMARKS=ON -DADA_USE_UNSAFE_STD_REGEX_PROVIDER=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/benchmarks/benchdata

# New way
cmake --preset benchmark
cmake --build --preset benchmark
./build/benchmark/benchmarks/benchdata
```

## IDE Integration

Modern IDEs (Visual Studio Code, CLion, Visual Studio 2019+) automatically detect `CMakePresets.json` and provide:

- **Preset selection** in the UI
- **IntelliSense/code completion** with correct flags
- **One-click configuration and building**
- **Integrated testing** with CTest

### VS Code

1. Install the CMake Tools extension
2. Open the command palette (Ctrl+Shift+P)
3. Select "CMake: Select Configure Preset"
4. Choose a preset (e.g., "dev")
5. Build with "CMake: Build" or F7

### CLion

CLion 2020.3+ automatically loads presets from `CMakePresets.json` in the CMake settings.

## Best Practices Summary

1. **Use Presets** - They encode the correct build configurations
2. **Enable Developer Mode** - During development for quality checks
3. **Build Type Matters** - Always use Release for benchmarks
4. **Test with Sanitizers** - Regularly run tests with ASan/UBSan
5. **Static Analysis** - Run clang-tidy in CI or before commits
6. **Separate Builds** - Use different build directories for different configurations

## Customizing for Your Project

If you're using Ada as a template or want to customize:

1. **Add new presets** in `CMakePresets.json`
2. **Modify warnings** in `cmake/CompilerWarnings.cmake`
3. **Configure analyzers** by editing `.clang-tidy`
4. **Add options** in `cmake/ProjectOptions.cmake`

## Troubleshooting

### Preset not found

**Error:** `CMake Error: Could not read presets from ...`

**Solution:** Requires CMake 3.19+ for presets. Update CMake or use traditional approach.

### clang-tidy too slow

**Solution:** Disable in dev preset or use a separate preset:

```bash
cmake --preset dev -DADA_ENABLE_CLANG_TIDY=OFF
```

### Warnings as errors failing

**Solution:** This is intentional in Developer Mode. Fix the warnings or temporarily disable:

```bash
cmake --preset dev -DADA_WARNINGS_AS_ERRORS=OFF
```

## Performance Notes

### Build Speed

Using Ninja generator can significantly speed up builds:

```bash
# Make (default)
cmake --preset dev
cmake --build build/dev
# Time: ~X seconds

# Ninja (faster)
cmake --preset dev-ninja
cmake --build build/dev-ninja
# Time: ~X/2 seconds
```

Install Ninja: `sudo apt install ninja-build` (Ubuntu/Debian)

### Development Checks Impact

Development checks add runtime overhead:

- **Development/Testing**: ~5-10% slowdown (acceptable)
- **Benchmarking**: ~20-50% slowdown (NOT acceptable)

**Always benchmark with Release build and checks disabled:**

```bash
cmake --preset benchmark  # Checks auto-disabled
```

## CI/CD Integration

The Ada project's GitHub Actions workflows have been updated to use CMake presets:

### Updated Workflows

**ubuntu.yml** - Main Ubuntu CI
```yaml
- name: Prepare (CMake with ci preset)
  run: cmake --preset ci -DBUILD_SHARED_LIBS=${{matrix.shared}} -DADA_USE_SIMDUTF=${{matrix.simdutf}} -DADA_BENCHMARKS=ON
```

**ubuntu-sanitized.yml** - Address Sanitizer
```yaml
- name: Prepare (CMake with sanitize-address preset)
  run: cmake --preset sanitize-address -DBUILD_SHARED_LIBS=${{matrix.shared}}
```

**ubuntu-undef.yml** - Undefined Behavior Sanitizer
```yaml
- name: Prepare (CMake with sanitize-undefined preset)
  run: cmake --preset sanitize-undefined -DBUILD_SHARED_LIBS=${{matrix.shared}}
```

**ubuntu-release.yml** - Release Builds
```yaml
- name: Prepare (CMake with release-ninja preset)
  run: cmake --preset release-ninja -DBUILD_TESTING=OFF
```

### Benefits in CI

- **Consistency**: Same preset configurations locally and in CI
- **Maintainability**: Less duplication of CMake flags
- **Clarity**: Preset names document intent (ci, sanitize-address, etc.)
- **Flexibility**: Can still override options via `-D` flags

## Further Reading

- [Modern CMake](https://cliutils.gitlab.io/modern-cmake/)
- [CMake Presets Documentation](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html)
- [cpp-best-practices/cmake_template](https://github.com/cpp-best-practices/cmake_template)
- [Effective Modern CMake](https://gist.github.com/mbinna/c61dbb39bca0e4fb7d1f73b0d66a4fd1)

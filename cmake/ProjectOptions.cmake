#
# ProjectOptions.cmake - Centralized build options for Ada URL Parser
#
# This file defines all configurable options for the Ada project.
# Inspired by modern CMake best practices from cpp-best-practices/cmake_template
#

# Include guard
include_guard(GLOBAL)

# ============================================================================
# Developer Mode
# ============================================================================
# When enabled, activates additional quality and safety checks:
# - Compiler warnings as errors
# - Static analyzers (clang-tidy, cppcheck)
# - Development assertions
# - Stricter compilation flags
option(ADA_DEVELOPER_MODE "Enable developer mode (warnings as errors, static analysis, development checks)" OFF)

# ============================================================================
# Build Features
# ============================================================================
option(ADA_TESTING "Enable building tests" OFF)
option(ADA_BENCHMARKS "Enable building benchmarks (requires 64-bit architecture)" OFF)
option(ADA_TOOLS "Enable building CLI tools (adaparse)" OFF)
option(ADA_BUILD_SINGLE_HEADER_LIB "Build from single-header amalgamated files" OFF)

# ============================================================================
# Library Features
# ============================================================================
option(ADA_USE_SIMDUTF "Enable SIMD-accelerated Unicode processing via simdutf library" OFF)
option(ADA_INCLUDE_URL_PATTERN "Include URL pattern implementation" ON)
option(ADA_USE_UNSAFE_STD_REGEX_PROVIDER "Use std::regex for URL patterns (security-sensitive)" OFF)

# ============================================================================
# Development & Debugging Features
# ============================================================================
option(ADA_DEVELOPMENT_CHECKS "Enable internal assertions and validation checks (impacts performance)" OFF)
option(ADA_LOGGING "Enable verbose logging output for debugging" OFF)

# ============================================================================
# Code Quality & Analysis
# ============================================================================
option(ADA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(ADA_ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" OFF)
option(ADA_ENABLE_CPPCHECK "Enable cppcheck static analysis" OFF)

# ============================================================================
# Sanitizers & Testing Tools
# ============================================================================
option(ADA_SANITIZE "Enable Address Sanitizer for memory error detection" OFF)
option(ADA_SANITIZE_UNDEFINED "Enable Undefined Behavior Sanitizer" OFF)
option(ADA_SANITIZE_BOUNDS_STRICT "Enable strict bounds checking (GCC only)" OFF)
option(ADA_COVERAGE "Enable code coverage instrumentation (requires gcovr)" OFF)

# ============================================================================
# Benchmark Competitors (for performance comparison)
# ============================================================================
option(ADA_COMPETITION "Enable building competitive benchmark comparisons" OFF)
option(ADA_BOOST_URL "Enable Boost.URL benchmarks (requires Boost 1.86+)" OFF)

# ============================================================================
# Developer Mode Automatic Configuration
# ============================================================================
# When DEVELOPER_MODE is enabled, automatically enable quality features
# These can still be overridden by passing -DADA_OPTION=OFF explicitly
if(ADA_DEVELOPER_MODE)
  message(STATUS "Ada Developer Mode enabled - activating quality checks")

  # Enable warnings as errors in developer mode
  if(NOT ADA_WARNINGS_AS_ERRORS)
    set(ADA_WARNINGS_AS_ERRORS ON)
    message(STATUS "  -> Warnings as errors: ENABLED")
  endif()

  # Enable development checks
  if(NOT ADA_DEVELOPMENT_CHECKS)
    set(ADA_DEVELOPMENT_CHECKS ON)
    message(STATUS "  -> Development checks: ENABLED")
  endif()

  # Enable static analyzers if available
  if(NOT ADA_ENABLE_CLANG_TIDY)
    set(ADA_ENABLE_CLANG_TIDY ON)
    message(STATUS "  -> clang-tidy: ENABLED (if available)")
  endif()

  if(NOT ADA_ENABLE_CPPCHECK)
    set(ADA_ENABLE_CPPCHECK ON)
    message(STATUS "  -> cppcheck: ENABLED (if available)")
  endif()
endif()

# ============================================================================
# Build Type Defaults
# ============================================================================
# Set sensible default build types based on enabled features
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  # If sanitizers or coverage enabled, default to Debug
  if(ADA_SANITIZE OR ADA_SANITIZE_UNDEFINED OR ADA_SANITIZE_BOUNDS_STRICT OR ADA_COVERAGE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (defaulted to Debug for sanitizers/coverage)" FORCE)
    message(STATUS "Build type not specified, defaulting to Debug (sanitizers/coverage enabled)")
  # If benchmarks enabled, strongly encourage Release
  elseif(ADA_BENCHMARKS)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type (defaulted to Release for benchmarks)" FORCE)
    message(STATUS "Build type not specified, defaulting to Release (benchmarks enabled)")
  # Otherwise default to Release for optimal performance
  else()
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    message(STATUS "Build type not specified, defaulting to Release")
  endif()

  # Set the possible values for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# ============================================================================
# Validation & Warnings
# ============================================================================

# Warn if benchmarking without Release build
if(ADA_BENCHMARKS AND NOT CMAKE_BUILD_TYPE STREQUAL "Release")
  message(WARNING
    "Benchmarks should be built in Release mode for accurate performance measurements. "
    "Current build type: ${CMAKE_BUILD_TYPE}. "
    "Development checks and debug symbols will impact benchmark results. "
    "Recommended: cmake -B build -DADA_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release"
  )
endif()

# Inform about development checks impact
if(ADA_DEVELOPMENT_CHECKS AND ADA_BENCHMARKS)
  message(WARNING
    "Development checks are enabled while building benchmarks. "
    "This will significantly impact performance measurements. "
    "To disable: -DADA_DEVELOPMENT_CHECKS=OFF or build in Release mode with -DNDEBUG"
  )
endif()

# Architecture check for benchmarks
if(ADA_BENCHMARKS)
  # Check if we're on a 64-bit system
  if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(WARNING "Benchmarks require 64-bit architecture. Some benchmarks may not build on 32-bit systems.")
  endif()
endif()

# ============================================================================
# Feature Summary
# ============================================================================
# Print configuration summary for user visibility
if(PROJECT_NAME STREQUAL "ada")  # Only show when Ada is the main project
  message(STATUS "")
  message(STATUS "=== Ada URL Parser Configuration ===")
  message(STATUS "Version:           ${PROJECT_VERSION}")
  message(STATUS "Build Type:        ${CMAKE_BUILD_TYPE}")
  message(STATUS "")
  message(STATUS "Build Features:")
  message(STATUS "  Testing:         ${ADA_TESTING}")
  message(STATUS "  Benchmarks:      ${ADA_BENCHMARKS}")
  message(STATUS "  Tools:           ${ADA_TOOLS}")
  message(STATUS "  Single Header:   ${ADA_BUILD_SINGLE_HEADER_LIB}")
  message(STATUS "")
  message(STATUS "Library Features:")
  message(STATUS "  SIMD UTF:        ${ADA_USE_SIMDUTF}")
  message(STATUS "  URL Pattern:     ${ADA_INCLUDE_URL_PATTERN}")
  message(STATUS "")
  message(STATUS "Quality & Analysis:")
  message(STATUS "  Developer Mode:  ${ADA_DEVELOPER_MODE}")
  message(STATUS "  Warnings->Errors: ${ADA_WARNINGS_AS_ERRORS}")
  message(STATUS "  Dev Checks:      ${ADA_DEVELOPMENT_CHECKS}")
  message(STATUS "  clang-tidy:      ${ADA_ENABLE_CLANG_TIDY}")
  message(STATUS "  cppcheck:        ${ADA_ENABLE_CPPCHECK}")
  message(STATUS "")
  message(STATUS "Sanitizers:")
  message(STATUS "  Address:         ${ADA_SANITIZE}")
  message(STATUS "  Undefined:       ${ADA_SANITIZE_UNDEFINED}")
  message(STATUS "  Coverage:        ${ADA_COVERAGE}")
  message(STATUS "====================================")
  message(STATUS "")
endif()

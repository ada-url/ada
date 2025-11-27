#
# ada-flags.cmake - Compiler flags and build configuration
#
# NOTE: This file is being refactored to use modular CMake best practices.
# Most options are now defined in cmake/ProjectOptions.cmake
# This file now focuses on applying those options to the build.
#

include_guard(GLOBAL)

# ============================================================================
# Backward Compatibility
# ============================================================================
# These options are now defined in ProjectOptions.cmake but we keep them here
# commented for documentation purposes. If ProjectOptions.cmake was not included,
# they will be defined there with proper defaults.
#
# Defined in ProjectOptions.cmake:
# - ADA_DEVELOPER_MODE
# - ADA_LOGGING
# - ADA_DEVELOPMENT_CHECKS
# - ADA_SANITIZE
# - ADA_SANITIZE_BOUNDS_STRICT
# - ADA_SANITIZE_UNDEFINED
# - ADA_COVERAGE
# - ADA_TOOLS
# - ADA_BENCHMARKS
# - ADA_TESTING
# - ADA_USE_UNSAFE_STD_REGEX_PROVIDER
# - ADA_INCLUDE_URL_PATTERN
# - ADA_WARNINGS_AS_ERRORS
# - ADA_ENABLE_CLANG_TIDY
# - ADA_ENABLE_CPPCHECK

# ============================================================================
# Code Coverage Setup
# ============================================================================
if(ADA_COVERAGE)
  message(STATUS "Code coverage enabled. Assuming gcovr is installed.")
  message(STATUS "  Usage:")
  message(STATUS "    cmake -B build -DADA_COVERAGE=ON")
  message(STATUS "    cmake --build build")
  message(STATUS "    cmake --build build --target ada_coverage")
  message(STATUS "    open build/ada_coverage/index.html")

  include(${PROJECT_SOURCE_DIR}/cmake/codecoverage.cmake)
  APPEND_COVERAGE_COMPILER_FLAGS()
  setup_target_for_coverage_gcovr_html(
    NAME ada_coverage
    EXECUTABLE ctest
    EXCLUDE
      "${PROJECT_SOURCE_DIR}/dependencies/*"
      "${PROJECT_SOURCE_DIR}/tools/*"
      "${PROJECT_SOURCE_DIR}/singleheader/*"
      "${PROJECT_SOURCE_DIR}/include/ada/common_defs.h"
  )
endif()

# ============================================================================
# Build Type Configuration
# ============================================================================
# Build type defaults are now handled in ProjectOptions.cmake
# This provides better integration with presets and developer mode

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# C++ Standard Configuration
# ============================================================================
# Require C++20 standard without compiler extensions
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

message(STATUS "C++ Standard: C++${CMAKE_CXX_STANDARD}")

# ============================================================================
# Compiler Caching (ccache)
# ============================================================================
# Use ccache if available to speed up recompilation
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  message(STATUS "ccache found - using it as compiler launcher: ${CCACHE_FOUND}")
  set(CMAKE_C_COMPILER_LAUNCHER ccache)
  set(CMAKE_CXX_COMPILER_LAUNCHER ccache)
else()
  message(STATUS "ccache not found - consider installing it for faster rebuilds")
endif()

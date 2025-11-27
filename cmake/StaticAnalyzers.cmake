#
# StaticAnalyzers.cmake - Static analysis tool integration
#
# This module provides integration with static analysis tools:
# - clang-tidy: C++ linter and static analyzer
# - cppcheck: C/C++ static analysis tool
#
# Inspired by modern CMake best practices from cpp-best-practices/cmake_template
#

include_guard(GLOBAL)

# ============================================================================
# Function: ada_enable_clang_tidy
# ============================================================================
# Enables clang-tidy for a target if available and enabled via options
#
# Usage:
#   ada_enable_clang_tidy(target_name [WARNINGS_AS_ERRORS])
#
# Arguments:
#   target_name         - The target to apply clang-tidy to
#   WARNINGS_AS_ERRORS  - Treat clang-tidy warnings as errors
#
function(ada_enable_clang_tidy target_name)
  set(options WARNINGS_AS_ERRORS)
  cmake_parse_arguments(TIDY "${options}" "" "" ${ARGN})

  if(NOT ADA_ENABLE_CLANG_TIDY)
    return()
  endif()

  # Find clang-tidy executable
  find_program(CLANG_TIDY_EXE NAMES clang-tidy)

  if(NOT CLANG_TIDY_EXE)
    message(WARNING "clang-tidy requested but not found. Install clang-tidy to enable static analysis.")
    return()
  endif()

  # Build clang-tidy command
  set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}")

  # Add configuration file if it exists
  if(EXISTS "${PROJECT_SOURCE_DIR}/.clang-tidy")
    list(APPEND CLANG_TIDY_COMMAND "--config-file=${PROJECT_SOURCE_DIR}/.clang-tidy")
  endif()

  # Warnings as errors
  if(TIDY_WARNINGS_AS_ERRORS OR ADA_WARNINGS_AS_ERRORS)
    list(APPEND CLANG_TIDY_COMMAND "--warnings-as-errors=*")
  endif()

  # Apply to target
  set_target_properties(${target_name} PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}"
  )

  message(STATUS "${target_name}: clang-tidy enabled (${CLANG_TIDY_EXE})")
endfunction()

# ============================================================================
# Function: ada_enable_cppcheck
# ============================================================================
# Enables cppcheck for a target if available and enabled via options
#
# Usage:
#   ada_enable_cppcheck(target_name [WARNINGS_AS_ERRORS])
#
# Arguments:
#   target_name         - The target to apply cppcheck to
#   WARNINGS_AS_ERRORS  - Treat cppcheck warnings as errors
#
function(ada_enable_cppcheck target_name)
  set(options WARNINGS_AS_ERRORS)
  cmake_parse_arguments(CPPCHECK "${options}" "" "" ${ARGN})

  if(NOT ADA_ENABLE_CPPCHECK)
    return()
  endif()

  # Find cppcheck executable
  find_program(CPPCHECK_EXE NAMES cppcheck)

  if(NOT CPPCHECK_EXE)
    message(WARNING "cppcheck requested but not found. Install cppcheck to enable static analysis.")
    return()
  endif()

  # Build cppcheck command with appropriate flags
  set(CPPCHECK_COMMAND
    "${CPPCHECK_EXE}"
    "--enable=all"                          # Enable all checks
    "--suppress=missingIncludeSystem"       # Suppress missing system include warnings
    "--suppress=unmatchedSuppression"       # Suppress unmatched suppression warnings
    "--suppress=unusedFunction"             # Suppress unused function (library code)
    "--inline-suppr"                        # Allow inline suppressions
    "--std=c++20"                           # C++20 standard
    "--language=c++"                        # C++ language
    "--template=gcc"                        # GCC-style output format
  )

  # Warnings as errors
  if(CPPCHECK_WARNINGS_AS_ERRORS OR ADA_WARNINGS_AS_ERRORS)
    list(APPEND CPPCHECK_COMMAND "--error-exitcode=1")
  endif()

  # Apply to target
  set_target_properties(${target_name} PROPERTIES
    CXX_CPPCHECK "${CPPCHECK_COMMAND}"
  )

  message(STATUS "${target_name}: cppcheck enabled (${CPPCHECK_EXE})")
endfunction()

# ============================================================================
# Function: ada_enable_static_analyzers
# ============================================================================
# Convenience function to enable all configured static analyzers
#
# Usage:
#   ada_enable_static_analyzers(target_name [WARNINGS_AS_ERRORS])
#
# This function will enable both clang-tidy and cppcheck if they are
# enabled via ADA_ENABLE_CLANG_TIDY and ADA_ENABLE_CPPCHECK options.
#
function(ada_enable_static_analyzers target_name)
  set(options WARNINGS_AS_ERRORS)
  cmake_parse_arguments(ANALYZERS "${options}" "" "" ${ARGN})

  if(ANALYZERS_WARNINGS_AS_ERRORS)
    ada_enable_clang_tidy(${target_name} WARNINGS_AS_ERRORS)
    ada_enable_cppcheck(${target_name} WARNINGS_AS_ERRORS)
  else()
    ada_enable_clang_tidy(${target_name})
    ada_enable_cppcheck(${target_name})
  endif()
endfunction()

# ============================================================================
# Global Setup (called when module is included)
# ============================================================================

# Display status of static analyzers if this is the main project
if(PROJECT_NAME STREQUAL "ada" AND (ADA_ENABLE_CLANG_TIDY OR ADA_ENABLE_CPPCHECK))
  message(STATUS "")
  message(STATUS "=== Static Analyzers ===")

  if(ADA_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy)
    if(CLANG_TIDY_EXE)
      message(STATUS "clang-tidy: Enabled (${CLANG_TIDY_EXE})")
      execute_process(
        COMMAND ${CLANG_TIDY_EXE} --version
        OUTPUT_VARIABLE CLANG_TIDY_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
      message(STATUS "  Version: ${CLANG_TIDY_VERSION}")
    else()
      message(STATUS "clang-tidy: Not found (will skip)")
    endif()
  endif()

  if(ADA_ENABLE_CPPCHECK)
    find_program(CPPCHECK_EXE NAMES cppcheck)
    if(CPPCHECK_EXE)
      message(STATUS "cppcheck: Enabled (${CPPCHECK_EXE})")
      execute_process(
        COMMAND ${CPPCHECK_EXE} --version
        OUTPUT_VARIABLE CPPCHECK_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
      message(STATUS "  Version: ${CPPCHECK_VERSION}")
    else()
      message(STATUS "cppcheck: Not found (will skip)")
    endif()
  endif()

  message(STATUS "========================")
  message(STATUS "")
endif()

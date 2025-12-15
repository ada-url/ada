#
# CompilerWarnings.cmake - Systematic compiler warning configuration
#
# This module provides functions to set up compiler warnings for Ada targets.
# Inspired by modern CMake best practices from cpp-best-practices/cmake_template
#

include_guard(GLOBAL)

# ============================================================================
# Function: ada_set_project_warnings
# ============================================================================
# Sets up compiler warnings for a target based on the compiler being used.
# Supports MSVC, GCC, Clang, and AppleClang.
#
# Usage:
#   ada_set_project_warnings(
#     target_name
#     [WARNINGS_AS_ERRORS]
#     [MSVC_WARNINGS warn1 warn2 ...]
#     [CLANG_WARNINGS warn1 warn2 ...]
#     [GCC_WARNINGS warn1 warn2 ...]
#   )
#
# Arguments:
#   target_name          - The target to apply warnings to
#   WARNINGS_AS_ERRORS   - Treat warnings as errors
#   MSVC_WARNINGS        - Custom MSVC warnings (optional)
#   CLANG_WARNINGS       - Custom Clang warnings (optional)
#   GCC_WARNINGS         - Custom GCC warnings (optional)
#
function(ada_set_project_warnings target_name)
  set(options WARNINGS_AS_ERRORS)
  set(oneValueArgs "")
  set(multiValueArgs MSVC_WARNINGS CLANG_WARNINGS GCC_WARNINGS)
  cmake_parse_arguments(WARNINGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  # ========================================
  # Default Warning Sets
  # ========================================

  # MSVC default warnings
  set(MSVC_DEFAULT_WARNINGS
    /W3           # Warning level 3 (production quality)
    /sdl          # Enable additional security checks
    /w34714       # Force inline warning
  )

  # GCC/Clang common warnings
  set(GCC_CLANG_COMMON_WARNINGS
    -Wall                       # Enable most warnings
    -Wextra                     # Extra warnings not covered by -Wall
    -Weffc++                    # Scott Meyers' Effective C++ warnings
    -Wfatal-errors              # Stop on first error
    -Wsign-compare              # Warn about signed/unsigned comparisons
    -Wshadow                    # Warn about variable shadowing
    -Wwrite-strings             # Warn about string literal conversions
    -Wpointer-arith             # Warn about pointer arithmetic
    -Winit-self                 # Warn about self-initialization
    -Wconversion                # Warn about type conversions
    -Wno-sign-conversion        # But allow sign conversions (too noisy)
  )

  # GCC-specific warnings
  set(GCC_SPECIFIC_WARNINGS
    -Wsuggest-override          # Suggest override keyword
  )

  # Clang-specific warnings
  set(CLANG_SPECIFIC_WARNINGS
    -Winconsistent-missing-override  # Warn about missing override keywords
  )

  # ========================================
  # Apply Custom or Default Warnings
  # ========================================

  if(WARNINGS_MSVC_WARNINGS)
    set(MSVC_WARNINGS_TO_USE ${WARNINGS_MSVC_WARNINGS})
  else()
    set(MSVC_WARNINGS_TO_USE ${MSVC_DEFAULT_WARNINGS})
  endif()

  if(WARNINGS_CLANG_WARNINGS)
    set(CLANG_WARNINGS_TO_USE ${WARNINGS_CLANG_WARNINGS})
  else()
    set(CLANG_WARNINGS_TO_USE ${GCC_CLANG_COMMON_WARNINGS} ${CLANG_SPECIFIC_WARNINGS})
  endif()

  if(WARNINGS_GCC_WARNINGS)
    set(GCC_WARNINGS_TO_USE ${WARNINGS_GCC_WARNINGS})
  else()
    set(GCC_WARNINGS_TO_USE ${GCC_CLANG_COMMON_WARNINGS} ${GCC_SPECIFIC_WARNINGS})
  endif()

  # ========================================
  # Warnings as Errors
  # ========================================

  if(WARNINGS_WARNINGS_AS_ERRORS OR ADA_WARNINGS_AS_ERRORS)
    if(MSVC)
      list(APPEND MSVC_WARNINGS_TO_USE /WX)
    else()
      list(APPEND GCC_WARNINGS_TO_USE -Werror)
      list(APPEND CLANG_WARNINGS_TO_USE -Werror)
    endif()
    message(STATUS "${target_name}: Warnings will be treated as errors")
  endif()

  # ========================================
  # Apply Warnings Based on Compiler
  # ========================================

  if(MSVC)
    # Check for legacy Visual Studio
    if("${MSVC_TOOLSET_VERSION}" STREQUAL "140")
      # Visual Studio 2015 - use minimal warnings
      target_compile_options(${target_name} PRIVATE /W0 /sdl)
      message(STATUS "${target_name}: Using minimal warnings for legacy MSVC toolset 140")
    else()
      target_compile_options(${target_name} PRIVATE ${MSVC_WARNINGS_TO_USE})
    endif()

  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${target_name} PRIVATE ${GCC_WARNINGS_TO_USE})

    # Suppress variable tracking notes in debug builds (prevents verbose "retrying without" messages)
    # This affects large files like wpt_urlpattern_tests.cpp that exceed variable tracking limits
    target_compile_options(${target_name} PRIVATE
      $<$<CONFIG:Debug>:-fno-var-tracking-assignments>
    )

    # Workaround for GCC poor AVX load/store code generation on x86
    # Skip this workaround when clang-tidy is enabled (it's Clang-based and doesn't support these flags)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i.86|x86(_64)?)$" AND NOT ADA_ENABLE_CLANG_TIDY)
      target_compile_options(${target_name} PRIVATE
        -mno-avx256-split-unaligned-load
        -mno-avx256-split-unaligned-store
      )
      message(STATUS "${target_name}: Applied GCC AVX workaround for x86 architecture")
    endif()

  elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Matches both "Clang" and "AppleClang"
    target_compile_options(${target_name} PRIVATE ${CLANG_WARNINGS_TO_USE})

  else()
    message(STATUS "${target_name}: Unknown compiler, using GCC-like warnings as fallback")
    target_compile_options(${target_name} PRIVATE ${GCC_WARNINGS_TO_USE})
  endif()

endfunction()

# ============================================================================
# Function: ada_set_sanitizer_flags
# ============================================================================
# Applies sanitizer flags to a target
#
# Usage:
#   ada_set_sanitizer_flags(target_name)
#
# Respects the following cache variables:
#   ADA_SANITIZE               - Address Sanitizer
#   ADA_SANITIZE_UNDEFINED     - Undefined Behavior Sanitizer
#   ADA_SANITIZE_BOUNDS_STRICT - Strict bounds checking (GCC only)
#
function(ada_set_sanitizer_flags target_name)
  set(SANITIZER_FLAGS "")
  set(SANITIZER_LINK_FLAGS "")

  # Address Sanitizer
  if(ADA_SANITIZE)
    list(APPEND SANITIZER_FLAGS
      -fsanitize=address
      -fno-omit-frame-pointer
      -fno-sanitize-recover=all
    )
    list(APPEND SANITIZER_LINK_FLAGS
      -fsanitize=address
      -fno-omit-frame-pointer
      -fno-sanitize-recover=all
    )
    target_compile_definitions(${target_name} PUBLIC ASAN_OPTIONS=detect_leaks=1)
    message(STATUS "${target_name}: Address Sanitizer enabled")
  endif()

  # Undefined Behavior Sanitizer
  if(ADA_SANITIZE_UNDEFINED)
    list(APPEND SANITIZER_FLAGS
      -fsanitize=undefined
      -fno-sanitize-recover=all
    )
    list(APPEND SANITIZER_LINK_FLAGS
      -fsanitize=undefined
      -fno-sanitize-recover=all
    )
    message(STATUS "${target_name}: Undefined Behavior Sanitizer enabled")
  endif()

  # Strict bounds checking (GCC only)
  if(ADA_SANITIZE_BOUNDS_STRICT AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    list(APPEND SANITIZER_FLAGS
      -fsanitize=bounds-strict
      -fno-sanitize-recover=all
    )
    list(APPEND SANITIZER_LINK_FLAGS
      -fsanitize=bounds-strict
      -fno-sanitize-recover=all
    )
    message(STATUS "${target_name}: Strict bounds checking enabled (GCC)")
  endif()

  # Apply flags if any sanitizers are enabled
  if(SANITIZER_FLAGS)
    target_compile_options(${target_name} PUBLIC ${SANITIZER_FLAGS})
    target_link_libraries(${target_name} PUBLIC ${SANITIZER_LINK_FLAGS})
  endif()
endfunction()

# ============================================================================
# Function: ada_set_standard_settings
# ============================================================================
# Sets standard C++ settings for Ada targets
#
# Usage:
#   ada_set_standard_settings(target_name)
#
function(ada_set_standard_settings target_name)
  # Require C++20
  target_compile_features(${target_name} PUBLIC cxx_std_20)

  # Apply development checks if enabled
  if(ADA_DEVELOPMENT_CHECKS)
    target_compile_definitions(${target_name} PUBLIC ADA_DEVELOPMENT_CHECKS=1)
  endif()

  # Apply logging if enabled
  if(ADA_LOGGING)
    target_compile_definitions(${target_name} PRIVATE ADA_LOGGING=1)
  endif()

  # Apply testing flag if enabled
  if(ADA_TESTING)
    target_compile_definitions(${target_name} PRIVATE ADA_TESTING=1)
  endif()

  # URL Pattern support
  if(ADA_INCLUDE_URL_PATTERN)
    target_compile_definitions(${target_name} PRIVATE ADA_INCLUDE_URL_PATTERN=1)
  else()
    target_compile_definitions(${target_name} PRIVATE ADA_INCLUDE_URL_PATTERN=0)
  endif()
endfunction()

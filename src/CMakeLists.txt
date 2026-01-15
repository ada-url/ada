#
# Ada Library Target Configuration
#
# This file configures the main Ada library target with:
# - Compiler warnings (via CompilerWarnings.cmake)
# - Static analyzers (via StaticAnalyzers.cmake)
# - Sanitizers and development checks
# - Platform-specific optimizations
#

# ============================================================================
# Include Modern CMake Modules
# ============================================================================
include(${PROJECT_SOURCE_DIR}/cmake/CompilerWarnings.cmake)
include(${PROJECT_SOURCE_DIR}/cmake/StaticAnalyzers.cmake)

# ============================================================================
# Build Information
# ============================================================================
message(STATUS "Compiler ID : " ${CMAKE_CXX_COMPILER_ID})
message(STATUS "CMAKE_BUILD_TYPE : " ${CMAKE_BUILD_TYPE})

# ============================================================================
# Interface Libraries (for embedding)
# ============================================================================
add_library(ada-include-source INTERFACE)
target_include_directories(ada-include-source INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

add_library(ada-source INTERFACE)
target_sources(ada-source INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/ada.cpp)
target_link_libraries(ada-source INTERFACE ada-include-source)

# ============================================================================
# Main Ada Library Target
# ============================================================================
add_library(ada ada.cpp)

# C++20 standard requirement
target_compile_features(ada PUBLIC cxx_std_20)

# Include directories
target_include_directories(ada PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_include_directories(ada PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")

# Position Independent Code (for shared library compatibility)
if(NOT DEFINED CMAKE_POSITION_INDEPENDENT_CODE)
  set_target_properties(ada PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()
# ============================================================================
# Compiler Warnings
# ============================================================================
# Apply systematic compiler warnings using modern CMake patterns
ada_set_project_warnings(ada)

# ============================================================================
# Static Analysis
# ============================================================================
# Enable clang-tidy and cppcheck if requested
ada_enable_static_analyzers(ada)
# ============================================================================
# Standard Settings & Compile Definitions
# ============================================================================
# Apply standard Ada settings (development checks, logging, testing flags, etc.)
ada_set_standard_settings(ada)

# ============================================================================
# Sanitizers
# ============================================================================
# Apply sanitizer flags if enabled
ada_set_sanitizer_flags(ada)

# ============================================================================
# Optional Dependencies
# ============================================================================
# SIMDUTF for accelerated Unicode processing
if(ADA_USE_SIMDUTF)
  target_link_libraries(ada PRIVATE simdutf)
  target_compile_definitions(ada PRIVATE ADA_USE_SIMDUTF)
  message(STATUS "Ada library: SIMDUTF support enabled")
endif()

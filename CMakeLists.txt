cmake_minimum_required(VERSION 3.16)

project(ada
  DESCRIPTION "Fast spec-compliant URL parser"
  LANGUAGES C CXX
  VERSION 2.7.0
)

set(ADA_LIB_VERSION "2.7.0" CACHE STRING "ada library version")
set(ADA_LIB_SOVERSION "2" CACHE STRING "ada library soversion")

include(GNUInstallDirs)

include (cmake/clang-format.cmake)

include(CTest)
include(cmake/ada-flags.cmake)

set(ADA_SOURCE_DIR src)

add_subdirectory(src)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake)

option(ADA_BENCHMARKS "Build benchmarks" OFF)

# We use Google Benchmark, but it does not build under several 32-bit systems.
if((BUILD_TESTING OR ADA_BENCHMARKS) AND (CMAKE_SIZEOF_VOID_P EQUAL 8))
  include(cmake/CPM.cmake)
  CPMAddPackage("gh:simdjson/simdjson@3.3.0")
  CPMAddPackage(
    NAME GTest
    GITHUB_REPOSITORY google/googletest
    VERSION 1.14.0
    OPTIONS  "BUILD_GMOCK OFF" "INSTALL_GTEST OFF"
  )
  CPMAddPackage(
    NAME benchmark
    GITHUB_REPOSITORY google/benchmark
    GIT_TAG f91b6b4
    OPTIONS "BENCHMARK_ENABLE_TESTING OFF"
            "BENCHMARK_ENABLE_INSTALL OFF"
            "BENCHMARK_ENABLE_WERROR OFF"

  )
endif()

if (BUILD_TESTING AND NOT EMSCRIPTEN)
  message(STATUS "The tests are enabled.")
  add_subdirectory(tests)
else()
  if(is_top_project)
    message(STATUS "The tests are disabled.")
  endif()
endif(BUILD_TESTING AND NOT EMSCRIPTEN)

If(ADA_BENCHMARKS AND NOT EMSCRIPTEN)
  message(STATUS "Ada benchmarks enabled.")
  add_subdirectory(benchmarks)
else(ADA_BENCHMARKS AND NOT EMSCRIPTEN)
  if(is_top_project)
    message(STATUS "Ada benchmarks disabled. Set ADA_BENCHMARKS=ON to enable them.")
  endif()
endif(ADA_BENCHMARKS AND NOT EMSCRIPTEN)

if (BUILD_TESTING AND EMSCRIPTEN)
  add_subdirectory(tests/wasm)
endif(BUILD_TESTING AND EMSCRIPTEN)

add_library(ada::ada ALIAS ada)

set_target_properties(
  ada PROPERTIES
  VERSION "${ADA_LIB_VERSION}"
  SOVERSION "${ADA_LIB_SOVERSION}"
  WINDOWS_EXPORT_ALL_SYMBOLS YES
)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

if(NOT ADA_COVERAGE AND NOT EMSCRIPTEN)
  add_subdirectory(singleheader)
endif()

if(ADA_TOOLS)
  add_subdirectory(tools)
endif()

install(
  FILES include/ada.h include/ada_c.h
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT ada_development
)

install(
  DIRECTORY include/ada
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT ada_development
)

install(
  TARGETS ada
  EXPORT ada_targets
  RUNTIME COMPONENT ada_runtime
  LIBRARY COMPONENT ada_runtime
  NAMELINK_COMPONENT ada_development
  ARCHIVE COMPONENT ada_development
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

configure_file(cmake/ada-config.cmake.in ada-config.cmake @ONLY)

write_basic_package_version_file(
  ada-config-version.cmake
  COMPATIBILITY SameMinorVersion
)

set(
  ADA_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/ada"
  CACHE STRING "CMake package config location relative to the install prefix"
)
mark_as_advanced(ADA_INSTALL_CMAKEDIR)

install(
  FILES
  "${PROJECT_BINARY_DIR}/ada-config.cmake"
  "${PROJECT_BINARY_DIR}/ada-config-version.cmake"
  DESTINATION "${ADA_INSTALL_CMAKEDIR}"
  COMPONENT ada_development
)

install(
  EXPORT ada_targets
  NAMESPACE ada::
  DESTINATION "${ADA_INSTALL_CMAKEDIR}"
  COMPONENT ada_development
)

install(
  EXPORT ada_targets
  NAMESPACE ada::
  DESTINATION "${ADA_INSTALL_CMAKEDIR}"
  COMPONENT example_development
)

if(is_top_project)
  set(CPACK_PACKAGE_VENDOR "Ada Authors")
  set(CPACK_PACKAGE_CONTACT "yagiz@nizipli.com")
  set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE-MIT")
  set(CPACK_RPM_PACKAGE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE-MIT")
  set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README.md")
  set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
  include(CPack)
endif()

cmake_minimum_required(VERSION 3.16)

project(ada
  DESCRIPTION "Fast spec-compliant URL parser"
  LANGUAGES C CXX
  VERSION 0.1.0
)

include(GNUInstallDirs)

include(CTest)
include(cmake/ada-flags.cmake)

set(ADA_LIB_VERSION "0.1.0" CACHE STRING "ada library version")
set(ADA_LIB_SOVERSION "1" CACHE STRING "ada library soversion")

set(ADA_SOURCE_DIR src)

add_subdirectory(src)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake)

option(ADA_BENCHMARKS "Build benchmarks" OFF)

if(BUILD_TESTING OR ADA_BENCHMARKS)
  include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)
  import_dependency(simdjson simdjson/simdjson 0a3a00c95665cc1fda760e121ba8d442945ede13)
  add_dependency(simdjson)
endif()

if (BUILD_TESTING)
  message(STATUS "The tests are enabled.")
  add_subdirectory(tests)
else()
  if(is_top_project)
    message(STATUS "The tests are disabled.")
  endif()
endif(BUILD_TESTING)


If(ADA_BENCHMARKS)
  message(STATUS "Ada benchmarks enabled.")
  add_subdirectory(benchmarks)
else(ADA_BENCHMARKS)
  if(is_top_project)
    message(STATUS "Ada benchmarks disabled. Set ADA_BENCHMARKS=ON to enable them.")
  endif()
endif(ADA_BENCHMARKS)

add_library(ada::ada ALIAS ada)

set_target_properties(
  ada PROPERTIES
  VERSION "${ADA_LIB_VERSION}"
  SOVERSION "${ADA_LIB_SOVERSION}"
  WINDOWS_EXPORT_ALL_SYMBOLS YES
)

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
  message(STATUS "Big-endian system detected.")
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  message(STATUS "Apple system detected.")
  # People who run macOS often use brew.
  if(EXISTS /opt/homebrew/opt/icu4c)
    message(STATUS "icu is provided by homebrew at /opt/homebrew/opt/icu4c.")
    ## This is a bit awkward, but it is a lot better than asking the
    ## user to figure that out.
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/icu4c/include")
    list(APPEND CMAKE_LIBRARY_PATH "/opt/homebrew/opt/icu4c/lib")
  elseif(EXISTS /usr/local/opt/icu4c)
    message(STATUS "icu is provided by homebrew at /usr/local/opt/icu4c.")
    list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/icu4c/include")
    list(APPEND CMAKE_LIBRARY_PATH "/usr/local/opt/icu4c/lib")
  endif()
endif()


find_package(ICU COMPONENTS uc i18n)
### If the user does not have ICU, let us help them with instructions:
if(ICU_FOUND)
  target_link_libraries(ada PRIVATE ICU::uc ICU::i18n)
else(ICU_FOUND)
  # Under Windows, we have a backup.
  if(MSVC) # could be WIN32 but there are other systems under Windows.
    if(MSVC_VERSION GREATER_EQUAL 1920)
      message(STATUS "You have a recent Visual Studio (2019 or better), congratulations!")
    else()
      message(SEND_ERROR "If you use Visual Studio, then Visual Studio 2019 or better is required.")
      return()
    endif()
    option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
    target_link_libraries(ada PRIVATE Normaliz)
  else(MSVC)
    if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
      if(EXISTS /opt/homebrew)
        message(STATUS "Under macOS, you may install ICU with brew, using 'brew install icu4c'.")
      else()
        message(STATUS "Under macOS, you should install brew (see https://brew.sh) and then icu4c ('brew install icu4c').")
      endif()
    elif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      message(STATUS "Under Linux, you may be able to install ICU with a command such as 'apt-get install libicu-dev'." )
    endif()
    message(SEND_ERROR "ICU with components uc and i18n/in is required for building ada.")
    return()
  endif(MSVC)
endif(ICU_FOUND)
### Going forward, we have ICU for sure, except under Windows.

if(NOT ADA_COVERAGE)
  add_subdirectory(singleheader)
  add_subdirectory(tools)
endif()

install(
  FILES include/ada.h
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

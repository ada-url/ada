cmake_minimum_required(VERSION 3.24)

project(ada
  DESCRIPTION "Fast spec-compliant URL parser"
  LANGUAGES CXX
  VERSION 0.1.0
)

include(GNUInstallDirs)

include(CTest)
include(cmake/ada-flags.cmake)

set(ADA_LIB_VERSION "0.1.0" CACHE STRING "ada library version")
set(ADA_LIB_SOVERSION "1" CACHE STRING "ada library soversion")

set(ADA_SOURCE_DIR src)

add_subdirectory(src)

IF (BUILD_TESTING)
  message(STATUS "The tests are enabled.")
  add_subdirectory(tests)
else()
  message(STATUS "The tests are disabled.")
endif(BUILD_TESTING)

add_library(ada::ada ALIAS ada)

set_target_properties(
  ada PROPERTIES
  VERSION "${ADA_LIB_VERSION}"
  SOVERSION "${ADA_LIB_SOVERSION}"
  WINDOWS_EXPORT_ALL_SYMBOLS YES
)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

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
  ada-config.version.cmake
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
  # TODO: Update contact information
  set(CPACK_PACKAGE_VENDOR "Ada Authors")
  set(CPACK_PACKAGE_CONTACT "example@email.com")
  set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE-MIT")
  set(CPACK_RPM_PACKAGE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE-MIT")
  set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README.md")
  set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
  include(CPack)
endif()

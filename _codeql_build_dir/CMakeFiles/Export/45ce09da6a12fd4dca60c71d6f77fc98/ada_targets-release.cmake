#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "ada::ada" for configuration "Release"
set_property(TARGET ada::ada APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(ada::ada PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libada.a"
  )

list(APPEND _cmake_import_check_targets ada::ada )
list(APPEND _cmake_import_check_files_for_ada::ada "${_IMPORT_PREFIX}/lib/libada.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)

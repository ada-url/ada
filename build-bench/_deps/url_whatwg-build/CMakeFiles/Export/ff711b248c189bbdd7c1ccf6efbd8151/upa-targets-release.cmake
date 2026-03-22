#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "upa::url" for configuration "Release"
set_property(TARGET upa::url APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(upa::url PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libupa_url.a"
  )

list(APPEND _cmake_import_check_targets upa::url )
list(APPEND _cmake_import_check_files_for_upa::url "${_IMPORT_PREFIX}/lib/libupa_url.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)

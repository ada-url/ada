
message(STATUS "Compiler ID : " ${CMAKE_CXX_COMPILER_ID})
message(STATUS "CMAKE_BUILD_TYPE : " ${CMAKE_BUILD_TYPE})

add_library(ada-include-source INTERFACE)
target_include_directories(ada-include-source INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
add_library(ada-source INTERFACE)
target_sources(ada-source INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/ada.cpp)
target_link_libraries(ada-source INTERFACE ada-include-source)
add_library(ada ada.cpp unicode_percent_encode.cpp url_pattern_list.cpp)
target_compile_features(ada PUBLIC cxx_std_20)
target_include_directories(ada PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> )
target_include_directories(ada PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
if(NOT DEFINED CMAKE_POSITION_INDEPENDENT_CODE)
  # We default to ON for all targets, so that we can use the library in shared libraries.
  set_target_properties(ada PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif(NOT DEFINED CMAKE_POSITION_INDEPENDENT_CODE)
if(MSVC)
  if("${MSVC_TOOLSET_VERSION}" STREQUAL "140")
    target_compile_options(ada INTERFACE /W0 /sdl)
    set(ADA_LEGACY_VISUAL_STUDIO TRUE)
  else()
    target_compile_options(ada PRIVATE /WX /W3 /sdl /w34714) # https://docs.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warning-level-4-c4714?view=vs-2019
  endif()
else(MSVC)
  message(STATUS "Assuming GCC-like compiler.")
  target_compile_options(ada PRIVATE -Wall -Wextra -Weffc++)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(ada PRIVATE -Wsuggest-override)
  endif()
  if((CMAKE_CXX_COMPILER_ID STREQUAL "Clang") OR (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang"))
    target_compile_options(ada PRIVATE -Winconsistent-missing-override)
  endif()
  target_compile_options(ada PRIVATE -Wfatal-errors -Wsign-compare -Wshadow -Wwrite-strings -Wpointer-arith -Winit-self -Wconversion -Wno-sign-conversion)
endif(MSVC)

# workaround for GNU GCC poor AVX load/store code generation
if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") AND (CMAKE_SYSTEM_PROCESSOR MATCHES "^(i.86|x86(_64)?)$"))
  target_compile_options(ada PRIVATE -mno-avx256-split-unaligned-load -mno-avx256-split-unaligned-store)
endif()
if(ADA_DEVELOPMENT_CHECKS)
  target_compile_definitions(ada PUBLIC ADA_DEVELOPMENT_CHECKS=1)
endif()

if(ADA_SANITIZE)
  target_compile_options(ada PUBLIC -fsanitize=address  -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_compile_definitions(ada PUBLIC ASAN_OPTIONS=detect_leaks=1)
  target_link_libraries(ada PUBLIC -fsanitize=address  -fno-omit-frame-pointer -fno-sanitize-recover=all)
endif()
if(ADA_SANITIZE_WITHOUT_LEAKS)
  target_compile_options(ada PUBLIC -fsanitize=address  -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_link_libraries(ada PUBLIC -fsanitize=address  -fno-omit-frame-pointer -fno-sanitize-recover=all)
endif()

if(ADA_LOGGING)
  target_compile_definitions(ada PRIVATE ADA_LOGGING=1)
endif()

if(ADA_NEON_SAFE_ZERO_CHECK)
  target_compile_definitions(ada PRIVATE ADA_NEON_SAFE_ZERO_CHECK=1)
endif()

if(ADA_TESTING)
  target_compile_definitions(ada PRIVATE ADA_TESTING=1)
endif()

# Keep the SIMD percent-encode kernel in its own TU so the unity ada.cpp
# inlining budget for setters matches main.
target_compile_definitions(ada PRIVATE ADA_PERCENT_ENCODE_SIMD_SEPARATE_TU=1)

# Keep the URLPattern route-set compiler (the builder, src/url_pattern_list.cpp)
# in its own TU for the same reason: the extra code in the unity TU reshuffles
# GCC's unit-wide inlining budget and de-inlines url_aggregator setter hot
# paths (CodSpeed: SetHash -12%). The matcher itself is inline in the public
# header so it inlines into url_pattern_list::match. The amalgamated
# single-file build still includes the builder inline.
target_compile_definitions(ada PRIVATE ADA_URL_PATTERN_LIST_SEPARATE_TU=1)

if(ADA_INCLUDE_URL_PATTERN)
  target_compile_definitions(ada PRIVATE ADA_INCLUDE_URL_PATTERN=1)
else()
  target_compile_definitions(ada PRIVATE ADA_INCLUDE_URL_PATTERN=0)
endif()

if (ADA_USE_SIMDUTF)
  target_link_libraries(ada PRIVATE simdutf)
  target_compile_definitions(ada PRIVATE ADA_USE_SIMDUTF)
endif()

# Editing ada_c.cpp inside the unity translation unit changes GCC's inlining of
# the setters (CodSpeed). On ELF the unity TU keeps a byte-for-byte copy of
# main's C API, and the fixed implementation is a separate object. The baseline
# symbols are renamed out of the way before the archive is created.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND UNIX AND NOT APPLE)
  target_sources(ada PRIVATE ada_c.cpp)
  target_compile_definitions(ada PRIVATE ADA_C_API_BASELINE=1)
  find_program(ADA_OBJCOPY objcopy REQUIRED)
  add_custom_command(
    TARGET ada
    PRE_LINK
    COMMAND
      /bin/sh "${CMAKE_CURRENT_SOURCE_DIR}/rename_baseline_c_symbols.sh"
      "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ada.dir/ada.cpp.o"
      "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ada.dir/ada_c.cpp.o"
    VERBATIM)
endif()

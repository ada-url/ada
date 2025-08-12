add_executable(adaparse adaparse.cpp line_iterator.h)
target_link_libraries(adaparse PRIVATE ada)
target_include_directories(adaparse PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")


if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    # We are on an Apple platform, so we can use dead_strip and LTO
    # to reduce the size of the final binary.
    message(STATUS "Apple platform detected, using dead_strip and LTO")
    target_link_options(adaparse PRIVATE "-Wl,-dead_strip")
    target_compile_options(adaparse PRIVATE "-flto")
    target_link_options(adaparse PRIVATE "-flto")
endif(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")

if((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
  execute_process(COMMAND ${CMAKE_CXX_COMPILER} -print-libgcc-file-name OUTPUT_VARIABLE ADA_GCC_LIB)
  get_filename_component(ADA_GCC_DIR "${ADA_GCC_LIB}" DIRECTORY)
  message(STATUS "looking for static C++ library in " ${ADA_GCC_DIR})
  find_library(LIBSTDCPP libstdc++.a PATHS "${ADA_GCC_DIR}")
  if(LIBSTDCPP)
    # static linkink for speed
    message(STATUS "libstdc++.a found")
    target_link_options(adaparse PRIVATE "-static-libstdc++")
  else()
    message(STATUS "libstdc++.a not found")
  endif()
  # Note that we are not under Apple at this time.
  # We can use the -Wl,--gc-sections option to remove unused sections
  # from the final binary, which can reduce the size of the binary.
  target_link_options(adaparse PRIVATE "-Wl,--gc-sections")
endif()

if(MSVC AND BUILD_SHARED_LIBS)
  # Copy the ada dll into the directory
  add_custom_command(TARGET adaparse POST_BUILD        # Adds a post-build event
    COMMAND ${CMAKE_COMMAND} -E copy_if_different  # which executes "cmake -E copy_if_different..."
        "$<TARGET_FILE:ada>"      # <--this is in-file
        "$<TARGET_FILE_DIR:adaparse>")                 # <--this is out-file path
endif()
CPMFindPackage(
  NAME fmt
  GITHUB_REPOSITORY fmtlib/fmt
  GIT_TAG 11.0.2
)
CPMFindPackage(
  NAME cxxopts
  GITHUB_REPOSITORY jarro2783/cxxopts
  GIT_TAG v3.2.0
  OPTIONS "CXXOPTS_BUILD_EXAMPLES NO" "CXXOPTS_BUILD_TESTS NO" "CXXOPTS_ENABLE_INSTALL YES"
)
target_link_libraries(adaparse PRIVATE cxxopts::cxxopts fmt::fmt)

if(MSVC OR MINGW)
  target_compile_definitions(adaparse PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
endif()

install(
   TARGETS
    adaparse
   ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
   LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
   RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

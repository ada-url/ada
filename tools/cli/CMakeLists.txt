add_executable(adaparse adaparse.cpp line_iterator.h)
target_link_libraries(adaparse PRIVATE ada)
target_include_directories(adaparse PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
if(MSVC AND BUILD_SHARED_LIBS)
  # Copy the ada dll into the directory
  add_custom_command(TARGET adaparse POST_BUILD        # Adds a post-build event
    COMMAND ${CMAKE_COMMAND} -E copy_if_different  # which executes "cmake -E copy_if_different..."
        "$<TARGET_FILE:ada>"      # <--this is in-file
        "$<TARGET_FILE_DIR:adaparse>")                 # <--this is out-file path
endif()
CPMAddPackage("gh:fmtlib/fmt#7.1.3")
CPMAddPackage(
  GITHUB_REPOSITORY jarro2783/cxxopts
  VERSION 3.1.1
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
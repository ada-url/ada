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
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 11.0.2
)
FetchContent_MakeAvailable(fmt)
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.2.0
)
set(CXXOPTS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CXXOPTS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CXXOPTS_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cxxopts)
target_link_libraries(adaparse PRIVATE cxxopts::cxxopts fmt::fmt)

if(MSVC OR MINGW)
  target_compile_definitions(adaparse PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
endif()

install(
  TARGETS adaparse
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

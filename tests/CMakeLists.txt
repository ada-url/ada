add_subdirectory(wpt)

set(ADA_TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
if(MSVC)
  add_compile_options("/Zi" "/EHsc" "/GR")
  add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
  add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
endif()

include(${PROJECT_SOURCE_DIR}/cmake/add-cpp-test.cmake)
link_libraries(ada)

add_cpp_test(basic_fuzzer)

if(MSVC AND BUILD_SHARED_LIBS)
  # Copy the ada dll into the directory
  add_custom_command(TARGET basic_fuzzer PRE_BUILD        # Adds a pre-build event
    COMMAND ${CMAKE_COMMAND} -E copy_if_different  # which executes "cmake -E copy_if_different..."
        "$<TARGET_FILE:ada>"      # <--this is in-file
        "$<TARGET_FILE_DIR:basic_fuzzer>")                 # <--this is out-file path
endif()

if(MSVC AND BUILD_SHARED_LIBS)
  message(STATUS "For some tests we use Google Test and it fails when building a DLL.")
  message(STATUS "Thus the tests are disabled. Sorry.")
else()
  include(GoogleTest)
  add_executable(wpt_tests wpt_tests.cpp)
  add_executable(url_components url_components.cpp)
  add_executable(basic_tests basic_tests.cpp)
  add_executable(from_file_tests from_file_tests.cpp)
  add_executable(ada_c ada_c.cpp)
  add_executable(url_search_params url_search_params.cpp)

  target_link_libraries(wpt_tests PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(url_components PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(basic_tests PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(from_file_tests PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(ada_c PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(url_search_params PRIVATE simdjson GTest::gtest_main)

  gtest_discover_tests(wpt_tests)
  gtest_discover_tests(url_components)
  gtest_discover_tests(basic_tests)
  gtest_discover_tests(from_file_tests)
  gtest_discover_tests(ada_c)
  gtest_discover_tests(url_search_params)

  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
      target_link_libraries(wpt_tests PUBLIC stdc++fs)
      target_link_libraries(url_components PUBLIC stdc++fs)
      target_link_libraries(url_search_params PUBLIC stdc++fs)
    endif()
  endif()

  if(MSVC OR MINGW)
    target_compile_definitions(wpt_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(url_components PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(basic_fuzzer PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(from_file_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(basic_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(url_search_params PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()

endif()

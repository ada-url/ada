#
# Source files should be just ASCII
#
find_program(FIND find)
find_program(FILE file)
find_program(GREP grep)
if(FIND AND FILE AND GREP)
  add_test(
      NAME just_ascii
      COMMAND sh -c "\
${FIND} include src tests tools benchmarks  -name '*.h' -o -name '*.txt' -o -name '*.cpp' -type f -exec ${FILE} '{}' \; | ${GREP} -qv ASCII || exit 0  && exit 1"
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  )
endif()

add_subdirectory(wpt)

set(ADA_TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
if(MSVC)
  add_compile_options("/Zi" "/EHsc" "/GR")
  add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
  add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
endif()

if(ADA_LOGGING)
  add_compile_definitions(ADA_LOGGING=1)
endif()

if(ADA_TESTING)
  add_compile_definitions(ADA_TESTING=1)
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
  add_executable(wpt_url_tests wpt_url_tests.cpp)
  add_executable(wpt_urlpattern_tests wpt_urlpattern_tests.cpp)
  add_executable(url_components url_components.cpp)
  add_executable(basic_tests basic_tests.cpp)
  add_executable(from_file_tests from_file_tests.cpp)
  add_executable(ada_c ada_c.cpp)
  add_executable(url_search_params url_search_params.cpp)

  target_link_libraries(wpt_url_tests PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(wpt_urlpattern_tests PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(url_components PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(basic_tests PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(from_file_tests PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(ada_c PRIVATE simdjson GTest::gtest_main)
  target_link_libraries(url_search_params PRIVATE simdjson GTest::gtest_main)

  gtest_discover_tests(wpt_url_tests PROPERTIES TEST_DISCOVERY_TIMEOUT 600)
  gtest_discover_tests(wpt_urlpattern_tests PROPERTIES TEST_DISCOVERY_TIMEOUT 600)
  gtest_discover_tests(url_components PROPERTIES TEST_DISCOVERY_TIMEOUT 600)
  gtest_discover_tests(basic_tests PROPERTIES TEST_DISCOVERY_TIMEOUT 600)
  gtest_discover_tests(from_file_tests PROPERTIES TEST_DISCOVERY_TIMEOUT 600)
  gtest_discover_tests(ada_c PROPERTIES TEST_DISCOVERY_TIMEOUT 600)
  gtest_discover_tests(url_search_params PROPERTIES TEST_DISCOVERY_TIMEOUT 600)

  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
      target_link_libraries(wpt_url_tests PUBLIC stdc++fs)
      target_link_libraries(wpt_urlpattern_tests PUBLIC stdc++fs)
      target_link_libraries(url_components PUBLIC stdc++fs)
      target_link_libraries(url_search_params PUBLIC stdc++fs)
    endif()
  endif()

  if(MSVC OR MINGW)
    target_compile_definitions(wpt_url_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(wpt_urlpattern_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(url_components PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(basic_fuzzer PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(from_file_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(basic_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(url_search_params PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()

endif()

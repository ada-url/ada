add_subdirectory(wpt)

set(ADA_TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
if(MSVC)
  add_compile_options("/Zi" "/EHsc" "/GR")
endif()

include(${PROJECT_SOURCE_DIR}/cmake/add-cpp-test.cmake)
link_libraries(ada)

include(GoogleTest)

add_cpp_test(wpt_tests)
add_cpp_test(url_components )
add_cpp_test(basic_fuzzer)
add_cpp_test(from_file_tests)
add_cpp_test(basic_tests)

target_link_libraries(wpt_tests PRIVATE simdjson gtest)
target_link_libraries(url_components PRIVATE simdjson gtest)
target_link_libraries(basic_tests PRIVATE simdjson gtest)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(wpt_tests PUBLIC stdc++fs)
    target_link_libraries(url_components PUBLIC stdc++fs)
  endif()
endif()

if(MSVC OR MINGW)
  target_compile_definitions(wpt_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(url_components PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(basic_fuzzer PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(from_file_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(basic_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_subdirectory(wpt)

set(ADA_TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
if(MSVC)
  add_compile_options("/Zi" "/EHsc" "/GR")
endif()

include(${PROJECT_SOURCE_DIR}/cmake/add-cpp-test.cmake)
link_libraries(ada)

add_cpp_test(wpt_tests)
add_cpp_test(url_components)
target_link_libraries(wpt_tests PRIVATE simdjson)
target_link_libraries(url_components PRIVATE simdjson)
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(wpt_tests PUBLIC stdc++fs)
    target_link_libraries(url_components PUBLIC stdc++fs)
  endif()
endif()

add_cpp_test(basic_fuzzer)
add_cpp_test(from_file_tests)
add_cpp_test(basic_tests)

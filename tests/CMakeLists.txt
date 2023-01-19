include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)

import_dependency(gtest google/googletest ec25eea)
add_dependency(gtest)

import_dependency(simdjson simdjson/simdjson v3.0.1)
add_dependency(simdjson)
add_subdirectory(wpt)


set(ADA_TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
if(MSVC)
  add_compile_options("/Zi" "/EHsc" "/GR")
endif()

include(${PROJECT_SOURCE_DIR}/cmake/add-cpp-test.cmake)
link_libraries(ada)


add_cpp_test(wpt_tests)
target_link_libraries(wpt_tests PUBLIC simdjson)
target_link_libraries(wpt_tests PUBLIC ada)
target_link_libraries(wpt_tests PUBLIC gtest)

add_cpp_test(basic_fuzzer)
target_link_libraries(basic_fuzzer PUBLIC ada)


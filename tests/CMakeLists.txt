include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)

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

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
target_link_libraries(wpt_tests PUBLIC stdc++fs)
endif()
endif()


add_cpp_test(basic_fuzzer)
target_link_libraries(basic_fuzzer PUBLIC ada)


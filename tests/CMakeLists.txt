
include(FetchContent)
FetchContent_Declare(
  simdjson
  GIT_REPOSITORY https://github.com/simdjson/simdjson.git
  GIT_SHALLOW TRUE
  GIT_TAG tags/v3.0.1
  )

FetchContent_MakeAvailable(simdjson)

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

set(ADA_TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
if(MSVC)
  add_compile_options("/Zi" "/EHsc" "/GR")
endif()

include(${PROJECT_SOURCE_DIR}/cmake/add-cpp-test.cmake)
link_libraries(ada)

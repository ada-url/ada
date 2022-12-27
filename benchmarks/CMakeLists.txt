
include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)

set_off(BENCHMARK_ENABLE_TESTING)
set_off(BENCHMARK_ENABLE_INSTALL)
set_off(BENCHMARK_ENABLE_WERROR)

import_dependency(google_benchmarks google/benchmark f91b6b4)
add_dependency(google_benchmarks)

set_off(URIPARSER_BUILD_TESTS)
set_off(URIPARSER_BUILD_DOCS)
import_dependency(uriparser uriparser/uriparser 634b678)
add_dependency(uriparser)

import_dependency(boost_url boostorg/url boost-1.81.0)
add_library(boost_url INTERFACE)
target_include_directories(boost_url INTERFACE
           "${boost_url_SOURCE_DIR}/include")

find_package(
    Boost
    COMPONENTS system
)
if(Boost_FOUND)
    message(STATUS "Boost was found.")
    add_executable(bench bench.cpp)
    target_link_libraries(bench PRIVATE boost_url)
    target_link_libraries(bench PRIVATE ada)
    target_include_directories(bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
    target_link_libraries(bench PRIVATE benchmark::benchmark)
    target_link_libraries(bench PRIVATE Boost::system)
    target_link_libraries(bench PRIVATE uriparser)
else(Boost_FOUND)
    message(STATUS "Boost was not found, please install it for benchmarking purposes.")
endif(Boost_FOUND)


add_executable(bench bench.cpp)
target_link_libraries(bench PRIVATE ada)
target_include_directories(bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_include_directories(bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/benchmarks>")


add_executable(bbc_bench bbc_bench.cpp)
target_link_libraries(bbc_bench PRIVATE ada)
target_include_directories(bbc_bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_include_directories(bbc_bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/benchmarks>")


include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)

set_off(BENCHMARK_ENABLE_TESTING)
set_off(BENCHMARK_ENABLE_INSTALL)
set_off(BENCHMARK_ENABLE_WERROR)

import_dependency(google_benchmarks google/benchmark f91b6b4)
add_dependency(google_benchmarks)
target_link_libraries(bench PRIVATE benchmark::benchmark)
target_link_libraries(bbc_bench PRIVATE benchmark::benchmark)



set_off(URIPARSER_BUILD_TESTS)
set_off(URIPARSER_BUILD_DOCS)
import_dependency(uriparser uriparser/uriparser 634b678)
add_dependency(uriparser)
target_link_libraries(bench PRIVATE uriparser)
target_link_libraries(bbc_bench PRIVATE uriparser)

import_dependency(urlparser netmindms/urlparser 69c09ed)
add_library(urlparser STATIC "${urlparser_SOURCE_DIR}/src/EdUrlParser.cpp")
target_include_directories(urlparser PUBLIC "${urlparser_SOURCE_DIR}/src")
target_link_libraries(bench PRIVATE urlparser)
target_link_libraries(bbc_bench PRIVATE urlparser)

import_dependency(httpparser nodejs/http-parser v2.9.4)
add_library(httpparser STATIC "${httpparser_SOURCE_DIR}/http_parser.c")
set_source_files_properties("${httpparser_SOURCE_DIR}/http_parser.c" PROPERTIES LANGUAGE C)
target_include_directories(httpparser PUBLIC "${httpparser_SOURCE_DIR}")
target_link_libraries(bench PRIVATE httpparser)
target_link_libraries(bbc_bench PRIVATE httpparser)

import_dependency(boost_url boostorg/url boost-1.81.0)
add_library(boost_url INTERFACE)
target_include_directories(boost_url INTERFACE
           "${boost_url_SOURCE_DIR}/include")

find_package(CURL)
if(CURL_FOUND)
    message(STATUS "curl version ${CURL_VERSION}")
    include_directories(${CURL_INCLUDE_DIRS})
    if(NOT CURL_LIBRARIES)
        target_link_libraries(bench PRIVATE CURL::libcurl)
        target_link_libraries(bbc_bench PRIVATE CURL::libcurl)
    else()
        target_link_libraries(bench PRIVATE ${CURL_LIBRARIES})
        target_link_libraries(bbc_bench PRIVATE ${CURL_LIBRARIES})
    endif()
    target_compile_definitions(bench PRIVATE CURL_ENABLED=1)
    target_compile_definitions(bbc_bench PRIVATE CURL_ENABLED=1)
else(CURL_FOUND)
    message(STATUS "Curl not found! Please install the curl library.")
endif(CURL_FOUND)

find_package(
    Boost 1.80
    COMPONENTS system
)

if(Boost_FOUND)
    target_link_libraries(bench PRIVATE Boost::system)
    target_link_libraries(bench PRIVATE boost_url)
    target_compile_definitions(bench PRIVATE BOOST_ENABLED=1)


    target_link_libraries(bbc_bench PRIVATE Boost::system)
    target_link_libraries(bbc_bench PRIVATE boost_url)
    target_compile_definitions(bbc_bench PRIVATE BOOST_ENABLED=1)
else(Boost_FOUND)
    message(STATUS "Boost 1.80 or better was not found, please install it for benchmarking purposes.")
endif(Boost_FOUND)

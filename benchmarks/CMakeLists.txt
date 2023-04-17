

# Bench
add_executable(wpt_bench wpt_bench.cpp)
target_link_libraries(wpt_bench PRIVATE ada)
target_link_libraries(wpt_bench PRIVATE simdjson)
target_include_directories(wpt_bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_include_directories(wpt_bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/benchmarks>")

# Bench
add_executable(bench bench.cpp)
target_link_libraries(bench PRIVATE ada)
target_include_directories(bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_include_directories(bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/benchmarks>")

# Benchdata
import_dependency(url-dataset ada-url/url-dataset 9749b92c13e970e70409948fa862461191504ccc)
add_executable(benchdata bench.cpp)
target_link_libraries(benchdata PRIVATE ada)
target_include_directories(benchdata PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_include_directories(benchdata PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/benchmarks>")
target_compile_definitions(benchdata PRIVATE ADA_URL_FILE="${url-dataset_SOURCE_DIR}/out.txt")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    # model bench
    add_executable(model_bench model_bench.cpp)
    target_link_libraries(model_bench PRIVATE ada)
    target_compile_definitions(model_bench PRIVATE ADA_URL_FILE="${url-dataset_SOURCE_DIR}/out.txt")
endif()

# BBC Bench
add_executable(bbc_bench bbc_bench.cpp)
target_link_libraries(bbc_bench PRIVATE ada)
target_include_directories(bbc_bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_include_directories(bbc_bench PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/benchmarks>")

# Percent Encode
add_executable(percent_encode percent_encode.cpp)
target_link_libraries(percent_encode PRIVATE ada)
target_include_directories(percent_encode PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_include_directories(percent_encode PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/benchmarks>")

include(${PROJECT_SOURCE_DIR}/cmake/import.cmake)

set_off(BENCHMARK_ENABLE_TESTING)
set_off(BENCHMARK_ENABLE_INSTALL)
set_off(BENCHMARK_ENABLE_WERROR)

import_dependency(google_benchmarks google/benchmark f91b6b4)
add_dependency(google_benchmarks)
target_link_libraries(wpt_bench PRIVATE benchmark::benchmark)
target_link_libraries(bench PRIVATE benchmark::benchmark)
target_link_libraries(benchdata PRIVATE benchmark::benchmark)
target_link_libraries(bbc_bench PRIVATE benchmark::benchmark)
target_link_libraries(percent_encode PRIVATE benchmark::benchmark)

option(ADA_COMPETITION "Whether to install various competitors." OFF)



if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  message(STATUS "Apple system detected.")
  # People who run macOS often use brew.
  if(EXISTS /opt/homebrew/opt/icu4c)
    message(STATUS "icu is provided by homebrew at /opt/homebrew/opt/icu4c.")
    ## This is a bit awkward, but it is a lot better than asking the
    ## user to figure that out.
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/icu4c/include")
    list(APPEND CMAKE_LIBRARY_PATH "/opt/homebrew/opt/icu4c/lib")
  elseif(EXISTS /usr/local/opt/icu4c)
    message(STATUS "icu is provided by homebrew at /usr/local/opt/icu4c.")
    list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/icu4c/include")
    list(APPEND CMAKE_LIBRARY_PATH "/usr/local/opt/icu4c/lib")
  endif()
endif()

find_package(ICU COMPONENTS uc i18n)
### If the user does not have ICU, let us help them with instructions:
if(NOT ICU_FOUND)
  if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
      if(EXISTS /opt/homebrew)
        message(STATUS "Under macOS, you may install ICU with brew, using 'brew install icu4c'.")
      else()
        message(STATUS "Under macOS, you should install brew (see https://brew.sh) and then icu4c ('brew install icu4c').")
      endif()
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      message(STATUS "Under Linux, you may be able to install ICU with a command such as 'apt-get install libicu-dev'." )
  endif()
endif(NOT ICU_FOUND)

if(ICU_FOUND)
    set_off(URL_BUILD_TESTS)
    set_off(URL_USE_LIBS)
    import_dependency(url_whatwg rmisev/url_whatwg cbcf3043eccb380cb4bef7486465ac3b02d2f674)
    add_dependency(url_whatwg)
    add_library(url_whatwg_lib STATIC "${url_whatwg_SOURCE_DIR}/src/url.cpp"
      "${url_whatwg_SOURCE_DIR}/src/url_idna.cpp"
      "${url_whatwg_SOURCE_DIR}/src/url_ip.cpp"
      "${url_whatwg_SOURCE_DIR}/src/url_percent_encode.cpp"
      "${url_whatwg_SOURCE_DIR}/src/url_search_params.cpp"
      "${url_whatwg_SOURCE_DIR}/src/url_utf.cpp"
      "${url_whatwg_SOURCE_DIR}/src/url.cpp")
    target_link_libraries(url_whatwg_lib PRIVATE ICU::uc ICU::i18n)


    target_link_libraries(bench PRIVATE url_whatwg_lib)
    target_link_libraries(benchdata PRIVATE url_whatwg_lib)
    target_link_libraries(bbc_bench PRIVATE url_whatwg_lib)
    target_link_libraries(wpt_bench PRIVATE url_whatwg_lib)

    target_include_directories(bench PUBLIC "${url_whatwg_SOURCE_DIR}")
    target_include_directories(benchdata PUBLIC "${url_whatwg_SOURCE_DIR}")
    target_include_directories(bbc_bench PUBLIC "${url_whatwg_SOURCE_DIR}")
    target_include_directories(wpt_bench PUBLIC "${url_whatwg_SOURCE_DIR}")

    target_compile_definitions(bench PRIVATE ADA_url_whatwg_ENABLED=1)
    target_compile_definitions(benchdata PRIVATE ADA_url_whatwg_ENABLED=1)
    target_compile_definitions(bbc_bench PRIVATE ADA_url_whatwg_ENABLED=1)
    target_compile_definitions(wpt_bench PRIVATE ADA_url_whatwg_ENABLED=1)

endif(ICU_FOUND)

if(ADA_COMPETITION)
    # URI Parser
    set_off(URIPARSER_BUILD_TESTS)
    set_off(URIPARSER_BUILD_DOCS)
    import_dependency(uriparser uriparser/uriparser 634b678)
    add_dependency(uriparser)
    target_link_libraries(bench PRIVATE uriparser)
    target_link_libraries(bbc_bench PRIVATE uriparser)

    # URL Parser
    import_dependency(urlparser netmindms/urlparser 69c09ed)
    add_library(urlparser STATIC "${urlparser_SOURCE_DIR}/src/EdUrlParser.cpp")
    target_include_directories(urlparser PUBLIC "${urlparser_SOURCE_DIR}/src")
    target_link_libraries(bench PRIVATE urlparser)
    target_link_libraries(bbc_bench PRIVATE urlparser)

    # HTTP Parser
    import_dependency(httpparser nodejs/http-parser v2.9.4)
    add_library(httpparser STATIC "${httpparser_SOURCE_DIR}/http_parser.c")
    set_source_files_properties("${httpparser_SOURCE_DIR}/http_parser.c" PROPERTIES LANGUAGE C)
    target_include_directories(httpparser PUBLIC "${httpparser_SOURCE_DIR}")
    target_link_libraries(bench PRIVATE httpparser)
    target_link_libraries(bbc_bench PRIVATE httpparser)


    target_compile_definitions(bench PRIVATE ADA_VARIOUS_COMPETITION_ENABLED=1)
    target_compile_definitions(bbc_bench PRIVATE ADA_VARIOUS_COMPETITION_ENABLED=1)
endif(ADA_COMPETITION)

# CURL
find_package(CURL)
if(CURL_FOUND)
    message(STATUS "curl version " ${CURL_VERSION_STRING})
    if (CURL_VERSION_STRING VERSION_LESS "7.62.0")
        message(STATUS "curl is too old, we need version 7.62.0 or better")
    else()
        include_directories(${CURL_INCLUDE_DIRS})
        if(NOT CURL_LIBRARIES)
            target_link_libraries(bench PRIVATE CURL::libcurl)
            target_link_libraries(benchdata PRIVATE CURL::libcurl)
            target_link_libraries(bbc_bench PRIVATE CURL::libcurl)
        else()
            target_link_libraries(bench PRIVATE ${CURL_LIBRARIES})
            target_link_libraries(benchdata PRIVATE ${CURL_LIBRARIES})
            target_link_libraries(bbc_bench PRIVATE ${CURL_LIBRARIES})
        endif()
        target_compile_definitions(bench PRIVATE ADA_CURL_ENABLED=1)
        target_compile_definitions(benchdata PRIVATE ADA_CURL_ENABLED=1)
        target_compile_definitions(bbc_bench PRIVATE ADA_CURL_ENABLED=1)
    endif()
else(CURL_FOUND)
    message(STATUS "Curl not found! Please install the curl library.")
endif(CURL_FOUND)

option(ADA_BOOST_URL "Whether to install boost URL." OFF)

message(STATUS "Compiler is " ${CMAKE_CXX_COMPILER_ID})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
message(STATUS "Compiler version " ${CMAKE_CXX_COMPILER_VERSION})

if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
message(STATUS "Compiler is too old, disabling boost url.")
SET(ADA_BOOST_URL OFF CACHE BOOL "Whether to install boost URL." FORCE)
endif()
endif()

# Boost
if(ADA_BOOST_URL)
find_package(
    Boost 1.80
    COMPONENTS system
)
endif(ADA_BOOST_URL)

if(Boost_FOUND)
    import_dependency(boost_url boostorg/url boost-1.81.0)
    add_library(boost_url INTERFACE)
    target_include_directories(boost_url INTERFACE
           "${boost_url_SOURCE_DIR}/include")

    target_link_libraries(bench PRIVATE Boost::system)
    target_link_libraries(bench PRIVATE boost_url)
    target_compile_definitions(bench PRIVATE ADA_BOOST_ENABLED=1)

    target_link_libraries(benchdata PRIVATE Boost::system)
    target_link_libraries(benchdata PRIVATE boost_url)
    target_compile_definitions(benchdata PRIVATE ADA_BOOST_ENABLED=1)

    target_link_libraries(bbc_bench PRIVATE Boost::system)
    target_link_libraries(bbc_bench PRIVATE boost_url)
    target_compile_definitions(bbc_bench PRIVATE ADA_BOOST_ENABLED=1)
else(Boost_FOUND)
if(ADA_BOOST_URL)
    message(STATUS "Boost 1.80 or better was not found, please install it for benchmarking purposes.")
endif(ADA_BOOST_URL)
endif(Boost_FOUND)



# We want the check whether Rust is available before trying to build a crate.
set(Rust_FIND_QUIETLY ON) # No need to alarm the user if rust is not available.
import_dependency(corrosion corrosion-rs/corrosion v0.3.4)
include("${corrosion_SOURCE_DIR}/cmake/FindRust.cmake")


if(RUST_FOUND)
  message(STATUS "Rust found: " ${Rust_VERSION} )
  # Important: we only want to include corrosion *if* rust is available.
  # Otherwise, it is impossible to run ada benchmarks without rust.
  add_dependency(corrosion)
  # Important: we want to build in release mode!
  corrosion_import_crate(MANIFEST_PATH "competitors/servo-url/Cargo.toml" NO_LINKER_OVERRIDE PROFILE release)

  target_link_libraries(bench PRIVATE servo-url)
  target_compile_definitions(bench PRIVATE ADA_RUST_VERSION="${Rust_VERSION}")

  target_link_libraries(benchdata PRIVATE servo-url)
  target_compile_definitions(benchdata PRIVATE ADA_RUST_VERSION="${Rust_VERSION}")

  target_link_libraries(bbc_bench PRIVATE servo-url)
  target_compile_definitions(bbc_bench PRIVATE ADA_RUST_VERSION="${Rust_VERSION}")

  target_link_libraries(percent_encode PRIVATE servo-url)
  target_compile_definitions(percent_encode PRIVATE ADA_RUST_VERSION="${Rust_VERSION}")

  target_link_libraries(wpt_bench PRIVATE servo-url)
  target_compile_definitions(wpt_bench PRIVATE ADA_RUST_VERSION="${Rust_VERSION}")
else()
  message(STATUS "Rust/Cargo is unavailable." )
  message(STATUS "We will not benchmark servo-url." )
  if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    message(STATUS "Under macOS, you may be able to install rust with")
    message(STATUS "curl https://sh.rustup.rs -sSf | sh")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Under Linux, you may be able to install rust with a command such as")
    message(STATUS "apt-get install cargo" )
    message(STATUS "or" )
    message(STATUS "curl https://sh.rustup.rs -sSf | sh")
  endif()
endif()

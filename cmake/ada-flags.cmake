option(ADA_LOGGING "verbose output (useful for debugging)" OFF)
option(ADA_DEVELOPMENT_CHECKS "development checks (useful for debugging)" OFF)
option(ADA_SANITIZE "Sanitize addresses" OFF)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  option(ADA_SANITIZE_BOUNDS_STRICT "Sanitize bounds (strict): only for GCC" OFF)
endif()
option(ADA_SANITIZE_UNDEFINED "Sanitize undefined behaviour" OFF)
if(ADA_SANITIZE)
  message(STATUS "Address sanitizer enabled.")
endif()
if(ADA_SANITIZE_UNDEFINED)
  message(STATUS "Undefined sanitizer enabled.")
endif()
option(ADA_COVERAGE "Compute coverage" OFF)
option(ADA_TOOLS "Build cli tools (adaparse)" ON)

if (ADA_COVERAGE)
    message(STATUS "You want to compute coverage. We assume that you have installed gcovr.")
    if (NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
    endif()
    #######################
    # You need to install gcovr. Under macos, you may do so with brew.
    # brew install gcovr
    # Then build...
    # cmake -D ADA_COVERAGE=ON  -B buildcoverage
    # cmake --build buildcoverage
    # cmake --build buildcoverage --target ada_coverage
    #
    # open buildcoverage/ada_coverage/index.html
    #####################
    include(${PROJECT_SOURCE_DIR}/cmake/codecoverage.cmake)
    APPEND_COVERAGE_COMPILER_FLAGS()
    setup_target_for_coverage_gcovr_html(NAME ada_coverage EXECUTABLE ctest EXCLUDE "${PROJECT_SOURCE_DIR}/dependencies/*" "${PROJECT_SOURCE_DIR}/tools/*"  "${PROJECT_SOURCE_DIR}/singleheader/*" ${PROJECT_SOURCE_DIR}/include/ada/common_defs.h)
endif()

if (NOT CMAKE_BUILD_TYPE)
  if(ADA_SANITIZE OR ADA_SANITIZE_BOUNDS_STRICT OR ADA_SANITIZE_UNDEFINED)
    message(STATUS "No build type selected, default to Debug because you have sanitizers.")
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
  else()
    message(STATUS "No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  endif()
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  message(STATUS "Ccache found using it as compiler launcher.")
  set(CMAKE_C_COMPILER_LAUNCHER ccache)
  set(CMAKE_CXX_COMPILER_LAUNCHER ccache)
endif(CCACHE_FOUND)

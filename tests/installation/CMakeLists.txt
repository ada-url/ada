cmake_minimum_required(VERSION 3.15)

project(test_ada_install VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Let us help macOS users:
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


if(MSVC) # could be WIN32 but there are other systems under Windows.
  target_link_libraries(ada PRIVATE Normaliz)
else()
  find_package(ICU COMPONENTS uc i18n)
  ### If the user does not have ICU, let us help them with instructions:
  if (NOT ICU_FOUND)
    message(SEND_ERROR "ICU with components uc and i18n/in is required for building ada.")
    return()
  endif (NOT ICU_FOUND)
endif()

find_package(ada REQUIRED)


# You can provide your own code, this is just an example:

file(WRITE main.cpp "
#include \"ada.h\"
#include <iostream>

int main(int , char *[]) {
  ada::url url = ada::parse(\"https://www.google.com\");
  url.set_protocol(\"http\");
  std::cout << url.get_protocol() << std::endl;
  std::cout << url.get_host() << std::endl;
  return EXIT_SUCCESS;
}")



add_executable(main main.cpp)
target_link_libraries(main PUBLIC ada::ada)

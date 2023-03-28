cmake_minimum_required(VERSION 3.15)

project(test_ada_install VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(ada REQUIRED)

# You can provide your own code, this is just an example:
file(WRITE main.cpp "
#include \"ada.h\"
#include <iostream>

int main(int , char *[]) {
  ada::result<ada::url_aggregator> url = ada::parse<ada::url_aggregator>(\"https://www.google.com\");
  url->set_protocol(\"http\");
  std::cout << url->get_protocol() << std::endl;
  std::cout << url->get_host() << std::endl;
  return EXIT_SUCCESS;
}")

add_executable(main main.cpp)
target_link_libraries(main PUBLIC ada::ada)

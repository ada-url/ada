#include "ada.cpp"
#include "ada.h"
#include <iostream>

int main(int, char *[]) {
  auto url = ada::parse<ada::url>("https://www.google.com");
  if (!url) {
    std::cout << "failure" << std::endl;
    return EXIT_FAILURE;
  }
  url->set_protocol("http");
  std::cout << url->get_protocol() << std::endl;
  std::cout << url->get_host() << std::endl;
  return EXIT_SUCCESS;
}

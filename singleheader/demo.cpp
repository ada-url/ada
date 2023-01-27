#include "ada.cpp"
#include "ada.h"
#include <iostream>

int main(int , char *[]) {
  ada::url url = ada::parse("https://www.google.com");
  url.set_protocol("http");
  std::cout << url.get_protocol() << std::endl;
  std::cout << url.get_host() << std::endl;
  return EXIT_SUCCESS;
}


#include "ada.cpp"
#include "ada.h"

int main(int , char *[]) {
  ada::url url = ada::parse("https://www.google.com");
  ada::set_scheme(url, "http");
  std::cout << url.get_scheme() << std::endl;
  std::cout << *url.host << std::endl;
  return EXIT_SUCCESS;
}


#include "ada.cpp"
#include "ada.h"

int main(int , char *[]) {
  ada::url url = ada::parse("https://www.google.com");
  ada::set_scheme(url, "http");
  return EXIT_SUCCESS;
}

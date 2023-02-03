#include "ada.h"
#include <cstdlib>
#include <iostream>

std::string long_way(std::string path) {
  ada::url base = ada::parse("file://");
  base.set_pathname(path);
  return base.get_href();
}

void test(std::string path) {
  if (long_way(path) != ada::href_from_file(path)) {
    std::cerr << "bug: " << path << std::endl;
    exit(-1);
  }
}

int main() {
  for (std::string in :
       {"", "fsfds", "C:\\\\blabala\\fdfds\\back.txt", "/home/user/txt.txt",
        "/%2e.bar", "/foo/%2e%2", "/foo/..bar", "foo\t\u0091%91"}) {
    test(in);
  }
  return EXIT_SUCCESS;
}
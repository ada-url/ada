#include "ada.h"
#include <cstdlib>
#include <iostream>
#include "gtest/gtest.h"

std::string long_way(std::string path) {
  ada::result<ada::url> base = ada::parse<ada::url>("file://");
  base->set_pathname(path);
  return base->get_href();
}

TEST(from_file_tests, basics) {
  for (std::string path :
       {"", "fsfds", "C:\\\\blabala\\fdfds\\back.txt", "/home/user/txt.txt",
        "/%2e.bar", "/foo/%2e%2", "/foo/..bar", "foo\t%91"}) {
    ASSERT_TRUE(long_way(path) == ada::href_from_file(path));
  }
}

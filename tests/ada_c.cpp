// gest is a C++ library so we are in C++.
#include "gtest/gtest.h"
extern "C" {
#include "ada_c.h"
}
std::string convert_string(const ada_string& input) {
  printf("result %s \n", std::string(input.data, input.length).c_str());
  return std::string(input.data, input.length);
}


TEST(ada_c, ada_parse) {
  ada_url url = ada_parse(
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists");

  ASSERT_TRUE(ada_is_valid(url));

  ada_free(url);

  SUCCEED();
}

TEST(ada_c, getters) {
  ada_url url = ada_parse(
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists");

  ASSERT_TRUE(ada_is_valid(url));

  // TODO: Fix ada_get_origin returning invalid address.
  //  ASSERT_EQ(convert_string(ada_get_origin(url)),
  //  "https://www.google.com:8080");

  ASSERT_EQ(convert_string(ada_get_href(url)),
            "https://username:password@www.google.com:8080/"
            "pathname?query=true#hash-exists");
  ASSERT_EQ(convert_string(ada_get_username(url)), "username");
  ASSERT_EQ(convert_string(ada_get_password(url)), "password");
  ASSERT_EQ(convert_string(ada_get_port(url)), "8080");
  ASSERT_EQ(convert_string(ada_get_hash(url)), "#hash-exists");
  ASSERT_EQ(convert_string(ada_get_host(url)), "www.google.com:8080");
  ASSERT_EQ(convert_string(ada_get_hostname(url)), "www.google.com");
  ASSERT_EQ(convert_string(ada_get_pathname(url)), "/pathname");
  ASSERT_EQ(convert_string(ada_get_search(url)), "?query=true");
  ASSERT_EQ(convert_string(ada_get_protocol(url)), "https:");

  ada_free(url);

  SUCCEED();
}

TEST(ada_c, setters) {
  ada_url url = ada_parse(
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists");

  ASSERT_TRUE(ada_is_valid(url));

  ada_set_href(url, "https://www.yagiz.co");
  ASSERT_EQ(convert_string(ada_get_href(url)), "https://www.yagiz.co/");

  ada_set_username(url, "new-username");
  ASSERT_EQ(convert_string(ada_get_username(url)), "new-username");

  ada_set_password(url, "new-password");
  ASSERT_EQ(convert_string(ada_get_password(url)), "new-password");

  ada_set_port(url, "4242");
  ASSERT_EQ(convert_string(ada_get_port(url)), "4242");

  ada_set_hash(url, "new-hash");
  ASSERT_EQ(convert_string(ada_get_hash(url)), "#new-hash");

  ada_set_hostname(url, "new-host");
  ASSERT_EQ(convert_string(ada_get_hostname(url)), "new-host");

  ada_set_host(url, "changed-host:9090");
  ASSERT_EQ(convert_string(ada_get_host(url)), "changed-host:9090");

  ada_set_pathname(url, "new-pathname");
  ASSERT_EQ(convert_string(ada_get_pathname(url)), "/new-pathname");

  ada_set_search(url, "new-search");
  ASSERT_EQ(convert_string(ada_get_search(url)), "?new-search");

  ada_set_protocol(url, "wss");
  ASSERT_EQ(convert_string(ada_get_protocol(url)), "wss:");

  ada_free(url);

  SUCCEED();
}
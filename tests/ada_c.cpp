// gest is a C++ library so we are in C++.
#include "gtest/gtest.h"
extern "C" {
#include "ada_c.h"
}

template <typename T>
std::string convert_string(const T& input) {
  printf("result %s \n", std::string(input.data, input.length).c_str());
  return std::string(input.data, input.length);
}

TEST(ada_c, ada_parse) {
  std::string_view input =
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists";
  ada_url url = ada_parse(input.data(), input.length());

  ASSERT_TRUE(ada_is_valid(url));

  ada_free(url);

  SUCCEED();
}

TEST(ada_c, ada_parse_with_base) {
  std::string_view input = "/hello";
  std::string_view base =
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists";
  ada_url url = ada_parse_with_base(input.data(), input.length(), base.data(),
                                    base.length());

  ASSERT_TRUE(ada_is_valid(url));

  ada_free(url);

  SUCCEED();
}

TEST(ada_c, getters) {
  std::string_view input =
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists";
  ada_url url = ada_parse(input.data(), input.length());

  ASSERT_TRUE(ada_is_valid(url));

  ada_owned_string origin = ada_get_origin(url);
  ASSERT_EQ(convert_string(origin), "https://www.google.com:8080");
  ada_free_owned_string(origin);

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
  std::string input =
      "https://username:password@www.google.com:8080/"
      "pathname?query=true#hash-exists";
  ada_url url = ada_parse(input.data(), input.length());

  ASSERT_TRUE(ada_is_valid(url));

  ada_set_href(url, "https://www.yagiz.co", strlen("https://www.yagiz.co"));
  ASSERT_EQ(convert_string(ada_get_href(url)), "https://www.yagiz.co/");

  ada_set_username(url, "new-username", strlen("new-username"));
  ASSERT_EQ(convert_string(ada_get_username(url)), "new-username");

  ada_set_password(url, "new-password", strlen("new-password"));
  ASSERT_EQ(convert_string(ada_get_password(url)), "new-password");

  ada_set_port(url, "4242", 4);
  ASSERT_EQ(convert_string(ada_get_port(url)), "4242");

  ada_set_hash(url, "new-hash", strlen("new-hash"));
  ASSERT_EQ(convert_string(ada_get_hash(url)), "#new-hash");

  ada_set_hostname(url, "new-host", strlen("new-host"));
  ASSERT_EQ(convert_string(ada_get_hostname(url)), "new-host");

  ada_set_host(url, "changed-host:9090", strlen("changed-host:9090"));
  ASSERT_EQ(convert_string(ada_get_host(url)), "changed-host:9090");

  ada_set_pathname(url, "new-pathname", strlen("new-pathname"));
  ASSERT_EQ(convert_string(ada_get_pathname(url)), "/new-pathname");

  ada_set_search(url, "new-search", strlen("new-search"));
  ASSERT_EQ(convert_string(ada_get_search(url)), "?new-search");

  ada_set_protocol(url, "wss", 3);
  ASSERT_EQ(convert_string(ada_get_protocol(url)), "wss:");

  ada_free(url);

  SUCCEED();
}

TEST(ada_c, can_parse) {
  std::string input = "https://www.google.com";
  std::string path = "/hello-world";

  ASSERT_TRUE(ada_can_parse(input.data(), input.length()));
  ASSERT_FALSE(ada_can_parse(path.data(), path.length()));
  ASSERT_TRUE(ada_can_parse_with_base(path.data(), path.length(), input.data(),
                                      input.length()));
}

TEST(ada_c, ada_url_components) {
  std::string input = "https://www.google.com";
  ada_url url = ada_parse(input.data(), input.length());
  const ada_url_components* components = ada_get_components(url);

  ASSERT_EQ(components->protocol_end, 6);
  ASSERT_EQ(components->port, ada_url_omitted);
  ASSERT_EQ(components->search_start, ada_url_omitted);
  ASSERT_EQ(components->hash_start, ada_url_omitted);

  ada_free(url);

  SUCCEED();
}

TEST(ada_c, ada_idna) {
  std::string_view ascii_input = "straße.de";
  std::string_view unicode_input = "xn--strae-oqa.de";
  ada_owned_string ascii =
      ada_idna_to_ascii(ascii_input.data(), ascii_input.length());
  ASSERT_EQ(std::string_view(ascii.data, ascii.length), unicode_input);

  ada_owned_string unicode =
      ada_idna_to_unicode(unicode_input.data(), unicode_input.length());
  ASSERT_EQ(std::string_view(unicode.data, unicode.length), ascii_input);

  ada_free_owned_string(ascii);
  ada_free_owned_string(unicode);
  SUCCEED();
}

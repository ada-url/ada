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
  ada_clear_port(url);
  ASSERT_EQ(convert_string(ada_get_port(url)), "");
  ASSERT_FALSE(ada_has_port(url));

  ada_set_hash(url, "new-hash", strlen("new-hash"));
  ASSERT_EQ(convert_string(ada_get_hash(url)), "#new-hash");
  ada_clear_hash(url);
  ASSERT_FALSE(ada_has_hash(url));

  ada_set_hostname(url, "new-host", strlen("new-host"));
  ASSERT_EQ(convert_string(ada_get_hostname(url)), "new-host");

  ada_set_host(url, "changed-host:9090", strlen("changed-host:9090"));
  ASSERT_EQ(convert_string(ada_get_host(url)), "changed-host:9090");

  ada_set_pathname(url, "new-pathname", strlen("new-pathname"));
  ASSERT_EQ(convert_string(ada_get_pathname(url)), "/new-pathname");

  ada_set_search(url, "new-search", strlen("new-search"));
  ASSERT_EQ(convert_string(ada_get_search(url)), "?new-search");
  ada_clear_search(url);
  ASSERT_EQ(convert_string(ada_get_search(url)), "");

  ada_set_protocol(url, "wss", 3);
  ASSERT_EQ(convert_string(ada_get_protocol(url)), "wss:");

  ASSERT_EQ(ada_get_host_type(url), 0);

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

TEST(ada_c, ada_copy) {
  std::string lemire_blog = "https://lemire.me";
  std::string anonrig_blog = "https://yagiz.co";
  ada_url first = ada_parse(lemire_blog.data(), lemire_blog.length());
  ada_url second = ada_copy(first);

  ASSERT_TRUE(ada_set_href(second, anonrig_blog.data(), anonrig_blog.size()));

  ASSERT_EQ(convert_string(ada_get_href(first)), "https://lemire.me/");
  ASSERT_EQ(convert_string(ada_get_href(second)), "https://yagiz.co/");

  ada_free(first);
  ada_free(second);

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

TEST(ada_c, ada_clear_hash) {
  // Make sure a hash attribute with `#` is removed.
  std::string_view input = "https://www.google.com/hello-world?query=1#";
  ada_url out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));

  ada_clear_hash(out);
  ASSERT_EQ(convert_string(ada_get_hash(out)), "");
  ASSERT_FALSE(ada_has_hash(out));
  ASSERT_EQ(convert_string(ada_get_href(out)),
            "https://www.google.com/hello-world?query=1");

  ada_free(out);
  SUCCEED();
}

TEST(ada_c, ada_clear_search) {
  // Make sure a search attribute with `?` is removed.
  std::string_view input = "https://www.google.com/hello-world?#hash";
  ada_url out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));

  ada_clear_search(out);
  ASSERT_EQ(convert_string(ada_get_search(out)), "");
  ASSERT_FALSE(ada_has_search(out));
  ASSERT_EQ(convert_string(ada_get_href(out)),
            "https://www.google.com/hello-world#hash");

  ada_free(out);
  SUCCEED();
}

TEST(ada_c, ada_get_scheme_type) {
  std::string_view input;
  ada_url out;

  input = "http://www.google.com";
  out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));
  ASSERT_EQ(ada_get_scheme_type(out), 0);

  input = "notspecial://www.google.com";
  ada_free(out);
  out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));
  ASSERT_EQ(ada_get_scheme_type(out), 1);

  input = "https://www.google.com";
  ada_free(out);
  out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));
  ASSERT_EQ(ada_get_scheme_type(out), 2);

  input = "ws://www.google.com/ws";
  ada_free(out);
  out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));
  ASSERT_EQ(ada_get_scheme_type(out), 3);

  input = "ftp://www.google.com/file.txt";
  ada_free(out);
  out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));
  ASSERT_EQ(ada_get_scheme_type(out), 4);

  input = "wss://www.google.com/wss";
  ada_free(out);
  out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));
  ASSERT_EQ(ada_get_scheme_type(out), 5);

  input = "file:///foo/bar";
  ada_free(out);
  out = ada_parse(input.data(), input.size());
  ASSERT_TRUE(ada_is_valid(out));
  ASSERT_EQ(ada_get_scheme_type(out), 6);

  ada_free(out);
  SUCCEED();
}

TEST(ada_c, ada_url_search_params) {
  std::string_view input;
  ada_url_search_params out;

  input = "a=b&c=d&c=e&f=g";
  out = ada_parse_search_params(input.data(), input.size());

  ASSERT_EQ(ada_search_params_size(out), 4);

  std::string key = "key1";
  std::string value = "value1";
  std::string value2 = "value2";
  ada_search_params_append(out, key.c_str(), key.length(), value.c_str(),
                           value.length());
  ASSERT_EQ(ada_search_params_size(out), 5);

  ada_search_params_set(out, key.c_str(), key.length(), value2.c_str(),
                        value2.length());
  ASSERT_EQ(ada_search_params_size(out), 5);

  ASSERT_TRUE(ada_search_params_has(out, key.c_str(), key.length()));
  ASSERT_FALSE(ada_search_params_has_value(out, key.c_str(), key.length(),
                                           value.c_str(), value.length()));
  ASSERT_TRUE(ada_search_params_has_value(out, key.c_str(), key.length(),
                                          value2.c_str(), value2.length()));

  ada_strings result =
      ada_search_params_get_all(out, key.c_str(), key.length());
  ASSERT_EQ(ada_strings_size(result), 1);
  ada_free_strings(result);

  ada_url_search_params_keys_iter keys = ada_search_params_get_keys(out);
  ada_url_search_params_values_iter values = ada_search_params_get_values(out);
  ada_url_search_params_entries_iter entries =
      ada_search_params_get_entries(out);

  ASSERT_TRUE(ada_search_params_keys_iter_has_next(keys));
  ASSERT_TRUE(ada_search_params_values_iter_has_next(values));
  ASSERT_TRUE(ada_search_params_entries_iter_has_next(entries));

  ASSERT_EQ(convert_string(ada_search_params_keys_iter_next(keys)), "a");
  ASSERT_EQ(convert_string(ada_search_params_keys_iter_next(keys)), "c");
  ASSERT_EQ(convert_string(ada_search_params_keys_iter_next(keys)), "c");
  ASSERT_EQ(convert_string(ada_search_params_keys_iter_next(keys)), "f");
  ASSERT_EQ(convert_string(ada_search_params_keys_iter_next(keys)), "key1");
  ASSERT_FALSE(ada_search_params_keys_iter_has_next(keys));

  ASSERT_EQ(convert_string(ada_search_params_values_iter_next(values)), "b");
  ASSERT_EQ(convert_string(ada_search_params_values_iter_next(values)), "d");
  ASSERT_EQ(convert_string(ada_search_params_values_iter_next(values)), "e");
  ASSERT_EQ(convert_string(ada_search_params_values_iter_next(values)), "g");
  ASSERT_EQ(convert_string(ada_search_params_values_iter_next(values)),
            "value2");
  ASSERT_FALSE(ada_search_params_values_iter_has_next(values));

  ada_string_pair pair = ada_search_params_entries_iter_next(entries);
  ASSERT_EQ(convert_string(pair.value), "b");
  ASSERT_EQ(convert_string(pair.key), "a");

  pair = ada_search_params_entries_iter_next(entries);
  ASSERT_EQ(convert_string(pair.value), "d");
  ASSERT_EQ(convert_string(pair.key), "c");

  while (ada_search_params_entries_iter_has_next(entries)) {
    ada_search_params_entries_iter_next(entries);
  }

  ada_search_params_remove(out, key.c_str(), key.length());
  ada_search_params_remove_value(out, key.c_str(), key.length(), value.c_str(),
                                 value.length());

  ada_owned_string str = ada_search_params_to_string(out);
  ASSERT_EQ(convert_string(str), "a=b&c=d&c=e&f=g");

  ada_free_search_params_keys_iter(keys);
  ada_free_search_params_values_iter(values);
  ada_free_search_params_entries_iter(entries);
  ada_free_owned_string(str);
  ada_free_search_params(out);

  SUCCEED();
}

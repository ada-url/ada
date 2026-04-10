// gtest is a C++ library so we are in C++.
#include "gtest/gtest.h"
#include "simdjson.h"
#include <filesystem>
extern "C" {
#include "ada_c.h"
}

#ifndef WPT_DATA_DIR
#define WPT_DATA_DIR "wpt/"
#endif

static const char* URLTESTDATA_JSON = WPT_DATA_DIR "urltestdata.json";
static const char* ADA_URLTESTDATA_JSON =
    WPT_DATA_DIR "ada_extra_urltestdata.json";
static const char* SETTERS_TESTS_JSON = WPT_DATA_DIR "setters_tests.json";
static const char* ADA_SETTERS_TESTS_JSON =
    WPT_DATA_DIR "ada_extra_setters_tests.json";

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
  std::string ascii_input = "stra\u00dfe.de";
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

TEST(ada_c, ada_search_params_reset) {
  ada_url_search_params out;

  std::string_view input = "a=b&c=d&c=e&f=g";
  out = ada_parse_search_params(input.data(), input.size());
  ASSERT_EQ(ada_search_params_size(out), 4);

  std::string_view resetted_value = "a=b";
  ada_search_params_reset(out, resetted_value.data(), resetted_value.size());
  ASSERT_EQ(ada_search_params_size(out), 1);

  ada_free_search_params(out);
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

TEST(ada_c, ada_get_version) {
  std::string_view raw = ada_get_version();
  ada_version_components parsed = ada_get_version_components();

  char buffer[32];
  snprintf(buffer, 32, "%d.%d.%d", parsed.major, parsed.minor, parsed.revision);

  ASSERT_EQ(raw, std::string_view(buffer));

  SUCCEED();
}

TEST(ada_c, urltestdata_encoding) {
  using namespace simdjson;
  for (auto source : {URLTESTDATA_JSON, ADA_URLTESTDATA_JSON}) {
    ondemand::parser parser;
    ASSERT_TRUE(std::filesystem::exists(source)) << "Missing: " << source;
    padded_string json = padded_string::load(source);
    ondemand::document doc = parser.iterate(json);
    try {
      for (auto element : doc.get_array()) {
        if (element.type() == ondemand::json_type::string) {
          continue;
        } else if (element.type() == ondemand::json_type::object) {
          ondemand::object object = element.get_object();
          object.reset();

          std::string_view input{};
          bool allow_replacement_characters = true;
          ASSERT_FALSE(object["input"]
                           .get_string(allow_replacement_characters)
                           .get(input));

          std::string_view base;
          ada_url base_url = nullptr;
          bool has_base = !object["base"].get(base);
          if (has_base) {
            base_url = ada_parse(base.data(), base.size());
            if (!ada_is_valid(base_url)) {
              ada_free(base_url);
              bool failure = false;
              if (!object["failure"].get(failure) && failure == true) {
                continue;
              } else {
                ASSERT_TRUE(false) << "base URL failed to parse: " << base;
              }
            }
          }

          ada_url input_url =
              has_base ? ada_parse_with_base(input.data(), input.size(),
                                             base.data(), base.size())
                       : ada_parse(input.data(), input.size());

          if (has_base) {
            ada_free(base_url);
          }

          bool failure = false;
          if (!object["failure"].get(failure) && failure == true) {
            ASSERT_FALSE(ada_is_valid(input_url));
            ada_free(input_url);
            continue;
          }

          ASSERT_TRUE(ada_is_valid(input_url));

          std::string_view protocol = object["protocol"].get_string();
          ada_string got_protocol = ada_get_protocol(input_url);
          ASSERT_EQ(std::string_view(got_protocol.data, got_protocol.length),
                    protocol);

          std::string_view username = object["username"].get_string();
          ada_string got_username = ada_get_username(input_url);
          ASSERT_EQ(std::string_view(got_username.data, got_username.length),
                    username);

          std::string_view password = object["password"].get_string();
          ada_string got_password = ada_get_password(input_url);
          ASSERT_EQ(std::string_view(got_password.data, got_password.length),
                    password);

          std::string_view host = object["host"].get_string();
          ada_string got_host = ada_get_host(input_url);
          ASSERT_EQ(std::string_view(got_host.data, got_host.length), host);

          std::string_view hostname = object["hostname"].get_string();
          ada_string got_hostname = ada_get_hostname(input_url);
          ASSERT_EQ(std::string_view(got_hostname.data, got_hostname.length),
                    hostname);

          std::string_view port = object["port"].get_string();
          ada_string got_port = ada_get_port(input_url);
          ASSERT_EQ(std::string_view(got_port.data, got_port.length), port);

          std::string_view pathname = object["pathname"].get_string();
          ada_string got_pathname = ada_get_pathname(input_url);
          ASSERT_EQ(std::string_view(got_pathname.data, got_pathname.length),
                    pathname);

          std::string_view search = object["search"].get_string();
          ada_string got_search = ada_get_search(input_url);
          ASSERT_EQ(std::string_view(got_search.data, got_search.length),
                    search);

          std::string_view hash = object["hash"].get_string();
          ada_string got_hash = ada_get_hash(input_url);
          ASSERT_EQ(std::string_view(got_hash.data, got_hash.length), hash);

          std::string_view href = object["href"].get_string();
          ada_string got_href = ada_get_href(input_url);
          ASSERT_EQ(std::string_view(got_href.data, got_href.length), href);

          std::string_view origin;
          if (!object["origin"].get(origin)) {
            ada_owned_string got_origin = ada_get_origin(input_url);
            ASSERT_EQ(std::string_view(got_origin.data, got_origin.length),
                      origin);
            ada_free_owned_string(got_origin);
          }

          ada_free(input_url);
        }
      }
    } catch (simdjson::simdjson_error& error) {
      FAIL() << "JSON error: " << error.what() << " in " << source;
    }
  }
  SUCCEED();
}

TEST(ada_c, setters_tests_encoding) {
  using namespace simdjson;
  for (auto source : {SETTERS_TESTS_JSON, ADA_SETTERS_TESTS_JSON}) {
    ondemand::parser parser;
    ASSERT_TRUE(std::filesystem::exists(source)) << "Missing: " << source;
    padded_string json = padded_string::load(source);
    ondemand::document doc = parser.iterate(json);
    try {
      ondemand::object main_object = doc.get_object();
      for (auto mainfield : main_object) {
        auto category = mainfield.key().value();
        ondemand::array cases = mainfield.value();
        if (category == "comment") {
          continue;
        }
        for (auto element_value : cases) {
          ondemand::object element = element_value;
          element.reset();
          std::string_view new_value = element["new_value"].get_string();
          std::string_view href = element["href"];

          ada_url base = ada_parse(href.data(), href.size());
          ASSERT_TRUE(ada_is_valid(base));

          if (category == "protocol") {
            std::string_view expected = element["expected"]["protocol"];
            ada_set_protocol(base, new_value.data(), new_value.size());
            ada_string got = ada_get_protocol(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          } else if (category == "username") {
            std::string_view expected = element["expected"]["username"];
            ada_set_username(base, new_value.data(), new_value.size());
            ada_string got = ada_get_username(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          } else if (category == "password") {
            std::string_view expected = element["expected"]["password"];
            ada_set_password(base, new_value.data(), new_value.size());
            ada_string got = ada_get_password(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          } else if (category == "host") {
            std::string_view expected;
            if (!element["expected"]["host"].get(expected)) {
              ada_set_host(base, new_value.data(), new_value.size());
              ada_string got = ada_get_host(base);
              ASSERT_EQ(std::string_view(got.data, got.length), expected);
            }
          } else if (category == "hostname") {
            std::string_view expected;
            if (!element["expected"]["hostname"].get(expected)) {
              ada_set_hostname(base, new_value.data(), new_value.size());
              ada_string got = ada_get_hostname(base);
              ASSERT_EQ(std::string_view(got.data, got.length), expected);
            }
          } else if (category == "port") {
            std::string_view expected = element["expected"]["port"];
            ada_set_port(base, new_value.data(), new_value.size());
            ada_string got = ada_get_port(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          } else if (category == "pathname") {
            std::string_view expected = element["expected"]["pathname"];
            ada_set_pathname(base, new_value.data(), new_value.size());
            ada_string got = ada_get_pathname(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          } else if (category == "search") {
            std::string_view expected = element["expected"]["search"];
            ada_set_search(base, new_value.data(), new_value.size());
            ada_string got = ada_get_search(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          } else if (category == "hash") {
            std::string_view expected = element["expected"]["hash"];
            ada_set_hash(base, new_value.data(), new_value.size());
            ada_string got = ada_get_hash(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          } else if (category == "href") {
            std::string_view expected = element["expected"]["href"];
            ada_set_href(base, new_value.data(), new_value.size());
            ada_string got = ada_get_href(base);
            ASSERT_EQ(std::string_view(got.data, got.length), expected);
          }

          ada_free(base);
        }
      }
    } catch (simdjson::simdjson_error& error) {
      FAIL() << "JSON error: " << error.what() << " in " << source;
    }
  }
  SUCCEED();
}

TEST(ada_c, max_input_length) {
  // Save default and set a small limit.
  uint32_t original = ada_get_max_input_length();
  ada_set_max_input_length(512);
  ASSERT_EQ(ada_get_max_input_length(), 512u);

  // Parse a URL that exceeds the limit.
  std::string long_url = "https://example.com/" + std::string(512, 'a');
  ada_url result = ada_parse(long_url.c_str(), long_url.size());
  ASSERT_FALSE(ada_is_valid(result));
  ada_free(result);

  // Parse a URL that fits within the limit.
  const char* short_url = "https://example.com/ok";
  result = ada_parse(short_url, strlen(short_url));
  ASSERT_TRUE(ada_is_valid(result));

  // Setter that would exceed the limit should fail.
  std::string long_path(512, 'x');
  ASSERT_FALSE(ada_set_pathname(result, long_path.c_str(), long_path.size()));

  // URL should be unchanged after failed setter.
  ada_string href = ada_get_href(result);
  ASSERT_EQ(std::string_view(href.data, href.length), "https://example.com/ok");

  ada_free(result);

  // can_parse may return true for overlength inputs that are structurally
  // valid, because the fast path does not check the length limit (by design,
  // for performance). The full parse (ada_parse) does enforce the limit. We
  // just verify it doesn't crash.
  (void)ada_can_parse(long_url.c_str(), long_url.size());

  // Restore default.
  ada_set_max_input_length(original);
  ASSERT_EQ(ada_get_max_input_length(), original);
}

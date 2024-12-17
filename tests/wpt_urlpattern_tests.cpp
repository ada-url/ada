#include <filesystem>
#include <iostream>

#include "gtest/gtest.h"
#include "simdjson.h"

#include "ada.h"
#include "ada/url_pattern.h"
#include "ada/parser.h"

using namespace simdjson;

constexpr std::string_view URL_PATTERN_TEST_DATA =
    "wpt/urlpatterntestdata.json";

// Tests are taken from WPT
// https://github.com/web-platform-tests/wpt/blob/0c1d19546fd4873bb9f4147f0bbf868e7b4f91b7/urlpattern/resources/urlpattern-hasregexpgroups-tests.js
TEST(wpt_urlpattern_tests, has_regexp_groups) {
  auto create_init = [](std::string_view component,
                        std::string value) -> ada::url_pattern_init {
    if (component == "protocol") return {.protocol = value};
    if (component == "username") return {.username = value};
    if (component == "password") return {.password = value};
    if (component == "hostname") return {.hostname = value};
    if (component == "port") return {.port = value};
    if (component == "pathname") return {.pathname = value};
    if (component == "search") return {.search = value};
    if (component == "hash") return {.hash = value};
    ada::unreachable();
  };
  constexpr std::string_view fields[] = {"protocol", "username", "password",
                                         "hostname", "port",     "pathname",
                                         "search",   "hash"};

  for (const auto& field : fields) {
    std::cout << "field " << field << std::endl;

    ASSERT_FALSE(
        ada::parse_url_pattern(create_init(field, "*"))->has_regexp_groups());
    ASSERT_FALSE(ada::parse_url_pattern(create_init(field, ":foo"))
                     ->has_regexp_groups());
    ASSERT_FALSE(ada::parse_url_pattern(create_init(field, ":foo?"))
                     ->has_regexp_groups());
    ASSERT_TRUE(ada::parse_url_pattern(create_init(field, ":foo(hi)"))
                    ->has_regexp_groups());
    ASSERT_TRUE(ada::parse_url_pattern(create_init(field, "(hi)"))
                    ->has_regexp_groups());

    if (field != "protocol" && field != "port") {
      ASSERT_FALSE(
          ada::parse_url_pattern(create_init(field, "a-{:hello}-z-*-a"))
              ->has_regexp_groups());
      ASSERT_FALSE(ada::parse_url_pattern(create_init(field, "a-(hi)-z-(lo)-a"))
                       ->has_regexp_groups());
    }

    ASSERT_FALSE(ada::parse_url_pattern(create_init(field, "/a/:foo/:baz?/b/*"))
                     ->has_regexp_groups());
    ASSERT_FALSE(
        ada::parse_url_pattern(create_init(field, "/a/:foo/:baz([a-z]+)?/b/*"))
            ->has_regexp_groups());
  }

  SUCCEED();
}

ada::url_pattern_init parse_pattern_field(ondemand::array& patterns) {
  ada::url_pattern_init init{};
  size_t pattern_size = patterns.count_elements().value_unsafe();
  EXPECT_TRUE(pattern_size == 1);
  for (auto pattern : patterns) {
    ondemand::object object = pattern.get_object();

    for (auto field : object) {
      object.reset();
      auto key = field.key().value();
      std::string_view value;
      EXPECT_FALSE(field.value().get_string(value));
      if (key == "protocol") {
        init.protocol = std::string(value);
      } else if (key == "username") {
        init.username = std::string(value);
      } else if (key == "password") {
        init.password = std::string(value);
      } else if (key == "hostname") {
        init.hostname = std::string(value);
      } else if (key == "port") {
        init.port = std::string(value);
      } else if (key == "pathname") {
        init.pathname = std::string(value);
      } else if (key == "search") {
        init.search = std::string(value);
      } else if (key == "hash") {
        init.hash = std::string(value);
      }
    }
  }
  return init;
}

TEST(wpt_urlpattern_tests, urlpattern_test_data) {
  ondemand::parser parser;
  ASSERT_TRUE(std::filesystem::exists(URL_PATTERN_TEST_DATA));
  padded_string json = padded_string::load(URL_PATTERN_TEST_DATA);
  ondemand::document doc = parser.iterate(json);
  try {
    for (auto element : doc.get_array()) {
      if (element.type() == ondemand::json_type::string) {
        std::cout << "   comment: " << element.get_string() << std::endl;
        continue;
      }

      ondemand::object main_object = element.get_object();
      // If we have a key with 'expected_obj' and the value is 'error', then
      // we expect the pattern to be invalid. There should be a key with
      // 'pattern' and the value should be an array.
      std::string_view expected_obj;
      if (!main_object["expected_obj"].get_string().get(expected_obj) &&
          expected_obj == "error") {
        ondemand::array patterns;
        if (!main_object["pattern"].get_array().get(patterns)) {
          auto init = parse_pattern_field(patterns);
          std::cout << "patterns: " << patterns.raw_json().value() << std::endl;
          ASSERT_FALSE(ada::parse_url_pattern(init));
        } else {
          std::cerr << "expected_obj does not have an array in pattern"
                    << std::endl;
          FAIL();
        }
      }
    }
  } catch (simdjson_error& error) {
    std::cerr << "JSON error: " << error.what() << " near "
              << doc.current_location() << " in " << URL_PATTERN_TEST_DATA
              << std::endl;
    FAIL();
  }
  SUCCEED();
}

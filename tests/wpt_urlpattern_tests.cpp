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
      ASSERT_TRUE(ada::parse_url_pattern(create_init(field, "a-(hi)-z-(lo)-a"))
                      ->has_regexp_groups());
    }
  }

  ASSERT_FALSE(ada::parse_url_pattern(
                   ada::url_pattern_init{.pathname = "/a/:foo/:baz?/b/*"})
                   ->has_regexp_groups());
  ASSERT_TRUE(
      ada::parse_url_pattern(
          ada::url_pattern_init{.pathname = "/a/:foo/:baz([a-z]+)?/b/*"})
          ->has_regexp_groups());

  SUCCEED();
}

ada::url_pattern_init parse_init(ondemand::object& object) {
  ada::url_pattern_init init{};
  for (auto field : object) {
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
    } else if (key == "baseURL") {
      init.base_url = std::string(value);
    }
  }
  return init;
}

ada::url_pattern_options parse_options(ondemand::object& object) {
  ada::url_pattern_options options{};
  if (object["ignoreCase"]) {
    options.ignore_case = object["ignoreCase"].get_bool().value();
  }
  return options;
}

// URLPattern can accept the following use cases:
// new URLPattern(input)
// new URLPattern(input, baseURL)
// new URLPattern(input, options)
// new URLPattern(input, baseURL, options)
std::tuple<std::variant<std::string, ada::url_pattern_init, bool>,
           std::optional<std::string>, std::optional<ada::url_pattern_options>>
parse_pattern_field(ondemand::array& patterns) {
  std::optional<ada::url_pattern_init> init_obj{};
  std::optional<std::string> init_str{};
  std::optional<std::string> base_url{};
  std::optional<ada::url_pattern_options> options{};
  // In simdjson's On-Demand, we disallow the pattern array size, access element
  // 0, access element 1... as it leads to inefficient code. Instead, we iterate
  // over the array.
  // The following can be used for debugging:
  //  std::cout << "parse_pattern_field" << patterns.raw_json().value()<<
  //  std::endl; patterns.reset(); // <==== Do not forget because raw_json()
  //  consumes the object!!!
  size_t pattern_size = 0;  // how many elements we have consumed.
  patterns.reset();
  for (auto pattern : patterns) {
    if (pattern_size == 0) {
      // Init can be a string or an object.
      if (pattern.type() == ondemand::json_type::string) {
        EXPECT_FALSE(pattern.get_string(init_str));
      } else {
        EXPECT_TRUE(pattern.type() == ondemand::json_type::object);
        ondemand::object object = pattern.get_object();
        init_obj = parse_init(object);
      }
    } else if (pattern_size == 1) {
      // The second value can be a base url or an option.
      if (pattern.type() == ondemand::json_type::string) {
        EXPECT_FALSE(pattern.get_string(base_url));
      } else {
        EXPECT_TRUE(pattern.type() == ondemand::json_type::object);
        ondemand::object object = pattern.get_object();
        options = parse_options(object);
      }
    } else if (pattern_size == 2) {
      // This can only be options now.
      if (pattern.type() == ondemand::json_type::object) {
        EXPECT_FALSE(options.has_value());
        ondemand::object object = pattern.get_object();
        options = parse_options(object);
      } else if (pattern.type() == ondemand::json_type::string) {
        // E.g., [ "/foo?bar#baz", { "ignoreCase": true },
        // "https://example.com:8080" ]
        // This is an invalid pattern. We should not test it.
        // We return false to indicate that should skip the test.
        return std::tuple(false, std::nullopt, std::nullopt);
      }
    }
    pattern_size++;
  }
  EXPECT_TRUE(pattern_size > 0);
  if (init_obj) {
    return std::tuple(*init_obj, base_url, options);
  }
  EXPECT_TRUE(init_str.has_value());
  return std::tuple(*init_str, base_url, options);
}

std::optional<tl::expected<ada::url_pattern, ada::url_pattern_errors>>
parse_pattern(
    std::variant<std::string, ada::url_pattern_init, bool>& init_variant,
    std::optional<std::string>& base_url,
    std::optional<ada::url_pattern_options>& options) {
  std::string_view base_url_view{};

  // This is an invalid test case. We should not test it.
  if (std::holds_alternative<bool>(init_variant)) {
    return std::nullopt;
  }

  if (base_url) {
    base_url_view = {base_url->data(), base_url->size()};
  }

  if (std::holds_alternative<std::string>(init_variant)) {
    auto str_init = std::get<std::string>(init_variant);
    std::cout << "init: " << str_init << std::endl;
    return ada::parse_url_pattern(
        std::string_view(str_init),
        base_url.has_value() ? &base_url_view : nullptr,
        options.has_value() ? &options.value() : nullptr);
  }

  auto obj_init = std::get<ada::url_pattern_init>(init_variant);
  std::cout << "init: " << obj_init.to_string() << std::endl;
  return ada::parse_url_pattern(
      obj_init, base_url.has_value() ? &base_url_view : nullptr,
      options.has_value() ? &options.value() : nullptr);
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

      std::cout << "--------------------" << std::endl;

      ondemand::object main_object = element.get_object();
      // If we have a key with 'expected_obj' and the value is 'error', then
      // we expect the pattern to be invalid. There should be a key with
      // 'pattern' and the value should be an array.
      std::string_view expected_obj;
      ondemand::array patterns;
      ASSERT_FALSE(main_object["pattern"].get_array().get(patterns));
      auto [init_variant, base_url, options] = parse_pattern_field(patterns);
      auto parse_result = parse_pattern(init_variant, base_url, options);

      if (!parse_result) {
        // Skip invalid test cases.
        continue;
      }

      if (!main_object["expected_obj"].get_string().get(expected_obj) &&
          expected_obj == "error") {
        if (parse_result.has_value()) {
          main_object.reset();
          FAIL() << "Test should have failed but it didn't" << std::endl
                 << main_object.raw_json().value() << std::endl;
        }
        continue;
      }

      // Test for valid cases.
      if (!parse_result->has_value()) {
        main_object.reset();
        if (base_url) {
          std::cerr << "base_url: " << base_url.value_or("") << std::endl;
        }
        if (options) {
          std::cerr << "options: " << options->to_string() << std::endl;
        }
        std::cerr << "JSON: " << main_object.raw_json().value() << std::endl;
        FAIL();
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

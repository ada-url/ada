#include <filesystem>
#include <iostream>

#include "ada/log.h"
#include "gtest/gtest.h"
#include "simdjson.h"

#include "ada.h"
#include "ada/url_pattern.h"
#include "ada/parser.h"

using namespace simdjson;

constexpr std::string_view URL_PATTERN_TEST_DATA =
    "wpt/urlpatterntestdata.json";

TEST(wpt_urlpattern_tests, parser_tokenize_basic_tests) {
  auto tokenize_result =
      tokenize("*", ada::url_pattern_helpers::token_policy::STRICT);
  ASSERT_TRUE(tokenize_result);
}

TEST(wpt_urlpattern_tests, parse_pattern_string_basic_tests) {
  auto part_list = ada::url_pattern_helpers::parse_pattern_string(
      "*", ada::url_pattern_compile_component_options::DEFAULT,
      ada::url_pattern_helpers::canonicalize_protocol);

  ASSERT_TRUE(part_list);
}

TEST(wpt_urlpattern_tests, compile_basic_tests) {
  auto protocol_component = ada::url_pattern_component::compile(
      "*", ada::url_pattern_helpers::canonicalize_protocol,
      ada::url_pattern_compile_component_options::DEFAULT);
  ASSERT_TRUE(protocol_component);
}

TEST(wpt_urlpattern_tests, basic_tests) {
  auto init = ada::url_pattern_init{};
  init.pathname = "/books";
  auto url = ada::parse_url_pattern(init);
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_protocol(), "*");
  ASSERT_EQ(url->get_hostname(), "*");
  ASSERT_EQ(url->get_username(), "*");
  ASSERT_EQ(url->get_password(), "*");
  ASSERT_EQ(url->get_port(), "*");
  ASSERT_EQ(url->get_pathname(), "/books");
  ASSERT_EQ(url->get_search(), "*");
  ASSERT_EQ(url->get_hash(), "*");
  ASSERT_FALSE(url->has_regexp_groups());
  SUCCEED();
}

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
  // If no arguments have been passed let's assume it's an empty init.
  if (patterns.count_elements().value() == 0) {
    return {ada::url_pattern_init{}, {}, {}};
  }

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
        // TODO: URLPattern({ ignoreCase: true }) should also work...
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

tl::expected<ada::url_pattern, ada::url_pattern_errors> parse_pattern(
    std::variant<std::string, ada::url_pattern_init, bool>& init_variant,
    std::optional<std::string>& base_url,
    std::optional<ada::url_pattern_options>& options) {
  std::string_view base_url_view{};

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

std::variant<std::string, ada::url_pattern_init> parse_inputs_array(
    ondemand::array& inputs) {
  std::cout << "inputs: " << inputs.raw_json().value() << std::endl;
  inputs.reset();

  for (auto input : inputs) {
    if (input.type() == ondemand::json_type::string) {
      std::string_view value;
      EXPECT_FALSE(input.get_string().get(value));
      return std::string(value);
    }

    ondemand::object attribute;
    EXPECT_FALSE(input.get_object().get(attribute));
    return parse_init(attribute);
  }

  return ada::url_pattern_init{};
}

ada::url_pattern_result parse_url_pattern_result(
    simdjson::ondemand::object& expected_obj) {
  ada::url_pattern_result result;

  for (auto field : expected_obj) {
    auto key = field.key().value();
    std::string_view value;
    EXPECT_FALSE(field.value().get_string(value));

    if (key == "protocol") {
      result.protocol = ada::url_pattern_component_result{std::string(value)};
    } else if (key == "username") {
      result.username = ada::url_pattern_component_result{std::string(value)};
    } else if (key == "password") {
      result.password = ada::url_pattern_component_result{std::string(value)};
    } else if (key == "hostname") {
      result.hostname = ada::url_pattern_component_result{std::string(value)};
    } else if (key == "port") {
      result.port = ada::url_pattern_component_result{std::string(value)};
    } else if (key == "pathname") {
      result.pathname = ada::url_pattern_component_result{std::string(value)};
    } else if (key == "search") {
      result.search = ada::url_pattern_component_result{std::string(value)};
    } else if (key == "hash") {
      result.hash = ada::url_pattern_component_result{std::string(value)};
    } else {
      ADD_FAILURE() << "Unknown key in expected object: " << key;
      return ada::url_pattern_result{};
    }
  }

  return result;
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
      std::string_view expected_obj_str;
      ondemand::array patterns;
      ASSERT_FALSE(main_object["pattern"].get_array().get(patterns));
      auto [init_variant, base_url, options] = parse_pattern_field(patterns);
      // This is an invalid test case. We should not test it.
      if (std::holds_alternative<bool>(init_variant)) {
        // Skip invalid test cases.
        continue;
      }
      auto parse_result = parse_pattern(init_variant, base_url, options);

      if (!main_object["expected_obj"].get_string().get(expected_obj_str) &&
          expected_obj_str == "error") {
        if (parse_result) {
          main_object.reset();
          FAIL() << "Test should have failed but it didn't" << std::endl
                 << main_object.raw_json().value() << std::endl;
        }
        continue;
      }

      // Test for valid cases.
      if (!parse_result) {
        main_object.reset();
        if (base_url) {
          std::cerr << "base_url: " << base_url.value_or("") << std::endl;
        }
        if (options) {
          std::cerr << "options: " << options->to_string() << std::endl;
        }
        FAIL() << "Test should have succeeded but failed" << std::endl
               << main_object.raw_json().value() << std::endl;
      }
      ada_log("parse_result: ", parse_result->to_string());
      ondemand::array exactly_empty_components;
      if (!main_object["exactly_empty_components"].get_array().get(
              exactly_empty_components)) {
        for (auto component : exactly_empty_components) {
          std::string_view key;
          ASSERT_FALSE(component.get_string().get(key));
          if (key == "hash") {
            ASSERT_TRUE(parse_result->get_hash().empty());
          } else if (key == "hostname") {
            ASSERT_TRUE(parse_result->get_hostname().empty());
          } else if (key == "pathname") {
            ASSERT_TRUE(parse_result->get_pathname().empty());
          } else if (key == "search") {
            ASSERT_TRUE(parse_result->get_search().empty());
          } else if (key == "port") {
            ASSERT_TRUE(parse_result->get_port().empty());
          } else if (key == "protocol") {
            ASSERT_TRUE(parse_result->get_protocol().empty());
          } else if (key == "username") {
            ASSERT_TRUE(parse_result->get_username().empty());
          } else if (key == "password") {
            ASSERT_TRUE(parse_result->get_password().empty());
          } else {
            FAIL() << "Unknown key in exactly_empty_components: " << key
                   << std::endl;
          }
        }
      }

      ondemand::object expected_obj;
      if (!main_object["expected_obj"].get_object().get(expected_obj)) {
        for (auto obj_element : expected_obj) {
          auto key = obj_element.key().value();
          std::string_view value;
          ASSERT_FALSE(obj_element.value().get_string().get(value));
          if (key == "hash") {
            ASSERT_EQ(parse_result->get_hash(), value);
          } else if (key == "hostname") {
            ASSERT_EQ(parse_result->get_hostname(), value);
          } else if (key == "password") {
            ASSERT_EQ(parse_result->get_password(), value);
          } else if (key == "pathname") {
            ASSERT_EQ(parse_result->get_pathname(), value);
          } else if (key == "port") {
            ASSERT_EQ(parse_result->get_port(), value);
          } else if (key == "protocol") {
            ASSERT_EQ(parse_result->get_protocol(), value);
          } else if (key == "search") {
            ASSERT_EQ(parse_result->get_search(), value);
          } else if (key == "username") {
            ASSERT_EQ(parse_result->get_username(), value);
          } else {
            FAIL() << "Unknown key in expected object: " << key << std::endl;
          }
        }
      }

      ondemand::array inputs;
      if (!main_object["inputs"].get_array().get(inputs)) {
        // Expected match can be:
        // - "error"
        // - null
        // - {} // response here.
        auto [input_value, base_url] = parse_inputs_array(inputs);
        tl::expected<std::optional<ada::url_pattern_result>, ada::errors>
            result;
        std::string_view base_url_view;
        std::string_view* opt_base_url = nullptr;
        if (base_url) {
          base_url_view = std::string_view(base_url.value());
          opt_base_url = &base_url_view;
        }
        if (std::holds_alternative<std::string>(init_variant)) {
          auto str = std::get<std::string>(init_variant);
          ada_log("init_variant is str=", str);
          result = parse_result->exec(std::string_view(str), opt_base_url);
        } else {
          ada_log("init_variant is url_pattern_init");
          auto obj = std::get<ada::url_pattern_init>(init_variant);
          result = parse_result->exec(obj, opt_base_url);
        }

        ondemand::value expected_match = main_object["expected_match"].value();
        std::cout << "expected_match: " << expected_match.raw_json().value()
                  << std::endl;
        if (expected_match.type() == ondemand::json_type::string) {
          // If it is a string, it will always be "error"
          ASSERT_EQ(expected_match.get_string().value(), "error");
          ASSERT_EQ(result.has_value(), false)
              << "Expected error but exec() has_value= " << result->has_value();
        } else if (expected_match.type() == ondemand::json_type::null) {
          ASSERT_EQ(result.has_value(), true)
              << "Expected non failure but it throws an error";
          ASSERT_EQ(result->has_value(), false)
              << "Expected null value but exec() returned a value ";
        } else {
          ondemand::value expected_match_value;
          auto error = main_object["expected_match"].get(expected_match_value);

          if (!error) {
            if (expected_match_value.type() ==
                simdjson::ondemand::json_type::object) {
              if (expected_match_value.type() ==
                  simdjson::ondemand::json_type::null) {
                std::cout << "Expected match is null." << std::endl;
              } else if (expected_match_value.type() ==
                         simdjson::ondemand::json_type::null) {
                std::cout << "Expected match is null." << std::endl;
              } else if (expected_match_value.type() ==
                         simdjson::ondemand::json_type::object) {
                ondemand::object expected_match_obj;
                ASSERT_FALSE(
                    expected_match_value.get_object().get(expected_match_obj));
                std::cout << "Expected match is an object." << std::endl;

                ada::url_pattern_result result =
                    parse_url_pattern_result(expected_match_obj);

                ASSERT_EQ(result.protocol.input, "expected_protocol");
                ASSERT_EQ(result.hostname.input, "expected_hostname");
                ASSERT_EQ(result.username.input, "expected_username");
                ASSERT_EQ(result.password.input, "expected_password");
                ASSERT_EQ(result.port.input, "expected_port");
                ASSERT_EQ(result.pathname.input, "expected_pathname");
                ASSERT_EQ(result.search.input, "expected_search");
                ASSERT_EQ(result.hash.input, "expected_hash");
              } else {
                FAIL() << "Unexpected type for expected_match.";
              }
            }
          }
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

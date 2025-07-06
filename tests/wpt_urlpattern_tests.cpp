#include <filesystem>
#include <iostream>

#include "ada/log.h"
#include "gtest/gtest.h"
#include "simdjson.h"

#include "ada.h"
#include "ada/url_pattern.h"
#include "ada/parser.h"

using namespace simdjson;
using regex_provider = ada::url_pattern_regex::std_regex_provider;

constexpr std::string_view URL_PATTERN_TEST_DATA =
    "wpt/urlpatterntestdata.json";

// Ref: https://github.com/nodejs/node/issues/57043
TEST(wpt_urlpattern_tests, test_std_out_of_range) {
  std::string_view base = "http://example.com";
  auto u = ada::parse_url_pattern<regex_provider>("/foo", &base);
  ASSERT_TRUE(u);
  auto match = u->exec("?", nullptr);
  ASSERT_TRUE(match);
  SUCCEED();
}

TEST(wpt_urlpattern_tests, test_regex_difference) {
  // {
  //   "pattern": [{ "pathname": "/foo/bar" }],
  //   "inputs": [{ "pathname": "/foo/bar" }],
  //   "expected_match": {
  //     "pathname": { "input": "/foo/bar", "groups": {} }
  //   }
  // }
  auto init = ada::url_pattern_init{};
  init.pathname = "/foo/bar";
  auto u = ada::parse_url_pattern<regex_provider>(init);
  ASSERT_TRUE(u);
  auto match = u->exec(init, nullptr);
  ASSERT_TRUE(match);
  ASSERT_TRUE(match->has_value());

  std::unordered_map<std::string, std::optional<std::string>> empty_object{};

  ASSERT_EQ(match->value().protocol.input, "");
  ASSERT_EQ(match->value().protocol.groups, empty_object);
  ASSERT_EQ(match->value().pathname.input, "/foo/bar");
  ASSERT_EQ(match->value().pathname.groups, empty_object);
  SUCCEED();
}

TEST(wpt_urlpattern_tests, parser_tokenize_basic_tests) {
  auto tokenize_result =
      tokenize("*", ada::url_pattern_helpers::token_policy::strict);
  ASSERT_TRUE(tokenize_result);
}

TEST(wpt_urlpattern_tests, parse_pattern_string_basic_tests) {
  auto part_list = ada::url_pattern_helpers::parse_pattern_string(
      "*", ada::url_pattern_compile_component_options::DEFAULT,
      ada::url_pattern_helpers::canonicalize_protocol);

  ASSERT_TRUE(part_list);
}

TEST(wpt_urlpattern_tests, basic_tests) {
  auto init = ada::url_pattern_init{};
  init.pathname = "/books";
  auto url = ada::parse_url_pattern<regex_provider>(init);
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

    ASSERT_FALSE(ada::parse_url_pattern<regex_provider>(create_init(field, "*"))
                     ->has_regexp_groups());
    ASSERT_FALSE(
        ada::parse_url_pattern<regex_provider>(create_init(field, ":foo"))
            ->has_regexp_groups());
    ASSERT_FALSE(
        ada::parse_url_pattern<regex_provider>(create_init(field, ":foo?"))
            ->has_regexp_groups());
    ASSERT_TRUE(
        ada::parse_url_pattern<regex_provider>(create_init(field, ":foo(hi)"))
            ->has_regexp_groups());
    ASSERT_TRUE(
        ada::parse_url_pattern<regex_provider>(create_init(field, "(hi)"))
            ->has_regexp_groups());

    if (field != "protocol" && field != "port") {
      ASSERT_FALSE(ada::parse_url_pattern<regex_provider>(
                       create_init(field, "a-{:hello}-z-*-a"))
                       ->has_regexp_groups());
      ASSERT_TRUE(ada::parse_url_pattern<regex_provider>(
                      create_init(field, "a-(hi)-z-(lo)-a"))
                      ->has_regexp_groups());
    }
  }

  ASSERT_FALSE(ada::parse_url_pattern<regex_provider>(
                   ada::url_pattern_init{.pathname = "/a/:foo/:baz?/b/*"})
                   ->has_regexp_groups());
  ASSERT_TRUE(
      ada::parse_url_pattern<regex_provider>(
          ada::url_pattern_init{.pathname = "/a/:foo/:baz([a-z]+)?/b/*"})
          ->has_regexp_groups());

  SUCCEED();
}

std::variant<ada::url_pattern_init, ada::url_pattern_options> parse_init(
    ondemand::object& object) {
  ada::url_pattern_init init{};
  for (auto field : object) {
    auto key = field.key().value();
    std::string_view value;
    if (field.value().get_string(value)) {
      bool ignore_case = false;
      EXPECT_FALSE(field.value().get_bool().get(ignore_case));
      return ada::url_pattern_options{.ignore_case = ignore_case};
    }
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
        auto init_result = parse_init(object);
        if (std::holds_alternative<ada::url_pattern_init>(init_result)) {
          init_obj = std::get<ada::url_pattern_init>(init_result);
        } else {
          init_obj = ada::url_pattern_init{};
          options = std::get<ada::url_pattern_options>(init_result);
          return std::tuple(*init_obj, base_url, options);
        }
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

tl::expected<ada::url_pattern<regex_provider>, ada::errors> parse_pattern(
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
    return ada::parse_url_pattern<regex_provider>(
        std::string_view(str_init),
        base_url.has_value() ? &base_url_view : nullptr,
        options.has_value() ? &options.value() : nullptr);
  }

  auto obj_init = std::get<ada::url_pattern_init>(init_variant);
  return ada::parse_url_pattern<regex_provider>(
      obj_init, base_url.has_value() ? &base_url_view : nullptr,
      options.has_value() ? &options.value() : nullptr);
}

std::tuple<std::variant<std::string, ada::url_pattern_init>,
           std::optional<std::string>>
parse_inputs_array(ondemand::array& inputs) {
  std::cout << "inputs: " << inputs.raw_json().value() << std::endl;
  inputs.reset();

  std::variant<std::string, ada::url_pattern_init> first_param =
      ada::url_pattern_init{};
  std::optional<std::string> base_url{};

  size_t index = 0;
  for (auto input : inputs) {
    if (index == 0) {
      if (input.type() == ondemand::json_type::string) {
        std::string_view value;
        EXPECT_FALSE(input.get_string().get(value));
        first_param = std::string(value);
        index++;
        continue;
      }

      ondemand::object attribute;
      EXPECT_FALSE(input.get_object().get(attribute));
      // We always know that this function is called with url pattern init.
      first_param = std::get<ada::url_pattern_init>(parse_init(attribute));
      index++;
      continue;
    }

    std::string_view value;
    EXPECT_FALSE(input.get_string().get(value));
    base_url = std::string(value);
    index++;
  }

  return {first_param, base_url};
}

ada::url_pattern_component_result parse_component_result(
    ondemand::object& component, bool& skip_test) {
  auto result = ada::url_pattern_component_result{};

  for (auto element : component) {
    auto key = element.key().value();

    if (key == "input") {
      // The value will always be string
      std::string_view value;
      EXPECT_FALSE(element.value().get_string().get(value));
      result.input = std::string(value);
    } else if (key == "groups") {
      ondemand::object groups;
      EXPECT_FALSE(element.value().get_object().get(groups));
      for (auto group : groups) {
        auto group_key = group.unescaped_key().value();
        std::string_view group_value;

        // Some values contain "null". We just skip them.
        if (group.value().get_string(group_value)) {
          skip_test = true;
          return result;
        }
        result.groups.insert_or_assign(std::string(group_key), group_value);
      }
    }
  }

  return result;
}

std::tuple<ada::url_pattern_result, bool, bool> parse_exec_result(
    ondemand::object& exec_result) {
  auto result = ada::url_pattern_result{};
  bool has_inputs = false;
  bool skip_test = false;

  for (auto field : exec_result) {
    auto key = field.key().value();

    if (key == "inputs") {
      has_inputs = true;
      // All values will be string or init object.
      ondemand::array inputs;
      EXPECT_FALSE(field.value().get_array().get(inputs));
      for (auto input_field : inputs) {
        if (input_field.type() == ondemand::json_type::string) {
          std::string_view input_field_str;
          EXPECT_FALSE(input_field.get_string().get(input_field_str));
          result.inputs.emplace_back(std::string(input_field_str));
        } else if (input_field.type() == ondemand::json_type::object) {
          ondemand::object input_field_object;
          EXPECT_FALSE(input_field.get_object().get(input_field_object));
          auto parse_value = parse_init(input_field_object);
          EXPECT_TRUE(
              std::holds_alternative<ada::url_pattern_init>(parse_value));
          result.inputs.emplace_back(
              std::get<ada::url_pattern_init>(parse_value));
        } else {
          ADD_FAILURE() << "Unexpected input field type";
        }
      }
    } else {
      ondemand::object component;
      EXPECT_FALSE(field.value().get_object().get(component));
      auto component_result = parse_component_result(component, skip_test);

      if (key == "protocol") {
        result.protocol = component_result;
      } else if (key == "username") {
        result.username = component_result;
      } else if (key == "password") {
        result.password = component_result;
      } else if (key == "hostname") {
        result.hostname = component_result;
      } else if (key == "port") {
        result.port = component_result;
      } else if (key == "pathname") {
        result.pathname = component_result;
      } else if (key == "search") {
        result.search = component_result;
      } else if (key == "hash") {
        result.hash = component_result;
      } else {
        ADD_FAILURE() << "Unexpected key in url_pattern_component_result";
      }
    }
  }

  return {result, has_inputs, skip_test};
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
        FAIL() << "Test should have succeeded but failed" << std::endl
               << main_object.raw_json().value() << std::endl;
      }
      ada_log("parse_result:");
      ada_log("  protocol: '", parse_result->get_protocol(), "'");
      ada_log("  username: '", parse_result->get_username(), "'");
      ada_log("  password: '", parse_result->get_password(), "'");
      ada_log("  hostname: '", parse_result->get_hostname(), "'");
      ada_log("  port: '", parse_result->get_port(), "'");
      ada_log("  pathname: '", parse_result->get_pathname(), "'");
      ada_log("  search: '", parse_result->get_search(), "'");
      ada_log("  hash: '", parse_result->get_hash(), "'");
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
            exec_result;
        tl::expected<bool, ada::errors> test_result;
        std::string_view base_url_view;
        std::string_view* opt_base_url = nullptr;
        if (base_url) {
          base_url_view = std::string_view(base_url.value());
          opt_base_url = &base_url_view;
        }
        if (std::holds_alternative<std::string>(input_value)) {
          auto str = std::get<std::string>(input_value);
          ada_log("input_value is str=", str);
          exec_result = parse_result->exec(str, opt_base_url);
          test_result = parse_result->test(str, opt_base_url);
        } else {
          ada_log("input_value is url_pattern_init");
          auto obj = std::get<ada::url_pattern_init>(input_value);
          exec_result = parse_result->exec(obj, opt_base_url);
          test_result = parse_result->test(obj, opt_base_url);
        }

        ondemand::value expected_match = main_object["expected_match"].value();
        if (expected_match.type() == ondemand::json_type::string) {
          // If it is a string, it will always be "error"
          ASSERT_EQ(expected_match.get_string().value(), "error");
          ASSERT_EQ(exec_result.has_value(), false)
              << "Expected error but exec() has_value= "
              << exec_result->has_value();
          ASSERT_FALSE(test_result)
              << "Expected test() to throw, but it didn't";
        } else if (expected_match.type() == ondemand::json_type::null) {
          ASSERT_EQ(exec_result.has_value(), true)
              << "Expected non failure but it throws an error";
          ASSERT_EQ(exec_result->has_value(), false)
              << "Expected null value but exec() returned a value ";
          ASSERT_FALSE(test_result.value())
              << "Expected false for test() but received true";
        } else {
          ASSERT_EQ(exec_result.has_value(), true)
              << "Expect match to succeed but it throw an error";
          ASSERT_EQ(exec_result->has_value(), true)
              << "Expect match to succeed but it returned a null value";
          ASSERT_TRUE(test_result)
              << "Expected test() to not throw, but it did";
          ASSERT_TRUE(test_result.value())
              << "Expected true for test() but received false";
          auto exec_result_obj = expected_match.get_object().value();
          auto [expected_exec_result, has_inputs, skip_test] =
              parse_exec_result(exec_result_obj);

          if (skip_test) {
            continue;
          }

          // Some match_result data in JSON does not have any inputs output
          if (has_inputs) {
            ASSERT_EQ(exec_result->value().inputs, expected_exec_result.inputs);
          }

          ASSERT_EQ(exec_result->value().protocol,
                    expected_exec_result.protocol);
          ASSERT_EQ(exec_result->value().username,
                    expected_exec_result.username);
          ASSERT_EQ(exec_result->value().password,
                    expected_exec_result.password);
          ASSERT_EQ(exec_result->value().hostname,
                    expected_exec_result.hostname);
          ASSERT_EQ(exec_result->value().port, expected_exec_result.port);
          ASSERT_EQ(exec_result->value().pathname,
                    expected_exec_result.pathname);
          ASSERT_EQ(exec_result->value().search, expected_exec_result.search);
          ASSERT_EQ(exec_result->value().hash, expected_exec_result.hash);
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

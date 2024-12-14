#include <iostream>

#include "gtest/gtest.h"

#include "ada.h"
#include "ada/url_pattern.h"
#include "ada/parser.h"

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

#include <filesystem>
#include <iostream>

 #include "gtest/gtest.h"

 #include "ada.h"

TEST(wpt_urlpattern_tests, parser_tokenize_basic_tests) {
    auto tokenize_result =
       tokenize("*", ada::url_pattern_helpers::token_policy::STRICT);
    ASSERT_TRUE(tokenize_result);
}
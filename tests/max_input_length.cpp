#include "ada.h"
#include "gtest/gtest.h"

#include <limits>
#include <string>

// Use a small limit (1 KB) to test enforcement without huge allocations.
static constexpr uint32_t small_limit = 1024;

using Types = testing::Types<ada::url, ada::url_aggregator>;
template <class T>
struct max_input_length_tests : testing::Test {
  void SetUp() override { ada::set_max_input_length(small_limit); }
  void TearDown() override {
    ada::set_max_input_length(std::numeric_limits<uint32_t>::max());
  }
};
TYPED_TEST_SUITE(max_input_length_tests, Types);

TYPED_TEST(max_input_length_tests, get_set_round_trip) {
  ASSERT_EQ(ada::get_max_input_length(), small_limit);
}

TYPED_TEST(max_input_length_tests, parse_rejects_overlength) {
  std::string long_url = "https://example.com/" + std::string(small_limit, 'a');
  ASSERT_GT(long_url.size(), small_limit);
  auto result = ada::parse<TypeParam>(long_url);
  ASSERT_FALSE(result);
}

TYPED_TEST(max_input_length_tests, parse_accepts_under_limit) {
  std::string ok_url = "https://example.com/ok";
  ASSERT_LE(ok_url.size(), small_limit);
  auto result = ada::parse<TypeParam>(ok_url);
  ASSERT_TRUE(result);
}

TYPED_TEST(max_input_length_tests, set_href_rejects_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string long_url = "https://example.com/" + std::string(small_limit, 'b');
  ASSERT_FALSE(result->set_href(long_url));
}

TYPED_TEST(max_input_length_tests, set_host_rejects_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string long_host(small_limit + 1, 'a');
  ASSERT_FALSE(result->set_host(long_host));
}

TYPED_TEST(max_input_length_tests, set_hostname_rejects_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string long_hostname(small_limit + 1, 'a');
  ASSERT_FALSE(result->set_hostname(long_hostname));
}

TYPED_TEST(max_input_length_tests, set_protocol_rejects_overlength) {
  // Use a non-special URL so the scheme change actually takes effect
  // (special -> non-special scheme changes are rejected as no-ops).
  auto result = ada::parse<TypeParam>("foo://example.com/");
  ASSERT_TRUE(result);
  std::string original_href(result->get_href());
  // A long all-alpha scheme that would result in a URL > 1024 bytes.
  std::string long_protocol(small_limit, 'b');
  ASSERT_FALSE(result->set_protocol(long_protocol));
  ASSERT_EQ(result->get_href(), original_href);
}

TYPED_TEST(max_input_length_tests, set_username_rejects_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string long_username(small_limit + 1, 'u');
  ASSERT_FALSE(result->set_username(long_username));
}

TYPED_TEST(max_input_length_tests, set_password_rejects_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string long_password(small_limit + 1, 'p');
  ASSERT_FALSE(result->set_password(long_password));
}

TYPED_TEST(max_input_length_tests, set_port_rejects_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string long_port(small_limit + 1, '1');
  ASSERT_FALSE(result->set_port(long_port));
}

TYPED_TEST(max_input_length_tests, set_pathname_rejects_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string long_path = "/" + std::string(small_limit + 1, 'x');
  ASSERT_FALSE(result->set_pathname(long_path));
}

TYPED_TEST(max_input_length_tests, set_search_ignores_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string original_search(result->get_search());
  std::string long_search = "?" + std::string(small_limit + 1, 'q');
  result->set_search(long_search);
  // search should remain unchanged
  ASSERT_EQ(result->get_search(), original_search);
}

TYPED_TEST(max_input_length_tests, set_hash_ignores_overlength) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string original_hash(result->get_hash());
  std::string long_hash = "#" + std::string(small_limit + 1, 'h');
  result->set_hash(long_hash);
  // hash should remain unchanged
  ASSERT_EQ(result->get_hash(), original_hash);
}

TYPED_TEST(max_input_length_tests, setters_accept_under_limit) {
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);

  ASSERT_TRUE(result->set_username("user"));
  ASSERT_TRUE(result->set_password("pass"));
  ASSERT_TRUE(result->set_pathname("/path"));
  ASSERT_TRUE(result->set_port("8080"));
  result->set_search("?q=1");
  ASSERT_EQ(result->get_search(), "?q=1");
  result->set_hash("#frag");
  ASSERT_EQ(result->get_hash(), "#frag");
}

TYPED_TEST(max_input_length_tests, percent_encoding_expansion_blocked) {
  // Percent encoding triples the size of each non-ASCII byte (%XX).
  // Use a limit that the base URL fits within, but the encoded result exceeds.
  // "https://example.com/" is 20 bytes. With ~340 bytes of input that each
  // get percent-encoded to 3 bytes, the result would be ~1040 bytes > 1024.
  auto result = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(result);
  std::string original_href(result->get_href());

  // Each space character gets percent-encoded to %20 (3x expansion).
  // 340 spaces -> 1020 bytes of encoded path + 20 bytes base = 1040 > 1024.
  std::string spaces(340, ' ');
  ASSERT_LT(spaces.size(), small_limit);  // input itself is under the limit
  ASSERT_FALSE(result->set_pathname(spaces));
  ASSERT_EQ(result->get_href(), original_href);

  // Also test with username (percent-encoded in userinfo set).
  ASSERT_FALSE(result->set_username(spaces));
  ASSERT_EQ(result->get_href(), original_href);

  // Also test with search (percent-encoded).
  result->set_search(spaces);
  ASSERT_EQ(result->get_href(), original_href);

  // Also test with hash (percent-encoded).
  result->set_hash(spaces);
  ASSERT_EQ(result->get_href(), original_href);
}

TYPED_TEST(max_input_length_tests, url_unchanged_after_rejected_set) {
  auto result =
      ada::parse<TypeParam>("https://user:pass@example.com:8080/path?q=1#frag");
  ASSERT_TRUE(result);
  std::string original_href(result->get_href());

  std::string long_input(small_limit + 1, 'x');
  result->set_hash(long_input);
  result->set_search(long_input);
  ASSERT_FALSE(result->set_host(long_input));
  ASSERT_FALSE(result->set_hostname(long_input));
  ASSERT_FALSE(result->set_pathname(long_input));
  ASSERT_FALSE(result->set_username(long_input));
  ASSERT_FALSE(result->set_password(long_input));
  ASSERT_FALSE(result->set_port(long_input));
  ASSERT_FALSE(result->set_href(long_input));

  // The URL should be completely unchanged.
  ASSERT_EQ(result->get_href(), original_href);
}

TYPED_TEST(max_input_length_tests, parse_normalized_exceeds_limit) {
  // Parsing can produce a normalized URL longer than the input.
  // Spaces in paths are percent-encoded to %20, tripling their size.
  // Build a URL whose input is under the limit but whose normalized form
  // exceeds it.
  //
  // "http://x/" = 9 chars of overhead, + "y" = 1 char trailer.
  // We need the spaces in the middle (not trailing) to avoid stripping.
  // With N spaces: normalized = 10 + 3*N bytes.
  // We need 10 + 3*N > 1024, so N > 338, so N = 339.
  // Input size = 10 + 339 = 349, well under the 1024 limit.
  std::string input = "http://x/" + std::string(339, ' ') + "y";
  ASSERT_LE(input.size(), small_limit);
  auto result = ada::parse<TypeParam>(input);
  // The normalized URL should be 10 + 339*3 = 1027 bytes, exceeding the limit.
  ASSERT_FALSE(result);
}

TYPED_TEST(max_input_length_tests, parse_normalized_just_under_limit) {
  // Same idea but with fewer spaces so we stay under the limit.
  // With 337 spaces: normalized = 10 + 337*3 = 1021, under 1024.
  std::string input = "http://x/" + std::string(337, ' ') + "y";
  ASSERT_LE(input.size(), small_limit);
  auto result = ada::parse<TypeParam>(input);
  ASSERT_TRUE(result);
  ASSERT_LE(result->get_href().size(), small_limit);
}

TYPED_TEST(max_input_length_tests, parse_with_base_normalized_exceeds_limit) {
  // Relative URL resolution can also produce long normalized URLs.
  auto base = ada::parse<TypeParam>("http://x/");
  ASSERT_TRUE(base);
  // Put spaces between path chars so they don't get stripped as C0 whitespace.
  // "a" + 339 spaces + "y" -> "a%20%20...%20y"
  // Result: "http://x/" + "a" + 339*"%20" + "y" = 11 + 1017 = 1028 > 1024
  std::string relative_input = "a" + std::string(339, ' ') + "y";
  ASSERT_LE(relative_input.size(), small_limit);
  auto result = ada::parse<TypeParam>(relative_input, &*base);
  ASSERT_FALSE(result);
}

TYPED_TEST(max_input_length_tests, set_protocol_url_unchanged_after_reject) {
  auto result = ada::parse<TypeParam>("foo://example.com/path");
  ASSERT_TRUE(result);
  std::string original_href(result->get_href());

  std::string long_protocol(small_limit, 'z');
  ASSERT_FALSE(result->set_protocol(long_protocol));
  ASSERT_EQ(result->get_href(), original_href);
}

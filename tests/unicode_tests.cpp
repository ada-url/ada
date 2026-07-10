#include "ada.h"
#include "ada/character_sets.h"
#include "ada/unicode.h"
#include "gtest/gtest.h"

#include <string>

using Types = testing::Types<ada::url, ada::url_aggregator>;
template <class T>
struct unicode_setter_tests : testing::Test {};
TYPED_TEST_SUITE(unicode_setter_tests, Types);

TEST(unicode_tests, percent_encode_index_boundaries) {
  const uint8_t* userinfo = ada::character_sets::USERINFO_PERCENT_ENCODE;
  const uint8_t* query = ada::character_sets::QUERY_PERCENT_ENCODE;

  std::string at_15 = std::string(15, 'a') + "|" + std::string(16, 'b');
  std::string at_16 = std::string(16, 'a') + "|" + std::string(15, 'b');
  std::string at_17 = std::string(17, 'a') + "|" + std::string(14, 'b');
  std::string clean(32, 'a');
  std::string non_ascii = std::string(16, 'a') + std::string(1, char(0xE1));

  EXPECT_EQ(ada::unicode::percent_encode_index(at_15, userinfo), 15u);
  EXPECT_EQ(ada::unicode::percent_encode_index(at_16, userinfo), 16u);
  EXPECT_EQ(ada::unicode::percent_encode_index(at_17, userinfo), 17u);
  EXPECT_EQ(ada::unicode::percent_encode_index(clean, userinfo), clean.size());
  EXPECT_EQ(ada::unicode::percent_encode_index(non_ascii, query), 16u);
}

TEST(unicode_tests, percent_encode_with_index_matches_full_encode) {
  const uint8_t* userinfo = ada::character_sets::USERINFO_PERCENT_ENCODE;
  const uint8_t* query = ada::character_sets::QUERY_PERCENT_ENCODE;

  std::string needs_encoding =
      std::string(16, 'a') + "|" + std::string(16, 'b');
  size_t first_idx =
      ada::unicode::percent_encode_index(needs_encoding, userinfo);

  EXPECT_EQ(first_idx, 16u);
  EXPECT_EQ(ada::unicode::percent_encode(needs_encoding, userinfo),
            ada::unicode::percent_encode(needs_encoding, userinfo, first_idx));

  std::string non_ascii = std::string(16, 'a') + std::string(1, char(0xE1));
  EXPECT_EQ(ada::unicode::percent_encode(non_ascii, query),
            std::string(16, 'a') + "%E1");
}

TEST(unicode_tests, percent_decode_boundaries_and_invalid_sequences) {
  std::string valid =
      std::string(15, 'a') + "%41" + std::string(16, 'b') + "%2F";
  EXPECT_EQ(ada::unicode::percent_decode(valid, valid.find('%')),
            std::string(15, 'a') + "A" + std::string(16, 'b') + "/");

  std::string valid_at_16 = std::string(16, 'a') + "%20" + std::string(15, 'b');
  EXPECT_EQ(ada::unicode::percent_decode(valid_at_16, valid_at_16.find('%')),
            std::string(16, 'a') + " " + std::string(15, 'b'));

  std::string invalid =
      std::string(15, 'a') + "%G1" + std::string(16, 'b') + "%";
  EXPECT_EQ(ada::unicode::percent_decode(invalid, invalid.find('%')), invalid);

  std::string truncated = std::string(16, 'a') + "%4";
  EXPECT_EQ(ada::unicode::percent_decode(truncated, truncated.find('%')),
            truncated);

  EXPECT_EQ(ada::unicode::percent_decode("plain-text", std::string_view::npos),
            "plain-text");
}

TYPED_TEST(unicode_setter_tests, set_search_and_hash_encode_boundary_spaces) {
  auto url = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(url);

  std::string search_input = std::string(15, 'a') + " " + std::string(16, 'b');
  url->set_search(search_input);
  EXPECT_EQ(url->get_search(),
            "?" + std::string(15, 'a') + "%20" + std::string(16, 'b'));

  std::string hash_input = std::string(16, 'c') + " " + std::string(15, 'd');
  url->set_hash(hash_input);
  EXPECT_EQ(url->get_hash(),
            "#" + std::string(16, 'c') + "%20" + std::string(15, 'd'));
}

TYPED_TEST(unicode_setter_tests, set_pathname_encodes_boundary_space) {
  auto url = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(url);

  std::string pathname =
      "/" + std::string(15, 'a') + " " + std::string(16, 'b');
  url->set_pathname(pathname);
  EXPECT_EQ(url->get_pathname(),
            "/" + std::string(15, 'a') + "%20" + std::string(16, 'b'));
}

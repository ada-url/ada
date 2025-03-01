#include "ada.h"
#include "gtest/gtest.h"

#include <deque>
#include <string>
#include <utility>  // For std::pair
#include <vector>

TEST(url_search_params, append) {
  auto search_params = ada::url_search_params();
  search_params.append("key", "value");
  ASSERT_EQ(search_params.size(), 1);
  ASSERT_TRUE(search_params.has("key"));
  search_params.append("key", "value2");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.get_all("key").size(), 2);
  SUCCEED();
}

TEST(url_search_params, to_string) {
  auto search_params = ada::url_search_params();
  search_params.append("key1", "value1");
  search_params.append("key2", "value2");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.to_string(), "key1=value1&key2=value2");
  SUCCEED();
}

TEST(url_search_params, with_accents) {
  auto search_params = ada::url_search_params();
  search_params.append("key1", "\u00E9t\u00E9");
  search_params.append("key2", "C\u00E9line Dion++");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.to_string(),
            "key1=%C3%A9t%C3%A9&key2=C%C3%A9line+Dion%2B%2B");
  ASSERT_EQ(search_params.get("key1"), "\u00E9t\u00E9");
  ASSERT_EQ(search_params.get("key2"), "C\u00E9line Dion++");
  SUCCEED();
}

/**
 * @see
 * https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-stringifier.any.js
 */
TEST(url_search_params, to_string_serialize_space) {
  auto params = ada::url_search_params();
  params.append("a", "b c");
  ASSERT_EQ(params.to_string(), "a=b+c");
  ASSERT_EQ(params.get("a").value(), "b c");
  params.remove("a");
  params.append("a b", "c");
  ASSERT_EQ(params.to_string(), "a+b=c");
  params.remove("a b");
  ASSERT_EQ(params.to_string(), "");
  params.append("a", "");
  ASSERT_EQ(params.to_string(), "a=");
  params.append("", "");
  ASSERT_EQ(params.to_string(), "a=&=");
  params.append("", "b");
  ASSERT_EQ(params.to_string(), "a=&=&=b");
  SUCCEED();
}

TEST(url_search_params, to_string_serialize_plus) {
  auto params = ada::url_search_params();
  params.append("a", "b+c");
  ASSERT_EQ(params.to_string(), "a=b%2Bc");
  params.remove("a");
  params.append("a+b", "c");
  ASSERT_EQ(params.to_string(), "a%2Bb=c");
  SUCCEED();
}

TEST(url_search_params, to_string_serialize_ampersand) {
  auto params = ada::url_search_params();
  params.append("&", "a");
  ASSERT_EQ(params.to_string(), "%26=a");
  params.append("b", "&");
  ASSERT_EQ(params.to_string(), "%26=a&b=%26");
  SUCCEED();
}

TEST(url_search_params, set) {
  auto search_params = ada::url_search_params();
  search_params.append("key1", "value1");
  search_params.append("key1", "value2");
  ASSERT_EQ(search_params.size(), 2);
  search_params.set("key1", "hello");
  ASSERT_EQ(search_params.size(), 1);
  ASSERT_EQ(search_params.to_string(), "key1=hello");

  // reset to initial state
  search_params.remove("key1");
  search_params.append("key1", "value1");
  search_params.append("key1", "value2");
  search_params.append("key2", "value1");
  search_params.set("key1", "value3");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.to_string(), "key1=value3&key2=value1");
  search_params.set("key1", "value4");
  ASSERT_EQ(search_params.to_string(), "key1=value4&key2=value1");

  SUCCEED();
}

TEST(url_search_params, remove) {
  auto search_params = ada::url_search_params();
  search_params.append("key1", "value1");
  search_params.append("key1", "value2");
  search_params.append("key2", "value2");
  search_params.remove("key2");
  ASSERT_EQ(search_params.size(), 2);
  ASSERT_EQ(search_params.to_string(), "key1=value1&key1=value2");
  search_params.remove("key1", "value2");
  ASSERT_EQ(search_params.size(), 1);
  ASSERT_EQ(search_params.to_string(), "key1=value1");
  SUCCEED();
}

TEST(url_search_params, sort) {
  auto search_params = ada::url_search_params();
  search_params.append("bbb", "second");
  search_params.append("aaa", "first");
  search_params.append("ccc", "third");
  ASSERT_EQ(search_params.size(), 3);
  search_params.sort();
  ASSERT_EQ(search_params.to_string(), "aaa=first&bbb=second&ccc=third");
  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-sort.any.js#L3-L4
TEST(url_search_params, sort_repeated_keys) {
  ada::url_search_params search_params("z=b&a=b&z=a&a=a");
  ASSERT_EQ(search_params.size(), 4);
  search_params.sort();

  auto entries = search_params.get_entries();
  auto next = entries.next();
  ASSERT_EQ(next->first, "a");
  ASSERT_EQ(next->second, "b");

  next = entries.next();
  ASSERT_EQ(next->first, "a");
  ASSERT_EQ(next->second, "a");

  next = entries.next();
  ASSERT_EQ(next->first, "z");
  ASSERT_EQ(next->second, "b");

  next = entries.next();
  ASSERT_EQ(next->first, "z");
  ASSERT_EQ(next->second, "a");

  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/b7445afd17303e9443d1da92de9d2b93a9403b0b/url/urlsearchparams-sort.any.js#L7-L8
TEST(url_search_params, sort_unicode_replacement_chars) {
  ada::url_search_params search_params(
      "\xef\xbf\xbd=x&\xef\xbf\xbc&\xef\xbf\xbd=a");
  ASSERT_EQ(search_params.size(), 3);
  search_params.sort();

  auto entries = search_params.get_entries();
  auto next = entries.next();
  ASSERT_EQ(next->first, "\xef\xbf\xbc");
  ASSERT_EQ(next->second, "");

  next = entries.next();
  ASSERT_EQ(next->first, "\xef\xbf\xbd");
  ASSERT_EQ(next->second, "x");

  next = entries.next();
  ASSERT_EQ(next->first, "\xef\xbf\xbd");
  ASSERT_EQ(next->second, "a");

  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/b7445afd17303e9443d1da92de9d2b93a9403b0b/url/urlsearchparams-sort.any.js#L15-L16
TEST(url_search_params, sort_unicode_combining_chars) {
  ada::url_search_params search_params("\xc3\xa9&e\xef\xbf\xbd&e\xcc\x81");
  ASSERT_EQ(search_params.size(), 3);
  search_params.sort();

  auto keys = search_params.get_keys();
  ASSERT_EQ(keys.next(), "e\xcc\x81");
  ASSERT_EQ(keys.next(), "e\xef\xbf\xbd");
  ASSERT_EQ(keys.next(), "\xc3\xa9");

  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/b7445afd17303e9443d1da92de9d2b93a9403b0b/url/urlsearchparams-sort.any.js#L19-L20
TEST(url_search_params, sort_many_params) {
  ada::url_search_params search_params(
      "z=z&a=a&z=y&a=b&z=x&a=c&z=w&a=d&z=v&a=e&z=u&a=f&z=t&a=g");
  ASSERT_EQ(search_params.size(), 14);
  search_params.sort();

  std::deque<std::pair<std::string, std::string>> expected = {
      {"a", "a"}, {"a", "b"}, {"a", "c"}, {"a", "d"}, {"a", "e"},
      {"a", "f"}, {"a", "g"}, {"z", "z"}, {"z", "y"}, {"z", "x"},
      {"z", "w"}, {"z", "v"}, {"z", "u"}, {"z", "t"}};

  for (auto& entry : search_params) {
    auto check = expected.front();
    expected.pop_front();
    ASSERT_EQ(check.first, entry.first);
    ASSERT_EQ(check.second, entry.second);
  }
  ASSERT_EQ(expected.size(), 0);

  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/b7445afd17303e9443d1da92de9d2b93a9403b0b/url/urlsearchparams-sort.any.js#L23-L24
TEST(url_search_params, sort_empty_values) {
  ada::url_search_params search_params("bbb&bb&aaa&aa=x&aa=y");
  ASSERT_EQ(search_params.size(), 5);
  search_params.sort();

  auto entries = search_params.get_entries();
  auto next = entries.next();
  ASSERT_EQ(next->first, "aa");
  ASSERT_EQ(next->second, "x");

  next = entries.next();
  ASSERT_EQ(next->first, "aa");
  ASSERT_EQ(next->second, "y");

  next = entries.next();
  ASSERT_EQ(next->first, "aaa");
  ASSERT_EQ(next->second, "");

  next = entries.next();
  ASSERT_EQ(next->first, "bb");
  ASSERT_EQ(next->second, "");

  next = entries.next();
  ASSERT_EQ(next->first, "bbb");
  ASSERT_EQ(next->second, "");

  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/b7445afd17303e9443d1da92de9d2b93a9403b0b/url/urlsearchparams-sort.any.js#L27-L28
TEST(url_search_params, sort_empty_keys) {
  ada::url_search_params search_params("z=z&=f&=t&=x");
  ASSERT_EQ(search_params.size(), 4);
  search_params.sort();

  auto entries = search_params.get_entries();
  auto next = entries.next();
  ASSERT_EQ(next->first, "");
  ASSERT_EQ(next->second, "f");

  next = entries.next();
  ASSERT_EQ(next->first, "");
  ASSERT_EQ(next->second, "t");

  next = entries.next();
  ASSERT_EQ(next->first, "");
  ASSERT_EQ(next->second, "x");

  next = entries.next();
  ASSERT_EQ(next->first, "z");
  ASSERT_EQ(next->second, "z");

  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/b7445afd17303e9443d1da92de9d2b93a9403b0b/url/urlsearchparams-sort.any.js#L31-L32
TEST(url_search_params, sort_unicode_emoji) {
  ada::url_search_params search_params("a\xf0\x9f\x8c\x88&a\xf0\x9f\x92\xa9");
  ASSERT_EQ(search_params.size(), 2);
  search_params.sort();

  auto keys = search_params.get_keys();
  ASSERT_EQ(keys.next(), "a\xf0\x9f\x8c\x88");
  ASSERT_EQ(keys.next(), "a\xf0\x9f\x92\xa9");

  SUCCEED();
}

TEST(url_search_params, string_constructor) {
  auto p = ada::url_search_params("?a=b");
  ASSERT_EQ(p.to_string(), "a=b");
  SUCCEED();
}

TEST(url_search_params, string_constructor_with_empty_input) {
  auto p = ada::url_search_params("");
  ASSERT_EQ(p.to_string(), "");
  ASSERT_EQ(p.size(), 0);
  SUCCEED();
}

TEST(url_search_params, string_constructor_without_value) {
  auto p = ada::url_search_params("a=b&c");
  ASSERT_EQ(p.to_string(), "a=b&c=");
  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-constructor.any.js
TEST(url_search_params, string_constructor_with_edge_cases) {
  auto p = ada::url_search_params("&a&&& &&&&&a+b=& c&m%c3%b8%c3%b8");
  p.to_string();
  ASSERT_TRUE(p.has("a"));
  ASSERT_TRUE(p.has("a b"));
  ASSERT_TRUE(p.has(" "));
  ASSERT_TRUE(!p.has("c"));
  ASSERT_TRUE(p.has(" c"));
  ASSERT_TRUE(p.has("m\u00f8\u00f8"));
  SUCCEED();
}

TEST(url_search_params, has) {
  auto search_params = ada::url_search_params("key1=value1&key2=value2");
  ASSERT_TRUE(search_params.has("key1"));
  ASSERT_TRUE(search_params.has("key2"));
  ASSERT_TRUE(search_params.has("key1", "value1"));
  ASSERT_TRUE(search_params.has("key2", "value2"));
  ASSERT_TRUE(!search_params.has("key3"));
  ASSERT_TRUE(!search_params.has("key1", "value2"));
  ASSERT_TRUE(!search_params.has("key3", "value3"));
  SUCCEED();
}

TEST(url_search_params, iterators) {
  // JS style iterators
  auto search_params =
      ada::url_search_params("key1=value1&key1=value2&key2=value3");
  auto keys = search_params.get_keys();
  ASSERT_EQ(keys.next(), "key1");
  ASSERT_EQ(keys.next(), "key1");
  ASSERT_EQ(keys.next(), "key2");
  ASSERT_FALSE(keys.next().has_value());

  auto values = search_params.get_values();
  ASSERT_EQ(values.next(), "value1");
  ASSERT_EQ(values.next(), "value2");
  ASSERT_EQ(values.next(), "value3");
  ASSERT_FALSE(keys.next().has_value());

  auto entries = search_params.get_entries();
  auto next = entries.next();
  ASSERT_EQ(next->first, "key1");
  ASSERT_EQ(next->second, "value1");
  next = entries.next();
  ASSERT_EQ(next->first, "key1");
  ASSERT_EQ(next->second, "value2");
  next = entries.next();
  ASSERT_EQ(next->first, "key2");
  ASSERT_EQ(next->second, "value3");
  // At this point we can add a new entry and the iterator will pick it up.
  search_params.append("foo", "bar");
  next = entries.next();
  ASSERT_EQ(next->first, "foo");
  ASSERT_EQ(next->second, "bar");

  ASSERT_FALSE(entries.next().has_value());

  // C++ conventional iterator
  std::vector<std::pair<std::string, std::string>> expected = {
      {"foo", "bar"},
      {"key2", "value3"},
      {"key1", "value2"},
      {"key1", "value1"},
  };
  for (auto& entry : search_params) {
    auto check = expected.back();
    expected.pop_back();
    ASSERT_EQ(check.first, entry.first);
    ASSERT_EQ(check.second, entry.second);
  }
  ASSERT_EQ(expected.size(), 0);

  SUCCEED();
}

// https://github.com/cloudflare/workerd/issues/1777
TEST(url_search_params, test_to_string_encoding) {
  auto search_params =
      ada::url_search_params("q1=foo&q2=foo+bar&q3=foo bar&q4=foo/bar");
  ASSERT_EQ(search_params.get("q1").value(), "foo");
  ASSERT_EQ(search_params.get("q2").value(), "foo bar");
  ASSERT_EQ(search_params.get("q3").value(), "foo bar");
  ASSERT_EQ(search_params.get("q4").value(), "foo/bar");
  ASSERT_EQ(search_params.to_string(),
            "q1=foo&q2=foo+bar&q3=foo+bar&q4=foo%2Fbar");
  SUCCEED();
}

// https://github.com/cloudflare/workerd/issues/1777
TEST(url_search_params, test_character_set) {
  auto search_params = ada::url_search_params("key=value");

  // - The application/x-www-form-urlencoded percent-encode set is the component
  // percent-encode set and U+0021 (!), U+0027 (') to U+0029 RIGHT PARENTHESIS,
  // inclusive, and U+007E (~).
  // - The component percent-encode set is the userinfo percent-encode set and
  // U+0024 ($) to U+0026 (&), inclusive, U+002B (+), and U+002C (,).
  // - The userinfo percent-encode set is the path percent-encode set and U+002F
  // (/), U+003A (:), U+003B (;), U+003D (=), U+0040 (@), U+005B ([) to U+005E
  // (^), inclusive, and U+007C (|).
  std::vector<char> unique_keys = {'/', ':', ';', '=', '@', '[',  ']', '^', '|',
                                   '$', '&', '+', ',', '!', '\'', ')', '~'};
  for (auto& unique_key : unique_keys) {
    auto value = "value" + std::string(1, unique_key);
    search_params.set("key", value);
    // Getting should return the same thing.
    ASSERT_EQ(search_params.get("key").value(), value);
    // Stringified version should be percent encoded.
    ASSERT_NE(search_params.to_string(), "key=" + value);
  }
  SUCCEED();
}

// Taken from
// https://github.com/web-platform-tests/wpt/blob/d5085f61e2d949bc9fb24b04f4c6a47bdf6d3be9/url/urlsearchparams-sort.any.js#L11
TEST(url_search_params, sort_unicode_code_units) {
  ada::url_search_params search_params("\xef\xac\x83&\xf0\x9f\x8c\x88");
  search_params.sort();
  ASSERT_EQ(search_params.size(), 2);
  auto keys = search_params.get_keys();
  ASSERT_EQ(keys.next(), "\xf0\x9f\x8c\x88");
  ASSERT_EQ(keys.next(), "\xef\xac\x83");
  SUCCEED();
}

TEST(url_search_params, sort_unicode_code_units_edge_case) {
  ada::url_search_params search_params(
      "\xf0\x9f\x8c\x88\xef\xac\x83&\xf0\x9f\x8c\x88");
  search_params.sort();
  ASSERT_EQ(search_params.size(), 2);
  auto keys = search_params.get_keys();
  ASSERT_EQ(keys.next(), "\xf0\x9f\x8c\x88");
  ASSERT_EQ(keys.next(), "\xf0\x9f\x8c\x88\xef\xac\x83");
  SUCCEED();
}

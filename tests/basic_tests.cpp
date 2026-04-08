#include "ada.h"
#include "gtest/gtest.h"
#include <cstdlib>
#include <iostream>

using Types = testing::Types<ada::url, ada::url_aggregator>;
template <class T>
struct basic_tests : testing::Test {};
TYPED_TEST_SUITE(basic_tests, Types);

TYPED_TEST(basic_tests, insane_url) {
  auto r = ada::parse<ada::url_aggregator>("e:@EEEEEEEEEE");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->get_protocol(), "e:");
  ASSERT_EQ(r->get_username(), "");
  ASSERT_EQ(r->get_password(), "");
  ASSERT_EQ(r->get_hostname(), "");
  ASSERT_EQ(r->get_port(), "");
  ASSERT_EQ(r->get_pathname(), "@EEEEEEEEEE");
  SUCCEED();
}

TYPED_TEST(basic_tests, bad_percent_encoding) {
  auto r = ada::parse<TypeParam>("http://www.google.com/%X%");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->get_href(), "http://www.google.com/%X%");
  r = ada::parse<TypeParam>("http://www.google%X%.com/");
  ASSERT_FALSE(r);
  r = ada::parse<TypeParam>("http://www.google.com/");
  ASSERT_TRUE(r);
  r->set_href("http://www.google.com/%X%");
  ASSERT_EQ(r->get_href(), "http://www.google.com/%X%");
  ASSERT_FALSE(r->set_host("www.google%X%.com"));
  SUCCEED();
}

TYPED_TEST(basic_tests, spaces_spaces) {
  auto r = ada::parse<TypeParam>("http://www.google.com/%37/ /");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->get_href(), "http://www.google.com/%37/%20/");
  r->set_href("http://www.google.com/  /  /+/");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->get_href(), "http://www.google.com/%20%20/%20%20/+/");
  r = ada::parse<TypeParam>("http://www.google com/");
  ASSERT_FALSE(r);
  SUCCEED();
}

TYPED_TEST(basic_tests, pluses) {
  auto r = ada::parse<TypeParam>("http://www.google.com/%37+/");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->get_href(), "http://www.google.com/%37+/");
  r = ada::parse<TypeParam>("http://www.google+com/");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->get_href(), "http://www.google+com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, set_host_should_return_false_sometimes) {
  auto r = ada::parse<TypeParam>("mailto:a@b.com");
  ASSERT_FALSE(r->set_host("something"));
  auto r2 = ada::parse<TypeParam>("mailto:a@b.com");
  ASSERT_FALSE(r2->set_host("something"));
  SUCCEED();
}

TYPED_TEST(basic_tests, empty_url_should_return_false) {
  auto r = ada::parse<TypeParam>("");
  ASSERT_FALSE(r);
  SUCCEED();
}

TYPED_TEST(basic_tests, set_host_should_return_true_sometimes) {
  auto r = ada::parse<TypeParam>("https://www.google.com");
  ASSERT_TRUE(r->set_host("something"));
  SUCCEED();
}

TYPED_TEST(basic_tests, set_hostname_should_return_false_sometimes) {
  auto r = ada::parse<TypeParam>("mailto:a@b.com");
  ASSERT_FALSE(r->set_hostname("something"));
  SUCCEED();
}

TYPED_TEST(basic_tests, set_hostname_should_return_true_sometimes) {
  auto r = ada::parse<TypeParam>("https://www.google.com");
  ASSERT_TRUE(r->set_hostname("something"));
  SUCCEED();
}

TYPED_TEST(basic_tests, readme) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  ASSERT_TRUE(bool(url));
  SUCCEED();
}

TYPED_TEST(basic_tests, readmefree) {
  auto url = ada::parse("https://www.google.com");
  ASSERT_TRUE(bool(url));
  SUCCEED();
}

TYPED_TEST(basic_tests, readme2) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_username("username");
  url->set_password("password");
  ASSERT_EQ(url->get_href(), "https://username:password@www.google.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme2free) {
  auto url = ada::parse("https://www.google.com");
  url->set_username("username");
  url->set_password("password");
  ASSERT_EQ(url->get_href(), "https://username:password@www.google.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme3) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  ASSERT_EQ(url->set_protocol("wss"), true);
  ASSERT_EQ(url->get_protocol(), "wss:");
  ASSERT_EQ(url->get_href(), "wss://www.google.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme3free) {
  auto url = ada::parse("https://www.google.com");
  ASSERT_EQ(url->set_protocol("wss"), true);
  ASSERT_EQ(url->get_protocol(), "wss:");
  ASSERT_EQ(url->get_href(), "wss://www.google.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, set_protocol_should_return_false_sometimes) {
  auto url = ada::parse<TypeParam>("file:");
  ASSERT_EQ(url->set_protocol("https"), false);
  ASSERT_EQ(url->set_host("google.com"), true);
  ASSERT_EQ(url->get_href(), "file://google.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, set_protocol_should_return_true_sometimes) {
  auto url = ada::parse<TypeParam>("file:");
  ASSERT_EQ(url->set_host("google.com"), true);
  ASSERT_EQ(url->set_protocol("https"), true);
  ASSERT_EQ(url->get_href(), "https://google.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme4) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_host("github.com");
  ASSERT_EQ(url->get_host(), "github.com");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme5) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_port("8080");
  ASSERT_EQ(url->get_port(), "8080");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme6) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_pathname("/my-super-long-path");
  ASSERT_EQ(url->get_pathname(), "/my-super-long-path");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme7) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_search("target=self");
  ASSERT_EQ(url->get_search(), "?target=self");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme8) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_hash("is-this-the-real-life");
  ASSERT_EQ(url->get_hash(), "#is-this-the-real-life");
  SUCCEED();
}

TYPED_TEST(basic_tests, nodejs1) {
  auto base = ada::parse<TypeParam>("http://other.com/");
  ASSERT_TRUE(base.has_value());
  auto url = ada::parse<TypeParam>("http://GOOgoo.com", &base.value());
  ASSERT_TRUE(url.has_value());
  SUCCEED();
}

TYPED_TEST(basic_tests, nodejs2) {
  auto url = ada::parse<TypeParam>("data:space    ?test");
  ASSERT_EQ(url->get_search(), "?test");
  url->set_search("");
  ASSERT_EQ(url->get_search(), "");
  ASSERT_EQ(url->get_pathname(), "space   %20");
  ASSERT_EQ(url->get_href(), "data:space   %20");
  SUCCEED();
}

TYPED_TEST(basic_tests, nodejs3) {
  auto url = ada::parse<TypeParam>("data:space    ?test#test");
  ASSERT_EQ(url->get_search(), "?test");
  url->set_search("");
  ASSERT_EQ(url->get_search(), "");
  ASSERT_EQ(url->get_pathname(), "space   %20");
  ASSERT_EQ(url->get_href(), "data:space   %20#test");
  SUCCEED();
}

// https://github.com/nodejs/node/issues/46755
TYPED_TEST(basic_tests, nodejs4) {
  auto url = ada::parse<TypeParam>("file:///var/log/system.log");
  url->set_href("http://0300.168.0xF0");
  ASSERT_EQ(url->get_protocol(), "http:");
  ASSERT_EQ(url->get_href(), "http://192.168.0.240/");
  SUCCEED();
}

TYPED_TEST(basic_tests, empty_url) {
  auto url = ada::parse<TypeParam>("");
  ASSERT_FALSE(url);
  SUCCEED();
}

TYPED_TEST(basic_tests, just_hash) {
  auto url = ada::parse<TypeParam>("#x");
  ASSERT_FALSE(url);
  SUCCEED();
}

TYPED_TEST(basic_tests, empty_host_dash_dash_path) {
  auto url = ada::parse<TypeParam>("something:/.//");
  ASSERT_TRUE(url);
  ASSERT_FALSE(url->has_opaque_path);
  ASSERT_EQ(url->get_href(), "something:/.//");
  ASSERT_EQ(url->get_pathname(), "//");
  ASSERT_EQ(url->get_hostname(), "");
  SUCCEED();
}

TYPED_TEST(basic_tests, confusing_mess) {
  auto base_url = ada::parse<TypeParam>("http://example.org/foo/bar");
  ASSERT_TRUE(base_url);
  auto url = ada::parse<TypeParam>("http://::@c@d:2", &*base_url);
  ASSERT_TRUE(url);
  ASSERT_FALSE(url->has_opaque_path);
  ASSERT_EQ(url->get_hostname(), "d");
  ASSERT_EQ(url->get_host(), "d:2");
  ASSERT_EQ(url->get_pathname(), "/");
  ASSERT_EQ(url->get_href(), "http://:%3A%40c@d:2/");
  ASSERT_EQ(url->get_origin(), "http://d:2");
  SUCCEED();
}

TYPED_TEST(basic_tests, standard_file) {
  auto url = ada::parse<TypeParam>("file:///tmp/mock/path");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->has_empty_hostname());
  ASSERT_FALSE(url->has_opaque_path);
  ASSERT_EQ(url->get_pathname(), "/tmp/mock/path");
  ASSERT_EQ(url->get_hostname(), "");
  ASSERT_EQ(url->get_host(), "");
  ASSERT_EQ(url->get_href(), "file:///tmp/mock/path");
  SUCCEED();
}

TYPED_TEST(basic_tests, default_port_should_be_removed) {
  auto url = ada::parse<TypeParam>("http://www.google.com:443");
  ASSERT_TRUE(url);
  url->set_protocol("https");
  ASSERT_EQ(url->get_port(), "");
  ASSERT_EQ(url->get_host(), "www.google.com");
  SUCCEED();
}

TYPED_TEST(basic_tests, test_amazon) {
  auto url = ada::parse<TypeParam>("HTTP://AMAZON.COM");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href(), "http://amazon.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, remove_username) {
  auto url = ada::parse<TypeParam>("http://me@example.net");
  ASSERT_TRUE(url);
  url->set_username("");
  ASSERT_EQ(url->get_username(), "");
  ASSERT_EQ(url->get_href(), "http://example.net/");
  SUCCEED();
}

TYPED_TEST(basic_tests, remove_password) {
  auto url = ada::parse<TypeParam>("http://user:pass@example.net");
  ASSERT_TRUE(url);
  url->set_password("");
  ASSERT_EQ(url->get_password(), "");
  ASSERT_EQ(url->get_href(), "http://user@example.net/");
  SUCCEED();
}

TYPED_TEST(basic_tests, remove_password_with_empty_username) {
  auto url = ada::parse<TypeParam>("http://:pass@example.net");
  ASSERT_TRUE(url);
  url->set_password("");
  ASSERT_EQ(url->get_username(), "");
  ASSERT_EQ(url->get_password(), "");
  ASSERT_EQ(url->get_href(), "http://example.net/");
  SUCCEED();
}

TYPED_TEST(basic_tests, should_remove_dash_dot) {
  auto url = ada::parse<TypeParam>("non-spec:/.//p");
  ASSERT_TRUE(url);
  ASSERT_FALSE(url->has_empty_hostname());
  ASSERT_FALSE(url->has_hostname());
  url->set_hostname("h");
  ASSERT_TRUE(url->has_hostname());
  ASSERT_FALSE(url->has_empty_hostname());
  ASSERT_EQ(url->get_pathname(), "//p");
  ASSERT_EQ(url->get_href(), "non-spec://h//p");
  SUCCEED();
}

TYPED_TEST(basic_tests, should_remove_dash_dot_with_empty_hostname) {
  auto url = ada::parse<TypeParam>("non-spec:/.//p");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_pathname(), "//p");
  ASSERT_FALSE(url->has_empty_hostname());
  ASSERT_FALSE(url->has_hostname());
  url->set_hostname("");
  ASSERT_TRUE(url->has_hostname());
  ASSERT_TRUE(url->has_empty_hostname());
  ASSERT_EQ(url->get_pathname(), "//p");
  ASSERT_EQ(url->get_href(), "non-spec:////p");
  SUCCEED();
}

TYPED_TEST(basic_tests, should_add_dash_dot_on_pathname) {
  auto url = ada::parse<TypeParam>("non-spec:/");
  ASSERT_TRUE(url);
  url->set_pathname("//p");
  ASSERT_EQ(url->get_pathname(), "//p");
  ASSERT_EQ(url->get_href(), "non-spec:/.//p");
  SUCCEED();
}

TYPED_TEST(basic_tests, should_update_password_correctly) {
  auto url = ada::parse<TypeParam>(
      "https://username:password@host:8000/path?query#fragment");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->set_password("test"));
  ASSERT_EQ(url->get_password(), "test");
  ASSERT_EQ(url->get_href(),
            "https://username:test@host:8000/path?query#fragment");
  SUCCEED();
}

// https://github.com/nodejs/node/issues/47889
TYPED_TEST(basic_tests, node_issue_47889) {
  auto urlbase = ada::parse<TypeParam>("a:b");
  ASSERT_EQ(urlbase->get_href(), "a:b");
  ASSERT_EQ(urlbase->get_protocol(), "a:");
  ASSERT_EQ(urlbase->get_pathname(), "b");
  ASSERT_TRUE(urlbase->has_opaque_path);
  ASSERT_TRUE(urlbase);
  auto expected_url = ada::parse<TypeParam>("a:b#");
  ASSERT_TRUE(expected_url);
  ASSERT_TRUE(expected_url->has_opaque_path);
  ASSERT_EQ(expected_url->get_href(), "a:b#");
  ASSERT_EQ(expected_url->get_pathname(), "b");
  auto url = ada::parse<TypeParam>("..#", &*urlbase);
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->has_opaque_path);
  ASSERT_EQ(url->get_href(), "a:b/#");
  ASSERT_EQ(url->get_pathname(), "b/");
  SUCCEED();
}

TEST(basic_tests, can_parse) {
  ASSERT_TRUE(ada::can_parse("https://www.yagiz.co"));
  std::string_view base = "https://yagiz.co";
  ASSERT_TRUE(ada::can_parse("/hello", &base));

  std::string_view invalid_base = "!!!!!!!1";
  ASSERT_FALSE(ada::can_parse("/hello", &invalid_base));
  ASSERT_FALSE(ada::can_parse("!!!"));
  SUCCEED();
}

// Helper: assert can_parse == parse.has_value() for both url and
// url_aggregator, and that the href round-trips cleanly if parsing succeeds.
static void assert_can_parse_consistent(const std::string& input) {
  bool cp = ada::can_parse(input);

  auto agg = ada::parse<ada::url_aggregator>(input);
  ASSERT_EQ(cp, agg.has_value())
      << "can_parse/parse<url_aggregator> mismatch for: " << input;

  auto url = ada::parse<ada::url>(input);
  ASSERT_EQ(cp, url.has_value())
      << "can_parse/parse<url> mismatch for: " << input;

  if (agg) {
    std::string href{agg->get_href()};
    ASSERT_TRUE(ada::can_parse(href)) << "can_parse rejected normalised href '"
                                      << href << "' derived from: " << input;
    auto reparsed = ada::parse<ada::url_aggregator>(href);
    ASSERT_TRUE(reparsed.has_value())
        << "re-parse of href '" << href << "' failed";
    ASSERT_EQ(std::string(reparsed->get_href()), href)
        << "href idempotency failure for: " << input;
  }
}

// Regression: extra slashes after "://" are consumed by
// SPECIAL_AUTHORITY_IGNORE_SLASHES in the full parser, but
// try_can_parse_absolute_fast stopped at the first extra '/' after "//",
// making the host appear empty and returning false when the full parse
// succeeds. OSS-Fuzz crashes: address-202603300607, msan-202603300607,
//                   ubsan-202603300607.
TEST(basic_tests, can_parse_consistency_extra_slashes) {
  for (const auto& input : std::vector<std::string>{
           "ws://////////00s:",  // address-sanitizer crash
           std::string("ws:///\xe3\x88\x8c\xe3\x88\x88"),  // msan crash
           "ws://////5///\\Ws:",                           // ubsan crash
           "ws:///host",
           "http:////example.com",
           "wss:///host/path",
       }) {
    assert_can_parse_consistent(input);
  }
}

// Regression: '%' in the authority triggered the forbidden-domain-code-point
// check in try_can_parse_absolute_fast and returned false, but the full parser
// calls to_ascii which percent-decodes the host first (e.g. %2E -> '.') and may
// accept it.  Fix: return nullopt for '%' so the full parser always decides.
// OSS-Fuzz crashes: address-202603300607, ubsan-202603300607.
TEST(basic_tests, can_parse_consistency_percent_encoded_host) {
  for (const auto& input : std::vector<std::string>{
           "Ws://%2E",               // exact OSS-Fuzz ubsan crash input
           "ws://%2E",               // lowercase variant
           "http://%2E/",            // http scheme
           "http://1%2E2%2E3%2E4/",  // percent-encoded IPv4 dots
           "ws://host%2Eexample/",   // percent-encoded dot in domain
           "ws://%00/",              // %00 -> forbidden after decode
           "ws://%2F/",              // %2F -> '/' -> forbidden after decode
       }) {
    assert_can_parse_consistent(input);
  }
}

// Regression: try_can_parse_absolute_fast returned true for a valid IPv4 host
// without validating the port. For "wS://1.3.3.51.:+" the host "1.3.3.51."
// passes the IPv4 fast path, but the port "+" is not a valid digit, so the
// full parser correctly returns failure.  Fix: fall through to port validation
// even when the IPv4 host check succeeds.
// OSS-Fuzz crash: ubsan-202603300607.
TEST(basic_tests, can_parse_consistency_ipv4_invalid_port) {
  for (const auto& input : std::vector<std::string>{
           "wS://1.3.3.51.:+",             // exact OSS-Fuzz ubsan crash
           "ws://1.2.3.4:+",               // simpler variant
           "ws://1.2.3.4:abc",             // letters in port
           "ws://0.0.0.0:!",               // punctuation in port
           "ws://255.255.255.255:65536a",  // overflow + trailing char
       }) {
    assert_can_parse_consistent(input);
  }
}

// Regression: the pl>5 port-length guard in try_can_parse_absolute_fast did
// not account for leading zeros.  Ports like "0000000000000" (= 0) and
// "000000000" (= 0) are valid per WHATWG but have more than 5 characters,
// so the fast path returned false while the full parser returned true.
// OSS-Fuzz crashes: msan-202603300607, ubsan-202603300607.
// Also covers the complex "many colons" crash (address-202603300607).
TEST(basic_tests, can_parse_consistency_port_leading_zeros) {
  for (const auto& input : std::vector<std::string>{
           // exact msan crash:
           "ws://000000000S:0000000000000\\SS:",
           // exact ubsan crash:
           "ws://L:000000000\\\x14\x44"
           "\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x97"
           "\x8c\x8c\x8c\x8c\x8c\x8c\x8c\x8c"
           "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
           "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
           "ddddddddddddddddddddddddddddddddddddddd:",
           // simpler leading-zero coverage:
           "ws://host:0000001/",
           "ws://host:0000000000000/",
           "ws://host:065535/",
           "ws://host:065536/",
       }) {
    assert_can_parse_consistent(input);
  }
}

// Regression test: can_parse must agree with parse<url_aggregator> for all
// inputs, including special-scheme URLs without "//". The href round-trip
// must also be accepted by can_parse.
TEST(basic_tests, can_parse_consistency) {
  const std::vector<std::string> inputs = {
      "ws:.",   "wss:.",  "http:.",  "https:.",
      "ws:/./", "ws://.", "ws://./", "ws:./",
  };
  for (const auto& input : inputs) {
    bool cp = ada::can_parse(input);
    auto agg = ada::parse<ada::url_aggregator>(input);
    ASSERT_EQ(cp, agg.has_value())
        << "can_parse/parse<url_aggregator> mismatch for: " << input;

    auto url = ada::parse<ada::url>(input);
    ASSERT_EQ(cp, url.has_value())
        << "can_parse/parse<url> mismatch for: " << input;

    // If the URL parsed successfully, its href must also be can_parse-able.
    if (agg) {
      std::string href{agg->get_href()};
      ASSERT_TRUE(ada::can_parse(href))
          << "can_parse rejected normalised href '" << href
          << "' derived from input: " << input;
    }
  }
}

// Regression: can_parse("", &"W:") returned true while
// parse<url_aggregator>("", base) returned false. The OPAQUE_PATH
// early-return optimization did not set has_opaque_path = true before
// returning, so when "" was resolved against base "W:" in NO_SCHEME,
// the opaque-path check incorrectly passed.
// OSS-Fuzz crashes: memory-202603310657
TEST(basic_tests, can_parse_consistency_opaque_path) {
  std::string_view base = "W:";
  bool cp = ada::can_parse("", &base);
  auto base_url = ada::parse<ada::url_aggregator>("W:");
  ASSERT_TRUE(base_url.has_value());
  auto agg = ada::parse<ada::url_aggregator>("", &*base_url);
  ASSERT_EQ(cp, agg.has_value())
      << "can_parse/parse<url_aggregator> mismatch for input='' base='W:'";
}

// Regression: can_parse disagreed with parse<url_aggregator> for ws:// URLs
// containing spaces, non-ASCII bytes, and special characters in the authority.
// OSS-Fuzz crash: memory-202604020601.
TEST(basic_tests, can_parse_consistency_special_chars_in_authority) {
  for (const auto& input : std::vector<std::string>{
           "ws:// @@@@@@@@@@@@@@@@@@@@@@@@:@@@@\xf5@@@@@@@@@@@@5",
       }) {
    assert_can_parse_consistent(input);
  }
}

TYPED_TEST(basic_tests, node_issue_48254) {
  auto base_url = ada::parse<TypeParam>("localhost:80");
  ASSERT_TRUE(base_url);
  ASSERT_EQ(base_url->get_hostname(), "");
  ASSERT_EQ(base_url->get_host(), "");
  ASSERT_EQ(base_url->get_pathname(), "80");
  ASSERT_EQ(base_url->get_href(), "localhost:80");
  ASSERT_EQ(base_url->get_origin(), "null");
  ASSERT_EQ(base_url->has_opaque_path, true);
  auto url = ada::parse<TypeParam>("", &*base_url);
  ASSERT_FALSE(url);
  SUCCEED();
}

TYPED_TEST(basic_tests, url_host_type) {
  ASSERT_EQ(ada::parse<TypeParam>("http://localhost:3000")->host_type,
            ada::url_host_type::DEFAULT);
  ASSERT_EQ(ada::parse<TypeParam>("http://0.0.0.0")->host_type,
            ada::url_host_type::IPV4);
  ASSERT_EQ(
      ada::parse<TypeParam>("http://[2001:db8:3333:4444:5555:6666:7777:8888]")
          ->host_type,
      ada::url_host_type::IPV6);
  SUCCEED();
}

// https://github.com/nodejs/node/issues/49650
TYPED_TEST(basic_tests, nodejs_49650) {
  auto out = ada::parse<TypeParam>("http://foo");
  ASSERT_TRUE(out);
  ASSERT_FALSE(out->set_host("::"));
  ASSERT_EQ(out->get_href(), "http://foo/");
  SUCCEED();
}

// https://github.com/nodejs/node/issues/50235
TYPED_TEST(basic_tests, nodejs_50235) {
  auto out = ada::parse<TypeParam>("http://test.com:5/?param=1");
  ASSERT_TRUE(out);
  ASSERT_TRUE(out->set_pathname("path"));
  ASSERT_EQ(out->get_href(), "http://test.com:5/path?param=1");
  SUCCEED();
}

// https://github.com/nodejs/node/issues/51514
TYPED_TEST(basic_tests, nodejs_51514) {
  auto out = ada::parse<TypeParam>("http://1.1.1.256");
  ASSERT_FALSE(out);
}

// https://github.com/nodejs/node/issues/51593
TYPED_TEST(basic_tests, nodejs_51593) {
  auto out = ada::parse<TypeParam>("http://\u200b123.123.123.123");
  ASSERT_TRUE(out);
  ASSERT_EQ(out->get_href(), "http://123.123.123.123/");
  SUCCEED();
}

// https://github.com/nodejs/node/issues/51619
TYPED_TEST(basic_tests, nodejs_51619) {
  auto out = ada::parse<TypeParam>("https://0.0.0.0x100/");
  ASSERT_FALSE(out);
  SUCCEED();
}

// https://github.com/nodejs/undici/pull/2971
TYPED_TEST(basic_tests, nodejs_undici_2971) {
  std::string_view base =
      "https://non-ascii-location-header.sys.workers.dev/redirect";
  auto base_url = ada::parse<TypeParam>(base);
  ASSERT_TRUE(base_url);
  auto out = ada::parse<TypeParam>("/\xec\x95\x88\xeb\x85\x95", &*base_url);
  ASSERT_TRUE(out);
  ASSERT_EQ(
      out->get_href(),
      R"(https://non-ascii-location-header.sys.workers.dev/%EC%95%88%EB%85%95)");
  SUCCEED();
}

TYPED_TEST(basic_tests, path_setter_bug) {
  std::string_view base = "blob:/?";
  auto base_url = ada::parse<ada::url_aggregator>(base);
  ASSERT_TRUE(base_url);
  ASSERT_TRUE(base_url->validate());
  ASSERT_TRUE(base_url->set_pathname("//.."));
  ASSERT_TRUE(base_url->validate());
  SUCCEED();
}

TYPED_TEST(basic_tests, negativeport) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  ASSERT_FALSE(url->set_port("-1"));
  SUCCEED();
}

// https://github.com/ada-url/ada/issues/826
TYPED_TEST(basic_tests, set_invalid_port) {
  auto url = ada::parse<TypeParam>("fake://dummy.test");
  ASSERT_TRUE(url);
  ASSERT_FALSE(url->set_port("invalid80"));
  ASSERT_EQ(url->get_port(), "");
  ASSERT_TRUE(url->set_port("80valid"));
  ASSERT_TRUE(url->is_valid);
  ASSERT_EQ(url->get_port(), "80");
  ASSERT_TRUE(url->is_valid);
  SUCCEED();
}

TYPED_TEST(basic_tests, test_possible_asan) {
  auto url = ada::parse<TypeParam>("file:///");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_protocol(), "file:");
  SUCCEED();
}

TYPED_TEST(basic_tests, test_issue_935) {
  auto url = ada::parse<TypeParam>("file:///foo/.bar/../baz.js");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_pathname(), "/foo/baz.js");

  // this should go into the fast path also
  auto no_dot = ada::parse<TypeParam>("file:///foo/bar/baz.js");
  ASSERT_EQ(no_dot->get_pathname(), "/foo/bar/baz.js");
  SUCCEED();
}

TYPED_TEST(basic_tests, test_issue_970) {
  auto url = ada::parse<TypeParam>("http://foo/bar^baz");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_pathname(), "/bar%5Ebaz");
  SUCCEED();
}

// Ref: https://github.com/cloudflare/workerd/issues/5144
TYPED_TEST(basic_tests, test_workerd_issue_5144_1) {
  auto url = ada::parse<TypeParam>("https://example.sub.com/??");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_search(), "??");
  ASSERT_EQ(url->get_href(), "https://example.sub.com/??");

  SUCCEED();
}

// Ref: https://github.com/cloudflare/workerd/issues/5144
TYPED_TEST(basic_tests, test_workerd_issue_5144_2) {
  auto url = ada::parse<TypeParam>("https://example.sub.com/???");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_search(), "???");
  ASSERT_EQ(url->get_href(), "https://example.sub.com/???");
  SUCCEED();
}

// Ref: https://github.com/cloudflare/workerd/issues/5144
TYPED_TEST(basic_tests, test_workerd_issue_5144_3) {
  auto url = ada::parse<TypeParam>("https://example.sub.com/????");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_search(), "????");
  ASSERT_EQ(url->get_href(), "https://example.sub.com/????");
  SUCCEED();
}

// Ref: https://github.com/cloudflare/workerd/issues/5144
TYPED_TEST(basic_tests, test_workerd_issue_5144_4) {
  using regex_provider = ada::url_pattern_regex::std_regex_provider;
  auto init = ada::url_pattern_init{};
  init.hostname = ":subdomain.:domain.:tld";
  auto pattern = ada::parse_url_pattern<regex_provider>(init);
  ASSERT_TRUE(pattern);
  ASSERT_TRUE(pattern->match("https://example.com"));
  ASSERT_TRUE(pattern->match("https://example.com/?"));
  ASSERT_TRUE(pattern->match("https://example.com/??"));

  auto dummy_init = ada::url_pattern_init{};
  dummy_init.search = "???";
  ASSERT_TRUE(pattern->exec(std::move(dummy_init)));
  SUCCEED();
}

// https://github.com/ada-url/ada/issues/1076
// Setting pathname to a "//" path on a non-special URL without authority but
// with a query or hash component should not trigger a validate() assertion
// failure caused by stale search_start/hash_start offsets after "/." insertion.
TEST(basic_tests, issue_1076_set_pathname_dashdot_with_query) {
  // Non-special URL with a query: no authority, has search component
  auto url = ada::parse<ada::url_aggregator>("foo:/?q");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->validate());
  ASSERT_TRUE(url->set_pathname("//bar"));
  ASSERT_TRUE(url->validate());
  ASSERT_EQ(url->get_pathname(), "//bar");
  ASSERT_EQ(url->get_search(), "?q");
  SUCCEED();
}

TEST(basic_tests, issue_1076_set_pathname_dashdot_with_hash) {
  // Non-special URL with a hash: no authority, has hash component
  auto url = ada::parse<ada::url_aggregator>("foo:/#h");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->validate());
  ASSERT_TRUE(url->set_pathname("//bar"));
  ASSERT_TRUE(url->validate());
  ASSERT_EQ(url->get_pathname(), "//bar");
  ASSERT_EQ(url->get_hash(), "#h");
  SUCCEED();
}

TEST(basic_tests, issue_1076_set_pathname_dashdot_with_query_and_hash) {
  // Non-special URL with both query and hash
  auto url = ada::parse<ada::url_aggregator>("foo:/?q#h");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->validate());
  ASSERT_TRUE(url->set_pathname("//bar"));
  ASSERT_TRUE(url->validate());
  ASSERT_EQ(url->get_pathname(), "//bar");
  ASSERT_EQ(url->get_search(), "?q");
  ASSERT_EQ(url->get_hash(), "#h");
  SUCCEED();
}

TEST(basic_tests, issue_1076_blob_with_query) {
  // blob: scheme with query - similar to existing path_setter_bug test
  auto url = ada::parse<ada::url_aggregator>("blob:/?q");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->validate());
  ASSERT_TRUE(url->set_pathname("//p"));
  ASSERT_TRUE(url->validate());
  ASSERT_EQ(url->get_pathname(), "//p");
  ASSERT_EQ(url->get_search(), "?q");
  SUCCEED();
}

TEST(basic_tests, issue_1076_setter_sequence) {
  // Simulates the fuzzer scenario: parse a URL, then call multiple setters
  // to put it into a vulnerable state before set_pathname
  auto url = ada::parse<ada::url_aggregator>("foo://host/path?query#hash");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->validate());
  // Clear the host to remove authority
  url->set_hostname("");
  url->set_host("");
  ASSERT_TRUE(url->validate());
  // Now set pathname to something starting with //
  ASSERT_TRUE(url->set_pathname("//newpath"));
  ASSERT_TRUE(url->validate());
  SUCCEED();
}

// Regression test: parsing an empty string or no-scheme input relative to a
// base URL with an empty query string ("?") must preserve the empty query in
// both ada::url and ada::url_aggregator. Previously, url_aggregator would
// drop the query entirely because update_base_search("") incorrectly cleared
// it instead of preserving the "?" marker.
TEST(basic_tests, empty_query_base_consistency) {
  // FILE state: empty source against file:// base with empty query.
  {
    auto bu = ada::parse<ada::url>("file:///path?");
    auto ba = ada::parse<ada::url_aggregator>("file:///path?");
    ASSERT_TRUE(bu);
    ASSERT_TRUE(ba);
    auto ru = ada::parse<ada::url>("", &*bu);
    auto ra = ada::parse<ada::url_aggregator>("", &*ba);
    ASSERT_TRUE(ru);
    ASSERT_TRUE(ra);
    EXPECT_EQ(ru->get_href(), std::string(ra->get_href()));
    EXPECT_TRUE(ru->has_search());
    EXPECT_TRUE(ra->has_search());
    EXPECT_EQ(ru->get_search(), "");
    EXPECT_EQ(std::string(ra->get_search()), "");
  }

  // FILE state: original fuzzer crash input.
  {
    auto bu = ada::parse<ada::url>("file://e//.U./UU.//&eSe?");
    auto ba = ada::parse<ada::url_aggregator>("file://e//.U./UU.//&eSe?");
    ASSERT_TRUE(bu);
    ASSERT_TRUE(ba);
    auto ru = ada::parse<ada::url>("", &*bu);
    auto ra = ada::parse<ada::url_aggregator>("", &*ba);
    ASSERT_TRUE(ru);
    ASSERT_TRUE(ra);
    EXPECT_EQ(ru->get_href(), std::string(ra->get_href()));
  }

  // RELATIVE_SCHEME state: empty source against https:// base with empty query.
  {
    auto bu = ada::parse<ada::url>("https://example.com/path?");
    auto ba = ada::parse<ada::url_aggregator>("https://example.com/path?");
    ASSERT_TRUE(bu);
    ASSERT_TRUE(ba);
    auto ru = ada::parse<ada::url>("", &*bu);
    auto ra = ada::parse<ada::url_aggregator>("", &*ba);
    ASSERT_TRUE(ru);
    ASSERT_TRUE(ra);
    EXPECT_EQ(ru->get_href(), std::string(ra->get_href()));
    EXPECT_TRUE(ru->has_search());
    EXPECT_TRUE(ra->has_search());
  }

  // NO_SCHEME state: fragment-only input against opaque-path base with empty
  // query.
  {
    auto bu = ada::parse<ada::url>("foo:bar?");
    auto ba = ada::parse<ada::url_aggregator>("foo:bar?");
    ASSERT_TRUE(bu);
    ASSERT_TRUE(ba);
    auto ru = ada::parse<ada::url>("#hash", &*bu);
    auto ra = ada::parse<ada::url_aggregator>("#hash", &*ba);
    ASSERT_TRUE(ru);
    ASSERT_TRUE(ra);
    EXPECT_EQ(ru->get_href(), std::string(ra->get_href()));
  }
}

// Regression test: canonicalize_pathname with path traversal that reduces
// the normalized pathname to fewer than 2 characters must not throw
// std::out_of_range. Previously, "fake://fake-url/-../../" normalized to
// pathname "/" (1 char) and the code called pathname.substr(2) which threw.
#if ADA_INCLUDE_URL_PATTERN
TEST(basic_tests, url_pattern_canonicalize_pathname_traversal) {
  using regex_provider = ada::url_pattern_regex::std_regex_provider;
  // These inputs have non-leading-slash pathnames that, after URL
  // normalization of path traversal sequences, produce a pathname shorter
  // than 2 characters.  They must return a failure (not crash).
  ada::url_pattern_init init1{};
  init1.pathname = "../../";
  auto result1 =
      ada::parse_url_pattern<regex_provider>(init1, nullptr, nullptr);
  // Result may be success or failure, but must not crash.
  (void)result1;

  ada::url_pattern_init init2{};
  init2.pathname = "../";
  auto result2 =
      ada::parse_url_pattern<regex_provider>(init2, nullptr, nullptr);
  (void)result2;

  // A simple relative pathname (no traversal) exercises the
  // !leading_slash && pathname.size() >= 2 branch (returns substr(2)).
  ada::url_pattern_init init3{};
  init3.pathname = "simple";
  auto result3 =
      ada::parse_url_pattern<regex_provider>(init3, nullptr, nullptr);
  (void)result3;

  SUCCEED();
}
#endif  // ADA_INCLUDE_URL_PATTERN

// Regression test for https://github.com/whatwg/url/issues/803
// A mixed label whose ASCII chars happen to spell "xn--" must not be rejected
// during Punycode decoding.  The label encodes to a Punycode sequence whose
// encoded (ASCII-prefix) portion starts with "xn--", but the *decoded* label
// does NOT start with "xn--" (it starts with a non-ASCII code point).
// Before the fix, both punycode_to_utf32 and verify_punycode rejected these
// inputs early by checking the encoded input instead of the decoded output,
// causing href idempotency failures: parsing the serialised href of a valid
// URL would return a different (invalid) result.
TEST(basic_tests, idna_mixed_label_xn_prefix_regression) {
  // "http://\u33ff\u33fdxn--./":
  //   label "\u33ff\u33fdxn--" encodes to "xn--xn---ue6f785fgsonh6a"
  //   which decodes back to "\u33ff\u33fdxn--" (starts with non-ASCII, valid).
  auto r = ada::parse<ada::url>("http://\u33ff\u33fdxn--./");
  ASSERT_TRUE(r) << "URL with mixed IDNA label ending in 'xn--' must parse";

  // Re-parsing the serialised href must produce the same href (idempotency).
  auto href = r->get_href();
  auto r2 = ada::parse<ada::url>(href);
  ASSERT_TRUE(r2) << "Re-parse of serialised href must succeed";
  ASSERT_EQ(r2->get_href(), href) << "href must be idempotent after re-parse";
}

// Regression test for parse_host fast paths not restoring is_valid=true.
//
// If a setter call fails (leaving is_valid=false) and a subsequent set_host
// call succeeds via the fast path (lowercase ASCII, no forbidden code points),
// is_valid would remain false. parse_port gates on is_valid, so the port
// would silently not update - diverging url and url_aggregator state.
//
// Reproducer: start from https://user:pass@example.com:8080/path?query=1#hash
//   1. set_host("@invalid") - fails (@ is forbidden), sets is_valid=false
//   2. set_host("rf:1")     - host "rf" takes fast path; is_valid must become
//                             true so that port 1 is accepted by parse_port.
TYPED_TEST(basic_tests, set_host_fast_path_restores_is_valid) {
  auto url = ada::parse<TypeParam>(
      "https://user:pass@example.com:8080/path?query=1#hash");
  ASSERT_TRUE(url);

  // Step 1: fail with a forbidden code point in the host - sets is_valid=false.
  ASSERT_FALSE(url->set_host("@invalid"));

  // Step 2: succeed with a lowercase ASCII host + port via the fast path.
  // Port must be updated to 1, not silently left at 8080.
  ASSERT_TRUE(url->set_host("rf:1"));
  ASSERT_TRUE(url->is_valid);
  ASSERT_EQ(url->get_hostname(), "rf");
  ASSERT_EQ(url->get_port(), "1");
}

TYPED_TEST(basic_tests, get_href_size_matches_get_href) {
  // Verify that get_href_size() returns the same value as get_href().size()
  // across a variety of URLs.
  const std::string_view urls[] = {
      "https://www.google.com/",
      "https://user:pass@example.com:8080/path?query=1#hash",
      "http://localhost/",
      "http://localhost:3000/",
      "ftp://ftp.example.com/pub/file.txt",
      "ws://echo.websocket.org/",
      "wss://secure.example.com:8443/chat",
      "file:///tmp/test.txt",
      "data:text/html,<h1>Hello</h1>",
      "mailto:user@example.com",
      "http://[::1]:8080/path",
      "http://example.com/?q=hello%20world#section",
      "https://example.com/path/to/resource",
  };
  for (const auto& input : urls) {
    auto url = ada::parse<TypeParam>(input);
    ASSERT_TRUE(url) << "Failed to parse: " << input;
    ASSERT_EQ(url->get_href_size(), url->get_href().size())
        << "Mismatch for: " << input;
  }
}

TYPED_TEST(basic_tests, get_href_size_after_setters) {
  auto url =
      ada::parse<TypeParam>("https://user:pass@example.com:8080/path?q=1#frag");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_username("newuser");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_password("newpass");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_pathname("/new/path");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_search("?new=search");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_hash("#newhash");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_port("9090");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_hostname("other.com");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_protocol("http");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());
}

TYPED_TEST(basic_tests, get_href_size_no_port) {
  auto url = ada::parse<TypeParam>("https://example.com/");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());
}

TYPED_TEST(basic_tests, get_href_size_no_credentials) {
  auto url = ada::parse<TypeParam>("https://example.com:443/path?q=1#h");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());
}

TYPED_TEST(basic_tests, get_href_size_empty_components) {
  auto url = ada::parse<TypeParam>("http://x");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_search("");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  url->set_hash("");
  ASSERT_EQ(url->get_href_size(), url->get_href().size());
}

TYPED_TEST(basic_tests, get_href_size_non_special_scheme) {
  auto url = ada::parse<TypeParam>("foo://bar/baz?q#f");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());
}

TYPED_TEST(basic_tests, get_href_size_all_port_lengths) {
  // Test ports with 1 through 5 digits to exercise the digit-counting logic.
  const std::string_view ports[] = {"1", "80", "443", "8080", "65535"};
  for (const auto& port : ports) {
    auto url = ada::parse<TypeParam>("http://example.com/");
    ASSERT_TRUE(url);
    url->set_port(port);
    ASSERT_EQ(url->get_href_size(), url->get_href().size())
        << "Mismatch for port: " << port;
  }
}

TYPED_TEST(basic_tests, get_href_size_percent_encoded) {
  auto url = ada::parse<TypeParam>("http://example.com/hello%20world?q=%23#f");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());
}

TYPED_TEST(basic_tests, get_href_size_opaque_path) {
  auto url = ada::parse<TypeParam>("data:text/html,content");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());
}

TYPED_TEST(basic_tests, get_href_size_password_no_password) {
  // URL with username but no password.
  auto url = ada::parse<TypeParam>("http://user@example.com/");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href_size(), url->get_href().size());

  // URL with username and password.
  auto url2 = ada::parse<TypeParam>("http://user:pass@example.com/");
  ASSERT_TRUE(url2);
  ASSERT_EQ(url2->get_href_size(), url2->get_href().size());
}

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

// A failed set_host on a non-special URL that has no authority must leave the
// URL untouched. url_aggregator used to roll back through update_base_hostname,
// which re-added the "//" authority ("non-spec:/x" -> "non-spec:///x").
TYPED_TEST(basic_tests, failed_set_host_keeps_authority_less_url) {
  auto r = ada::parse<TypeParam>("non-spec:/x");
  ASSERT_TRUE(r);
  ASSERT_FALSE(r->set_host("@\b["));
  ASSERT_EQ(r->get_href(), "non-spec:/x");
  ASSERT_FALSE(r->set_hostname("@\b["));
  ASSERT_EQ(r->get_href(), "non-spec:/x");
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

TYPED_TEST(basic_tests, file_shorten_path_normalized_drive_letter_only) {
  // https://url.spec.whatwg.org/#shorten-a-urls-path : a file path's first
  // segment is protected from ".." only when it is a *normalized Windows drive
  // letter*, which is exactly two code points (an ASCII alpha followed by ":").
  // Longer segments that merely start with "<alpha>:" must be popped.
  ASSERT_EQ(ada::parse<TypeParam>("file:c:x/..")->get_href(), "file:///");
  ASSERT_EQ(ada::parse<TypeParam>("file:u:p@h/..")->get_href(), "file:///");
  // A real drive letter is still preserved.
  ASSERT_EQ(ada::parse<TypeParam>("file:c:/..")->get_href(), "file:///c:/");
  SUCCEED();
}

TYPED_TEST(basic_tests, set_empty_host_on_non_special_without_authority) {
  // A non-special URL with a non-opaque path but no authority (e.g. "foo:/bar")
  // must gain an empty authority when its host is set to the empty string. The
  // WHATWG host setter only returns early for an opaque path, and ada::url
  // already behaves this way; url_aggregator must match.
  auto a = ada::parse<TypeParam>("non-special:/x");
  ASSERT_TRUE(a->set_host(""));
  ASSERT_EQ(a->get_href(), "non-special:///x");
  auto b = ada::parse<TypeParam>("sc:/x");
  ASSERT_TRUE(b->set_hostname(""));
  ASSERT_EQ(b->get_href(), "sc:///x");
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

// Companion to set_protocol_should_return_false_sometimes: the same
// WHATWG state-override validation errors apply when the target scheme
// is non-special. parse_scheme's fast path (special target) and slow
// path (non-special target) must agree.
TYPED_TEST(basic_tests, set_protocol_non_special_target_returns_false) {
  // file: with empty host -> cannot change scheme (validation error #4).
  {
    auto url = ada::parse<TypeParam>("file:");
    ASSERT_EQ(url->set_protocol("foo"), false);
    ASSERT_EQ(url->get_protocol(), "file:");
  }

  // Special -> non-special is also a validation error (#1, mirror of the
  // existing readme3 test which goes special -> special and succeeds).
  {
    auto url = ada::parse<TypeParam>("https://example.com/");
    ASSERT_EQ(url->set_protocol("foo"), false);
    ASSERT_EQ(url->get_protocol(), "https:");
    ASSERT_EQ(url->get_href(), "https://example.com/");
  }

  // Non-special -> non-special must still succeed.
  {
    auto url = ada::parse<TypeParam>("git://example.com/");
    ASSERT_EQ(url->set_protocol("svn"), true);
    ASSERT_EQ(url->get_protocol(), "svn:");
  }
  SUCCEED();
}

TYPED_TEST(basic_tests, set_protocol_should_return_true_sometimes) {
  auto url = ada::parse<TypeParam>("file:");
  ASSERT_EQ(url->set_host("google.com"), true);
  ASSERT_EQ(url->set_protocol("https"), true);
  ASSERT_EQ(url->get_href(), "https://google.com/");
  SUCCEED();
}

// Changing to a non-special scheme (default port 0) must not drop an explicit
// port of 0. The port is only cleared when it equals the target scheme's
// default port, and a non-special scheme has none.
TYPED_TEST(basic_tests, set_protocol_keeps_zero_port_non_special_target) {
  auto url = ada::parse<TypeParam>("a://h:0");
  ASSERT_EQ(url->set_protocol("b"), true);
  ASSERT_EQ(url->get_port(), "0");
  ASSERT_EQ(url->get_href(), "b://h:0");
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

TYPED_TEST(basic_tests, setters_strip_ascii_tab_or_newline) {
  auto url = ada::parse<TypeParam>(
      "https://user:pass@www.example.com:8080/path?q=1#h");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->set_protocol("w\tss"));
  ASSERT_EQ(url->get_protocol(), "wss:");
  ASSERT_TRUE(url->set_port("90\t90"));
  ASSERT_EQ(url->get_port(), "9090");
  url->set_search("?a=\t1");
  ASSERT_EQ(url->get_search(), "?a=1");
  url->set_hash("#new\tfrag");
  ASSERT_EQ(url->get_hash(), "#newfrag");
  ASSERT_TRUE(url->set_hostname("www.newhost.exam\tple.org"));
  ASSERT_EQ(url->get_hostname(), "www.newhost.example.org");
}

TYPED_TEST(basic_tests, host_nfc_reorders_precomposed_starter) {
  // A precomposed starter followed by a combining mark of lower combining class
  // is not in NFC: normalization decomposes the starter and reorders the marks.
  // %C3%A1%CC%A3 is U+00E1 (a + acute, class 230) then U+0323 (dot below, class
  // 220); NFC is U+1EA1 (a + dot below) with the acute floating -> xn--lsa752l.
  auto url = ada::parse<TypeParam>("http://%C3%A1%CC%A3/");
  ASSERT_TRUE(url.has_value());
  ASSERT_EQ(url->get_hostname(), "xn--lsa752l");

  auto url2 = ada::parse<TypeParam>("https://%C5%9A%CC%A7.example/");
  ASSERT_TRUE(url2.has_value());
  ASSERT_EQ(url2->get_hostname(), "xn--nga05f.example");
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

TYPED_TEST(basic_tests, credential_replacement_preserves_url_tail) {
  auto url = ada::parse<TypeParam>(
      "https://initial:secret@example.com/path?before=yes#fragment");
  ASSERT_TRUE(url);

  ASSERT_TRUE(url->set_username("changed"));
  ASSERT_TRUE(url->set_password("planet"));
  ASSERT_EQ(url->get_href(),
            "https://changed:planet@example.com/path?before=yes#fragment");

  ASSERT_TRUE(url->set_username("x"));
  ASSERT_TRUE(url->set_password("y"));
  ASSERT_EQ(url->get_href(),
            "https://x:y@example.com/path?before=yes#fragment");

  ASSERT_TRUE(url->set_username("a-much-longer-username"));
  ASSERT_TRUE(url->set_password("a-much-longer-password"));
  ASSERT_EQ(url->get_href(),
            "https://a-much-longer-username:a-much-longer-password@"
            "example.com/path?before=yes#fragment");
}

TYPED_TEST(basic_tests, credential_insertion_and_encoding_preserve_url_tail) {
  auto url = ada::parse<TypeParam>("https://example.com/path?q=1#fragment");
  ASSERT_TRUE(url);

  ASSERT_TRUE(url->set_username("a b"));
  ASSERT_TRUE(url->set_password("p@ss"));
  ASSERT_EQ(url->get_href(),
            "https://a%20b:p%40ss@example.com/path?q=1#fragment");

  ASSERT_TRUE(url->set_username(""));
  ASSERT_TRUE(url->set_password(""));
  ASSERT_EQ(url->get_href(), "https://example.com/path?q=1#fragment");
}

TYPED_TEST(basic_tests, query_replacement_preserves_url_tail) {
  auto url = ada::parse<TypeParam>(
      "https://user:pass@example.com/path?before=yes#fragment");
  ASSERT_TRUE(url);

  url->set_search("?same=value");
  ASSERT_EQ(url->get_href(),
            "https://user:pass@example.com/path?same=value#fragment");

  url->set_search("?a=1");
  ASSERT_EQ(url->get_href(), "https://user:pass@example.com/path?a=1#fragment");

  url->set_search("?longer query=value");
  ASSERT_EQ(url->get_href(),
            "https://user:pass@example.com/path?"
            "longer%20query=value#fragment");
}

TYPED_TEST(basic_tests, query_insertion_and_encoding_preserve_url_tail) {
  auto url = ada::parse<TypeParam>("https://example.com/path#fragment");
  ASSERT_TRUE(url);

  url->set_search("?value='x y'");
  ASSERT_EQ(url->get_href(),
            "https://example.com/path?value=%27x%20y%27#fragment");

  url->set_search("");
  ASSERT_EQ(url->get_href(), "https://example.com/path#fragment");
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
  // The base has an opaque path and the input does not begin with '#', so
  // "no scheme state" returns failure. It must report that instead of
  // crashing, which is what the node issue asked for.
  ASSERT_FALSE(ada::parse<TypeParam>("..#", &*urlbase));
  ASSERT_FALSE(ada::parse<TypeParam>("x#f", &*urlbase));
  // A fragment-only input is the one relative form such a base accepts.
  auto url = ada::parse<TypeParam>("#f", &*urlbase);
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->has_opaque_path);
  ASSERT_EQ(url->get_href(), "a:b#f");
  ASSERT_EQ(url->get_pathname(), "b");
  SUCCEED();
}

// A '#' anywhere in the input must not turn an opaque-path base into a
// hierarchical one: the authority here is never parsed.
TYPED_TEST(basic_tests, opaque_base_relative_hash_no_authority) {
  auto base = ada::parse<TypeParam>("about:blank");
  ASSERT_TRUE(base);
  ASSERT_TRUE(base->has_opaque_path);
  ASSERT_FALSE(ada::parse<TypeParam>("//evil.com/p", &*base));
  ASSERT_FALSE(ada::parse<TypeParam>("//evil.com/p#", &*base));
  ASSERT_FALSE(ada::parse<TypeParam>("/etc/passwd#", &*base));
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

TEST(basic_tests, can_parse_consistency_clean_http_frontend) {
  for (const auto& input : std::vector<std::string>{
           "https://example.com/",
           "https://example.de/a/long/path?query=value#fragment",
           "http://foo_bar.example/path with spaces",
           "http://example.com",
           "http://",
           "http://?query",
           "http:///path",
           "http://Example.com/",
           "http://example.com:65536/",
           "https://www.google.com/webhp?hl=en",
           "https://images-na.ssl-images-amazon.com/images/I/x.css",
           "http://abcdefghijklmnopqrstuvwxyz0123456789-._~example.com/path",
           "http://1.2.3.999/",
           "http://xn--/",
           "http://example.com./",
           "http://%65xample.com/",
           "http://foo.0xffffffff/",
           "http://foo.0xfffffffff/",
           "http://0xfffffffff/",
           "http://example.0x/",
           "http://foo.0x1/",
           "http://0xffffffff/",
       }) {
    assert_can_parse_consistent(input);
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
           "http://@19%2E68.1.10.",
           "http://19%2E68.1.10.",
           "http://@19%2E68.1.10.0.@'foo",
       }) {
    assert_can_parse_consistent(input);
  }
}

// url and url_aggregator must agree after percent-decoding an IPv4 host.
// Passing get_hostname() (a view into the aggregator buffer) into parse_ipv4
// overlapped when the decoded host had a trailing dot.
TEST(basic_tests, percent_encoded_ipv4_url_aggregator_agree) {
  const char* inputs[] = {
      "http://@19%2E68.1.10.",  "http://19%2E68.1.10.",
      "http://19%2E68.1.10./x", "http://@19%2E68.1.10.0.@'foo",
      "http://0xffffffff.",     "http://%31%2e%32%2e%33%2e%34/",
      "http://19%2E68.1.10",
  };
  for (const char* input : inputs) {
    auto url = ada::parse<ada::url>(input);
    auto agg = ada::parse<ada::url_aggregator>(input);
    ASSERT_EQ(url.has_value(), agg.has_value()) << input;
    if (!url) {
      continue;
    }
    ASSERT_EQ(url->get_href(), std::string(agg->get_href())) << input;
    ASSERT_EQ(std::string(url->get_hostname()),
              std::string(agg->get_hostname()))
        << input;
    ASSERT_EQ(std::string(url->get_host()), std::string(agg->get_host()))
        << input;
    ASSERT_EQ(url->get_username(), std::string(agg->get_username())) << input;
    ASSERT_EQ(std::string(url->get_pathname()),
              std::string(agg->get_pathname()))
        << input;
    ASSERT_TRUE(agg->validate()) << input;
  }
}

// ada::unicode::percent_decode
TEST(basic_tests, percent_decode_direct) {
  using ada::unicode::percent_decode;
  constexpr auto npos = std::string_view::npos;
  // No percent sign: first_percent == npos returns the input unchanged.
  ASSERT_EQ(percent_decode("no percent here", npos), "no percent here");
  ASSERT_EQ(percent_decode("", npos), "");
  // Valid escapes are decoded.
  ASSERT_EQ(percent_decode("a%2Eb", 1), "a.b");
  ASSERT_EQ(percent_decode("%41%42%43", 0), "ABC");
  ASSERT_EQ(percent_decode("caf%C3%A9", 3), std::string("caf\xc3\xa9"));
  // A plain run followed by an escape exercises the memchr run-copy.
  ASSERT_EQ(percent_decode("hello%20world", 5), "hello world");
  // Invalid escapes are copied literally.
  ASSERT_EQ(percent_decode("%zz", 0), "%zz");    // non-hex digits
  ASSERT_EQ(percent_decode("x%2", 1), "x%2");    // truncated escape at end
  ASSERT_EQ(percent_decode("100%", 3), "100%");  // trailing '%'
  ASSERT_EQ(percent_decode("%%41", 0), "%A");    // '%' then a valid escape
}

namespace {
size_t scalar_percent_encode_index(std::string_view input,
                                   const uint8_t character_set[]) {
  for (size_t i = 0; i < input.size(); i++) {
    if (ada::character_sets::bit_at(character_set, input[i])) {
      return i;
    }
  }
  return input.size();
}

std::string scalar_percent_encode(std::string_view input,
                                  const uint8_t character_set[]) {
  std::string out;
  for (unsigned char c : input) {
    if (ada::character_sets::bit_at(character_set, c)) {
      out.append(ada::character_sets::hex + static_cast<size_t>(c) * 4, 3);
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  return out;
}

const uint8_t* percent_encode_sets[] = {
    ada::character_sets::C0_CONTROL_PERCENT_ENCODE,
    ada::character_sets::FRAGMENT_PERCENT_ENCODE,
    ada::character_sets::QUERY_PERCENT_ENCODE,
    ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE,
    ada::character_sets::USERINFO_PERCENT_ENCODE,
    ada::character_sets::PATH_PERCENT_ENCODE,
    ada::character_sets::WWW_FORM_URLENCODED_PERCENT_ENCODE,
};
}  // namespace

TEST(basic_tests, percent_encode_index_and_encode_match_scalar) {
  for (const uint8_t* character_set : percent_encode_sets) {
    for (size_t len = 0; len <= 80; len++) {
      std::string clean(len, 'a');
      ASSERT_EQ(ada::unicode::percent_encode_index(clean, character_set),
                clean.size())
          << "clean len=" << len;
      ASSERT_EQ(ada::unicode::percent_encode(clean, character_set), clean)
          << "clean len=" << len;

      for (size_t pos = 0; pos < len; pos++) {
        std::string one_space = clean;
        one_space[pos] = ' ';
        ASSERT_EQ(ada::unicode::percent_encode_index(one_space, character_set),
                  scalar_percent_encode_index(one_space, character_set))
            << "space at " << pos << " len=" << len;
        ASSERT_EQ(ada::unicode::percent_encode(one_space, character_set),
                  scalar_percent_encode(one_space, character_set))
            << "space at " << pos << " len=" << len;

        std::string one_high = clean;
        one_high[pos] = static_cast<char>(0xE1);
        ASSERT_EQ(ada::unicode::percent_encode_index(one_high, character_set),
                  pos)
            << "high at " << pos << " len=" << len;
        ASSERT_EQ(ada::unicode::percent_encode(one_high, character_set),
                  scalar_percent_encode(one_high, character_set))
            << "high at " << pos << " len=" << len;
      }
    }

    std::string dense(32, '"');
    ASSERT_EQ(ada::unicode::percent_encode_index(dense, character_set),
              scalar_percent_encode_index(dense, character_set));
    ASSERT_EQ(ada::unicode::percent_encode(dense, character_set),
              scalar_percent_encode(dense, character_set));

    std::string long_dense(64, '"');
    ASSERT_EQ(ada::unicode::percent_encode(long_dense, character_set),
              scalar_percent_encode(long_dense, character_set));

    for (size_t len : {96u, 128u, 256u}) {
      std::string clean(len, 'a');
      ASSERT_EQ(ada::unicode::percent_encode(clean, character_set), clean)
          << "clean len=" << len;
      clean[len / 2] = ' ';
      clean[len - 1] = static_cast<char>(0x7F);
      ASSERT_EQ(ada::unicode::percent_encode(clean, character_set),
                scalar_percent_encode(clean, character_set))
          << "wide len=" << len;
    }

    std::string mixed = std::string(15, 'a') + "|" + std::string(16, 'b') +
                        std::string(1, char(0x7F)) + std::string(17, 'c');
    ASSERT_EQ(ada::unicode::percent_encode_index(mixed, character_set),
              scalar_percent_encode_index(mixed, character_set));
    ASSERT_EQ(ada::unicode::percent_encode(mixed, character_set),
              scalar_percent_encode(mixed, character_set));
    const size_t idx = ada::unicode::percent_encode_index(mixed, character_set);
    ASSERT_EQ(ada::unicode::percent_encode(mixed, character_set, idx),
              ada::unicode::percent_encode(mixed, character_set));
  }
}

TEST(basic_tests, percent_encode_template_append_and_replace) {
  const uint8_t* query = ada::character_sets::QUERY_PERCENT_ENCODE;
  const std::string clean(24, 'n');
  const std::string dirty = std::string(16, 'n') + " " + std::string(16, 'n');
  const std::string long_dirty =
      std::string(16, 'n') + " " + std::string(48, 'n');

  std::string replace_clean;
  ASSERT_FALSE(
      ada::unicode::percent_encode<false>(clean, query, replace_clean));
  ASSERT_TRUE(replace_clean.empty());

  std::string replace_dirty;
  ASSERT_TRUE(ada::unicode::percent_encode<false>(dirty, query, replace_dirty));
  ASSERT_EQ(replace_dirty, scalar_percent_encode(dirty, query));

  std::string replace_long;
  ASSERT_TRUE(
      ada::unicode::percent_encode<false>(long_dirty, query, replace_long));
  ASSERT_EQ(replace_long, scalar_percent_encode(long_dirty, query));

  std::string append_out = "pre:";
  ASSERT_FALSE(ada::unicode::percent_encode<true>(clean, query, append_out));
  ASSERT_EQ(append_out, "pre:");

  ASSERT_TRUE(ada::unicode::percent_encode<true>(dirty, query, append_out));
  ASSERT_EQ(append_out, "pre:" + scalar_percent_encode(dirty, query));

  ASSERT_TRUE(
      ada::unicode::percent_encode<true>(long_dirty, query, append_out));
  ASSERT_EQ(append_out, "pre:" + scalar_percent_encode(dirty, query) +
                            scalar_percent_encode(long_dirty, query));
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

TYPED_TEST(basic_tests, ipv4_hex_leading_zeros) {
  // Leading zeros are permitted in a hex IPv4 number, so digit runs longer
  // than eight still map to a <= 32-bit value.
  auto a = ada::parse<TypeParam>("http://0x0000000ff/");
  ASSERT_TRUE(a);
  ASSERT_EQ(a->get_hostname(), "0.0.0.255");
  auto b = ada::parse<TypeParam>("http://0x00000000ff/");
  ASSERT_TRUE(b);
  ASSERT_EQ(b->get_hostname(), "0.0.0.255");
  // A value that genuinely exceeds 32 bits is still rejected.
  auto c = ada::parse<TypeParam>("http://0x100000000/");
  ASSERT_FALSE(c);
  SUCCEED();
}

TYPED_TEST(basic_tests, ipv4_fast_path_malformed_groups) {
  // A pure-decimal IPv4 group must hold 1-3 digits and be non-empty. These
  // hosts look digit/dot-shaped but violate group structure, so they are
  // not valid IPv4 addresses and must be rejected on every build.
  // Group longer than three digits:
  ASSERT_FALSE(ada::parse<TypeParam>("http://1234.5.6.7/"));
  ASSERT_FALSE(ada::parse<TypeParam>("http://1.2345.6.7/"));
  // Empty group / consecutive dots:
  ASSERT_FALSE(ada::parse<TypeParam>("http://1..2.34/"));
  ASSERT_FALSE(ada::parse<TypeParam>("http://12.3..4/"));
  // A well-formed address with the same length still parses:
  auto ok = ada::parse<TypeParam>("http://12.34.56.78/");
  ASSERT_TRUE(ok);
  ASSERT_EQ(ok->get_hostname(), "12.34.56.78");
  SUCCEED();
}

TEST(ipv4_fast_path, packed_decimal_and_rejects) {
  using ada::checkers::ipv4_fast_fail;
  using ada::checkers::try_parse_ipv4_fast;
  ASSERT_EQ(try_parse_ipv4_fast("192.168.1.1"), 0xC0A80101ull);
  ASSERT_EQ(try_parse_ipv4_fast("0.0.0.0"), 0ull);
  ASSERT_EQ(try_parse_ipv4_fast("255.255.255.255"), 0xFFFFFFFFull);
  ASSERT_EQ(try_parse_ipv4_fast("1.2.3.4."), 0x01020304ull);
  ASSERT_EQ(try_parse_ipv4_fast("255.255.255.255."), 0xFFFFFFFFull);
  // Double trailing dot, overflow, leading zeros, short form: not this path.
  ASSERT_EQ(try_parse_ipv4_fast("1.2.3.4.."), ipv4_fast_fail);
  ASSERT_EQ(try_parse_ipv4_fast("256.0.0.1"), ipv4_fast_fail);
  ASSERT_EQ(try_parse_ipv4_fast("01.2.3.4"), ipv4_fast_fail);
  ASSERT_EQ(try_parse_ipv4_fast("127.1"), ipv4_fast_fail);
  ASSERT_EQ(try_parse_ipv4_fast("1.2.3.4.5"), ipv4_fast_fail);
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

TYPED_TEST(basic_tests, failed_set_host_does_not_poison_set_port) {
  auto url = ada::parse<TypeParam>(
      "https://user:pass@example.com:8080/path?query=1#hash");
  ASSERT_TRUE(url);

  // A rejected set_host must leave the URL fully usable. Rolling back through
  // update_base_port left is_valid=false, which made the following set_port
  // fail (port stuck at 8080) instead of updating it.
  ASSERT_FALSE(url->set_host("7\x03"));
  ASSERT_TRUE(url->set_port("1"));
  ASSERT_EQ(url->get_port(), "1");
  ASSERT_EQ(url->get_href(),
            "https://user:pass@example.com:1/path?query=1#hash");
}

TYPED_TEST(basic_tests, set_host_with_port_strips_dash_dot) {
  // A non-special URL with a null host and a path starting with "//" carries a
  // "/." guard in its serialization. Setting a host that contains a port (so
  // the ":" host/port split is taken) must drop that guard, exactly like the
  // no-port path already does. url_aggregator used to leave the "/." wedged in
  // the path, diverging from ada::url.
  auto url = ada::parse<TypeParam>("non-spec:/.//p");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href(), "non-spec:/.//p");

  ASSERT_TRUE(url->set_host("host:99"));
  ASSERT_EQ(url->get_host(), "host:99");
  ASSERT_EQ(url->get_pathname(), "//p");
  ASSERT_EQ(url->get_href(), "non-spec://host:99//p");
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

TYPED_TEST(basic_tests, clear_hash_on_opaque_path) {
  auto url = ada::parse<TypeParam>("data:hello#frag");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->has_opaque_path);
  url->set_hash("");
  ASSERT_EQ(url->get_hash(), "");
  ASSERT_EQ(url->get_pathname(), "hello");
}

TYPED_TEST(basic_tests, mailto_rejects_credentials) {
  auto url = ada::parse<TypeParam>("mailto:a@b.com");
  ASSERT_TRUE(url);
  ASSERT_FALSE(url->set_username("user"));
  ASSERT_FALSE(url->set_password("pass"));
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

TYPED_TEST(basic_tests, simple_absolute_fast_path) {
  {
    auto url =
        ada::parse<TypeParam>("https://www.google.com/imghp?hl=en&tab=wi");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "https:");
    ASSERT_EQ(url->get_hostname(), "www.google.com");
    ASSERT_EQ(url->get_pathname(), "/imghp");
    ASSERT_EQ(url->get_search(), "?hl=en&tab=wi");
    ASSERT_EQ(url->get_href(), "https://www.google.com/imghp?hl=en&tab=wi");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
    ASSERT_EQ(url->get_href(), "https://example.com/");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com?q=1");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
    ASSERT_EQ(url->get_search(), "?q=1");
    ASSERT_EQ(url->get_href(), "https://example.com/?q=1");
  }
  {
    auto url = ada::parse<TypeParam>(
        "https://example.com/path?continue=https%3A%2F%2Fexample.com%2F");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_href(),
              "https://example.com/path?continue=https%3A%2F%2Fexample.com%2F");
  }
  {
    auto url = ada::parse<TypeParam>("http://WWW.Example.COM/file.js");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "www.example.com");
    ASSERT_EQ(url->get_pathname(), "/file.js");
    ASSERT_EQ(url->get_href(), "http://www.example.com/file.js");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/a/./b/../c");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/a/c");
    ASSERT_EQ(url->get_href(), "https://example.com/a/c");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo/%2e");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo/");
    ASSERT_EQ(url->get_href(), "https://example.com/foo/");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo/%2e%2e");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
    ASSERT_EQ(url->get_href(), "https://example.com/");
  }
  {
    auto url =
        ada::parse<TypeParam>("https://user:pass@example.com:8080/x?y=1#z");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_username(), "user");
    ASSERT_EQ(url->get_password(), "pass");
    ASSERT_EQ(url->get_port(), "8080");
    ASSERT_EQ(url->get_pathname(), "/x");
    ASSERT_EQ(url->get_search(), "?y=1");
    ASSERT_EQ(url->get_hash(), "#z");
  }
  const char* samples[] = {
      "https://www.youtube.com/about/",
      "http://example.com/",
      "https://maps.google.com/maps?hl=en&tab=wl",
      "https://example.com",
      "https://example.com?q=1#frag",
      "ws://example.com/chat",
      "wss://example.com/chat",
      "ftp://ftp.example.com/file",
      "https://example.com/foo'bar",
      "https://example.com/foo%20bar",
      "https://example.com/a/./b/../c",
      "https://example.com/path?q='x'#f",
      "https://WWW.Example.COM/Long/Path/Name/Without/Dot/Segments?x=1#y",
      "https://www.tiktok.com/@aguyandagolden/video/7133277734310038830",
      "http://localhost:3000/",
      "http://127.0.0.1:8080/",
      "http://10.0.0.5:8080/foo",
      "http://127.0.0.1/",
      "http://localhost:3000/foo%20bar",
      "http://127.0.0.1:8080/a/./b/../c",
  };
  for (const char* s : samples) {
    auto u = ada::parse<ada::url>(s);
    auto a = ada::parse<ada::url_aggregator>(s);
    ASSERT_EQ(u.has_value(), a.has_value()) << s;
    if (u) {
      ASSERT_EQ(u->get_href(), std::string(a->get_href())) << s;
    }
  }
  {
    auto url = ada::parse<TypeParam>("ws://example.com/chat");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "ws:");
    ASSERT_EQ(url->get_hostname(), "example.com");
    ASSERT_EQ(url->get_pathname(), "/chat");
    ASSERT_EQ(url->get_href(), "ws://example.com/chat");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo'bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo'bar");
    ASSERT_EQ(url->get_href(), "https://example.com/foo'bar");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo%20bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo%20bar");
    ASSERT_EQ(url->get_href(), "https://example.com/foo%20bar");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com?q='x'");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_search(), "?q=%27x%27");
    ASSERT_EQ(url->get_href(), "https://example.com/?q=%27x%27");
  }
  {
    // Host, path, query, and fragment long enough to exercise the 16-byte
    // scanners, including a stop character inside a SIMD block.
    auto url = ada::parse<TypeParam>(
        "https://this-is-a-long-hostname.example.com/"
        "abcdefghijklmnopqrstuvwxyz?q=abcdefghijklmnopqrstuvwxyz#h");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "this-is-a-long-hostname.example.com");
    ASSERT_EQ(url->get_pathname(), "/abcdefghijklmnopqrstuvwxyz");
    ASSERT_EQ(url->get_search(), "?q=abcdefghijklmnopqrstuvwxyz");
    ASSERT_EQ(url->get_hash(), "#h");
  }
  {
    auto url = ada::parse<TypeParam>(
        "https://THIS-IS-A-LONG-HOSTNAME.EXAMPLE.COM/abc.def.ghi.jkl.mno/foo");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "this-is-a-long-hostname.example.com");
    ASSERT_EQ(url->get_pathname(), "/abc.def.ghi.jkl.mno/foo");
  }
  {
    auto url =
        ada::parse<TypeParam>("https://example.com/abcdefghijklmnop%20rest");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/abcdefghijklmnop%20rest");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo\\bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo/bar");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com#foo\"bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hash(), "#foo%22bar");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/path?q=1#f`x");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_search(), "?q=1");
    ASSERT_EQ(url->get_hash(), "#f%60x");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com:8080/x");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_port(), "8080");
    ASSERT_EQ(url->get_hostname(), "example.com");
  }
  {
    auto url = ada::parse<TypeParam>("ftp://ftp.example.com/file");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "ftp:");
    ASSERT_EQ(url->get_href(), "ftp://ftp.example.com/file");
  }
  SUCCEED();
}

TYPED_TEST(basic_tests, last_label_may_be_a_number_gate) {
  // Ordinary .com/.org hosts end with a letter outside 0-9a-fxX, so the
  // last-label gate rejects IPv4 without walking the label.
  {
    auto url = ada::parse<TypeParam>("https://www.google.com/search");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "www.google.com");
    ASSERT_EQ(url->get_href(), "https://www.google.com/search");
  }
  {
    auto url = ada::parse<TypeParam>("http://192.168.1.1/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "192.168.1.1");
    ASSERT_EQ(url->host_type, ada::url_host_type::IPV4);
  }
  {
    auto url = ada::parse<TypeParam>("http://127.0.0.1:8080/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "127.0.0.1");
    ASSERT_EQ(url->get_port(), "8080");
    ASSERT_EQ(url->get_href(), "http://127.0.0.1:8080/");
    ASSERT_EQ(url->host_type, ada::url_host_type::IPV4);
  }
  {
    auto url = ada::parse<TypeParam>("http://0x7f.0.0.1/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "127.0.0.1");
    ASSERT_EQ(url->host_type, ada::url_host_type::IPV4);
  }
  // Last label is a number but the host is not valid IPv4.
  ASSERT_FALSE(ada::parse<TypeParam>("https://foo.123"));
  ASSERT_FALSE(ada::parse<TypeParam>("https://foo.0x"));
  {
    auto url = ada::parse<TypeParam>("http://192.168.1.1./");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "192.168.1.1");
  }
  SUCCEED();
}

TYPED_TEST(basic_tests, simple_absolute_fast_path_edges) {
  // Scheme forms the fast path rejects (falls through to the state machine).
  {
    auto url = ada::parse<TypeParam>("http:/example.com");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "http:");
    ASSERT_EQ(url->get_hostname(), "example.com");
  }
  {
    auto url = ada::parse<TypeParam>("http:example.com");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "http:");
  }
  {
    auto url = ada::parse<TypeParam>("wsx://example.com");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "wsx:");
    ASSERT_EQ(url->get_hostname(), "example.com");
  }
  ASSERT_FALSE(ada::parse<TypeParam>("http:///"));

  // IPv6 must not enter the host scanner.
  {
    auto url = ada::parse<TypeParam>("http://[::1]/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "[::1]");
  }
  {
    auto url = ada::parse<TypeParam>("https://[2001:db8::1]/path");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "[2001:db8::1]");
  }

  // Last-label gate inside the fast path. Digit-led domains are accepted;
  // a numeric last label that is not dotted-decimal IPv4 is rejected.
  ASSERT_FALSE(ada::parse<TypeParam>("https://foo.123"));
  ASSERT_FALSE(ada::parse<TypeParam>("https://foo.123."));
  ASSERT_FALSE(ada::parse<TypeParam>("https://foo.0xFF"));
  {
    auto url = ada::parse<TypeParam>("ws://123");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "0.0.0.123");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://1and1.com/x"), u));
    ASSERT_EQ(u.get_hostname(), "1and1.com");
    ASSERT_EQ(u.get_pathname(), "/x");
    ASSERT_EQ(u.host_type, ada::DEFAULT);
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://123.com/"), u));
    ASSERT_EQ(u.get_hostname(), "123.com");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://192.168.1.1"), u));
    ASSERT_EQ(u.get_hostname(), "192.168.1.1");
    ASSERT_EQ(u.get_pathname(), "/");
    ASSERT_EQ(u.host_type, ada::IPV4);
  }
  {
    auto url = ada::parse<TypeParam>("http://192.168.1.1/x");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "192.168.1.1");
    ASSERT_EQ(url->get_pathname(), "/x");
    ASSERT_EQ(url->host_type, ada::IPV4);
  }
  {
    // Trailing-dot IPv4 is rewritten to dotted-decimal on the fast path.
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://192.168.1.1./"), u));
    ASSERT_EQ(u.get_hostname(), "192.168.1.1");
    ASSERT_EQ(u.host_type, ada::IPV4);
    auto url = ada::parse<TypeParam>("http://192.168.1.1./");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "192.168.1.1");
    ASSERT_EQ(url->host_type, ada::IPV4);
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://0x7f.0x0.0x0.0x1"), u));
    ASSERT_EQ(u.get_hostname(), "127.0.0.1");
    ASSERT_EQ(u.get_pathname(), "/");
    ASSERT_EQ(u.get_href(), "http://127.0.0.1/");
    ASSERT_EQ(u.host_type, ada::IPV4);
    auto url = ada::parse<TypeParam>("http://0x7f.0x0.0x0.0x1");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "127.0.0.1");
    ASSERT_EQ(url->get_href(), "http://127.0.0.1/");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://127.1"), u));
    ASSERT_EQ(u.get_hostname(), "127.0.0.1");
    ASSERT_EQ(u.host_type, ada::IPV4);
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://[::1]/"), u));
    ASSERT_EQ(u.get_hostname(), "[::1]");
    ASSERT_EQ(u.get_pathname(), "/");
    ASSERT_EQ(u.get_href(), "http://[::1]/");
    ASSERT_EQ(u.host_type, ada::IPV6);
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://[2001:db8::1]/path"), u));
    ASSERT_EQ(u.get_hostname(), "[2001:db8::1]");
    ASSERT_EQ(u.get_pathname(), "/path");
    ASSERT_EQ(u.host_type, ada::IPV6);
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://[0:0:0:0:0:0:0:1]"), u));
    ASSERT_EQ(u.get_hostname(), "[::1]");
    ASSERT_EQ(u.get_href(), "http://[::1]/");
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://[::1]?q=1"), u));
    ASSERT_EQ(u.get_search(), "?q=1");
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://[::1]#f"), u));
    ASSERT_EQ(u.get_hash(), "#f");
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://[::1]:8080/"), u));
    ASSERT_EQ(u.get_port(), "8080");
    // Junk after ']' is not a hash. The state machine rejects it.
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://[::1]foo"), u));
    ASSERT_FALSE(ada::parse<TypeParam>("http://[::1]foo"));
    ASSERT_EQ(ada::can_parse("http://[::1]foo"), false);
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://[::1]bar/"), u));
    ASSERT_FALSE(ada::parse<TypeParam>("http://[::1]bar/"));
  }
  {
    // ada_c fuzzer aborts when can_parse and parse disagree.
    static constexpr const char* kSchemes[] = {
        "http://", "https://", "ws://", "wss://", "ftp://", "file://"};
    static constexpr const char* kHosts[] = {
        "example.com", "0x7f.1", "[::1]", "127.1", "3232235777", "a"};
    static constexpr const char* kRest[] = {"",   "/",   "/path", "?q=1",
                                            "#f", "foo", "bar/"};
    for (const char* scheme : kSchemes) {
      for (const char* host : kHosts) {
        for (const char* rest : kRest) {
          const std::string input = std::string(scheme) + host + rest;
          ASSERT_EQ(ada::can_parse(input),
                    ada::parse<TypeParam>(input).has_value())
              << input;
        }
      }
    }
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://192.168.1.1:8080/"), u));
    ASSERT_EQ(u.get_hostname(), "192.168.1.1");
    ASSERT_EQ(u.get_port(), "8080");
    ASSERT_EQ(u.host_type, ada::IPV4);
    auto url = ada::parse<TypeParam>("http://192.168.1.1:8080/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "192.168.1.1");
    ASSERT_EQ(url->get_port(), "8080");
    ASSERT_EQ(url->host_type, ada::IPV4);
  }
  {
    auto url = ada::parse<TypeParam>("https://foo.x/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "foo.x");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com./path");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "example.com.");
  }

  // Punycode and overlong hosts leave the fast path.
  {
    auto url = ada::parse<TypeParam>("http://xn--ls8h.com/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "xn--ls8h.com");
    ada::url u;
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://xn--ls8h.com/"), u));
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://foo.xn--bar.com/"), u));
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/"), u));
    ASSERT_EQ(u.get_hostname(), "example.com");
  }
  {
    const std::string long_host(254, 'a');
    auto url = ada::parse<TypeParam>("http://" + long_host + "/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), long_host);
  }

  // Uppercase host plus percent-encoding (handoff, both url types).
  {
    auto url = ada::parse<TypeParam>("https://WWW.EXAMPLE.COM/foo%20bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "www.example.com");
    ASSERT_EQ(url->get_pathname(), "/foo%20bar");
  }
  {
    auto url = ada::parse<TypeParam>("https://WWW.EXAMPLE.COM?q='x'");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "www.example.com");
    ASSERT_EQ(url->get_search(), "?q=%27x%27");
    ASSERT_EQ(url->get_pathname(), "/");
  }
  {
    auto url = ada::parse<TypeParam>("https://WWW.EXAMPLE.COM#foo\"bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hash(), "#foo%22bar");
  }

  // Dots that are not dot-segments stay on the copy path.
  {
    auto url = ada::parse<TypeParam>("https://example.com/file.txt");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/file.txt");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/.hidden");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/.hidden");
  }

  // Dot-segment handoff at the start and middle of the path.
  {
    auto url = ada::parse<TypeParam>("https://example.com/./a");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/a");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/../a");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/a");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo/./bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo/bar");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo/../bar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/bar");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo/.");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo/");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo/..");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
  }

  // Overlapping 16-byte host window: remaining host region is < 16.
  {
    auto url = ada::parse<TypeParam>("https://ab.com/x");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "ab.com");
    ASSERT_EQ(url->get_pathname(), "/x");
    ASSERT_EQ(url->get_href(), "https://ab.com/x");
  }
  {
    auto url = ada::parse<TypeParam>("https://a.co");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "a.co");
    ASSERT_EQ(url->get_href(), "https://a.co/");
  }

  // '%' in a path is copyable unless the segment is %2e / %2e%2e.
  {
    auto url = ada::parse<TypeParam>("https://example.com/a%2fb%20c");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/a%2fb%20c");
    ASSERT_EQ(url->get_href(), "https://example.com/a%2fb%20c");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/a%2fb"), u));
    ASSERT_EQ(u.get_pathname(), "/a%2fb");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/foo/%2e"), u));
    ASSERT_EQ(u.get_pathname(), "/foo/");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo/%2E");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo/");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/%2e%2e/x");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/x");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/.%2e");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
  }
  {
    // Mid-segment %2e is not a dot-segment.
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/foo%2ebar"), u));
    ASSERT_EQ(u.get_pathname(), "/foo%2ebar");
  }

  // Path encoding then query/hash; query encoding then hash.
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo bar?q=1");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo%20bar");
    ASSERT_EQ(url->get_search(), "?q=1");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo bar#h");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo%20bar");
    ASSERT_EQ(url->get_hash(), "#h");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo?q='x'#h");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_search(), "?q=%27x%27");
    ASSERT_EQ(url->get_hash(), "#h");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com/foo{bar}");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/foo%7Bbar%7D");
  }

  // SIMD block + scalar remainder (host/path/query/hash > 16 bytes).
  {
    auto url = ada::parse<TypeParam>(
        "https://abcdefghijklmnopxyz.example.com/"
        "0123456789abcdefghi?q=0123456789abcdefghi#0123456789abcdefghi");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "abcdefghijklmnopxyz.example.com");
    ASSERT_EQ(url->get_pathname(), "/0123456789abcdefghi");
    ASSERT_EQ(url->get_search(), "?q=0123456789abcdefghi");
    ASSERT_EQ(url->get_hash(), "#0123456789abcdefghi");
  }
  {
    auto url = ada::parse<TypeParam>(
        "https://ABCDEFGHIJKLMNOP.example.com/0123456789abcdef%20rest");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "abcdefghijklmnop.example.com");
    ASSERT_EQ(url->get_pathname(), "/0123456789abcdef%20rest");
  }
  {
    auto url = ada::parse<TypeParam>(
        "https://example.com/0123456789abcdef?q=0123456789abcdef'x#h");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_search(), "?q=0123456789abcdef%27x");
  }
  {
    auto url =
        ada::parse<TypeParam>("https://example.com#0123456789abcdef\"rest");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hash(), "#0123456789abcdef%22rest");
  }

  // wss and no-path hash/query already-canonical copies.
  {
    auto url = ada::parse<TypeParam>("wss://example.com/chat");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "wss:");
    ASSERT_EQ(url->get_href(), "wss://example.com/chat");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com#frag");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
    ASSERT_EQ(url->get_hash(), "#frag");
  }
  {
    auto url = ada::parse<TypeParam>("https://example.com?q=1");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
    ASSERT_EQ(url->get_search(), "?q=1");
  }
  // '@' in the path is not userinfo; the fast path must still accept it.
  {
    auto url = ada::parse<TypeParam>(
        "https://www.tiktok.com/@aguyandagolden/video/7133277734310038830");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "www.tiktok.com");
    ASSERT_EQ(url->get_pathname(),
              "/@aguyandagolden/video/7133277734310038830");
  }
  {
    auto url = ada::parse<TypeParam>(
        "https://user:pass@www.example.com:8080/path/to/resource?foo=bar#s");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_username(), "user");
    ASSERT_EQ(url->get_password(), "pass");
    ASSERT_EQ(url->get_hostname(), "www.example.com");
    ASSERT_EQ(url->get_port(), "8080");
    // set_href re-parses a credential URL; the '@' skip must not reject it.
    ASSERT_TRUE(
        url->set_href("https://user:pass@www.example.com:8080/path/to/"
                      "resource?foo=bar&baz=qux#section"));
    ASSERT_EQ(url->get_username(), "user");
    ASSERT_EQ(url->get_href(),
              "https://user:pass@www.example.com:8080/path/to/"
              "resource?foo=bar&baz=qux#section");
  }
  // 16-byte inputs use an overlapping last-16 path window that starts at
  // byte 0. A leading '.' in that window must not read b[-1].
  {
    constexpr std::string_view k16 = "https://u@x/c.de";
    ASSERT_EQ(k16.size(), 16u);
    auto url = ada::parse<TypeParam>(k16);
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_username(), "u");
    ASSERT_EQ(url->get_hostname(), "x");
    ASSERT_EQ(url->get_pathname(), "/c.de");
    ASSERT_EQ(url->get_href(), "https://u@x/c.de");
    ada::url fast;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(k16, fast));
    ASSERT_EQ(fast.get_href(), "https://u@x/c.de");
  }
  {
    constexpr std::string_view k16 = "https://a.com/.x";
    ASSERT_EQ(k16.size(), 16u);
    auto url = ada::parse<TypeParam>(k16);
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "a.com");
    ASSERT_EQ(url->get_pathname(), "/.x");
    ada::url fast;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(k16, fast));
    ASSERT_EQ(fast.get_pathname(), "/.x");
  }
  // Userinfo without a password, empty userinfo, and a missing path.
  {
    auto url = ada::parse<TypeParam>("https://user@example.com/x");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_username(), "user");
    ASSERT_EQ(url->get_password(), "");
    ASSERT_EQ(url->get_hostname(), "example.com");
    ASSERT_EQ(url->get_href(), "https://user@example.com/x");
  }
  {
    auto url = ada::parse<TypeParam>("https://@example.com/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_username(), "");
    ASSERT_EQ(url->get_hostname(), "example.com");
    ASSERT_EQ(url->get_href(), "https://example.com/");
  }
  {
    auto url = ada::parse<TypeParam>("https://user:pass@example.com");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
    ASSERT_EQ(url->get_href(), "https://user:pass@example.com/");
  }
  {
    auto url = ada::parse<TypeParam>("https://user:pass@example.com?q=1#f");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_pathname(), "/");
    ASSERT_EQ(url->get_search(), "?q=1");
    ASSERT_EQ(url->get_hash(), "#f");
    ASSERT_EQ(url->get_href(), "https://user:pass@example.com/?q=1#f");
  }
  // Encoding-needed userinfo must fall through (space is not copyable).
  {
    auto url = ada::parse<TypeParam>("https://user name@example.com/");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_username(), "user%20name");
  }
  assert_can_parse_consistent(
      "https://user:pass@www.example.com:8080/path/to/"
      "resource?foo=bar&baz=qux#section");
  assert_can_parse_consistent("https://user@example.com/x");
  assert_can_parse_consistent("https://@example.com/");
  assert_can_parse_consistent("https://user:pass@example.com");
  // Empty port after userinfo (`host://`) must not keep the colon.
  assert_can_parse_consistent("https://htt@ps://example.com/ath?q=1/.?x/./x");
  assert_can_parse_consistent("https://e@ample.com:0080/x");
  {
    auto url = ada::parse<TypeParam>("https://e@ample.com:0080/x");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_port(), "80");
    ASSERT_EQ(std::string(url->get_href()), "https://e@ample.com:80/x");
  }
  {
    auto url =
        ada::parse<TypeParam>("https://htt@ps://example.com/ath?q=1/.?x/./x");
    ASSERT_TRUE(url);
    ASSERT_EQ(std::string(url->get_href()),
              std::string(ada::parse<ada::url_aggregator>(
                              "https://htt@ps://example.com/ath?q=1/.?x/./x")
                              ->get_href()));
  }
  // 8-byte scheme match + 32-byte host window (BBC-style CDN hosts).
  {
    auto url = ada::parse<TypeParam>(
        "https://abcdefghijklmnopqrstuvwxyz.com/0123456789abcdef0123456789");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "abcdefghijklmnopqrstuvwxyz.com");
    ASSERT_EQ(url->get_pathname(), "/0123456789abcdef0123456789");
  }
  {
    auto url = ada::parse<TypeParam>("ws://example.com/chat");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_protocol(), "ws:");
  }
  // 'x' in the path must not force an xn-- reject of a clean host.
  {
    auto url = ada::parse<TypeParam>("https://example.com/xn--path");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "example.com");
    ASSERT_EQ(url->get_pathname(), "/xn--path");
  }
  // Uppercase in the path of a short host must not lowercase the path.
  {
    auto url = ada::parse<TypeParam>("https://ex.com/FooBar");
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_hostname(), "ex.com");
    ASSERT_EQ(url->get_pathname(), "/FooBar");
    ASSERT_EQ(url->get_href(), "https://ex.com/FooBar");
  }
  {
    ASSERT_TRUE(ada::can_parse("https://foo_bar.com/"));
    ASSERT_TRUE(ada::can_parse("https://foo~bar.com/"));
    ASSERT_TRUE(ada::can_parse("https://foo-bar.com/"));
    ASSERT_TRUE(ada::can_parse("http://ab.cd.ef/"));
    // SWAR must not treat "./" or "_^" as eight clean host bytes.
    ASSERT_FALSE(ada::can_parse("https://foo_^bar.com/"));
    ASSERT_FALSE(ada::parse<TypeParam>("https://foo_^bar.com/"));
    assert_can_parse_consistent("https://foo_^bar.com/");
    assert_can_parse_consistent("https://x./xxxxx");
    assert_can_parse_consistent("file://");
    assert_can_parse_consistent("file://p");
    assert_can_parse_consistent("abcd://");
    assert_can_parse_consistent("xxxx://");
  }
  {
    auto u = ada::parse<TypeParam>("https://example.com/a%20b/c%2Fd");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_pathname(), "/a%20b/c%2Fd");
    ASSERT_EQ(u->get_href(), "https://example.com/a%20b/c%2Fd");
  }
  {
    auto u = ada::parse<TypeParam>("http://example.com:80/x");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_port(), "");
    ASSERT_EQ(u->get_href(), "http://example.com/x");
  }
  {
    auto u = ada::parse<TypeParam>("https://example.com:443");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_port(), "");
    ASSERT_EQ(u->get_href(), "https://example.com/");
  }
  {
    auto u = ada::parse<TypeParam>("http://example.com:8080/x?y#z");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_port(), "8080");
    ASSERT_EQ(u->get_href(), "http://example.com:8080/x?y#z");
  }
  {
    auto u = ada::parse<TypeParam>("https://example.com:0080/x");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_port(), "80");
    ASSERT_EQ(u->get_href(), "https://example.com:80/x");
  }
  {
    auto u = ada::parse<TypeParam>("http://example.com:0080/x");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_port(), "");
    ASSERT_EQ(u->get_href(), "http://example.com/x");
  }
  {
    auto base = ada::parse<TypeParam>("https://example.com/a/b?old#old");
    ASSERT_TRUE(base);
    auto path = ada::parse<TypeParam>("/c/d?q=1#f", &*base);
    ASSERT_TRUE(path);
    ASSERT_EQ(path->get_href(), "https://example.com/c/d?q=1#f");
    auto query = ada::parse<TypeParam>("?new", &*base);
    ASSERT_TRUE(query);
    ASSERT_EQ(query->get_href(), "https://example.com/a/b?new");
    auto qmark_query = ada::parse<TypeParam>("??a=b&c=d", &*base);
    ASSERT_TRUE(qmark_query);
    ASSERT_EQ(qmark_query->get_search(), "??a=b&c=d");
    ASSERT_EQ(qmark_query->get_href(), "https://example.com/a/b??a=b&c=d");
    auto hash = ada::parse<TypeParam>("#new", &*base);
    ASSERT_TRUE(hash);
    ASSERT_EQ(hash->get_href(), "https://example.com/a/b?old#new");
    auto rel = ada::parse<TypeParam>("c/d?q", &*base);
    ASSERT_TRUE(rel);
    ASSERT_EQ(rel->get_href(), "https://example.com/a/c/d?q");
  }
  SUCCEED();
}

TEST(basic_tests, try_parse_simple_absolute_ada_url) {
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/path?q=1#f"), u));
    ASSERT_EQ(u.get_href(), "https://example.com/path?q=1#f");
    ASSERT_EQ(u.get_hostname(), "example.com");
    ASSERT_EQ(u.get_pathname(), "/path");
    ASSERT_EQ(u.get_search(), "?q=1");
    ASSERT_EQ(u.get_hash(), "#f");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://EXAMPLE.COM"), u));
    ASSERT_EQ(u.get_hostname(), "example.com");
    ASSERT_EQ(u.get_pathname(), "/");
    ASSERT_EQ(u.get_href(), "http://example.com/");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://example.com:8080/x"), u));
    ASSERT_EQ(u.get_port(), "8080");
    ASSERT_EQ(u.get_href(), "http://example.com:8080/x");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://example.com:80/x"), u));
    ASSERT_EQ(u.get_port(), "");
    ASSERT_EQ(u.get_href(), "http://example.com/x");
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://192.168.1.1/x"), u));
    ASSERT_EQ(u.get_hostname(), "192.168.1.1");
    ASSERT_EQ(u.host_type, ada::IPV4);
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("http://user@example.com/x"), u));
    ASSERT_EQ(u.get_username(), "user");
    ASSERT_EQ(u.get_href(), "http://user@example.com/x");
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("http:////example.com/x"), u));
  }
  {
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/foo/../bar"), u));
    ASSERT_EQ(u.get_pathname(), "/bar");
    ASSERT_EQ(u.get_href(), "https://example.com/bar");
  }
  {
    // Host contains 'x' but is not punycode; long query exercises the
    // 32-byte scan unroll; .css is not a dot-segment.
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view(
            "https://example.com/style.css?q=abcdefghijklmnopqrstuvwxyz012345"),
        u));
    ASSERT_EQ(u.get_pathname(), "/style.css");
    ASSERT_EQ(u.get_search(), "?q=abcdefghijklmnopqrstuvwxyz012345");
  }
  {
    // "/." after a 16-byte path prefix so the SIMD window and tail agree.
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/0123456789abcdef/./x"), u));
    ASSERT_EQ(u.get_pathname(), "/0123456789abcdef/x");
  }
  {
    ada::url u;
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://xn--nxasmq6b.com/"), u));
  }
  {
    // Overlapping last-16 path: first path byte is '.' and the '/' before
    // it is outside the SIMD valid mask.
    ada::url u;
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://example.com/./a"), u));
    ASSERT_EQ(u.get_pathname(), "/a");
    ASSERT_EQ(u.get_href(), "https://example.com/a");
  }
  {
    ada::url u;
    ASSERT_TRUE(
        ada::parser::try_parse_simple_absolute(std::string_view("ws://x"), u));
    ASSERT_EQ(u.get_href(), "ws://x/");
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("ftp://example.com/f"), u));
    ASSERT_EQ(u.get_href(), "ftp://example.com/f");
    ASSERT_TRUE(ada::parser::try_parse_simple_absolute(
        std::string_view("wss://example.com/c"), u));
    ASSERT_EQ(u.get_href(), "wss://example.com/c");
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("https:///extra"), u));
    ASSERT_FALSE(ada::parser::try_parse_simple_absolute(
        std::string_view("https://"), u));
  }
}

TEST(basic_tests, ada_url_get_href_assembly) {
  {
    auto u = ada::parse<ada::url>("https://example.com/path?q=1#f");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_href(), "https://example.com/path?q=1#f");
    ASSERT_EQ(u->get_href_size(), u->get_href().size());
  }
  {
    auto u = ada::parse<ada::url>("https://example.com:8080/x");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_href(), "https://example.com:8080/x");
    ASSERT_EQ(u->get_href_size(), u->get_href().size());
  }
  {
    auto u = ada::parse<ada::url>("https://user:pass@example.com/x");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_href(), "https://user:pass@example.com/x");
    ASSERT_EQ(u->get_href_size(), u->get_href().size());
  }
  {
    auto u = ada::parse<ada::url>("http://example.com/path");
    ASSERT_TRUE(u);
    ASSERT_EQ(u->get_href(), "http://example.com/path");
    ASSERT_EQ(u->get_href_size(), u->get_href().size());
  }
}

TEST(basic_tests, last_label_may_be_a_number_cases) {
  using ada::checkers::is_ipv4_number_char;
  using ada::checkers::last_label_may_be_a_number;
  ASSERT_FALSE(is_ipv4_number_char('m'));
  ASSERT_FALSE(is_ipv4_number_char('g'));
  ASSERT_FALSE(is_ipv4_number_char('t'));
  ASSERT_TRUE(is_ipv4_number_char('e'));
  ASSERT_TRUE(is_ipv4_number_char('c'));
  ASSERT_TRUE(is_ipv4_number_char('x'));
  ASSERT_TRUE(is_ipv4_number_char('X'));
  ASSERT_TRUE(is_ipv4_number_char('A'));
  ASSERT_TRUE(is_ipv4_number_char('F'));
  ASSERT_TRUE(is_ipv4_number_char('9'));
  ASSERT_TRUE(is_ipv4_number_char('0'));
  ASSERT_FALSE(is_ipv4_number_char('.'));
  ASSERT_FALSE(is_ipv4_number_char('z'));
  ASSERT_TRUE(ada::checkers::ends_with_dot_com("example.com", 11));
  ASSERT_TRUE(ada::checkers::ends_with_dot_com("example.COM.", 12));
  ASSERT_FALSE(ada::checkers::ends_with_dot_com("example.org", 11));
  ASSERT_FALSE(last_label_may_be_a_number(""));
  ASSERT_FALSE(last_label_may_be_a_number("."));
  ASSERT_FALSE(last_label_may_be_a_number("example.com"));
  ASSERT_FALSE(last_label_may_be_a_number("example.com."));
  ASSERT_FALSE(last_label_may_be_a_number("example.COM"));
  ASSERT_FALSE(last_label_may_be_a_number("www.google.com"));
  ASSERT_FALSE(last_label_may_be_a_number("wikipedia.org"));
  ASSERT_FALSE(last_label_may_be_a_number("foo.gov"));
  ASSERT_FALSE(last_label_may_be_a_number("foo.edu"));
  ASSERT_FALSE(last_label_may_be_a_number("abc."));
  ASSERT_TRUE(last_label_may_be_a_number("foo.123"));
  ASSERT_TRUE(last_label_may_be_a_number("foo.123."));
  ASSERT_TRUE(last_label_may_be_a_number("0x10"));
  ASSERT_TRUE(last_label_may_be_a_number("0xffffffff"));
  ASSERT_TRUE(last_label_may_be_a_number("foo.0xA"));
  ASSERT_TRUE(last_label_may_be_a_number("192.168.1.1"));
  ASSERT_TRUE(last_label_may_be_a_number("0x"));
  ASSERT_FALSE(last_label_may_be_a_number("123abc.com"));
  ASSERT_FALSE(last_label_may_be_a_number("abc"));
  ASSERT_FALSE(last_label_may_be_a_number("foo.x10"));
  ASSERT_FALSE(last_label_may_be_a_number("foo.bar.baz"));
  ASSERT_TRUE(last_label_may_be_a_number("19%2E68.1.10."));
  ASSERT_TRUE(last_label_may_be_a_number("19.68.1.10."));
  ASSERT_TRUE(last_label_may_be_a_number("0xffffffff."));
}

TYPED_TEST(basic_tests, aggregator_href_buffer_reuse) {
  // Successive parses must not leak a previous href into a later URL.
  const char* long_url =
      "https://this-is-a-long-hostname.example.com/"
      "abcdefghijklmnopqrstuvwxyz0123456789/path?q=1#frag";
  for (int i = 0; i < 8; ++i) {
    auto url = ada::parse<TypeParam>(long_url);
    ASSERT_TRUE(url);
    ASSERT_EQ(url->get_href(), long_url);
  }
  auto short_url = ada::parse<TypeParam>("https://example.com/x");
  ASSERT_TRUE(short_url);
  ASSERT_EQ(short_url->get_href(), "https://example.com/x");
  ASSERT_EQ(short_url->get_hostname(), "example.com");
}

TYPED_TEST(basic_tests,
           absolute_fast_path_strips_tab_newline_and_trailing_space) {
  // The absolute fast path must remove ASCII tab/newline and trim a trailing
  // C0 control or space just like the general parser; a query or fragment that
  // reaches the fast path's percent-encoding helpers must not keep those bytes
  // as %09/%0A/%20.
  auto check = [](std::string_view input, std::string_view expected) {
    auto r = ada::parse<TypeParam>(input);
    ASSERT_TRUE(r);
    ASSERT_EQ(r->get_href(), expected);
  };
  check("wss://ab?x\n9", "wss://ab/?x9");
  check("http://ab?a\tb", "http://ab/?ab");
  check("wss://ab?x9 ", "wss://ab/?x9");
  check("http://ab#f\ng", "http://ab/#fg");
  check("http://ab#f ", "http://ab/#f");
  check("http://ab/p ", "http://ab/p");
  // with an explicit port (finish_simple_absolute_with_port)
  check("http://ab:81?x\n9", "http://ab:81/?x9");
  check("http://ab:81/p?x\ty#h", "http://ab:81/p?xy#h");
  check("http://ab:81#f ", "http://ab:81/#f");
  // a byte that legitimately needs encoding is still encoded
  check("http://ab?x y", "http://ab/?x%20y");
}

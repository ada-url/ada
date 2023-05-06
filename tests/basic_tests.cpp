#include "ada.h"
#include "gtest/gtest.h"
#include <cstdlib>
#include <iostream>

using Types = testing::Types<ada::url, ada::url_aggregator>;
template <class T>
struct basic_tests : testing::Test {};
TYPED_TEST_SUITE(basic_tests, Types);

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

TYPED_TEST(basic_tests, readme2) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_username("username");
  url->set_password("password");
  ASSERT_EQ(url->get_href(), "https://username:password@www.google.com/");
  SUCCEED();
}

TYPED_TEST(basic_tests, readme3) {
  auto url = ada::parse<TypeParam>("https://www.google.com");
  url->set_protocol("wss");
  ASSERT_EQ(url->get_protocol(), "wss:");
  ASSERT_EQ(url->get_href(), "wss://www.google.com/");
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
  ASSERT_EQ(url->get_pathname(), "space");
  ASSERT_EQ(url->get_href(), "data:space");
  SUCCEED();
}

TYPED_TEST(basic_tests, nodejs3) {
  auto url = ada::parse<TypeParam>("data:space    ?test#test");
  ASSERT_EQ(url->get_search(), "?test");
  url->set_search("");
  ASSERT_EQ(url->get_search(), "");
  ASSERT_EQ(url->get_pathname(), "space    ");
  ASSERT_EQ(url->get_href(), "data:space    #test");
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
  auto url = ada::parse<TypeParam>("..#", &*urlbase);
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->has_opaque_path);
  ASSERT_EQ(url->get_href(), "a:b/#");
  ASSERT_EQ(url->get_pathname(), "b/");
  SUCCEED();
}

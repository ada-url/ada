#include "ada.h"
#include "gtest/gtest.h"
#include <cstdlib>
#include <iostream>

template <class result>
void set_host_should_return_false_sometimes() {
  ada::result<result> r = ada::parse<result>("mailto:a@b.com");
  ASSERT_FALSE(r->set_host("something"));
  auto r2 = ada::parse<result>("mailto:a@b.com");
  ASSERT_FALSE(r2->set_host("something"));
  SUCCEED();
}

template <class result>
void set_host_should_return_true_sometimes() {
  ada::result<result> r = ada::parse<result>("https://www.google.com");
  ASSERT_TRUE(r->set_host("something"));
  SUCCEED();
}

template <class result>
void set_hostname_should_return_false_sometimes() {
  ada::result<result> r = ada::parse<result>("mailto:a@b.com");
  ASSERT_FALSE(r->set_hostname("something"));
  SUCCEED();
}

template <class result>
void set_hostname_should_return_true_sometimes() {
  ada::result<result> r = ada::parse<result>("https://www.google.com");
  ASSERT_TRUE(r->set_hostname("something"));
  SUCCEED();
}

template <class result>
void readme1() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  ASSERT_TRUE(bool(url));
  SUCCEED();
}

template <class result>
void readme2() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_username("username");
  url->set_password("password");
  ASSERT_EQ(url->get_href(), "https://username:password@www.google.com/");
  SUCCEED();
}

template <class result>
void readme3() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_protocol("wss");
  ASSERT_EQ(url->get_protocol(), "wss:");
  ASSERT_EQ(url->get_href(), "wss://www.google.com/");
  SUCCEED();
}

template <class result>
void readme4() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_host("github.com");
  ASSERT_EQ(url->get_host(), "github.com");
  SUCCEED();
}

template <class result>
void readme5() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_port("8080");
  ASSERT_EQ(url->get_port(), "8080");
  SUCCEED();
}

template <class result>
void readme6() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_pathname("/my-super-long-path");
  ASSERT_EQ(url->get_pathname(), "/my-super-long-path");
  SUCCEED();
}

template <class result>
void readme7() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_search("target=self");
  ASSERT_EQ(url->get_search(), "?target=self");
  SUCCEED();
}

template <class result>
void readme8() {
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_hash("is-this-the-real-life");
  ASSERT_EQ(url->get_hash(), "#is-this-the-real-life");
  SUCCEED();
}

template <class result>
void nodejs1() {
  auto base = ada::parse<result>("http://other.com/");
  ASSERT_TRUE(base.has_value());
  auto url = ada::parse<result>("http://GOOgoo.com", &base.value());
  ASSERT_TRUE(url.has_value());
  SUCCEED();
}

template <class result>
void nodejs2() {
  auto url = ada::parse<result>("data:space    ?test");
  ASSERT_EQ(url->get_search(), "?test");
  url->set_search("");
  ASSERT_EQ(url->get_search(), "");
  ASSERT_EQ(url->get_pathname(), "space");
  ASSERT_EQ(url->get_href(), "data:space");
  SUCCEED();
}

template <class result>
void nodejs3() {
  auto url = ada::parse<result>("data:space    ?test#test");
  ASSERT_EQ(url->get_search(), "?test");
  url->set_search("");
  ASSERT_EQ(url->get_search(), "");
  ASSERT_EQ(url->get_pathname(), "space    ");
  ASSERT_EQ(url->get_href(), "data:space    #test");
  SUCCEED();
}

// https://github.com/nodejs/node/issues/46755
template <class result>
void nodejs4() {
  auto url = ada::parse<result>("file:///var/log/system.log");
  url->set_href("http://0300.168.0xF0");
  ASSERT_EQ(url->get_protocol(), "http:");
  ASSERT_EQ(url->get_href(), "http://192.168.0.240/");
  SUCCEED();
}

template <class result>
void empty_url() {
  auto url = ada::parse<result>("");
  ASSERT_FALSE(url);
  SUCCEED();
}

template <class result>
void just_hash() {
  auto url = ada::parse<result>("#x");
  ASSERT_FALSE(url);
  SUCCEED();
}

template <class result>
void empty_host_dash_dash_path() {
  auto url = ada::parse<result>("something:/.//");
  ASSERT_TRUE(url);
  ASSERT_FALSE(url->has_opaque_path);
  ASSERT_EQ(url->get_href(), "something:/.//");
  ASSERT_EQ(url->get_pathname(), "//");
  ASSERT_EQ(url->get_hostname(), "");
  SUCCEED();
}

template <class result>
void confusing_mess() {
  auto base_url = ada::parse<result>("http://example.org/foo/bar");
  ASSERT_TRUE(base_url);
  auto url = ada::parse<result>("http://::@c@d:2", &*base_url);
  ASSERT_TRUE(url);
  ASSERT_FALSE(url->has_opaque_path);
  ASSERT_EQ(url->get_hostname(), "d");
  ASSERT_EQ(url->get_host(), "d:2");
  ASSERT_EQ(url->get_pathname(), "/");
  ASSERT_EQ(url->get_href(), "http://:%3A%40c@d:2/");
  ASSERT_EQ(url->get_origin(), "http://d:2");
  SUCCEED();
}

template <class result>
void standard_file() {
  auto url = ada::parse<result>("file:///tmp/mock/path");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->has_empty_hostname());
  ASSERT_FALSE(url->has_opaque_path);
  ASSERT_EQ(url->get_pathname(), "/tmp/mock/path");
  ASSERT_EQ(url->get_hostname(), "");
  ASSERT_EQ(url->get_host(), "");
  ASSERT_EQ(url->get_href(), "file:///tmp/mock/path");
  SUCCEED();
}

template <class result>
void default_port_should_be_removed() {
  auto url = ada::parse<result>("http://www.google.com:443");
  ASSERT_TRUE(url);
  url->set_protocol("https");
  ASSERT_EQ(url->get_port(), "");
  ASSERT_EQ(url->get_host(), "www.google.com");
  SUCCEED();
}

template <class result>
void test_amazon() {
  auto url = ada::parse<result>("HTTP://AMAZON.COM");
  ASSERT_TRUE(url);
  ASSERT_EQ(url->get_href(), "http://amazon.com/");
  SUCCEED();
}

template <class result>
void remove_username() {
  auto url = ada::parse<result>("http://me@example.net");
  ASSERT_TRUE(url);
  url->set_username("");
  ASSERT_EQ(url->get_username(), "");
  ASSERT_EQ(url->get_href(), "http://example.net/");
  SUCCEED();
}

template <class result>
void remove_password() {
  auto url = ada::parse<result>("http://user:pass@example.net");
  ASSERT_TRUE(url);
  url->set_password("");
  ASSERT_EQ(url->get_password(), "");
  ASSERT_EQ(url->get_href(), "http://user@example.net/");
  SUCCEED();
}

template <class result>
void remove_password_with_empty_username() {
  auto url = ada::parse<result>("http://:pass@example.net");
  ASSERT_TRUE(url);
  url->set_password("");
  ASSERT_EQ(url->get_username(), "");
  ASSERT_EQ(url->get_password(), "");
  ASSERT_EQ(url->get_href(), "http://example.net/");
  SUCCEED();
}

template <class result>
void should_remove_dash_dot() {
  auto url = ada::parse<result>("non-spec:/.//p");
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

template <class result>
void should_remove_dash_dot_with_empty_hostname() {
  auto url = ada::parse<result>("non-spec:/.//p");
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

template <class result>
void should_add_dash_dot_on_pathname() {
  auto url = ada::parse<result>("non-spec:/");
  ASSERT_TRUE(url);
  url->set_pathname("//p");
  ASSERT_EQ(url->get_pathname(), "//p");
  ASSERT_EQ(url->get_href(), "non-spec:/.//p");
  SUCCEED();
}

template <class result>
void should_update_password_correctly() {
  auto url = ada::parse<result>(
      "https://username:password@host:8000/path?query#fragment");
  ASSERT_TRUE(url);
  ASSERT_TRUE(url->set_password("test"));
  ASSERT_EQ(url->get_password(), "test");
  ASSERT_EQ(url->get_href(),
            "https://username:test@host:8000/path?query#fragment");
  SUCCEED();
}

template <class result>
void all_tests() {
  confusing_mess<result>();
  standard_file<result>();
  empty_host_dash_dash_path<result>();
  just_hash<result>();
  empty_url<result>();
  default_port_should_be_removed<result>();
  remove_username<result>();
  remove_password<result>();
  remove_password_with_empty_username<result>();
  should_remove_dash_dot<result>();
  should_remove_dash_dot_with_empty_hostname<result>();
  should_add_dash_dot_on_pathname<result>();
  should_update_password_correctly<result>();
  set_host_should_return_false_sometimes<result>();
  set_host_should_return_true_sometimes<result>();
  set_hostname_should_return_false_sometimes<result>();
  set_hostname_should_return_true_sometimes<result>();
  readme1<result>();
  readme2<result>();
  readme3<result>();
  readme4<result>();
  readme5<result>();
  readme6<result>();
  readme7<result>();
  nodejs1<result>();
  nodejs2<result>();
  nodejs3<result>();
  nodejs4<result>();
  test_amazon<result>();
}

int main() {
  all_tests<ada::url>();
  all_tests<ada::url_aggregator>();
}

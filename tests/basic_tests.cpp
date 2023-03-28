#include "ada.h"

#include <cstdlib>
#include <iostream>

#define TEST_START()                                              \
  do {                                                            \
    std::cout << "> Running " << __func__ << " ..." << std::endl; \
  } while (0);
#define RUN_TEST(ACTUAL) \
  do {                   \
    if (!(ACTUAL)) {     \
      return false;      \
    }                    \
  } while (0);
#define TEST_FAIL(MESSAGE)                           \
  do {                                               \
    std::cerr << "FAIL: " << (MESSAGE) << std::endl; \
    return false;                                    \
  } while (0);
#define TEST_SUCCEED() \
  do {                 \
    return true;       \
  } while (0);
#define TEST_ASSERT(LHS, RHS, MESSAGE)                                         \
  do {                                                                         \
    if (LHS != RHS) {                                                          \
      std::cerr << "Mismatch: '" << LHS << "' - '" << RHS << "'" << std::endl; \
      TEST_FAIL(MESSAGE);                                                      \
    }                                                                          \
  } while (0);

template <class result>
bool set_host_should_return_false_sometimes() {
  TEST_START()
  ada::result<result> r = ada::parse<result>("mailto:a@b.com");
  bool b = r->set_host("something");
  TEST_ASSERT(b, false, "set_host should return false")
  //
  auto r2 = ada::parse<result>("mailto:a@b.com");
  bool b2 = r2->set_host("something");
  TEST_ASSERT(b2, false, "set_host should return false")
  TEST_SUCCEED()
}

template <class result>
bool set_host_should_return_true_sometimes() {
  TEST_START()
  ada::result<result> r = ada::parse<result>("https://www.google.com");
  bool b = r->set_host("something");
  TEST_ASSERT(b, true, "set_host should return true")
  TEST_SUCCEED()
}

template <class result>
bool set_hostname_should_return_false_sometimes() {
  TEST_START()
  ada::result<result> r = ada::parse<result>("mailto:a@b.com");
  bool b = r->set_hostname("something");
  TEST_ASSERT(b, false, "set_hostname should return false")
  TEST_SUCCEED()
}

template <class result>
bool set_hostname_should_return_true_sometimes() {
  TEST_START()
  ada::result<result> r = ada::parse<result>("https://www.google.com");
  bool b = r->set_hostname("something");
  TEST_ASSERT(b, true, "set_hostname should return true")
  TEST_SUCCEED()
}

template <class result>
bool readme1() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  TEST_ASSERT(bool(url), true, "URL is valid")
  TEST_SUCCEED()
}

template <class result>
bool readme2() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_username("username");
  url->set_password("password");
  TEST_ASSERT(url->get_href(), "https://username:password@www.google.com/",
              "href returned bad result")
  TEST_SUCCEED()
}

template <class result>
bool readme3() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_protocol("wss");
  TEST_ASSERT(url->get_protocol(), "wss:", "get_protocol returned bad result")
  TEST_ASSERT(url->get_href(), "wss://www.google.com/",
              "get_href returned bad result")

  TEST_SUCCEED()
}

template <class result>
bool readme4() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_host("github.com");
  TEST_ASSERT(url->get_host(), "github.com", "get_host returned bad result")
  TEST_SUCCEED()
}

template <class result>
bool readme5() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_port("8080");
  TEST_ASSERT(url->get_port(), "8080", "get_port returned bad result")
  TEST_SUCCEED()
}

template <class result>
bool readme6() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_pathname("/my-super-long-path");
  TEST_ASSERT(url->get_pathname(), "/my-super-long-path",
              "get_pathname returned bad result")
  TEST_SUCCEED()
}

template <class result>
bool readme7() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_search("target=self");
  TEST_ASSERT(url->get_search(), "?target=self",
              "get_pathname returned bad result");
  TEST_SUCCEED()
}

template <class result>
bool readme8() {
  TEST_START()
  ada::result<result> url = ada::parse<result>("https://www.google.com");
  url->set_hash("is-this-the-real-life");
  TEST_ASSERT(url->get_hash(), "#is-this-the-real-life",
              "get_hash returned bad result");
  TEST_SUCCEED()
}

template <class result>
bool nodejs1() {
  TEST_START()
  auto base = ada::parse<result>("http://other.com/");
  TEST_ASSERT(base.has_value(), true, "base should have a value");
  auto url = ada::parse<result>("http://GOOgoo.com", &base.value());
  TEST_ASSERT(url.has_value(), true, "root should have a value");
  TEST_SUCCEED()
}

template <class result>
bool nodejs2() {
  TEST_START()
  auto url = ada::parse<result>("data:space    ?test");
  TEST_ASSERT(url->get_search(), "?test", "search is not equal");
  url->set_search("");
  TEST_ASSERT(url->get_search(), "", "search should have been empty");
  TEST_ASSERT(url->get_pathname(), "space",
              "pathname should have been 'space' without trailing spaces");
  TEST_ASSERT(url->get_href(), "data:space", "href is not equal");
  TEST_SUCCEED()
}

template <class result>
bool nodejs3() {
  TEST_START()
  auto url = ada::parse<result>("data:space    ?test#test");
  TEST_ASSERT(url->get_search(), "?test", "search is not equal");
  url->set_search("");
  TEST_ASSERT(url->get_search(), "", "search should have been empty");
  TEST_ASSERT(url->get_pathname(), "space    ",
              "pathname should have been 'space' without trailing spaces");
  TEST_ASSERT(url->get_href(), "data:space    #test", "href is not equal");
  TEST_SUCCEED()
}

// https://github.com/nodejs/node/issues/46755
template <class result>
bool nodejs4() {
  TEST_START()
  auto url = ada::parse<result>("file:///var/log/system.log");
  url->set_href("http://0300.168.0xF0");
  TEST_ASSERT(url->get_protocol(),
              "http:", "protocol should have been updated");
  TEST_ASSERT(url->get_href(), "http://192.168.0.240/",
              "href should have been updated");
  TEST_SUCCEED()
}

template <class result>
bool empty_url() {
  TEST_START()
  auto url = ada::parse<result>("");
  if (url) {
    TEST_FAIL("Should not succeed on base-less empty URL.");
  }
  TEST_SUCCEED()
}

template <class result>
bool just_hash() {
  TEST_START()
  auto url = ada::parse<result>("#x");
  if (url) {
    TEST_FAIL("Should not succeed on base-less hash url.");
  }
  TEST_SUCCEED()
}

template <class result>
bool empty_host_dash_dash_path() {
  TEST_START()
  auto url = ada::parse<result>("something:/.//");
  if (!url) {
    TEST_FAIL("Should succeed");
  }
  TEST_ASSERT(url->has_opaque_path, false, "path is not opaque");
  TEST_ASSERT(url->get_href(), "something:/.//", "href should stay unchanged");
  TEST_ASSERT(url->get_pathname(), "//", "path name should be //")
  TEST_ASSERT(url->get_hostname(), "", "host should be empty")
  TEST_SUCCEED()
}

template <class result>
bool confusing_mess() {
  TEST_START()
  auto base_url = ada::parse<result>("http://example.org/foo/bar");
  if (!base_url) {
    TEST_FAIL("Should succeed");
  }
  auto url = ada::parse<result>("http://::@c@d:2", &*base_url);
  if (!url) {
    TEST_FAIL("Should succeed");
  }
  TEST_ASSERT(url->has_opaque_path, false, "path is not opaque");
  TEST_ASSERT(url->get_hostname(), "d", "bad hostname")
  TEST_ASSERT(url->get_host(), "d:2", "bad host")
  TEST_ASSERT(url->get_pathname(), "/", "bad path")
  TEST_ASSERT(url->get_href(), "http://:%3A%40c@d:2/", "bad href");
  TEST_ASSERT(url->get_origin(), "http://d:2", "bad origin")

  TEST_SUCCEED()
}

template <class result>
bool standard_file() {
  TEST_START()
  auto url = ada::parse<result>("file:///tmp/mock/path");
  if (!url) {
    TEST_FAIL("Should succeed");
  }
  std::cout << url->to_string() << std::endl;
  TEST_ASSERT(url->has_empty_hostname(), true, "path is not opaque");
  TEST_ASSERT(url->has_opaque_path, false, "path is not opaque");
  TEST_ASSERT(url->get_pathname(), "/tmp/mock/path",
              "path name should be /tmp/mock/path")
  TEST_ASSERT(url->get_hostname(), "", "host should be empty")
  TEST_ASSERT(url->get_host(), "", "host should be empty")
  TEST_ASSERT(url->get_href(), "file:///tmp/mock/path",
              "href should stay unchanged");
  TEST_SUCCEED()
}

template <class result>
bool all_tests() {
  return confusing_mess<result>() && standard_file<result>() &&
         empty_host_dash_dash_path<result>() && just_hash<result>() &&
         empty_url<result>() &&
         set_host_should_return_false_sometimes<result>() &&
         set_host_should_return_true_sometimes<result>() &&
         set_hostname_should_return_false_sometimes<result>() &&
         set_hostname_should_return_true_sometimes<result>() &&
         readme1<result>() && readme2<result>() && readme3<result>() &&
         readme4<result>() && readme5<result>() && readme6<result>() &&
         readme7<result>() && nodejs1<result>() && nodejs2<result>() &&
         nodejs3<result>() && nodejs4<result>();
}

int main() {
#if ADA_IS_BIG_ENDIAN
  std::cout << "You have big-endian system." << std::endl;
#else
  std::cout << "You have litte-endian system." << std::endl;
#endif
  bool success = all_tests<ada::url>() && all_tests<ada::url_aggregator>();
  if (success) {
    return EXIT_SUCCESS;
  }
  return EXIT_FAILURE;
}

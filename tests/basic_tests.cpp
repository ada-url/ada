#include "ada.h"

#include <cstdlib>
#include <iostream>

#define TEST_START()                                                           \
  do {                                                                         \
    std::cout << "> Running " << __func__ << " ..." << std::endl;              \
  } while (0);
#define RUN_TEST(ACTUAL)                                                       \
  do {                                                                         \
    if (!(ACTUAL)) {                                                           \
      return false;                                                            \
    }                                                                          \
  } while (0);
#define TEST_FAIL(MESSAGE)                                                     \
  do {                                                                         \
    std::cerr << "FAIL: " << (MESSAGE) << std::endl;                           \
    return false;                                                              \
  } while (0);
#define TEST_SUCCEED()                                                         \
  do {                                                                         \
    return true;                                                               \
  } while (0);
#define TEST_ASSERT(LHS, RHS, MESSAGE)                                         \
  do {                                                                         \
    if (LHS != RHS)  {                                                         \
      std::cerr << "Mismatch: '" << LHS << "' - '" << RHS << "'" << std::endl; \
      TEST_FAIL(MESSAGE);                                                      \
    }                                                                          \
  } while (0);                                                                 \


bool set_host_should_return_false_sometimes() {
    TEST_START()
    ada::result<ada::url> r = ada::parse("mailto:a@b.com");
    bool b = r->set_host("something");
    TEST_ASSERT(b, false, "set_host should return false")
    TEST_SUCCEED() 
}

bool set_host_should_return_true_sometimes() {
    TEST_START()
    ada::result<ada::url> r = ada::parse("https://www.google.com");
    bool b = r->set_host("something");
    TEST_ASSERT(b, true, "set_host should return true")
    TEST_SUCCEED() 
}


bool set_hostname_should_return_false_sometimes() {
    TEST_START()
    ada::result<ada::url> r = ada::parse("mailto:a@b.com");
    bool b = r->set_hostname("something");
    TEST_ASSERT(b, false, "set_hostname should return false")
    TEST_SUCCEED() 
}

bool set_hostname_should_return_true_sometimes() {
    TEST_START()
    ada::result<ada::url> r = ada::parse("https://www.google.com");
    bool b = r->set_hostname("something");
    TEST_ASSERT(b, true, "set_hostname should return true")
    TEST_SUCCEED() 
}

bool readme1() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    TEST_ASSERT(bool(url), true, "URL is valid")
    TEST_SUCCEED() 
}

bool readme2() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    url->set_username("username");
    url->set_password("password");
    TEST_ASSERT(url->get_href(), "https://username:password@www.google.com/", "href returned bad result")
    TEST_SUCCEED() 
}

bool readme3() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    url->set_protocol("wss");
    TEST_ASSERT(url->get_protocol(), "wss:", "get_protocol returned bad result")
    TEST_ASSERT(url->get_href(), "wss://www.google.com/", "get_href returned bad result")

    TEST_SUCCEED() 
}

bool readme4() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    url->set_host("github.com");
    TEST_ASSERT(url->get_host(), "github.com", "get_host returned bad result")
    TEST_SUCCEED() 
}

bool readme5() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    url->set_port("8080");
    TEST_ASSERT(url->get_port(), "8080", "get_port returned bad result")
    TEST_SUCCEED() 
}

bool readme6() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    url->set_pathname("/my-super-long-path");
    TEST_ASSERT(url->get_pathname(), "/my-super-long-path", "get_pathname returned bad result")
    TEST_SUCCEED() 
}

bool readme7() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    url->set_search("target=self");
    TEST_ASSERT(url->get_search(), "?target=self", "get_pathname returned bad result");
    TEST_SUCCEED() 
}

bool readme8() {
    TEST_START()
    ada::result<ada::url> url = ada::parse("https://www.google.com");
    url->set_hash("is-this-the-real-life");
    TEST_ASSERT(url->get_hash(), "#is-this-the-real-life", "get_hash returned bad result");
    TEST_SUCCEED() 
}

bool nodejs1() {
  TEST_START()
  auto base = ada::parse("http://other.com/");
  TEST_ASSERT(base.has_value(), true, "base should have a value");
  auto url = ada::parse("http://GOOgoo.com", &base.value());
  TEST_ASSERT(url.has_value(), true, "root should have a value");
  TEST_SUCCEED()
}

bool nodejs2() {
  TEST_START()
  auto url = ada::parse("data:space    ?test");
  TEST_ASSERT(url->get_search(), "?test", "search is not equal");
  url->set_search("");
  TEST_ASSERT(url->get_search(), "", "search should have been empty");
  TEST_ASSERT(url->get_pathname(), "space", "pathname should have been 'space' without trailing spaces");
  TEST_ASSERT(url->get_href(), "data:space", "href is not equal");
  TEST_SUCCEED()
}

bool nodejs3() {
  TEST_START()
  auto url = ada::parse("data:space    ?test#test");
  TEST_ASSERT(url->get_search(), "?test", "search is not equal");
  url->set_search("");
  TEST_ASSERT(url->get_search(), "", "search should have been empty");
  TEST_ASSERT(url->get_pathname(), "space    ", "pathname should have been 'space' without trailing spaces");
  TEST_ASSERT(url->get_href(), "data:space    #test", "href is not equal");
  TEST_SUCCEED()
}

// https://github.com/nodejs/node/issues/46755
bool nodejs4() {
  TEST_START()
  auto url = ada::parse("file:///var/log/system.log");
  url->set_href("http://0300.168.0xF0");
  TEST_ASSERT(url->get_protocol(), "http:", "protocol should have been updated");
  TEST_ASSERT(url->get_href(), "http://192.168.0.240/", "href should have been updated");
  TEST_SUCCEED()
}

bool empty_url() {
  TEST_START()
  auto url = ada::parse("");
  if(url) {
    TEST_FAIL("Should not succeed on base-less empty URL.");
  }
  TEST_SUCCEED()
}

bool just_hash() {
  TEST_START()
  auto url = ada::parse("#x");
  if(url) {
    TEST_FAIL("Should not succeed on base-less hash url.");
  }
  TEST_SUCCEED()
}

template <class result>
bool empty_host_dash_dash_path() {
  TEST_START()
  auto url = ada::parse<result>("something:/.//");
  if(!url) {
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
  if(!base_url) {
    TEST_FAIL("Should succeed");
  }
  auto url = ada::parse<result>("http://::@c@d:2", &*base_url);
  if(!url) {
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
  if(!url) {
    TEST_FAIL("Should succeed");
  }
  std::cout << url->to_string() << std::endl;
  TEST_ASSERT(url->has_hostname(), true, "path is not opaque");
  TEST_ASSERT(url->has_empty_hostname(), true, "path is not opaque");
  TEST_ASSERT(url->has_opaque_path, false, "path is not opaque");
  TEST_ASSERT(url->get_pathname(), "/tmp/mock/path", "path name should be /tmp/mock/path")
  TEST_ASSERT(url->get_hostname(), "", "host should be empty")
  TEST_ASSERT(url->get_host(), "", "host should be empty")
  TEST_ASSERT(url->get_href(), "file:///tmp/mock/path", "href should stay unchanged");
  TEST_SUCCEED()
}




int main() {
#if ADA_HAS_ICU
  std::cout << "We are using ICU."<< std::endl;
#else
  std::cout << "We are not using ICU."<< std::endl;
#endif
#if ADA_IS_BIG_ENDIAN
  std::cout << "You have big-endian system."<< std::endl;
#else
  std::cout << "You have litte-endian system."<< std::endl;
#endif
  bool success = confusing_mess<ada::url>()
     && confusing_mess<ada::url_aggregator>()
     && standard_file<ada::url_aggregator>()
     && standard_file<ada::url>()
     && empty_host_dash_dash_path<ada::url_aggregator>()
     && empty_host_dash_dash_path<ada::url>()
     && just_hash() && empty_url()
     && set_host_should_return_false_sometimes()
     && set_host_should_return_true_sometimes()
     && set_hostname_should_return_false_sometimes()
     && set_hostname_should_return_true_sometimes()
     && readme1() && readme2() && readme3() 
     && readme4() && readme5() && readme6()
     && readme7() && nodejs1() && nodejs2()
     && nodejs3() && nodejs4();
  if(success) { return EXIT_SUCCESS; }
  return EXIT_FAILURE;
}

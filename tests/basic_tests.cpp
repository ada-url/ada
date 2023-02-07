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
    ada::result r = ada::parse("mailto:a@b.com");
    bool b = r->set_host("something");
    TEST_ASSERT(b, false, "set_host should return false")
    TEST_SUCCEED() 
}

bool set_host_should_return_true_sometimes() {
    TEST_START()
    ada::result r = ada::parse("https://www.google.com");
    bool b = r->set_host("something");
    TEST_ASSERT(b, true, "set_host should return true")
    TEST_SUCCEED() 
}


bool set_hostname_should_return_false_sometimes() {
    TEST_START()
    ada::result r = ada::parse("mailto:a@b.com");
    bool b = r->set_hostname("something");
    TEST_ASSERT(b, false, "set_hostname should return false")
    TEST_SUCCEED() 
}

bool set_hostname_should_return_true_sometimes() {
    TEST_START()
    ada::result r = ada::parse("https://www.google.com");
    bool b = r->set_hostname("something");
    TEST_ASSERT(b, true, "set_hostname should return true")
    TEST_SUCCEED() 
}

bool readme1() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
    TEST_ASSERT(bool(url), true, "URL is valid")
    TEST_SUCCEED() 
}

bool readme2() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
    url->set_username("username");
    url->set_password("password");
    TEST_ASSERT(url->get_href(), "https://username:password@www.google.com/", "href returned bad result")
    TEST_SUCCEED() 
}

bool readme3() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
    url->set_protocol("wss");
    TEST_ASSERT(url->get_protocol(), "wss:", "get_protocol returned bad result")
    TEST_ASSERT(url->get_href(), "wss://www.google.com/", "get_href returned bad result")

    TEST_SUCCEED() 
}

bool readme4() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
    url->set_host("github.com");
    TEST_ASSERT(url->get_host(), "github.com", "get_host returned bad result")
    TEST_SUCCEED() 
}

bool readme5() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
    url->set_port("8080");
    TEST_ASSERT(url->get_port(), "8080", "get_port returned bad result")
    TEST_SUCCEED() 
}

bool readme6() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
    url->set_pathname("/my-super-long-path");
    TEST_ASSERT(url->get_pathname(), "/my-super-long-path", "get_pathname returned bad result")
    TEST_SUCCEED() 
}

bool readme7() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
    url->set_search("target=self");
    TEST_ASSERT(url->get_search(), "?target=self", "get_pathname returned bad result");
    TEST_SUCCEED() 
}

bool readme8() {
    TEST_START()
    ada::result url = ada::parse("https://www.google.com");
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

int main() {
    bool success = set_host_should_return_false_sometimes()
     && set_host_should_return_true_sometimes()
     && set_hostname_should_return_false_sometimes()
     && set_hostname_should_return_true_sometimes()
     && readme1() && readme2() && readme3() 
     && readme4() && readme5() && readme6()
     && readme7() && nodejs1() && nodejs2()
     && nodejs3();
    if(success) { return EXIT_SUCCESS; }
    return EXIT_FAILURE;
}

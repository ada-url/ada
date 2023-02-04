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

int main() {
    bool success = set_host_should_return_false_sometimes()
     && set_host_should_return_true_sometimes();
    if(success) { return EXIT_SUCCESS; }
    return EXIT_FAILURE;
}
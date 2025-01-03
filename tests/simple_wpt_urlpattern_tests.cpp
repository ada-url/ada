#include <cstdlib>

#include "ada.h"



bool test() {
  auto tokenize_result = ada::url_pattern_helpers::tokenize();
  return tokenize_result.empty();
}

int main() {
    test();
    return EXIT_SUCCESS;
}
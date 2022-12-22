#include "ada.h"
#include "unicode.cpp"

#include <algorithm>

namespace ada::checkers {

  bool ends_in_a_number(std::string_view input) {
    // Let parts be the result of strictly splitting input on U+002E (.).
    std::vector<std::string_view> parts = ada::helpers::split_string_view(input, ".");

    // If the last item in parts is the empty string, then:
    if (parts.back().empty()) {
      // If parts’s size is 1, then return false.
      if (parts.size() == 1) {
        return false;
      }

      // Remove the last item from parts.
      parts.pop_back();
    }

    // Let last be the last item in parts.
    std::string_view last = parts.back();

    // If last is non-empty and contains only ASCII digits, then return true.
    if (!last.empty()) {
      auto non_ascii_digit = std::find_if(last.begin(), last.end(), [](char c) {
        return !ada::unicode::is_ascii_digit(c);
      });

      if (non_ascii_digit != last.end()) {
        return true;
      }
    }

    // If parsing last as an IPv4 number does not return failure, then return true.
    return std::get<0>(ada::parser::parse_ipv4_number(last)).has_value();
  }

} // namespace ada::checkers

#include "ada.h"
#include "unicode.cpp"

#include <algorithm>
#include <cstring>

namespace ada::checkers {

  // TODO: Refactor this to not use `std::vector` but use pointer arithmetic for performance.
  bool ends_in_a_number(const std::string_view input) noexcept {
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
      bool non_ascii_digit = std::any_of(last.begin(), last.end(), [](char c) {
        return std::isdigit(c);
      });

      if (non_ascii_digit) {
        return true;
      }
    }

    // If parsing last as an IPv4 number does not return failure, then return true.
    return ada::checkers::is_ipv4_number_valid(last);
  }

  // A Windows drive letter is two code points, of which the first is an ASCII alpha
  // and the second is either U+003A (:) or U+007C (|).
  bool is_windows_drive_letter(const std::string_view input) noexcept {
    return input.length() == 2 && std::isalpha(input[0]) && (input[1] == ':' || input[1] == '|');
  }

  // A normalized Windows drive letter is a Windows drive letter of which the second code point is U+003A (:).
  bool is_normalized_windows_drive_letter(const std::string_view input) noexcept {
    return is_windows_drive_letter(input) && input[1] == ':';
  }

  // TODO: Make the input const.
  bool is_ipv4_number_valid(std::string_view input) noexcept {
    // If input is the empty string, then return failure.
    if (input.empty()) {
      return false;
    }

    if (input.length() >= 2) {
      // If input contains at least two code points and the first two code points are either "0X" or "0x", then:
      if (input[0] == '0' && (input[1] == 'X' || input[1] == 'x')) {
        // Remove the first two code points from input.
        input.remove_prefix(2);

        // If input is the empty string, then return (0, true).
        if (input.empty()) {
          return true;
        }

        // If input contains a code point that is not a radix-R digit, then return failure.
        return input.find_first_of("0123456789abcdefABCDEF") != std::string_view::npos;
      }
      // Otherwise, if input contains at least two code points and the first code point is U+0030 (0), then:
      else if (input[1] == '0') {
        // Remove the first code point from input.
        input.remove_prefix(1);
      }
    }

    // If input contains a code point that is not a radix-R digit, then return failure.
    return input.find_first_of("0123456789") != std::string_view::npos;
  }

} // namespace ada::checkers

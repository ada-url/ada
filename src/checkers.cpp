#include "ada.h"
#include "unicode.cpp"

#include <algorithm>

namespace ada::checkers {

  // TODO: Refactor this to not use `std::vector` but use pointer arithmetic for performance.
  bool ends_in_a_number(const std::string_view input) noexcept {
    // Let parts be the result of strictly splitting input on U+002E (.).
    std::vector<std::string> parts = ada::helpers::split_string_view(input, '.', false);

    if (parts.empty()) {
      return false;
    }

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
    if (!last.empty() && std::all_of(last.begin(), last.end(), ::isdigit)) {
      return true;
    }

    // If parsing last as an IPv4 number does not return failure, then return true.
    return ada::parser::parse_ipv4_number(last).has_value();
  }

  // A Windows drive letter is two code points, of which the first is an ASCII alpha
  // and the second is either U+003A (:) or U+007C (|).
  bool is_windows_drive_letter(const std::string_view input) noexcept {
    return input.size() == 2 && std::isalpha(input[0]) && (input[1] == ':' || input[1] == '|');
  }

  // A normalized Windows drive letter is a Windows drive letter of which the second code point is U+003A (:).
  bool is_normalized_windows_drive_letter(const std::string_view input) noexcept {
    return is_windows_drive_letter(input) && input[1] == ':';
  }


} // namespace ada::checkers

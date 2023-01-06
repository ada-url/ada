#include "ada.h"
#include "unicode.cpp"

#include <algorithm>

namespace ada::checkers {

  // TODO: Refactor this to not use `std::vector` but use pointer arithmetic for performance.
  bool ends_in_a_number(const std::string_view input) noexcept {
    if (input.empty()) {
      return false;
    }

    size_t parts_count = std::count(input.begin(), input.end(), '.');

    if (parts_count > 0) { parts_count++; }

    static const std::string delimiter = ".";
    std::string_view::iterator pointer_start = input.begin();
    std::string_view::iterator pointer_end = input.end();

    // If the last item in parts is the empty string, then:
    if (input.back() == '.') {
      // If parts’s size is 1, then return false.
      if (parts_count == 1) {
        return false;
      }

      // Remove the last item from parts.
      pointer_end--;
      parts_count--;
    }

    if (std::distance(pointer_start, pointer_end) == 0) {
      return false;
    }

    if (parts_count > 1) {
      pointer_start = std::find_end(pointer_start, pointer_end, delimiter.begin(), delimiter.end());

      if (pointer_start == pointer_end) {
        return false;
      }

      pointer_start++;
    }

    if (std::distance(pointer_start, pointer_end) == 0) {
      return false;
    }

    // If last is non-empty and contains only ASCII digits, then return true.
    if (std::all_of(pointer_start, pointer_end, ::isdigit)) {
      return true;
    }

    // If parsing last as an IPv4 number does not return failure, then return true.
    return is_ipv4_number_valid(std::string(pointer_start, pointer_end));
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

  // This function assumes the input is not empty.
  ada_really_inline constexpr bool is_ipv4_number_valid(const std::string_view input) noexcept {
    // The first two code points are either "0X" or "0x", then:
    if (input.length() >= 2 && input[0] == '0' && (input[1] == 'X' || input[1] == 'x')) {
      if (input.length() == 2) {
        return true;
      }

      // Remove the first two code points from input.
      // If input contains a code point that is not a radix-R digit, then return failure.
      return input.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string_view::npos;
    }
    // Otherwise, if the first code point is U+0030 (0), then:
    else if (input[0] == '0') {
      if (input.length() == 1) {
        return true;
      }

      // Remove the first code point from input.
      // If input contains a code point that is not a radix-R digit, then return failure.
      return input.find_first_not_of("01234567", 1) == std::string_view::npos;
    }

    return std::all_of(input.begin(), input.end(), ::isdigit);
  }

} // namespace ada::checkers

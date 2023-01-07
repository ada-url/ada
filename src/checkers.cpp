#include "ada.h"
#include "unicode.cpp"

#include <algorithm>

namespace ada::checkers {

  bool ends_in_a_number(const std::string_view input) noexcept {
    if (input.empty()) {
      return false;
    }

    size_t parts_count = std::count(input.begin(), input.end(), '.');

    if (parts_count > 0) { parts_count++; }
    static const char delimiter = '.';
    std::string_view::iterator pointer_start = input.begin();
    std::string_view::iterator pointer_end = input.end();

    // If the last item in parts is the empty string, then:
    if (input.back() == delimiter) {
      // If parts’s size is 1, then return false.
      if (parts_count == 1) {
        return false;
      }

      // Remove the last item from parts.
      pointer_end--;
      parts_count--;

      if (std::distance(pointer_start, pointer_end) == 0) {
        return false;
      }
    }

    if (parts_count > 1) {
      pointer_start = pointer_start + std::string_view{pointer_start, size_t(pointer_end - pointer_start)}.rfind(delimiter);

      if (pointer_start == pointer_end) {
        return false;
      }

      pointer_start++;
    }

    // If parsing last as an IPv4 number does not return failure, then return true.
    return is_ipv4_number_valid(pointer_start, pointer_end);
  }

  // Assuming that x is an ASCII letter, this returns the lower case equivalent.
  // More likely to be inlined by the compiler and constexpr.
  constexpr char to_lower(char x) { return (x | 0x20); }

  // Returns true if the character is an ASCII letter. Equivalent to std::isalpha but
  // more likely to be inlined by the compiler. Also, std::isalpha is not constexpr
  // generally.
  constexpr bool is_alpha(char x) { return (to_lower(x) >= 'a') & (to_lower(x) <= 'z'); }

  // A Windows drive letter is two code points, of which the first is an ASCII alpha
  // and the second is either U+003A (:) or U+007C (|).
  inline bool is_windows_drive_letter(const std::string_view input) noexcept {
    return input.size() >= 2 && (is_alpha(input[0]) & (input[1] == ':' | input[1] == '|'));
  }
  // A normalized Windows drive letter is a Windows drive letter of which the second code point is U+003A (:).
  inline bool is_normalized_windows_drive_letter(const std::string_view input) noexcept {
    return is_windows_drive_letter(input) && input[1] == ':';
  }

  // This function assumes the input is not empty.
  ada_really_inline constexpr bool is_ipv4_number_valid(const std::string_view::iterator iterator_start, const std::string_view::iterator iterator_end) noexcept {
    size_t length = std::distance(iterator_start, iterator_end);

    if (length == 0) {
      return false;
    }

    if (length >= 2) {
      std::string_view::iterator next_iterator = std::next(iterator_start);

      // The first two code points are either "0X" or "0x", then:
      if (*iterator_start == '0' && (to_lower(*next_iterator) == 'x')) {
        if (length == 2) {
          return true;
        }

        // Remove the first two code points from input.
        // If input contains a code point that is not a radix-R digit, then return failure.
        return std::all_of(iterator_start + 2, iterator_end, unicode::is_ascii_hex_digit);
      }
      // Otherwise, if the first code point is U+0030 (0), then:
      else if (*iterator_start == '0') {
        // Remove the first code point from input.
        // If input contains a code point that is not a radix-R digit, then return failure.
        return std::find_if_not(iterator_start + 1, iterator_end, [](char c) {
          return c >= '0' && c <= '7';
        });
      }
    }


    return std::all_of(iterator_start, iterator_end, ::isdigit);
  }

} // namespace ada::checkers

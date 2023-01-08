#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "common_defs.h"

#include <string_view>

namespace ada::checkers {

  // If we wish to separate definitions and declarations, we can do
  // it with a -inl.h files.


  // Assuming that x is an ASCII letter, this returns the lower case equivalent.
  // More likely to be inlined by the compiler and constexpr.
  constexpr char to_lower(char x) { return (x | 0x20); }

  // Returns true if the character is an ASCII letter. Equivalent to std::isalpha but
  // more likely to be inlined by the compiler. Also, std::isalpha is not constexpr
  // generally.
  constexpr bool is_alpha(char x) { return (to_lower(x) >= 'a') & (to_lower(x) <= 'z'); }

  // Check whether x is an ASCII digit. More likely to be inlined than std::isdigit.
  constexpr bool is_digit(char x) { return (x >= '0') & (x <= '9'); }

  // A Windows drive letter is two code points, of which the first is an ASCII alpha
  // and the second is either U+003A (:) or U+007C (|).
  inline bool is_windows_drive_letter(const std::string_view input) noexcept {
    return input.size() >= 2 && (is_alpha(input[0]) & ((input[1] == ':') | (input[1] == '|')));
  }

  // A normalized Windows drive letter is a Windows drive letter of which the second code point is U+003A (:).
  inline bool is_normalized_windows_drive_letter(std::string_view input) noexcept {
    return input.size() >= 2 && (is_alpha(input[0]) & (input[1] == ':'));
  }

  /* too large to be inlined: */
  bool ends_in_a_number(std::string_view input) noexcept;

  ada_really_inline constexpr bool is_ipv4_number_valid(std::string_view::iterator iterator_start, std::string_view::iterator iterator_end) noexcept;

} // namespace ada::checkers

#endif //ADA_CHECKERS_H

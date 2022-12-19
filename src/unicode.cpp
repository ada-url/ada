#pragma once

namespace ada::unicode {

  // An ASCII upper alpha is a code point in the range U+0041 (A) to U+005A (Z), inclusive.
  bool is_ascii_upper_alpha(const char c) {
    return c >= 'A' && c <= 'Z';
  }

  // An ASCII lower alpha is a code point in the range U+0061 (a) to U+007A (z), inclusive.
  bool is_ascii_lower_alpha(const char c) {
    return c >= 'a' && c <= 'z';
  }

  // An ASCII alpha is an ASCII upper alpha or ASCII lower alpha.
  bool is_ascii_alpha(const char c) {
    return is_ascii_upper_alpha(c) || is_ascii_lower_alpha(c);
  }

  // An ASCII digit is a code point in the range U+0030 (0) to U+0039 (9), inclusive.
  bool is_ascii_digit(const char c) {
    return c >= 0 && c <= 9;
  }

  // An ASCII alphanumeric is an ASCII digit or ASCII alpha.
  bool is_ascii_alphanumeric(const char c) {
    return is_ascii_digit(c) || is_ascii_alpha(c);
  }

} // namespace ada::unicode

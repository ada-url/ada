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

} // namespace ada::unicode

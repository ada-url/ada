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
    return c >= '0' && c <= '9';
  }

  // An ASCII alphanumeric is an ASCII digit or ASCII alpha.
  bool is_ascii_alphanumeric(const char c) {
    return is_ascii_digit(c) || is_ascii_alpha(c);
  }

  // A C0 control or space is a C0 control or U+0020 SPACE.
  // A C0 control is a code point in the range U+0000 NULL to U+001F INFORMATION SEPARATOR ONE, inclusive.
  bool is_c0_control_or_space(const char c) {
    return (unsigned char) c <= ' ';
  }

  // An ASCII tab or newline is U+0009 TAB, U+000A LF, or U+000D CR.
  bool is_ascii_tab_or_newline(const char c) {
    return c == '\t' || c == '\n' || c == '\r';
  }

  /**
   * @see https://encoding.spec.whatwg.org/#utf-8-decode-without-bom
   */
  std::string_view utf8_decode_without_bom(const std::string_view input) {
    // TODO: Implement this.
    return "";
  }

} // namespace ada::unicode

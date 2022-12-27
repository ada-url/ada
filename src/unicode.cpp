#include <set>

namespace ada::unicode {

  // A forbidden host code point is U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR, U+0020 SPACE, U+0023 (#),
  // U+002F (/), U+003A (:), U+003C (<), U+003E (>), U+003F (?), U+0040 (@), U+005B ([), U+005C (\), U+005D (]),
  // U+005E (^), or U+007C (|).
  static const std::set<char> FORBIDDEN_HOST_CODE_POINTS {
    '\u0000', '\u0009', '\u000A', '\u000D', ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|'
  };

  // An ASCII upper alpha is a code point in the range U+0041 (A) to U+005A (Z), inclusive.
  ada_really_inline bool is_ascii_upper_alpha(const char c) {
    return c >= 'A' && c <= 'Z';
  }

  // An ASCII upper hex digit is an ASCII digit or a code point in the range U+0041 (A) to U+0046 (F), inclusive.
  ada_really_inline bool is_ascii_upper_hex_digit(const char c) {
    return std::isdigit(c) || (c >= 'A' && c <= 'F');
  }

  // An ASCII lower hex digit is an ASCII digit or a code point in the range U+0061 (a) to U+0066 (f), inclusive.
  ada_really_inline bool is_ascii_lower_hex_digit(const char c) {
    return std::isdigit(c) || (c >= 'a' && c<= 'f');
  }

  // An ASCII hex digit is an ASCII upper hex digit or ASCII lower hex digit.
  ada_really_inline bool is_ascii_hex_digit(const char c) {
    return is_ascii_upper_hex_digit(c) || is_ascii_lower_hex_digit(c);
  }

  // A C0 control or space is a C0 control or U+0020 SPACE.
  // A C0 control is a code point in the range U+0000 NULL to U+001F INFORMATION SEPARATOR ONE, inclusive.
  ada_really_inline bool is_c0_control_or_space(const char c) {
    return (unsigned char) c <= ' ';
  }

  // An ASCII tab or newline is U+0009 TAB, U+000A LF, or U+000D CR.
  ada_really_inline bool is_ascii_tab_or_newline(const char c) {
    return c == '\t' || c == '\n' || c == '\r';
  }

  // A double-dot path segment must be ".." or an ASCII case-insensitive match for ".%2e", "%2e.", or "%2e%2e".
  ada_really_inline bool is_double_dot_path_segment(std::string_view input) {
    return input == ".." ||
      input == ".%2e" || input == ".%2E" ||
      input == "%2e." || input == "%2E." ||
      input == "%2e%2e" || input == "%2E%2E" || input == "%2E%2e" || input == "%2e%2E";
  }

  // A single-dot path segment must be "." or an ASCII case-insensitive match for "%2e".
  ada_really_inline bool is_single_dot_path_segment(std::string_view input) {
    return input == "." || input == "%2e" || input == "%2E";
  }

  unsigned convert_hex_to_binary(const char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    else if (c >= 'A' && c <= 'F')
      return 10 + (c - 'A');
    else // if (c >= 'a' && c <= 'f')
      return 10 + (c - 'a');
  }

  /**
   * Taken from Node.js
   * https://github.com/nodejs/node/blob/main/src/node_url.cc#L245
   *
   * @see https://encoding.spec.whatwg.org/#utf-8-decode-without-bom
   */
  std::string utf8_decode_without_bom(const std::string_view input) {
    if (input.empty()) {
      return "";
    }

    std::string output;
    output.reserve(input.length());

    for (auto pointer = input.begin(); pointer < input.end(); pointer++) {
      size_t remaining = std::distance(pointer, input.end());

      if (*pointer != '%' || remaining < 2 ||
          (*pointer == '%' &&
           (!is_ascii_hex_digit(pointer[1]) ||
            !is_ascii_hex_digit(pointer[2])))) {
        output += *pointer;
        pointer++;
        continue;
      }

      unsigned a = convert_hex_to_binary(pointer[1]);
      unsigned b = convert_hex_to_binary(pointer[2]);
      output += static_cast<char>(a * 16 + b);
      pointer += 3;
    }

    return output;
  }

  /**
   * @see https://github.com/nodejs/node/blob/main/src/node_url.cc#L226
   */
  std::string utf8_percent_encode(const std::string_view input, const uint8_t character_set[]) {
    std::string result;

    for(auto iterator = input.begin(); iterator < input.end(); iterator++) {
      if (character_sets::BitAt(character_set, *iterator)) {
        result += character_sets::hex + *iterator * 4;
      } else {
        result += iterator;
      }
    }

    return result;
  }

} // namespace ada::unicode

#include <unordered_set>

namespace ada::unicode {

  // A forbidden host code point is U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR, U+0020 SPACE, U+0023 (#),
  // U+002F (/), U+003A (:), U+003C (<), U+003E (>), U+003F (?), U+0040 (@), U+005B ([), U+005C (\), U+005D (]),
  // U+005E (^), or U+007C (|).
  static const std::unordered_set<char> FORBIDDEN_HOST_CODE_POINTS {
    '\u0000', '\u0009', '\u000A', '\u000D', ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|'
  };

  // A forbidden domain code point is a forbidden host code point, a C0 control, U+0025 (%), or U+007F DELETE.
  static constexpr char FORBIDDEN_DOMAIN_CODE_POINTS[] = {
    // Forbidden host code points
    '\u0000', '\u0009', '\u000A', '\u000D', ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|',
    // U+0025 (%), or U+007F DELETE.
    '\u0025', '\u007F',
    // C0 control
    '\u0001', '\u0002', '\u0003', '\u0004', '\u0005', '\u0006', '\u0007', '\u0008',
    '\u0012', '\u0013', '\u0014', '\u0015', '\u0016', '\u0017', '\u0018', '\u0019',
    '\u0020', '\u0021', '\u0022', '\u0023', '\u0024', '\u0025', '\u0026', '\u0027', '\u0028', '\u0029',
    '\u0030', '\u0031', '\u0032', '\u0033', '\u0034', '\u0035', '\u0036', '\u0037'
  };

  // An ASCII upper alpha is a code point in the range U+0041 (A) to U+005A (Z), inclusive.
  ada_really_inline bool is_ascii_upper_alpha(const char c) noexcept {
    return c >= 'A' && c <= 'Z';
  }

  // An ASCII hex digit is an ASCII upper hex digit or ASCII lower hex digit.
  // An ASCII upper hex digit is an ASCII digit or a code point in the range U+0041 (A) to U+0046 (F), inclusive.
  // An ASCII lower hex digit is an ASCII digit or a code point in the range U+0061 (a) to U+0066 (f), inclusive.
  ada_really_inline bool is_ascii_hex_digit(const char c) noexcept {
    return std::isdigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c<= 'f');
  }

  // A C0 control or space is a C0 control or U+0020 SPACE.
  // A C0 control is a code point in the range U+0000 NULL to U+001F INFORMATION SEPARATOR ONE, inclusive.
  ada_really_inline constexpr bool is_c0_control_or_space(const char c) noexcept {
    return (unsigned char) c <= ' ';
  }

  // An ASCII tab or newline is U+0009 TAB, U+000A LF, or U+000D CR.
  ada_really_inline constexpr bool is_ascii_tab_or_newline(const char c) noexcept {
    return c == '\t' || c == '\n' || c == '\r';
  }

  // A double-dot path segment must be ".." or an ASCII case-insensitive match for ".%2e", "%2e.", or "%2e%2e".
  ada_really_inline constexpr bool is_double_dot_path_segment(std::string_view input) noexcept {
    return input == ".." ||
      input == ".%2e" || input == ".%2E" ||
      input == "%2e." || input == "%2E." ||
      input == "%2e%2e" || input == "%2E%2E" || input == "%2E%2e" || input == "%2e%2E";
  }

  // A single-dot path segment must be "." or an ASCII case-insensitive match for "%2e".
  ada_really_inline bool is_single_dot_path_segment(std::string_view input) noexcept {
    return input == "." || input == "%2e" || input == "%2E";
  }

  unsigned constexpr convert_hex_to_binary(const char c) noexcept {
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
  std::string percent_decode(const std::string_view input) noexcept {
    std::string dest;
    if (input.length() == 0)
      return dest;
    dest.reserve(input.length());
    const char* pointer = input.begin();
    const char* end = input.end();

    while (pointer < end) {
      const char ch = pointer[0];
      size_t remaining = end - pointer - 1;
      if (ch != '%' || remaining < 2 ||
          (ch == '%' &&
           (!is_ascii_hex_digit(pointer[1]) ||
            !is_ascii_hex_digit(pointer[2])))) {
        dest += ch;
        pointer++;
        continue;
      } else {
        unsigned a = convert_hex_to_binary(pointer[1]);
        unsigned b = convert_hex_to_binary(pointer[2]);
        char c = static_cast<char>(a * 16 + b);
        dest += c;
        pointer += 3;
      }
    }
    return dest;
  }

  /**
   * @see https://github.com/nodejs/node/blob/main/src/node_url.cc#L226
   */
  std::string utf8_percent_encode(const std::string_view input, const uint8_t character_set[]) noexcept {
    std::string result{};
    result.reserve(input.length());

    for (uint8_t iterator: input) {
      if (character_sets::bit_at(character_set, iterator)) {
        result += character_sets::hex + iterator * 4;
      } else {
        result += static_cast<char>(iterator);
      }
    }

    return result;
  }

} // namespace ada::unicode

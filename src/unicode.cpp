#pragma once
namespace ada::unicode {

  // A forbidden host code point is U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR, U+0020 SPACE, U+0023 (#),
  // U+002F (/), U+003A (:), U+003C (<), U+003E (>), U+003F (?), U+0040 (@), U+005B ([), U+005C (\), U+005D (]),
  // U+005E (^), or U+007C (|).
  constexpr static bool is_forbidden_host_code_point_table[] = {
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static_assert(sizeof(is_forbidden_host_code_point_table) == 256);

  ada_really_inline constexpr bool is_forbidden_host_code_point(const char c) noexcept {
    return is_forbidden_host_code_point_table[uint8_t(c)];
  }

  static_assert(unicode::is_forbidden_host_code_point('\0'));
  static_assert(unicode::is_forbidden_host_code_point('\t'));
  static_assert(unicode::is_forbidden_host_code_point('\n'));
  static_assert(unicode::is_forbidden_host_code_point('\r'));
  static_assert(unicode::is_forbidden_host_code_point(' '));
  static_assert(unicode::is_forbidden_host_code_point('#'));
  static_assert(unicode::is_forbidden_host_code_point('/'));
  static_assert(unicode::is_forbidden_host_code_point(':'));
  static_assert(unicode::is_forbidden_host_code_point('?'));
  static_assert(unicode::is_forbidden_host_code_point('@'));
  static_assert(unicode::is_forbidden_host_code_point('['));
  static_assert(unicode::is_forbidden_host_code_point('?'));
  static_assert(unicode::is_forbidden_host_code_point('<'));
  static_assert(unicode::is_forbidden_host_code_point('>'));
  static_assert(unicode::is_forbidden_host_code_point('\\'));
  static_assert(unicode::is_forbidden_host_code_point(']'));
  static_assert(unicode::is_forbidden_host_code_point('^'));
  static_assert(unicode::is_forbidden_host_code_point('|'));

  constexpr static bool is_forbidden_domain_code_point_table[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    static_assert(sizeof(is_forbidden_domain_code_point_table) == 256);

  ada_really_inline constexpr bool is_forbidden_domain_code_point(const char c) noexcept {
   // abort();
    return is_forbidden_domain_code_point_table[uint8_t(c)];
    // A table is almost surely much faster than the
    // following under most compilers: return
    // is_forbidden_host_code_point(c) |
    // std::iscntrl(c) | c == '%' | c == '\x7f';
  }

  static_assert(unicode::is_forbidden_domain_code_point('%'));
  static_assert(unicode::is_forbidden_domain_code_point('\x7f'));
  static_assert(unicode::is_forbidden_domain_code_point('\0'));
  static_assert(unicode::is_forbidden_domain_code_point('\t'));
  static_assert(unicode::is_forbidden_domain_code_point('\n'));
  static_assert(unicode::is_forbidden_domain_code_point('\r'));
  static_assert(unicode::is_forbidden_domain_code_point(' '));
  static_assert(unicode::is_forbidden_domain_code_point('#'));
  static_assert(unicode::is_forbidden_domain_code_point('/'));
  static_assert(unicode::is_forbidden_domain_code_point(':'));
  static_assert(unicode::is_forbidden_domain_code_point('?'));
  static_assert(unicode::is_forbidden_domain_code_point('@'));
  static_assert(unicode::is_forbidden_domain_code_point('['));
  static_assert(unicode::is_forbidden_domain_code_point('?'));
  static_assert(unicode::is_forbidden_domain_code_point('<'));
  static_assert(unicode::is_forbidden_domain_code_point('>'));
  static_assert(unicode::is_forbidden_domain_code_point('\\'));
  static_assert(unicode::is_forbidden_domain_code_point(']'));
  static_assert(unicode::is_forbidden_domain_code_point('^'));
  static_assert(unicode::is_forbidden_domain_code_point('|'));

  constexpr static bool is_alnum_plus_table[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
      0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  static_assert(sizeof(is_alnum_plus_table) == 256);

  ada_really_inline constexpr bool is_alnum_plus(const char c) noexcept {
    return is_alnum_plus_table[uint8_t(c)];
    // A table is almost surely much faster than the
    // following under most compilers: return
    // return (std::isalnum(c) || c == '+' || c == '-' || c == '.');
  }
  static_assert(unicode::is_alnum_plus('+'));
  static_assert(unicode::is_alnum_plus('-'));
  static_assert(unicode::is_alnum_plus('.'));
  static_assert(unicode::is_alnum_plus('0'));
  static_assert(unicode::is_alnum_plus('1'));
  static_assert(unicode::is_alnum_plus('a'));
  static_assert(unicode::is_alnum_plus('b'));

  // An ASCII hex digit is an ASCII upper hex digit or ASCII lower hex digit.
  // An ASCII upper hex digit is an ASCII digit or a code point in the range U+0041 (A) to U+0046 (F), inclusive.
  // An ASCII lower hex digit is an ASCII digit or a code point in the range U+0061 (a) to U+0066 (f), inclusive.
  ada_really_inline constexpr bool is_ascii_hex_digit(const char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c<= 'f');
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
    // this code can be optimized.
    if (c >= '0' && c <= '9')
      return c - '0';
    else if (c >= 'A' && c <= 'F')
      return 10 + (c - 'A');
    else // if (c >= 'a' && c <= 'f')
      return 10 + (c - 'a');
  }

  /**
   * first_percent should be  = input.find('%')
   * Adapted from Node.js
   * https://github.com/nodejs/node/blob/main/src/node_url.cc#L245
   *
   * @see https://encoding.spec.whatwg.org/#utf-8-decode-without-bom
   */
  std::string percent_decode(const std::string_view input, size_t first_percent) {
    // next line is for safety only, we expect users to avoid calling percent_decode
    // when first_percent is outside the range.
    if(first_percent == std::string_view::npos) { return std::string(input); }
    std::string dest(input.substr(0, first_percent));
    dest.reserve(input.length());
    const char* pointer = input.begin() + first_percent;
    const char* end = input.end();
    // Optimization opportunity: if the following code gets
    // called often, it can be optimized quite a bit.
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
  std::string percent_encode(const std::string_view input, const uint8_t character_set[]) {
    auto pointer = std::find_if(input.begin(), input.end(), [character_set](const char c) {
      return character_sets::bit_at(character_set, c);
    });
    // Optimization: Don't iterate if percent encode is not required
    if (pointer == input.end()) { return std::string(input); }

    std::string result(input.substr(0,std::distance(input.begin(), pointer)));
    result.reserve(input.length()); // in the worst case, percent encoding might produce 3 characters.
    const char* end = input.end();

    while (pointer < end) {
      if (character_sets::bit_at(character_set, *pointer)) {
        result.append(character_sets::hex + uint8_t(*pointer) * 4, 3);
      } else {
        result += *pointer;
      }
      pointer++;
    }

    return result;
  }

  /**
   * Encode a single character in the string. This is likely much faster than taking
   * a character, making a string out of it, creating a new string, returning said string,
   * and then appending the string at the caller site. Generally, we want to have as
   * few std::string created as possible.
   */
  void percent_encode_character(const char input, const uint8_t character_set[], std::string &out) {
    if (character_sets::bit_at(character_set, input)) {
        // append will be faster because out += char* requires the
        // system to determine the size of the input, by looking for the
        // null byte, which implies a call to strlen. Yet we know that the
        // size of the appended string is always 3. Let us tell it to the
        // compiler.
        out.append(character_sets::hex + uint8_t(input) * 4,3);
      } else {
        out += input;
      }
  }

} // namespace ada::unicode

#include "ada.h"
#include "ada/character_sets.h"

#include <algorithm>

#include <unicode/utypes.h>
#include <unicode/uidna.h>
#include <unicode/utf8.h>

namespace ada::unicode {

  /**
   * The has_tabs_or_newline function is a bottleneck and it is simple enough that compilers
   * like GCC can 'autovectorize it'.
   */
  ada_really_inline constexpr bool has_tabs_or_newline(std::string_view user_input) noexcept {
    auto has_zero_byte = [](uint64_t v) {
      return ((v - 0x0101010101010101) & ~(v)&0x8080808080808080);
    };
    auto broadcast = [](uint8_t v) -> uint64_t { return 0x101010101010101 * v; };
    size_t i = 0;
    uint64_t mask1 = broadcast('\r');
    uint64_t mask2 = broadcast('\n');
    uint64_t mask3 = broadcast('\t');
    uint64_t running{0};
    for (; i + 7 < user_input.size(); i += 8) {
      uint64_t word{};
      memcpy(&word, user_input.data() + i, sizeof(word));
      uint64_t xor1 = word ^ mask1;
      uint64_t xor2 = word ^ mask2;
      uint64_t xor3 = word ^ mask3;
      running |= has_zero_byte(xor1) | has_zero_byte(xor2) | has_zero_byte(xor3);
    }
    if (i < user_input.size()) {
      uint64_t word{};
      memcpy(&word, user_input.data() + i, user_input.size() - i);
      uint64_t xor1 = word ^ mask1;
      uint64_t xor2 = word ^ mask2;
      uint64_t xor3 = word ^ mask3;
      running |= has_zero_byte(xor1) | has_zero_byte(xor2) | has_zero_byte(xor3);
    }
    return running;
  }

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
    0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

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


  constexpr std::string_view table_is_double_dot_path_segment[] = {"..", "%2e.", ".%2e", "%2e%2e"};


  // A double-dot path segment must be ".." or an ASCII case-insensitive match for ".%2e", "%2e.", or "%2e%2e".
  ada_really_inline ada_constexpr bool is_double_dot_path_segment(std::string_view input) noexcept {
    // This will catch most cases:
    // The length must be 2,4 or 6.
    // We divide by two and require
    // that the result be between 1 and 3 inclusively.
    uint64_t half_length = uint64_t(input.size())/2;
    if(half_length - 1 > 2) { return false; }
    // We have a string of length 2, 4 or 6.
    // We now check the first character:
    if((input[0] != '.') && (input[0] != '%')) { return false; }
     // We are unlikely the get beyond this point.
    int hash_value = (input.size() + (unsigned)(input[0])) & 3;
    const std::string_view target = table_is_double_dot_path_segment[hash_value];
    if(target.size() != input.size()) { return false; }
    // We almost never get here.
    // Optimizing the rest is relatively unimportant.
    auto prefix_equal_unsafe = [](std::string_view a, std::string_view b) {
      uint16_t A, B;
      memcpy(&A,a.data(), sizeof(A));
      memcpy(&B,b.data(), sizeof(B));
      return A == B;
    };
    if(!prefix_equal_unsafe(input,target)) { return false; }
    for(size_t i = 2; i < input.size(); i++) {
      char c = input[i];
      if((uint8_t((c|0x20) - 0x61) <= 25 ? (c|0x20) : c) != target[i]) { return false; }
    }
    return true;
    // The above code might be a bit better than the code below. Compilers
    // are not stupid and may use the fact that these strings have length 2,4 and 6
    // and other tricks.
    //return input == ".." ||
    //  input == ".%2e" || input == ".%2E" ||
    //  input == "%2e." || input == "%2E." ||
    //  input == "%2e%2e" || input == "%2E%2E" || input == "%2E%2e" || input == "%2e%2E";
  }


  // A single-dot path segment must be "." or an ASCII case-insensitive match for "%2e".
  ada_really_inline constexpr bool is_single_dot_path_segment(std::string_view input) noexcept {
    return input == "." || input == "%2e" || input == "%2E";
  }

  // ipv4 character might contain 0-9 or a-f character ranges.
  ada_really_inline constexpr bool is_lowercase_hex(const char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c<= 'f');
  }

  unsigned constexpr convert_hex_to_binary(const char c) noexcept {
    // this code can be optimized.
    if (c <= '9') { return c - '0'; }
    char del = c >= 'a' ? 'a' : 'A';
    return 10 + (c - del);
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
   * We receive a UTF-8 string representing a domain name.
   * If the string is percent encoded, we apply percent decoding.
   *
   * Given a domain, we need to identify its labels.
   * They are separated by label-separators:
   *
   * U+002E ( . ) FULL STOP
   * U+FF0E ( ． ) FULLWIDTH FULL STOP
   * U+3002 ( 。 ) IDEOGRAPHIC FULL STOP
   * U+FF61 ( ｡ ) HALFWIDTH IDEOGRAPHIC FULL STOP
   *
   * They are all mapped to U+002E.
   *
   * We process each label into a string that should not exceed 63 octets.
   * If the string is already punycode (starts with "xn--"), then we must
   * scan it to look for unallowed code points.
   * Otherwise, if the string is not pure ASCII, we need to transcode it
   * to punycode by following RFC 3454 which requires us to
   * - Map characters  (see section 3),
   * - Normalize (see section 4),
   * - Reject forbidden characters,
   * - Check for right-to-left characters and if so, check all requirements (see section 6),
   * - Optionally reject based on unassigned code points (section 7).
   *
   * The Unicode standard provides a table of code points with a mapping, a list of
   * forbidden code points and so forth. This table is subject to change and will
   * vary based on the implementation. For Unicode 15, the table is at
   * https://www.unicode.org/Public/idna/15.0.0/IdnaMappingTable.txt
   * If you use ICU, they parse this table and map it to code using a Python script.
   *
   * The resulting strings should not exceed 255 octets according to RFC 1035 section 2.3.4.
   * ICU checks for label size and domain size, but if we pass "be_strict = false", these
   * errors are ignored.
   *
   * @see https://url.spec.whatwg.org/#concept-domain-to-ascii
   *
   */
  bool to_ascii(std::optional<std::string>& out, const std::string_view plain, const bool be_strict, size_t first_percent) {
    std::string percent_decoded_buffer;
    std::string_view input = plain;
    if(first_percent != std::string_view::npos) {
      percent_decoded_buffer = unicode::percent_decode(plain, first_percent);
      input = percent_decoded_buffer;
    }
    UErrorCode status = U_ZERO_ERROR;
    uint32_t options = UIDNA_CHECK_BIDI | UIDNA_CHECK_CONTEXTJ | UIDNA_NONTRANSITIONAL_TO_ASCII;

    if (be_strict) {
      options |= UIDNA_USE_STD3_RULES;
    }

    UIDNA* uidna = uidna_openUTS46(options, &status);
    if (U_FAILURE(status)) {
      return false;
    }

    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    out = std::string(255, 0);
    // RFC 1035 section 2.3.4.
    // The domain  name must be at most 255 octets.
    // It cannot contain a label longer than 63 octets.
    // Thus we should never need more than 255 octets, if we
    // do the domain name is in error.
    int32_t length = uidna_nameToASCII_UTF8(uidna,
                                         input.data(),
                                         int32_t(input.length()),
                                         out.value().data(), 255,
                                         &info,
                                         &status);

    if (status == U_BUFFER_OVERFLOW_ERROR) {
      status = U_ZERO_ERROR;
      out.value().resize(length);
      // When be_strict is true, this should not be allowed!
      length = uidna_nameToASCII_UTF8(uidna,
                                     input.data(),
                                     int32_t(input.length()),
                                     out.value().data(), length,
                                     &info,
                                     &status);
    }

    // A label contains hyphen-minus ('-') in the third and fourth positions.
    info.errors &= ~UIDNA_ERROR_HYPHEN_3_4;
    // A label starts with a hyphen-minus ('-').
    info.errors &= ~UIDNA_ERROR_LEADING_HYPHEN;
    // A label ends with a hyphen-minus ('-').
    info.errors &= ~UIDNA_ERROR_TRAILING_HYPHEN;

    if (!be_strict) { // This seems to violate RFC 1035 section 2.3.4.
      // A non-final domain name label (or the whole domain name) is empty.
      info.errors &= ~UIDNA_ERROR_EMPTY_LABEL;
      // A domain name label is longer than 63 bytes.
      info.errors &= ~UIDNA_ERROR_LABEL_TOO_LONG;
      // A domain name is longer than 255 bytes in its storage form.
      info.errors &= ~UIDNA_ERROR_DOMAIN_NAME_TOO_LONG;
    }

    uidna_close(uidna);

    if (U_FAILURE(status) || info.errors != 0 || length == 0) {
      out = std::nullopt;
      return false;
    }

    out.value().resize(length); // we possibly want to call :shrink_to_fit otherwise we use 255 bytes.
    if(std::any_of(out.value().begin(), out.value().end(), ada::unicode::is_forbidden_domain_code_point)) {
      out = std::nullopt;
      return false;
    }
    return true;
  }

  // This function attemps to convert an ASCII string to a lower-case version.
  // Once the lower cased version has been materialized, we check for the presence
  // of the substring 'xn-', if it is found (unlikely), we then call the expensive 'to_ascii'.
  ada_really_inline bool to_lower_ascii_string(std::optional<std::string>& out, size_t first_percent) noexcept {
#if ADA_DEVELOP_MODE
    if(!out.has_value()) { abort(); }
#endif
    if(std::any_of(out.value().begin(), out.value().end(), ada::unicode::is_forbidden_domain_code_point)) { return false; }
    std::transform(out.value().begin(), out.value().end(), out.value().begin(), [](char c) -> char {
      return (uint8_t((c|0x20) - 0x61) <= 25 ? (c|0x20) : c);}
    );
    if (out.value().find("xn-") == std::string_view::npos) {
      return true;
    }

    return to_ascii(out, out.value(), false, first_percent);
  }


  size_t utf16_to_utf8(const char16_t* buf, size_t len, char* utf8_output, encoding_type type) {
    uint32_t value_one = 1;
    bool is_little_endian = (reinterpret_cast<char*>(&value_one)[0] == 1);
    bool need_flip = (is_little_endian) ? (type == encoding_type::UTF_16BE) : (type == encoding_type::UTF_16LE);
    const uint16_t *data = reinterpret_cast<const uint16_t *>(buf);
    size_t pos = 0;
    auto swap_bytes = [](uint16_t word) { return uint16_t((word >> 8) | (word << 8)); };
    char* start{utf8_output};
    while (pos < len) {
      // try to convert the next block of 8 ASCII characters
      if (pos + 4 <= len) { // if it is safe to read 8 more bytes, check that they are ascii
        uint64_t v;
        ::memcpy(&v, data + pos, sizeof(uint64_t));
        if (need_flip) v = (v >> 8) | (v << (64 - 8));
        if ((v & 0xFF80FF80FF80FF80) == 0) {
          size_t final_pos = pos + 4;
          while(pos < final_pos) {
            *utf8_output++ = need_flip ? char(swap_bytes(buf[pos])) : char(buf[pos]);
            pos++;
          }
          continue;
        }
      }
      uint16_t word = need_flip ? swap_bytes(data[pos]) : data[pos];
      if((word & 0xFF80)==0) {
        // will generate one UTF-8 bytes
        *utf8_output++ = char(word);
        pos++;
      } else if((word & 0xF800)==0) {
        // will generate two UTF-8 bytes
        // we have 0b110XXXXX 0b10XXXXXX
        *utf8_output++ = char((word>>6) | 0b11000000);
        *utf8_output++ = char((word & 0b111111) | 0b10000000);
        pos++;
      } else if((word &0xF800 ) != 0xD800) {
        // will generate three UTF-8 bytes
        // we have 0b1110XXXX 0b10XXXXXX 0b10XXXXXX
        *utf8_output++ = char((word>>12) | 0b11100000);
        *utf8_output++ = char(((word>>6) & 0b111111) | 0b10000000);
        *utf8_output++ = char((word & 0b111111) | 0b10000000);
        pos++;
      } else {
        // must be a surrogate pair
        if(pos + 1 >= len) { return 0; }
        uint16_t diff = uint16_t(word - 0xD800);
        if(diff > 0x3FF) { return 0; }
        uint16_t next_word = need_flip ? swap_bytes(data[pos + 1]) : data[pos + 1];
        uint16_t diff2 = uint16_t(next_word - 0xDC00);
        if(diff2 > 0x3FF) { return 0; }
        uint32_t value = (diff << 10) + diff2 + 0x10000;
        // will generate four UTF-8 bytes
        // we have 0b11110XXX 0b10XXXXXX 0b10XXXXXX 0b10XXXXXX
        *utf8_output++ = char((value>>18) | 0b11110000);
        *utf8_output++ = char(((value>>12) & 0b111111) | 0b10000000);
        *utf8_output++ = char(((value>>6) & 0b111111) | 0b10000000);
        *utf8_output++ = char((value & 0b111111) | 0b10000000);
        pos += 2;
      }
    }
    return utf8_output - start;
  }
} // namespace ada::unicode

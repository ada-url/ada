#include "ada.h"
#include "ada/character_sets.h"
#include "ada/common_defs.h"

#include <algorithm>
#if ADA_HAS_ICU
// We are god.
#else

#ifdef _WIN32 // let us hope that we are linking with the proper libraries.

#ifndef __wtypes_h__
#include <wtypes.h>
#endif // __wtypes_h__

#ifndef __WINDEF_
#include <windef.h>
#endif // __WINDEF_

#include <winnls.h>
#endif // _WIN32

#endif // ADA_HAS_ICU

namespace ada::unicode {

  constexpr bool to_lower_ascii(char * input, size_t length) noexcept {
    auto broadcast = [](uint8_t v) -> uint64_t { return 0x101010101010101 * v; };
    uint64_t broadcast_80 = broadcast(0x80);
    uint64_t broadcast_Ap = broadcast(128 - 'A');
    uint64_t broadcast_Zp = broadcast(128 - 'Z');
    uint64_t non_ascii = 0;
    size_t i = 0;

    for (; i + 7 < length; i += 8) {
      uint64_t word{};
      memcpy(&word, input + i, sizeof(word));
      non_ascii |= (word & broadcast_80);
      word ^= (((word+broadcast_Ap)^(word+broadcast_Zp))&broadcast_80)>>2;
      memcpy(input + i, &word, sizeof(word));
    }
    if (i < length) {
      uint64_t word{};
      memcpy(&word, input + i, length - i);
      non_ascii |= (word & broadcast_80);
      word ^= (((word+broadcast_Ap)^(word+broadcast_Zp))&broadcast_80)>>2;
      memcpy(input + i, &word, length - i);
    }
    return non_ascii == 0;
  }

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

constexpr static uint8_t is_forbidden_domain_code_point_table[] = {
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
  ada_really_inline constexpr bool contains_forbidden_host_code_point(char * input, size_t length) noexcept {
    size_t i = 0;
    uint8_t accumulator{};
    for(; i + 4 <= length; i+=4) {
      accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i])];
      accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i+1])];
      accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i+2])];
      accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i+3])];
    }
    for(; i < length; i++) {
      accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i])];
    }
    return accumulator;
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

  ada_really_inline constexpr bool is_ascii_hex_digit(const char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c<= 'f');
  }

  ada_really_inline constexpr bool is_c0_control_or_space(const char c) noexcept {
    return (unsigned char) c <= ' ';
  }

  ada_really_inline constexpr bool is_ascii_tab_or_newline(const char c) noexcept {
    return c == '\t' || c == '\n' || c == '\r';
  }

  constexpr std::string_view table_is_double_dot_path_segment[] = {"..", "%2e.", ".%2e", "%2e%2e"};

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

  ada_really_inline constexpr bool is_single_dot_path_segment(std::string_view input) noexcept {
    return input == "." || input == "%2e" || input == "%2E";
  }

  ada_really_inline constexpr bool is_lowercase_hex(const char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c<= 'f');
  }

  unsigned constexpr convert_hex_to_binary(const char c) noexcept {
    // this code can be optimized.
    if (c <= '9') { return c - '0'; }
    char del = c >= 'a' ? 'a' : 'A';
    return 10 + (c - del);
  }

  std::string percent_decode(const std::string_view input, size_t first_percent) {
    // next line is for safety only, we expect users to avoid calling percent_decode
    // when first_percent is outside the range.
    if(first_percent == std::string_view::npos) { return std::string(input); }
    std::string dest(input.substr(0, first_percent));
    dest.reserve(input.length());
    const char* pointer = input.data() + first_percent;
    const char* end = input.data() + input.size();
    // Optimization opportunity: if the following code gets
    // called often, it can be optimized quite a bit.
    while (pointer < end) {
      const char ch = pointer[0];
      size_t remaining = end - pointer - 1;
      if (ch != '%' || remaining < 2 ||
          (//ch == '%' && // It is unnecessary to check that ch == '%'.
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

  std::string percent_encode(const std::string_view input, const uint8_t character_set[]) {
    auto pointer = std::find_if(input.begin(), input.end(), [character_set](const char c) {
      return character_sets::bit_at(character_set, c);
    });
    // Optimization: Don't iterate if percent encode is not required
    if (pointer == input.end()) { return std::string(input); }

    std::string result(input.substr(0,std::distance(input.begin(), pointer)));
    result.reserve(input.length()); // in the worst case, percent encoding might produce 3 characters.

    for (;pointer != input.end(); pointer++) {
      if (character_sets::bit_at(character_set, *pointer)) {
        result.append(character_sets::hex + uint8_t(*pointer) * 4, 3);
      } else {
        result += *pointer;
      }
    }

    return result;
  }


  bool percent_encode(const std::string_view input, const uint8_t character_set[], std::string &out) {
    auto pointer = std::find_if(input.begin(), input.end(), [character_set](const char c) {
      return character_sets::bit_at(character_set, c);
    });
    // Optimization: Don't iterate if percent encode is not required
    if (pointer == input.end()) { return false; }
    out.clear();
    out.append(input.data(), std::distance(input.begin(), pointer));

    for (;pointer != input.end(); pointer++) {
      if (character_sets::bit_at(character_set, *pointer)) {
        out.append(character_sets::hex + uint8_t(*pointer) * 4, 3);
      } else {
        out += *pointer;
      }
    }
    return true;
  }

  bool to_ascii(std::optional<std::string>& out, const std::string_view plain, const bool be_strict, size_t first_percent) {
    std::string percent_decoded_buffer;
    std::string_view input = plain;
    if(first_percent != std::string_view::npos) {
      percent_decoded_buffer = unicode::percent_decode(plain, first_percent);
      input = percent_decoded_buffer;
    }
#if ADA_HAS_ICU
    out = std::string(255, 0);

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
    out.value().shrink_to_fit();

#elif defined(_WIN32)
    (void)be_strict; // unused.
    // Fallback on the system if ICU is not available.
    // Windows function assumes UTF-16.
    std::unique_ptr<char16_t[]> buffer(new char16_t[input.size()]);
    auto convert = [](const char* buf, size_t len, char16_t* utf16_output) {
    const uint8_t *data = reinterpret_cast<const uint8_t *>(buf);
      size_t pos = 0;
      char16_t* start{utf16_output};
      while (pos < len) {
        // try to convert the next block of 16 ASCII bytes
        if (pos + 16 <= len) { // if it is safe to read 16 more bytes, check that they are ascii
          uint64_t v1;
          ::memcpy(&v1, data + pos, sizeof(uint64_t));
          uint64_t v2;
          ::memcpy(&v2, data + pos + sizeof(uint64_t), sizeof(uint64_t));
          uint64_t v{v1 | v2};
          if ((v & 0x8080808080808080) == 0) {
            size_t final_pos = pos + 16;
            while(pos < final_pos) {
              *utf16_output++ = char16_t(buf[pos]);
              pos++;
            }
            continue;
          }
        }
        uint8_t leading_byte = data[pos]; // leading byte
        if (leading_byte < 0b10000000) {
          // converting one ASCII byte !!!
          *utf16_output++ = char16_t(leading_byte);
          pos++;
        } else if ((leading_byte & 0b11100000) == 0b11000000) {
          // We have a two-byte UTF-8, it should become
          // a single UTF-16 word.
          if(pos + 1 >= len) { return 0; } // minimal bound checking
          if ((data[pos + 1] & 0b11000000) != 0b10000000) { return 0; }
          // range check
          uint32_t code_point = (leading_byte & 0b00011111) << 6 | (data[pos + 1] & 0b00111111);
          if (code_point < 0x80 || 0x7ff < code_point) { return 0; }
          *utf16_output++ = char16_t(code_point);
          pos += 2;
        } else if ((leading_byte & 0b11110000) == 0b11100000) {
          // We have a three-byte UTF-8, it should become
          // a single UTF-16 word.
          if(pos + 2 >= len) { return 0; } // minimal bound checking

          if ((data[pos + 1] & 0b11000000) != 0b10000000) { return 0; }
          if ((data[pos + 2] & 0b11000000) != 0b10000000) { return 0; }
          // range check
          uint32_t code_point = (leading_byte & 0b00001111) << 12 |
                      (data[pos + 1] & 0b00111111) << 6 |
                      (data[pos + 2] & 0b00111111);
          if (code_point < 0x800 || 0xffff < code_point ||
              (0xd7ff < code_point && code_point < 0xe000)) {
            return 0;
          }
          *utf16_output++ = char16_t(code_point);
          pos += 3;
        } else if ((leading_byte & 0b11111000) == 0b11110000) { // 0b11110000
          // we have a 4-byte UTF-8 word.
          if(pos + 3 >= len) { return 0; } // minimal bound checking
          if ((data[pos + 1] & 0b11000000) != 0b10000000) { return 0; }
          if ((data[pos + 2] & 0b11000000) != 0b10000000) { return 0; }
          if ((data[pos + 3] & 0b11000000) != 0b10000000) { return 0; }

          // range check
          uint32_t code_point =
              (leading_byte & 0b00000111) << 18 | (data[pos + 1] & 0b00111111) << 12 |
              (data[pos + 2] & 0b00111111) << 6 | (data[pos + 3] & 0b00111111);
          if (code_point <= 0xffff || 0x10ffff < code_point) { return 0; }
          code_point -= 0x10000;
          uint16_t high_surrogate = uint16_t(0xD800 + (code_point >> 10));
          uint16_t low_surrogate = uint16_t(0xDC00 + (code_point & 0x3FF));
          *utf16_output++ = char16_t(high_surrogate);
          *utf16_output++ = char16_t(low_surrogate);
          pos += 4;
        } else {
          return 0;
        }
      }
      return int(utf16_output - start);
    };
    size_t codepoints = convert(input.data(), input.size(), buffer.get());
    if(codepoints == 0) {
          out = std::nullopt;
          return false;
    }
    int required_buffer_size = IdnToAscii(IDN_ALLOW_UNASSIGNED, (LPCWSTR)buffer.get(), codepoints, NULL, 0);

    if(required_buffer_size == 0) {
      out = std::nullopt;
      return false;
    }

    out = std::string(required_buffer_size, 0);
    std::unique_ptr<char16_t[]> ascii_buffer(new char16_t[required_buffer_size]);

    required_buffer_size = IdnToAscii(IDN_ALLOW_UNASSIGNED, (LPCWSTR)buffer.get(), codepoints, (LPWSTR)ascii_buffer.get(), required_buffer_size);
    if(required_buffer_size == 0) {
      out = std::nullopt;
      return false;
    }
    // This will not validate the punycode, so let us work it in reverse.
    int test_reverse = IdnToUnicode(IDN_ALLOW_UNASSIGNED, (LPCWSTR)ascii_buffer.get(), required_buffer_size, NULL, 0);
    if(test_reverse == 0) {
      out = std::nullopt;
      return false;
    }
    out = std::string(required_buffer_size, 0);
    for(size_t i = 0; i < required_buffer_size; i++) { (*out)[i] = char(ascii_buffer.get()[i]); }
#else
    (void)be_strict; // unused.
    out = input; // We cannot do much more for now.
#endif
    if(std::any_of(out.value().begin(), out.value().end(), ada::unicode::is_forbidden_domain_code_point)) {
      out = std::nullopt;
      return false;
    }
    return true;
  }

} // namespace ada::unicode

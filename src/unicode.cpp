#include "ada/common_defs.h"
#include "ada/character_sets-inl.h"
#include "ada/character_sets.h"
#include "ada/unicode.h"
#include "ada/log.h"

ADA_PUSH_DISABLE_ALL_WARNINGS
#include "ada_idna.cpp"
ADA_POP_DISABLE_WARNINGS

#include <algorithm>
#if ADA_NEON
#include <arm_neon.h>
#elif ADA_SSE2
#include <emmintrin.h>
#elif ADA_LSX
#include <lsxintrin.h>
#endif

#include <ranges>

namespace ada::unicode {

constexpr bool is_tabs_or_newline(char c) noexcept {
  return c == '\r' || c == '\n' || c == '\t';
}

constexpr uint64_t broadcast(uint8_t v) noexcept {
  return 0x101010101010101ull * v;
}

constexpr bool to_lower_ascii(char* input, size_t length) noexcept {
  uint64_t broadcast_80 = broadcast(0x80);
  uint64_t broadcast_Ap = broadcast(128 - 'A');
  uint64_t broadcast_Zp = broadcast(128 - 'Z' - 1);
  uint64_t non_ascii = 0;
  size_t i = 0;

  for (; i + 7 < length; i += 8) {
    uint64_t word{};
    memcpy(&word, input + i, sizeof(word));
    non_ascii |= (word & broadcast_80);
    word ^=
        (((word + broadcast_Ap) ^ (word + broadcast_Zp)) & broadcast_80) >> 2;
    memcpy(input + i, &word, sizeof(word));
  }
  if (i < length) {
    uint64_t word{};
    memcpy(&word, input + i, length - i);
    non_ascii |= (word & broadcast_80);
    word ^=
        (((word + broadcast_Ap) ^ (word + broadcast_Zp)) & broadcast_80) >> 2;
    memcpy(input + i, &word, length - i);
  }
  return non_ascii == 0;
}
#if ADA_NEON
ada_really_inline bool has_tabs_or_newline(
    std::string_view user_input) noexcept {
  // first check for short strings in which case we do it naively.
  if (user_input.size() < 16) {  // slow path
    return std::ranges::any_of(user_input, is_tabs_or_newline);
  }
  // fast path for long strings (expected to be common)
  size_t i = 0;
  /**
   * The fastest way to check for `\t` (==9), '\n'(== 10) and `\r` (==13) relies
   * on table lookup instruction. We notice that these are all unique numbers
   * between 0..15. Let's prepare a special register, where we put '\t' in the
   * 9th position, '\n' - 10th and '\r' - 13th. Then we shuffle this register by
   * input register. If the input had `\t` in position X then this shuffled
   * register will also have '\t' in that position. Comparing input with this
   * shuffled register will mark us all interesting characters in the input.
   *
   * credit for algorithmic idea: @aqrit, credit for description:
   * @DenisYaroshevskiy
   */
  static uint8_t rnt_array[16] = {1, 0, 0,  0, 0, 0,  0, 0,
                                  0, 9, 10, 0, 0, 13, 0, 0};
  const uint8x16_t rnt = vld1q_u8(rnt_array);
  // m['0xd', '0xa', '0x9']
  uint8x16_t running{0};
  for (; i + 15 < user_input.size(); i += 16) {
    uint8x16_t word = vld1q_u8((const uint8_t*)user_input.data() + i);

    running = vorrq_u8(running, vceqq_u8(vqtbl1q_u8(rnt, word), word));
  }
  if (i < user_input.size()) {
    uint8x16_t word =
        vld1q_u8((const uint8_t*)user_input.data() + user_input.length() - 16);
    running = vorrq_u8(running, vceqq_u8(vqtbl1q_u8(rnt, word), word));
  }
  return vmaxvq_u32(vreinterpretq_u32_u8(running)) != 0;
}
#elif ADA_SSE2
ada_really_inline bool has_tabs_or_newline(
    std::string_view user_input) noexcept {
  // first check for short strings in which case we do it naively.
  if (user_input.size() < 16) {  // slow path
    return std::ranges::any_of(user_input, is_tabs_or_newline);
  }
  // fast path for long strings (expected to be common)
  size_t i = 0;
  const __m128i mask1 = _mm_set1_epi8('\r');
  const __m128i mask2 = _mm_set1_epi8('\n');
  const __m128i mask3 = _mm_set1_epi8('\t');
  // If we supported SSSE3, we could use the algorithm that we use for NEON.
  __m128i running{0};
  for (; i + 15 < user_input.size(); i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(user_input.data() + i));
    running = _mm_or_si128(
        _mm_or_si128(running, _mm_or_si128(_mm_cmpeq_epi8(word, mask1),
                                           _mm_cmpeq_epi8(word, mask2))),
        _mm_cmpeq_epi8(word, mask3));
  }
  if (i < user_input.size()) {
    __m128i word = _mm_loadu_si128(
        (const __m128i*)(user_input.data() + user_input.length() - 16));
    running = _mm_or_si128(
        _mm_or_si128(running, _mm_or_si128(_mm_cmpeq_epi8(word, mask1),
                                           _mm_cmpeq_epi8(word, mask2))),
        _mm_cmpeq_epi8(word, mask3));
  }
  return _mm_movemask_epi8(running) != 0;
}
#elif ADA_LSX
ada_really_inline bool has_tabs_or_newline(
    std::string_view user_input) noexcept {
  // first check for short strings in which case we do it naively.
  if (user_input.size() < 16) {  // slow path
    return std::ranges::any_of(user_input, is_tabs_or_newline);
  }
  // fast path for long strings (expected to be common)
  size_t i = 0;
  const __m128i mask1 = __lsx_vrepli_b('\r');
  const __m128i mask2 = __lsx_vrepli_b('\n');
  const __m128i mask3 = __lsx_vrepli_b('\t');
  // If we supported SSSE3, we could use the algorithm that we use for NEON.
  __m128i running{0};
  for (; i + 15 < user_input.size(); i += 16) {
    __m128i word = __lsx_vld((const __m128i*)(user_input.data() + i), 0);
    running = __lsx_vor_v(
        __lsx_vor_v(running, __lsx_vor_v(__lsx_vseq_b(word, mask1),
                                         __lsx_vseq_b(word, mask2))),
        __lsx_vseq_b(word, mask3));
  }
  if (i < user_input.size()) {
    __m128i word = __lsx_vld(
        (const __m128i*)(user_input.data() + user_input.length() - 16), 0);
    running = __lsx_vor_v(
        __lsx_vor_v(running, __lsx_vor_v(__lsx_vseq_b(word, mask1),
                                         __lsx_vseq_b(word, mask2))),
        __lsx_vseq_b(word, mask3));
  }
  if (__lsx_bz_v(running)) return false;
  return true;
}
#else
ada_really_inline bool has_tabs_or_newline(
    std::string_view user_input) noexcept {
  auto has_zero_byte = [](uint64_t v) {
    return ((v - 0x0101010101010101) & ~(v) & 0x8080808080808080);
  };
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
#endif

// A forbidden host code point is U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR,
// U+0020 SPACE, U+0023 (#), U+002F (/), U+003A (:), U+003C (<), U+003E (>),
// U+003F (?), U+0040 (@), U+005B ([), U+005C (\), U+005D (]), U+005E (^), or
// U+007C (|).
constexpr static std::array<uint8_t, 256> is_forbidden_host_code_point_table =
    []() consteval {
      std::array<uint8_t, 256> result{};
      for (uint8_t c : {'\0', '\x09', '\x0a', '\x0d', ' ', '#', '/', ':', '<',
                        '>', '?', '@', '[', '\\', ']', '^', '|'}) {
        result[c] = true;
      }
      return result;
    }();

ada_really_inline constexpr bool is_forbidden_host_code_point(
    const char c) noexcept {
  return is_forbidden_host_code_point_table[uint8_t(c)];
}

constexpr static std::array<uint8_t, 256> is_forbidden_domain_code_point_table =
    []() consteval {
      std::array<uint8_t, 256> result{};
      for (uint8_t c : {'\0', '\x09', '\x0a', '\x0d', ' ', '#', '/', ':', '<',
                        '>', '?', '@', '[', '\\', ']', '^', '|', '%'}) {
        result[c] = true;
      }
      for (uint8_t c = 0; c <= 32; c++) {
        result[c] = true;
      }
      for (size_t c = 127; c < 255; c++) {
        result[c] = true;
      }
      return result;
    }();

static_assert(sizeof(is_forbidden_domain_code_point_table) == 256);

ada_really_inline constexpr bool is_forbidden_domain_code_point(
    const char c) noexcept {
  return is_forbidden_domain_code_point_table[uint8_t(c)];
}

ada_really_inline constexpr bool contains_forbidden_domain_code_point(
    const char* input, size_t length) noexcept {
  size_t i = 0;
  uint8_t accumulator{};
  for (; i + 4 <= length; i += 4) {
    accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i])];
    accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i + 1])];
    accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i + 2])];
    accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i + 3])];
  }
  for (; i < length; i++) {
    accumulator |= is_forbidden_domain_code_point_table[uint8_t(input[i])];
  }
  return accumulator;
}

constexpr static std::array<uint8_t, 256>
    is_forbidden_domain_code_point_table_or_upper = []() consteval {
      std::array<uint8_t, 256> result{};
      for (uint8_t c : {'\0', '\x09', '\x0a', '\x0d', ' ', '#', '/', ':', '<',
                        '>', '?', '@', '[', '\\', ']', '^', '|', '%'}) {
        result[c] = 1;
      }
      for (uint8_t c = 'A'; c <= 'Z'; c++) {
        result[c] = 2;
      }
      for (uint8_t c = 0; c <= 32; c++) {
        result[c] = 1;
      }
      for (size_t c = 127; c < 255; c++) {
        result[c] = 1;
      }
      return result;
    }();

ada_really_inline constexpr uint8_t
contains_forbidden_domain_code_point_or_upper(const char* input,
                                              size_t length) noexcept {
  size_t i = 0;
  uint8_t accumulator{};
  for (; i + 4 <= length; i += 4) {
    accumulator |=
        is_forbidden_domain_code_point_table_or_upper[uint8_t(input[i])];
    accumulator |=
        is_forbidden_domain_code_point_table_or_upper[uint8_t(input[i + 1])];
    accumulator |=
        is_forbidden_domain_code_point_table_or_upper[uint8_t(input[i + 2])];
    accumulator |=
        is_forbidden_domain_code_point_table_or_upper[uint8_t(input[i + 3])];
  }
  for (; i < length; i++) {
    accumulator |=
        is_forbidden_domain_code_point_table_or_upper[uint8_t(input[i])];
  }
  return accumulator;
}

// std::isalnum(c) || c == '+' || c == '-' || c == '.') is true for
constexpr static std::array<bool, 256> is_alnum_plus_table = []() consteval {
  std::array<bool, 256> result{};
  for (size_t c = 0; c < 256; c++) {
    result[c] = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') || c == '+' || c == '-' || c == '.';
  }
  return result;
}();

ada_really_inline constexpr bool is_alnum_plus(const char c) noexcept {
  return is_alnum_plus_table[uint8_t(c)];
  // A table is almost surely much faster than the
  // following under most compilers: return
  // return (std::isalnum(c) || c == '+' || c == '-' || c == '.');
}

ada_really_inline constexpr bool is_ascii_hex_digit(const char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
         (c >= 'a' && c <= 'f');
}

ada_really_inline constexpr bool is_ascii_digit(const char c) noexcept {
  // An ASCII digit is a code point in the range U+0030 (0) to U+0039 (9),
  // inclusive.
  return (c >= '0' && c <= '9');
}

ada_really_inline constexpr bool is_ascii(const char32_t c) noexcept {
  // If code point is between U+0000 and U+007F inclusive, then return true.
  return c <= 0x7F;
}

ada_really_inline constexpr bool is_c0_control_or_space(const char c) noexcept {
  return (unsigned char)c <= ' ';
}

ada_really_inline constexpr bool is_ascii_tab_or_newline(
    const char c) noexcept {
  return c == '\t' || c == '\n' || c == '\r';
}

constexpr std::string_view table_is_double_dot_path_segment[] = {
    "..", "%2e.", ".%2e", "%2e%2e"};

ada_really_inline constexpr bool is_double_dot_path_segment(
    std::string_view input) noexcept {
  // This will catch most cases:
  // The length must be 2,4 or 6.
  // We divide by two and require
  // that the result be between 1 and 3 inclusively.
  uint64_t half_length = uint64_t(input.size()) / 2;
  if (half_length - 1 > 2) {
    return false;
  }
  // We have a string of length 2, 4 or 6.
  // We now check the first character:
  if ((input[0] != '.') && (input[0] != '%')) {
    return false;
  }
  // We are unlikely the get beyond this point.
  int hash_value = (input.size() + (unsigned)(input[0])) & 3;
  const std::string_view target = table_is_double_dot_path_segment[hash_value];
  if (target.size() != input.size()) {
    return false;
  }
  // We almost never get here.
  // Optimizing the rest is relatively unimportant.
  auto prefix_equal_unsafe = [](std::string_view a, std::string_view b) {
    uint16_t A, B;
    memcpy(&A, a.data(), sizeof(A));
    memcpy(&B, b.data(), sizeof(B));
    return A == B;
  };
  if (!prefix_equal_unsafe(input, target)) {
    return false;
  }
  for (size_t i = 2; i < input.size(); i++) {
    char c = input[i];
    if ((uint8_t((c | 0x20) - 0x61) <= 25 ? (c | 0x20) : c) != target[i]) {
      return false;
    }
  }
  return true;
  // The above code might be a bit better than the code below. Compilers
  // are not stupid and may use the fact that these strings have length 2,4 and
  // 6 and other tricks.
  // return input == ".." ||
  //  input == ".%2e" || input == ".%2E" ||
  //  input == "%2e." || input == "%2E." ||
  //  input == "%2e%2e" || input == "%2E%2E" || input == "%2E%2e" || input ==
  //  "%2e%2E";
}

ada_really_inline constexpr bool is_single_dot_path_segment(
    std::string_view input) noexcept {
  return input == "." || input == "%2e" || input == "%2E";
}

ada_really_inline constexpr bool is_lowercase_hex(const char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

constexpr static char hex_to_binary_table[] = {
    0,  1,  2,  3,  4, 5, 6, 7, 8, 9, 0, 0,  0,  0,  0,  0,  0, 10, 11,
    12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0,  0,
    0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15};
unsigned constexpr convert_hex_to_binary(const char c) noexcept {
  return hex_to_binary_table[c - '0'];
}

std::string percent_decode(const std::string_view input, size_t first_percent) {
  // next line is for safety only, we expect users to avoid calling
  // percent_decode when first_percent is outside the range.
  if (first_percent == std::string_view::npos) {
    return std::string(input);
  }
  std::string dest;
  dest.reserve(input.length());
  dest.append(input.substr(0, first_percent));
  const char* pointer = input.data() + first_percent;
  const char* end = input.data() + input.size();
  // Optimization opportunity: if the following code gets
  // called often, it can be optimized quite a bit.
  while (pointer < end) {
    const char ch = pointer[0];
    size_t remaining = end - pointer - 1;
    if (ch != '%' || remaining < 2 ||
        (  // ch == '%' && // It is unnecessary to check that ch == '%'.
            (!is_ascii_hex_digit(pointer[1]) ||
             !is_ascii_hex_digit(pointer[2])))) {
      dest += ch;
      pointer++;
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

std::string percent_encode(const std::string_view input,
                           const uint8_t character_set[]) {
  auto pointer = std::ranges::find_if(input, [character_set](const char c) {
    return character_sets::bit_at(character_set, c);
  });
  // Optimization: Don't iterate if percent encode is not required
  if (pointer == input.end()) {
    return std::string(input);
  }

  std::string result;
  result.reserve(input.length());  // in the worst case, percent encoding might
                                   // produce 3 characters.
  result.append(input.substr(0, std::distance(input.begin(), pointer)));

  for (; pointer != input.end(); pointer++) {
    if (character_sets::bit_at(character_set, *pointer)) {
      result.append(character_sets::hex + uint8_t(*pointer) * 4, 3);
    } else {
      result += *pointer;
    }
  }

  return result;
}

template <bool append>
bool percent_encode(const std::string_view input, const uint8_t character_set[],
                    std::string& out) {
  ada_log("percent_encode ", input, " to output string while ",
          append ? "appending" : "overwriting");
  auto pointer = std::ranges::find_if(input, [character_set](const char c) {
    return character_sets::bit_at(character_set, c);
  });
  ada_log("percent_encode done checking, moved to ",
          std::distance(input.begin(), pointer));

  // Optimization: Don't iterate if percent encode is not required
  if (pointer == input.end()) {
    ada_log("percent_encode encoding not needed.");
    return false;
  }
  if constexpr (!append) {
    out.clear();
  }
  ada_log("percent_encode appending ", std::distance(input.begin(), pointer),
          " bytes");
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  out.append(input.data(), std::distance(input.begin(), pointer));
  ada_log("percent_encode processing ", std::distance(pointer, input.end()),
          " bytes");
  for (; pointer != input.end(); pointer++) {
    if (character_sets::bit_at(character_set, *pointer)) {
      out.append(character_sets::hex + uint8_t(*pointer) * 4, 3);
    } else {
      out += *pointer;
    }
  }
  return true;
}

bool to_ascii(std::optional<std::string>& out, const std::string_view plain,
              size_t first_percent) {
  std::string percent_decoded_buffer;
  std::string_view input = plain;
  if (first_percent != std::string_view::npos) {
    percent_decoded_buffer = unicode::percent_decode(plain, first_percent);
    input = percent_decoded_buffer;
  }
  // input is a non-empty UTF-8 string, must be percent decoded
  std::string idna_ascii = ada::idna::to_ascii(input);
  if (idna_ascii.empty() || contains_forbidden_domain_code_point(
                                idna_ascii.data(), idna_ascii.size())) {
    return false;
  }
  out = std::move(idna_ascii);
  return true;
}

std::string percent_encode(const std::string_view input,
                           const uint8_t character_set[], size_t index) {
  std::string out;
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  out.append(input.data(), index);
  auto pointer = input.begin() + index;
  for (; pointer != input.end(); pointer++) {
    if (character_sets::bit_at(character_set, *pointer)) {
      out.append(character_sets::hex + uint8_t(*pointer) * 4, 3);
    } else {
      out += *pointer;
    }
  }
  return out;
}

}  // namespace ada::unicode

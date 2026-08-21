#include "ada/unicode.h"

#include "ada/character_sets-inl.h"
#include "ada/character_sets.h"
#include "ada/common_defs.h"
#include "ada/log.h"

ADA_PUSH_DISABLE_ALL_WARNINGS
#include "ada_idna.cpp"
ADA_POP_DISABLE_WARNINGS

#include <algorithm>
#include <array>
#include <cstring>
#if ADA_SSSE3
#include <tmmintrin.h>
#define ADA_UNICODE_SSSE3 1
#elif ADA_NEON
#include <arm_neon.h>
#elif ADA_SSE2
#include <emmintrin.h>
#elif ADA_LSX
#include <lsxintrin.h>
#elif ADA_RVV
#include <riscv_vector.h>
#endif

// gcc/clang honor target("ssse3") on an SSE2 translation unit. clang-cl and
// MSVC do not: they still compile the function as SSE2, then reject
// always_inline _mm_shuffle_epi8. Same approach as parser.cpp.
#if !ADA_UNICODE_SSSE3 && (defined(__x86_64__) || defined(__amd64__)) && \
    defined(__GNUC__) && !defined(_MSC_VER)
#include <tmmintrin.h>
#define ADA_UNICODE_SSSE3 1
#define ADA_UNICODE_NEED_SSSE3_TARGET 1
#endif
#ifndef ADA_UNICODE_SSSE3
#define ADA_UNICODE_SSSE3 0
#endif
#ifdef ADA_UNICODE_NEED_SSSE3_TARGET
#define ADA_UNICODE_SIMD __attribute__((target("ssse3")))
#else
#define ADA_UNICODE_SIMD ada_really_inline
#endif

#ifdef ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
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
#if ADA_SSSE3
ada_really_inline bool has_tabs_or_newline(
    std::string_view user_input) noexcept {
  // first check for short strings in which case we do it naively.
  if (user_input.size() < 16) {  // slow path
    return std::ranges::any_of(user_input, is_tabs_or_newline);
  }
  // fast path for long strings (expected to be common)
  // Using SSSE3's _mm_shuffle_epi8 for table lookup (same approach as NEON)
  size_t i = 0;
  // Lookup table where positions 9, 10, 13 contain their own values
  // Everything else is set to 1 so it won't match
  const __m128i rnt =
      _mm_setr_epi8(1, 0, 0, 0, 0, 0, 0, 0, 0, 9, 10, 0, 0, 13, 0, 0);
  __m128i running = _mm_setzero_si128();
  for (; i + 15 < user_input.size(); i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(user_input.data() + i));
    // Shuffle the lookup table using input bytes as indices
    __m128i shuffled = _mm_shuffle_epi8(rnt, word);
    // Compare: if shuffled value matches input, we found \t, \n, or \r
    __m128i matches = _mm_cmpeq_epi8(shuffled, word);
    running = _mm_or_si128(running, matches);
  }
  if (i < user_input.size()) {
    __m128i word = _mm_loadu_si128(
        (const __m128i*)(user_input.data() + user_input.length() - 16));
    __m128i shuffled = _mm_shuffle_epi8(rnt, word);
    __m128i matches = _mm_cmpeq_epi8(shuffled, word);
    running = _mm_or_si128(running, matches);
  }
  return _mm_movemask_epi8(running) != 0;
}
#elif ADA_NEON
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
  // `running` accumulates comparison results, so every lane is 0x00 or 0xFF:
  // narrowing to four bits per lane and comparing the result against zero as a
  // double is a cheaper "is anything set?" test than a horizontal maximum.
  uint8x8_t narrowed = vshrn_n_u16(vreinterpretq_u16_u8(running), 4);
  return vdupd_lane_f64(vreinterpret_f64_u8(narrowed), 0) != 0.0;
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
#elif ADA_RVV
ada_really_inline bool has_tabs_or_newline(
    std::string_view user_input) noexcept {
  uint8_t* src = (uint8_t*)user_input.data();
  for (size_t vl, n = user_input.size(); n > 0; n -= vl, src += vl) {
    vl = __riscv_vsetvl_e8m1(n);
    vuint8m1_t v = __riscv_vle8_v_u8m1(src, vl);
    vbool8_t m1 = __riscv_vmseq(v, '\r', vl);
    vbool8_t m2 = __riscv_vmseq(v, '\n', vl);
    vbool8_t m3 = __riscv_vmseq(v, '\t', vl);
    vbool8_t m = __riscv_vmor(__riscv_vmor(m1, m2, vl), m3, vl);
    long idx = __riscv_vfirst(m, vl);
    if (idx >= 0) return true;
  }
  return false;
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
      for (size_t c = 127; c < 256; c++) {
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
      for (size_t c = 127; c < 256; c++) {
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

  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* const src = input.data();
  const char* const end = src + input.size();

  // Decoding never grows the string, so a single pre-sized buffer written via
  // bulk memcpy of the plain runs (then shrunk to the final length) avoids the
  // byte-at-a-time appends of the naive version.
  std::string out(input.size(), '\0');
  char* d = out.data();
  char* const d0 = d;

  std::memcpy(d, src, first_percent);
  d += first_percent;

  const char* p = src + first_percent;
  while (p < end) {
    if (*p == '%') {
      // Decode runs of valid %XX tightly (common for nested/encoded URLs).
      while (p + 2 < end && *p == '%') {
        if (!is_ascii_hex_digit(p[1]) || !is_ascii_hex_digit(p[2])) {
          break;
        }
        *d++ = static_cast<char>(convert_hex_to_binary(p[1]) * 16 +
                                 convert_hex_to_binary(p[2]));
        p += 3;
      }
      if (p < end && *p == '%') {
        // Not a valid escape (too few chars left or bad hex): copy '%'
        // literally and keep scanning after it.
        *d++ = *p++;
      }
    } else {
      const char* q = static_cast<const char*>(
          std::memchr(p, '%', static_cast<size_t>(end - p)));
      const char* run_end = q ? q : end;
      const size_t n = static_cast<size_t>(run_end - p);
      std::memcpy(d, p, n);
      d += n;
      p = run_end;
    }
  }

  out.resize(static_cast<size_t>(d - d0));
  return out;
}

// 0..15 for hex digits, 0xFF otherwise - validate and decode with two loads.
constexpr static std::array<uint8_t, 256> unhex_table = []() consteval {
  std::array<uint8_t, 256> t{};
  for (size_t i = 0; i < 256; ++i) {
    t[i] = 0xFF;
  }
  for (uint8_t i = 0; i < 10; ++i) {
    t[static_cast<size_t>('0') + i] = i;
  }
  for (uint8_t i = 0; i < 6; ++i) {
    t[static_cast<size_t>('A') + i] = static_cast<uint8_t>(10 + i);
    t[static_cast<size_t>('a') + i] = static_cast<uint8_t>(10 + i);
  }
  return t;
}();

std::string form_urlencoded_decode(const std::string_view input) {
  const size_t len = input.size();
  if (len == 0) [[unlikely]] {
    return {};
  }

  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* const src = input.data();
  const char* const end = src + len;
  const char* p = src;

  // Advance over the untransformed prefix.
  while (p < end && *p != '+' && *p != '%') {
    ++p;
  }
  if (p == end) {
    return std::string(input);
  }

  // Output is always at most as long as the input: write into a single
  // pre-sized buffer, then shrink to the final length.
  std::string out(len, '\0');
  char* d = out.data();
  char* const d0 = d;

  const size_t prefix = static_cast<size_t>(p - src);
  std::memcpy(d, src, prefix);
  d += prefix;

  while (p < end) {
    const char c = *p;
    if (c == '+') {
      *d++ = ' ';
      ++p;
    } else if (c == '%') {
      // Decode runs of valid %XX tightly (common for nested URL query values).
      while (p + 2 < end && *p == '%') {
        const uint8_t hi = unhex_table[static_cast<uint8_t>(p[1])];
        const uint8_t lo = unhex_table[static_cast<uint8_t>(p[2])];
        if ((hi | lo) >= 16) {
          break;
        }
        *d++ = static_cast<char>((hi << 4) | lo);
        p += 3;
      }
      if (p < end && *p == '%') {
        // Invalid escape: copy '%' literally and continue.
        *d++ = *p++;
      }
    } else {
      // Copy a plain run until the next '+' or '%'.
      const char* start = p;
      ++p;
      while (p < end && *p != '+' && *p != '%') {
        ++p;
      }
      const size_t n = static_cast<size_t>(p - start);
      std::memcpy(d, start, n);
      d += n;
    }
  }

  out.resize(static_cast<size_t>(d - d0));
  return out;
}

namespace {

ada_really_inline int trailing_zeroes32(uint32_t input_num) noexcept {
#ifdef ADA_REGULAR_VISUAL_STUDIO
  unsigned long ret;
  _BitScanForward(&ret, input_num);
  return static_cast<int>(ret);
#else
  return __builtin_ctz(input_num);
#endif
}

// Append one 16-byte window whose set bits mark bytes that need encoding.
ada_really_inline void encode_mask_window(const char* p, uint32_t mask,
                                          std::string& out) {
  size_t off = 0;
  while (mask != 0) {
    const int zero_run = trailing_zeroes32(mask);
    if (zero_run != 0) {
      out.append(p + off, static_cast<size_t>(zero_run));
    }
    off += static_cast<size_t>(zero_run);
    out.append(character_sets::hex + uint8_t(p[off]) * 4, 3);
    ++off;
    mask >>= static_cast<unsigned>(zero_run + 1);
  }
  if (off < 16) {
    out.append(p + off, 16 - off);
  }
}

ada_really_inline void percent_encode_to_scalar(const char* p, const char* end,
                                                const uint8_t character_set[],
                                                std::string& out) {
  for (; p != end; ++p) {
    if (character_sets::bit_at(character_set, *p)) {
      out.append(character_sets::hex + uint8_t(*p) * 4, 3);
    } else {
      out += *p;
    }
  }
}

#if ADA_UNICODE_SSSE3
// Classify 16 input bytes against the 32-byte character_set bitmap:
// bit_at(cs, b) == cs[b >> 3] & (1 << (b & 7)). pshufb looks up the two
// 16-byte halves of that bitmap; no per-call nibble table is built.
struct ssse3_percent_tables {
  __m128i cs_lo;
  __m128i cs_hi;
  __m128i pow2;
  __m128i mask_0f;
  __m128i mask_07;
  __m128i zero;
};

ADA_UNICODE_SIMD ssse3_percent_tables
load_ssse3_percent_tables(const uint8_t character_set[]) noexcept {
  ssse3_percent_tables t{};
  t.cs_lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(character_set));
  t.cs_hi =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(character_set + 16));
  // 1 << (0..7), duplicated so pshufb(index & 7) works for every lane.
  t.pow2 =
      _mm_setr_epi8(1, 2, 4, 8, 16, 32, 64, -128, 1, 2, 4, 8, 16, 32, 64, -128);
  t.mask_0f = _mm_set1_epi8(0x0F);
  t.mask_07 = _mm_set1_epi8(0x07);
  t.zero = _mm_setzero_si128();
  return t;
}

ADA_UNICODE_SIMD int ssse3_percent_mask(
    __m128i word, const ssse3_percent_tables& tables) noexcept {
  const __m128i idx = _mm_and_si128(_mm_srli_epi16(word, 3), tables.mask_0f);
  const __m128i lo = _mm_shuffle_epi8(tables.cs_lo, idx);
  const __m128i hi = _mm_shuffle_epi8(tables.cs_hi, idx);
  // Bytes 0x80-0xFF are signed-negative; select the high half of the bitmap.
  const __m128i high_byte = _mm_cmpgt_epi8(tables.zero, word);
  const __m128i cs_byte = _mm_or_si128(_mm_and_si128(hi, high_byte),
                                       _mm_andnot_si128(high_byte, lo));
  const __m128i bits =
      _mm_shuffle_epi8(tables.pow2, _mm_and_si128(word, tables.mask_07));
  const __m128i hits = _mm_and_si128(cs_byte, bits);
  return _mm_movemask_epi8(_mm_cmpeq_epi8(hits, tables.zero)) ^ 0xFFFF;
}

ADA_UNICODE_SIMD void percent_encode_to_ssse3(
    const char* p, const char* end, const uint8_t character_set[],
    const ssse3_percent_tables& tables, std::string& out) {
  while (p + 16 <= end) {
    const __m128i word = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
    const int mask = ssse3_percent_mask(word, tables);
    if (mask == 0) {
      out.append(p, 16);
    } else {
      encode_mask_window(p, static_cast<uint32_t>(mask), out);
    }
    p += 16;
  }
  percent_encode_to_scalar(p, end, character_set, out);
}
#endif  // ADA_UNICODE_SSSE3

#if ADA_NEON
ada_really_inline uint8x16x2_t
load_neon_percent_table(const uint8_t character_set[]) noexcept {
  uint8x16x2_t table{};
  table.val[0] = vld1q_u8(character_set);
  table.val[1] = vld1q_u8(character_set + 16);
  return table;
}

ada_really_inline uint8x16_t neon_percent_hits(uint8x16_t word,
                                               uint8x16x2_t table) noexcept {
  const uint8x16_t cs_bytes = vqtbl2q_u8(table, vshrq_n_u8(word, 3));
  const uint8x16_t bit_mask = vshlq_u8(
      vdupq_n_u8(1), vreinterpretq_s8_u8(vandq_u8(word, vdupq_n_u8(7))));
  return vandq_u8(cs_bytes, bit_mask);
}

ada_really_inline uint32_t neon_percent_mask(uint8x16_t hits) noexcept {
  const uint8x16_t cmp = vcgtq_u8(hits, vdupq_n_u8(0));
  const uint8x16_t bit = {1, 2, 4, 8, 16, 32, 64, 128,
                          1, 2, 4, 8, 16, 32, 64, 128};
  const uint8x16_t masked = vandq_u8(cmp, bit);
  return static_cast<uint32_t>(vaddv_u8(vget_low_u8(masked))) |
         (static_cast<uint32_t>(vaddv_u8(vget_high_u8(masked))) << 8);
}

ada_really_inline void percent_encode_to_neon(const char* p, const char* end,
                                              const uint8_t character_set[],
                                              uint8x16x2_t table,
                                              std::string& out) {
  while (p + 16 <= end) {
    const uint8x16_t hits =
        neon_percent_hits(vld1q_u8(reinterpret_cast<const uint8_t*>(p)), table);
    if (vmaxvq_u32(vreinterpretq_u32_u8(hits)) == 0) {
      out.append(p, 16);
    } else {
      encode_mask_window(p, neon_percent_mask(hits), out);
    }
    p += 16;
  }
  percent_encode_to_scalar(p, end, character_set, out);
}
#endif  // ADA_NEON

#if ADA_RVV
ada_really_inline void percent_encode_to_rvv(const char* p, const char* end,
                                             const uint8_t character_set[],
                                             std::string& out) {
  while (p < end) {
    const size_t remaining = static_cast<size_t>(end - p);
    const size_t vl = __riscv_vsetvl_e8m1(remaining);
    const vuint8m1_t word =
        __riscv_vle8_v_u8m1(reinterpret_cast<const uint8_t*>(p), vl);
    const vuint8m1_t cs_bytes =
        __riscv_vluxei8(character_set, __riscv_vsrl(word, 3, vl), vl);
    const vuint8m1_t bit_mask = __riscv_vsll(__riscv_vmv_v_x_u8m1(1, vl),
                                             __riscv_vand(word, 7, vl), vl);
    const long idx = __riscv_vfirst(
        __riscv_vmsne(__riscv_vand(cs_bytes, bit_mask, vl), 0, vl), vl);
    if (idx < 0) {
      out.append(p, vl);
      p += vl;
      continue;
    }
    if (idx > 0) {
      out.append(p, static_cast<size_t>(idx));
      p += idx;
    }
    out.append(character_sets::hex + uint8_t(*p) * 4, 3);
    ++p;
  }
}
#endif  // ADA_RVV

// Setter and existing percent_encode benches are 2-44 bytes. Table setup
// plus mask walking costs more instructions than bit_at on those inputs
// (especially dense USERINFO). SIMD pays off on the remaining suffix.
static constexpr size_t kPercentEncodeSimdMin = 48;

#if ADA_UNICODE_SSSE3 || ADA_NEON || ADA_RVV
#if ADA_UNICODE_SSSE3
ADA_UNICODE_SIMD
#endif
ada_never_inline void percent_encode_to_wide(const char* p, const char* end,
                                             const uint8_t character_set[],
                                             std::string& out) {
#if ADA_UNICODE_SSSE3
  const ssse3_percent_tables tables = load_ssse3_percent_tables(character_set);
  percent_encode_to_ssse3(p, end, character_set, tables, out);
#elif ADA_NEON
  percent_encode_to_neon(p, end, character_set,
                         load_neon_percent_table(character_set), out);
#else
  percent_encode_to_rvv(p, end, character_set, out);
#endif
}
#endif

void percent_encode_to(const char* p, const char* end,
                       const uint8_t character_set[], std::string& out) {
#if ADA_UNICODE_SSSE3 || ADA_NEON || ADA_RVV
  if (static_cast<size_t>(end - p) >= kPercentEncodeSimdMin) {
    percent_encode_to_wide(p, end, character_set, out);
    return;
  }
#endif
  percent_encode_to_scalar(p, end, character_set, out);
}

}  // namespace

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
  percent_encode_to(&*pointer, input.data() + input.size(), character_set,
                    result);
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
  // Keep this loop in the template so set_hash/set_search inlining matches
  // main. SIMD is only used by the allocating percent_encode overloads.
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
  percent_encode_to(input.data() + index, input.data() + input.size(),
                    character_set, out);
  return out;
}

}  // namespace ada::unicode

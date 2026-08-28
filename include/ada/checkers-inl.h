/**
 * @file checkers-inl.h
 * @brief Definitions for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_INL_H
#define ADA_CHECKERS_INL_H

#include <bit>
#include <cstdint>
#include <string_view>
#include "ada/checkers.h"
#include "ada/common_defs.h"

#if defined(ADA_AVX512) && defined(__AVX512VBMI2__)
#include <immintrin.h>
#endif

namespace ada::checkers {

constexpr bool is_digit(char x) noexcept { return (x >= '0') & (x <= '9'); }

constexpr bool is_ipv4_number_char(char x) noexcept {
  const unsigned char c = static_cast<unsigned char>(x);
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F') || c == 'x' || c == 'X';
}

// ".com" / ".COM" after an optional trailing dot. 'm' is an IPv4 number
// char, so last_label_may_be_a_number would otherwise walk the label.
constexpr bool ends_with_dot_com(const char* start, size_t n) noexcept {
  if (n > 0 && start[n - 1] == '.') {
    --n;
  }
  if (n < 4) {
    return false;
  }
  const uint32_t last4 = uint32_t(uint8_t(start[n - 4])) |
                         (uint32_t(uint8_t(start[n - 3])) << 8) |
                         (uint32_t(uint8_t(start[n - 2])) << 16) |
                         (uint32_t(uint8_t(start[n - 1])) << 24);
  return (last4 | 0x20202020u) == 0x6d6f632eu;
}

constexpr bool last_label_may_be_a_number(std::string_view view) noexcept {
  if (view.empty()) {
    return false;
  }
  const char* start = view.data();
  const char* end = start + view.size();
  if (end[-1] == '.') {
    --end;
    if (end == start) {
      return false;
    }
  }
  // .org / .net / .gov / ... end with a non-hex letter: one compare.
  if (!is_ipv4_number_char(end[-1])) {
    return false;
  }
  // .com ends with hex 'm'. Reject it before walking the label.
  if (end - start >= 4 &&
      ends_with_dot_com(start, static_cast<size_t>(end - start))) {
    return false;
  }
  const char* label = end;
  while (label != start && is_ipv4_number_char(label[-1])) {
    --label;
  }
  if (label != start && label[-1] != '.') {
    return false;
  }
  return label != end && is_digit(*label);
}

constexpr char to_lower(char x) noexcept { return (x | 0x20); }

constexpr bool is_alpha(char x) noexcept {
  return (to_lower(x) >= 'a') && (to_lower(x) <= 'z');
}

constexpr bool is_windows_drive_letter(std::string_view input) noexcept {
  return input.size() >= 2 &&
         (is_alpha(input[0]) && ((input[1] == ':') || (input[1] == '|'))) &&
         ((input.size() == 2) || (input[2] == '/' || input[2] == '\\' ||
                                  input[2] == '?' || input[2] == '#'));
}

constexpr bool is_normalized_windows_drive_letter(
    std::string_view input) noexcept {
  return input.size() == 2 && (is_alpha(input[0]) && (input[1] == ':'));
}

namespace detail {

// Unrolled pure-decimal IPv4. The common portable path for 7-16 byte hosts.
ada_really_inline uint64_t
parse_ipv4_decimal_scalar(const char* p, const char* pend) noexcept {
  uint32_t ipv4 = 0;
  for (int i = 0; i < 4; ++i) {
    if (p == pend) [[unlikely]] {
      return ipv4_fast_fail;
    }
    uint32_t val;
    char c = *p;
    if (c >= '0' && c <= '9') [[likely]] {
      val = static_cast<uint32_t>(c - '0');
      ++p;
    } else {
      return ipv4_fast_fail;
    }
    if (p < pend) {
      c = *p;
      if (c >= '0' && c <= '9') {
        if (val == 0) [[unlikely]] {
          return ipv4_fast_fail;
        }
        val = val * 10u + static_cast<uint32_t>(c - '0');
        ++p;
        if (p < pend) {
          c = *p;
          if (c >= '0' && c <= '9') {
            val = val * 10u + static_cast<uint32_t>(c - '0');
            ++p;
            if (val > 255u) [[unlikely]] {
              return ipv4_fast_fail;
            }
          }
        }
      }
    }
    ipv4 = (ipv4 << 8) | val;
    if (i < 3) {
      if (p == pend || *p != '.') [[unlikely]] {
        return ipv4_fast_fail;
      }
      ++p;
    }
  }
  if (p != pend) {
    if (p == pend - 1 && *p == '.') {
      return ipv4;
    }
    return ipv4_fast_fail;
  }
  return ipv4;
}

#if defined(ADA_AVX512) && defined(__AVX512VBMI2__)
// Table-free AVX-512VL IPv4 parse (simdip parse_ipv4_avx512vl_notab5).
// Needs VBMI2 for vpcompressb; ADA_AVX512 stays BW+VL (IPv6 does not use
// VBMI2). Masked load of exactly `len` bytes (no over-read). Digit
// placement is computed from compressed delimiter positions; octet > 255
// is a dword compare on the zero-padded reversed digit group, in parallel
// with the convert. Unusual-but-valid forms (octal, hex, leading zeros,
// fewer than four parts) return ipv4_fast_fail so the general parser runs.
ada_really_inline uint64_t try_parse_ipv4_avx512(const char* data,
                                                 size_t len) noexcept {
  // One trailing dot is WHATWG-legal ("1.2.3.4."); the SIMD kernel is
  // strict four-group dotted-decimal.
  if (data[len - 1] == '.') {
    --len;
  }
  if (len > 15) [[unlikely]] {
    return ipv4_fast_fail;
  }

#if defined(__BMI2__)
  const uint32_t len_mask = _bzhi_u32(0xFFFFFFFFu, static_cast<unsigned>(len));
#else
  const uint32_t len_mask = (1u << static_cast<unsigned>(len)) - 1u;
#endif
  const __mmask16 len_k = static_cast<__mmask16>(len_mask);
  const __m128i dot = _mm_set1_epi8('.');
  const __m128i v =
      _mm_mask_loadu_epi8(dot, len_k, reinterpret_cast<const void*>(data));

  const __mmask16 delim = _mm_cmpeq_epi8_mask(v, dot);
  const uint32_t dots = static_cast<uint32_t>(delim) & len_mask;
  const uint32_t keep = len_mask & ~dots;

  const __m128i zero = _mm_set1_epi8('0');
  const __m128i digits = _mm_sub_epi8(v, zero);
  const __mmask16 is_digit = _mm_cmple_epu8_mask(digits, _mm_set1_epi8(9));
  // Junk in a digit slot: inside [0, len) yet neither a digit nor a dot.
  const __mmask16 hole = _kandn_mask16(_kor_mask16(delim, is_digit), len_k);
  const __m128i v0 = _mm_maskz_mov_epi8(is_digit, digits);

  const __m128i iota =
      _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
  const __m128i c = _mm_maskz_compress_epi8(delim, iota);
  const __m128i k_rep =
      _mm_setr_epi8(0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3);
  const __m128i qi = _mm_shuffle_epi8(c, k_rep);
  const __m128i prev =
      _mm_shuffle_epi8(_mm_alignr_epi8(c, _mm_set1_epi8(-1), 15), k_rep);
  // Reversed group order: lane 4i+j fetches q_i-(j+1), so the dword is
  // ones | tens<<8 | hundreds<<16, monotone in the decimal value.
  const __m128i offr = _mm_setr_epi8(-1, -2, -3, -4, -1, -2, -3, -4, -1, -2, -3,
                                     -4, -1, -2, -3, -4);
  const __m128i idx = _mm_max_epi8(_mm_add_epi8(qi, offr), prev);
  const __m128i padded = _mm_shuffle_epi8(v0, idx);

  const __m128i lim =
      _mm_setr_epi8(5, 5, 2, 0, 5, 5, 2, 0, 5, 5, 2, 0, 5, 5, 2, 0);
  const __mmask8 over = _mm_cmpgt_epu32_mask(padded, lim);
  const __m128i wtsr =
      _mm_setr_epi8(1, 10, 100, 0, 1, 10, 100, 0, 1, 10, 100, 0, 1, 10, 100, 0);
#if defined(__AVX512VNNI__)
  const __m128i res = _mm_dpbusd_epi32(_mm_setzero_si128(), padded, wtsr);
#else
  const __m128i res =
      _mm_madd_epi16(_mm_maddubs_epi16(padded, wtsr), _mm_set1_epi16(1));
#endif

  const __m128i gmin =
      _mm_setr_epi8(1, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  const __m128i gmax =
      _mm_setr_epi8(2, 2, 2, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
  const __m128i gap = _mm_sub_epi8(c, _mm_slli_si128(c, 1));
  const __mmask16 bad_gap = _mm_cmpgt_epu8_mask(_mm_sub_epi8(gap, gmin), gmax);

  const uint32_t zero_bits =
      static_cast<uint32_t>(_mm_cmpeq_epi8_mask(v, zero));
  const uint32_t start_bits = (dots << 1) | 1u;

  const __mmask16 kerr =
      _kor_mask16(_kor_mask16(hole, static_cast<__mmask16>(over)), bad_gap);
  const uint32_t gerr = static_cast<uint32_t>(_mm_popcnt_u32(dots) ^ 3u) |
                        (zero_bits & start_bits & (keep >> 1));

  if ((gerr | static_cast<uint32_t>(kerr)) == 0) [[likely]] {
    const uint32_t packed =
        static_cast<uint32_t>(_mm_cvtsi128_si32(_mm_cvtepi32_epi8(res)));
#if defined(__GNUC__) || defined(__clang__)
    return static_cast<uint64_t>(__builtin_bswap32(packed));
#else
    return static_cast<uint64_t>(_byteswap_ulong(packed));
#endif
  }
  return ipv4_fast_fail;
}
#endif  // ADA_AVX512 && __AVX512VBMI2__

}  // namespace detail

/**
 * Fast pure-decimal IPv4 parse. Returns packed address or ipv4_fast_fail.
 * Accepts an optional single trailing dot.
 *
 * On AVX-512BW+VL+VBMI2 targets, uses a table-free SIMD parse (masked
 * load, no source over-read) based on parse_ipv4_avx512vl_notab5.
 * Otherwise uses an unrolled scalar path (typically faster than SSE2/NEON
 * pre-validation for these 7-16 byte hosts).
 */
ada_really_inline uint64_t
try_parse_ipv4_fast(std::string_view input) noexcept {
  const size_t len = input.size();
  // Shortest pure decimal: "0.0.0.0" (7). Longest + trailing dot: 16.
  if (len < 7 || len > 16) [[unlikely]] {
    return ipv4_fast_fail;
  }
  const char* data = input.data();

#if defined(ADA_AVX512) && defined(__AVX512VBMI2__)
  return detail::try_parse_ipv4_avx512(data, len);
#else
  return detail::parse_ipv4_decimal_scalar(data, data + len);
#endif
}

}  // namespace ada::checkers

#endif  // ADA_CHECKERS_INL_H

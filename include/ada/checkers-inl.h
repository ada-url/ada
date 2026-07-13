/**
 * @file checkers-inl.h
 * @brief Definitions for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_INL_H
#define ADA_CHECKERS_INL_H

#include <bit>
#include <cstdint>
#include <cstring>
#include <string_view>
#include "ada/checkers.h"
#include "ada/common_defs.h"

#if defined(ADA_AVX512)
#include <immintrin.h>
#endif

namespace ada::checkers {

constexpr bool has_hex_prefix_unsafe(std::string_view input) {
  // This is actually efficient code, see has_hex_prefix for the assembly.
  constexpr bool is_little_endian = std::endian::native == std::endian::little;
  constexpr uint16_t word0x = 0x7830;
  uint16_t two_first_bytes =
      static_cast<uint16_t>(input[0]) |
      static_cast<uint16_t>((static_cast<uint16_t>(input[1]) << 8));
  if constexpr (is_little_endian) {
    two_first_bytes |= 0x2000;
  } else {
    two_first_bytes |= 0x020;
  }
  return two_first_bytes == word0x;
}

constexpr bool has_hex_prefix(std::string_view input) {
  return input.size() >= 2 && has_hex_prefix_unsafe(input);
}

constexpr bool is_digit(char x) noexcept { return (x >= '0') & (x <= '9'); }

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
ada_really_inline uint64_t parse_ipv4_decimal_scalar(
    const char* p, const char* pend) noexcept {
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

#if defined(ADA_AVX512)
// After SIMD validation: fewer rejection branches on convert.
ada_really_inline uint64_t parse_ipv4_decimal_trusted(
    const char* p, const char* pend) noexcept {
  uint32_t ipv4 = 0;
  for (int i = 0; i < 4; ++i) {
    uint32_t val = static_cast<uint32_t>(*p - '0');
    ++p;
    if (p < pend && static_cast<unsigned char>(*p - '0') <= 9) {
      if (val == 0) [[unlikely]] {
        return ipv4_fast_fail;
      }
      val = val * 10u + static_cast<uint32_t>(*p - '0');
      ++p;
      if (p < pend && static_cast<unsigned char>(*p - '0') <= 9) {
        val = val * 10u + static_cast<uint32_t>(*p - '0');
        ++p;
        if (val > 255u) [[unlikely]] {
          return ipv4_fast_fail;
        }
      }
    }
    ipv4 = (ipv4 << 8) | val;
    if (i < 3) {
      ++p;  // trusted '.'
    }
  }
  return ipv4;  // trailing-dot already accounted for by caller via pend
}

// AVX-512 pure-decimal IPv4 (Lemire/Mula-style masked load + parallel checks).
// No over-read of the source string. Wins when the binary is built with
// -mavx512bw -mavx512vl (or -march that enables them).
ada_really_inline uint64_t try_parse_ipv4_avx512(const char* data,
                                                 size_t len) noexcept {
  const __mmask16 live = static_cast<__mmask16>((1u << len) - 1u);
  const __m128i input =
      _mm_maskz_loadu_epi8(live, reinterpret_cast<const void*>(data));
  const __mmask16 is_dot =
      _mm_mask_cmpeq_epi8_mask(live, input, _mm_set1_epi8('.'));
  const __m128i shifted = _mm_sub_epi8(input, _mm_set1_epi8('0'));
  const __mmask16 is_digit =
      _mm_mask_cmplt_epu8_mask(live, shifted, _mm_set1_epi8(10));
  if ((is_digit | is_dot) != live) {
    return ipv4_fast_fail;
  }
  const unsigned dot_count =
      static_cast<unsigned>(_mm_popcnt_u32(static_cast<unsigned>(is_dot)));
  size_t effective_len = len;
  if (dot_count == 3) {
    // ok
  } else if (dot_count == 4 && data[len - 1] == '.') {
    effective_len = len - 1;  // strip trailing dot for convert
  } else {
    return ipv4_fast_fail;
  }
  // Convert from a tiny stack copy so trusted peeks stay in-bounds.
  alignas(16) char buf[16]{};
  std::memcpy(buf, data, effective_len);
  return parse_ipv4_decimal_trusted(buf, buf + effective_len);
}
#endif  // ADA_AVX512

}  // namespace detail

/**
 * Fast pure-decimal IPv4 parse. Returns packed address or ipv4_fast_fail.
 * Accepts an optional single trailing dot.
 *
 * On AVX-512BW+VL targets, uses a masked-load SIMD kernel (no source
 * over-read) inspired by Lemire/Mula. Otherwise uses an unrolled scalar path
 * (typically faster than SSE2/NEON pre-validation for these 7-16 byte hosts).
 */
ada_really_inline uint64_t try_parse_ipv4_fast(
    std::string_view input) noexcept {
  const size_t len = input.size();
  // Shortest pure decimal: "0.0.0.0" (7). Longest + trailing dot: 16.
  if (len < 7 || len > 16) [[unlikely]] {
    return ipv4_fast_fail;
  }
  const char* data = input.data();

#if defined(ADA_AVX512)
  return detail::try_parse_ipv4_avx512(data, len);
#else
  return detail::parse_ipv4_decimal_scalar(data, data + len);
#endif
}

}  // namespace ada::checkers

#endif  // ADA_CHECKERS_INL_H

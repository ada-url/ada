/**
 * @file url_ip-inl.h
 * @brief Shared IPv4/IPv6 parsing helpers used by url and url_aggregator.
 *
 * Not part of the public API. Defined inline so the single-TU amalgamation
 * (ada.cpp) can include them from multiple translation-unit sources once.
 */
#ifndef ADA_URL_IP_INL_H
#define ADA_URL_IP_INL_H

#include "ada/common_defs.h"

#include <array>
#include <cstdint>

#if defined(ADA_AVX512)
#include <immintrin.h>
#endif

namespace ada::detail {

// 256-entry: 0xff = not hex, else nibble value.
inline constexpr std::array<uint8_t, 256> make_hex_nibble_table() noexcept {
  std::array<uint8_t, 256> t{};
  for (size_t i = 0; i < 256; ++i) {
    t[i] = 0xff;
  }
  for (size_t d = 0; d < 10; ++d) {
    t[size_t{'0'} + d] = static_cast<uint8_t>(d);
  }
  for (size_t d = 0; d < 6; ++d) {
    t[size_t{'a'} + d] = static_cast<uint8_t>(10 + d);
    t[size_t{'A'} + d] = static_cast<uint8_t>(10 + d);
  }
  return t;
}

inline constexpr auto hex_nibble = make_hex_nibble_table();

inline bool parse_ipv4_number(const char*& p, const char* end, uint64_t& value,
                              bool& is_pure_decimal) noexcept {
  is_pure_decimal = false;
  if (p >= end) [[unlikely]] {
    return false;
  }
  if (end - p >= 2 && p[0] == '0' && ((p[1] | 0x20) == 'x')) {
    p += 2;
    if (p == end || *p == '.') {
      value = 0;
      return true;
    }
    uint64_t v = 0;
    int digits = 0;
    while (p < end && *p != '.') {
      const uint8_t nib = hex_nibble[static_cast<unsigned char>(*p)];
      if (nib == 0xff || digits >= 8) [[unlikely]] {
        return false;
      }
      v = (v << 4) | nib;
      ++p;
      ++digits;
    }
    if (digits == 0) [[unlikely]] {
      return false;
    }
    value = v;
    return true;
  }
  if (end - p >= 2 && p[0] == '0' && p[1] >= '0' && p[1] <= '9') {
    ++p;
    uint64_t v = 0;
    while (p < end && *p != '.') {
      const char c = *p;
      if (c < '0' || c > '7') [[unlikely]] {
        return false;
      }
      if (v > (0xFFFFFFFFULL >> 3)) [[unlikely]] {
        return false;
      }
      v = (v << 3) | static_cast<uint64_t>(c - '0');
      ++p;
    }
    value = v;
    return true;
  }
  if (*p < '0' || *p > '9') [[unlikely]] {
    return false;
  }
  is_pure_decimal = true;
  uint64_t v = static_cast<uint64_t>(*p - '0');
  ++p;
  while (p < end && *p != '.') {
    const char c = *p;
    if (c < '0' || c > '9') [[unlikely]] {
      return false;
    }
    if (v > 429496729ULL) [[unlikely]] {
      return false;
    }
    v = v * 10u + static_cast<uint64_t>(c - '0');
    if (v > 0xFFFFFFFFULL) [[unlikely]] {
      return false;
    }
    ++p;
  }
  value = v;
  return true;
}

// Parse up to 4 hex digits. Returns digit count (0 if none).
inline int parse_hex_piece(const char*& pointer, const char* end,
                           uint16_t& value) noexcept {
  if (pointer == end) {
    return 0;
  }
  const uint8_t n0 = hex_nibble[static_cast<unsigned char>(*pointer)];
  if (n0 == 0xff) {
    return 0;
  }
  uint32_t v = n0;
  ++pointer;
  int length = 1;
  if (pointer != end) {
    const uint8_t n1 = hex_nibble[static_cast<unsigned char>(*pointer)];
    if (n1 != 0xff) {
      v = (v << 4) | n1;
      ++pointer;
      ++length;
      if (pointer != end) {
        const uint8_t n2 = hex_nibble[static_cast<unsigned char>(*pointer)];
        if (n2 != 0xff) {
          v = (v << 4) | n2;
          ++pointer;
          ++length;
          if (pointer != end) {
            const uint8_t n3 = hex_nibble[static_cast<unsigned char>(*pointer)];
            if (n3 != 0xff) {
              v = (v << 4) | n3;
              ++pointer;
              ++length;
            }
          }
        }
      }
    }
  }
  value = static_cast<uint16_t>(v);
  return length;
}

#if defined(ADA_AVX512)
// Classify an IPv6 host (no brackets) with one masked 512-bit load.
// Returns false if the colon/dot shape is impossible (e.g. two "::", >8
// colons, full form without 7 colons). Used as a cheap prefilter before the
// full WHATWG piece parser.
ada_really_inline bool ipv6_structure_plausible(const char* data,
                                                size_t len) noexcept {
  if (len < 2 || len > 45) {
    return false;
  }
  const __mmask64 live = static_cast<__mmask64>((1ULL << len) - 1ULL);
  const __m512i input =
      _mm512_maskz_loadu_epi8(live, reinterpret_cast<const void*>(data));
  const __mmask64 is_colon =
      _mm512_mask_cmpeq_epi8_mask(live, input, _mm512_set1_epi8(':'));
  const __mmask64 is_dot =
      _mm512_mask_cmpeq_epi8_mask(live, input, _mm512_set1_epi8('.'));
  const int colons =
      static_cast<int>(_mm_popcnt_u64(static_cast<uint64_t>(is_colon)));
  if (colons > 8) {
    return false;
  }
  const uint64_t doubles =
      static_cast<uint64_t>(is_colon) & (static_cast<uint64_t>(is_colon) << 1);
  if (doubles != 0 && (doubles & (doubles - 1)) != 0) {
    return false;  // more than one "::" (or ":::...")
  }
  const bool has_double = doubles != 0;
  const bool has_dot = is_dot != 0;
  if (!has_double && !has_dot && colons != 7) {
    return false;
  }
  return true;
}
#endif  // ADA_AVX512

}  // namespace ada::detail

#endif  // ADA_URL_IP_INL_H

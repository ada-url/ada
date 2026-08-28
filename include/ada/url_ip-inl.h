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
#include <string_view>

// The IPv6 kernel needs vpermi2b/vpermb (VBMI) and vpcompressb/vpexpandb
// (VBMI2) on top of ADA_AVX512's BW+VL.
#if defined(ADA_AVX512) && defined(__AVX512VBMI__) && defined(__AVX512VBMI2__)
#define ADA_AVX512_IPV6 1
#endif

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
      if (nib == 0xff) [[unlikely]] {
        return false;
      }
      if (v > (0xFFFFFFFFULL >> 4)) [[unlikely]] {
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

#if defined(ADA_AVX512_IPV6)
// Gather each group's up-to-four nibbles and fold them into eight hextets.
// `prev` is the byte before each group, so an index that runs off the front of
// a short group clamps onto a colon, which translates to zero: no write mask.
ada_really_inline void ipv6_gather(__m128i ends, __m128i prev, __m512i nib,
                                   std::array<uint16_t, 8>& address) noexcept {
  const __m256i grp =
      _mm256_setr_epi8(0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4,
                       4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7);
  const __m256i off = _mm256_setr_epi8(
      -4, -3, -2, -1, -4, -3, -2, -1, -4, -3, -2, -1, -4, -3, -2, -1, -4, -3,
      -2, -1, -4, -3, -2, -1, -4, -3, -2, -1, -4, -3, -2, -1);
  const __m256i idx = _mm256_max_epi8(
      _mm256_add_epi8(
          _mm256_permutexvar_epi8(grp, _mm256_castsi128_si256(ends)), off),
      _mm256_permutexvar_epi8(grp, _mm256_castsi128_si256(prev)));
  const __m256i gathered = _mm512_castsi512_si256(
      _mm512_permutexvar_epi8(_mm512_castsi256_si512(idx), nib));
  // (a,b) -> 16a+b are the sixteen address bytes; 256*hi+lo pairs them.
  const __m256i hextets = _mm256_madd_epi16(
      _mm256_maddubs_epi16(gathered, _mm256_set1_epi16(0x0110)),
      _mm256_set1_epi32(0x00010100));
  _mm_storeu_si128(reinterpret_cast<__m128i*>(address.data()),
                   _mm256_cvtepi32_epi16(hextets));
}

// Parse an IPv6 host with one masked 512-bit load. Derived from
// vtlmks/ipv6-avx512 (Peter Fors, MIT).
//
// Returns false when the input is outside this kernel's grammar and the caller
// must run the scalar parser. Otherwise `valid` receives the verdict, and
// `address` the eight hextets when valid.
ada_really_inline bool try_parse_ipv6_avx512(const char* data, size_t len,
                                             std::array<uint16_t, 8>& address,
                                             bool& valid) noexcept {
  if (len < 2 || len > 45) [[unlikely]] {
    return false;
  }
  // ':' rather than 0x80 for the colon, so a clamped index reads a zero nibble.
  alignas(64) static constexpr uint8_t hex_lo[64] = {
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
      0x07, 0x08, 0x09, 0x00, 0x80, 0x80, 0x80, 0x80, 0x80};
  alignas(64) static constexpr uint8_t hex_hi[64] = {
      0x80, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80};
  alignas(64) static constexpr uint8_t iota[64] = {
      0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
      32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
      48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63};

  const __mmask64 active =
      static_cast<__mmask64>(_bzhi_u64(~0ULL, static_cast<uint32_t>(len)));
  const __m512i colon = _mm512_set1_epi8(':');
  // Merging ':' into the tail makes the terminator at `len` a real colon, so
  // the compress mask below never has to be rebuilt in a general register.
  const __m512i v = _mm512_mask_loadu_epi8(colon, active, data);
  const __mmask64 mcolon = _mm512_cmpeq_epi8_mask(v, colon);

  // An embedded dotted quad is the one valid form this kernel does not cover.
  // Because that is the only gap, every other input it does not accept is
  // invalid, which is what makes `valid = false` below safe.
  if (_mm512_cmpeq_epi8_mask(v, _mm512_set1_epi8('.'))) [[unlikely]] {
    return false;
  }

  const __m512i nib = _mm512_permutex2var_epi8(_mm512_load_si512(hex_lo), v,
                                               _mm512_load_si512(hex_hi));
  const __m128i comp = _mm512_castsi512_si128(
      _mm512_maskz_compress_epi8(mcolon, _mm512_load_si512(iota)));
  const __m128i lane0 =
      _mm_setr_epi8(-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  const __m128i prev = _mm_or_si128(_mm_bslli_si128(comp, 1), lane0);
  const __m128i width = _mm_sub_epi8(comp, prev);  // one too large

  const uint64_t mc = static_cast<uint64_t>(mcolon);
  const uint64_t act = static_cast<uint64_t>(active);
  const uint64_t dc = mc & (mc >> 1) & (act >> 1);  // a "::" inside [0, len)

  if (!dc) {
    ipv6_gather(comp, prev, nib, address);
    // nib | (v & 0x80): one scan for non-hex bytes and for bytes whose high
    // bit made vpermi2b alias a legal one.
    const __m512i fused = _mm512_ternarylogic_epi32(
        nib, v, _mm512_set1_epi8(static_cast<char>(0x80)), 0xf8);
    // Lanes 8..15 bound against 255, which an unsigned byte cannot exceed.
    const __m128i wmax =
        _mm_setr_epi8(3, 3, 3, 3, 3, 3, 3, 3, -1, -1, -1, -1, -1, -1, -1, -1);
    __mmask64 err = _kandn_mask64(mcolon, _mm512_movepi8_mask(fused));
    err = _kor_mask64(
        err, static_cast<__mmask64>(static_cast<uint16_t>(_mm_cmpgt_epu8_mask(
                 _mm_sub_epi8(width, _mm_set1_epi8(2)), wmax))));
    valid = (_mm_popcnt_u64(mc & act) == 7) && !err;
    return true;
  }

  // Drop the zero-width gap field(s), then expand the surviving head and tail
  // fields into eight slots with all-zero groups inserted at the gap.
  const uint32_t head = static_cast<uint32_t>(_mm_popcnt_u64(mc & (dc - 1))) +
                        static_cast<uint32_t>(dc > 1);
  const __mmask16 keep = _mm_cmpgt_epi8_mask(width, _mm_set1_epi8(1));
  const uint32_t kept = static_cast<uint32_t>(_mm_popcnt_u32(keep));
  const __mmask16 slots = static_cast<__mmask16>(
      ~(_bzhi_u32(0xFFFFFFFFu, 8 - kept) << head) & 0xFFu);
  // Inserted groups take prev = -1, so their indices clamp to byte 63, a tail
  // colon, and read zero.
  ipv6_gather(_mm_maskz_expand_epi8(slots, _mm_maskz_compress_epi8(keep, comp)),
              _mm_mask_expand_epi8(_mm_set1_epi8(-1), slots,
                                   _mm_maskz_compress_epi8(keep, prev)),
              nib, address);

  uint64_t err = _mm512_movepi8_mask(v);    // high-bit bytes
  err |= _mm512_movepi8_mask(nib) & ~mc;    // non-hex
  err |= _blsr_u64(dc);                     // a second "::"
  err |= static_cast<uint64_t>(kept >= 8);  // "::" elides nothing
  err |= _mm_cmpgt_epu8_mask(width, _mm_set1_epi8(5)) & keep;  // group > 4
  err |= (mc & 1ULL) & ~dc;                                // leading lone ':'
  err |= ((mc >> (len - 1)) & 1ULL) & ~(dc >> (len - 2));  // trailing lone ':'
  valid = !err;
  return true;
}
#endif  // ADA_AVX512_IPV6

// Parse an IPv6 host (no surrounding brackets). Shared by url, url_aggregator,
// and the simple-absolute fast path.
inline bool parse_ipv6_address(std::string_view input,
                               std::array<uint16_t, 8>& address) noexcept {
  if (input.empty() || input.size() > 45) [[unlikely]] {
    return false;
  }
#if defined(ADA_AVX512_IPV6)
  if (bool simd_valid;
      try_parse_ipv6_avx512(input.data(), input.size(), address, simd_valid)) {
    return simd_valid;
  }
  address = {};
#endif
  const char* pointer = input.data();
  const char* const end = pointer + input.size();
  int piece_index = 0;
  int compress = -1;

  if (*pointer == ':') {
    if (input.size() == 1 || pointer[1] != ':') [[unlikely]] {
      return false;
    }
    pointer += 2;
    compress = ++piece_index;
  }

  while (pointer != end) {
    if (piece_index == 8) [[unlikely]] {
      return false;
    }
    if (*pointer == ':') {
      if (compress != -1) [[unlikely]] {
        return false;
      }
      ++pointer;
      compress = ++piece_index;
      continue;
    }

    uint16_t value = 0;
    const int length = parse_hex_piece(pointer, end, value);

    if (pointer != end && *pointer == '.') {
      if (length == 0) [[unlikely]] {
        return false;
      }
      pointer -= length;
      if (piece_index > 6) [[unlikely]] {
        return false;
      }

      int numbers_seen = 0;
      while (pointer != end) {
        int ipv4_piece = -1;
        if (numbers_seen > 0) {
          if (*pointer == '.' && numbers_seen < 4) {
            ++pointer;
          } else {
            return false;
          }
        }
        if (pointer == end || *pointer < '0' || *pointer > '9') [[unlikely]] {
          return false;
        }
        ipv4_piece = *pointer - '0';
        ++pointer;
        if (pointer != end && *pointer >= '0' && *pointer <= '9') {
          if (ipv4_piece == 0) [[unlikely]] {
            return false;
          }
          ipv4_piece = ipv4_piece * 10 + (*pointer - '0');
          ++pointer;
          if (pointer != end && *pointer >= '0' && *pointer <= '9') {
            ipv4_piece = ipv4_piece * 10 + (*pointer - '0');
            ++pointer;
            if (ipv4_piece > 255) [[unlikely]] {
              return false;
            }
          }
        }
        address[static_cast<size_t>(piece_index)] = static_cast<uint16_t>(
            address[static_cast<size_t>(piece_index)] * 0x100 +
            static_cast<uint16_t>(ipv4_piece));
        ++numbers_seen;
        if (numbers_seen == 2 || numbers_seen == 4) {
          ++piece_index;
        }
      }
      if (numbers_seen != 4) [[unlikely]] {
        return false;
      }
      break;
    }

    if (length == 0) [[unlikely]] {
      return false;
    }

    if (pointer != end && *pointer == ':') {
      ++pointer;
      if (pointer == end) [[unlikely]] {
        return false;
      }
    } else if (pointer != end) [[unlikely]] {
      return false;
    }

    address[static_cast<size_t>(piece_index)] = value;
    ++piece_index;
  }

  if (compress != -1) {
    const int right = piece_index - compress;
    if (right > 0) {
      const size_t dest = static_cast<size_t>(8 - right);
      const size_t src = static_cast<size_t>(compress);
      if (dest != src) {
        for (size_t i = static_cast<size_t>(right); i-- > 0;) {
          address[dest + i] = address[src + i];
          address[src + i] = 0;
        }
      }
    }
  } else if (piece_index != 8) [[unlikely]] {
    return false;
  }
  return true;
}

}  // namespace ada::detail

#endif  // ADA_URL_IP_INL_H

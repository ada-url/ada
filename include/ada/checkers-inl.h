/**
 * @file checkers-inl.h
 * @brief Definitions for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_INL_H
#define ADA_CHECKERS_INL_H

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include "ada/checkers.h"
#include "ada/common_defs.h"

#if defined(ADA_AVX512) && defined(__AVX512VBMI2__)
#define ADA_AVX512_IPV4 1
#elif defined(__x86_64__) && defined(__AVX2__) && defined(__BMI2__)
#define ADA_HYBRID_IPV4 1
#endif

#if defined(ADA_AVX512_IPV4) || defined(ADA_HYBRID_IPV4)
#include <immintrin.h>
#endif
#if defined(ADA_HYBRID_IPV4)
#include "ada/ipv4_hybrid_table.h"
#endif

namespace ada::checkers {

constexpr bool is_digit(char x) noexcept { return (x >= '0') & (x <= '9'); }

constexpr bool is_ipv4_number_char(char x) noexcept {
  const unsigned char c = static_cast<unsigned char>(x);
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F') || c == 'x' || c == 'X';
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
  if (!is_ipv4_number_char(end[-1])) {
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

#if defined(ADA_AVX512_IPV4)
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
#endif  // ADA_AVX512_IPV4

#if defined(ADA_HYBRID_IPV4)
// pext turns where the dots are into a table index; the entry's pshufb pattern
// lines up the digits for pmaddubsw, and its offsets range-check every lane.
//
// Lanes after the shuffle (T/O/H = tens/ones/hundreds of an octet):
//   lane:    0  1  2  3  4  5  6  7    8  9 10 11 12 13 14 15
//   holds:  Td Od Tc Oc Tb Ob Ta Oa   Hd  - Hc  . Hb  . Ha  .
//   weight: 10  1 10  1 10  1 10  1  100  0 100 0 100 0 100 0
namespace ipv4_hybrid {

#if defined(__znver1__) || defined(__znver2__)
// Zen 1 and Zen 2 run pext in microcode, so a mask and a multiply stand in for
// it: the multiply's partial products move the five digit bits to bits 59-63,
// with no two of them landing on the same bit (so no carries), and the shift
// leaves them in bits 1-5, the same doubled index pext gives for ASCII. Bit 7
// of char 0 is dropped: that char is a digit lane of every entry, so the range
// check rejects it anyway.
template <uint64_t mask>
constexpr size_t pext(uint64_t word) noexcept {
  constexpr uint64_t bits = mask & ~uint64_t(0x80);
  constexpr uint64_t magic = [] {
    uint64_t result = 0;
    int target = 59;
    for (uint64_t remaining = bits; remaining != 0;
         remaining &= remaining - 1, ++target) {
      result |= uint64_t(1) << (target - std::countr_zero(remaining));
    }
    return result;
  }();
  return ((word & bits) * magic) >> 58;
}

// Every placement of the five digit bits, with the other bits clear or set,
// must give pext's doubled index.
template <uint64_t mask>
constexpr bool pext_is_exact() noexcept {
  constexpr uint64_t bits = mask & ~uint64_t(0x80);
  for (size_t index = 0; index < entries_per_half; ++index) {
    uint64_t word = 0;
    size_t bit = 0;
    for (uint64_t remaining = bits; remaining != 0;
         remaining &= remaining - 1, ++bit) {
      if (((index >> bit) & 1) != 0) {
        word |= remaining & (~remaining + 1);
      }
    }
    if (pext<mask>(word) != 2 * index ||
        pext<mask>(word | ~bits) != 2 * index) {
      return false;
    }
  }
  return true;
}

static_assert(pext_is_exact<head_digit_bits>() &&
                  pext_is_exact<tail_digit_bits>(),
              "the multiply must match pext");
#else
template <uint64_t mask>
ada_really_inline size_t pext(uint64_t word) noexcept {
  return static_cast<size_t>(_pext_u64(word, mask));
}
#endif

}  // namespace ipv4_hybrid

// Only 7 chars: every octet is a single digit, so check the chars directly.
ada_really_inline uint64_t parse_ipv4_seven_chars(const char* data,
                                                  size_t len) noexcept {
  if (len != 7) {
    return ipv4_fast_fail;
  }

  uint32_t head;
  uint32_t tail;
  std::memcpy(&head, data, 4);
  std::memcpy(&tail, data + 3, 4);

  const __m128i values =
      _mm_sub_epi8(_mm_insert_epi32(_mm_cvtsi32_si128(static_cast<int>(head)),
                                    static_cast<int>(tail), 1),
                   _mm_setr_epi8('0', '.', '0', '.', '.', '0', '.', '0', 0, 0,
                                 0, 0, 0, 0, 0, 0));

  const __m128i over_max = _mm_subs_epu8(
      values, _mm_setr_epi8(9, 0, 9, 0, 0, 9, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0));
  if (_mm_cvtsi128_si64(over_max) != 0) {
    return ipv4_fast_fail;
  }

  // d, c, b, a: the packed address.
  return static_cast<uint32_t>(_mm_cvtsi128_si32(
      _mm_shuffle_epi8(values, _mm_setr_epi8(7, 5, 2, 0, -1, -1, -1, -1, -1, -1,
                                             -1, -1, -1, -1, -1, -1))));
}

// Strict four-group dotted-decimal, no trailing dot: unusual-but-valid forms
// (octal, hex, leading zeros, fewer than four parts) return ipv4_fast_fail so
// the general parser runs.
ada_really_inline uint64_t parse_ipv4_hybrid(const char* data,
                                             size_t len) noexcept {
  using ipv4_hybrid::high;
  using ipv4_hybrid::hybrid_table;
  using ipv4_hybrid::low;

  const size_t tail_offset = len - 8;
  if (tail_offset > 7) [[unlikely]] {
    return parse_ipv4_seven_chars(data, len);
  }

  uint64_t head;
  uint64_t tail;
  std::memcpy(&head, data, 8);
  std::memcpy(&tail, data + tail_offset, 8);
  // Loaded again from memory, which beats moving head and tail over from the
  // general purpose registers: the empty asm stops the compiler from reusing
  // the two loads above.
  const char* vector_data = data;
  __asm__("" : "+r"(vector_data));
  const __m128i head_tail = _mm_blend_epi32(
      _mm_loadl_epi64(reinterpret_cast<const __m128i*>(vector_data)),
      _mm_broadcastq_epi64(_mm_loadl_epi64(
          reinterpret_cast<const __m128i*>(vector_data + tail_offset))),
      0b1100);

  const size_t index_low =
      ipv4_hybrid::pext<ipv4_hybrid::head_digit_bits>(head);
  const size_t index_high =
      ipv4_hybrid::pext<ipv4_hybrid::tail_digit_bits>(tail);

  if (len - hybrid_table.get_length<low>(index_low) !=
      hybrid_table.get_length<high>(index_high)) {
    return ipv4_fast_fail;
  }

  const __m128i low_entry = _mm_loadu_si128(
      reinterpret_cast<const __m128i*>(hybrid_table.get<low>(index_low)));
  const __m128i high_entry = _mm_loadu_si128(
      reinterpret_cast<const __m128i*>(hybrid_table.get<high>(index_high)));

  // Interlaced 4 bytes at a time, high first.
  const __m128i pattern = _mm_unpacklo_epi32(high_entry, low_entry);
  const __m128i lanes =
      _mm_shuffle_epi8(_mm_sub_epi8(head_tail, _mm_set1_epi8('0')), pattern);
  const __m128i products =
      _mm_maddubs_epi16(lanes, _mm_setr_epi8(10, 1, 10, 1, 10, 1, 10, 1, 100, 0,
                                             100, 0, 100, 0, 100, 0));
  const __m128i sums =
      _mm_add_epi16(products, _mm_shuffle_epi32(products, 0xEE));

  const __m128i too_big = _mm_and_si128(
      sums,
      _mm_setr_epi16(static_cast<short>(0xFF00), static_cast<short>(0xFF00),
                     static_cast<short>(0xFF00), static_cast<short>(0xFF00), 0,
                     0, 0, 0));

  const __m128i sub = _mm_unpackhi_epi32(high_entry, low_entry);
  const __m128i flips = _mm_setr_epi8(9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                                      char(0xFE), 9, char(0xFE), 9, char(0xFE));
  const __m128i bad_lanes =
      _mm_subs_epu8(_mm_sub_epi8(lanes, sub), _mm_xor_si128(sub, flips));

  const __m128i errors = _mm_or_si128(too_big, bad_lanes);
  if (!_mm_testz_si128(errors, errors)) [[unlikely]] {
    return ipv4_fast_fail;
  }

  return static_cast<uint32_t>(_mm_cvtsi128_si32(_mm_packus_epi16(sums, sums)));
}

// The same, after dropping the trailing dot. Kept out of line: it only runs
// for the rare "1.2.3.4." form.
ada_never_inline uint64_t parse_ipv4_hybrid_trailing_dot(const char* data,
                                                         size_t len) noexcept {
  return parse_ipv4_hybrid(data, len - 1);
}

// One trailing dot is WHATWG-legal ("1.2.3.4."), but a strict address never
// ends with one: the dot is only looked at once the strict parse has failed,
// which keeps it off the common path.
ada_really_inline uint64_t try_parse_ipv4_hybrid(const char* data,
                                                 size_t len) noexcept {
  const uint64_t result = parse_ipv4_hybrid(data, len);
  if (result != ipv4_fast_fail || data[len - 1] != '.') {
    return result;
  }
  return parse_ipv4_hybrid_trailing_dot(data, len);
}
#endif  // ADA_HYBRID_IPV4

}  // namespace detail

/**
 * Fast pure-decimal IPv4 parse. Returns packed address or ipv4_fast_fail.
 * Accepts an optional single trailing dot.
 *
 * On AVX-512BW+VL+VBMI2 targets, uses a table-free SIMD parse (masked
 * load, no source over-read) based on parse_ipv4_avx512vl_notab5.
 * On x86-64 AVX2 + BMI2 targets, uses the hybrid pext + pshufb parse (two
 * 8-byte loads, no source over-read, small compile-time lookup table).
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

#if defined(ADA_AVX512_IPV4)
  return detail::try_parse_ipv4_avx512(data, len);
#elif defined(ADA_HYBRID_IPV4)
  return detail::try_parse_ipv4_hybrid(data, len);
#else
  return detail::parse_ipv4_decimal_scalar(data, data + len);
#endif
}

}  // namespace ada::checkers

#endif  // ADA_CHECKERS_INL_H

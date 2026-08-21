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
#include <cstdint>
#include <cstring>

#include "ada/unicode-inl.h"
#if ADA_SSSE3
#include <tmmintrin.h>
#define ADA_UNICODE_SSSE3_ENCODE 1
#elif (defined(__x86_64__) || defined(__amd64__)) && defined(__GNUC__) && \
    !defined(_MSC_VER)
// gcc/clang honor target("ssse3"). clang-cl and MSVC do not.
#include <tmmintrin.h>
#define ADA_UNICODE_SSSE3_ENCODE 1
#define ADA_UNICODE_NEED_SSSE3_TARGET 1
#elif ADA_NEON
#include <arm_neon.h>
#elif ADA_SSE2
#include <emmintrin.h>
#elif ADA_LSX
#include <lsxintrin.h>
#elif ADA_RVV
#include <riscv_vector.h>
#endif

#ifndef ADA_UNICODE_SSSE3_ENCODE
#define ADA_UNICODE_SSSE3_ENCODE 0
#endif

#ifdef ADA_UNICODE_NEED_SSSE3_TARGET
#define ADA_UNICODE_SIMD __attribute__((target("ssse3")))
#define ADA_UNICODE_SIMD_NOINLINE __attribute__((target("ssse3"), noinline))
#else
#define ADA_UNICODE_SIMD ada_really_inline
#ifdef ADA_REGULAR_VISUAL_STUDIO
#define ADA_UNICODE_SIMD_NOINLINE __declspec(noinline)
#else
#define ADA_UNICODE_SIMD_NOINLINE __attribute__((noinline))
#endif
#endif

#ifdef ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif

#include <ranges>

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

#if ADA_NEON
ada_really_inline int trailing_zeroes64(uint64_t input_num) noexcept {
#ifdef ADA_REGULAR_VISUAL_STUDIO
  unsigned long ret;
  _BitScanForward64(&ret, input_num);
  return static_cast<int>(ret);
#else
  return __builtin_ctzll(input_num);
#endif
}

ada_really_inline uint64_t neon_nibble_bits(uint8x16_t matches) noexcept {
  const uint8x8_t nib = vshrn_n_u16(vreinterpretq_u16_u8(matches), 4);
  return vget_lane_u64(vreinterpret_u64_u8(nib), 0);
}
#endif  // ADA_NEON

#if ADA_UNICODE_SSSE3_ENCODE || ADA_NEON
// Nibble classifier from oven-sh/WebKit#454 / parser.cpp: a byte is a hit
// when low[b & 0xF] & high[b >> 4] != 0. Built consteval from each 32-byte
// percent-encode bitset so the vector path cannot disagree with bit_at.
struct nibble_tables {
  alignas(16) uint8_t low[16]{};
  alignas(16) uint8_t high[16]{};
  bool fits{true};
};

consteval nibble_tables make_stop_nibble_tables(
    const std::array<uint8_t, 256>& cls) {
  nibble_tables t{};
  uint16_t patterns[16]{};
  for (int hi = 0; hi < 16; ++hi) {
    for (int lo = 0; lo < 16; ++lo) {
      if (cls[static_cast<size_t>((hi << 4) | lo)] != 0) {
        patterns[hi] = static_cast<uint16_t>(patterns[hi] | (1u << lo));
      }
    }
  }
  int bits_used = 0;
  for (int hi = 0; hi < 16; ++hi) {
    if (patterns[hi] == 0 || t.high[hi] != 0) {
      continue;
    }
    if (bits_used == 8) {
      t.fits = false;
      return t;
    }
    const uint8_t bit = static_cast<uint8_t>(1u << bits_used++);
    for (int other = hi; other < 16; ++other) {
      if (patterns[other] == patterns[hi]) {
        t.high[other] = static_cast<uint8_t>(t.high[other] | bit);
      }
    }
    for (int lo = 0; lo < 16; ++lo) {
      if ((patterns[hi] & (1u << lo)) != 0) {
        t.low[lo] = static_cast<uint8_t>(t.low[lo] | bit);
      }
    }
  }
  return t;
}

consteval nibble_tables make_bitset_nibble_tables(const uint8_t (&bits)[32]) {
  std::array<uint8_t, 256> cls{};
  for (size_t i = 0; i < 256; ++i) {
    if ((bits[i >> 3] & static_cast<uint8_t>(1u << (i & 7))) != 0) {
      cls[i] = 1;
    }
  }
  return make_stop_nibble_tables(cls);
}

consteval bool nibble_matches_bitset(const nibble_tables& t,
                                     const uint8_t (&bits)[32]) {
  for (int i = 0; i < 256; ++i) {
    const bool bit = (bits[i >> 3] & static_cast<uint8_t>(1u << (i & 7))) != 0;
    const bool hit = (t.low[i & 0xF] & t.high[i >> 4]) != 0;
    if (bit != hit) {
      return false;
    }
  }
  return true;
}

constexpr nibble_tables k_c0_nibbles =
    make_bitset_nibble_tables(ada::character_sets::C0_CONTROL_PERCENT_ENCODE);
constexpr nibble_tables k_special_query_nibbles = make_bitset_nibble_tables(
    ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE);
constexpr nibble_tables k_query_nibbles =
    make_bitset_nibble_tables(ada::character_sets::QUERY_PERCENT_ENCODE);
constexpr nibble_tables k_fragment_nibbles =
    make_bitset_nibble_tables(ada::character_sets::FRAGMENT_PERCENT_ENCODE);
constexpr nibble_tables k_userinfo_nibbles =
    make_bitset_nibble_tables(ada::character_sets::USERINFO_PERCENT_ENCODE);
constexpr nibble_tables k_path_nibbles =
    make_bitset_nibble_tables(ada::character_sets::PATH_PERCENT_ENCODE);
constexpr nibble_tables k_www_form_nibbles = make_bitset_nibble_tables(
    ada::character_sets::WWW_FORM_URLENCODED_PERCENT_ENCODE);
static_assert(
    k_c0_nibbles.fits &&
    nibble_matches_bitset(k_c0_nibbles,
                          ada::character_sets::C0_CONTROL_PERCENT_ENCODE));
static_assert(
    k_special_query_nibbles.fits &&
    nibble_matches_bitset(k_special_query_nibbles,
                          ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE));
static_assert(k_query_nibbles.fits &&
              nibble_matches_bitset(k_query_nibbles,
                                    ada::character_sets::QUERY_PERCENT_ENCODE));
static_assert(
    k_fragment_nibbles.fits &&
    nibble_matches_bitset(k_fragment_nibbles,
                          ada::character_sets::FRAGMENT_PERCENT_ENCODE));
static_assert(
    k_userinfo_nibbles.fits &&
    nibble_matches_bitset(k_userinfo_nibbles,
                          ada::character_sets::USERINFO_PERCENT_ENCODE));
static_assert(k_path_nibbles.fits &&
              nibble_matches_bitset(k_path_nibbles,
                                    ada::character_sets::PATH_PERCENT_ENCODE));
static_assert(k_www_form_nibbles.fits &&
              nibble_matches_bitset(
                  k_www_form_nibbles,
                  ada::character_sets::WWW_FORM_URLENCODED_PERCENT_ENCODE));

const nibble_tables* nibble_tables_for(const uint8_t* set) noexcept {
  if (set == ada::character_sets::FRAGMENT_PERCENT_ENCODE) {
    return &k_fragment_nibbles;
  }
  if (set == ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE) {
    return &k_special_query_nibbles;
  }
  if (set == ada::character_sets::QUERY_PERCENT_ENCODE) {
    return &k_query_nibbles;
  }
  if (set == ada::character_sets::USERINFO_PERCENT_ENCODE) {
    return &k_userinfo_nibbles;
  }
  if (set == ada::character_sets::PATH_PERCENT_ENCODE) {
    return &k_path_nibbles;
  }
  if (set == ada::character_sets::C0_CONTROL_PERCENT_ENCODE) {
    return &k_c0_nibbles;
  }
  if (set == ada::character_sets::WWW_FORM_URLENCODED_PERCENT_ENCODE) {
    return &k_www_form_nibbles;
  }
  return nullptr;
}
#endif  // ADA_UNICODE_SSSE3_ENCODE || ADA_NEON

#if ADA_UNICODE_SSSE3_ENCODE
ADA_UNICODE_SIMD int ssse3_nibble_mask(__m128i w, __m128i lo_tbl,
                                       __m128i hi_tbl) noexcept {
  const __m128i nibble = _mm_set1_epi8(0x0F);
  const __m128i lo = _mm_and_si128(w, nibble);
  const __m128i hi = _mm_and_si128(_mm_srli_epi16(w, 4), nibble);
  const __m128i hit =
      _mm_and_si128(_mm_shuffle_epi8(lo_tbl, lo), _mm_shuffle_epi8(hi_tbl, hi));
  return _mm_movemask_epi8(_mm_cmpeq_epi8(hit, _mm_setzero_si128())) ^ 0xFFFF;
}

// Decode up to five leading "%XX" groups from a 16-byte load (15 used).
ADA_UNICODE_SIMD unsigned ssse3_decode_pct_groups(const uint8_t* p,
                                                  uint8_t* d) noexcept {
  const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
  const int pct = _mm_movemask_epi8(_mm_cmpeq_epi8(w, _mm_set1_epi8('%')));
  if ((pct & 1) == 0) {
    return 0;
  }
  const __m128i extract =
      _mm_setr_epi8(1, 2, 4, 5, 7, 8, 10, 11, 13, 14, -1, -1, -1, -1, -1, -1);
  const __m128i hexes = _mm_shuffle_epi8(w, extract);
  const __m128i is_digit = _mm_and_si128(
      _mm_cmpgt_epi8(hexes, _mm_set1_epi8(static_cast<char>('0' - 1))),
      _mm_cmpgt_epi8(_mm_set1_epi8(static_cast<char>('9' + 1)), hexes));
  const __m128i lower = _mm_or_si128(hexes, _mm_set1_epi8(0x20));
  const __m128i is_letter = _mm_and_si128(
      _mm_cmpgt_epi8(lower, _mm_set1_epi8(static_cast<char>('a' - 1))),
      _mm_cmpgt_epi8(_mm_set1_epi8(static_cast<char>('f' + 1)), lower));
  const int hex_ok = _mm_movemask_epi8(_mm_or_si128(is_digit, is_letter));

  unsigned n = 0;
  unsigned need_pct = 1;
  unsigned need_hex = 3;
  for (; n < 5; ++n) {
    if ((pct & static_cast<int>(need_pct)) == 0) {
      break;
    }
    if ((hex_ok & static_cast<int>(need_hex)) != static_cast<int>(need_hex)) {
      break;
    }
    need_pct <<= 3;
    need_hex <<= 2;
  }
  if (n == 0) {
    return 0;
  }

  const __m128i lo = _mm_and_si128(hexes, _mm_set1_epi8(0x0F));
  const __m128i hi6 =
      _mm_and_si128(_mm_srli_epi16(hexes, 6), _mm_set1_epi8(0x03));
  const __m128i nibbles =
      _mm_add_epi8(lo, _mm_add_epi8(hi6, _mm_slli_epi16(hi6, 3)));
  const __m128i packed = _mm_maddubs_epi16(nibbles, _mm_set1_epi16(0x0110));
  const __m128i bytes = _mm_packus_epi16(packed, _mm_setzero_si128());
  alignas(16) uint8_t tmp[16];
  _mm_storeu_si128(reinterpret_cast<__m128i*>(tmp), bytes);
  std::memcpy(d, tmp, n);
  return n;
}

#endif  // ADA_UNICODE_SSSE3_ENCODE

#if ADA_UNICODE_SSSE3_ENCODE || ADA_SSE2
// Find is SSE2-only (cmpeq + movemask). Keep it off the SSSE3 target so
// clang-cl/MSVC x64 still get the 16-byte scan.
ada_really_inline const char* sse2_find_percent(const char* p,
                                                const char* end) noexcept {
  const __m128i pct = _mm_set1_epi8('%');
  while (p + 16 <= end) {
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
    const int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(w, pct));
    if (mask != 0) {
      return p + trailing_zeroes32(static_cast<uint32_t>(mask));
    }
    p += 16;
  }
  return p;
}

ada_really_inline const char* sse2_find_plus_or_percent(
    const char* p, const char* end) noexcept {
  const __m128i pct = _mm_set1_epi8('%');
  const __m128i plus = _mm_set1_epi8('+');
  while (p + 16 <= end) {
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
    const int mask = _mm_movemask_epi8(
        _mm_or_si128(_mm_cmpeq_epi8(w, pct), _mm_cmpeq_epi8(w, plus)));
    if (mask != 0) {
      return p + trailing_zeroes32(static_cast<uint32_t>(mask));
    }
    p += 16;
  }
  return p;
}
#endif  // ADA_UNICODE_SSSE3_ENCODE || ADA_SSE2

#if ADA_NEON
unsigned neon_decode_pct_groups(const uint8_t* p, uint8_t* d) noexcept {
  const uint8x16_t w = vld1q_u8(p);
  const uint64_t pct_bits = neon_nibble_bits(vceqq_u8(w, vdupq_n_u8('%')));
  if ((pct_bits & 0xF) == 0) {
    return 0;
  }
  alignas(16) const uint8_t extract_idx[16] = {1,  2,  4, 5, 7, 8, 10, 11,
                                               13, 14, 0, 0, 0, 0, 0,  0};
  const uint8x16_t hexes = vqtbl1q_u8(w, vld1q_u8(extract_idx));
  const uint8x16_t is_digit = vandq_u8(vcgeq_u8(hexes, vdupq_n_u8('0')),
                                       vcleq_u8(hexes, vdupq_n_u8('9')));
  const uint8x16_t lower = vorrq_u8(hexes, vdupq_n_u8(0x20));
  const uint8x16_t is_letter = vandq_u8(vcgeq_u8(lower, vdupq_n_u8('a')),
                                        vcleq_u8(lower, vdupq_n_u8('f')));
  const uint64_t hex_ok = neon_nibble_bits(vorrq_u8(is_digit, is_letter));

  unsigned n = 0;
  for (; n < 5; ++n) {
    if ((pct_bits & (uint64_t{0xF} << (12 * n))) == 0) {
      break;
    }
    const uint64_t pair = uint64_t{0xFF} << (8 * n);
    if ((hex_ok & pair) != pair) {
      break;
    }
  }
  if (n == 0) {
    return 0;
  }
  const uint8x16_t lo = vandq_u8(hexes, vdupq_n_u8(0x0F));
  const uint8x16_t hi6 = vshrq_n_u8(hexes, 6);
  const uint8x16_t nibbles = vaddq_u8(lo, vaddq_u8(hi6, vshlq_n_u8(hi6, 3)));
  alignas(16) uint8_t nb[16];
  vst1q_u8(nb, nibbles);
  for (unsigned i = 0; i < n; ++i) {
    d[i] = static_cast<uint8_t>((nb[2 * i] << 4) | nb[2 * i + 1]);
  }
  return n;
}

const char* neon_find_percent(const char* p, const char* end) noexcept {
  const uint8x16_t pct = vdupq_n_u8('%');
  while (p + 16 <= end) {
    const uint64_t bits = neon_nibble_bits(
        vceqq_u8(vld1q_u8(reinterpret_cast<const uint8_t*>(p)), pct));
    if (bits != 0) {
      return p + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2);
    }
    p += 16;
  }
  return p;
}

const char* neon_find_plus_or_percent(const char* p, const char* end) noexcept {
  const uint8x16_t pct = vdupq_n_u8('%');
  const uint8x16_t plus = vdupq_n_u8('+');
  while (p + 16 <= end) {
    const uint8x16_t w = vld1q_u8(reinterpret_cast<const uint8_t*>(p));
    const uint64_t bits =
        neon_nibble_bits(vorrq_u8(vceqq_u8(w, pct), vceqq_u8(w, plus)));
    if (bits != 0) {
      return p + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2);
    }
    p += 16;
  }
  return p;
}
#endif  // ADA_NEON

ada_really_inline const char* find_percent(const char* p,
                                           const char* end) noexcept {
#if ADA_UNICODE_SSSE3_ENCODE || ADA_SSE2
  p = sse2_find_percent(p, end);
#elif ADA_NEON
  p = neon_find_percent(p, end);
#endif
  while (p < end && *p != '%') {
    ++p;
  }
  return p;
}

ada_really_inline const char* find_plus_or_percent(const char* p,
                                                   const char* end) noexcept {
#if ADA_UNICODE_SSSE3_ENCODE || ADA_SSE2
  p = sse2_find_plus_or_percent(p, end);
#elif ADA_NEON
  p = neon_find_plus_or_percent(p, end);
#endif
  while (p < end && *p != '+' && *p != '%') {
    ++p;
  }
  return p;
}

ada_really_inline unsigned decode_pct_groups(const uint8_t* p,
                                             uint8_t* d) noexcept {
#if ADA_UNICODE_SSSE3_ENCODE
  return ssse3_decode_pct_groups(p, d);
#elif ADA_NEON
  return neon_decode_pct_groups(p, d);
#else
  (void)p;
  (void)d;
  return 0;
#endif
}

template <bool space_as_plus>
ada_really_inline void append_encoded_byte(unsigned char c, const uint8_t* set,
                                           std::string& out) {
  if (space_as_plus && c == ' ') {
    out.push_back('+');
  } else if (ada::character_sets::bit_at(set, c)) {
    out.append(ada::character_sets::hex + static_cast<size_t>(c) * 4, 3);
  } else {
    out.push_back(static_cast<char>(c));
  }
}

template <bool space_as_plus>
void flush_encode_mask(const char* p, uint32_t mask, const uint8_t* set,
                       std::string& out) {
  unsigned consumed = 0;
  while (mask != 0) {
    const unsigned next = static_cast<unsigned>(trailing_zeroes32(mask));
    if (next > consumed) {
      out.append(p + consumed, next - consumed);
    }
    append_encoded_byte<space_as_plus>(static_cast<unsigned char>(p[next]), set,
                                       out);
    consumed = next + 1;
    mask &= mask - 1;
  }
  if (consumed < 16) {
    out.append(p + consumed, 16 - consumed);
  }
}

#if ADA_NEON
template <bool space_as_plus>
void flush_encode_bits_neon(const char* p, uint64_t bits, const uint8_t* set,
                            std::string& out) {
  unsigned consumed = 0;
  while (bits != 0) {
    const unsigned next = static_cast<unsigned>(trailing_zeroes64(bits)) >> 2;
    if (next > consumed) {
      out.append(p + consumed, next - consumed);
    }
    append_encoded_byte<space_as_plus>(static_cast<unsigned char>(p[next]), set,
                                       out);
    consumed = next + 1;
    bits &= ~(uint64_t{0xF} << (next * 4));
  }
  if (consumed < 16) {
    out.append(p + consumed, 16 - consumed);
  }
}
#endif

#if ADA_UNICODE_SSSE3_ENCODE || ADA_NEON
// Out of line so short percent_encode (setters, CodSpeed examples) does not
// grow by the 16-byte classify loop. 48-byte floor: below that, scalar
// bit_at wins on instruction count (#1218 / #1230).
template <bool space_as_plus>
ADA_UNICODE_SIMD_NOINLINE void simd_encode_windows(const char* p,
                                                   const char* end,
                                                   const uint8_t* set,
                                                   const nibble_tables* tables,
                                                   std::string& out) {
#if ADA_UNICODE_SSSE3_ENCODE
  const __m128i lo_tbl =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(tables->low));
  const __m128i hi_tbl =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(tables->high));
  const __m128i space = _mm_set1_epi8(' ');
  while (p + 16 <= end) {
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
    int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);
    if constexpr (space_as_plus) {
      mask |= _mm_movemask_epi8(_mm_cmpeq_epi8(w, space));
    }
    if (mask == 0) {
      out.append(p, 16);
      p += 16;
      continue;
    }
    flush_encode_mask<space_as_plus>(p, static_cast<uint32_t>(mask), set, out);
    p += 16;
  }
#elif ADA_NEON
  const uint8x16_t lo_tbl = vld1q_u8(tables->low);
  const uint8x16_t hi_tbl = vld1q_u8(tables->high);
  const uint8x16_t space = vdupq_n_u8(' ');
  while (p + 16 <= end) {
    const uint8x16_t w = vld1q_u8(reinterpret_cast<const uint8_t*>(p));
    const uint8x16_t hit =
        vandq_u8(vqtbl1q_u8(lo_tbl, vandq_u8(w, vdupq_n_u8(0x0F))),
                 vqtbl1q_u8(hi_tbl, vshrq_n_u8(w, 4)));
    uint64_t bits = neon_nibble_bits(vtstq_u8(hit, hit));
    if constexpr (space_as_plus) {
      bits |= neon_nibble_bits(vceqq_u8(w, space));
    }
    if (bits == 0) {
      out.append(p, 16);
      p += 16;
      continue;
    }
    flush_encode_bits_neon<space_as_plus>(p, bits, set, out);
    p += 16;
  }
#endif
  while (p < end) {
    append_encoded_byte<space_as_plus>(static_cast<unsigned char>(*p), set,
                                       out);
    ++p;
  }
}
#endif  // ADA_UNICODE_SSSE3_ENCODE || ADA_NEON

template <bool space_as_plus>
ada_really_inline void encode_tail(const char* p, const char* end,
                                   const uint8_t* set, std::string& out) {
#if ADA_UNICODE_SSSE3_ENCODE || ADA_NEON
  if (end - p >= 48) {
    if (const nibble_tables* tables = nibble_tables_for(set);
        tables != nullptr) {
      simd_encode_windows<space_as_plus>(p, end, set, tables, out);
      return;
    }
  }
#endif
  while (p < end) {
    append_encoded_byte<space_as_plus>(static_cast<unsigned char>(*p), set,
                                       out);
    ++p;
  }
}

}  // namespace

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

// Consume a run of valid %XX (or a literal '%' if the escape is invalid).
// Dense percent-encoded query values decode five triplets per 16-byte load.
ada_really_inline void consume_pct_run(const char*& p, const char* end,
                                       char*& d) {
#if ADA_UNICODE_SSSE3_ENCODE || ADA_NEON
  while (p + 16 <= end && *p == '%') {
    const unsigned n = decode_pct_groups(reinterpret_cast<const uint8_t*>(p),
                                         reinterpret_cast<uint8_t*>(d));
    if (n == 0) {
      break;
    }
    d += n;
    p += static_cast<size_t>(n) * 3;
    if (n < 5) {
      break;
    }
  }
#endif
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
    *d++ = *p++;
  }
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
      consume_pct_run(p, end, d);
    } else {
      const char* run_end = find_percent(p, end);
      const size_t n = static_cast<size_t>(run_end - p);
      std::memcpy(d, p, n);
      d += n;
      p = run_end;
    }
  }

  out.resize(static_cast<size_t>(d - d0));
  return out;
}

std::string form_urlencoded_decode(const std::string_view input) {
  const size_t len = input.size();
  if (len == 0) [[unlikely]] {
    return {};
  }

  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* const src = input.data();
  const char* const end = src + len;
  const char* p = find_plus_or_percent(src, end);
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
      consume_pct_run(p, end, d);
    } else {
      const char* run_end = find_plus_or_percent(p, end);
      const size_t n = static_cast<size_t>(run_end - p);
      std::memcpy(d, p, n);
      d += n;
      p = run_end;
    }
  }

  out.resize(static_cast<size_t>(d - d0));
  return out;
}

void form_urlencoded_encode_append(const std::string_view input,
                                   std::string& out) {
  const uint8_t* set = character_sets::WWW_FORM_URLENCODED_PERCENT_ENCODE;
  const size_t n = input.size();
  size_t idx = percent_encode_index(input, set);
  const size_t space = input.find(' ');
  if (space < idx) {
    idx = space;
  }
  if (idx == n) {
    out.append(input);
    return;
  }
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  out.append(input.data(), idx);
  const size_t remaining = n - idx;
  out.reserve(out.size() + remaining * 3);
  encode_tail<true>(input.data() + idx, input.data() + n, set, out);
}

std::string form_urlencoded_encode(const std::string_view input) {
  std::string out;
  form_urlencoded_encode_append(input, out);
  return out;
}

std::string percent_encode(const std::string_view input,
                           const uint8_t character_set[]) {
  const size_t idx = percent_encode_index(input, character_set);
  if (idx == input.size()) {
    return std::string(input);
  }
  return percent_encode(input, character_set, idx);
}

template <bool append>
bool percent_encode(const std::string_view input, const uint8_t character_set[],
                    std::string& out) {
  ada_log("percent_encode ", input, " to output string while ",
          append ? "appending" : "overwriting");
  const size_t idx = percent_encode_index(input, character_set);
  ada_log("percent_encode done checking, moved to ", idx);

  // Optimization: Don't iterate if percent encode is not required
  if (idx == input.size()) {
    ada_log("percent_encode encoding not needed.");
    return false;
  }
  if constexpr (!append) {
    out.clear();
  }
  ada_log("percent_encode appending ", idx, " bytes");
  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  out.append(input.data(), idx);
  ada_log("percent_encode processing ", input.size() - idx, " bytes");
  const size_t remaining = input.size() - idx;
  out.reserve(out.size() + remaining * 3);
  encode_tail<false>(input.data() + idx, input.data() + input.size(),
                     character_set, out);
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
  const size_t remaining = input.size() - index;
  out.reserve(out.size() + remaining * 3);
  encode_tail<false>(input.data() + index, input.data() + input.size(),
                     character_set, out);
  return out;
}

}  // namespace ada::unicode

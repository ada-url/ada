#include "ada/parser-inl.h"

#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <limits>
#include <ranges>

#include "ada/character_sets-inl.h"
#include "ada/checkers-inl.h"
#include "ada/common_defs.h"
#include "ada/implementation.h"
#include "ada/log.h"
#include "ada/scheme-inl.h"
#include "ada/unicode-inl.h"
#include "ada/unicode.h"
#include "ada/url.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"

#if ADA_NEON
#include <arm_neon.h>
#elif defined(__SSSE3__)
#include <tmmintrin.h>
#define ADA_PARSER_SSSE3 1
#elif (defined(__x86_64__) || defined(__amd64__)) && defined(__GNUC__) && \
    !defined(_MSC_VER)
// gcc/clang honor target("ssse3"). clang-cl and MSVC do not: they still
// compile the function as SSE2, then reject always_inline _mm_shuffle_epi8.
#include <tmmintrin.h>
#define ADA_PARSER_SSSE3 1
#define ADA_PARSER_NEED_SSSE3_TARGET 1
#elif ADA_SSE2
#include <emmintrin.h>
#endif
#ifndef ADA_PARSER_SSSE3
#define ADA_PARSER_SSSE3 0
#endif

#ifdef ADA_PARSER_NEED_SSSE3_TARGET
#define ADA_PARSER_SIMD __attribute__((target("ssse3")))
#else
#define ADA_PARSER_SIMD ada_really_inline
#endif

#ifdef ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif

namespace ada::parser {

// Classification tables and 16-byte run scanners for the absolute-URL fast
// path. Inspired by oven-sh/WebKit#452 and #454: scan 16 bytes at a time
// (nibble-table pshufb/tbl when SSSE3 or NEON is available), and when the
// path/query/fragment is not already canonical, keep the parsed host and
// finish with the existing path helpers instead of re-parsing from scratch.
namespace {

// 0 = host byte, 1 = host delimiter (/ ? # :), 2 = reject
constexpr std::array<uint8_t, 256> k_host_class = []() consteval {
  std::array<uint8_t, 256> t{};
  for (size_t i = 0; i < 256; ++i) {
    t[i] = 2;
  }
  for (size_t i = 0x21; i <= 0x7E; ++i) {
    t[i] = 0;
  }
  for (uint8_t c :
       {'#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|', '%'}) {
    t[c] = 2;
  }
  t[static_cast<uint8_t>('/')] = 1;
  t[static_cast<uint8_t>('?')] = 1;
  t[static_cast<uint8_t>('#')] = 1;
  t[static_cast<uint8_t>(':')] = 1;
  return t;
}();

// Path: 0 = copy, 1 = ?/#, 2 = needs work. Apostrophe is copyable in a path.
constexpr std::array<uint8_t, 256> k_path = []() consteval {
  std::array<uint8_t, 256> t{};
  for (size_t i = 0; i < 256; ++i) {
    t[i] = 2;
  }
  for (uint8_t c = 0x21; c <= 0x7E; ++c) {
    t[c] = 0;
  }
  for (uint8_t c : {static_cast<uint8_t>('"'), static_cast<uint8_t>('<'),
                    static_cast<uint8_t>('>'), static_cast<uint8_t>('`'),
                    static_cast<uint8_t>('{'), static_cast<uint8_t>('}'),
                    static_cast<uint8_t>('^'), static_cast<uint8_t>('\\'),
                    static_cast<uint8_t>('%')}) {
    t[c] = 2;
  }
  t[static_cast<uint8_t>('?')] = 1;
  t[static_cast<uint8_t>('#')] = 1;
  return t;
}();

// Special-query: 0 = copy, 1 = #, 2 = needs work. Apostrophe must be encoded.
constexpr std::array<uint8_t, 256> k_query = []() consteval {
  std::array<uint8_t, 256> t{};
  for (size_t i = 0; i < 256; ++i) {
    t[i] = 2;
  }
  for (uint8_t c = 0x21; c <= 0x7E; ++c) {
    t[c] = 0;
  }
  for (uint8_t c : {static_cast<uint8_t>('"'), static_cast<uint8_t>('<'),
                    static_cast<uint8_t>('>'), static_cast<uint8_t>('\'')}) {
    t[c] = 2;
  }
  t[static_cast<uint8_t>('#')] = 1;
  return t;
}();

// Fragment: 0 = copy, 2 = needs work. '?' '#' '%' are copyable.
constexpr std::array<uint8_t, 256> k_hash = []() consteval {
  std::array<uint8_t, 256> t{};
  for (size_t i = 0; i < 256; ++i) {
    t[i] = 2;
  }
  for (uint8_t c = 0x21; c <= 0x7E; ++c) {
    t[c] = 0;
  }
  for (uint8_t c : {static_cast<uint8_t>('"'), static_cast<uint8_t>('<'),
                    static_cast<uint8_t>('>'), static_cast<uint8_t>('`')}) {
    t[c] = 2;
  }
  return t;
}();

// Nibble tables for pshufb / tbl classification (oven-sh/WebKit#454).
// A byte is a stop when low[b & 0xF] & high[b >> 4] != 0. High nibbles whose
// sixteen bytes share a stop pattern share a bit, so any set with at most
// eight distinct patterns fits. Tables are built from the scalar class
// arrays, so the vector and scalar paths cannot disagree.
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

constexpr nibble_tables k_host_nibbles = make_stop_nibble_tables(k_host_class);
constexpr nibble_tables k_path_nibbles = make_stop_nibble_tables(k_path);
constexpr nibble_tables k_query_nibbles = make_stop_nibble_tables(k_query);
constexpr nibble_tables k_hash_nibbles = make_stop_nibble_tables(k_hash);
static_assert(k_host_nibbles.fits);
static_assert(k_path_nibbles.fits);
static_assert(k_query_nibbles.fits);
static_assert(k_hash_nibbles.fits);

// WHATWG serializes a port as its decimal value with no leading zeros.
ada_really_inline uint32_t port_decimal_digit_count(uint32_t port) noexcept {
  uint32_t digits = 1;
  while (port >= 10) {
    port /= 10;
    ++digits;
  }
  return digits;
}

ada_really_inline void append_canonical_port(std::string& buffer,
                                             uint32_t port) {
  buffer += ':';
  char port_buf[5];
  auto [ptr, ec] = std::to_chars(port_buf, port_buf + 5, port);
  (void)ec;
  buffer.append(port_buf, static_cast<size_t>(ptr - port_buf));
}

ada_really_inline int trailing_zeroes32(uint32_t input_num) noexcept {
#ifdef ADA_REGULAR_VISUAL_STUDIO
  unsigned long ret;
  _BitScanForward(&ret, input_num);
  return static_cast<int>(ret);
#else
  return __builtin_ctz(input_num);
#endif
}

ada_really_inline int trailing_zeroes64(uint64_t input_num) noexcept {
#ifdef ADA_REGULAR_VISUAL_STUDIO
  unsigned long ret;
  _BitScanForward64(&ret, input_num);
  return static_cast<int>(ret);
#else
  return __builtin_ctzll(input_num);
#endif
}

#if ADA_PARSER_SSSE3
ADA_PARSER_SIMD __m128i nibble_load(const uint8_t* t) noexcept {
  return _mm_load_si128(reinterpret_cast<const __m128i*>(t));
}

// Non-zero lanes are stops. Tables are passed in so the scan loops can hoist
// the loads out of the 16-byte iteration.
ADA_PARSER_SIMD int ssse3_nibble_mask(__m128i w, __m128i lo_tbl,
                                      __m128i hi_tbl) noexcept {
  const __m128i nibble = _mm_set1_epi8(0x0F);
  const __m128i lo = _mm_and_si128(w, nibble);
  const __m128i hi = _mm_and_si128(_mm_srli_epi16(w, 4), nibble);
  const __m128i hit =
      _mm_and_si128(_mm_shuffle_epi8(lo_tbl, lo), _mm_shuffle_epi8(hi_tbl, hi));
  return _mm_movemask_epi8(_mm_cmpeq_epi8(hit, _mm_setzero_si128())) ^ 0xFFFF;
}
#endif  // ADA_PARSER_SSSE3

#if ADA_SSE2
#if !ADA_PARSER_SSSE3
// Signed < 0x21 matches 0x00-0x20 and 0x80-0xFF; 0x7F is checked separately.
ada_really_inline __m128i sse2_ctrl_or_nonascii(__m128i w) noexcept {
  return _mm_or_si128(_mm_cmplt_epi8(w, _mm_set1_epi8(0x21)),
                      _mm_cmpeq_epi8(w, _mm_set1_epi8(0x7F)));
}

ada_really_inline int sse2_host_stop(__m128i w) noexcept {
  const __m128i ctrl = sse2_ctrl_or_nonascii(w);
  const __m128i is_upper = _mm_and_si128(
      _mm_cmpgt_epi8(w, _mm_set1_epi8(static_cast<char>('A' - 1))),
      _mm_cmplt_epi8(w, _mm_set1_epi8(static_cast<char>('Z' + 1))));
  const __m128i at = _mm_sub_epi8(w, _mm_set1_epi8('@'));
  const __m128i at_through_caret =
      _mm_cmpeq_epi8(_mm_min_epu8(at, _mm_set1_epi8('^' - '@')), at);
  const __m128i at_not_upper = _mm_andnot_si128(is_upper, at_through_caret);
  const __m128i spec = _mm_or_si128(
      _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('#')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('%'))),
                   _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('/')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8(':')))),
      _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('<')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('>'))),
                   _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('?')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('|')))));
  return _mm_movemask_epi8(
      _mm_or_si128(_mm_or_si128(ctrl, at_not_upper), spec));
}

ada_really_inline int sse2_path_stop(__m128i w) noexcept {
  const __m128i ctrl = sse2_ctrl_or_nonascii(w);
  const __m128i spec = _mm_or_si128(
      _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('"')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('#'))),
                   _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('%')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('<')))),
      _mm_or_si128(
          _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('>')),
                                    _mm_cmpeq_epi8(w, _mm_set1_epi8('?'))),
                       _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('\\')),
                                    _mm_cmpeq_epi8(w, _mm_set1_epi8('^')))),
          _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('`')),
                                    _mm_cmpeq_epi8(w, _mm_set1_epi8('{'))),
                       _mm_cmpeq_epi8(w, _mm_set1_epi8('}')))));
  return _mm_movemask_epi8(_mm_or_si128(ctrl, spec));
}

ada_really_inline int sse2_query_stop(__m128i w) noexcept {
  const __m128i ctrl = sse2_ctrl_or_nonascii(w);
  const __m128i spec = _mm_or_si128(
      _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('"')),
                   _mm_cmpeq_epi8(w, _mm_set1_epi8('#'))),
      _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('<')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('>'))),
                   _mm_cmpeq_epi8(w, _mm_set1_epi8('\''))));
  return _mm_movemask_epi8(_mm_or_si128(ctrl, spec));
}

ada_really_inline int sse2_hash_stop(__m128i w) noexcept {
  const __m128i ctrl = sse2_ctrl_or_nonascii(w);
  const __m128i spec =
      _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('"')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('<'))),
                   _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('>')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('`'))));
  return _mm_movemask_epi8(_mm_or_si128(ctrl, spec));
}
#endif  // !ADA_PARSER_SSSE3

ada_really_inline int sse2_uppercase(__m128i w) noexcept {
  return _mm_movemask_epi8(_mm_and_si128(
      _mm_cmpgt_epi8(w, _mm_set1_epi8(static_cast<char>('A' - 1))),
      _mm_cmplt_epi8(w, _mm_set1_epi8(static_cast<char>('Z' + 1)))));
}
#endif  // ADA_SSE2

#if ADA_NEON
ada_really_inline uint64_t neon_nibble_bits(uint8x16_t matches) noexcept {
  const uint8x8_t nib = vshrn_n_u16(vreinterpretq_u16_u8(matches), 4);
  return vget_lane_u64(vreinterpret_u64_u8(nib), 0);
}

ada_really_inline uint64_t neon_table_stop(uint8x16_t w, uint8x16_t lo_tbl,
                                           uint8x16_t hi_tbl) noexcept {
  const uint8x16_t hit =
      vandq_u8(vqtbl1q_u8(lo_tbl, vandq_u8(w, vdupq_n_u8(0x0F))),
               vqtbl1q_u8(hi_tbl, vshrq_n_u8(w, 4)));
  return neon_nibble_bits(vtstq_u8(hit, hit));
}

ada_really_inline uint64_t neon_uppercase(uint8x16_t w) noexcept {
  return neon_nibble_bits(
      vandq_u8(vcgeq_u8(w, vdupq_n_u8('A')), vcleq_u8(w, vdupq_n_u8('Z'))));
}
#endif  // ADA_NEON

// Returns false if a forbidden host code point is found. On success, *end is
// the first / ? # or len, and has_upper reports any ASCII uppercase.
ADA_PARSER_SIMD bool scan_plain_host(const uint8_t* b, size_t start, size_t len,
                                     size_t& end, bool& has_upper) noexcept {
  has_upper = false;
  size_t i = start;
#if ADA_PARSER_SSSE3
  if (len - start >= 16) {
    const __m128i lo_tbl = nibble_load(k_host_nibbles.low);
    const __m128i hi_tbl = nibble_load(k_host_nibbles.high);
    auto visit = [&](size_t at) noexcept -> bool {
      const __m128i w =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at));
      if (sse2_uppercase(w) != 0) {
        has_upper = true;
      }
      const int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);
      if (mask == 0) {
        return false;
      }
      end = at +
            static_cast<size_t>(trailing_zeroes32(static_cast<uint32_t>(mask)));
      return true;
    };
    for (; i + 16 <= len; i += 16) {
      if (visit(i)) {
        return k_host_class[b[end]] == 1;
      }
    }
    // Overlapping tail only after a full 16-byte step so the window cannot
    // start before `start` (a prior '/' would otherwise look like a host stop).
    if (i > start && i < len) {
      if (visit(len - 16) && end >= i) {
        return k_host_class[b[end]] == 1;
      }
      end = len;
      return true;
    }
  }
#elif ADA_SSE2
  for (; i + 16 <= len; i += 16) {
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
    if (sse2_uppercase(w) != 0) {
      has_upper = true;
    }
    const int mask = sse2_host_stop(w);
    if (mask != 0) {
      end = i +
            static_cast<size_t>(trailing_zeroes32(static_cast<uint32_t>(mask)));
      return k_host_class[b[end]] == 1;
    }
  }
#elif ADA_NEON
  if (len - start >= 16) {
    const uint8x16_t lo_tbl = vld1q_u8(k_host_nibbles.low);
    const uint8x16_t hi_tbl = vld1q_u8(k_host_nibbles.high);
    auto visit = [&](size_t at) noexcept -> bool {
      const uint8x16_t w = vld1q_u8(b + at);
      if (neon_uppercase(w) != 0) {
        has_upper = true;
      }
      const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);
      if (bits == 0) {
        return false;
      }
      end = at + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2);
      return true;
    };
    for (; i + 16 <= len; i += 16) {
      if (visit(i)) {
        return k_host_class[b[end]] == 1;
      }
    }
    if (i > start && i < len) {
      if (visit(len - 16) && end >= i) {
        return k_host_class[b[end]] == 1;
      }
      end = len;
      return true;
    }
  }
#endif
  for (; i < len; ++i) {
    const uint8_t c = b[i];
    const uint8_t cls = k_host_class[c];
    if (cls == 1) {
      end = i;
      return true;
    }
    if (cls == 2) {
      return false;
    }
    if (c >= 'A' && c <= 'Z') {
      has_upper = true;
    }
  }
  end = len;
  return true;
}

ada_really_inline void note_possible_dot_segment(
    const uint8_t* b, size_t pos, size_t run_start,
    bool& maybe_dot_segment) noexcept {
  if (pos == run_start || b[pos - 1] == '/') {
    maybe_dot_segment = true;
  }
}

#if ADA_PARSER_SSSE3 || ADA_SSE2
// valid_mask selects bytes in this 16-byte window that belong to the path
// (bits after a stop are cleared). A '.' starts a possible dot-segment when
// it is the first path byte or immediately follows '/'.
ada_really_inline void note_dots_in_window(const uint8_t* b, size_t i,
                                           size_t run_start, __m128i w,
                                           int valid_mask,
                                           bool& maybe_dot_segment) noexcept {
  if (maybe_dot_segment || valid_mask == 0) {
    return;
  }
  const int dots =
      _mm_movemask_epi8(_mm_cmpeq_epi8(w, _mm_set1_epi8('.'))) & valid_mask;
  if (dots == 0) {
    return;
  }
  const int slashes =
      _mm_movemask_epi8(_mm_cmpeq_epi8(w, _mm_set1_epi8('/'))) & valid_mask;
  if (((dots & 1) != 0 && (i == run_start || b[i - 1] == '/')) ||
      (dots & (slashes << 1)) != 0) {
    maybe_dot_segment = true;
  }
}
#endif

// Advance i to the first path-class 1 or 2 character (or len).
ADA_PARSER_SIMD void scan_path_run(const uint8_t* b, size_t& i, size_t len,
                                   bool& maybe_dot_segment) noexcept {
  const size_t run_start = i;
#if ADA_PARSER_SSSE3
  if (i + 16 <= len) {
    const __m128i lo_tbl = nibble_load(k_path_nibbles.low);
    const __m128i hi_tbl = nibble_load(k_path_nibbles.high);
    for (; i + 32 <= len; i += 32) {
      const __m128i w0 =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
      const int m0 = ssse3_nibble_mask(w0, lo_tbl, hi_tbl);
      if (m0 != 0) {
        const int hit_bit = trailing_zeroes32(static_cast<uint32_t>(m0));
        note_dots_in_window(b, i, run_start, w0, (1 << hit_bit) - 1,
                            maybe_dot_segment);
        i += static_cast<size_t>(hit_bit);
        return;
      }
      note_dots_in_window(b, i, run_start, w0, 0xFFFF, maybe_dot_segment);
      const __m128i w1 =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i + 16));
      const int m1 = ssse3_nibble_mask(w1, lo_tbl, hi_tbl);
      if (m1 != 0) {
        const int hit_bit = trailing_zeroes32(static_cast<uint32_t>(m1));
        note_dots_in_window(b, i + 16, run_start, w1, (1 << hit_bit) - 1,
                            maybe_dot_segment);
        i += 16 + static_cast<size_t>(hit_bit);
        return;
      }
      note_dots_in_window(b, i + 16, run_start, w1, 0xFFFF, maybe_dot_segment);
    }
    for (; i + 16 <= len; i += 16) {
      const __m128i w =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
      const int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);
      if (mask != 0) {
        const int hit_bit = trailing_zeroes32(static_cast<uint32_t>(mask));
        note_dots_in_window(b, i, run_start, w, (1 << hit_bit) - 1,
                            maybe_dot_segment);
        i += static_cast<size_t>(hit_bit);
        return;
      }
      note_dots_in_window(b, i, run_start, w, 0xFFFF, maybe_dot_segment);
    }
    if (i > run_start && i < len) {
      const __m128i w =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + len - 16));
      const int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);
      if (mask != 0) {
        const size_t hit =
            len - 16 +
            static_cast<size_t>(trailing_zeroes32(static_cast<uint32_t>(mask)));
        if (hit >= i) {
          for (size_t j = i; j < hit; ++j) {
            if (b[j] == '.') {
              note_possible_dot_segment(b, j, run_start, maybe_dot_segment);
            }
          }
          i = hit;
          return;
        }
      }
      for (size_t j = i; j < len; ++j) {
        if (b[j] == '.') {
          note_possible_dot_segment(b, j, run_start, maybe_dot_segment);
        }
      }
      i = len;
      return;
    }
  }
#elif ADA_SSE2
  for (; i + 16 <= len; i += 16) {
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
    const int mask = sse2_path_stop(w);
    if (mask != 0) {
      const int hit_bit = trailing_zeroes32(static_cast<uint32_t>(mask));
      note_dots_in_window(b, i, run_start, w, (1 << hit_bit) - 1,
                          maybe_dot_segment);
      i += static_cast<size_t>(hit_bit);
      return;
    }
    note_dots_in_window(b, i, run_start, w, 0xFFFF, maybe_dot_segment);
  }
#elif ADA_NEON
  if (i + 16 <= len) {
    const uint8x16_t lo_tbl = vld1q_u8(k_path_nibbles.low);
    const uint8x16_t hi_tbl = vld1q_u8(k_path_nibbles.high);
    for (; i + 16 <= len; i += 16) {
      const uint8x16_t w = vld1q_u8(b + i);
      const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);
      if (bits != 0) {
        const size_t hit =
            i + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2);
        for (size_t j = i; j < hit; ++j) {
          if (b[j] == '.') {
            note_possible_dot_segment(b, j, run_start, maybe_dot_segment);
          }
        }
        i = hit;
        return;
      }
      if (neon_nibble_bits(vceqq_u8(w, vdupq_n_u8('.'))) != 0) {
        for (size_t j = i; j < i + 16; ++j) {
          if (b[j] == '.') {
            note_possible_dot_segment(b, j, run_start, maybe_dot_segment);
            if (maybe_dot_segment) {
              break;
            }
          }
        }
      }
    }
    if (i > run_start && i < len) {
      const uint8x16_t w = vld1q_u8(b + len - 16);
      const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);
      if (bits != 0) {
        const size_t hit =
            len - 16 + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2);
        if (hit >= i) {
          for (size_t j = i; j < hit; ++j) {
            if (b[j] == '.') {
              note_possible_dot_segment(b, j, run_start, maybe_dot_segment);
            }
          }
          i = hit;
          return;
        }
      }
      for (size_t j = i; j < len; ++j) {
        if (b[j] == '.') {
          note_possible_dot_segment(b, j, run_start, maybe_dot_segment);
        }
      }
      i = len;
      return;
    }
  }
#endif
  for (; i < len; ++i) {
    const uint8_t c = b[i];
    const uint8_t cls = k_path[c];
    if (cls != 0) {
      return;
    }
    if (c == '.') {
      note_possible_dot_segment(b, i, run_start, maybe_dot_segment);
    }
  }
}

// Advance i to the first class-table stop (or len). Query and hash share
// this loop; path keeps its own copy because it also tracks '.' segments.
#if ADA_PARSER_SSSE3
#define ADA_SCAN_STOP_RUN(nibbles, cls, unused_sse2_stop)                    \
  do {                                                                       \
    const size_t scan_start = i;                                             \
    if (i + 16 <= len) {                                                     \
      const __m128i lo_tbl = nibble_load((nibbles).low);                     \
      const __m128i hi_tbl = nibble_load((nibbles).high);                    \
      for (; i + 32 <= len; i += 32) {                                       \
        const __m128i w0 =                                                   \
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));        \
        const int m0 = ssse3_nibble_mask(w0, lo_tbl, hi_tbl);                \
        if (m0 != 0) {                                                       \
          i += static_cast<size_t>(                                          \
              trailing_zeroes32(static_cast<uint32_t>(m0)));                 \
          return;                                                            \
        }                                                                    \
        const __m128i w1 =                                                   \
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i + 16));   \
        const int m1 = ssse3_nibble_mask(w1, lo_tbl, hi_tbl);                \
        if (m1 != 0) {                                                       \
          i += 16 + static_cast<size_t>(                                     \
                        trailing_zeroes32(static_cast<uint32_t>(m1)));       \
          return;                                                            \
        }                                                                    \
      }                                                                      \
      for (; i + 16 <= len; i += 16) {                                       \
        const __m128i w =                                                    \
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));        \
        const int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);               \
        if (mask != 0) {                                                     \
          i += static_cast<size_t>(                                          \
              trailing_zeroes32(static_cast<uint32_t>(mask)));               \
          return;                                                            \
        }                                                                    \
      }                                                                      \
      if (i > scan_start && i < len) {                                       \
        const __m128i w =                                                    \
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + len - 16)); \
        const int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);               \
        if (mask != 0) {                                                     \
          const size_t hit = len - 16 +                                      \
                             static_cast<size_t>(trailing_zeroes32(          \
                                 static_cast<uint32_t>(mask)));              \
          if (hit >= i) {                                                    \
            i = hit;                                                         \
            return;                                                          \
          }                                                                  \
        }                                                                    \
        i = len;                                                             \
        return;                                                              \
      }                                                                      \
    }                                                                        \
    for (; i < len; ++i) {                                                   \
      if ((cls)[b[i]] != 0) {                                                \
        return;                                                              \
      }                                                                      \
    }                                                                        \
  } while (0)
#elif ADA_NEON
#define ADA_SCAN_STOP_RUN(nibbles, cls, unused_sse2_stop)                     \
  do {                                                                        \
    const size_t scan_start = i;                                              \
    if (i + 16 <= len) {                                                      \
      const uint8x16_t lo_tbl = vld1q_u8((nibbles).low);                      \
      const uint8x16_t hi_tbl = vld1q_u8((nibbles).high);                     \
      for (; i + 32 <= len; i += 32) {                                        \
        const uint64_t bits0 =                                                \
            neon_table_stop(vld1q_u8(b + i), lo_tbl, hi_tbl);                 \
        if (bits0 != 0) {                                                     \
          i += static_cast<size_t>(trailing_zeroes64(bits0)) >> 2;            \
          return;                                                             \
        }                                                                     \
        const uint64_t bits1 =                                                \
            neon_table_stop(vld1q_u8(b + i + 16), lo_tbl, hi_tbl);            \
        if (bits1 != 0) {                                                     \
          i += 16 + (static_cast<size_t>(trailing_zeroes64(bits1)) >> 2);     \
          return;                                                             \
        }                                                                     \
      }                                                                       \
      for (; i + 16 <= len; i += 16) {                                        \
        const uint8x16_t w = vld1q_u8(b + i);                                 \
        const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);             \
        if (bits != 0) {                                                      \
          i += static_cast<size_t>(trailing_zeroes64(bits)) >> 2;             \
          return;                                                             \
        }                                                                     \
      }                                                                       \
      if (i > scan_start && i < len) {                                        \
        const uint8x16_t w = vld1q_u8(b + len - 16);                          \
        const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);             \
        if (bits != 0) {                                                      \
          const size_t hit =                                                  \
              len - 16 + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2); \
          if (hit >= i) {                                                     \
            i = hit;                                                          \
            return;                                                           \
          }                                                                   \
        }                                                                     \
        i = len;                                                              \
        return;                                                               \
      }                                                                       \
    }                                                                         \
    for (; i < len; ++i) {                                                    \
      if ((cls)[b[i]] != 0) {                                                 \
        return;                                                               \
      }                                                                       \
    }                                                                         \
  } while (0)
#elif ADA_SSE2
#define ADA_SCAN_STOP_RUN(nibbles, cls, sse2_stop)                  \
  do {                                                              \
    for (; i + 16 <= len; i += 16) {                                \
      const __m128i w =                                             \
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i)); \
      const int mask = sse2_stop(w);                                \
      if (mask != 0) {                                              \
        i += static_cast<size_t>(                                   \
            trailing_zeroes32(static_cast<uint32_t>(mask)));        \
        return;                                                     \
      }                                                             \
    }                                                               \
    for (; i < len; ++i) {                                          \
      if ((cls)[b[i]] != 0) {                                       \
        return;                                                     \
      }                                                             \
    }                                                               \
  } while (0)
#else
#define ADA_SCAN_STOP_RUN(nibbles, cls, unused_sse2_stop) \
  do {                                                    \
    for (; i < len; ++i) {                                \
      if ((cls)[b[i]] != 0) {                             \
        return;                                           \
      }                                                   \
    }                                                     \
  } while (0)
#endif

ADA_PARSER_SIMD void scan_query_run(const uint8_t* b, size_t& i,
                                    size_t len) noexcept {
  ADA_SCAN_STOP_RUN(k_query_nibbles, k_query, sse2_query_stop);
}

ADA_PARSER_SIMD void scan_hash_run(const uint8_t* b, size_t& i,
                                   size_t len) noexcept {
  ADA_SCAN_STOP_RUN(k_hash_nibbles, k_hash, sse2_hash_stop);
}

#undef ADA_SCAN_STOP_RUN

ada_really_inline bool last_label_may_be_a_number(
    std::string_view view) noexcept {
  if (view.empty()) {
    return false;
  }
  if (view.back() == '.') {
    view.remove_suffix(1);
    if (view.empty()) {
      return false;
    }
  }
  auto is_ipv4_number_char = [](char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F') || c == 'x' || c == 'X';
  };
  size_t i = view.size();
  while (i > 0 && is_ipv4_number_char(view[i - 1])) {
    --i;
  }
  if (i > 0 && view[i - 1] != '.') {
    return false;
  }
  return i != view.size() && (view[i] >= '0' && view[i] <= '9');
}

bool path_has_dot_segment(std::string_view path) noexcept {
  if (path.empty()) {
    return false;
  }
  // "." / ".." at the start, with or without a leading '/'.
  const size_t i = (path[0] == '/') ? 1 : 0;
  if (i < path.size() && path[i] == '.') {
    const size_t after = i + 1;
    if (after == path.size() || path[after] == '/' ||
        (after < path.size() && path[after] == '.' &&
         (after + 1 == path.size() || path[after + 1] == '/'))) {
      return true;
    }
  }
  static constexpr std::string_view slash_dot{"/.", 2};
  size_t p = i;
  while ((p = path.find(slash_dot, p)) != std::string_view::npos) {
    const size_t after = p + 2;
    if (after == path.size() || path[after] == '/' ||
        (after < path.size() && path[after] == '.' &&
         (after + 1 == path.size() || path[after + 1] == '/'))) {
      return true;
    }
    p = after;
  }
  return false;
}

}  // namespace

template <class result_type>
ada_never_inline bool finish_simple_absolute_with_port(
    std::string_view input, result_type& out, ada::scheme::type scheme_type,
    uint32_t protocol_end, size_t host_start, size_t host_end, size_t host_len,
    bool has_upper) {
  constexpr bool is_ada_url = std::is_same_v<result_type, ada::url>;
  constexpr bool is_aggregator =
      std::is_same_v<result_type, ada::url_aggregator>;
  static_assert(is_ada_url || is_aggregator);

  const size_t len = input.size();
  const auto* b = reinterpret_cast<const uint8_t*>(input.data());
  size_t p = host_end + 1;
  uint32_t port_value = 0;
  bool any_digit = false;
  while (p < len && b[p] >= '0' && b[p] <= '9') {
    any_digit = true;
    port_value = port_value * 10 + static_cast<uint32_t>(b[p] - '0');
    if (port_value > 65535) [[unlikely]] {
      return false;
    }
    ++p;
  }
  if (p < len && b[p] != '/' && b[p] != '?' && b[p] != '#') [[unlikely]] {
    return false;
  }
  uint32_t parsed_port = url_components::omitted;
  const uint16_t default_port = ada::scheme::get_special_port(scheme_type);
  if (any_digit && port_value != default_port) {
    parsed_port = port_value;
  }
  const size_t authority_end = p;

  size_t i = authority_end;
  size_t path_start = host_end;
  size_t path_end = host_end;
  size_t query_start = std::string_view::npos;
  size_t hash_start = std::string_view::npos;
  bool has_path = false;
  bool maybe_dot_segment = false;
  bool rest_simple = true;

  if (i < len && b[i] == '/') {
    has_path = true;
    path_start = i;
    ++i;
    scan_path_run(b, i, len, maybe_dot_segment);
    if (i < len) {
      const uint8_t cls = k_path[b[i]];
      if (cls == 1) {
        path_end = i;
        if (b[i] == '?') {
          query_start = i;
          ++i;
          goto scan_query;
        }
        hash_start = i;
        ++i;
        goto scan_hash;
      }
      rest_simple = false;
      for (; i < len; ++i) {
        if (b[i] == '?') {
          path_end = i;
          query_start = i;
          ++i;
          goto scan_query_boundary;
        }
        if (b[i] == '#') {
          path_end = i;
          hash_start = i;
          ++i;
          goto after_rest;
        }
      }
      path_end = i;
      goto after_rest;
    }
    path_end = i;
  } else if (i < len && b[i] == '?') {
    query_start = i;
    ++i;
    goto scan_query;
  } else if (i < len && b[i] == '#') {
    hash_start = i;
    ++i;
    goto scan_hash;
  }
  goto after_rest;

scan_query:
  scan_query_run(b, i, len);
  if (i < len) {
    if (b[i] == '#') {
      hash_start = i;
      ++i;
      goto scan_hash;
    }
    rest_simple = false;
    goto scan_query_boundary;
  }
  goto after_rest;

scan_query_boundary:
  for (; i < len; ++i) {
    if (b[i] == '#') {
      hash_start = i;
      ++i;
      goto after_rest;
    }
  }
  goto after_rest;

scan_hash:
  scan_hash_run(b, i, len);
  if (i < len) {
    rest_simple = false;
  }

after_rest:
  if (rest_simple && maybe_dot_segment) {
    const std::string_view path_body(input.data() + path_start,
                                     path_end - path_start);
    if (path_has_dot_segment(path_body)) {
      rest_simple = false;
    }
  }

  // The slow path removes ASCII tab/newline anywhere in the input and trims a
  // trailing C0 control or space; this fast path does neither. A query or
  // fragment reaching the helpers below would keep those bytes percent-encoded
  // ("?a\nb" -> "?a%0Ab", "#f " -> "#f%20") instead of stripped, so hand such
  // inputs back to the slow path.
  if (!rest_simple && (unicode::is_c0_control_or_space(input.back()) ||
                       unicode::has_tabs_or_newline(input))) {
    return false;
  }

  out.type = scheme_type;
  out.is_valid = true;
  out.has_opaque_path = false;
  out.host_type = DEFAULT;

  const uint32_t port_bytes = (parsed_port != url_components::omitted)
                                  ? (1 + port_decimal_digit_count(parsed_port))
                                  : 0;

  if (!rest_simple) {
    const std::string_view path_view =
        has_path
            ? std::string_view(input.data() + path_start, path_end - path_start)
            : std::string_view{};
    auto apply_query_and_hash = [&]() {
      if (query_start != std::string_view::npos) {
        const size_t q_end =
            (hash_start != std::string_view::npos) ? hash_start : len;
        out.update_base_search(std::string_view(input.data() + query_start + 1,
                                                q_end - query_start - 1),
                               character_sets::SPECIAL_QUERY_PERCENT_ENCODE);
      }
      if (hash_start != std::string_view::npos) {
        out.update_unencoded_base_hash(std::string_view(
            input.data() + hash_start + 1, len - hash_start - 1));
      }
    };
    if constexpr (is_aggregator) {
      out.buffer.assign(input.substr(0, host_end));
      if (parsed_port != url_components::omitted) {
        append_canonical_port(out.buffer, parsed_port);
      }
      if (has_upper) {
        unicode::to_lower_ascii(out.buffer.data() + host_start, host_len);
      }
      out.components.protocol_end = protocol_end;
      out.components.username_end = protocol_end + 2;
      out.components.host_start = protocol_end + 2;
      out.components.host_end = static_cast<uint32_t>(host_end);
      out.components.port = parsed_port;
      out.components.pathname_start = static_cast<uint32_t>(out.buffer.size());
      out.components.search_start = url_components::omitted;
      out.components.hash_start = url_components::omitted;
      out.parse_path(path_view);
      apply_query_and_hash();
    } else {
      std::string host_str(input.substr(host_start, host_len));
      if (has_upper) {
        unicode::to_lower_ascii(host_str.data(), host_str.size());
      }
      out.host = std::move(host_str);
      if (parsed_port != url_components::omitted) {
        out.port = static_cast<uint16_t>(parsed_port);
      }
      out.parse_path(path_view);
      apply_query_and_hash();
    }
    return true;
  }

  const bool insert_slash = !has_path;
  if constexpr (is_aggregator) {
    const size_t out_len =
        host_end + port_bytes + (insert_slash ? 1 : 0) + (len - authority_end);
    const bool omit_port_bytes = parsed_port == url_components::omitted;
    if (out_len == len && !insert_slash && !omit_port_bytes) {
      out.buffer.assign(input);
    } else {
      out.buffer.clear();
      out.buffer.reserve(out_len);
      out.buffer.append(input.substr(0, host_end));
      if (parsed_port != url_components::omitted) {
        append_canonical_port(out.buffer, parsed_port);
      }
      if (insert_slash) {
        out.buffer.push_back('/');
      }
      if (authority_end < len) {
        out.buffer.append(input.substr(authority_end));
      }
    }
    if (has_upper) {
      unicode::to_lower_ascii(out.buffer.data() + host_start, host_len);
    }
    const uint32_t pathname_start =
        static_cast<uint32_t>(host_end) + port_bytes;
    const int32_t tail_delta = static_cast<int32_t>(pathname_start) +
                               (insert_slash ? 1 : 0) -
                               static_cast<int32_t>(authority_end);
    out.components.protocol_end = protocol_end;
    out.components.username_end = protocol_end + 2;
    out.components.host_start = protocol_end + 2;
    out.components.host_end = static_cast<uint32_t>(host_end);
    out.components.port = parsed_port;
    out.components.pathname_start = pathname_start;
    out.components.search_start =
        (query_start != std::string_view::npos)
            ? static_cast<uint32_t>(static_cast<int32_t>(query_start) +
                                    tail_delta)
            : url_components::omitted;
    out.components.hash_start =
        (hash_start != std::string_view::npos)
            ? static_cast<uint32_t>(static_cast<int32_t>(hash_start) +
                                    tail_delta)
            : url_components::omitted;
  } else {
    std::string host_str(input.substr(host_start, host_len));
    if (has_upper) {
      unicode::to_lower_ascii(host_str.data(), host_str.size());
    }
    out.host = std::move(host_str);
    if (parsed_port != url_components::omitted) {
      out.port = static_cast<uint16_t>(parsed_port);
    }
    if (insert_slash) {
      out.path = "/";
    } else {
      out.path.assign(input.data() + path_start, path_end - path_start);
    }
    if (query_start != std::string_view::npos) {
      const size_t q_end =
          (hash_start != std::string_view::npos) ? hash_start : len;
      out.query.emplace(input.data() + query_start + 1,
                        q_end - query_start - 1);
    }
    if (hash_start != std::string_view::npos) {
      out.hash.emplace(input.data() + hash_start + 1, len - hash_start - 1);
    }
  }
  return true;
}

// Fast path for already-canonical special-scheme URLs of the shape
// scheme://host[/path][?query][#fragment]. When the host is a plain domain
// but the rest needs encoding or dot-segment normalization, the host is
// kept and the path/query/hash helpers finish the URL.
template <class result_type>
ada_never_inline bool try_parse_simple_absolute(std::string_view input,
                                                result_type& out) {
  constexpr bool is_ada_url = std::is_same_v<result_type, ada::url>;
  constexpr bool is_aggregator =
      std::is_same_v<result_type, ada::url_aggregator>;
  static_assert(is_ada_url || is_aggregator);

  const size_t len = input.size();
  // Shortest accepted form is "ws://x" (6).
  if (len < 6) [[unlikely]] {
    return false;
  }
  const auto* b = reinterpret_cast<const uint8_t*>(input.data());

  size_t pos = 0;
  ada::scheme::type scheme_type = ada::scheme::type::NOT_SPECIAL;
  uint32_t protocol_end = 0;
  bool matched_scheme = false;
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
    defined(_M_X64) || defined(_M_IX86) || defined(_M_AMD64)
  uint32_t first4 = 0;
  std::memcpy(&first4, b, 4);
  if (first4 == 0x70747468u) {  // "http"
    matched_scheme = true;
    if (len >= 7 && b[4] == ':' && b[5] == '/' && b[6] == '/') {
      pos = 7;
      scheme_type = ada::scheme::type::HTTP;
      protocol_end = 5;
    } else if (len >= 8 && b[4] == 's' && b[5] == ':' && b[6] == '/' &&
               b[7] == '/') {
      pos = 8;
      scheme_type = ada::scheme::type::HTTPS;
      protocol_end = 6;
    } else {
      return false;
    }
  }
#else
  // Big-endian / uncommon arches: byte-wise http(s) match (compiled out on LE).
  if (len >= 7 && b[0] == 'h' && b[1] == 't' && b[2] == 't' && b[3] == 'p') {
    matched_scheme = true;
    if (b[4] == ':' && b[5] == '/' && b[6] == '/') {
      pos = 7;
      scheme_type = ada::scheme::type::HTTP;
      protocol_end = 5;
    } else if (len >= 8 && b[4] == 's' && b[5] == ':' && b[6] == '/' &&
               b[7] == '/') {
      pos = 8;
      scheme_type = ada::scheme::type::HTTPS;
      protocol_end = 6;
    } else {
      return false;
    }
  }
#endif
  if (!matched_scheme) {
    if (b[0] == 'w' && b[1] == 's') {
      if (b[2] == ':' && b[3] == '/' && b[4] == '/') {
        pos = 5;
        scheme_type = ada::scheme::type::WS;
        protocol_end = 3;
      } else if (len >= 6 && b[2] == 's' && b[3] == ':' && b[4] == '/' &&
                 b[5] == '/') {
        pos = 6;
        scheme_type = ada::scheme::type::WSS;
        protocol_end = 4;
      } else {
        return false;
      }
    } else if (b[0] == 'f' && b[1] == 't' && b[2] == 'p' && b[3] == ':' &&
               b[4] == '/' && b[5] == '/') {
      pos = 6;
      scheme_type = ada::scheme::type::FTP;
      protocol_end = 4;
    } else {
      return false;
    }
  }
  if (pos < len && (b[pos] == '/' || b[pos] == '\\')) [[unlikely]] {
    return false;
  }

  // Digit-led hosts are IPv4/numeric; '[' is IPv6. Skip before scanning.
  if (pos < len && ((b[pos] >= '0' && b[pos] <= '9') || b[pos] == '[')) {
    return false;
  }

  const size_t host_start = pos;
  bool has_upper = false;
  size_t host_end = pos;
  if (!scan_plain_host(b, pos, len, host_end, has_upper)) {
    return false;
  }
  if (host_start == host_end) [[unlikely]] {
    return false;
  }
  const size_t host_len = host_end - host_start;
  if (host_len > 253) [[unlikely]] {
    return false;
  }
  {
    std::string_view hv(input.data() + host_start, host_len);
    char host_buf[256];
    if (has_upper) [[unlikely]] {
      std::memcpy(host_buf, input.data() + host_start, host_len);
      unicode::to_lower_ascii(host_buf, host_len);
      hv = std::string_view(host_buf, host_len);
    }
    if (last_label_may_be_a_number(hv)) [[unlikely]] {
      return false;
    }
    // Punycode is "xn--...". Skip the search when the host has no 'x'.
    static constexpr std::string_view xn{"xn-", 3};
    if (hv.find('x') != std::string_view::npos &&
        hv.find(xn) != std::string_view::npos) [[unlikely]] {
      return false;
    }
  }

  if (host_end < len && b[host_end] == ':') [[unlikely]] {
    return finish_simple_absolute_with_port(input, out, scheme_type,
                                            protocol_end, host_start, host_end,
                                            host_len, has_upper);
  }

  size_t i = host_end;
  size_t path_start = host_end;
  size_t path_end = host_end;
  size_t query_start = std::string_view::npos;
  size_t hash_start = std::string_view::npos;
  bool has_path = false;
  bool maybe_dot_segment = false;
  bool rest_simple = true;

  if (i < len && b[i] == '/') {
    has_path = true;
    path_start = i;
    ++i;
    scan_path_run(b, i, len, maybe_dot_segment);
    if (i < len) {
      const uint8_t cls = k_path[b[i]];
      if (cls == 1) {
        path_end = i;
        if (b[i] == '?') {
          query_start = i;
          ++i;
          goto scan_query;
        }
        hash_start = i;
        ++i;
        goto scan_hash;
      }
      rest_simple = false;
      for (; i < len; ++i) {
        if (b[i] == '?') {
          path_end = i;
          query_start = i;
          ++i;
          goto scan_query_boundary;
        }
        if (b[i] == '#') {
          path_end = i;
          hash_start = i;
          ++i;
          goto after_rest;
        }
      }
      path_end = i;
      goto after_rest;
    }
    path_end = i;
  } else if (i < len && b[i] == '?') {
    query_start = i;
    ++i;
    goto scan_query;
  } else if (i < len && b[i] == '#') {
    hash_start = i;
    ++i;
    goto scan_hash;
  }
  goto after_rest;

scan_query:
  scan_query_run(b, i, len);
  if (i < len) {
    if (b[i] == '#') {
      hash_start = i;
      ++i;
      goto scan_hash;
    }
    rest_simple = false;
    goto scan_query_boundary;
  }
  goto after_rest;

scan_query_boundary:
  for (; i < len; ++i) {
    if (b[i] == '#') {
      hash_start = i;
      ++i;
      goto after_rest;
    }
  }
  goto after_rest;

scan_hash:
  scan_hash_run(b, i, len);
  if (i < len) {
    rest_simple = false;
  }

after_rest:
  if (rest_simple && maybe_dot_segment) {
    const std::string_view path_body(input.data() + path_start,
                                     path_end - path_start);
    if (path_has_dot_segment(path_body)) {
      rest_simple = false;
    }
  }

  // The slow path removes ASCII tab/newline anywhere in the input and trims a
  // trailing C0 control or space; this fast path does neither. A query or
  // fragment reaching the helpers below would keep those bytes percent-encoded
  // ("?a\nb" -> "?a%0Ab", "#f " -> "#f%20") instead of stripped, so hand such
  // inputs back to the slow path.
  if (!rest_simple && (unicode::is_c0_control_or_space(input.back()) ||
                       unicode::has_tabs_or_newline(input))) {
    return false;
  }

  out.type = scheme_type;
  out.is_valid = true;
  out.has_opaque_path = false;
  out.host_type = DEFAULT;

  if (!rest_simple) {
    // Host is a plain domain. Finish path/query/hash with
    // the regular helpers
    // so percent-encoding and dot segments do not re-parse the authority.
    const std::string_view path_view =
        has_path
            ? std::string_view(input.data() + path_start, path_end - path_start)
            : std::string_view{};
    auto apply_query_and_hash = [&]() {
      if (query_start != std::string_view::npos) {
        const size_t q_end =
            (hash_start != std::string_view::npos) ? hash_start : len;
        out.update_base_search(std::string_view(input.data() + query_start + 1,
                                                q_end - query_start - 1),
                               character_sets::SPECIAL_QUERY_PERCENT_ENCODE);
      }
      if (hash_start != std::string_view::npos) {
        out.update_unencoded_base_hash(std::string_view(
            input.data() + hash_start + 1, len - hash_start - 1));
      }
    };
    if constexpr (is_aggregator) {
      out.buffer.assign(input.substr(0, host_end));
      if (has_upper) {
        unicode::to_lower_ascii(out.buffer.data() + host_start, host_len);
      }
      out.components.protocol_end = protocol_end;
      out.components.username_end = protocol_end + 2;
      out.components.host_start = protocol_end + 2;
      out.components.host_end = static_cast<uint32_t>(host_end);
      out.components.port = url_components::omitted;
      out.components.pathname_start = static_cast<uint32_t>(host_end);
      out.components.search_start = url_components::omitted;
      out.components.hash_start = url_components::omitted;
      out.parse_path(path_view);
      apply_query_and_hash();
    } else {
      std::string host_str(input.substr(host_start, host_len));
      if (has_upper) {
        unicode::to_lower_ascii(host_str.data(), host_str.size());
      }
      out.host = std::move(host_str);
      out.parse_path(path_view);
      apply_query_and_hash();
    }
    return true;
  }

  const bool need_slash = !has_path;
  if constexpr (is_aggregator) {
    if (!need_slash) {
      // assign copies once. resize()+memcpy would value-init then overwrite.
      out.buffer.assign(input);
      if (has_upper) {
        unicode::to_lower_ascii(out.buffer.data() + host_start, host_len);
      }
      out.components.protocol_end = protocol_end;
      out.components.username_end = protocol_end + 2;
      out.components.host_start = protocol_end + 2;
      out.components.host_end = static_cast<uint32_t>(host_end);
      out.components.port = url_components::omitted;
      out.components.pathname_start = static_cast<uint32_t>(path_start);
      out.components.search_start = (query_start != std::string_view::npos)
                                        ? static_cast<uint32_t>(query_start)
                                        : url_components::omitted;
      out.components.hash_start = (hash_start != std::string_view::npos)
                                      ? static_cast<uint32_t>(hash_start)
                                      : url_components::omitted;
    } else {
      out.buffer.clear();
      out.buffer.reserve(len + 1);
      out.buffer.append(input.substr(0, host_end));
      out.buffer.push_back('/');
      if (host_end < len) {
        out.buffer.append(input.substr(host_end));
      }
      if (has_upper) {
        unicode::to_lower_ascii(out.buffer.data() + host_start, host_len);
      }
      out.components.protocol_end = protocol_end;
      out.components.username_end = protocol_end + 2;
      out.components.host_start = protocol_end + 2;
      out.components.host_end = static_cast<uint32_t>(host_end);
      out.components.port = url_components::omitted;
      out.components.pathname_start = static_cast<uint32_t>(host_end);
      out.components.search_start = (query_start != std::string_view::npos)
                                        ? static_cast<uint32_t>(query_start + 1)
                                        : url_components::omitted;
      out.components.hash_start = (hash_start != std::string_view::npos)
                                      ? static_cast<uint32_t>(hash_start + 1)
                                      : url_components::omitted;
    }
  } else {
    std::string host_str(input.substr(host_start, host_len));
    if (has_upper) {
      unicode::to_lower_ascii(host_str.data(), host_str.size());
    }
    out.host = std::move(host_str);
    if (need_slash) {
      out.path = "/";
    } else {
      out.path.assign(input.data() + path_start, path_end - path_start);
    }
    if (query_start != std::string_view::npos) {
      const size_t q_end =
          (hash_start != std::string_view::npos) ? hash_start : len;
      out.query.emplace(input.data() + query_start + 1,
                        q_end - query_start - 1);
    }
    if (hash_start != std::string_view::npos) {
      out.hash.emplace(input.data() + hash_start + 1, len - hash_start - 1);
    }
  }
  return true;
}

// Fast path for `/path`, path-relative (`foo`, `c/d?q`), `?query`, and
// `#fragment` against a special-scheme base. Scheme-relative (`//`) and
// scheme-like first segments (`foo:bar`) stay on the state machine.
template <class result_type>
ada_never_inline bool try_parse_simple_relative(std::string_view input,
                                                const result_type& base,
                                                result_type& out) {
  constexpr bool is_ada_url = std::is_same_v<result_type, ada::url>;
  constexpr bool is_aggregator =
      std::is_same_v<result_type, ada::url_aggregator>;
  static_assert(is_ada_url || is_aggregator);

  if (!base.is_special() || base.type == ada::scheme::type::FILE ||
      base.has_opaque_path || input.empty()) {
    return false;
  }
  const auto* b = reinterpret_cast<const uint8_t*>(input.data());
  const size_t len = input.size();
  const uint8_t first = b[0];
  const bool path_relative = first != '/' && first != '?' && first != '#';
  if (first == '/' && len > 1 && (b[1] == '/' || b[1] == '\\')) {
    return false;
  }
  // A ':' before the first / ? # is a scheme, not a path segment.
  if (path_relative) {
    const size_t delim = input.find_first_of("/?#:");
    if (delim != std::string_view::npos && input[delim] == ':') {
      return false;
    }
  }

  size_t i = 0;
  size_t path_start = 0;
  size_t path_end = 0;
  size_t query_start = std::string_view::npos;
  size_t hash_start = std::string_view::npos;
  bool has_path = false;
  bool maybe_dot_segment = false;

  if (first == '/' || path_relative) {
    has_path = true;
    path_start = 0;
    if (first == '/') {
      i = 1;
    }
    scan_path_run(b, i, len, maybe_dot_segment);
    if (i < len) {
      const uint8_t cls = k_path[b[i]];
      if (cls == 2) {
        return false;
      }
    }
    path_end = i;
    if (i < len && b[i] == '?') {
      query_start = i;
      ++i;
      scan_query_run(b, i, len);
      if (i < len) {
        if (b[i] != '#') {
          return false;
        }
        hash_start = i;
        ++i;
        scan_hash_run(b, i, len);
        if (i < len) {
          return false;
        }
      }
    } else if (i < len && b[i] == '#') {
      hash_start = i;
      ++i;
      scan_hash_run(b, i, len);
      if (i < len) {
        return false;
      }
    } else if (i < len) {
      return false;
    }
  } else if (first == '?') {
    query_start = 0;
    i = 1;
    scan_query_run(b, i, len);
    if (i < len) {
      if (b[i] != '#') {
        return false;
      }
      hash_start = i;
      ++i;
      scan_hash_run(b, i, len);
      if (i < len) {
        return false;
      }
    }
  } else {
    hash_start = 0;
    i = 1;
    scan_hash_run(b, i, len);
    if (i < len) {
      return false;
    }
  }

  if (has_path && maybe_dot_segment) {
    const std::string_view path_body(input.data() + path_start,
                                     path_end - path_start);
    if (path_has_dot_segment(path_body)) {
      return false;
    }
  }

  out = base;
  out.is_valid = true;
  out.has_opaque_path = false;

  const size_t q_end =
      (hash_start != std::string_view::npos) ? hash_start : len;
  const bool has_query = query_start != std::string_view::npos;
  const bool has_hash = hash_start != std::string_view::npos;
  const std::string_view query =
      has_query ? std::string_view(input.data() + query_start + 1,
                                   q_end - query_start - 1)
                : std::string_view{};
  const std::string_view hash =
      has_hash ? std::string_view(input.data() + hash_start + 1,
                                  len - hash_start - 1)
               : std::string_view{};

  if constexpr (is_aggregator) {
    if (first == '/' || first == '?' || path_relative) {
      out.clear_hash();
      out.clear_search();
    }
    if (first == '/') {
      out.update_base_pathname(input.substr(path_start, path_end - path_start));
    } else if (path_relative) {
      const std::string_view base_path = out.get_pathname();
      const size_t slash = base_path.rfind('/');
      const std::string_view prefix = (slash == std::string_view::npos)
                                          ? std::string_view("/")
                                          : base_path.substr(0, slash + 1);
      const std::string_view rel(input.data() + path_start,
                                 path_end - path_start);
      std::string new_path;
      new_path.reserve(prefix.size() + rel.size());
      new_path.assign(prefix);
      new_path.append(rel);
      out.update_base_pathname(new_path);
    }
    if (has_query) {
      // Do not use update_base_search: it strips a leading '?' and would
      // collapse '??a=b' into '?a=b'.
      out.components.search_start = static_cast<uint32_t>(out.buffer.size());
      out.buffer += '?';
      out.buffer.append(query);
    }
    if (has_hash) {
      out.update_unencoded_base_hash(hash);
    }
  } else {
    if (first == '/' || first == '?' || path_relative) {
      out.hash.reset();
    }
    if (first == '/') {
      out.query.reset();
      out.path.assign(input.substr(path_start, path_end - path_start));
    } else if (path_relative) {
      out.query.reset();
      const size_t slash = out.path.rfind('/');
      if (slash == std::string::npos) {
        out.path = '/';
      } else {
        out.path.resize(slash + 1);
      }
      out.path.append(input.substr(path_start, path_end - path_start));
    }
    if (has_query) {
      out.query.emplace(query);
    }
    if (has_hash) {
      out.hash.emplace(hash);
    }
  }
  return true;
}

template <class result_type, bool store_values>
result_type parse_url_impl(std::string_view user_input,
                           const result_type* base_url) {
  // We can specialize the implementation per type.
  // Important: result_type_is_ada_url is evaluated at *compile time*. This
  // means that doing if constexpr(result_type_is_ada_url) { something } else {
  // something else } is free (at runtime). This means that ada::url_aggregator
  // and ada::url **do not have to support the exact same API**.
  constexpr bool result_type_is_ada_url = std::is_same_v<url, result_type>;
  constexpr bool result_type_is_ada_url_aggregator =
      std::is_same_v<url_aggregator, result_type>;
  static_assert(result_type_is_ada_url ||
                result_type_is_ada_url_aggregator);  // We don't support
                                                     // anything else for now.

  ada_log("ada::parser::parse_url('", user_input, "' [", user_input.size(),
          " bytes],", (base_url != nullptr ? base_url->to_string() : "null"),
          ")");

  result_type url{};

  const uint32_t max_input_length = ada::get_max_input_length();

  // We refuse to parse URL strings that exceed the maximum input length.
  // By default, this is 4GB but can be configured via
  // ada::set_max_input_length().
  if (user_input.size() > max_input_length) [[unlikely]] {
    url.is_valid = false;
  }
  // Going forward, user_input.size() is in [0,
  // std::numeric_limits<uint32_t>::max). If we are provided with an invalid
  // base, or the optional_url was invalid, we must return.
  if (base_url != nullptr) {
    url.is_valid &= base_url->is_valid;
  }
  if (!url.is_valid) {
    return url;
  }

  // Simple absolute / relative fast paths (before tabs/newline scan).
  if constexpr (store_values) {
    bool hit_fast_path = false;
    if (base_url == nullptr) {
      // IPv4/IPv6 hosts start with a digit or '['. Skip the never_inline
      // fast path so those URLs do not pay for a guaranteed miss.
      const auto* p = reinterpret_cast<const uint8_t*>(user_input.data());
      const size_t n = user_input.size();
      uint8_t host_first = 0;
      if (n >= 8 && p[4] == ':' && p[5] == '/' && p[6] == '/') {
        host_first = p[7];
      } else if (n >= 9 && p[5] == ':' && p[6] == '/' && p[7] == '/') {
        host_first = p[8];
      }
      const bool skip_ip =
          host_first == '[' || (host_first >= '0' && host_first <= '9');
      hit_fast_path = !skip_ip && try_parse_simple_absolute(user_input, url);
    } else {
      hit_fast_path = try_parse_simple_relative(user_input, *base_url, url);
    }
    if (hit_fast_path) {
      if constexpr (result_type_is_ada_url_aggregator) {
        if (url.buffer.size() > max_input_length) [[unlikely]] {
          url.is_valid = false;
        }
      } else {
        if (url.get_href_size() > max_input_length) [[unlikely]] {
          url.is_valid = false;
        }
      }
      return url;
    }
  }

  state state = state::SCHEME_START;

  std::string tmp_buffer;
  std::string_view url_data;
  if (unicode::has_tabs_or_newline(user_input)) [[unlikely]] {
    tmp_buffer = user_input;
    // Optimization opportunity: Instead of copying and then pruning, we could
    // just directly build the string from user_input.
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    url_data = tmp_buffer;
  } else [[likely]] {
    url_data = user_input;
  }

  // Leading and trailing control characters are uncommon and easy to deal with
  // (no performance concern).
  helpers::trim_c0_whitespace(url_data);

  if constexpr (result_type_is_ada_url_aggregator && store_values) {
    // Most of the time, we just need user_input.size().
    // In some instances, we may need a bit more.
    ///////////////////////////
    // This is *very* important. This line should *not* be removed
    // hastily. There are principled reasons why reserve is important
    // for performance. If you have a benchmark with small inputs,
    // it may not matter, but in other instances, it could.
    ////
    // This rounds up to the next power of two.
    // We know that user_input.size() is in [0,
    // std::numeric_limits<uint32_t>::max).
    uint32_t reserve_capacity =
        (0xFFFFFFFF >>
         helpers::leading_zeroes(uint32_t(1 | user_input.size()))) +
        1;
    url.reserve(reserve_capacity);
  }

  // Optimization opportunity. Most websites do not have fragment.
  std::optional<std::string_view> fragment = helpers::prune_hash(url_data);
  // We add it last so that an implementation like ada::url_aggregator
  // can append it last to its internal buffer, thus improving performance.

  // Here url_data no longer has its fragment.
  // We are going to access the data from url_data (it is immutable).
  // At any given time, we are pointing at byte 'input_position' in url_data.
  // The input_position variable should range from 0 to input_size.
  // It is illegal to access url_data at input_size.
  size_t input_position = 0;
  const size_t input_size = url_data.size();
  // Keep running the following state machine by switching on state.
  // If after a run pointer points to the EOF code point, go to the next step.
  // Otherwise, increase pointer by 1 and continue with the state machine.
  // We never decrement input_position.
  while (input_position <= input_size) {
    ada_log("In parsing at ", input_position, " out of ", input_size,
            " in state ", ada::to_string(state));
    switch (state) {
      case state::SCHEME_START: {
        ada_log("SCHEME_START ", helpers::substring(url_data, input_position));
        // If c is an ASCII alpha, append c, lowercased, to buffer, and set
        // state to scheme state.
        if ((input_position != input_size) &&
            checkers::is_alpha(url_data[input_position])) {
          state = state::SCHEME;
          input_position++;
        } else {
          // Otherwise, if state override is not given, set state to no scheme
          // state and decrease pointer by 1.
          state = state::NO_SCHEME;
        }
        break;
      }
      case state::SCHEME: {
        ada_log("SCHEME ", helpers::substring(url_data, input_position));
        // If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.),
        // append c, lowercased, to buffer.
        while ((input_position != input_size) &&
               (unicode::is_alnum_plus(url_data[input_position]))) {
          input_position++;
        }
        // Otherwise, if c is U+003A (:), then:
        if ((input_position != input_size) &&
            (url_data[input_position] == ':')) {
          ada_log("SCHEME the scheme should be ",
                  url_data.substr(0, input_position));
          if constexpr (result_type_is_ada_url) {
            if (!url.parse_scheme(url_data.substr(0, input_position))) {
              return url;
            }
          } else {
            // we pass the colon along instead of painfully adding it back.
            if (!url.parse_scheme_with_colon(
                    url_data.substr(0, input_position + 1))) {
              return url;
            }
          }
          ada_log("SCHEME the scheme is ", url.get_protocol());

          // If url's scheme is "file", then:
          // NOLINTNEXTLINE(bugprone-branch-clone)
          if (url.type == scheme::type::FILE) {
            // Set state to file state.
            state = state::FILE;
          }
          // Otherwise, if url is special, base is non-null, and base's scheme
          // is url's scheme: Note: Doing base_url->scheme is unsafe if base_url
          // != nullptr is false.
          else if (url.is_special() && base_url != nullptr &&
                   base_url->type == url.type) {
            // Set state to special relative or authority state.
            state = state::SPECIAL_RELATIVE_OR_AUTHORITY;
          }
          // Otherwise, if url is special, set state to special authority
          // slashes state.
          else if (url.is_special()) {
            state = state::SPECIAL_AUTHORITY_SLASHES;
          }
          // Otherwise, if remaining starts with an U+002F (/), set state to
          // path or authority state and increase pointer by 1.
          else if (input_position + 1 < input_size &&
                   url_data[input_position + 1] == '/') {
            state = state::PATH_OR_AUTHORITY;
            input_position++;
          }
          // Otherwise, set url's path to the empty string and set state to
          // opaque path state.
          else {
            state = state::OPAQUE_PATH;
          }
        }
        // Otherwise, if state override is not given, set buffer to the empty
        // string, state to no scheme state, and start over (from the first code
        // point in input).
        else {
          state = state::NO_SCHEME;
          input_position = 0;
          break;
        }
        input_position++;
        break;
      }
      case state::NO_SCHEME: {
        ada_log("NO_SCHEME ", helpers::substring(url_data, input_position));
        // The fragment was pruned from url_data before the state machine ran,
        // so 'c is U+0023 (#)' holds exactly when a fragment was found and
        // nothing else remains in front of it.
        const bool c_is_hash =
            fragment.has_value() && input_position == input_size;
        // If base is null, or base has an opaque path and c is not U+0023 (#),
        // validation error, return failure.
        if (base_url == nullptr || (base_url->has_opaque_path && !c_is_hash)) {
          ada_log("NO_SCHEME validation error");
          url.is_valid = false;
          return url;
        }
        // Otherwise, if base has an opaque path and c is U+0023 (#),
        // set url's scheme to base's scheme, url's path to base's path, url's
        // query to base's query, and set state to fragment state.
        else if (base_url->has_opaque_path && c_is_hash) {
          ada_log("NO_SCHEME opaque base with fragment");
          url.copy_scheme(*base_url);
          url.has_opaque_path = base_url->has_opaque_path;

          if constexpr (result_type_is_ada_url) {
            url.path = base_url->path;
            url.query = base_url->query;
          } else {
            url.update_base_pathname(base_url->get_pathname());
            if (base_url->has_search()) {
              // get_search() returns "" for an empty query string (URL ends
              // with '?'). update_base_search("") would incorrectly clear the
              // query, so pass "?" to preserve the empty query distinction.
              auto s = base_url->get_search();
              url.update_base_search(s.empty() ? std::string_view("?") : s);
            }
          }
          url.update_unencoded_base_hash(*fragment);
          return url;
        }
        // Otherwise, if base's scheme is not "file", set state to relative
        // state and decrease pointer by 1.
        // NOLINTNEXTLINE(bugprone-branch-clone)
        else if (base_url->type != scheme::type::FILE) {
          ada_log("NO_SCHEME non-file relative path");
          state = state::RELATIVE_SCHEME;
        }
        // Otherwise, set state to file state and decrease pointer by 1.
        else {
          ada_log("NO_SCHEME file base type");
          state = state::FILE;
        }
        break;
      }
      case state::AUTHORITY: {
        ada_log("AUTHORITY ", helpers::substring(url_data, input_position));
        // most URLs have no @. Having no @ tells us that we don't have to worry
        // about AUTHORITY. Of course, we could have @ and still not have to
        // worry about AUTHORITY.
        // TODO: Instead of just collecting a bool, collect the location of the
        // '@' and do something useful with it.
        // TODO: We could do various processing early on, using a single pass
        // over the string to collect information about it, e.g., telling us
        // whether there is a @ and if so, where (or how many).

        // Check if url data contains an @.
        if (url_data.find('@', input_position) == std::string_view::npos) {
          state = state::HOST;
          break;
        }
        bool at_sign_seen{false};
        bool password_token_seen{false};
        /**
         * We expect something of the sort...
         * https://user:pass@example.com:1234/foo/bar?baz#quux
         * --------^
         */
        do {
          std::string_view view = url_data.substr(input_position);
          // The delimiters are @, /, ? \\.
          size_t location =
              url.is_special() ? helpers::find_authority_delimiter_special(view)
                               : helpers::find_authority_delimiter(view);
          std::string_view authority_view = view.substr(0, location);
          size_t end_of_authority = input_position + authority_view.size();
          // If c is U+0040 (@), then:
          if ((end_of_authority != input_size) &&
              (url_data[end_of_authority] == '@')) {
            // If atSignSeen is true, then prepend "%40" to buffer.
            if (at_sign_seen) {
              if (password_token_seen) {
                if constexpr (result_type_is_ada_url) {
                  url.password += "%40";
                } else {
                  url.append_base_password("%40");
                }
              } else {
                if constexpr (result_type_is_ada_url) {
                  url.username += "%40";
                } else {
                  url.append_base_username("%40");
                }
              }
            }

            at_sign_seen = true;

            if (!password_token_seen) {
              size_t password_token_location = authority_view.find(':');
              password_token_seen =
                  password_token_location != std::string_view::npos;

              if constexpr (store_values) {
                if (!password_token_seen) {
                  if constexpr (result_type_is_ada_url) {
                    url.username += unicode::percent_encode(
                        authority_view,
                        character_sets::USERINFO_PERCENT_ENCODE);
                  } else {
                    url.append_base_username(unicode::percent_encode(
                        authority_view,
                        character_sets::USERINFO_PERCENT_ENCODE));
                  }
                } else {
                  if constexpr (result_type_is_ada_url) {
                    url.username += unicode::percent_encode(
                        authority_view.substr(0, password_token_location),
                        character_sets::USERINFO_PERCENT_ENCODE);
                    url.password += unicode::percent_encode(
                        authority_view.substr(password_token_location + 1),
                        character_sets::USERINFO_PERCENT_ENCODE);
                  } else {
                    url.append_base_username(unicode::percent_encode(
                        authority_view.substr(0, password_token_location),
                        character_sets::USERINFO_PERCENT_ENCODE));
                    url.append_base_password(unicode::percent_encode(
                        authority_view.substr(password_token_location + 1),
                        character_sets::USERINFO_PERCENT_ENCODE));
                  }
                }
              }
            } else if constexpr (store_values) {
              if constexpr (result_type_is_ada_url) {
                url.password += unicode::percent_encode(
                    authority_view, character_sets::USERINFO_PERCENT_ENCODE);
              } else {
                url.append_base_password(unicode::percent_encode(
                    authority_view, character_sets::USERINFO_PERCENT_ENCODE));
              }
            }
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          else if (end_of_authority == input_size ||
                   url_data[end_of_authority] == '/' ||
                   url_data[end_of_authority] == '?' ||
                   (url.is_special() && url_data[end_of_authority] == '\\')) {
            // If atSignSeen is true and authority_view is the empty string,
            // validation error, return failure.
            if (at_sign_seen && authority_view.empty()) {
              url.is_valid = false;
              return url;
            }
            state = state::HOST;
            break;
          }
          if (end_of_authority == input_size) {
            if constexpr (store_values) {
              if (fragment.has_value()) {
                url.update_unencoded_base_hash(*fragment);
              }
            }
            return url;
          }
          input_position = end_of_authority + 1;
        } while (true);

        break;
      }
      case state::SPECIAL_RELATIVE_OR_AUTHORITY: {
        ada_log("SPECIAL_RELATIVE_OR_AUTHORITY ",
                helpers::substring(url_data, input_position));

        // If c is U+002F (/) and remaining starts with U+002F (/),
        // then set state to special authority ignore slashes state and increase
        // pointer by 1.
        if (url_data.substr(input_position, 2) == "//") {
          state = state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
          input_position += 2;
        } else {
          // Otherwise, validation error, set state to relative state and
          // decrease pointer by 1.
          state = state::RELATIVE_SCHEME;
        }

        break;
      }
      case state::PATH_OR_AUTHORITY: {
        ada_log("PATH_OR_AUTHORITY ",
                helpers::substring(url_data, input_position));

        // If c is U+002F (/), then set state to authority state.
        if ((input_position != input_size) &&
            (url_data[input_position] == '/')) {
          state = state::AUTHORITY;
          input_position++;
        } else {
          // Otherwise, set state to path state, and decrease pointer by 1.
          state = state::PATH;
        }

        break;
      }
      case state::RELATIVE_SCHEME: {
        ada_log("RELATIVE_SCHEME ",
                helpers::substring(url_data, input_position));

        // Set url's scheme to base's scheme.
        url.copy_scheme(*base_url);

        // If c is U+002F (/), then set state to relative slash state.
        if ((input_position != input_size) &&
            // NOLINTNEXTLINE(bugprone-branch-clone)
            (url_data[input_position] == '/')) {
          ada_log(
              "RELATIVE_SCHEME if c is U+002F (/), then set state to relative "
              "slash state");
          state = state::RELATIVE_SLASH;
        } else if (url.is_special() && (input_position != input_size) &&
                   (url_data[input_position] == '\\')) {
          // Otherwise, if url is special and c is U+005C (\), validation error,
          // set state to relative slash state.
          ada_log(
              "RELATIVE_SCHEME  if url is special and c is U+005C, validation "
              "error, set state to relative slash state");
          state = state::RELATIVE_SLASH;
        } else {
          ada_log("RELATIVE_SCHEME otherwise");
          // Set url's username to base's username, url's password to base's
          // password, url's host to base's host, url's port to base's port,
          // url's path to a clone of base's path, and url's query to base's
          // query.
          if constexpr (result_type_is_ada_url) {
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            // cloning the base path includes cloning the has_opaque_path flag
            url.has_opaque_path = base_url->has_opaque_path;
            url.path = base_url->path;
            url.query = base_url->query;
          } else {
            url.update_base_authority(base_url->get_href(),
                                      base_url->get_components());
            url.update_host_to_base_host(base_url->get_hostname());
            url.update_base_port(base_url->retrieve_base_port());
            // cloning the base path includes cloning the has_opaque_path flag
            url.has_opaque_path = base_url->has_opaque_path;
            url.update_base_pathname(base_url->get_pathname());
            if (base_url->has_search()) {
              // get_search() returns "" for an empty query string (URL ends
              // with '?'). update_base_search("") would incorrectly clear the
              // query, so pass "?" to preserve the empty query distinction.
              auto s = base_url->get_search();
              url.update_base_search(s.empty() ? std::string_view("?") : s);
            }
          }

          url.has_opaque_path = base_url->has_opaque_path;

          // If c is U+003F (?), then set url's query to the empty string, and
          // state to query state.
          if ((input_position != input_size) &&
              (url_data[input_position] == '?')) {
            state = state::QUERY;
          }
          // Otherwise, if c is not the EOF code point:
          else if (input_position != input_size) {
            // Set url's query to null.
            url.clear_search();
            if constexpr (result_type_is_ada_url) {
              // Shorten url's path.
              helpers::shorten_path(url.path, url.type);
            } else {
              std::string_view path = url.get_pathname();
              if (helpers::shorten_path(path, url.type)) {
                url.update_base_pathname(std::move(std::string(path)));
              }
            }
            // Set state to path state and decrease pointer by 1.
            state = state::PATH;
            break;
          }
        }
        input_position++;
        break;
      }
      case state::RELATIVE_SLASH: {
        ada_log("RELATIVE_SLASH ",
                helpers::substring(url_data, input_position));

        // If url is special and c is U+002F (/) or U+005C (\), then:
        // NOLINTNEXTLINE(bugprone-branch-clone)
        if (url.is_special() && (input_position != input_size) &&
            (url_data[input_position] == '/' ||
             url_data[input_position] == '\\')) {
          // Set state to special authority ignore slashes state.
          state = state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
        }
        // Otherwise, if c is U+002F (/), then set state to authority state.
        else if ((input_position != input_size) &&
                 (url_data[input_position] == '/')) {
          state = state::AUTHORITY;
        }
        // Otherwise, set
        // - url's username to base's username,
        // - url's password to base's password,
        // - url's host to base's host,
        // - url's port to base's port,
        // - state to path state, and then, decrease pointer by 1.
        else {
          if constexpr (result_type_is_ada_url) {
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
          } else {
            url.update_base_authority(base_url->get_href(),
                                      base_url->get_components());
            url.update_host_to_base_host(base_url->get_hostname());
            url.update_base_port(base_url->retrieve_base_port());
          }
          state = state::PATH;
          break;
        }

        input_position++;
        break;
      }
      case state::SPECIAL_AUTHORITY_SLASHES: {
        ada_log("SPECIAL_AUTHORITY_SLASHES ",
                helpers::substring(url_data, input_position));

        // If c is U+002F (/) and remaining starts with U+002F (/),
        // then set state to special authority ignore slashes state and increase
        // pointer by 1.
        if (url_data.substr(input_position, 2) == "//") {
          input_position += 2;
        }

        [[fallthrough]];
      }
      case state::SPECIAL_AUTHORITY_IGNORE_SLASHES: {
        ada_log("SPECIAL_AUTHORITY_IGNORE_SLASHES ",
                helpers::substring(url_data, input_position));

        // If c is neither U+002F (/) nor U+005C (\), then set state to
        // authority state and decrease pointer by 1.
        while ((input_position != input_size) &&
               ((url_data[input_position] == '/') ||
                (url_data[input_position] == '\\'))) {
          input_position++;
        }
        state = state::AUTHORITY;

        break;
      }
      case state::QUERY: {
        ada_log("QUERY ", helpers::substring(url_data, input_position));
        if constexpr (store_values) {
          // Let queryPercentEncodeSet be the special-query percent-encode set
          // if url is special; otherwise the query percent-encode set.
          const uint8_t* query_percent_encode_set =
              url.is_special() ? character_sets::SPECIAL_QUERY_PERCENT_ENCODE
                               : character_sets::QUERY_PERCENT_ENCODE;

          // Percent-encode after encoding, with encoding, buffer, and
          // queryPercentEncodeSet, and append the result to url's query.
          url.update_base_search(url_data.substr(input_position),
                                 query_percent_encode_set);
          ada_log("QUERY update_base_search completed ");
          if (fragment.has_value()) {
            url.update_unencoded_base_hash(*fragment);
          }
        }
        return url;
      }
      case state::HOST: {
        ada_log("HOST ", helpers::substring(url_data, input_position));

        std::string_view host_view = url_data.substr(input_position);
        auto [location, found_colon] =
            helpers::get_host_delimiter_location(url.is_special(), host_view);
        input_position = (location != std::string_view::npos)
                             ? input_position + location
                             : input_size;
        // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
        // Note: the 'found_colon' value is true if and only if a colon was
        // encountered while not inside brackets.
        if (found_colon) {
          // If buffer is the empty string, validation error, return failure.
          // Let host be the result of host parsing buffer with url is not
          // special.
          ada_log("HOST parsing ", host_view);
          if (!url.parse_host(host_view)) {
            return url;
          }
          ada_log("HOST parsing results in ", url.get_hostname());
          // Set url's host to host, buffer to the empty string, and state to
          // port state.
          state = state::PORT;
          input_position++;
        }
        // Otherwise, if one of the following is true:
        // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
        // - url is special and c is U+005C (\)
        // The get_host_delimiter_location function either brings us to
        // the colon outside of the bracket, or to one of those characters.
        else {
          // If url is special and host_view is the empty string, validation
          // error, return failure.
          if (host_view.empty() && url.is_special()) {
            url.is_valid = false;
            return url;
          }
          ada_log("HOST parsing ", host_view, " href=", url.get_href());
          // Let host be the result of host parsing host_view with url is not
          // special.
          if (host_view.empty()) {
            url.update_base_hostname("");
          } else if (!url.parse_host(host_view)) {
            return url;
          }
          ada_log("HOST parsing results in ", url.get_hostname(),
                  " href=", url.get_href());

          // Set url's host to host, and state to path start state.
          state = state::PATH_START;
        }

        break;
      }
      case state::OPAQUE_PATH: {
        ada_log("OPAQUE_PATH ", helpers::substring(url_data, input_position));
        // Opaque path, query, and fragment are structurally always valid:
        // the parser would just percent-encode whatever is there. When we
        // are not storing values (can_parse), we can return immediately.
        // We must set has_opaque_path = true before returning so that when
        // this URL is used as an internal base inside can_parse, NO_SCHEME
        // correctly rejects relative inputs against an opaque-path base
        // (e.g. can_parse("", &"W:") must return false).
        if constexpr (!store_values) {
          url.has_opaque_path = true;
          return url;
        }
        std::string_view view = url_data.substr(input_position);
        // If c is U+003F (?), then set url's query to the empty string and
        // state to query state.
        size_t location = view.find('?');
        if (location != std::string_view::npos) {
          view.remove_suffix(view.size() - location);
          state = state::QUERY;
          input_position += location + 1;
        } else {
          input_position = input_size + 1;
        }
        url.has_opaque_path = true;

        // This is a really unlikely scenario in real world. We should not seek
        // to optimize it.
        if (view.ends_with(' ')) {
          std::string modified_view =
              std::string(view.substr(0, view.size() - 1)) + "%20";
          url.update_base_pathname(unicode::percent_encode(
              modified_view, character_sets::C0_CONTROL_PERCENT_ENCODE));
        } else {
          url.update_base_pathname(unicode::percent_encode(
              view, character_sets::C0_CONTROL_PERCENT_ENCODE));
        }
        break;
      }
      case state::PORT: {
        ada_log("PORT ", helpers::substring(url_data, input_position));
        std::string_view port_view = url_data.substr(input_position);
        input_position += url.parse_port(port_view, true);
        if (!url.is_valid) {
          return url;
        }
        state = state::PATH_START;
        [[fallthrough]];
      }
      case state::PATH_START: {
        ada_log("PATH_START ", helpers::substring(url_data, input_position));
        // Path, query, and fragment are structurally always valid: the
        // parser would just percent-encode whatever is there. When we are
        // not storing values (can_parse), we can return immediately since
        // no subsequent state can invalidate the URL.
        if constexpr (!store_values) {
          return url;
        }

        // If url is special, then:
        if (url.is_special()) {
          // Set state to path state.
          state = state::PATH;

          // Optimization: Avoiding going into PATH state improves the
          // performance of urls ending with /.
          if (input_position == input_size) {
            if constexpr (store_values) {
              url.update_base_pathname("/");
              if (fragment.has_value()) {
                url.update_unencoded_base_hash(*fragment);
              }
            }
            return url;
          }
          // If c is neither U+002F (/) nor U+005C (\), then decrease pointer
          // by 1. We know that (input_position == input_size) is impossible
          // here, because of the previous if-check.
          if ((url_data[input_position] != '/') &&
              (url_data[input_position] != '\\')) {
            break;
          }
        }
        // Otherwise, if state override is not given and c is U+003F (?),
        // set url's query to the empty string and state to query state.
        else if ((input_position != input_size) &&
                 (url_data[input_position] == '?')) {
          state = state::QUERY;
        }
        // Otherwise, if c is not the EOF code point:
        else if (input_position != input_size) {
          // Set state to path state.
          state = state::PATH;

          // If c is not U+002F (/), then decrease pointer by 1.
          if (url_data[input_position] != '/') {
            break;
          }
        }

        input_position++;
        break;
      }
      case state::PATH: {
        ada_log("PATH ", helpers::substring(url_data, input_position));
        // Path, query, and fragment are structurally always valid: the
        // parser would just percent-encode whatever is there. When we are
        // not storing values (can_parse), we can return immediately since
        // no subsequent state can invalidate the URL.
        if constexpr (!store_values) {
          return url;
        }
        std::string_view view = url_data.substr(input_position);

        // Most time, we do not need percent encoding.
        // Furthermore, we can immediately locate the '?'.
        size_t locofquestionmark = view.find('?');
        if (locofquestionmark != std::string_view::npos) {
          state = state::QUERY;
          view.remove_suffix(view.size() - locofquestionmark);
          input_position += locofquestionmark + 1;
        } else {
          input_position = input_size + 1;
        }
        if constexpr (store_values) {
          if constexpr (result_type_is_ada_url) {
            helpers::parse_prepared_path(view, url.type, url.path);
          } else {
            url.consume_prepared_path(view);
            ADA_ASSERT_TRUE(url.validate());
          }
        }
        break;
      }
      case state::FILE_SLASH: {
        ada_log("FILE_SLASH ", helpers::substring(url_data, input_position));

        // If c is U+002F (/) or U+005C (\), then:
        if ((input_position != input_size) &&
            (url_data[input_position] == '/' ||
             url_data[input_position] == '\\')) {
          ada_log("FILE_SLASH c is U+002F or U+005C");
          // Set state to file host state.
          state = state::FILE_HOST;
          input_position++;
        } else {
          ada_log("FILE_SLASH otherwise");
          // If base is non-null and base's scheme is "file", then:
          // Note: it is unsafe to do base_url->scheme unless you know that
          // base_url_has_value() is true.
          if (base_url != nullptr && base_url->type == scheme::type::FILE) {
            // Set url's host to base's host.
            if constexpr (result_type_is_ada_url) {
              url.host = base_url->host;
            } else {
              url.update_host_to_base_host(base_url->get_host());
            }
            // If the code point substring from pointer to the end of input does
            // not start with a Windows drive letter and base's path[0] is a
            // normalized Windows drive letter, then append base's path[0] to
            // url's path.
            if (!base_url->get_pathname().empty()) {
              if (!checkers::is_windows_drive_letter(
                      url_data.substr(input_position))) {
                std::string_view first_base_url_path =
                    base_url->get_pathname().substr(1);
                size_t loc = first_base_url_path.find('/');
                if (loc != std::string_view::npos) {
                  helpers::resize(first_base_url_path, loc);
                }
                if (checkers::is_normalized_windows_drive_letter(
                        first_base_url_path)) {
                  if constexpr (result_type_is_ada_url) {
                    url.path += '/';
                    url.path += first_base_url_path;
                  } else {
                    url.append_base_pathname(
                        helpers::concat("/", first_base_url_path));
                  }
                }
              }
            }
          }

          // Set state to path state, and decrease pointer by 1.
          state = state::PATH;
        }

        break;
      }
      case state::FILE_HOST: {
        ada_log("FILE_HOST ", helpers::substring(url_data, input_position));
        std::string_view view = url_data.substr(input_position);

        size_t location = view.find_first_of("/\\?");
        std::string_view file_host_buffer = view.substr(
            0, (location != std::string_view::npos) ? location : view.size());

        if (checkers::is_windows_drive_letter(file_host_buffer)) {
          state = state::PATH;
        } else if (file_host_buffer.empty()) {
          // Set url's host to the empty string.
          if constexpr (result_type_is_ada_url) {
            url.host = "";
          } else {
            url.update_base_hostname("");
          }
          // Set state to path start state.
          state = state::PATH_START;
        } else {
          size_t consumed_bytes = file_host_buffer.size();
          input_position += consumed_bytes;
          // Let host be the result of host parsing buffer with url is not
          // special.
          if (!url.parse_host(file_host_buffer)) {
            return url;
          }

          if constexpr (result_type_is_ada_url) {
            // If host is "localhost", then set host to the empty string.
            if (url.host.has_value() && url.host.value() == "localhost") {
              url.host = "";
            }
          } else {
            if (url.get_hostname() == "localhost") {
              url.update_base_hostname("");
            }
          }

          // Set buffer to the empty string and state to path start state.
          state = state::PATH_START;
        }

        break;
      }
      case state::FILE: {
        ada_log("FILE ", helpers::substring(url_data, input_position));
        std::string_view file_view = url_data.substr(input_position);

        url.set_protocol_as_file();
        if constexpr (result_type_is_ada_url) {
          // Set url's host to the empty string.
          url.host = "";
        } else {
          url.update_base_hostname("");
        }
        // If c is U+002F (/) or U+005C (\), then:
        if (input_position != input_size &&
            (url_data[input_position] == '/' ||
             url_data[input_position] == '\\')) {
          ada_log("FILE c is U+002F or U+005C");
          // Set state to file slash state.
          state = state::FILE_SLASH;
        }
        // Otherwise, if base is non-null and base's scheme is "file":
        else if (base_url != nullptr && base_url->type == scheme::type::FILE) {
          // Set url's host to base's host, url's path to a clone of base's
          // path, and url's query to base's query.
          ada_log("FILE base non-null");
          if constexpr (result_type_is_ada_url) {
            url.host = base_url->host;
            url.path = base_url->path;
            url.query = base_url->query;
          } else {
            url.update_host_to_base_host(base_url->get_hostname());
            url.update_base_pathname(base_url->get_pathname());
            if (base_url->has_search()) {
              // get_search() returns "" for an empty query string (URL ends
              // with '?'). update_base_search("") would incorrectly clear the
              // query, so pass "?" to preserve the empty query distinction.
              auto s = base_url->get_search();
              url.update_base_search(s.empty() ? std::string_view("?") : s);
            }
          }
          url.has_opaque_path = base_url->has_opaque_path;

          // If c is U+003F (?), then set url's query to the empty string and
          // state to query state.
          if (input_position != input_size && url_data[input_position] == '?') {
            state = state::QUERY;
          }
          // Otherwise, if c is not the EOF code point:
          else if (input_position != input_size) {
            // Set url's query to null.
            url.clear_search();
            // If the code point substring from pointer to the end of input does
            // not start with a Windows drive letter, then shorten url's path.
            if (!checkers::is_windows_drive_letter(file_view)) {
              if constexpr (result_type_is_ada_url) {
                helpers::shorten_path(url.path, url.type);
              } else {
                std::string_view path = url.get_pathname();
                if (helpers::shorten_path(path, url.type)) {
                  url.update_base_pathname(std::move(std::string(path)));
                }
              }
            }
            // Otherwise:
            else {
              // Set url's path to an empty list.
              url.clear_pathname();
              url.has_opaque_path = true;
            }

            // Set state to path state and decrease pointer by 1.
            state = state::PATH;
            break;
          }
        }
        // Otherwise, set state to path state, and decrease pointer by 1.
        else {
          ada_log("FILE go to path");
          state = state::PATH;
          break;
        }

        input_position++;
        break;
      }
      default:
        unreachable();
    }
  }
  if constexpr (store_values) {
    if (fragment.has_value()) {
      url.update_unencoded_base_hash(*fragment);
    }
  }
  // Check the resulting (normalized) URL size against the maximum input length.
  // Normalization (percent-encoding, IDNA, etc.) can expand the URL beyond the
  // original input size.
  if constexpr (store_values) {
    if (url.is_valid) {
      if constexpr (result_type_is_ada_url_aggregator) {
        if (url.buffer.size() > max_input_length) {
          url.is_valid = false;
        }
      } else {
        if (url.get_href_size() > max_input_length) {
          url.is_valid = false;
        }
      }
    }
  }
  return url;
}

template bool try_parse_simple_absolute<url>(std::string_view, url&);
template bool try_parse_simple_absolute<url_aggregator>(std::string_view,
                                                        url_aggregator&);
template bool finish_simple_absolute_with_port<url>(std::string_view, url&,
                                                    ada::scheme::type, uint32_t,
                                                    size_t, size_t, size_t,
                                                    bool);
template bool finish_simple_absolute_with_port<url_aggregator>(
    std::string_view, url_aggregator&, ada::scheme::type, uint32_t, size_t,
    size_t, size_t, bool);
template bool try_parse_simple_relative<url>(std::string_view, const url&,
                                             url&);
template bool try_parse_simple_relative<url_aggregator>(std::string_view,
                                                        const url_aggregator&,
                                                        url_aggregator&);

template url parse_url_impl<url, true>(std::string_view user_input,
                                       const url* base_url = nullptr);
template url_aggregator parse_url_impl<url_aggregator, true>(
    std::string_view user_input, const url_aggregator* base_url = nullptr);
template url_aggregator parse_url_impl<url_aggregator, false>(
    std::string_view user_input, const url_aggregator* base_url = nullptr);

template <class result_type>
result_type parse_url(std::string_view user_input,
                      const result_type* base_url) {
  return parse_url_impl<result_type, true>(user_input, base_url);
}

template url parse_url<url>(std::string_view user_input,
                            const url* base_url = nullptr);
template url_aggregator parse_url<url_aggregator>(
    std::string_view user_input, const url_aggregator* base_url = nullptr);
}  // namespace ada::parser
#include "ada.h"
#include "ada/parser.h"
#include "ada/parser-inl.h"

#include <array>
#include <bit>
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
#include "ada/serializers.h"
#include "ada/url.h"
#include "ada/url-inl.h"
#include "ada/url_base-inl.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"
#include "ada/url_ip-inl.h"

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
#if defined(__clang__)
// clang ignores #pragma GCC target and treats unknown pragmas as
// errors under -Werror. Per-function target() works; do not
// always_inline the pshufb helpers (lambdas do not inherit target).
#define ADA_PARSER_SIMD inline __attribute__((target("ssse3")))
#define ADA_PARSER_FASTPATH __attribute__((target("ssse3"), noinline))
#define ADA_PARSER_COLD __attribute__((target("ssse3"), noinline, cold))
#else
// gcc: file-scope pragma so lambdas inherit SSSE3 and always_inline
// pshufb helpers can inline. parse_url_impl stays outside the pragma.
#define ADA_PARSER_SIMD ada_really_inline
#define ADA_PARSER_FASTPATH ada_never_inline
#define ADA_PARSER_COLD ada_never_inline ada_cold
#define ADA_PARSER_ENABLE_SSSE3_PRAGMA 1
#endif
#else
#define ADA_PARSER_SIMD ada_really_inline
#define ADA_PARSER_FASTPATH ada_never_inline
#define ADA_PARSER_COLD ada_never_inline ada_cold
#endif

#ifdef ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif

namespace ada {
extern bool max_input_length_customized;
}  // namespace ada

namespace ada::parser {

#ifdef ADA_PARSER_ENABLE_SSSE3_PRAGMA
#pragma GCC push_options
#pragma GCC target("ssse3")
#endif

#if !defined(ADA_SKIP_PARSER_FASTPATH) || !defined(ADA_SKIP_PARSER_FINISH)
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

// Path: 0 = copy, 1 = ?/#, 2 = needs work. Apostrophe and '%' are
// copyable. '%' is left as-is by the path percent-encode set; only a
// whole segment that is "." / ".." / "%2e" / "%2e%2e" (ASCII case
// insensitive) needs the path helpers.
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
                    static_cast<uint8_t>('^'), static_cast<uint8_t>('\\')}) {
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

// One helper for the no-userinfo special-scheme authority offsets.
ada_really_inline void set_plain_host_components(
    url_components& c, uint32_t protocol_end, uint32_t host_end,
    uint32_t pathname_start, uint32_t search_start, uint32_t hash_start,
    uint32_t port = url_components::omitted) noexcept {
  const uint32_t host_off = protocol_end + 2;
  c.protocol_end = protocol_end;
  c.username_end = host_off;
  c.host_start = host_off;
  c.host_end = host_end;
  c.port = port;
  c.pathname_start = pathname_start;
  c.search_start = search_start;
  c.hash_start = hash_start;
}

// npos truncated to uint32_t is omitted, so the 99% has-path finish
// can store query/hash starts without a cmov against string_view::npos.
static_assert(static_cast<uint32_t>(std::string_view::npos) ==
              url_components::omitted);

// https:// is ~96% of the dataset: protocol_end=6, host at 8, port omitted.
ada_really_inline void set_https_plain_host_components(
    url_components& c, uint32_t host_end, uint32_t pathname_start,
    uint32_t search_start, uint32_t hash_start) noexcept {
  c.protocol_end = 6;
  c.username_end = 8;
  c.host_start = 8;
  c.host_end = host_end;
  c.pathname_start = pathname_start;
  c.search_start = search_start;
  c.hash_start = hash_start;
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
  // '%' is copyable in a path (left as-is by the percent-encode set).
  const __m128i spec = _mm_or_si128(
      _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('"')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('#'))),
                   _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('<')),
                                _mm_cmpeq_epi8(w, _mm_set1_epi8('>')))),
      _mm_or_si128(
          _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('?')),
                                    _mm_cmpeq_epi8(w, _mm_set1_epi8('\\'))),
                       _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('^')),
                                    _mm_cmpeq_epi8(w, _mm_set1_epi8('`')))),
          _mm_or_si128(_mm_cmpeq_epi8(w, _mm_set1_epi8('{')),
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

// Punycode "xn-" at pos. Path bytes after a host delimiter are never "n-",
// so a host-final 'x' cannot false-positive.
ada_really_inline void note_xn_prefix(const uint8_t* b, size_t pos, size_t len,
                                      bool& has_xn) noexcept {
  if (!has_xn && pos + 2 < len && b[pos + 1] == 'n' && b[pos + 2] == '-') {
    has_xn = true;
  }
}

ada_really_inline void note_xn_mask(const uint8_t* b, size_t at, int x_mask,
                                    size_t len, bool& has_xn) noexcept {
  if (has_xn || x_mask == 0) {
    return;
  }
  unsigned bits = static_cast<unsigned>(x_mask);
  do {
    note_xn_prefix(b, at + static_cast<size_t>(trailing_zeroes32(bits)), len,
                   has_xn);
    bits &= bits - 1;
  } while (bits != 0 && !has_xn);
}

#if ADA_NEON
ada_really_inline void note_xn_neon(const uint8_t* b, size_t at, uint64_t xs,
                                    size_t len, bool& has_xn) noexcept {
  if (has_xn || xs == 0) {
    return;
  }
  do {
    const int tz = trailing_zeroes64(xs);
    note_xn_prefix(b, at + (static_cast<size_t>(tz) >> 2), len, has_xn);
    xs &= ~(uint64_t{0xF} << (static_cast<unsigned>(tz) & ~3u));
  } while (xs != 0 && !has_xn);
}
#endif

ada_really_inline bool is_host_delimiter(uint8_t c) noexcept {
  return c == '/' || c == '?' || c == '#' || c == ':';
}

// Returns false if a forbidden host code point is found. On success, *end is
// the first / ? # or len. has_upper / has_xn only count host bytes, not the
// path/query bytes that may sit in the same SIMD window after the delimiter.
ADA_PARSER_SIMD bool scan_plain_host(const uint8_t* b, size_t start, size_t len,
                                     size_t& end, bool& has_upper,
                                     bool& has_xn) noexcept {
  has_upper = false;
  has_xn = false;
  size_t i = start;
#if ADA_PARSER_SSSE3
  if (len - start >= 16) {
    const __m128i lo_tbl = nibble_load(k_host_nibbles.low);
    const __m128i hi_tbl = nibble_load(k_host_nibbles.high);
    const __m128i x_splat = _mm_set1_epi8('x');
    auto visit = [&](size_t at) noexcept -> bool {
      const __m128i w =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at));
      const int up = sse2_uppercase(w);
      const int xs = _mm_movemask_epi8(_mm_cmpeq_epi8(w, x_splat));
      const int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);
      if (mask == 0) {
        if (up != 0) {
          has_upper = true;
        }
        note_xn_mask(b, at, xs, len, has_xn);
        return false;
      }
      const int hit = trailing_zeroes32(static_cast<uint32_t>(mask));
      const int valid = (1 << hit) - 1;
      if ((up & valid) != 0) {
        has_upper = true;
      }
      note_xn_mask(b, at, xs & valid, len, has_xn);
      end = at + static_cast<size_t>(hit);
      return true;
    };
    for (; i + 32 <= len; i += 32) {
      if (visit(i) || visit(i + 16)) {
        return is_host_delimiter(b[end]);
      }
    }
    for (; i + 16 <= len; i += 16) {
      if (visit(i)) {
        return is_host_delimiter(b[end]);
      }
    }
    // Overlapping tail only after a full 16-byte step so the window cannot
    // start before `start` (a prior '/' would otherwise look like a host stop).
    if (i > start && i < len) {
      if (visit(len - 16) && end >= i) {
        return is_host_delimiter(b[end]);
      }
      end = len;
      return true;
    }
  } else if (len >= 16 && start < len) {
    // Remaining host region is shorter than 16, but the whole URL is
    // not: classify the last 16 bytes and ignore bytes before `start`.
    const size_t at = len - 16;
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at));
    const int skip = static_cast<int>(start - at);
    const int keep = static_cast<int>(~((1u << skip) - 1u));
    const int up = sse2_uppercase(w) & keep;
    const int xs =
        _mm_movemask_epi8(_mm_cmpeq_epi8(w, _mm_set1_epi8('x'))) & keep;
    const int mask = ssse3_nibble_mask(w, nibble_load(k_host_nibbles.low),
                                       nibble_load(k_host_nibbles.high)) &
                     keep;
    if (mask == 0) {
      if (up != 0) {
        has_upper = true;
      }
      note_xn_mask(b, at, xs, len, has_xn);
      end = len;
      return true;
    }
    const int hit = trailing_zeroes32(static_cast<uint32_t>(mask));
    const int valid = ((1 << hit) - 1) & keep;
    if ((up & valid) != 0) {
      has_upper = true;
    }
    note_xn_mask(b, at, xs & valid, len, has_xn);
    end = at + static_cast<size_t>(hit);
    return is_host_delimiter(b[end]);
  }
#elif ADA_SSE2
  const __m128i x_splat = _mm_set1_epi8('x');
  for (; i + 32 <= len; i += 32) {
    for (size_t off = 0; off < 32; off += 16) {
      const __m128i w =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i + off));
      const int up = sse2_uppercase(w);
      const int xs = _mm_movemask_epi8(_mm_cmpeq_epi8(w, x_splat));
      const int mask = sse2_host_stop(w);
      if (mask != 0) {
        const int hit = trailing_zeroes32(static_cast<uint32_t>(mask));
        const int valid = (1 << hit) - 1;
        if ((up & valid) != 0) {
          has_upper = true;
        }
        note_xn_mask(b, i + off, xs & valid, len, has_xn);
        end = i + off + static_cast<size_t>(hit);
        return is_host_delimiter(b[end]);
      }
      if (up != 0) {
        has_upper = true;
      }
      note_xn_mask(b, i + off, xs, len, has_xn);
    }
  }
  for (; i + 16 <= len; i += 16) {
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
    const int up = sse2_uppercase(w);
    const int xs = _mm_movemask_epi8(_mm_cmpeq_epi8(w, x_splat));
    const int mask = sse2_host_stop(w);
    if (mask != 0) {
      const int hit = trailing_zeroes32(static_cast<uint32_t>(mask));
      const int valid = (1 << hit) - 1;
      if ((up & valid) != 0) {
        has_upper = true;
      }
      note_xn_mask(b, i, xs & valid, len, has_xn);
      end = i + static_cast<size_t>(hit);
      return is_host_delimiter(b[end]);
    }
    if (up != 0) {
      has_upper = true;
    }
    note_xn_mask(b, i, xs, len, has_xn);
  }
  if (len >= 16 && i < len) {
    const size_t at = len - 16;
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at));
    const int skip = static_cast<int>(i - at);
    const int keep = static_cast<int>(~((1u << skip) - 1u));
    const int up = sse2_uppercase(w) & keep;
    const int xs = _mm_movemask_epi8(_mm_cmpeq_epi8(w, x_splat)) & keep;
    const int mask = sse2_host_stop(w) & keep;
    if (mask == 0) {
      if (up != 0) {
        has_upper = true;
      }
      note_xn_mask(b, at, xs, len, has_xn);
      end = len;
      return true;
    }
    const int hit = trailing_zeroes32(static_cast<uint32_t>(mask));
    const int valid = ((1 << hit) - 1) & keep;
    if ((up & valid) != 0) {
      has_upper = true;
    }
    note_xn_mask(b, at, xs & valid, len, has_xn);
    end = at + static_cast<size_t>(hit);
    return is_host_delimiter(b[end]);
  }
#elif ADA_NEON
  if (len - start >= 16) {
    const uint8x16_t lo_tbl = vld1q_u8(k_host_nibbles.low);
    const uint8x16_t hi_tbl = vld1q_u8(k_host_nibbles.high);
    const uint8x16_t x_splat = vdupq_n_u8('x');
    auto visit = [&](size_t at) noexcept -> bool {
      const uint8x16_t w = vld1q_u8(b + at);
      const uint64_t up = neon_uppercase(w);
      const uint64_t xs = neon_nibble_bits(vceqq_u8(w, x_splat));
      const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);
      if (bits == 0) {
        if (up != 0) {
          has_upper = true;
        }
        note_xn_neon(b, at, xs, len, has_xn);
        return false;
      }
      const size_t hit = static_cast<size_t>(trailing_zeroes64(bits)) >> 2;
      const uint64_t valid = (hit == 0) ? 0 : (uint64_t{1} << (hit * 4)) - 1;
      if ((up & valid) != 0) {
        has_upper = true;
      }
      note_xn_neon(b, at, xs & valid, len, has_xn);
      end = at + hit;
      return true;
    };
    for (; i + 32 <= len; i += 32) {
      if (visit(i) || visit(i + 16)) {
        return is_host_delimiter(b[end]);
      }
    }
    for (; i + 16 <= len; i += 16) {
      if (visit(i)) {
        return is_host_delimiter(b[end]);
      }
    }
    if (i > start && i < len) {
      if (visit(len - 16) && end >= i) {
        return is_host_delimiter(b[end]);
      }
      end = len;
      return true;
    }
  } else if (len >= 16 && start < len) {
    const size_t at = len - 16;
    const uint8x16_t w = vld1q_u8(b + at);
    const size_t skip = start - at;
    const uint64_t keep = (skip >= 16) ? 0 : ~((uint64_t{1} << (skip * 4)) - 1);
    const uint64_t up = neon_uppercase(w) & keep;
    const uint64_t xs = neon_nibble_bits(vceqq_u8(w, vdupq_n_u8('x'))) & keep;
    const uint64_t bits = neon_table_stop(w, vld1q_u8(k_host_nibbles.low),
                                          vld1q_u8(k_host_nibbles.high)) &
                          keep;
    if (bits == 0) {
      if (up != 0) {
        has_upper = true;
      }
      note_xn_neon(b, at, xs, len, has_xn);
      end = len;
      return true;
    }
    const size_t hit = static_cast<size_t>(trailing_zeroes64(bits)) >> 2;
    const uint64_t valid = (hit == 0) ? 0 : (uint64_t{1} << (hit * 4)) - 1;
    if ((up & valid) != 0) {
      has_upper = true;
    }
    note_xn_neon(b, at, xs & valid, len, has_xn);
    end = at + hit;
    return is_host_delimiter(b[end]);
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
      end = i;
      return false;
    }
    if (c >= 'A' && c <= 'Z') {
      has_upper = true;
    } else if (c == 'x') {
      note_xn_prefix(b, i, len, has_xn);
    }
  }
  end = len;
  return true;
}

ada_really_inline void note_possible_segment_prefix(const uint8_t* b,
                                                    size_t pos,
                                                    size_t run_start,
                                                    bool& flag) noexcept {
  // pos==0 and pos!=run_start is an overlapping window that starts at the
  // first input byte; do not read b[-1].
  if (pos == run_start || (pos != 0 && b[pos - 1] == '/')) {
    flag = true;
  }
}

ada_really_inline void note_scalar_path_byte(const uint8_t* b, size_t pos,
                                             size_t run_start,
                                             bool& maybe_dot_segment,
                                             bool& saw_percent) noexcept {
  if (b[pos] == '.') {
    note_possible_segment_prefix(b, pos, run_start, maybe_dot_segment);
  } else if (b[pos] == '%') {
    saw_percent = true;
  }
}

#if ADA_PARSER_SSSE3 || ADA_SSE2
// valid_mask selects bytes in this 16-byte window that belong to the path
// (bits after a stop are cleared). '.' starts a possible dot-segment when it
// is the first path byte or immediately follows '/'. A raw '%' anywhere is
// recorded so the caller can skip the %2e walk on the common percent-free
// path without a second memchr.
ada_really_inline void note_dots_in_window(const uint8_t* b, size_t i,
                                           size_t run_start, __m128i w,
                                           int valid_mask,
                                           bool& maybe_dot_segment,
                                           bool& saw_percent) noexcept {
  if (valid_mask == 0) {
    return;
  }
  if (!saw_percent &&
      (_mm_movemask_epi8(_mm_cmpeq_epi8(w, _mm_set1_epi8('%'))) & valid_mask) !=
          0) {
    saw_percent = true;
  }
  if (maybe_dot_segment) {
    return;
  }
  const int dots =
      _mm_movemask_epi8(_mm_cmpeq_epi8(w, _mm_set1_epi8('.'))) & valid_mask;
  if (dots == 0) {
    return;
  }
  const int slashes =
      _mm_movemask_epi8(_mm_cmpeq_epi8(w, _mm_set1_epi8('/'))) & valid_mask;
  const bool leading_prefix = i == run_start || (i != 0 && b[i - 1] == '/');
  // Overlapping last-16 windows that start before the path must mark the
  // first path byte as a segment start separately (see scan_path_run).
  // Doing that here taxes every dotted aligned window.
  if (((dots & 1) != 0 && leading_prefix) || (dots & (slashes << 1)) != 0) {
    maybe_dot_segment = true;
  }
}
#endif

#if ADA_NEON
// Each NEON match nibble occupies 4 bits, so a marker immediately after '/'
// is (slashes << 4) rather than (slashes << 1).
ada_really_inline void note_dots_in_window_neon(const uint8_t* b, size_t i,
                                                size_t run_start, uint8x16_t w,
                                                uint64_t valid_bits,
                                                bool& maybe_dot_segment,
                                                bool& saw_percent) noexcept {
  if (valid_bits == 0) {
    return;
  }
  if (!saw_percent &&
      (neon_nibble_bits(vceqq_u8(w, vdupq_n_u8('%'))) & valid_bits) != 0) {
    saw_percent = true;
  }
  if (maybe_dot_segment) {
    return;
  }
  const uint64_t dots =
      neon_nibble_bits(vceqq_u8(w, vdupq_n_u8('.'))) & valid_bits;
  if (dots == 0) {
    return;
  }
  const uint64_t slashes =
      neon_nibble_bits(vceqq_u8(w, vdupq_n_u8('/'))) & valid_bits;
  const bool leading_prefix = i == run_start || (i != 0 && b[i - 1] == '/');
  if (((dots & 0xF) != 0 && leading_prefix) || (dots & (slashes << 4)) != 0) {
    maybe_dot_segment = true;
  }
}
#endif

// Advance i to the first path-class 1 or 2 character (or len).
ADA_PARSER_SIMD void scan_path_run(const uint8_t* b, size_t& i, size_t len,
                                   bool& maybe_dot_segment,
                                   bool& saw_percent) noexcept {
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
                            maybe_dot_segment, saw_percent);
        i += static_cast<size_t>(hit_bit);
        return;
      }
      note_dots_in_window(b, i, run_start, w0, 0xFFFF, maybe_dot_segment,
                          saw_percent);
      const __m128i w1 =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i + 16));
      const int m1 = ssse3_nibble_mask(w1, lo_tbl, hi_tbl);
      if (m1 != 0) {
        const int hit_bit = trailing_zeroes32(static_cast<uint32_t>(m1));
        note_dots_in_window(b, i + 16, run_start, w1, (1 << hit_bit) - 1,
                            maybe_dot_segment, saw_percent);
        i += 16 + static_cast<size_t>(hit_bit);
        return;
      }
      note_dots_in_window(b, i + 16, run_start, w1, 0xFFFF, maybe_dot_segment,
                          saw_percent);
    }
    for (; i + 16 <= len; i += 16) {
      const __m128i w =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
      const int mask = ssse3_nibble_mask(w, lo_tbl, hi_tbl);
      if (mask != 0) {
        const int hit_bit = trailing_zeroes32(static_cast<uint32_t>(mask));
        note_dots_in_window(b, i, run_start, w, (1 << hit_bit) - 1,
                            maybe_dot_segment, saw_percent);
        i += static_cast<size_t>(hit_bit);
        return;
      }
      note_dots_in_window(b, i, run_start, w, 0xFFFF, maybe_dot_segment,
                          saw_percent);
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
            note_scalar_path_byte(b, j, run_start, maybe_dot_segment,
                                  saw_percent);
          }
          i = hit;
          return;
        }
      }
      for (size_t j = i; j < len; ++j) {
        note_scalar_path_byte(b, j, run_start, maybe_dot_segment, saw_percent);
      }
      i = len;
      return;
    }
  } else if (len >= 16 && i < len) {
    // The path delimiter sits before run_start, so it is outside valid_mask.
    // Note the first path byte as a segment start (https://host/./a).
    note_scalar_path_byte(b, i, run_start, maybe_dot_segment, saw_percent);
    const size_t at = len - 16;
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at));
    const int skip = static_cast<int>(i - at);
    const int keep = static_cast<int>(~((1u << skip) - 1u));
    const int mask = ssse3_nibble_mask(w, nibble_load(k_path_nibbles.low),
                                       nibble_load(k_path_nibbles.high)) &
                     keep;
    const int hit =
        (mask == 0) ? 16 : trailing_zeroes32(static_cast<uint32_t>(mask));
    const int valid = (hit == 16) ? keep : (((1 << hit) - 1) & keep);
    note_dots_in_window(b, at, run_start, w, valid, maybe_dot_segment,
                        saw_percent);
    i = (hit == 16) ? len : at + static_cast<size_t>(hit);
    return;
  }
#elif ADA_SSE2
  for (; i + 16 <= len; i += 16) {
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
    const int mask = sse2_path_stop(w);
    if (mask != 0) {
      const int hit_bit = trailing_zeroes32(static_cast<uint32_t>(mask));
      note_dots_in_window(b, i, run_start, w, (1 << hit_bit) - 1,
                          maybe_dot_segment, saw_percent);
      i += static_cast<size_t>(hit_bit);
      return;
    }
    note_dots_in_window(b, i, run_start, w, 0xFFFF, maybe_dot_segment,
                        saw_percent);
  }
  if (len >= 16 && i < len) {
    note_scalar_path_byte(b, i, run_start, maybe_dot_segment, saw_percent);
    const size_t at = len - 16;
    const __m128i w = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at));
    const int skip = static_cast<int>(i - at);
    const int keep = static_cast<int>(~((1u << skip) - 1u));
    const int mask = sse2_path_stop(w) & keep;
    const int hit =
        (mask == 0) ? 16 : trailing_zeroes32(static_cast<uint32_t>(mask));
    const int valid = (hit == 16) ? keep : (((1 << hit) - 1) & keep);
    note_dots_in_window(b, at, run_start, w, valid, maybe_dot_segment,
                        saw_percent);
    i = (hit == 16) ? len : at + static_cast<size_t>(hit);
    return;
  }
#elif ADA_NEON
  if (i + 16 <= len) {
    const uint8x16_t lo_tbl = vld1q_u8(k_path_nibbles.low);
    const uint8x16_t hi_tbl = vld1q_u8(k_path_nibbles.high);
    for (; i + 32 <= len; i += 32) {
      const uint8x16_t w0 = vld1q_u8(b + i);
      const uint64_t bits0 = neon_table_stop(w0, lo_tbl, hi_tbl);
      if (bits0 != 0) {
        const size_t hit_off =
            static_cast<size_t>(trailing_zeroes64(bits0)) >> 2;
        const uint64_t valid =
            (hit_off == 0) ? 0 : (uint64_t{1} << (hit_off * 4)) - 1;
        note_dots_in_window_neon(b, i, run_start, w0, valid, maybe_dot_segment,
                                 saw_percent);
        i += hit_off;
        return;
      }
      note_dots_in_window_neon(b, i, run_start, w0, ~uint64_t{0},
                               maybe_dot_segment, saw_percent);
      const uint8x16_t w1 = vld1q_u8(b + i + 16);
      const uint64_t bits1 = neon_table_stop(w1, lo_tbl, hi_tbl);
      if (bits1 != 0) {
        const size_t hit_off =
            static_cast<size_t>(trailing_zeroes64(bits1)) >> 2;
        const uint64_t valid =
            (hit_off == 0) ? 0 : (uint64_t{1} << (hit_off * 4)) - 1;
        note_dots_in_window_neon(b, i + 16, run_start, w1, valid,
                                 maybe_dot_segment, saw_percent);
        i += 16 + hit_off;
        return;
      }
      note_dots_in_window_neon(b, i + 16, run_start, w1, ~uint64_t{0},
                               maybe_dot_segment, saw_percent);
    }
    for (; i + 16 <= len; i += 16) {
      const uint8x16_t w = vld1q_u8(b + i);
      const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);
      if (bits != 0) {
        const size_t hit_off =
            static_cast<size_t>(trailing_zeroes64(bits)) >> 2;
        const uint64_t valid =
            (hit_off == 0) ? 0 : (uint64_t{1} << (hit_off * 4)) - 1;
        note_dots_in_window_neon(b, i, run_start, w, valid, maybe_dot_segment,
                                 saw_percent);
        i += hit_off;
        return;
      }
      note_dots_in_window_neon(b, i, run_start, w, ~uint64_t{0},
                               maybe_dot_segment, saw_percent);
    }
    if (i > run_start && i < len) {
      const uint8x16_t w = vld1q_u8(b + len - 16);
      const uint64_t bits = neon_table_stop(w, lo_tbl, hi_tbl);
      if (bits != 0) {
        const size_t hit =
            len - 16 + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2);
        if (hit >= i) {
          for (size_t j = i; j < hit; ++j) {
            note_scalar_path_byte(b, j, run_start, maybe_dot_segment,
                                  saw_percent);
          }
          i = hit;
          return;
        }
      }
      for (size_t j = i; j < len; ++j) {
        note_scalar_path_byte(b, j, run_start, maybe_dot_segment, saw_percent);
      }
      i = len;
      return;
    }
  } else if (len >= 16 && i < len) {
    note_scalar_path_byte(b, i, run_start, maybe_dot_segment, saw_percent);
    const size_t at = len - 16;
    const uint8x16_t w = vld1q_u8(b + at);
    const size_t skip = i - at;
    const uint64_t keep = (skip >= 16) ? 0 : ~((uint64_t{1} << (skip * 4)) - 1);
    const uint64_t bits = neon_table_stop(w, vld1q_u8(k_path_nibbles.low),
                                          vld1q_u8(k_path_nibbles.high)) &
                          keep;
    uint64_t valid = keep;
    if (bits != 0) {
      const size_t hit_off = static_cast<size_t>(trailing_zeroes64(bits)) >> 2;
      valid = (hit_off == 0) ? 0 : (uint64_t{1} << (hit_off * 4)) - 1;
      i = at + hit_off;
    } else {
      i = len;
    }
    note_dots_in_window_neon(b, at, run_start, w, valid, maybe_dot_segment,
                             saw_percent);
    return;
  }
#endif
  for (; i < len; ++i) {
    const uint8_t c = b[i];
    const uint8_t cls = k_path[c];
    if (cls != 0) {
      return;
    }
    note_scalar_path_byte(b, i, run_start, maybe_dot_segment, saw_percent);
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
    } else if (len >= 16 && i < len) {                                       \
      const size_t at = len - 16;                                            \
      const int skip = static_cast<int>(i - at);                             \
      const int keep = static_cast<int>(~((1u << skip) - 1u));               \
      const __m128i w =                                                      \
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at));         \
      const int mask = ssse3_nibble_mask(w, nibble_load((nibbles).low),      \
                                         nibble_load((nibbles).high)) &      \
                       keep;                                                 \
      i = (mask == 0) ? len                                                  \
                      : at + static_cast<size_t>(trailing_zeroes32(          \
                                 static_cast<uint32_t>(mask)));              \
      return;                                                                \
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
    } else if (len >= 16 && i < len) {                                        \
      const size_t at = len - 16;                                             \
      const size_t skip = i - at;                                             \
      const uint64_t keep =                                                   \
          (skip >= 16) ? 0 : ~((uint64_t{1} << (skip * 4)) - 1);              \
      const uint64_t bits =                                                   \
          neon_table_stop(vld1q_u8(b + at), vld1q_u8((nibbles).low),          \
                          vld1q_u8((nibbles).high)) &                         \
          keep;                                                               \
      i = (bits == 0)                                                         \
              ? len                                                           \
              : at + (static_cast<size_t>(trailing_zeroes64(bits)) >> 2);     \
      return;                                                                 \
    }                                                                         \
    for (; i < len; ++i) {                                                    \
      if ((cls)[b[i]] != 0) {                                                 \
        return;                                                               \
      }                                                                       \
    }                                                                         \
  } while (0)
#elif ADA_SSE2
#define ADA_SCAN_STOP_RUN(nibbles, cls, sse2_stop)                   \
  do {                                                               \
    for (; i + 16 <= len; i += 16) {                                 \
      const __m128i w =                                              \
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));  \
      const int mask = sse2_stop(w);                                 \
      if (mask != 0) {                                               \
        i += static_cast<size_t>(                                    \
            trailing_zeroes32(static_cast<uint32_t>(mask)));         \
        return;                                                      \
      }                                                              \
    }                                                                \
    if (len >= 16 && i < len) {                                      \
      const size_t at = len - 16;                                    \
      const int skip = static_cast<int>(i - at);                     \
      const int keep = static_cast<int>(~((1u << skip) - 1u));       \
      const __m128i w =                                              \
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + at)); \
      const int mask = sse2_stop(w) & keep;                          \
      i = (mask == 0) ? len                                          \
                      : at + static_cast<size_t>(trailing_zeroes32(  \
                                 static_cast<uint32_t>(mask)));      \
      return;                                                        \
    }                                                                \
    for (; i < len; ++i) {                                           \
      if ((cls)[b[i]] != 0) {                                        \
        return;                                                      \
      }                                                              \
    }                                                                \
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

// Bodies live here so the finish TU does not depend on always_inline
// unicode.cpp helpers (no standalone symbol).
ada_really_inline constexpr bool is_single_dot_seg(
    std::string_view input) noexcept {
  return input == "." || input == "%2e" || input == "%2E";
}

ada_really_inline bool is_double_dot_seg(std::string_view input) noexcept {
  return input == ".." || input == ".%2e" || input == ".%2E" ||
         input == "%2e." || input == "%2E." || input == "%2e%2e" ||
         input == "%2E%2E" || input == "%2E%2e" || input == "%2e%2E";
}

// Local copy so the fast-path TU does not depend on always_inline
// unicode.cpp (no standalone symbol).
ada_really_inline bool ascii_to_lower(char* input, size_t length) noexcept {
  constexpr uint64_t broadcast_80 = 0x8080808080808080ull;
  constexpr uint64_t broadcast_Ap = 0x101010101010101ull * (128 - 'A');
  constexpr uint64_t broadcast_Zp = 0x101010101010101ull * (128 - 'Z' - 1);
  uint64_t non_ascii = 0;
  size_t i = 0;
  for (; i + 7 < length; i += 8) {
    uint64_t word{};
    std::memcpy(&word, input + i, sizeof(word));
    non_ascii |= (word & broadcast_80);
    word ^=
        (((word + broadcast_Ap) ^ (word + broadcast_Zp)) & broadcast_80) >> 2;
    std::memcpy(input + i, &word, sizeof(word));
  }
  if (i < length) {
    uint64_t word{};
    std::memcpy(&word, input + i, length - i);
    non_ascii |= (word & broadcast_80);
    word ^=
        (((word + broadcast_Ap) ^ (word + broadcast_Zp)) & broadcast_80) >> 2;
    std::memcpy(input + i, &word, length - i);
  }
  return non_ascii == 0;
}

// True when a path segment is "." / ".." or a percent-encoded form
// ("%2e", "%2e%2e", ".%2e", "%2e.") that the path helpers would collapse.
bool path_has_percent_encoded_dot_segment(std::string_view path) noexcept {
  size_t i = (!path.empty() && path[0] == '/') ? 1 : 0;
  while (i <= path.size()) {
    const size_t end = path.find('/', i);
    const size_t seg_end = (end == std::string_view::npos) ? path.size() : end;
    const std::string_view seg(path.data() + i, seg_end - i);
    if (is_single_dot_seg(seg) || is_double_dot_seg(seg)) {
      return true;
    }
    if (end == std::string_view::npos) {
      break;
    }
    i = end + 1;
  }
  return false;
}

ada_really_inline bool path_body_needs_normalization(
    std::string_view path_body, bool maybe_dot_segment,
    bool maybe_percent_dot) noexcept {
  if (maybe_dot_segment && path_has_dot_segment(path_body)) {
    return true;
  }
  // ".%2e" starts with '.' so maybe_dot is set, but path_has_dot_segment
  // does not treat percent-encoded dots. Walk segments only when a
  // '%' was seen during the path scan.
  if (maybe_percent_dot) {
    return path_has_percent_encoded_dot_segment(path_body);
  }
  return false;
}

ada_really_inline bool simple_path_is_canonical(std::string_view path_body,
                                                bool maybe_dot_segment,
                                                bool saw_percent) noexcept {
  if (!maybe_dot_segment && !saw_percent) {
    return true;
  }
  return !path_body_needs_normalization(path_body, maybe_dot_segment,
                                        saw_percent);
}

// http/ws/wss/ftp and URLs shorter than 8 bytes are ~4% of the dataset.
// Keep those compares out of the https:// I-cache.
ada_never_inline bool match_non_https_special_scheme(
    uint64_t first8, size_t len, const uint8_t* b, size_t& pos,
    ada::scheme::type& scheme_type, uint32_t& protocol_end) noexcept {
  // first8 == 0 means the caller did not load one (short URL or big-endian).
  if (len >= 8 && first8 != 0) {
    if ((first8 & 0x00ffffffffffffffull) == 0x002f2f3a70747468ull) {
      pos = 7;
      scheme_type = ada::scheme::type::HTTP;
      protocol_end = 5;
      return true;
    }
    if ((first8 & 0x0000ffffffffffffull) == 0x00002f2f3a737377ull) {
      pos = 6;
      scheme_type = ada::scheme::type::WSS;
      protocol_end = 4;
      return true;
    }
    if ((first8 & 0x0000ffffffffffffull) == 0x00002f2f3a707466ull) {
      pos = 6;
      scheme_type = ada::scheme::type::FTP;
      protocol_end = 4;
      return true;
    }
    if ((first8 & 0x000000ffffffffffull) == 0x0000002f2f3a7377ull) {
      pos = 5;
      scheme_type = ada::scheme::type::WS;
      protocol_end = 3;
      return true;
    }
    return false;
  }
  if (len < 6) {
    return false;
  }
  if (b[0] == 'w' && b[1] == 's') {
    if (b[2] == ':' && b[3] == '/' && b[4] == '/') {
      pos = 5;
      scheme_type = ada::scheme::type::WS;
      protocol_end = 3;
      return true;
    }
    if (b[2] == 's' && b[3] == ':' && b[4] == '/' && b[5] == '/') {
      pos = 6;
      scheme_type = ada::scheme::type::WSS;
      protocol_end = 4;
      return true;
    }
    return false;
  }
  if (b[0] == 'f' && b[1] == 't' && b[2] == 'p' && b[3] == ':' && b[4] == '/' &&
      b[5] == '/') {
    pos = 6;
    scheme_type = ada::scheme::type::FTP;
    protocol_end = 4;
    return true;
  }
  if (len >= 7 && b[0] == 'h' && b[1] == 't' && b[2] == 't' && b[3] == 'p' &&
      b[4] == ':' && b[5] == '/' && b[6] == '/') {
    pos = 7;
    scheme_type = ada::scheme::type::HTTP;
    protocol_end = 5;
    return true;
  }
  return false;
}

// Uppercase hosts and numeric last labels are rare on the dataset. Keep
// their buffers and IPv4 parser out of the hot I-cache.
ada_never_inline bool reject_uppercase_plain_host(const char* host,
                                                  size_t host_len) noexcept {
  char host_buf[256];
  std::memcpy(host_buf, host, host_len);
  ascii_to_lower(host_buf, host_len);
  const std::string_view hv(host_buf, host_len);
  if (ada::checkers::last_label_may_be_a_number(hv)) {
    return true;
  }
  static constexpr std::string_view xn{"xn-", 3};
  return hv.find(xn) != std::string_view::npos;
}

// Hex/octal/compressed IPv4. Decimal-with-trailing-dot is handled by
// try_parse_ipv4_fast; this runs only after that miss.
ada_cold uint64_t try_parse_ipv4_any(std::string_view input) noexcept {
  if (input.empty()) {
    return checkers::ipv4_fast_fail;
  }
  if (input.back() == '.') {
    input.remove_suffix(1);
    if (input.empty()) {
      return checkers::ipv4_fast_fail;
    }
  }
  const char* p = input.data();
  const char* end = p + input.size();
  uint64_t ipv4 = 0;
  int digit_count = 0;
  for (; digit_count < 4 && p < end; ++digit_count) {
    uint64_t segment = 0;
    bool pure = false;
    if (!detail::parse_ipv4_number(p, end, segment, pure)) {
      return checkers::ipv4_fast_fail;
    }
    if (p >= end) {
      const unsigned shift = static_cast<unsigned>(32 - digit_count * 8);
      if (segment >= (uint64_t{1} << shift)) {
        return checkers::ipv4_fast_fail;
      }
      return (ipv4 << shift) | segment;
    }
    if (segment > 255 || *p != '.') {
      return checkers::ipv4_fast_fail;
    }
    ipv4 = (ipv4 << 8) | segment;
    ++p;
  }
  if (digit_count != 4 || p != end) {
    return checkers::ipv4_fast_fail;
  }
  return ipv4;
}

#if !defined(ADA_SKIP_PARSER_FASTPATH)
ada_really_inline char* write_u8_dec(char* p, uint8_t v) noexcept {
  if (v < 10) {
    *p++ = static_cast<char>('0' + v);
  } else if (v < 100) {
    *p++ = static_cast<char>('0' + v / 10);
    *p++ = static_cast<char>('0' + v % 10);
  } else {
    *p++ = static_cast<char>('0' + v / 100);
    v = static_cast<uint8_t>(v % 100);
    *p++ = static_cast<char>('0' + v / 10);
    *p++ = static_cast<char>('0' + v % 10);
  }
  return p;
}

ada_cold size_t write_ipv4_dotted(char* buf, uint32_t addr) noexcept {
  char* p = buf;
  p = write_u8_dec(p, static_cast<uint8_t>(addr >> 24));
  *p++ = '.';
  p = write_u8_dec(p, static_cast<uint8_t>(addr >> 16));
  *p++ = '.';
  p = write_u8_dec(p, static_cast<uint8_t>(addr >> 8));
  *p++ = '.';
  p = write_u8_dec(p, static_cast<uint8_t>(addr));
  return static_cast<size_t>(p - buf);
}
#endif  // ADA_SKIP_PARSER_FASTPATH

// true => leave the simple-absolute path. false => stay; may set is_ipv4
// and ask the caller to rewrite the host to dotted-decimal.
ada_never_inline ada_cold bool reject_or_classify_numeric_last_label(
    std::string_view hv, bool& is_ipv4, uint64_t& ipv4_addr,
    bool& rewrite_host) noexcept {
  if (!ada::checkers::last_label_may_be_a_number(hv)) {
    return false;
  }
  const uint64_t fast = checkers::try_parse_ipv4_fast(hv);
  if (fast < checkers::ipv4_fast_fail) {
    is_ipv4 = true;
    ipv4_addr = fast;
    rewrite_host = hv.back() == '.';
    return false;
  }
  const uint64_t any = try_parse_ipv4_any(hv);
  if (any < checkers::ipv4_fast_fail) {
    is_ipv4 = true;
    ipv4_addr = any;
    rewrite_host = true;
    return false;
  }
  return true;
}

// Visible in this TU so finish helpers can run outside the unity build.
// unicode::has_tabs_or_newline / is_c0_control_or_space are always_inline
// in unicode.cpp and have no standalone symbol.
ada_really_inline bool view_has_tab_or_newline(
    std::string_view input) noexcept {
  for (const char c : input) {
    if (c == '\t' || c == '\n' || c == '\r') {
      return true;
    }
  }
  return false;
}

ada_really_inline bool trailing_c0_or_tab_newline(
    std::string_view input) noexcept {
  return static_cast<unsigned char>(input.back()) <= ' ' ||
         view_has_tab_or_newline(input);
}

}  // namespace
#endif  // scanners (fast path or finish)

#ifndef ADA_SKIP_PARSER_FINISH
// Percent-encoding / dot-segment handoff. Kept out of the already-canonical
// fast-path I-cache: this is the uncommon rest_simple=false tail.
template <class result_type>
ada_never_inline ada_cold void finish_simple_absolute_handoff(
    std::string_view input, result_type& out, size_t host_start,
    size_t host_end, size_t host_len, uint32_t protocol_end, bool has_upper,
    bool has_path, size_t path_start, size_t path_end, size_t query_start,
    size_t hash_start) {
  constexpr bool is_aggregator =
      std::is_same_v<result_type, ada::url_aggregator>;
  const size_t len = input.size();
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
      ascii_to_lower(out.buffer.data() + host_start, host_len);
    }
    set_plain_host_components(out.components, protocol_end,
                              static_cast<uint32_t>(host_end),
                              static_cast<uint32_t>(host_end),
                              url_components::omitted, url_components::omitted);
    out.parse_path_outlined(path_view);
    apply_query_and_hash();
  } else {
    out.host.emplace(input.data() + host_start, host_len);
    if (has_upper) {
      ascii_to_lower(out.host->data(), host_len);
    }
    out.parse_path_outlined(path_view);
    apply_query_and_hash();
  }
}

template <class result_type>
ADA_PARSER_COLD bool finish_simple_absolute_with_port(
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
  bool saw_percent = false;
  bool rest_simple = true;

  if (i < len) {
    if (b[i] == '/') {
      has_path = true;
      path_start = i;
      ++i;
      scan_path_run(b, i, len, maybe_dot_segment, saw_percent);
      if (i < len) {
        if (b[i] == '?') {
          path_end = i;
          query_start = i;
          ++i;
          goto scan_query;
        }
        if (b[i] == '#') {
          path_end = i;
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
    } else if (b[i] == '?') {
      query_start = i;
      ++i;
      goto scan_query;
    } else {
      hash_start = i;
      ++i;
      goto scan_hash;
    }
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
  if (rest_simple && has_path && (maybe_dot_segment || saw_percent)) {
    const std::string_view path_body(input.data() + path_start,
                                     path_end - path_start);
    if (!simple_path_is_canonical(path_body, maybe_dot_segment, saw_percent)) {
      rest_simple = false;
    }
  }

  // The slow path removes ASCII tab/newline anywhere in the input and trims a
  // trailing C0 control or space; this fast path does neither. A query or
  // fragment reaching the helpers below would keep those bytes percent-encoded
  // ("?a\nb" -> "?a%0Ab", "#f " -> "#f%20") instead of stripped, so hand such
  // inputs back to the slow path.
  if (!rest_simple && trailing_c0_or_tab_newline(input)) {
    return false;
  }

  out.type = scheme_type;

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
        ascii_to_lower(out.buffer.data() + host_start, host_len);
      }
      set_plain_host_components(
          out.components, protocol_end, static_cast<uint32_t>(host_end),
          static_cast<uint32_t>(out.buffer.size()), url_components::omitted,
          url_components::omitted, parsed_port);
      out.parse_path_outlined(path_view);
      apply_query_and_hash();
    } else {
      out.host.emplace(input.data() + host_start, host_len);
      if (has_upper) {
        ascii_to_lower(out.host->data(), host_len);
      }
      if (parsed_port != url_components::omitted) {
        out.port = static_cast<uint16_t>(parsed_port);
      }
      out.parse_path_outlined(path_view);
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
      ascii_to_lower(out.buffer.data() + host_start, host_len);
    }
    const uint32_t pathname_start =
        static_cast<uint32_t>(host_end) + port_bytes;
    const int32_t tail_delta = static_cast<int32_t>(pathname_start) +
                               (insert_slash ? 1 : 0) -
                               static_cast<int32_t>(authority_end);
    set_plain_host_components(
        out.components, protocol_end, static_cast<uint32_t>(host_end),
        pathname_start,
        (query_start != std::string_view::npos)
            ? static_cast<uint32_t>(static_cast<int32_t>(query_start) +
                                    tail_delta)
            : url_components::omitted,
        (hash_start != std::string_view::npos)
            ? static_cast<uint32_t>(static_cast<int32_t>(hash_start) +
                                    tail_delta)
            : url_components::omitted,
        parsed_port);
  } else {
    out.host.emplace(input.data() + host_start, host_len);
    if (has_upper) {
      ascii_to_lower(out.host->data(), host_len);
    }
    if (parsed_port != url_components::omitted) {
      out.port = static_cast<uint16_t>(parsed_port);
    }
    if (insert_slash) {
      out.path.assign(1, '/');
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

// Host is already canonical (IPv4 dotted-decimal or IPv6 with brackets) and
// is not a slice of `input`. Port / path / query / hash still come from input
// after `host_end`.
template <class result_type>
ADA_PARSER_COLD bool finish_simple_absolute_literal_host(
    std::string_view input, result_type& out, ada::scheme::type scheme_type,
    uint32_t protocol_end, size_t host_start, size_t host_end,
    std::string_view host, url_host_type parsed_host_type) {
  constexpr bool is_ada_url = std::is_same_v<result_type, ada::url>;
  constexpr bool is_aggregator =
      std::is_same_v<result_type, ada::url_aggregator>;
  static_assert(is_ada_url || is_aggregator);

  const size_t len = input.size();
  const auto* b = reinterpret_cast<const uint8_t*>(input.data());
  size_t p = host_end;
  uint32_t parsed_port = url_components::omitted;
  if (p < len && b[p] == ':') {
    ++p;
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
    const uint16_t default_port = ada::scheme::get_special_port(scheme_type);
    if (any_digit && port_value != default_port) {
      parsed_port = port_value;
    }
  }
  const size_t authority_end = p;

  size_t i = authority_end;
  size_t path_start = host_end;
  size_t path_end = host_end;
  size_t query_start = std::string_view::npos;
  size_t hash_start = std::string_view::npos;
  bool has_path = false;
  bool maybe_dot_segment = false;
  bool saw_percent = false;
  bool rest_simple = true;

  if (i < len) {
    if (b[i] == '/') {
      has_path = true;
      path_start = i;
      ++i;
      scan_path_run(b, i, len, maybe_dot_segment, saw_percent);
      if (i < len) {
        if (b[i] == '?') {
          path_end = i;
          query_start = i;
          ++i;
          goto scan_query;
        }
        if (b[i] == '#') {
          path_end = i;
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
    } else if (b[i] == '?') {
      query_start = i;
      ++i;
      goto scan_query;
    } else {
      hash_start = i;
      ++i;
      goto scan_hash;
    }
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
  if (rest_simple && has_path && (maybe_dot_segment || saw_percent)) {
    const std::string_view path_body(input.data() + path_start,
                                     path_end - path_start);
    if (!simple_path_is_canonical(path_body, maybe_dot_segment, saw_percent)) {
      rest_simple = false;
    }
  }

  if (!rest_simple && trailing_c0_or_tab_newline(input)) {
    return false;
  }

  out.type = scheme_type;
  out.host_type = parsed_host_type;

  const uint32_t port_bytes = (parsed_port != url_components::omitted)
                                  ? (1 + port_decimal_digit_count(parsed_port))
                                  : 0;
  const uint32_t new_host_end = static_cast<uint32_t>(host_start + host.size());

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

  if (!rest_simple) {
    const std::string_view path_view =
        has_path
            ? std::string_view(input.data() + path_start, path_end - path_start)
            : std::string_view{};
    if constexpr (is_aggregator) {
      out.buffer.clear();
      out.buffer.reserve(host_start + host.size() + port_bytes +
                         (has_path ? path_end - path_start : 1) + 8);
      out.buffer.append(input.substr(0, host_start));
      out.buffer.append(host);
      if (parsed_port != url_components::omitted) {
        append_canonical_port(out.buffer, parsed_port);
      }
      set_plain_host_components(out.components, protocol_end, new_host_end,
                                static_cast<uint32_t>(out.buffer.size()),
                                url_components::omitted,
                                url_components::omitted, parsed_port);
      out.parse_path_outlined(path_view);
      apply_query_and_hash();
    } else {
      out.host.emplace(host);
      if (parsed_port != url_components::omitted) {
        out.port = static_cast<uint16_t>(parsed_port);
      }
      out.parse_path_outlined(path_view);
      apply_query_and_hash();
    }
    return true;
  }

  const bool insert_slash = !has_path;
  if constexpr (is_aggregator) {
    const size_t out_len = host_start + host.size() + port_bytes +
                           (insert_slash ? 1 : 0) + (len - authority_end);
    out.buffer.clear();
    out.buffer.reserve(out_len);
    out.buffer.append(input.substr(0, host_start));
    out.buffer.append(host);
    if (parsed_port != url_components::omitted) {
      append_canonical_port(out.buffer, parsed_port);
    }
    if (insert_slash) {
      out.buffer.push_back('/');
    }
    if (authority_end < len) {
      out.buffer.append(input.substr(authority_end));
    }
    const uint32_t pathname_start = new_host_end + port_bytes;
    const int32_t tail_delta = static_cast<int32_t>(pathname_start) +
                               (insert_slash ? 1 : 0) -
                               static_cast<int32_t>(authority_end);
    set_plain_host_components(
        out.components, protocol_end, new_host_end, pathname_start,
        (query_start != std::string_view::npos)
            ? static_cast<uint32_t>(static_cast<int32_t>(query_start) +
                                    tail_delta)
            : url_components::omitted,
        (hash_start != std::string_view::npos)
            ? static_cast<uint32_t>(static_cast<int32_t>(hash_start) +
                                    tail_delta)
            : url_components::omitted,
        parsed_port);
  } else {
    out.host.emplace(host);
    if (parsed_port != url_components::omitted) {
      out.port = static_cast<uint16_t>(parsed_port);
    }
    if (insert_slash) {
      out.path.assign(1, '/');
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

// After the host scanner misses on '[', finish a bracket IPv6 host. The
// character after ']' must be a real authority/path delimiter; otherwise
// the state machine rejects (e.g. http://[::1]foo).
template <class result_type>
ADA_PARSER_COLD bool try_finish_simple_ipv6(std::string_view input,
                                            result_type& out,
                                            ada::scheme::type scheme_type,
                                            uint32_t protocol_end,
                                            size_t host_start) {
  const auto* b = reinterpret_cast<const uint8_t*>(input.data());
  const size_t len = input.size();
  size_t close = host_start + 1;
  while (close < len && b[close] != ']') {
    ++close;
  }
  if (close >= len) {
    return false;
  }
  const size_t after = close + 1;
  if (after < len) {
    const uint8_t c = b[after];
    if (c != ':' && c != '/' && c != '?' && c != '#') {
      return false;
    }
  }
  std::array<uint16_t, 8> addr{};
  if (!detail::parse_ipv6_address(
          std::string_view(input.data() + host_start + 1,
                           close - host_start - 1),
          addr)) {
    return false;
  }
  const std::string canon = ada::serializers::ipv6(addr);
  return finish_simple_absolute_literal_host(
      input, out, scheme_type, protocol_end, host_start, after, canon, IPV6);
}

// Already-canonical `user[:password]@host[:port][/path][?query][#hash]`.
// Invoked only after the host scanner misses or a port parse fails, so the
// 99% no-credential path never pays for an '@' check.
template <class result_type>
ADA_PARSER_COLD bool try_finish_simple_userinfo(std::string_view input,
                                                result_type& out,
                                                ada::scheme::type scheme_type,
                                                uint32_t protocol_end,
                                                size_t auth_start) {
  constexpr bool is_ada_url = std::is_same_v<result_type, ada::url>;
  constexpr bool is_aggregator =
      std::is_same_v<result_type, ada::url_aggregator>;
  static_assert(is_ada_url || is_aggregator);

  const auto* b = reinterpret_cast<const uint8_t*>(input.data());
  const size_t len = input.size();
  size_t at = auth_start;
  for (; at < len; ++at) {
    const uint8_t c = b[at];
    if (c == '@') {
      break;
    }
    if (c == '/' || c == '?' || c == '#') {
      return false;
    }
  }
  if (at >= len || b[at] != '@') {
    return false;
  }

  const std::string_view userinfo(input.data() + auth_start, at - auth_start);
  const size_t colon = userinfo.find(':');
  const std::string_view username =
      colon == std::string_view::npos ? userinfo : userinfo.substr(0, colon);
  const std::string_view password = colon == std::string_view::npos
                                        ? std::string_view{}
                                        : userinfo.substr(colon + 1);
  // Empty credentials serialize without '@'. An empty password after ':'
  // drops the colon (`user:@host` -> `user@host`). Leave those to the
  // state machine so href stays canonical.
  if ((username.empty() && password.empty()) ||
      (password.empty() && colon != std::string_view::npos)) {
    return false;
  }
  if (unicode::percent_encode_index(username,
                                    character_sets::USERINFO_PERCENT_ENCODE) !=
          username.size() ||
      unicode::percent_encode_index(password,
                                    character_sets::USERINFO_PERCENT_ENCODE) !=
          password.size()) {
    return false;
  }

  const size_t host_begin = at + 1;
  bool has_upper = false;
  bool has_xn = false;
  size_t host_end = host_begin;
  if (!scan_plain_host(b, host_begin, len, host_end, has_upper, has_xn)) {
    return false;
  }
  const size_t host_len = host_end - host_begin;
  if (host_len - 1 >= 253 || has_xn) {
    return false;
  }
  {
    uint8_t lastc = b[host_end - 1];
    if (lastc == '.' && host_len > 1) {
      lastc = b[host_end - 2];
    }
    if (has_upper) {
      if (reject_uppercase_plain_host(input.data() + host_begin, host_len)) {
        return false;
      }
    } else if (ada::checkers::is_ipv4_number_char(static_cast<char>(lastc)) &&
               ada::checkers::last_label_may_be_a_number(
                   std::string_view(input.data() + host_begin, host_len))) {
      return false;
    }
  }

  size_t p = host_end;
  uint32_t parsed_port = url_components::omitted;
  if (p < len && b[p] == ':') {
    ++p;
    uint32_t port_value = 0;
    bool any_digit = false;
    while (p < len && b[p] >= '0' && b[p] <= '9') {
      any_digit = true;
      port_value = port_value * 10 + static_cast<uint32_t>(b[p] - '0');
      if (port_value > 65535) {
        return false;
      }
      ++p;
    }
    if (p < len && b[p] != '/' && b[p] != '?' && b[p] != '#') {
      return false;
    }
    const uint16_t default_port = ada::scheme::get_special_port(scheme_type);
    if (!any_digit || port_value == default_port) {
      // Empty or default port: href drops the colon. `https://u@h://x`
      // must not keep the extra ':' in the aggregator buffer.
      return false;
    }
    // `:0080` parses as 80 but href writes `:80`. Only finish when the
    // digits are already the canonical decimal form.
    if (p - (host_end + 1) != port_decimal_digit_count(port_value)) {
      return false;
    }
    parsed_port = port_value;
  }
  const size_t authority_end = p;

  size_t i = authority_end;
  size_t path_start = authority_end;
  size_t path_end = authority_end;
  size_t query_start = std::string_view::npos;
  size_t hash_start = std::string_view::npos;
  bool has_path = false;
  bool maybe_dot_segment = false;
  bool saw_percent = false;
  if (i < len && b[i] == '/') {
    has_path = true;
    path_start = i;
    ++i;
    scan_path_run(b, i, len, maybe_dot_segment, saw_percent);
    if (i < len && k_path[b[i]] == 2) {
      return false;
    }
    path_end = i;
  }
  if (i < len && b[i] == '?') {
    query_start = i;
    ++i;
    scan_query_run(b, i, len);
    if (i < len && b[i] != '#') {
      return false;
    }
  }
  if (i < len && b[i] == '#') {
    hash_start = i;
    ++i;
    scan_hash_run(b, i, len);
    if (i < len) {
      return false;
    }
  } else if (i < len) {
    return false;
  }
  if (has_path && (maybe_dot_segment || saw_percent) &&
      !simple_path_is_canonical(
          std::string_view(input.data() + path_start, path_end - path_start),
          maybe_dot_segment, saw_percent)) {
    return false;
  }

  out.type = scheme_type;
  out.host_type = DEFAULT;
  const bool insert_slash = !has_path;
  const uint32_t username_end =
      protocol_end + 2 + static_cast<uint32_t>(username.size());
  const uint32_t at_host_start = static_cast<uint32_t>(at);
  const uint32_t pathname_start =
      static_cast<uint32_t>(insert_slash ? authority_end : path_start);
  const uint32_t tail_delta = insert_slash ? 1 : 0;

  if constexpr (is_aggregator) {
    if (!insert_slash) {
      out.buffer.assign(input);
    } else {
      out.buffer.clear();
      out.buffer.reserve(len + 1);
      out.buffer.append(input.substr(0, authority_end));
      out.buffer.push_back('/');
      if (authority_end < len) {
        out.buffer.append(input.substr(authority_end));
      }
    }
    if (has_upper) {
      ascii_to_lower(out.buffer.data() + host_begin, host_len);
    }
    out.components.protocol_end = protocol_end;
    out.components.username_end = username_end;
    out.components.host_start = at_host_start;
    out.components.host_end = static_cast<uint32_t>(host_end);
    out.components.port = parsed_port;
    out.components.pathname_start = pathname_start;
    out.components.search_start =
        (query_start != std::string_view::npos)
            ? static_cast<uint32_t>(query_start + tail_delta)
            : url_components::omitted;
    out.components.hash_start =
        (hash_start != std::string_view::npos)
            ? static_cast<uint32_t>(hash_start + tail_delta)
            : url_components::omitted;
  } else {
    out.username.assign(username);
    out.password.assign(password);
    out.host.emplace(input.substr(host_begin, host_len));
    if (has_upper) {
      ascii_to_lower(out.host->data(), host_len);
    }
    if (parsed_port != url_components::omitted) {
      out.port = static_cast<uint16_t>(parsed_port);
    }
    if (insert_slash) {
      out.path.assign(1, '/');
    } else {
      out.path.assign(input.substr(path_start, path_end - path_start));
    }
    if (query_start != std::string_view::npos) {
      const size_t q_end =
          (hash_start != std::string_view::npos) ? hash_start : len;
      out.query.emplace(input.substr(query_start + 1, q_end - query_start - 1));
    }
    if (hash_start != std::string_view::npos) {
      out.hash.emplace(input.substr(hash_start + 1, len - hash_start - 1));
    }
  }
  return true;
}

template bool finish_simple_absolute_with_port<url>(std::string_view, url&,
                                                    ada::scheme::type, uint32_t,
                                                    size_t, size_t, size_t,
                                                    bool);
template bool finish_simple_absolute_with_port<url_aggregator>(
    std::string_view, url_aggregator&, ada::scheme::type, uint32_t, size_t,
    size_t, size_t, bool);
template bool finish_simple_absolute_literal_host<url>(std::string_view, url&,
                                                       ada::scheme::type,
                                                       uint32_t, size_t, size_t,
                                                       std::string_view,
                                                       url_host_type);
template bool finish_simple_absolute_literal_host<url_aggregator>(
    std::string_view, url_aggregator&, ada::scheme::type, uint32_t, size_t,
    size_t, std::string_view, url_host_type);
template bool try_finish_simple_userinfo<url>(std::string_view, url&,
                                              ada::scheme::type, uint32_t,
                                              size_t);
template bool try_finish_simple_userinfo<url_aggregator>(std::string_view,
                                                         url_aggregator&,
                                                         ada::scheme::type,
                                                         uint32_t, size_t);
template bool try_finish_simple_ipv6<url>(std::string_view, url&,
                                          ada::scheme::type, uint32_t, size_t);
template bool try_finish_simple_ipv6<url_aggregator>(std::string_view,
                                                     url_aggregator&,
                                                     ada::scheme::type,
                                                     uint32_t, size_t);
template void finish_simple_absolute_handoff<url>(std::string_view, url&,
                                                  size_t, size_t, size_t,
                                                  uint32_t, bool, bool, size_t,
                                                  size_t, size_t, size_t);
template void finish_simple_absolute_handoff<url_aggregator>(
    std::string_view, url_aggregator&, size_t, size_t, size_t, uint32_t, bool,
    bool, size_t, size_t, size_t, size_t);

#endif  // ADA_SKIP_PARSER_FINISH

#ifndef ADA_SKIP_PARSER_FASTPATH
// Fast path for already-canonical special-scheme URLs of the shape
// scheme://host[/path][?query][#fragment]. When the host is a plain domain
// but the rest needs encoding or dot-segment normalization, the host is
// kept and the path/query/hash helpers finish the URL.
template <class result_type>
ADA_PARSER_FASTPATH bool try_parse_simple_absolute(std::string_view input,
                                                   result_type& out) {
  constexpr bool is_ada_url = std::is_same_v<result_type, ada::url>;
  constexpr bool is_aggregator =
      std::is_same_v<result_type, ada::url_aggregator>;
  static_assert(is_ada_url || is_aggregator);

  const size_t len = input.size();
  const auto* b = reinterpret_cast<const uint8_t*>(input.data());

  size_t pos = 0;
  ada::scheme::type scheme_type = ada::scheme::type::NOT_SPECIAL;
  uint32_t protocol_end = 0;
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
    defined(_M_X64) || defined(_M_IX86) || defined(_M_AMD64)
  // One 8-byte load + integer compare is a single cmp/jcc on x86-64.
  // Non-https schemes stay in a never_inline helper (~4% of URLs).
  if (len >= 8) [[likely]] {
    uint64_t first8 = 0;
    std::memcpy(&first8, b, 8);
    if (first8 == 0x2f2f3a7370747468ull) {  // "https://"
      pos = 8;
      scheme_type = ada::scheme::type::HTTPS;
      protocol_end = 6;
    } else if (!match_non_https_special_scheme(first8, len, b, pos, scheme_type,
                                               protocol_end)) {
      return false;
    }
  } else if (!match_non_https_special_scheme(0, len, b, pos, scheme_type,
                                             protocol_end)) {
    return false;
  }
#else
  // Big-endian / uncommon arches: byte-wise special-scheme match.
  if (len >= 8 && b[0] == 'h' && b[1] == 't' && b[2] == 't' && b[3] == 'p' &&
      b[4] == 's' && b[5] == ':' && b[6] == '/' && b[7] == '/') {
    pos = 8;
    scheme_type = ada::scheme::type::HTTPS;
    protocol_end = 6;
  } else if (!match_non_https_special_scheme(0, len, b, pos, scheme_type,
                                             protocol_end)) {
    return false;
  }
#endif

  const size_t host_start = pos;
  bool has_upper = false;
  bool has_xn = false;
  size_t host_end = pos;
  if (!scan_plain_host(b, pos, len, host_end, has_upper, has_xn)) {
    // '[' is a host-class reject. Only inspect it after the scanner misses
    // so the 99% domain path never pays for an IPv6 check.
    if (pos < len && b[pos] == '[') {
      return try_finish_simple_ipv6(input, out, scheme_type, protocol_end, pos);
    }
    return try_finish_simple_userinfo(input, out, scheme_type, protocol_end,
                                      pos);
  }
  const size_t host_len = host_end - host_start;
  // Empty (0) or too long (>253): (0-1) wraps to SIZE_MAX.
  // Extra slashes after "://" are an empty host here; the state machine
  // consumes them, so this correctly misses the fast path.
  if (host_len - 1 >= 253) [[unlikely]] {
    return false;
  }
  bool is_ipv4 = false;
  {
    uint8_t lastc = b[host_end - 1];
    if (lastc == '.' && host_len > 1) {
      lastc = b[host_end - 2];
    }
    // .com/.org last letters are outside 0-9a-fxX, so this is one
    // not-taken branch on the common path instead of has_upper /
    // ipv4-char / has_xn as three separate checks.
    const bool rare_host =
        has_xn || has_upper ||
        ada::checkers::is_ipv4_number_char(static_cast<char>(lastc));
    if (rare_host) [[unlikely]] {
      if (has_xn) {
        return false;
      }
      if (has_upper) {
        if (reject_uppercase_plain_host(input.data() + host_start, host_len)) {
          return false;
        }
      } else {
        const std::string_view hv(input.data() + host_start, host_len);
        uint64_t ipv4_addr = 0;
        bool rewrite_host = false;
        if (reject_or_classify_numeric_last_label(hv, is_ipv4, ipv4_addr,
                                                  rewrite_host)) {
          return false;
        }
        if (rewrite_host) {
          char dotted[16];
          const size_t n =
              write_ipv4_dotted(dotted, static_cast<uint32_t>(ipv4_addr));
          return finish_simple_absolute_literal_host(
              input, out, scheme_type, protocol_end, host_start, host_end,
              std::string_view(dotted, n), IPV4);
        }
        out.host_type = IPV4;
      }
    }
  }

  size_t i = host_end;
  size_t path_start = host_end;
  size_t path_end = host_end;
  size_t query_start = std::string_view::npos;
  size_t hash_start = std::string_view::npos;
  bool has_path = false;
  bool maybe_dot_segment = false;
  bool saw_percent = false;
  bool rest_simple = true;

  if (host_end < len) {
    const uint8_t delim = b[host_end];
    if (delim == ':') [[unlikely]] {
      if (finish_simple_absolute_with_port(input, out, scheme_type,
                                           protocol_end, host_start, host_end,
                                           host_len, has_upper)) {
        if (is_ipv4) {
          out.host_type = IPV4;
        }
        return true;
      }
      // `user:pass@host` looks like a port until the '@'.
      return try_finish_simple_userinfo(input, out, scheme_type, protocol_end,
                                        host_start);
    }
    // scan_plain_host succeeded, so delim is / ? # (or we returned above).
    if (delim == '/') {
      has_path = true;
      path_start = i;
      ++i;
      scan_path_run(b, i, len, maybe_dot_segment, saw_percent);
      if (i < len) {
        if (b[i] == '?') {
          path_end = i;
          query_start = i;
          ++i;
          goto scan_query;
        }
        if (b[i] == '#') {
          path_end = i;
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
    } else if (delim == '?') {
      query_start = i;
      ++i;
      goto scan_query;
    } else {
      hash_start = i;
      ++i;
      goto scan_hash;
    }
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
  if (rest_simple && has_path && (maybe_dot_segment || saw_percent)) {
    const std::string_view path_body(input.data() + path_start,
                                     path_end - path_start);
    if (!simple_path_is_canonical(path_body, maybe_dot_segment, saw_percent)) {
      rest_simple = false;
    }
  }

  // The slow path removes ASCII tab/newline anywhere in the input and trims a
  // trailing C0 control or space; this fast path does neither. A query or
  // fragment reaching the helpers below would keep those bytes percent-encoded
  // ("?a\nb" -> "?a%0Ab", "#f " -> "#f%20") instead of stripped, so hand such
  // inputs back to the slow path.
  if (!rest_simple && trailing_c0_or_tab_newline(input)) {
    return false;
  }

  out.type = scheme_type;

  if (!rest_simple) {
    finish_simple_absolute_handoff<result_type>(
        input, out, host_start, host_end, host_len, protocol_end, has_upper,
        has_path, path_start, path_end, query_start, hash_start);
    return true;
  }

  const bool need_slash = !has_path;
  if constexpr (is_aggregator) {
    if (!need_slash) [[likely]] {
      // assign copies once. resize()+memcpy would value-init then overwrite.
      out.buffer.assign(input);
      if (has_upper) [[unlikely]] {
        ascii_to_lower(out.buffer.data() + host_start, host_len);
      }
      // query_start / hash_start are npos when absent; the uint32_t
      // truncation is omitted (see static_assert above).
      if (scheme_type == ada::scheme::type::HTTPS) [[likely]] {
        set_https_plain_host_components(out.components,
                                        static_cast<uint32_t>(host_end),
                                        static_cast<uint32_t>(path_start),
                                        static_cast<uint32_t>(query_start),
                                        static_cast<uint32_t>(hash_start));
      } else {
        set_plain_host_components(out.components, protocol_end,
                                  static_cast<uint32_t>(host_end),
                                  static_cast<uint32_t>(path_start),
                                  static_cast<uint32_t>(query_start),
                                  static_cast<uint32_t>(hash_start));
      }
    } else {
      out.buffer.clear();
      out.buffer.reserve(len + 1);
      out.buffer.append(input.substr(0, host_end));
      out.buffer.push_back('/');
      if (host_end < len) {
        out.buffer.append(input.substr(host_end));
      }
      if (has_upper) {
        ascii_to_lower(out.buffer.data() + host_start, host_len);
      }
      if (scheme_type == ada::scheme::type::HTTPS) {
        set_https_plain_host_components(
            out.components, static_cast<uint32_t>(host_end),
            static_cast<uint32_t>(host_end),
            (query_start != std::string_view::npos)
                ? static_cast<uint32_t>(query_start + 1)
                : url_components::omitted,
            (hash_start != std::string_view::npos)
                ? static_cast<uint32_t>(hash_start + 1)
                : url_components::omitted);
      } else {
        set_plain_host_components(out.components, protocol_end,
                                  static_cast<uint32_t>(host_end),
                                  static_cast<uint32_t>(host_end),
                                  (query_start != std::string_view::npos)
                                      ? static_cast<uint32_t>(query_start + 1)
                                      : url_components::omitted,
                                  (hash_start != std::string_view::npos)
                                      ? static_cast<uint32_t>(hash_start + 1)
                                      : url_components::omitted);
      }
    }
  } else {
    out.host.emplace(input.data() + host_start, host_len);
    if (has_upper) [[unlikely]] {
      ascii_to_lower(out.host->data(), host_len);
    }
    if (need_slash) {
      out.path.assign(1, '/');
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

template bool try_parse_simple_absolute<url>(std::string_view, url&);
template bool try_parse_simple_absolute<url_aggregator>(std::string_view,
                                                        url_aggregator&);
#endif  // ADA_SKIP_PARSER_FASTPATH

#ifndef ADA_SKIP_PARSER_RELATIVE
// Fast path for `/path`, path-relative (`foo`, `c/d?q`), `?query`, and
// `#fragment` against a special-scheme base. Scheme-relative (`//`) and
// scheme-like first segments (`foo:bar`) stay on the state machine.
// Compiled in the finish TU so the absolute/https I-cache is not
// displaced by relative resolution.
template <class result_type>
ADA_PARSER_FASTPATH bool try_parse_simple_relative(std::string_view input,
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
  bool saw_percent = false;

  if (first == '/' || path_relative) {
    has_path = true;
    path_start = 0;
    if (first == '/') {
      i = 1;
    }
    scan_path_run(b, i, len, maybe_dot_segment, saw_percent);
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

  if (has_path && (maybe_dot_segment || saw_percent) &&
      !simple_path_is_canonical(
          std::string_view(input.data() + path_start, path_end - path_start),
          maybe_dot_segment, saw_percent)) {
    return false;
  }

  out = base;

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

template bool try_parse_simple_relative<url>(std::string_view, const url&,
                                             url&);
template bool try_parse_simple_relative<url_aggregator>(std::string_view,
                                                        const url_aggregator&,
                                                        url_aggregator&);
#endif  // ADA_SKIP_PARSER_RELATIVE

#ifdef ADA_PARSER_ENABLE_SSSE3_PRAGMA
#pragma GCC pop_options
#endif

#ifndef ADA_SKIP_PARSER_IMPL
template <class result_type, bool store_values>
result_type& parse_url_impl_into(result_type& url, std::string_view user_input,
                                 const result_type* base_url,
                                 bool try_fast_path) {
  // We can specialize the implementation per type.
  // Important: result_type_is_ada_url is evaluated at *compile time*. This
  // means that doing if constexpr(result_type_is_ada_url) { something } else {
  // something else } is free (at runtime). This means that ada::url_aggregator
  // and ada::url **do not have to support the exact same API**.
  constexpr bool result_type_is_ada_url = std::is_same_v<ada::url, result_type>;
  constexpr bool result_type_is_ada_url_aggregator =
      std::is_same_v<ada::url_aggregator, result_type>;
  static_assert(result_type_is_ada_url ||
                result_type_is_ada_url_aggregator);  // We don't support
                                                     // anything else for now.

  ada_log("ada::parser::parse_url('", user_input, "' [", user_input.size(),
          " bytes],", (base_url != nullptr ? base_url->to_string() : "null"),
          ")");

  // Default max is ~4 GB. Skip the atomic unless set_max_input_length ran.
  // parse() already applied this check on the no-base miss path.
  if (try_fast_path &&
      (user_input.size() > std::numeric_limits<uint32_t>::max() ||
       (ada::max_input_length_customized &&
        user_input.size() > ada::get_max_input_length()))) [[unlikely]] {
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
  // IPv6 ('[') is a host-class reject; dotted-decimal IPv4 is finished
  // inside try_parse_simple_absolute. No extra preamble on the 99% path.
  if constexpr (store_values) {
    const bool hit_fast_path =
        try_fast_path &&
        ((base_url == nullptr)
             ? try_parse_simple_absolute(user_input, url)
             : try_parse_simple_relative(user_input, *base_url, url));
    if (hit_fast_path) {
      // Percent-encoding expands at most 3x and IDNA at most 4.5x. Skip
      // the post-parse length walk when the input (absolute) cannot grow
      // past the limit. Relative resolution can grow to base+input, so
      // always recheck that path.
      const bool may_expand_past_max =
          ada::max_input_length_customized
              ? user_input.size() >
                    static_cast<size_t>(ada::get_max_input_length()) / 5
              : user_input.size() > std::numeric_limits<uint32_t>::max() / 5;
      if (base_url != nullptr || may_expand_past_max) [[unlikely]] {
        const uint32_t max_input_length = ada::get_max_input_length();
        if constexpr (result_type_is_ada_url_aggregator) {
          if (url.buffer.size() > max_input_length) {
            url.is_valid = false;
          }
        } else if (url.get_href_size() > max_input_length) {
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
      const bool may_exceed =
          ada::max_input_length_customized ||
          user_input.size() > std::numeric_limits<uint32_t>::max() / 5;
      if (may_exceed) [[unlikely]] {
        const uint32_t max_input_length =
            ada::max_input_length_customized
                ? ada::get_max_input_length()
                : std::numeric_limits<uint32_t>::max();
        if constexpr (result_type_is_ada_url_aggregator) {
          if (url.buffer.size() > max_input_length) {
            url.is_valid = false;
          }
        } else if (url.get_href_size() > max_input_length) {
          url.is_valid = false;
        }
      }
    }
  }
  return url;
}

template url& parse_url_impl_into<url, true>(url&, std::string_view, const url*,
                                             bool);
template url_aggregator& parse_url_impl_into<url_aggregator, true>(
    url_aggregator&, std::string_view, const url_aggregator*, bool);
template url_aggregator& parse_url_impl_into<url_aggregator, false>(
    url_aggregator&, std::string_view, const url_aggregator*, bool);

template <class result_type, bool store_values>
result_type parse_url_impl(std::string_view user_input,
                           const result_type* base_url) {
  result_type url{};
  parse_url_impl_into<result_type, store_values>(url, user_input, base_url,
                                                 true);
  return url;
}

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
#endif  // ADA_SKIP_PARSER_IMPL
}  // namespace ada::parser

#ifdef ADA_PARSER_ENABLE_SSSE3_PRAGMA
#pragma GCC push_options
#pragma GCC target("ssse3")
#endif

#ifndef ADA_SKIP_PARSER_FASTPATH
namespace ada {

template <class result_type>
ada_warn_unused tl::expected<result_type, errors> parse(
    std::string_view input, const result_type* base_url) {
  if (base_url == nullptr) [[likely]] {
    if (input.size() > std::numeric_limits<uint32_t>::max()) [[unlikely]] {
      return tl::unexpected(errors::type_error);
    }
    if (max_input_length_customized && input.size() > get_max_input_length())
        [[unlikely]] {
      return tl::unexpected(errors::type_error);
    }
    result_type u{};
    if (ada::parser::try_parse_simple_absolute(input, u)) [[likely]] {
      // Default max is ~4 GB; only re-check expansion when the input
      // could grow past that (or past a customized limit).
      if (max_input_length_customized) [[unlikely]] {
        const uint32_t max_length = get_max_input_length();
        if (input.size() > static_cast<size_t>(max_length) / 5 &&
            u.get_href_size() > max_length) {
          return tl::unexpected(errors::type_error);
        }
      } else if (input.size() > std::numeric_limits<uint32_t>::max() / 5)
          [[unlikely]] {
        if (u.get_href_size() > std::numeric_limits<uint32_t>::max()) {
          return tl::unexpected(errors::type_error);
        }
      }
      return u;
    }
    ada::parser::parse_url_impl_into<result_type, true>(u, input, nullptr,
                                                        false);
    if (!u.is_valid) {
      return tl::unexpected(errors::type_error);
    }
    return u;
  }
  result_type u = ada::parser::parse_url_impl<result_type>(input, base_url);
  if (!u.is_valid) {
    return tl::unexpected(errors::type_error);
  }
  return u;
}

template ada::result<url> parse<url>(std::string_view input,
                                     const url* base_url);
template ada::result<url_aggregator> parse<url_aggregator>(
    std::string_view input, const url_aggregator* base_url);

}  // namespace ada

#endif  // ADA_SKIP_PARSER_FASTPATH

#ifdef ADA_PARSER_ENABLE_SSSE3_PRAGMA
#pragma GCC pop_options
#endif
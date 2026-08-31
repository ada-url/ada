#include <cstdint>

#include "ada/unicode.h"

#include "ada/character_sets-inl.h"
#include "ada/character_sets.h"
#include "ada/common_defs.h"

#include <cstring>
#if ADA_SSSE3
#include <tmmintrin.h>
#define ADA_UNICODE_SSSE3 1
#elif ADA_NEON
#include <arm_neon.h>
#elif ADA_RVV
#include <riscv_vector.h>
#endif
#ifndef ADA_UNICODE_SSSE3
#define ADA_UNICODE_SSSE3 0
#endif
#ifdef ADA_NEED_X86_64_V2_TARGET
#define ADA_UNICODE_SIMD ADA_X86_64_V2_SIMD
#else
#define ADA_UNICODE_SIMD ada_really_inline
#endif

#ifdef ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif

namespace ada::unicode {
namespace {

#if ADA_UNICODE_SSSE3 || ADA_NEON
ada_really_inline int trailing_zeroes32(uint32_t input_num) noexcept {
#ifdef ADA_REGULAR_VISUAL_STUDIO
  unsigned long ret;
  _BitScanForward(&ret, input_num);
  return static_cast<int>(ret);
#else
  return __builtin_ctz(input_num);
#endif
}

// Append one window whose set bits mark bytes that need encoding.
ada_really_inline void encode_mask_window(const char* p, uint32_t mask,
                                          size_t width, std::string& out) {
  uint64_t bits = mask;
  size_t off = 0;
  while (bits != 0) {
    const int zero_run = trailing_zeroes32(static_cast<uint32_t>(bits));
    if (zero_run != 0) {
      out.append(p + off, static_cast<size_t>(zero_run));
    }
    off += static_cast<size_t>(zero_run);
    out.append(character_sets::hex + uint8_t(p[off]) * 4, 3);
    ++off;
    bits >>= static_cast<unsigned>(zero_run + 1);
  }
  if (off < width) {
    out.append(p + off, width - off);
  }
}
#endif  // ADA_UNICODE_SSSE3 || ADA_NEON

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
  // Pair 16-byte windows so a fully clean 32-byte run is one append.
  while (p + 32 <= end) {
    const __m128i word0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
    const __m128i word1 =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16));
    const int mask0 = ssse3_percent_mask(word0, tables);
    const int mask1 = ssse3_percent_mask(word1, tables);
    if ((mask0 | mask1) == 0) {
      out.append(p, 32);
    } else {
      if (mask0 == 0) {
        out.append(p, 16);
      } else {
        encode_mask_window(p, static_cast<uint32_t>(mask0), 16, out);
      }
      if (mask1 == 0) {
        out.append(p + 16, 16);
      } else {
        encode_mask_window(p + 16, static_cast<uint32_t>(mask1), 16, out);
      }
    }
    p += 32;
  }
  if (p + 16 <= end) {
    const __m128i word = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
    const int mask = ssse3_percent_mask(word, tables);
    if (mask == 0) {
      out.append(p, 16);
    } else {
      encode_mask_window(p, static_cast<uint32_t>(mask), 16, out);
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
  while (p + 32 <= end) {
    const uint8x16_t hits0 =
        neon_percent_hits(vld1q_u8(reinterpret_cast<const uint8_t*>(p)), table);
    const uint8x16_t hits1 = neon_percent_hits(
        vld1q_u8(reinterpret_cast<const uint8_t*>(p + 16)), table);
    const bool clean0 = vmaxvq_u32(vreinterpretq_u32_u8(hits0)) == 0;
    const bool clean1 = vmaxvq_u32(vreinterpretq_u32_u8(hits1)) == 0;
    if (clean0 && clean1) {
      out.append(p, 32);
    } else {
      if (clean0) {
        out.append(p, 16);
      } else {
        encode_mask_window(p, neon_percent_mask(hits0), 16, out);
      }
      if (clean1) {
        out.append(p + 16, 16);
      } else {
        encode_mask_window(p + 16, neon_percent_mask(hits1), 16, out);
      }
    }
    p += 32;
  }
  if (p + 16 <= end) {
    const uint8x16_t hits =
        neon_percent_hits(vld1q_u8(reinterpret_cast<const uint8_t*>(p)), table);
    if (vmaxvq_u32(vreinterpretq_u32_u8(hits)) == 0) {
      out.append(p, 16);
    } else {
      encode_mask_window(p, neon_percent_mask(hits), 16, out);
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

#if ADA_UNICODE_SSSE3 || ADA_NEON || ADA_RVV
// Setter and existing percent_encode benches are 2-44 bytes. Table setup
// plus mask walking costs more instructions than bit_at on those inputs
// (especially dense USERINFO). SIMD pays off on the remaining suffix.
static constexpr size_t kPercentEncodeSimdMin = 48;

void percent_encode_to_wide(const char* p, const char* end,
                            const uint8_t character_set[], std::string& out) {
  // Worst case every byte becomes %XX. Avoids realloc while walking windows.
  out.reserve(out.size() + static_cast<size_t>(end - p) * 3);
#if ADA_UNICODE_SSSE3
  const ssse3_percent_tables tables = load_ssse3_percent_tables(character_set);
  percent_encode_to_ssse3(p, end, character_set, tables, out);
#elif ADA_NEON
  percent_encode_to_neon(p, end, character_set,
                         load_neon_percent_table(character_set), out);
#elif ADA_RVV
  percent_encode_to_rvv(p, end, character_set, out);
#endif
}
#endif

}  // namespace

void percent_encode_suffix(const char* p, const char* end,
                           const uint8_t character_set[], std::string& out) {
#if ADA_UNICODE_SSSE3 || ADA_NEON || ADA_RVV
  if (static_cast<size_t>(end - p) >= kPercentEncodeSimdMin) {
    percent_encode_to_wide(p, end, character_set, out);
    return;
  }
#endif
  percent_encode_to_scalar(p, end, character_set, out);
}

}  // namespace ada::unicode

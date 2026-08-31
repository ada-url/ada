#include "simd_x86_64_v2.h"

#include "ada/common_defs.h"

#include <cstdint>

#if ADA_SSSE3
#include <tmmintrin.h>
#if ADA_SSE41
#include <smmintrin.h>
#endif
#ifdef ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif
#endif

namespace ada::simd {
namespace {

#if ADA_SSSE3
ada_really_inline int trailing_zeroes(uint32_t input_num) noexcept {
#ifdef ADA_REGULAR_VISUAL_STUDIO
  unsigned long ret;
  _BitScanForward(&ret, input_num);
  return (int)ret;
#else
  return __builtin_ctzl(input_num);
#endif
}

ada_really_inline ADA_X86_64_V2_SIMD int ssse3_nibble_match_mask(
    __m128i word, __m128i low_mask, __m128i high_mask) noexcept {
  const __m128i fmask = _mm_set1_epi8(0x0f);
  const __m128i lowpart =
      _mm_shuffle_epi8(low_mask, _mm_and_si128(word, fmask));
  const __m128i highpart = _mm_shuffle_epi8(
      high_mask, _mm_and_si128(_mm_srli_epi16(word, 4), fmask));
  const __m128i classify = _mm_and_si128(lowpart, highpart);
  return ~_mm_movemask_epi8(_mm_cmpeq_epi8(classify, _mm_setzero_si128())) &
         0xFFFF;
}

ada_really_inline ADA_X86_64_V2_SIMD size_t
find_next_ssse3_nibble_match(std::string_view view, size_t location,
                             __m128i low_mask, __m128i high_mask) noexcept {
  size_t i = location;
  for (; i + 15 < view.size(); i += 16) {
    const __m128i word = _mm_loadu_si128((const __m128i*)(view.data() + i));
    const int mask = ssse3_nibble_match_mask(word, low_mask, high_mask);
    if (mask != 0) {
      return i + trailing_zeroes(static_cast<uint32_t>(mask));
    }
  }
  if (i < view.size()) {
    const __m128i word =
        _mm_loadu_si128((const __m128i*)(view.data() + view.length() - 16));
    const int mask = ssse3_nibble_match_mask(word, low_mask, high_mask);
    if (mask != 0) {
      return view.length() - 16 + trailing_zeroes(static_cast<uint32_t>(mask));
    }
  }
  return view.size();
}
#endif  // ADA_SSSE3

}  // namespace

#if ADA_SSSE3
ADA_X86_64_V2_SIMD bool has_tabs_or_newline_wide(
    std::string_view user_input) noexcept {
  size_t i = 0;
  const __m128i rnt =
      _mm_setr_epi8(1, 0, 0, 0, 0, 0, 0, 0, 0, 9, 10, 0, 0, 13, 0, 0);
  __m128i running = _mm_setzero_si128();
  for (; i + 15 < user_input.size(); i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(user_input.data() + i));
    __m128i shuffled = _mm_shuffle_epi8(rnt, word);
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
#if ADA_SSE41
  return _mm_testz_si128(running, running) == 0;
#else
  return _mm_movemask_epi8(running) != 0;
#endif
}

ADA_X86_64_V2_SIMD size_t find_next_host_delimiter_special_wide(
    std::string_view view, size_t location) noexcept {
  const __m128i low_mask =
      _mm_setr_epi8(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x04, 0x04, 0x00, 0x00, 0x03);
  const __m128i high_mask =
      _mm_setr_epi8(0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  return find_next_ssse3_nibble_match(view, location, low_mask, high_mask);
}

ADA_X86_64_V2_SIMD size_t
find_next_host_delimiter_wide(std::string_view view, size_t location) noexcept {
  const __m128i low_mask =
      _mm_setr_epi8(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x04, 0x00, 0x00, 0x00, 0x03);
  const __m128i high_mask =
      _mm_setr_epi8(0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  return find_next_ssse3_nibble_match(view, location, low_mask, high_mask);
}

ADA_X86_64_V2_SIMD size_t
find_authority_delimiter_special_wide(std::string_view view) noexcept {
  const __m128i low_mask =
      _mm_setr_epi8(0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x08, 0x00, 0x00, 0x06);
  const __m128i high_mask =
      _mm_setr_epi8(0x00, 0x00, 0x02, 0x04, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  return find_next_ssse3_nibble_match(view, 0, low_mask, high_mask);
}

ADA_X86_64_V2_SIMD size_t
find_authority_delimiter_wide(std::string_view view) noexcept {
  const __m128i low_mask =
      _mm_setr_epi8(0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x06);
  const __m128i high_mask =
      _mm_setr_epi8(0x00, 0x00, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  return find_next_ssse3_nibble_match(view, 0, low_mask, high_mask);
}
#endif  // ADA_SSSE3

}  // namespace ada::simd

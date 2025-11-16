#include <cstring>
#include <sstream>

#include "ada/checkers-inl.h"
#include "ada/common_defs.h"
#include "ada/scheme.h"

#if ADA_SSSE3
#include <tmmintrin.h>
#endif

namespace ada::helpers {

template <typename out_iter>
void encode_json(std::string_view view, out_iter out) {
  // trivial implementation. could be faster.
  const char* hexvalues =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  for (uint8_t c : view) {
    if (c == '\\') {
      *out++ = '\\';
      *out++ = '\\';
    } else if (c == '"') {
      *out++ = '\\';
      *out++ = '"';
    } else if (c <= 0x1f) {
      *out++ = '\\';
      *out++ = 'u';
      *out++ = '0';
      *out++ = '0';
      *out++ = hexvalues[2 * c];
      *out++ = hexvalues[2 * c + 1];
    } else {
      *out++ = c;
    }
  }
}

ada_unused std::string get_state(ada::state s) {
  switch (s) {
    case ada::state::AUTHORITY:
      return "Authority";
    case ada::state::SCHEME_START:
      return "Scheme Start";
    case ada::state::SCHEME:
      return "Scheme";
    case ada::state::HOST:
      return "Host";
    case ada::state::NO_SCHEME:
      return "No Scheme";
    case ada::state::FRAGMENT:
      return "Fragment";
    case ada::state::RELATIVE_SCHEME:
      return "Relative Scheme";
    case ada::state::RELATIVE_SLASH:
      return "Relative Slash";
    case ada::state::FILE:
      return "File";
    case ada::state::FILE_HOST:
      return "File Host";
    case ada::state::FILE_SLASH:
      return "File Slash";
    case ada::state::PATH_OR_AUTHORITY:
      return "Path or Authority";
    case ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES:
      return "Special Authority Ignore Slashes";
    case ada::state::SPECIAL_AUTHORITY_SLASHES:
      return "Special Authority Slashes";
    case ada::state::SPECIAL_RELATIVE_OR_AUTHORITY:
      return "Special Relative or Authority";
    case ada::state::QUERY:
      return "Query";
    case ada::state::PATH:
      return "Path";
    case ada::state::PATH_START:
      return "Path Start";
    case ada::state::OPAQUE_PATH:
      return "Opaque Path";
    case ada::state::PORT:
      return "Port";
    default:
      return "unknown state";
  }
}

ada_really_inline std::optional<std::string_view> prune_hash(
    std::string_view& input) noexcept {
  // compiles down to 20--30 instructions including a class to memchr (C
  // function). this function should be quite fast.
  size_t location_of_first = input.find('#');
  if (location_of_first == std::string_view::npos) {
    return std::nullopt;
  }
  std::string_view hash = input;
  hash.remove_prefix(location_of_first + 1);
  input.remove_suffix(input.size() - location_of_first);
  return hash;
}

ada_really_inline bool shorten_path(std::string& path,
                                    ada::scheme::type type) noexcept {
  // Let path be url's path.
  // If url's scheme is "file", path's size is 1, and path[0] is a normalized
  // Windows drive letter, then return.
  if (type == ada::scheme::type::FILE &&
      path.find('/', 1) == std::string_view::npos && !path.empty()) {
    if (checkers::is_normalized_windows_drive_letter(
            helpers::substring(path, 1))) {
      return false;
    }
  }

  // Remove path's last item, if any.
  size_t last_delimiter = path.rfind('/');
  if (last_delimiter != std::string::npos) {
    path.erase(last_delimiter);
    return true;
  }

  return false;
}

ada_really_inline bool shorten_path(std::string_view& path,
                                    ada::scheme::type type) noexcept {
  // Let path be url's path.
  // If url's scheme is "file", path's size is 1, and path[0] is a normalized
  // Windows drive letter, then return.
  if (type == ada::scheme::type::FILE &&
      path.find('/', 1) == std::string_view::npos && !path.empty()) {
    if (checkers::is_normalized_windows_drive_letter(
            helpers::substring(path, 1))) {
      return false;
    }
  }

  // Remove path's last item, if any.
  if (!path.empty()) {
    size_t slash_loc = path.rfind('/');
    if (slash_loc != std::string_view::npos) {
      path.remove_suffix(path.size() - slash_loc);
      return true;
    }
  }

  return false;
}

ada_really_inline void remove_ascii_tab_or_newline(
    std::string& input) noexcept {
  // if this ever becomes a performance issue, we could use an approach similar
  // to has_tabs_or_newline
  std::erase_if(input, ada::unicode::is_ascii_tab_or_newline);
}

ada_really_inline constexpr std::string_view substring(std::string_view input,
                                                       size_t pos) noexcept {
  ADA_ASSERT_TRUE(pos <= input.size());
  // The following is safer but unneeded if we have the above line:
  // return pos > input.size() ? std::string_view() : input.substr(pos);
  return input.substr(pos);
}

ada_really_inline void resize(std::string_view& input, size_t pos) noexcept {
  ADA_ASSERT_TRUE(pos <= input.size());
  input.remove_suffix(input.size() - pos);
}

// computes the number of trailing zeroes
// this is a private inline function only defined in this source file.
ada_really_inline int trailing_zeroes(uint32_t input_num) noexcept {
#ifdef ADA_REGULAR_VISUAL_STUDIO
  unsigned long ret;
  // Search the mask data from least significant bit (LSB)
  // to the most significant bit (MSB) for a set bit (1).
  _BitScanForward(&ret, input_num);
  return (int)ret;
#else   // ADA_REGULAR_VISUAL_STUDIO
  return __builtin_ctzl(input_num);
#endif  // ADA_REGULAR_VISUAL_STUDIO
}

// starting at index location, this finds the next location of a character
// :, /, \\, ? or [. If none is found, view.size() is returned.
// For use within get_host_delimiter_location.
#if ADA_SSSE3
ada_really_inline size_t find_next_host_delimiter_special(
    std::string_view view, size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '\\' ||
          view[i] == '?' || view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  // fast path for long strings (expected to be common)
  // Using SSSE3's _mm_shuffle_epi8 for table lookup (same approach as NEON)
  size_t i = location;
  const __m128i low_mask =
      _mm_setr_epi8(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x04, 0x04, 0x00, 0x00, 0x03);
  const __m128i high_mask =
      _mm_setr_epi8(0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  const __m128i fmask = _mm_set1_epi8(0xf);
  const __m128i zero = _mm_setzero_si128();
  for (; i + 15 < view.size(); i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(view.data() + i));
    __m128i lowpart = _mm_shuffle_epi8(low_mask, _mm_and_si128(word, fmask));
    __m128i highpart = _mm_shuffle_epi8(
        high_mask, _mm_and_si128(_mm_srli_epi16(word, 4), fmask));
    __m128i classify = _mm_and_si128(lowpart, highpart);
    __m128i is_zero = _mm_cmpeq_epi8(classify, zero);
    // _mm_movemask_epi8 returns a 16-bit mask in bits 0-15, with bits 16-31
    // zero. After NOT (~), bits 16-31 become 1. We must mask to 16 bits to
    // avoid false positives.
    int mask = ~_mm_movemask_epi8(is_zero) & 0xFFFF;
    if (mask != 0) {
      return i + trailing_zeroes(static_cast<uint32_t>(mask));
    }
  }
  if (i < view.size()) {
    __m128i word =
        _mm_loadu_si128((const __m128i*)(view.data() + view.length() - 16));
    __m128i lowpart = _mm_shuffle_epi8(low_mask, _mm_and_si128(word, fmask));
    __m128i highpart = _mm_shuffle_epi8(
        high_mask, _mm_and_si128(_mm_srli_epi16(word, 4), fmask));
    __m128i classify = _mm_and_si128(lowpart, highpart);
    __m128i is_zero = _mm_cmpeq_epi8(classify, zero);
    // _mm_movemask_epi8 returns a 16-bit mask in bits 0-15, with bits 16-31
    // zero. After NOT (~), bits 16-31 become 1. We must mask to 16 bits to
    // avoid false positives.
    int mask = ~_mm_movemask_epi8(is_zero) & 0xFFFF;
    if (mask != 0) {
      return view.length() - 16 + trailing_zeroes(static_cast<uint32_t>(mask));
    }
  }
  return size_t(view.size());
}
#elif ADA_NEON
// The ada_make_uint8x16_t macro is necessary because Visual Studio does not
// support direct initialization of uint8x16_t. See
// https://developercommunity.visualstudio.com/t/error-C2078:-too-many-initializers-whe/402911?q=backend+neon
#ifndef ada_make_uint8x16_t
#define ada_make_uint8x16_t(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, \
                            x13, x14, x15, x16)                                \
  ([=]() {                                                                     \
    static uint8_t array[16] = {x1, x2,  x3,  x4,  x5,  x6,  x7,  x8,          \
                                x9, x10, x11, x12, x13, x14, x15, x16};        \
    return vld1q_u8(array);                                                    \
  }())
#endif

ada_really_inline size_t find_next_host_delimiter_special(
    std::string_view view, size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '\\' ||
          view[i] == '?' || view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  auto to_bitmask = [](uint8x16_t input) -> uint16_t {
    uint8x16_t bit_mask =
        ada_make_uint8x16_t(0x01, 0x02, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x01,
                            0x02, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80);
    uint8x16_t minput = vandq_u8(input, bit_mask);
    uint8x16_t tmp = vpaddq_u8(minput, minput);
    tmp = vpaddq_u8(tmp, tmp);
    tmp = vpaddq_u8(tmp, tmp);
    return vgetq_lane_u16(vreinterpretq_u16_u8(tmp), 0);
  };

  // fast path for long strings (expected to be common)
  size_t i = location;
  uint8x16_t low_mask =
      ada_make_uint8x16_t(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x01, 0x04, 0x04, 0x00, 0x00, 0x03);
  uint8x16_t high_mask =
      ada_make_uint8x16_t(0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  uint8x16_t fmask = vmovq_n_u8(0xf);
  uint8x16_t zero{0};
  for (; i + 15 < view.size(); i += 16) {
    uint8x16_t word = vld1q_u8((const uint8_t*)view.data() + i);
    uint8x16_t lowpart = vqtbl1q_u8(low_mask, vandq_u8(word, fmask));
    uint8x16_t highpart = vqtbl1q_u8(high_mask, vshrq_n_u8(word, 4));
    uint8x16_t classify = vandq_u8(lowpart, highpart);
    if (vmaxvq_u32(vreinterpretq_u32_u8(classify)) != 0) {
      uint8x16_t is_zero = vceqq_u8(classify, zero);
      uint16_t is_non_zero = ~to_bitmask(is_zero);
      return i + trailing_zeroes(is_non_zero);
    }
  }

  if (i < view.size()) {
    uint8x16_t word =
        vld1q_u8((const uint8_t*)view.data() + view.length() - 16);
    uint8x16_t lowpart = vqtbl1q_u8(low_mask, vandq_u8(word, fmask));
    uint8x16_t highpart = vqtbl1q_u8(high_mask, vshrq_n_u8(word, 4));
    uint8x16_t classify = vandq_u8(lowpart, highpart);
    if (vmaxvq_u32(vreinterpretq_u32_u8(classify)) != 0) {
      uint8x16_t is_zero = vceqq_u8(classify, zero);
      uint16_t is_non_zero = ~to_bitmask(is_zero);
      return view.length() - 16 + trailing_zeroes(is_non_zero);
    }
  }
  return size_t(view.size());
}
#elif ADA_SSE2
ada_really_inline size_t find_next_host_delimiter_special(
    std::string_view view, size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '\\' ||
          view[i] == '?' || view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  // fast path for long strings (expected to be common)
  size_t i = location;
  const __m128i mask1 = _mm_set1_epi8(':');
  const __m128i mask2 = _mm_set1_epi8('/');
  const __m128i mask3 = _mm_set1_epi8('\\');
  const __m128i mask4 = _mm_set1_epi8('?');
  const __m128i mask5 = _mm_set1_epi8('[');

  for (; i + 15 < view.size(); i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(view.data() + i));
    __m128i m1 = _mm_cmpeq_epi8(word, mask1);
    __m128i m2 = _mm_cmpeq_epi8(word, mask2);
    __m128i m3 = _mm_cmpeq_epi8(word, mask3);
    __m128i m4 = _mm_cmpeq_epi8(word, mask4);
    __m128i m5 = _mm_cmpeq_epi8(word, mask5);
    __m128i m = _mm_or_si128(
        _mm_or_si128(_mm_or_si128(m1, m2), _mm_or_si128(m3, m4)), m5);
    int mask = _mm_movemask_epi8(m);
    if (mask != 0) {
      return i + trailing_zeroes(mask);
    }
  }
  if (i < view.size()) {
    __m128i word =
        _mm_loadu_si128((const __m128i*)(view.data() + view.length() - 16));
    __m128i m1 = _mm_cmpeq_epi8(word, mask1);
    __m128i m2 = _mm_cmpeq_epi8(word, mask2);
    __m128i m3 = _mm_cmpeq_epi8(word, mask3);
    __m128i m4 = _mm_cmpeq_epi8(word, mask4);
    __m128i m5 = _mm_cmpeq_epi8(word, mask5);
    __m128i m = _mm_or_si128(
        _mm_or_si128(_mm_or_si128(m1, m2), _mm_or_si128(m3, m4)), m5);
    int mask = _mm_movemask_epi8(m);
    if (mask != 0) {
      return view.length() - 16 + trailing_zeroes(mask);
    }
  }
  return size_t(view.length());
}
#elif ADA_LSX
ada_really_inline size_t find_next_host_delimiter_special(
    std::string_view view, size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '\\' ||
          view[i] == '?' || view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  // fast path for long strings (expected to be common)
  size_t i = location;
  const __m128i mask1 = __lsx_vrepli_b(':');
  const __m128i mask2 = __lsx_vrepli_b('/');
  const __m128i mask3 = __lsx_vrepli_b('\\');
  const __m128i mask4 = __lsx_vrepli_b('?');
  const __m128i mask5 = __lsx_vrepli_b('[');

  for (; i + 15 < view.size(); i += 16) {
    __m128i word = __lsx_vld((const __m128i*)(view.data() + i), 0);
    __m128i m1 = __lsx_vseq_b(word, mask1);
    __m128i m2 = __lsx_vseq_b(word, mask2);
    __m128i m3 = __lsx_vseq_b(word, mask3);
    __m128i m4 = __lsx_vseq_b(word, mask4);
    __m128i m5 = __lsx_vseq_b(word, mask5);
    __m128i m =
        __lsx_vor_v(__lsx_vor_v(__lsx_vor_v(m1, m2), __lsx_vor_v(m3, m4)), m5);
    int mask = __lsx_vpickve2gr_hu(__lsx_vmsknz_b(m), 0);
    if (mask != 0) {
      return i + trailing_zeroes(mask);
    }
  }
  if (i < view.size()) {
    __m128i word =
        __lsx_vld((const __m128i*)(view.data() + view.length() - 16), 0);
    __m128i m1 = __lsx_vseq_b(word, mask1);
    __m128i m2 = __lsx_vseq_b(word, mask2);
    __m128i m3 = __lsx_vseq_b(word, mask3);
    __m128i m4 = __lsx_vseq_b(word, mask4);
    __m128i m5 = __lsx_vseq_b(word, mask5);
    __m128i m =
        __lsx_vor_v(__lsx_vor_v(__lsx_vor_v(m1, m2), __lsx_vor_v(m3, m4)), m5);
    int mask = __lsx_vpickve2gr_hu(__lsx_vmsknz_b(m), 0);
    if (mask != 0) {
      return view.length() - 16 + trailing_zeroes(mask);
    }
  }
  return size_t(view.length());
}
#elif ADA_RVV
ada_really_inline size_t find_next_host_delimiter_special(
    std::string_view view, size_t location) noexcept {
  // The LUT approach was a bit slower on the SpacemiT X60, but I could see it
  // beeing faster on future hardware.
#if 0
  // LUT generated using: s=":/\\?["; list(zip([((ord(c)>>2)&0xF)for c in s],s))
  static const uint8_t tbl[16] = {
    0xF, 0, 0, 0, 0, 0, '[', '\\', 0, 0, 0, '/', 0, 0, ':', '?'
  };
  vuint8m1_t vtbl = __riscv_vle8_v_u8m1(tbl, 16);
#endif
  uint8_t* src = (uint8_t*)view.data() + location;
  for (size_t vl, n = view.size() - location; n > 0;
       n -= vl, src += vl, location += vl) {
    vl = __riscv_vsetvl_e8m1(n);
    vuint8m1_t v = __riscv_vle8_v_u8m1(src, vl);
#if 0
    vuint8m1_t vidx = __riscv_vand(__riscv_vsrl(v, 2, vl), 0xF, vl);
    vuint8m1_t vlut = __riscv_vrgather(vtbl, vidx, vl);
    vbool8_t m = __riscv_vmseq(v, vlut, vl);
#else
    vbool8_t m1 = __riscv_vmseq(v, ':', vl);
    vbool8_t m2 = __riscv_vmseq(v, '/', vl);
    vbool8_t m3 = __riscv_vmseq(v, '?', vl);
    vbool8_t m4 = __riscv_vmseq(v, '[', vl);
    vbool8_t m5 = __riscv_vmseq(v, '\\', vl);
    vbool8_t m = __riscv_vmor(
        __riscv_vmor(__riscv_vmor(m1, m2, vl), __riscv_vmor(m3, m4, vl), vl),
        m5, vl);
#endif
    long idx = __riscv_vfirst(m, vl);
    if (idx >= 0) return location + idx;
  }
  return size_t(view.size());
}
#else
// : / [ \\ ?
static constexpr std::array<uint8_t, 256> special_host_delimiters =
    []() consteval {
      std::array<uint8_t, 256> result{};
      for (int i : {':', '/', '[', '\\', '?'}) {
        result[i] = 1;
      }
      return result;
    }();
// credit: @the-moisrex recommended a table-based approach
ada_really_inline size_t find_next_host_delimiter_special(
    std::string_view view, size_t location) noexcept {
  auto const str = view.substr(location);
  for (auto pos = str.begin(); pos != str.end(); ++pos) {
    if (special_host_delimiters[(uint8_t)*pos]) {
      return pos - str.begin() + location;
    }
  }
  return size_t(view.size());
}
#endif

// starting at index location, this finds the next location of a character
// :, /, ? or [. If none is found, view.size() is returned.
// For use within get_host_delimiter_location.
#if ADA_SSSE3
ada_really_inline size_t find_next_host_delimiter(std::string_view view,
                                                  size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '?' ||
          view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  // fast path for long strings (expected to be common)
  size_t i = location;
  // Lookup tables for bit classification:
  // ':' (0x3A): low[0xA]=0x01, high[0x3]=0x01 -> match
  // '/' (0x2F): low[0xF]=0x02, high[0x2]=0x02 -> match
  // '?' (0x3F): low[0xF]=0x01, high[0x3]=0x01 -> match
  // '[' (0x5B): low[0xB]=0x04, high[0x5]=0x04 -> match
  const __m128i low_mask =
      _mm_setr_epi8(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x04, 0x00, 0x00, 0x00, 0x03);
  const __m128i high_mask =
      _mm_setr_epi8(0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  const __m128i fmask = _mm_set1_epi8(0xf);
  const __m128i zero = _mm_setzero_si128();

  for (; i + 15 < view.size(); i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(view.data() + i));
    __m128i lowpart = _mm_shuffle_epi8(low_mask, _mm_and_si128(word, fmask));
    __m128i highpart = _mm_shuffle_epi8(
        high_mask, _mm_and_si128(_mm_srli_epi16(word, 4), fmask));
    __m128i classify = _mm_and_si128(lowpart, highpart);
    __m128i is_zero = _mm_cmpeq_epi8(classify, zero);
    // _mm_movemask_epi8 returns a 16-bit mask in bits 0-15, with bits 16-31
    // zero. After NOT (~), bits 16-31 become 1. We must mask to 16 bits to
    // avoid false positives.
    int mask = ~_mm_movemask_epi8(is_zero) & 0xFFFF;
    if (mask != 0) {
      return i + trailing_zeroes(static_cast<uint32_t>(mask));
    }
  }

  if (i < view.size()) {
    __m128i word =
        _mm_loadu_si128((const __m128i*)(view.data() + view.length() - 16));
    __m128i lowpart = _mm_shuffle_epi8(low_mask, _mm_and_si128(word, fmask));
    __m128i highpart = _mm_shuffle_epi8(
        high_mask, _mm_and_si128(_mm_srli_epi16(word, 4), fmask));
    __m128i classify = _mm_and_si128(lowpart, highpart);
    __m128i is_zero = _mm_cmpeq_epi8(classify, zero);
    // _mm_movemask_epi8 returns a 16-bit mask in bits 0-15, with bits 16-31
    // zero. After NOT (~), bits 16-31 become 1. We must mask to 16 bits to
    // avoid false positives.
    int mask = ~_mm_movemask_epi8(is_zero) & 0xFFFF;
    if (mask != 0) {
      return view.length() - 16 + trailing_zeroes(static_cast<uint32_t>(mask));
    }
  }
  return size_t(view.size());
}
#elif ADA_NEON
ada_really_inline size_t find_next_host_delimiter(std::string_view view,
                                                  size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '?' ||
          view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  auto to_bitmask = [](uint8x16_t input) -> uint16_t {
    uint8x16_t bit_mask =
        ada_make_uint8x16_t(0x01, 0x02, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x01,
                            0x02, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80);
    uint8x16_t minput = vandq_u8(input, bit_mask);
    uint8x16_t tmp = vpaddq_u8(minput, minput);
    tmp = vpaddq_u8(tmp, tmp);
    tmp = vpaddq_u8(tmp, tmp);
    return vgetq_lane_u16(vreinterpretq_u16_u8(tmp), 0);
  };

  // fast path for long strings (expected to be common)
  size_t i = location;
  uint8x16_t low_mask =
      ada_make_uint8x16_t(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x03);
  uint8x16_t high_mask =
      ada_make_uint8x16_t(0x00, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  uint8x16_t fmask = vmovq_n_u8(0xf);
  uint8x16_t zero{0};
  for (; i + 15 < view.size(); i += 16) {
    uint8x16_t word = vld1q_u8((const uint8_t*)view.data() + i);
    uint8x16_t lowpart = vqtbl1q_u8(low_mask, vandq_u8(word, fmask));
    uint8x16_t highpart = vqtbl1q_u8(high_mask, vshrq_n_u8(word, 4));
    uint8x16_t classify = vandq_u8(lowpart, highpart);
    if (vmaxvq_u32(vreinterpretq_u32_u8(classify)) != 0) {
      uint8x16_t is_zero = vceqq_u8(classify, zero);
      uint16_t is_non_zero = ~to_bitmask(is_zero);
      return i + trailing_zeroes(is_non_zero);
    }
  }

  if (i < view.size()) {
    uint8x16_t word =
        vld1q_u8((const uint8_t*)view.data() + view.length() - 16);
    uint8x16_t lowpart = vqtbl1q_u8(low_mask, vandq_u8(word, fmask));
    uint8x16_t highpart = vqtbl1q_u8(high_mask, vshrq_n_u8(word, 4));
    uint8x16_t classify = vandq_u8(lowpart, highpart);
    if (vmaxvq_u32(vreinterpretq_u32_u8(classify)) != 0) {
      uint8x16_t is_zero = vceqq_u8(classify, zero);
      uint16_t is_non_zero = ~to_bitmask(is_zero);
      return view.length() - 16 + trailing_zeroes(is_non_zero);
    }
  }
  return size_t(view.size());
}
#elif ADA_SSE2
ada_really_inline size_t find_next_host_delimiter(std::string_view view,
                                                  size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '?' ||
          view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  // fast path for long strings (expected to be common)
  size_t i = location;
  const __m128i mask1 = _mm_set1_epi8(':');
  const __m128i mask2 = _mm_set1_epi8('/');
  const __m128i mask4 = _mm_set1_epi8('?');
  const __m128i mask5 = _mm_set1_epi8('[');

  for (; i + 15 < view.size(); i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(view.data() + i));
    __m128i m1 = _mm_cmpeq_epi8(word, mask1);
    __m128i m2 = _mm_cmpeq_epi8(word, mask2);
    __m128i m4 = _mm_cmpeq_epi8(word, mask4);
    __m128i m5 = _mm_cmpeq_epi8(word, mask5);
    __m128i m = _mm_or_si128(_mm_or_si128(m1, m2), _mm_or_si128(m4, m5));
    int mask = _mm_movemask_epi8(m);
    if (mask != 0) {
      return i + trailing_zeroes(mask);
    }
  }
  if (i < view.size()) {
    __m128i word =
        _mm_loadu_si128((const __m128i*)(view.data() + view.length() - 16));
    __m128i m1 = _mm_cmpeq_epi8(word, mask1);
    __m128i m2 = _mm_cmpeq_epi8(word, mask2);
    __m128i m4 = _mm_cmpeq_epi8(word, mask4);
    __m128i m5 = _mm_cmpeq_epi8(word, mask5);
    __m128i m = _mm_or_si128(_mm_or_si128(m1, m2), _mm_or_si128(m4, m5));
    int mask = _mm_movemask_epi8(m);
    if (mask != 0) {
      return view.length() - 16 + trailing_zeroes(mask);
    }
  }
  return size_t(view.length());
}
#elif ADA_LSX
ada_really_inline size_t find_next_host_delimiter(std::string_view view,
                                                  size_t location) noexcept {
  // first check for short strings in which case we do it naively.
  if (view.size() - location < 16) {  // slow path
    for (size_t i = location; i < view.size(); i++) {
      if (view[i] == ':' || view[i] == '/' || view[i] == '?' ||
          view[i] == '[') {
        return i;
      }
    }
    return size_t(view.size());
  }
  // fast path for long strings (expected to be common)
  size_t i = location;
  const __m128i mask1 = __lsx_vrepli_b(':');
  const __m128i mask2 = __lsx_vrepli_b('/');
  const __m128i mask4 = __lsx_vrepli_b('?');
  const __m128i mask5 = __lsx_vrepli_b('[');

  for (; i + 15 < view.size(); i += 16) {
    __m128i word = __lsx_vld((const __m128i*)(view.data() + i), 0);
    __m128i m1 = __lsx_vseq_b(word, mask1);
    __m128i m2 = __lsx_vseq_b(word, mask2);
    __m128i m4 = __lsx_vseq_b(word, mask4);
    __m128i m5 = __lsx_vseq_b(word, mask5);
    __m128i m = __lsx_vor_v(__lsx_vor_v(m1, m2), __lsx_vor_v(m4, m5));
    int mask = __lsx_vpickve2gr_hu(__lsx_vmsknz_b(m), 0);
    if (mask != 0) {
      return i + trailing_zeroes(mask);
    }
  }
  if (i < view.size()) {
    __m128i word =
        __lsx_vld((const __m128i*)(view.data() + view.length() - 16), 0);
    __m128i m1 = __lsx_vseq_b(word, mask1);
    __m128i m2 = __lsx_vseq_b(word, mask2);
    __m128i m4 = __lsx_vseq_b(word, mask4);
    __m128i m5 = __lsx_vseq_b(word, mask5);
    __m128i m = __lsx_vor_v(__lsx_vor_v(m1, m2), __lsx_vor_v(m4, m5));
    int mask = __lsx_vpickve2gr_hu(__lsx_vmsknz_b(m), 0);
    if (mask != 0) {
      return view.length() - 16 + trailing_zeroes(mask);
    }
  }
  return size_t(view.length());
}
#elif ADA_RVV
ada_really_inline size_t find_next_host_delimiter(std::string_view view,
                                                  size_t location) noexcept {
  uint8_t* src = (uint8_t*)view.data() + location;
  for (size_t vl, n = view.size() - location; n > 0;
       n -= vl, src += vl, location += vl) {
    vl = __riscv_vsetvl_e8m1(n);
    vuint8m1_t v = __riscv_vle8_v_u8m1(src, vl);
    vbool8_t m1 = __riscv_vmseq(v, ':', vl);
    vbool8_t m2 = __riscv_vmseq(v, '/', vl);
    vbool8_t m3 = __riscv_vmseq(v, '?', vl);
    vbool8_t m4 = __riscv_vmseq(v, '[', vl);
    vbool8_t m =
        __riscv_vmor(__riscv_vmor(m1, m2, vl), __riscv_vmor(m3, m4, vl), vl);
    long idx = __riscv_vfirst(m, vl);
    if (idx >= 0) return location + idx;
  }
  return size_t(view.size());
}
#else
// : / [ ?
static constexpr std::array<uint8_t, 256> host_delimiters = []() consteval {
  std::array<uint8_t, 256> result{};
  for (int i : {':', '/', '?', '['}) {
    result[i] = 1;
  }
  return result;
}();
// credit: @the-moisrex recommended a table-based approach
ada_really_inline size_t find_next_host_delimiter(std::string_view view,
                                                  size_t location) noexcept {
  auto const str = view.substr(location);
  for (auto pos = str.begin(); pos != str.end(); ++pos) {
    if (host_delimiters[(uint8_t)*pos]) {
      return pos - str.begin() + location;
    }
  }
  return size_t(view.size());
}
#endif

ada_really_inline std::pair<size_t, bool> get_host_delimiter_location(
    const bool is_special, std::string_view& view) noexcept {
  /**
   * The spec at https://url.spec.whatwg.org/#hostname-state expects us to
   * compute a variable called insideBrackets but this variable is only used
   * once, to check whether a ':' character was found outside brackets. Exact
   * text: "Otherwise, if c is U+003A (:) and insideBrackets is false, then:".
   * It is conceptually simpler and arguably more efficient to just return a
   * Boolean indicating whether ':' was found outside brackets.
   */
  const size_t view_size = view.size();
  size_t location = 0;
  bool found_colon = false;
  /**
   * Performance analysis:
   *
   * We are basically seeking the end of the hostname which can be indicated
   * by the end of the view, or by one of the characters ':', '/', '?', '\\'
   * (where '\\' is only applicable for special URLs). However, these must
   * appear outside a bracket range. E.g., if you have [something?]fd: then the
   * '?' does not count.
   *
   * So we can skip ahead to the next delimiter, as long as we include '[' in
   * the set of delimiters, and that we handle it first.
   *
   * So the trick is to have a fast function that locates the next delimiter.
   * Unless we find '[', then it only needs to be called once! Ideally, such a
   * function would be provided by the C++ standard library, but it seems that
   * find_first_of is not very fast, so we are forced to roll our own.
   *
   * We do not break into two loops for speed, but for clarity.
   */
  if (is_special) {
    // We move to the next delimiter.
    location = find_next_host_delimiter_special(view, location);
    // Unless we find '[' then we are going only going to have to call
    // find_next_host_delimiter_special once.
    for (; location < view_size;
         location = find_next_host_delimiter_special(view, location)) {
      if (view[location] == '[') {
        location = view.find(']', location);
        if (location == std::string_view::npos) {
          // performance: view.find might get translated to a memchr, which
          // has no notion of std::string_view::npos, so the code does not
          // reflect the assembly.
          location = view_size;
          break;
        }
      } else {
        found_colon = view[location] == ':';
        break;
      }
    }
  } else {
    // We move to the next delimiter.
    location = find_next_host_delimiter(view, location);
    // Unless we find '[' then we are going only going to have to call
    // find_next_host_delimiter_special once.
    for (; location < view_size;
         location = find_next_host_delimiter(view, location)) {
      if (view[location] == '[') {
        location = view.find(']', location);
        if (location == std::string_view::npos) {
          // performance: view.find might get translated to a memchr, which
          // has no notion of std::string_view::npos, so the code does not
          // reflect the assembly.
          location = view_size;
          break;
        }
      } else {
        found_colon = view[location] == ':';
        break;
      }
    }
  }
  // performance: remove_suffix may translate into a single instruction.
  view.remove_suffix(view_size - location);
  return {location, found_colon};
}

void trim_c0_whitespace(std::string_view& input) noexcept {
  while (!input.empty() &&
         ada::unicode::is_c0_control_or_space(input.front())) {
    input.remove_prefix(1);
  }
  while (!input.empty() && ada::unicode::is_c0_control_or_space(input.back())) {
    input.remove_suffix(1);
  }
}

ada_really_inline void parse_prepared_path(std::string_view input,
                                           ada::scheme::type type,
                                           std::string& path) {
  ada_log("parse_prepared_path ", input);
  uint8_t accumulator = checkers::path_signature(input);
  // Let us first detect a trivial case.
  // If it is special, we check that we have no dot, no %,  no \ and no
  // character needing percent encoding. Otherwise, we check that we have no %,
  // no dot, and no character needing percent encoding.
  constexpr uint8_t need_encoding = 1;
  constexpr uint8_t backslash_char = 2;
  constexpr uint8_t dot_char = 4;
  constexpr uint8_t percent_char = 8;
  bool special = type != ada::scheme::NOT_SPECIAL;
  bool may_need_slow_file_handling = (type == ada::scheme::type::FILE &&
                                      checkers::is_windows_drive_letter(input));
  bool trivial_path =
      (special ? (accumulator == 0)
               : ((accumulator & (need_encoding | dot_char | percent_char)) ==
                  0)) &&
      (!may_need_slow_file_handling);
  if (accumulator == dot_char && !may_need_slow_file_handling) {
    // '4' means that we have at least one dot, but nothing that requires
    // percent encoding or decoding. The only part that is not trivial is
    // that we may have single dots and double dots path segments.
    // If we have such segments, then we either have a path that begins
    // with '.' (easy to check), or we have the sequence './'.
    // Note: input cannot be empty, it must at least contain one character ('.')
    // Note: we know that '\' is not present.
    if (input[0] != '.') {
      size_t slashdot = 0;
      bool dot_is_file = true;
      for (;;) {
        slashdot = input.find("/.", slashdot);
        if (slashdot == std::string_view::npos) {  // common case
          break;
        } else {  // uncommon
          // only three cases matter: /./, /.. or a final /
          slashdot += 2;
          dot_is_file &= !(slashdot == input.size() || input[slashdot] == '.' ||
                           input[slashdot] == '/');
        }
      }
      trivial_path = dot_is_file;
    }
  }
  if (trivial_path) {
    ada_log("parse_path trivial");
    path += '/';
    path += input;
    return;
  }
  // We are going to need to look a bit at the path, but let us see if we can
  // ignore percent encoding *and* backslashes *and* percent characters.
  // Except for the trivial case, this is likely to capture 99% of paths out
  // there.
  bool fast_path =
      (special &&
       (accumulator & (need_encoding | backslash_char | percent_char)) == 0) &&
      (type != ada::scheme::type::FILE);
  if (fast_path) {
    ada_log("parse_prepared_path fast");
    // Here we don't need to worry about \ or percent encoding.
    // We also do not have a file protocol. We might have dots, however,
    // but dots must as appear as '.', and they cannot be encoded because
    // the symbol '%' is not present.
    size_t previous_location = 0;  // We start at 0.
    do {
      size_t new_location = input.find('/', previous_location);
      // std::string_view path_view = input;
      //  We process the last segment separately:
      if (new_location == std::string_view::npos) {
        std::string_view path_view = input.substr(previous_location);
        if (path_view == "..") {  // The path ends with ..
          // e.g., if you receive ".." with an empty path, you go to "/".
          if (path.empty()) {
            path = '/';
            return;
          }
          // Fast case where we have nothing to do:
          if (path.back() == '/') {
            return;
          }
          // If you have the path "/joe/myfriend",
          // then you delete 'myfriend'.
          path.resize(path.rfind('/') + 1);
          return;
        }
        path += '/';
        if (path_view != ".") {
          path.append(path_view);
        }
        return;
      } else {
        // This is a non-final segment.
        std::string_view path_view =
            input.substr(previous_location, new_location - previous_location);
        previous_location = new_location + 1;
        if (path_view == "..") {
          size_t last_delimiter = path.rfind('/');
          if (last_delimiter != std::string::npos) {
            path.erase(last_delimiter);
          }
        } else if (path_view != ".") {
          path += '/';
          path.append(path_view);
        }
      }
    } while (true);
  } else {
    ada_log("parse_path slow");
    // we have reached the general case
    bool needs_percent_encoding = (accumulator & 1);
    std::string path_buffer_tmp;
    do {
      size_t location = (special && (accumulator & 2))
                            ? input.find_first_of("/\\")
                            : input.find('/');
      std::string_view path_view = input;
      if (location != std::string_view::npos) {
        path_view.remove_suffix(path_view.size() - location);
        input.remove_prefix(location + 1);
      }
      // path_buffer is either path_view or it might point at a percent encoded
      // temporary file.
      std::string_view path_buffer =
          (needs_percent_encoding &&
           ada::unicode::percent_encode<false>(
               path_view, character_sets::PATH_PERCENT_ENCODE, path_buffer_tmp))
              ? path_buffer_tmp
              : path_view;
      if (unicode::is_double_dot_path_segment(path_buffer)) {
        helpers::shorten_path(path, type);
        if (location == std::string_view::npos) {
          path += '/';
        }
      } else if (unicode::is_single_dot_path_segment(path_buffer) &&
                 (location == std::string_view::npos)) {
        path += '/';
      }
      // Otherwise, if path_buffer is not a single-dot path segment, then:
      else if (!unicode::is_single_dot_path_segment(path_buffer)) {
        // If url's scheme is "file", url's path is empty, and path_buffer is a
        // Windows drive letter, then replace the second code point in
        // path_buffer with U+003A (:).
        if (type == ada::scheme::type::FILE && path.empty() &&
            checkers::is_windows_drive_letter(path_buffer)) {
          path += '/';
          path += path_buffer[0];
          path += ':';
          path_buffer.remove_prefix(2);
          path.append(path_buffer);
        } else {
          // Append path_buffer to url's path.
          path += '/';
          path.append(path_buffer);
        }
      }
      if (location == std::string_view::npos) {
        return;
      }
    } while (true);
  }
}

bool overlaps(std::string_view input1, const std::string& input2) noexcept {
  ada_log("helpers::overlaps check if string_view '", input1, "' [",
          input1.size(), " bytes] is part of string '", input2, "' [",
          input2.size(), " bytes]");
  return !input1.empty() && !input2.empty() && input1.data() >= input2.data() &&
         input1.data() < input2.data() + input2.size();
}

template <class url_type>
ada_really_inline void strip_trailing_spaces_from_opaque_path(
    url_type& url) noexcept {
  ada_log("helpers::strip_trailing_spaces_from_opaque_path");
  if (!url.has_opaque_path) return;
  if (url.has_hash()) return;
  if (url.has_search()) return;

  auto path = std::string(url.get_pathname());
  while (!path.empty() && path.back() == ' ') {
    path.resize(path.size() - 1);
  }
  url.update_base_pathname(path);
}

// @ / \\ ?
static constexpr std::array<uint8_t, 256> authority_delimiter_special =
    []() consteval {
      std::array<uint8_t, 256> result{};
      for (uint8_t i : {'@', '/', '\\', '?'}) {
        result[i] = 1;
      }
      return result;
    }();
// credit: @the-moisrex recommended a table-based approach
ada_really_inline size_t
find_authority_delimiter_special(std::string_view view) noexcept {
  // performance note: we might be able to gain further performance
  // with SIMD instrinsics.
  for (auto pos = view.begin(); pos != view.end(); ++pos) {
    if (authority_delimiter_special[(uint8_t)*pos]) {
      return pos - view.begin();
    }
  }
  return size_t(view.size());
}

// @ / ?
static constexpr std::array<uint8_t, 256> authority_delimiter = []() consteval {
  std::array<uint8_t, 256> result{};
  for (uint8_t i : {'@', '/', '?'}) {
    result[i] = 1;
  }
  return result;
}();
// credit: @the-moisrex recommended a table-based approach
ada_really_inline size_t
find_authority_delimiter(std::string_view view) noexcept {
  // performance note: we might be able to gain further performance
  // with SIMD instrinsics.
  for (auto pos = view.begin(); pos != view.end(); ++pos) {
    if (authority_delimiter[(uint8_t)*pos]) {
      return pos - view.begin();
    }
  }
  return size_t(view.size());
}

}  // namespace ada::helpers

namespace ada {
ada_warn_unused std::string to_string(ada::state state) {
  return ada::helpers::get_state(state);
}
#undef ada_make_uint8x16_t
}  // namespace ada

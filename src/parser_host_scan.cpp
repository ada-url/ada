#include "parser_host_scan.h"

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

#include "ada/common_defs.h"

namespace ada::parser {
// Named (not anonymous) so amalgamation with parser.cpp cannot collide
// on k_host_class in ada::parser::{anonymous}.
namespace short_host {

// Same classes as parser.cpp k_host_class: 0 = host, 1 = / ? # :, 2 = reject.
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

constexpr uint64_t k_ones = 0x0101010101010101ULL;
constexpr uint64_t k_high = 0x8080808080808080ULL;

ada_really_inline uint64_t splat(uint8_t c) noexcept { return k_ones * c; }

// High bit set in each lane whose byte equals c.
ada_really_inline uint64_t eq_high(uint64_t w, uint8_t c) noexcept {
  const uint64_t x = w ^ splat(c);
  return (x - k_ones) & ~x & k_high;
}

// High bit set in each lane whose byte is < n (n in 1..128).
ada_really_inline uint64_t lt_high(uint64_t w, uint8_t n) noexcept {
  return (w - splat(n)) & ~w & k_high;
}

ada_really_inline size_t first_lane(uint64_t high_mask) noexcept {
  return static_cast<size_t>(std::countr_zero(high_mask)) >> 3;
}

// Printable-ASCII lanes in ['A','Z']. Call only on a prefix that already
// passed the host-class check (no high-bit bytes).
ada_really_inline uint64_t upper_high(uint64_t w) noexcept {
  return lt_high(w - splat(static_cast<uint8_t>('A')), 26);
}

// One 8-byte load. A 16-byte SIMD load would over-read short hosts.
// Numbered GCC operands only: movq on x86-64, ldr on AArch64.
ada_really_inline uint64_t load_qword(const uint8_t* p) noexcept {
  uint64_t word;
#if defined(__GNUC__) && !defined(_MSC_VER) && !defined(__clang_analyzer__)
#if defined(__x86_64__) || defined(__amd64__)
  __asm__("movq (%1), %0" : "=r"(word) : "r"(p) : "memory");
#elif defined(__aarch64__)
  __asm__("ldr %0, [%1]" : "=r"(word) : "r"(p) : "memory");
#else
  std::memcpy(&word, p, sizeof(word));
#endif
#else
  std::memcpy(&word, p, sizeof(word));
#endif
  return word;
}

ada_really_inline void note_flags(uint64_t prefix, bool& has_upper,
                                  bool& has_x) noexcept {
  if (upper_high(prefix) != 0) {
    has_upper = true;
  }
  if (eq_high(prefix, static_cast<uint8_t>('x')) != 0) {
    has_x = true;
  }
}

}  // namespace short_host

// noinline: keep this out of ada.cpp even under LTO. Inlining it into
// scan_plain_host grew the setter/parse unity TU and lost CodSpeed.
#if defined(ADA_REGULAR_VISUAL_STUDIO)
#define ADA_HOST_SCAN_OUTLINE __declspec(noinline)
#else
#define ADA_HOST_SCAN_OUTLINE __attribute__((noinline))
#endif

ADA_HOST_SCAN_OUTLINE bool scan_plain_host_short(const uint8_t* b, size_t start,
                                                 size_t len, size_t& end,
                                                 bool& has_upper,
                                                 bool& has_x) noexcept {
  const uint64_t word = short_host::load_qword(b + start);
  const uint64_t delim = short_host::eq_high(word, static_cast<uint8_t>('/')) |
                         short_host::eq_high(word, static_cast<uint8_t>('?')) |
                         short_host::eq_high(word, static_cast<uint8_t>('#')) |
                         short_host::eq_high(word, static_cast<uint8_t>(':'));
  const uint64_t reject =
      short_host::lt_high(word, 0x21) | (word & short_host::k_high) |
      short_host::eq_high(word, 0x7F) |
      short_host::eq_high(word, static_cast<uint8_t>('<')) |
      short_host::eq_high(word, static_cast<uint8_t>('>')) |
      short_host::eq_high(word, static_cast<uint8_t>('@')) |
      short_host::eq_high(word, static_cast<uint8_t>('[')) |
      short_host::eq_high(word, static_cast<uint8_t>('\\')) |
      short_host::eq_high(word, static_cast<uint8_t>(']')) |
      short_host::eq_high(word, static_cast<uint8_t>('^')) |
      short_host::eq_high(word, static_cast<uint8_t>('|')) |
      short_host::eq_high(word, static_cast<uint8_t>('%'));
  const size_t rpos = short_host::first_lane(reject);
  const size_t dpos = short_host::first_lane(delim);
  if (rpos < dpos) {
    return false;
  }
  if (dpos < 8) {
    if (dpos != 0) {
      short_host::note_flags(((uint64_t{1} << (dpos * 8)) - 1) & word,
                             has_upper, has_x);
    }
    end = start + dpos;
    return true;
  }
  short_host::note_flags(word, has_upper, has_x);
  for (size_t i = start + 8; i < len; ++i) {
    const uint8_t c = b[i];
    const uint8_t cls = short_host::k_host_class[c];
    if (cls == 1) {
      end = i;
      return true;
    }
    if (cls == 2) {
      return false;
    }
    if (c >= 'A' && c <= 'Z') {
      has_upper = true;
    } else if (c == 'x') {
      has_x = true;
    }
  }
  end = len;
  return true;
}

}  // namespace ada::parser

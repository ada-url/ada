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

// Memory-order byte. SWAR countr_zero lanes are little-endian-only and
// the haszero borrow also mis-detects uppercase after '.', which broke
// s390x and made some hrefs non-idempotent on little-endian.
ada_really_inline uint8_t byte_at(uint64_t word, size_t k) noexcept {
  const size_t shift =
      (std::endian::native == std::endian::little ? k : 7 - k) * 8;
  return static_cast<uint8_t>(word >> shift);
}

// 1 = /?#:, -1 = reject, 0 = keep. Flags only for kept host bytes.
ada_really_inline int take_byte(uint8_t c, size_t at, size_t& end,
                                bool& has_upper, bool& has_x) noexcept {
  const uint8_t cls = k_host_class[c];
  if (cls == 1) {
    end = at;
    return 1;
  }
  if (cls == 2) {
    return -1;
  }
  if (c >= 'A' && c <= 'Z') {
    has_upper = true;
  } else if (c == 'x') {
    has_x = true;
  }
  return 0;
}

}  // namespace short_host

// noinline: keep this out of ada.cpp even under LTO. Inlining it into
// scan_plain_host grew the setter/parse unity TU and lost CodSpeed.
#if defined(ADA_REGULAR_VISUAL_STUDIO)
#define ADA_HOST_SCAN_OUTLINE __declspec(noinline)
#else
#define ADA_HOST_SCAN_OUTLINE __attribute__((noinline))
#endif

ADA_HOST_SCAN_OUTLINE bool scan_plain_host_tail(const uint8_t* b, size_t start,
                                                size_t len, size_t& end,
                                                bool& has_upper,
                                                bool& has_x) noexcept {
  size_t i = start;
  while (len - i >= 8) {
    const uint64_t word = short_host::load_qword(b + i);
    for (size_t k = 0; k < 8; ++k) {
      const int r = short_host::take_byte(short_host::byte_at(word, k), i + k,
                                          end, has_upper, has_x);
      if (r != 0) {
        return r > 0;
      }
    }
    i += 8;
  }
  for (; i < len; ++i) {
    const int r = short_host::take_byte(b[i], i, end, has_upper, has_x);
    if (r != 0) {
      return r > 0;
    }
  }
  end = len;
  return true;
}

}  // namespace ada::parser

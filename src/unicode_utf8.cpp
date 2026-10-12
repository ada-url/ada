#include "ada/unicode.h"

#include <array>
#include <cstring>
#include <string>
#include <string_view>

namespace ada::unicode {

// The Encoding Standard's UTF-8 decoder with replacement, re-encoded as
// UTF-8: well-formed sequences are kept, and each maximal ill-formed
// subsequence becomes U+FFFD.
// https://encoding.spec.whatwg.org/#utf-8-decoder
//
// This lives in its own translation unit. Keeping the body out of the unity
// ada.cpp build preserves GCC's inlining budget for the URL setter hot paths.
std::string utf8_decode_without_bom(std::string_view input) {
  constexpr std::string_view replacement = "\xEF\xBF\xBD";
  std::string out;
  out.reserve(input.size());
  size_t i = 0;
  while (i < input.size()) {
    const uint8_t b = static_cast<uint8_t>(input[i]);
    size_t needed = 0;
    uint8_t lower = 0x80, upper = 0xBF;
    if (b <= 0x7F) {
      out.push_back(static_cast<char>(b));
      i++;
      continue;
    } else if (b >= 0xC2 && b <= 0xDF) {
      needed = 1;
    } else if (b >= 0xE0 && b <= 0xEF) {
      needed = 2;
      if (b == 0xE0) lower = 0xA0;
      if (b == 0xED) upper = 0x9F;
    } else if (b >= 0xF0 && b <= 0xF4) {
      needed = 3;
      if (b == 0xF0) lower = 0x90;
      if (b == 0xF4) upper = 0x8F;
    } else {
      out.append(replacement);
      i++;
      continue;
    }
    size_t seen = 0;
    while (seen < needed && i + 1 + seen < input.size()) {
      const uint8_t c = static_cast<uint8_t>(input[i + 1 + seen]);
      if (c < lower || c > upper) {
        break;
      }
      lower = 0x80;
      upper = 0xBF;
      seen++;
    }
    if (seen == needed) {
      out.append(input.substr(i, needed + 1));
    } else {
      // The lead byte and the continuation bytes that fit form the maximal
      // subpart; the byte that broke it is read again.
      out.append(replacement);
    }
    i += seen + 1;
  }
  return out;
}

// 0..15 for hex digits, 0xFF otherwise - validate and decode with two loads.
constexpr static std::array<uint8_t, 256> form_unhex_table = []() consteval {
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

// Lives outside the unity TU. A non-ASCII result is either a raw input byte
// or a percent-escape whose high nibble is >= 8; both are noticed while the
// bytes are already in hand, so ASCII queries do not take a second pass.
std::string form_urlencoded_decode(const std::string_view input) {
  const size_t len = input.size();
  if (len == 0) [[unlikely]] {
    return {};
  }

  // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
  const char* const src = input.data();
  const char* const end = src + len;
  const char* p = src;

  unsigned raw_high = 0;
  while (p < end && *p != '+' && *p != '%') {
    raw_high |= static_cast<unsigned char>(*p);
    ++p;
  }
  if (p == end) {
    if (raw_high >= 0x80) [[unlikely]] {
      return utf8_decode_without_bom(input);
    }
    return std::string(input);
  }

  // Percent-decoding never grows the input. The UTF-8 pass below may.
  std::string out(len, '\0');
  char* d = out.data();
  char* const d0 = d;

  const size_t prefix = static_cast<size_t>(p - src);
  std::memcpy(d, src, prefix);
  d += prefix;

  // High nibbles of decoded escapes. >= 8 means the decoded byte is non-ASCII.
  unsigned decoded_high = 0;

  while (p < end) {
    const char c = *p;
    if (c == '+') {
      *d++ = ' ';
      ++p;
    } else if (c == '%') {
      // Decode runs of valid %XX tightly (common for nested URL query values).
      while (p + 2 < end && *p == '%') {
        const uint8_t hi = form_unhex_table[static_cast<uint8_t>(p[1])];
        const uint8_t lo = form_unhex_table[static_cast<uint8_t>(p[2])];
        if ((hi | lo) >= 16) {
          break;
        }
        *d++ = static_cast<char>((hi << 4) | lo);
        decoded_high |= hi;
        p += 3;
      }
      if (p < end && *p == '%') {
        // Invalid escape: copy '%' literally and continue.
        *d++ = *p++;
      }
    } else {
      // Copy a plain run until the next '+' or '%'.
      const char* start = p;
      raw_high |= static_cast<unsigned char>(*p);
      ++p;
      while (p < end && *p != '+' && *p != '%') {
        raw_high |= static_cast<unsigned char>(*p);
        ++p;
      }
      const size_t n = static_cast<size_t>(p - start);
      std::memcpy(d, start, n);
      d += n;
    }
  }

  out.resize(static_cast<size_t>(d - d0));
  if ((decoded_high >= 8) || (raw_high >= 0x80)) [[unlikely]] {
    return utf8_decode_without_bom(out);
  }
  return out;
}

}  // namespace ada::unicode

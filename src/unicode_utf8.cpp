#include "ada/unicode.h"

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

namespace {
// Word-wise high-bit test. Percent-decoding can turn an all-ASCII escape
// (`%AA`) into a non-ASCII byte, so the check runs on the decoded buffer
// once, after the hot loop, instead of on every copied run.
ada_really_inline bool contains_non_ascii(const char* s, size_t n) noexcept {
  constexpr uint64_t high_bit = 0x8080808080808080ull;
  size_t i = 0;
  for (; i + sizeof(uint64_t) <= n; i += sizeof(uint64_t)) {
    uint64_t word;
    std::memcpy(&word, s + i, sizeof(word));
    if ((word & high_bit) != 0) {
      return true;
    }
  }
  if (i < n) {
    uint64_t word = 0;
    std::memcpy(&word, s + i, n - i);
    if ((word & high_bit) != 0) {
      return true;
    }
  }
  return false;
}
}  // namespace

// The percent-decode loop stays in the unity TU (see unicode.cpp) so GCC's
// inlining budget for URL setters matches a build without this pass. Only
// the replacement step lives here.
std::string form_urlencoded_decode(const std::string_view input) {
  std::string out = form_urlencoded_percent_decode(input);
  if (contains_non_ascii(out.data(), out.size())) [[unlikely]] {
    return utf8_decode_without_bom(out);
  }
  return out;
}

}  // namespace ada::unicode

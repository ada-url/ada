/**
 * @file unicode-inl.h
 * @brief Definitions for unicode operations.
 */
#ifndef ADA_UNICODE_INL_H
#define ADA_UNICODE_INL_H
#include "ada/unicode.h"
#include "ada/character_sets.h"

#include <cstddef>

/**
 * Unicode operations. These functions are not part of our public API and may
 * change at any time.
 *
 * private
 * @namespace ada::unicode
 * @brief Includes the declarations for unicode operations
 */
namespace ada::unicode {
ada_really_inline size_t percent_encode_index(const std::string_view input,
                                              const uint8_t character_set[]) {
  // Longer inputs use the kernels in unicode_percent_encode.cpp (separate
  // translation unit, so the unity-build inlining budget of the URL setters is
  // unaffected). Very short inputs (<16 bytes) use a plain byte loop inline:
  // at most 15 iterations, smaller than a call. Mid-size inputs use the
  // shared out-of-line chunked scan, whose unrolled loop would bloat every
  // caller if inlined.
  if (input.size() >= 32) {
    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
    return percent_encode_index_simd(input.data(), input.size(), character_set);
  }
  if (input.size() >= 16) {
    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
    return percent_encode_index_scalar(input.data(), input.size(),
                                       character_set);
  }
  const char* data = input.data();
  const size_t size = input.size();
  for (size_t i = 0; i < size; i++) {
    if (character_sets::bit_at(character_set, data[i])) {
      return i;
    }
  }
  return size;
}
}  // namespace ada::unicode

#endif  // ADA_UNICODE_INL_H

/**
 * @file unicode-inl.h
 * @brief Definitions for unicode operations.
 */
#ifndef ADA_UNICODE_INL_H
#define ADA_UNICODE_INL_H
#include "ada/unicode.h"
#include "ada/character_sets.h"

#include <cstddef>
#include <cstring>

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
  // Longer inputs use the SIMD kernel in unicode_percent_encode.cpp (separate
  // translation unit, so the unity-build inlining budget of the URL setters is
  // unaffected). Below 32 bytes the inline scalar scan wins: the SIMD kernel
  // pays table setup that only amortizes on longer scans, and setter inputs
  // in this range are often dirty early (scalar exits on the first hit).
  if (input.size() >= 32) {
    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
    return percent_encode_index_simd(input.data(), input.size(), character_set);
  }
  const char* data = input.data();
  const size_t size = input.size();

  // Process 8 bytes at a time using unrolled loop
  size_t i = 0;
  for (; i + 8 <= size; i += 8) {
    unsigned char chunk[8];
    std::memcpy(&chunk, data + i,
                8);  // entices compiler to unconditionally process 8 characters

    // Check 8 characters at once
    for (size_t j = 0; j < 8; j++) {
      if (character_sets::bit_at(character_set, chunk[j])) {
        return i + j;
      }
    }
  }

  // Handle remaining bytes
  for (; i < size; i++) {
    if (character_sets::bit_at(character_set, data[i])) {
      return i;
    }
  }

  return size;
}
}  // namespace ada::unicode

#endif  // ADA_UNICODE_INL_H

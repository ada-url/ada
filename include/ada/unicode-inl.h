/**
 * @file unicode-inl.h
 * @brief Definitions for unicode operations.
 */
#ifndef ADA_UNICODE_INL_H
#define ADA_UNICODE_INL_H
#include <algorithm>
#include "ada/unicode.h"

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
  return std::distance(
      input.begin(),
      std::find_if(input.begin(), input.end(), [character_set](const char c) {
        return character_sets::bit_at(character_set, c);
      }));
}
}  // namespace ada::unicode

#endif  // ADA_UNICODE_INL_H

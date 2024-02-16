/**
 * @file character_sets.h
 * @brief Declaration of the character sets used by unicode functions.
 * @author Node.js
 * @see https://github.com/nodejs/node/blob/main/src/node_url_tables.cc
 */
#ifndef ADA_CHARACTER_SETS_H
#define ADA_CHARACTER_SETS_H

#include "ada/common_defs.h"
#include <cstdint>

/**
 * These functions are not part of our public API and may
 * change at any time.
 * @private
 * @namespace ada::character_sets
 * @brief Includes the definitions for unicode character sets.
 */
namespace ada::character_sets {
ada_really_inline bool bit_at(const uint8_t a[], uint8_t i);
}  // namespace ada::character_sets

#endif  // ADA_CHARACTER_SETS_H

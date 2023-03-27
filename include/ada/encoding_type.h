/**
 * @file encoding_type.h
 * @brief Definition for supported encoding types.
 */
#ifndef ADA_ENCODING_TYPE_H
#define ADA_ENCODING_TYPE_H

#include "ada/common_defs.h"
#include <string>

namespace ada {

/**
 * This specification defines three encodings with the same names as encoding
 * schemes defined in the Unicode standard: UTF-8, UTF-16LE, and UTF-16BE.
 *
 * @see https://encoding.spec.whatwg.org/#encodings
 */
enum class encoding_type {
  UTF8,
  UTF_16LE,
  UTF_16BE,
};

/**
 * Convert a encoding_type to string.
 */
ada_warn_unused std::string to_string(encoding_type type);

}  // namespace ada

#endif  // ADA_ENCODING_TYPE_H

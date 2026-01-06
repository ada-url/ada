/**
 * @file encoding_type.h
 * @brief Character encoding type definitions.
 *
 * Defines the encoding types supported for URL processing.
 *
 * @see https://encoding.spec.whatwg.org/
 */
#ifndef ADA_ENCODING_TYPE_H
#define ADA_ENCODING_TYPE_H

#include "ada/common_defs.h"
#include <string>

namespace ada {

/**
 * @brief Character encoding types for URL processing.
 *
 * Specifies the character encoding used for percent-decoding and other
 * string operations. UTF-8 is the most commonly used encoding for URLs.
 *
 * @see https://encoding.spec.whatwg.org/#encodings
 */
enum class encoding_type {
  UTF8,     /**< UTF-8 encoding (default for URLs) */
  UTF_16LE, /**< UTF-16 Little Endian encoding */
  UTF_16BE, /**< UTF-16 Big Endian encoding */
};

/**
 * Converts an encoding_type to its string representation.
 * @param type The encoding type to convert.
 * @return A string view of the encoding name.
 */
ada_warn_unused std::string_view to_string(encoding_type type);

}  // namespace ada

#endif  // ADA_ENCODING_TYPE_H

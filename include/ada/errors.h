/**
 * @file errors.h
 * @brief Error type definitions for URL parsing.
 *
 * Defines the error codes that can be returned when URL parsing fails.
 */
#ifndef ADA_ERRORS_H
#define ADA_ERRORS_H

#include <cstdint>
namespace ada {
/**
 * @brief Error codes for URL parsing operations.
 *
 * Used with `tl::expected` to indicate why a URL parsing operation failed.
 */
enum class errors : uint8_t {
  type_error /**< A type error occurred (e.g., invalid URL syntax). */
};
}  // namespace ada
#endif  // ADA_ERRORS_H
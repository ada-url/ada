/**
 * @file errors.h
 * @brief Definitions for the errors.
 */
#ifndef ADA_ERRORS_H
#define ADA_ERRORS_H

#include <cstdint>
namespace ada {
enum class errors : uint8_t { type_error };
}  // namespace ada
#endif  // ADA_ERRORS_H
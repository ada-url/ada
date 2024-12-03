/**
 * @file log.h
 * @brief Includes the definitions for logging.
 * @private Excluded from docs through the doxygen file.
 */
#ifndef ADA_LOG_H
#define ADA_LOG_H
#include "ada/common_defs.h"

// To enable logging, set ADA_LOGGING to 1:
#ifndef ADA_LOGGING
#define ADA_LOGGING 0
#endif

#if ADA_LOGGING
#include <iostream>
#endif  // ADA_LOGGING

namespace ada {

/**
 * Log a message. If you want to have no overhead when logging is disabled, use
 * the ada_log macro.
 * @private
 */
template <typename... Args>
constexpr ada_really_inline void log([[maybe_unused]] Args... args) {
#if ADA_LOGGING
  ((std::cout << "ADA_LOG: ") << ... << args) << std::endl;
#endif  // ADA_LOGGING
}
}  // namespace ada

#if ADA_LOGGING
#ifndef ada_log
#define ada_log(...)       \
  do {                     \
    ada::log(__VA_ARGS__); \
  } while (0)
#endif  // ada_log
#else
#define ada_log(...)
#endif  // ADA_LOGGING

#endif  // ADA_LOG_H

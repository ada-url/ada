
/**
 * @file log.h
 * @private
 * @brief logging code.
 */
#ifndef ADA_LOG_H
#define ADA_LOG_H
#include "ada/common_defs.h"

#include <iostream>
// To enable logging, set ADA_LOGGING to 1:
#ifndef ADA_LOGGING
#define ADA_LOGGING 0
#endif

namespace ada {

/**
 * Private function used for logging messages.
 * @private
 */
template <typename T>
ada_really_inline void inner_log([[maybe_unused]] T t) {
#if ADA_LOGGING
    std::cout << t << std::endl;
#endif
}


/**
 * Private function used for logging messages.
 * @private
 */
template<typename T, typename... Args>
ada_really_inline void inner_log([[maybe_unused]] T t, [[maybe_unused]] Args... args) {
#if ADA_LOGGING
    std::cout << t;
    inner_log(args...) ;
#endif
}


/**
 * Log a message.
 * @private
 */
template<typename T, typename... Args>
ada_really_inline void log([[maybe_unused]] T t, [[maybe_unused]] Args... args) {
#if ADA_LOGGING
    std::cout << "ADA_LOG: " << t;
    inner_log(args...) ;
#endif
}

/**
 * Log a message.
 * @private
 */
template<typename T>
ada_really_inline void log([[maybe_unused]] T t) {
#if ADA_LOGGING
    std::cout << "ADA_LOG: " <<  t << std::endl;
#endif

}


}

#endif // ADA_LOG_H
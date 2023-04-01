/**
 * @file state.h
 * @brief Definitions for the states of the URL state machine.
 */
#ifndef ADA_STATE_H
#define ADA_STATE_H

#include "ada/common_defs.h"

#include <string>

namespace ada {

#define ADA_STATE_LIST(V)             \
  V(AUTHORITY)                        \
  V(SCHEME_START)                     \
  V(SCHEME)                           \
  V(HOST)                             \
  V(NO_SCHEME)                        \
  V(FRAGMENT)                         \
  V(RELATIVE_SCHEME)                  \
  V(RELATIVE_SLASH)                   \
  V(FILE)                             \
  V(FILE_HOST)                        \
  V(FILE_SLASH)                       \
  V(PATH_OR_AUTHORITY)                \
  V(SPECIAL_AUTHORITY_IGNORE_SLASHES) \
  V(SPECIAL_AUTHORITY_SLASHES)        \
  V(SPECIAL_RELATIVE_OR_AUTHORITY)    \
  V(QUERY)                            \
  V(PATH)                             \
  V(PATH_START)                       \
  V(OPAQUE_PATH)                      \
  V(PORT)
/**
 * @see https://url.spec.whatwg.org/#url-parsing
 */

#define ENUM_ADA_STATE(state) state,
enum class state { ADA_STATE_LIST(ENUM_ADA_STATE) };
#undef ENUM_ADA_STATE

/**
 * Stringify a URL state machine state.
 */
ada_warn_unused std::string to_string(ada::state s);

}  // namespace ada

#endif  // ADA_STATE_H

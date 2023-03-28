/**
 * @file state.h
 * @brief Definitions for the states of the URL state machine.
 */
#ifndef ADA_STATE_H
#define ADA_STATE_H

#include "ada/common_defs.h"

#include <string>

namespace ada {

/**
 * @see https://url.spec.whatwg.org/#url-parsing
 */
enum class state {
  AUTHORITY,
  SCHEME_START,
  SCHEME,
  HOST,
  NO_SCHEME,
  FRAGMENT,
  RELATIVE_SCHEME,
  RELATIVE_SLASH,
  FILE,
  FILE_HOST,
  FILE_SLASH,
  PATH_OR_AUTHORITY,
  SPECIAL_AUTHORITY_IGNORE_SLASHES,
  SPECIAL_AUTHORITY_SLASHES,
  SPECIAL_RELATIVE_OR_AUTHORITY,
  QUERY,
  PATH,
  PATH_START,
  OPAQUE_PATH,
  PORT,
};

/**
 * Stringify a URL state machine state.
 */
ada_warn_unused std::string to_string(ada::state s);

}  // namespace ada

#endif  // ADA_STATE_H

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
  /**
   * @see https://url.spec.whatwg.org/#authority-state
   */
  AUTHORITY,

  /**
   * @see https://url.spec.whatwg.org/#scheme-start-state
   */
  SCHEME_START,

  /**
   * @see https://url.spec.whatwg.org/#scheme-state
   */
  SCHEME,

  /**
   * @see https://url.spec.whatwg.org/#host-state
   */
  HOST,

  /**
   * @see https://url.spec.whatwg.org/#no-scheme-state
   */
  NO_SCHEME,

  /**
   * @see https://url.spec.whatwg.org/#fragment-state
   */
  FRAGMENT,

  /**
   * @see https://url.spec.whatwg.org/#relative-state
   */
  RELATIVE_SCHEME,

  /**
   * @see https://url.spec.whatwg.org/#relative-slash-state
   */
  RELATIVE_SLASH,

  /**
   * @see https://url.spec.whatwg.org/#file-state
   */
  FILE,

  /**
   * @see https://url.spec.whatwg.org/#file-host-state
   */
  FILE_HOST,

  /**
   * @see https://url.spec.whatwg.org/#file-slash-state
   */
  FILE_SLASH,

  /**
   * @see https://url.spec.whatwg.org/#path-or-authority-state
   */
  PATH_OR_AUTHORITY,

  /**
   * @see https://url.spec.whatwg.org/#special-authority-ignore-slashes-state
   */
  SPECIAL_AUTHORITY_IGNORE_SLASHES,

  /**
   * @see https://url.spec.whatwg.org/#special-authority-slashes-state
   */
  SPECIAL_AUTHORITY_SLASHES,

  /**
   * @see https://url.spec.whatwg.org/#special-relative-or-authority-state
   */
  SPECIAL_RELATIVE_OR_AUTHORITY,

  /**
   * @see https://url.spec.whatwg.org/#query-state
   */
  QUERY,

  /**
   * @see https://url.spec.whatwg.org/#path-state
   */
  PATH,

  /**
   * @see https://url.spec.whatwg.org/#path-start-state
   */
  PATH_START,

  /**
   * @see https://url.spec.whatwg.org/#cannot-be-a-base-url-path-state
   */
  OPAQUE_PATH,

  /**
   * @see https://url.spec.whatwg.org/#port-state
   */
  PORT,
};

/**
 * Stringify a URL state machine state.
 */
ada_warn_unused std::string to_string(ada::state s);

}  // namespace ada

#endif  // ADA_STATE_H

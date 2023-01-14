#ifndef ADA_STATE_H
#define ADA_STATE_H

#include "common_defs.h"

namespace ada {

  enum class state {
    AUTHORITY,
    SCHEME_START,
    SCHEME,
    HOST,
    NO_SCHEME,
    FRAGMENT,
    RELATIVE,
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

  ada_warn_unused std::string to_string(ada::state s);

} // ada namespace

#endif // ADA_STATE_H

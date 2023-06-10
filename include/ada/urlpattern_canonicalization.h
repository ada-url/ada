#ifndef ADA_URLPATTERN_CANONICALIZATION_H
#define ADA_URLPATTERN_CANONICALIZATION_H

#include "ada/helpers.h"
#include <string_view>

namespace ada::urlpattern {

// Encoding Callbacks
std::u32string_view canonicalize_protocol(std::u32string_view protocol);

}  // namespace ada::urlpattern

#endif

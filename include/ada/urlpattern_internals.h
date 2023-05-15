#ifndef ADA_URLPATTERN_INTERNALS_H
#define ADA_URLPATTERN_INTERNALS_H

#include "ada/urlpattern_base.h"
#include <string_view>

namespace ada::urlpattern {

std::string_view compile_component(std::u32string_view input,
                                   std::function<std::u32string_view> &callback,
                                   u32urlpattern_options &options);

}

#endif
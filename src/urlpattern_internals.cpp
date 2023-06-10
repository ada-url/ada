#include "ada/urlpattern_internals.h"

namespace ada::urlpattern {

// https://wicg.github.io/urlpattern/#compile-a-component
std::string_view compile_component(std::u32string_view input,
                                   std::function<std::u32string_view> &callback,
                                   u32urlpattern_options &options) {
  // 1. If input is null, then set input to "*".
  if (input.empty()) input = U"*";

  // 2. Let part list be the result of running parse a pattern string given
  // input, options, and encoding callback.
  
}

}  // namespace ada::urlpattern
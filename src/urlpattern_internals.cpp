#include "ada/urlpattern_internals.h"

namespace ada::urlpattern {

// https://wicg.github.io/urlpattern/#compile-a-component
std::string_view compile_component(std::u32string_view input,
                                   std::function<std::u32string_view> &callback,
                                   u32urlpattern_options &options) {
  // If input is null, then set input to "*".
  if (input.empty()) input = U"*";
}

}  // namespace ada::urlpattern
#ifndef ADA_URLPATTERN_INTERNALS_H
#define ADA_URLPATTERN_INTERNALS_H

#include "ada/urlpattern_base.h"
#include <string_view>
#include "regex"
#include "vector"

namespace ada::urlpattern {
// https://wicg.github.io/urlpattern/#component
struct urlpattern_component {
  std::u32string_view pattern_string;
  // TODO: use a more performant lib, eg RE2
  std::regex regular_expression;
  std::vector<std::string_view> group_name_list;
};

// https://wicg.github.io/urlpattern/#component
std::string_view compile_component(std::u32string_view input,
                                   std::function<std::u32string_view> &callback,
                                   u32urlpattern_options &options);

}  // namespace ada::urlpattern

#endif
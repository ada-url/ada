#ifndef ADA_URL_PATTERN_H
#define ADA_URL_PATTERN_H

#include "ada/common_defs.h"

#include "ada/urlpattern_base.h"

#include <unordered_map>
#include <string_view>
#include <optional>

namespace ada::urlpattern {
// https://wicg.github.io/urlpattern/#options

struct urlpattern_component_result {
  std::string_view input;
  std::unordered_map<std::string_view, std::optional<std::string_view>> groups;
};

template <typename urlpattern_input>
struct urlpattern_result {
  urlpattern_component_result protocol;
  urlpattern_component_result username;
  urlpattern_component_result password;
  urlpattern_component_result hostname;
  urlpattern_component_result port;
  urlpattern_component_result pathname;
  urlpattern_component_result search;
  urlpattern_component_result hash;
  urlpattern_input input[];
};

struct urlpattern {
  // TODO: improve DX.. maybe create one constructor for each case and
  // make them call the right/following constructors 'under the hood'
  urlpattern(std::string_view input, std::optional<std::string_view> base_url,
             std::optional<urlpattern_options> &options);
  urlpattern(urlpattern_init &input,
             std::optional<urlpattern_options> &options);

  const std::string_view protocol;
  const std::string_view username;
  const std::string_view password;
  const std::string_view hostname;
  const std::string_view port;
  const std::string_view pathname;
  const std::string_view search;
  const std::string_view hash;
};

}  // namespace ada::urlpattern

#endif

#ifndef ADA_URL_PATTERN_H
#define ADA_URL_PATTERN_H

#include "ada/common_defs.h"

#include <unordered_map>
#include <array>
#include <string_view>
#include <optional>

namespace ada {

ada_really_inline bool is_valid_name_code_point(const char32_t &c,
                                                bool is_first) noexcept;

struct urlpattern_options {
  bool ignore_case = false;
};

struct urlpattern_component_result {
  std::string_view input;
  std::unordered_map<std::string_view, std::optional<std::string_view>> groups;
};

struct urlpattern_init {
  std::string_view protocol;
  std::string_view username;
  std::string_view password;
  std::string_view hostname;
  std::string_view port;
  std::string_view pathname;
  std::string_view search;
  std::string_view hash;
  std::string_view base_url;
};

union input_union {
  urlpattern_init init;
  std::string_view str;
};

typedef input_union urlpattern_input;

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
  urlpattern(urlpattern_input &input, std::string_view base_url,
             std::optional<urlpattern_options> &options);

  urlpattern(std::optional<urlpattern_input> &input,
             std::optional<urlpattern_options> &options);

  bool test(std::optional<urlpattern_input> &input,
            std::optional<std::string_view> base_url);

  std::optional<urlpattern_result> exec(
      std::optional<urlpattern_input> input,
      std::optional<std::string_view> base_url);

  const std::string_view protocol;
  const std::string_view username;
  const std::string_view password;
  const std::string_view hostname;
  const std::string_view port;
  const std::string_view pathname;
  const std::string_view search;
  const std::string_view hash;
};

}  // namespace ada

#endif

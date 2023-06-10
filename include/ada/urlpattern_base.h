#ifndef ADA_URLPATTERN_BASE_H
#define ADA_URLPATTERN_BASE_H

#include "ada/helpers.h"

#include <string_view>

namespace ada::urlpattern {

struct urlpattern_options {
  std::string_view delimiter = "";
  std::string_view prefix = "";
  bool ignore_case = false;
};

struct u32urlpattern_options {
  std::u32string_view delimiter = U"";
  std::u32string_view prefix = U"";
  bool ignore_case = false;
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

}  // namespace ada::urlpattern

#endif
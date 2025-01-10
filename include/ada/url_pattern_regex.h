/**
 * @file url_search_params.h
 * @brief Declaration for the URL Search Params
 */
#ifndef ADA_URL_PATTERN_REGEX_H
#define ADA_URL_PATTERN_REGEX_H

#include <regex>

namespace ada::url_pattern_regex {

class provider {
  struct type {};

  std::optional<type> create_regex_instance(std::string_view pattern,
                                            bool ignore_case);

  std::optional<std::vector<std::string>> regex_search(std::string_view input, std::string_view pattern);
};

class std_regex_provider : public provider {

};

}  // namespace ada::url_pattern_regex

#endif // ADA_URL_PATTERN_REGEX_H

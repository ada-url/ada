/**
 * @file url_search_params.h
 * @brief Declaration for the URL Search Params
 */
#ifndef ADA_URL_PATTERN_REGEX_H
#define ADA_URL_PATTERN_REGEX_H

#include <concepts>
#include <regex>

namespace ada::url_pattern_regex {

template <class T>
class provider {
 public:
  using regex_type = T;

  virtual ~provider() = default;
  virtual std::optional<regex_type> create_instance(std::string_view pattern,
                                                    bool ignore_case) = 0;
  virtual std::optional<std::vector<std::string>> regex_search(
      std::string_view input, const regex_type& pattern) = 0;
  virtual bool regex_match(std::string_view input,
                           const regex_type& pattern) = 0;
};

template <class derived_class, typename type>
concept derived_from_provider =
    std::is_base_of_v<provider<type>, derived_class>;

class std_regex_provider : public provider<std::regex> {
 public:
  std_regex_provider() = default;
  using regex_type = std::regex;
  std::optional<regex_type> create_instance(std::string_view pattern,
                                            bool ignore_case) override;
  std::optional<std::vector<std::string>> regex_search(
      std::string_view input, const regex_type& pattern) override;
  bool regex_match(std::string_view input, const regex_type& pattern) override;
};

}  // namespace ada::url_pattern_regex

#endif  // ADA_URL_PATTERN_REGEX_H

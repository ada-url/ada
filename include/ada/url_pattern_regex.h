/**
 * @file url_search_params.h
 * @brief Declaration for the URL Search Params
 */
#ifndef ADA_URL_PATTERN_REGEX_H
#define ADA_URL_PATTERN_REGEX_H

#include <concepts>
#include <regex>

namespace ada::url_pattern_regex {

template <typename T>
concept regex_concept = requires(T t, std::string_view pattern,
                                 bool ignore_case, std::string_view input) {
  // Ensure the class has a type alias 'regex_type'
  typename T::regex_type;

  // Function to create a regex instance
  {
    T::create_instance(pattern, ignore_case)
  } -> std::same_as<std::optional<typename T::regex_type>>;

  // Function to perform regex search
  {
    t.regex_search(input, std::declval<typename T::regex_type&>())
  } -> std::same_as<std::optional<std::vector<std::string>>>;

  // Function to match regex pattern
  {
    t.regex_match(input, std::declval<typename T::regex_type&>())
  } -> std::same_as<bool>;

  // Copy constructor
  { T(std::declval<const T&>()) } -> std::same_as<T>;

  // Move constructor
  { T(std::declval<T&&>()) } -> std::same_as<T>;
};

class std_regex_provider {
 public:
  std_regex_provider() = default;
  using regex_type = std::regex;
  static std::optional<regex_type> create_instance(std::string_view pattern,
                                                   bool ignore_case);
  std::optional<std::vector<std::string>> regex_search(
      std::string_view input, const regex_type& pattern);
  bool regex_match(std::string_view input, const regex_type& pattern);
};

}  // namespace ada::url_pattern_regex

#endif  // ADA_URL_PATTERN_REGEX_H

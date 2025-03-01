#include "ada/url_pattern_regex.h"

namespace ada::url_pattern_regex {

#ifdef ADA_USE_UNSAFE_STD_REGEX_PROVIDER
std::optional<std::regex> std_regex_provider::create_instance(
    std::string_view pattern, bool ignore_case) {
  // Let flags be an empty string.
  // If options's ignore case is true then set flags to "vi".
  // Otherwise set flags to "v"
  auto flags = ignore_case
                   ? std::regex::icase | std::regex_constants::ECMAScript
                   : std::regex_constants::ECMAScript;
  try {
    return std::regex(pattern.data(), pattern.size(), flags);
  } catch (const std::regex_error& e) {
    (void)e;
    ada_log("std_regex_provider::create_instance failed:", e.what());
    return std::nullopt;
  }
}

std::optional<std::vector<std::optional<std::string>>>
std_regex_provider::regex_search(std::string_view input,
                                 const std::regex& pattern) {
  std::string input_str(
      input.begin(),
      input.end());  // Convert string_view to string for regex_search
  std::smatch match_result;
  if (!std::regex_search(input_str, match_result, pattern,
                         std::regex_constants::match_any)) {
    return std::nullopt;
  }
  std::vector<std::optional<std::string>> matches;
  // If input is empty, let's assume the result will be empty as well.
  if (input.empty() || match_result.empty()) {
    return matches;
  }
  matches.reserve(match_result.size());
  for (size_t i = 1; i < match_result.size(); ++i) {
    if (auto entry = match_result[i]; entry.matched) {
      matches.emplace_back(entry.str());
    }
  }
  return matches;
}

bool std_regex_provider::regex_match(std::string_view input,
                                     const std::regex& pattern) {
  return std::regex_match(input.begin(), input.end(), pattern);
}

#endif  // ADA_USE_UNSAFE_STD_REGEX_PROVIDER

}  // namespace ada::url_pattern_regex

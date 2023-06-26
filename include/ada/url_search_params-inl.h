/**
 * @file url_search_params-inl.h
 * @brief Inline declarations for the URL Search Params
 */
#ifndef ADA_URL_SEARCH_PARAMS_INL_H
#define ADA_URL_SEARCH_PARAMS_INL_H

#include "ada.h"
#include "ada/url_search_params.h"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ada {

inline void url_search_params::append(const std::string_view key,
                                      const std::string_view value) {
  params.emplace_back(std::string(key), std::string(value));
}

inline size_t url_search_params::size() const noexcept { return params.size(); }

inline std::optional<std::string_view> url_search_params::get(
    const std::string_view key) {
  auto entry = std::find_if(params.begin(), params.end(), [&key](auto param) {
    return std::get<0>(param) == key;
  });

  if (entry == params.end()) {
    return std::nullopt;
  }

  return std::get<1>(*entry);
}

inline std::vector<std::string> url_search_params::get_all(
    const std::string_view key) {
  std::vector<std::string> out{};

  for (auto& param : params) {
    if (std::get<0>(param) == key) {
      out.emplace_back(std::get<1>(param));
    }
  }

  return out;
}

inline bool url_search_params::has(const std::string_view key) noexcept {
  auto entry = std::find_if(params.begin(), params.end(), [&key](auto param) {
    return std::get<0>(param) == key;
  });
  return entry != params.end();
}

}  // namespace ada

#endif  // ADA_URL_SEARCH_PARAMS_INL_H

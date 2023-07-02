/**
 * @file url_search_params-inl.h
 * @brief Inline declarations for the URL Search Params
 */
#ifndef ADA_URL_SEARCH_PARAMS_INL_H
#define ADA_URL_SEARCH_PARAMS_INL_H

#include "ada.h"
#include "ada/character_sets-inl.h"
#include "ada/unicode.h"
#include "ada/url_search_params.h"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ada {

inline void url_search_params::initialize(std::string_view input) {
  if (input.front() == '?') {
    input.remove_prefix(1);
  }

  auto process_key_value = [&](const std::string_view current) {
    auto equal = current.find_first_of("=");

    if (equal == std::string_view::npos) {
      params.emplace_back(current, "");
    } else {
      auto plain_name = current.substr(0, equal);
      auto plain_value = current.substr(equal + 1);
      auto name =
          unicode::percent_decode(plain_name, plain_name.find_first_of('%'));
      auto value =
          unicode::percent_decode(plain_value, plain_value.find_first_of('%'));

      std::replace(name.begin(), name.end(), '+', ' ');
      std::replace(value.begin(), value.end(), '+', ' ');

      params.emplace_back(name, value);
    }
  };

  while (!input.empty()) {
    auto ampersand_index = input.find_first_of("&");

    if (ampersand_index == std::string_view::npos) {
      if (!input.empty()) {
        process_key_value(input);
      }
      break;
    } else if (ampersand_index != 0) {
      process_key_value(input.substr(0, ampersand_index));
    }

    input.remove_prefix(ampersand_index + 1);
  }
}

inline void url_search_params::append(const std::string_view key,
                                      const std::string_view value) {
  params.emplace_back(key, value);
}

inline size_t url_search_params::size() const noexcept { return params.size(); }

inline std::optional<std::string_view> url_search_params::get(
    const std::string_view key) {
  auto entry = std::find_if(params.begin(), params.end(),
                            [&key](auto &param) { return param.first == key; });

  if (entry == params.end()) {
    return std::nullopt;
  }

  return entry->second;
}

inline std::vector<std::string> url_search_params::get_all(
    const std::string_view key) {
  std::vector<std::string> out{};

  for (auto &param : params) {
    if (param.first == key) {
      out.emplace_back(param.second);
    }
  }

  return out;
}

inline bool url_search_params::has(const std::string_view key) noexcept {
  auto entry = std::find_if(params.begin(), params.end(),
                            [&key](auto &param) { return param.first == key; });
  return entry != params.end();
}

inline std::string url_search_params::to_string() {
  auto character_set = ada::character_sets::WWW_FORM_URLENCODED_PERCENT_ENCODE;
  std::string out{};
  for (size_t i = 0; i < params.size(); i++) {
    auto key = ada::unicode::percent_encode(params[i].first, character_set);
    auto value = ada::unicode::percent_encode(params[i].second, character_set);

    // Performance optimization: Move this inside percent_encode.
    std::replace(key.begin(), key.end(), ' ', '+');
    std::replace(value.begin(), value.end(), ' ', '+');

    if (i != 0) {
      out += "&";
    }
    out.append(key);
    out += "=";
    out.append(value);
  }
  return out;
}

inline void url_search_params::set(const std::string_view key,
                                   const std::string_view value) {
  const auto find = [&key](auto &param) { return param.first == key; };

  auto it = std::find_if(params.begin(), params.end(), find);

  if (it == params.end()) {
    params.emplace_back(key, value);
  } else {
    it->second = value;
    params.erase(std::remove_if(std::next(it), params.end(), find),
                 params.end());
  }
}

inline void url_search_params::remove(const std::string_view key) {
  params.erase(
      std::remove_if(params.begin(), params.end(),
                     [&key](auto &param) { return param.first == key; }),
      params.end());
}

inline void url_search_params::remove(const std::string_view key,
                                      const std::string_view value) {
  params.erase(std::remove_if(params.begin(), params.end(),
                              [&key, &value](auto &param) {
                                return param.first == key &&
                                       param.second == value;
                              }),
               params.end());
}

inline void url_search_params::sort() {
  std::stable_sort(params.begin(), params.end(),
                   [](const key_value_pair &lhs, const key_value_pair &rhs) {
                     return lhs.first < rhs.first;
                   });
}

}  // namespace ada

#endif  // ADA_URL_SEARCH_PARAMS_INL_H

/**
 * @file url_search_params-inl.h
 * @brief Inline declarations for the URL Search Params
 */
#ifndef ADA_URL_SEARCH_PARAMS_INL_H
#define ADA_URL_SEARCH_PARAMS_INL_H

#include <algorithm>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

#include "character_sets-inl.h"
#include "unicode.h"
#include "url_search_params.h"

namespace ada {

// A default, empty url_search_params for use with empty iterators.
template <typename T, ada::url_search_params_iter_type Type>
url_search_params url_search_params_iter<T, Type>::EMPTY;

inline void url_search_params::reset(std::string_view input) {
  params.clear();
  initialize(input);
}

inline void url_search_params::initialize(std::string_view input) {
  if (!input.empty() && input.front() == '?') {
    input.remove_prefix(1);
  }

  auto process_key_value = [&](const std::string_view current) {
    auto equal = current.find('=');

    if (equal == std::string_view::npos) {
      std::string name(current);
      std::ranges::replace(name, '+', ' ');
      params.emplace_back(unicode::percent_decode(name, name.find('%')), "");
    } else {
      std::string name(current.substr(0, equal));
      std::string value(current.substr(equal + 1));

      std::ranges::replace(name, '+', ' ');
      std::ranges::replace(value, '+', ' ');

      params.emplace_back(unicode::percent_decode(name, name.find('%')),
                          unicode::percent_decode(value, value.find('%')));
    }
  };

  while (!input.empty()) {
    auto ampersand_index = input.find('&');

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
  auto entry = std::ranges::find_if(
      params, [&key](auto &param) { return param.first == key; });

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
  auto entry = std::ranges::find_if(
      params, [&key](auto &param) { return param.first == key; });
  return entry != params.end();
}

inline bool url_search_params::has(std::string_view key,
                                   std::string_view value) noexcept {
  auto entry = std::ranges::find_if(params, [&key, &value](auto &param) {
    return param.first == key && param.second == value;
  });
  return entry != params.end();
}

inline std::string url_search_params::to_string() const {
  auto character_set = ada::character_sets::WWW_FORM_URLENCODED_PERCENT_ENCODE;
  std::string out{};
  for (size_t i = 0; i < params.size(); i++) {
    auto key = ada::unicode::percent_encode(params[i].first, character_set);
    auto value = ada::unicode::percent_encode(params[i].second, character_set);

    // Performance optimization: Move this inside percent_encode.
    std::ranges::replace(key, ' ', '+');
    std::ranges::replace(value, ' ', '+');

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

  auto it = std::ranges::find_if(params, find);

  if (it == params.end()) {
    params.emplace_back(key, value);
  } else {
    it->second = value;
    params.erase(std::remove_if(std::next(it), params.end(), find),
                 params.end());
  }
}

inline void url_search_params::remove(const std::string_view key) {
  std::erase_if(params, [&key](auto &param) { return param.first == key; });
}

inline void url_search_params::remove(const std::string_view key,
                                      const std::string_view value) {
  std::erase_if(params, [&key, &value](auto &param) {
    return param.first == key && param.second == value;
  });
}

inline void url_search_params::sort() {
  std::ranges::stable_sort(
      params, [](const key_value_pair &lhs, const key_value_pair &rhs) {
        return lhs.first < rhs.first;
      });
}

inline url_search_params_keys_iter url_search_params::get_keys() {
  return url_search_params_keys_iter(*this);
}

/**
 * @see https://url.spec.whatwg.org/#interface-urlsearchparams
 */
inline url_search_params_values_iter url_search_params::get_values() {
  return url_search_params_values_iter(*this);
}

/**
 * @see https://url.spec.whatwg.org/#interface-urlsearchparams
 */
inline url_search_params_entries_iter url_search_params::get_entries() {
  return url_search_params_entries_iter(*this);
}

template <typename T, url_search_params_iter_type Type>
inline bool url_search_params_iter<T, Type>::has_next() const {
  return pos < params.params.size();
}

template <>
inline std::optional<std::string_view> url_search_params_keys_iter::next() {
  if (!has_next()) {
    return std::nullopt;
  }
  return params.params[pos++].first;
}

template <>
inline std::optional<std::string_view> url_search_params_values_iter::next() {
  if (!has_next()) {
    return std::nullopt;
  }
  return params.params[pos++].second;
}

template <>
inline std::optional<key_value_view_pair>
url_search_params_entries_iter::next() {
  if (!has_next()) {
    return std::nullopt;
  }
  return params.params[pos++];
}

}  // namespace ada

#endif  // ADA_URL_SEARCH_PARAMS_INL_H

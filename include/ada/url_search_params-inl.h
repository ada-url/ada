/**
 * @file url_search_params-inl.h
 * @brief Inline declarations for the URL Search Params
 */
#ifndef ADA_URL_SEARCH_PARAMS_INL_H
#define ADA_URL_SEARCH_PARAMS_INL_H

#include "ada/character_sets-inl.h"
#include "ada/unicode.h"
#include "ada/url_search_params.h"

#include <algorithm>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

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
  if (input.empty()) {
    return;
  }

  // Reserve roughly one slot per '&' so large query strings avoid reallocs.
  size_t ampersands = 0;
  for (const char c : input) {
    ampersands += static_cast<size_t>(c == '&');
  }
  params.reserve(ampersands + 1);

  // application/x-www-form-urlencoded: '+' -> ' ', then percent-decode.
  // Single allocation and a single pass (no intermediate string + replace).
  // Hex helpers are local: unicode::is_ascii_hex_digit is not header-inline.
  auto form_decode = [](std::string_view sv) -> std::string {
    const auto is_hex = [](const char c) noexcept {
      return (c >= '0' && c <= '9') || ((c | 0x20) >= 'a' && (c | 0x20) <= 'f');
    };
    const auto hex_val = [](const char c) noexcept -> unsigned {
      return (c >= '0' && c <= '9') ? unsigned(c - '0')
                                    : unsigned((c | 0x20) - 'a' + 10);
    };

    const char* const begin = sv.data();
    const char* const end = begin + sv.size();
    const char* p = begin;

    while (p < end && *p != '+' && *p != '%') {
      ++p;
    }
    if (p == end) {
      return std::string(sv);
    }

    std::string out;
    out.reserve(static_cast<size_t>(end - begin));
    out.append(begin, p);

    while (p < end) {
      const char ch = *p;
      if (ch == '+') {
        out.push_back(' ');
        ++p;
      } else if (ch == '%' && p + 2 < end && is_hex(p[1]) && is_hex(p[2])) {
        out.push_back(static_cast<char>(hex_val(p[1]) * 16 + hex_val(p[2])));
        p += 3;
      } else {
        // Append a run of plain bytes until the next '+' or valid '%XX'.
        const char* start = p;
        ++p;
        while (p < end) {
          if (*p == '+') {
            break;
          }
          if (*p == '%' && p + 2 < end && is_hex(p[1]) && is_hex(p[2])) {
            break;
          }
          ++p;
        }
        out.append(start, p);
      }
    }
    return out;
  };

  auto process_key_value = [&](const std::string_view current) {
    const auto equal = current.find('=');
    if (equal == std::string_view::npos) {
      params.emplace_back(form_decode(current), "");
    } else {
      params.emplace_back(form_decode(current.substr(0, equal)),
                          form_decode(current.substr(equal + 1)));
    }
  };

  while (!input.empty()) {
    const auto ampersand_index = input.find('&');

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
      params, [&key](const auto& param) { return param.first == key; });

  if (entry == params.end()) {
    return std::nullopt;
  }

  return entry->second;
}

inline std::vector<std::string> url_search_params::get_all(
    const std::string_view key) {
  std::vector<std::string> out{};

  for (auto& param : params) {
    if (param.first == key) {
      out.emplace_back(param.second);
    }
  }

  return out;
}

inline bool url_search_params::has(const std::string_view key) noexcept {
  auto entry = std::ranges::find_if(
      params, [&key](const auto& param) { return param.first == key; });
  return entry != params.end();
}

inline bool url_search_params::has(std::string_view key,
                                   std::string_view value) noexcept {
  auto entry = std::ranges::find_if(params, [&key, &value](const auto& param) {
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
  const auto find = [&key](const auto& param) { return param.first == key; };

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
  std::erase_if(params,
                [&key](const auto& param) { return param.first == key; });
}

inline void url_search_params::remove(const std::string_view key,
                                      const std::string_view value) {
  std::erase_if(params, [&key, &value](const auto& param) {
    return param.first == key && param.second == value;
  });
}

inline void url_search_params::sort() {
  // Keys are expected to be valid UTF-8, but percent_decode can produce
  // arbitrary byte sequences. Handle truncated/invalid sequences gracefully.
  std::ranges::stable_sort(params, [](const key_value_pair& lhs,
                                      const key_value_pair& rhs) {
    size_t i = 0, j = 0;
    uint32_t low_surrogate1 = 0, low_surrogate2 = 0;
    while ((i < lhs.first.size() || low_surrogate1 != 0) &&
           (j < rhs.first.size() || low_surrogate2 != 0)) {
      uint32_t codePoint1 = 0, codePoint2 = 0;

      if (low_surrogate1 != 0) {
        codePoint1 = low_surrogate1;
        low_surrogate1 = 0;
      } else {
        uint8_t c1 = uint8_t(lhs.first[i]);
        if (c1 > 0x7F && c1 <= 0xDF && i + 1 < lhs.first.size()) {
          codePoint1 = ((c1 & 0x1F) << 6) | (uint8_t(lhs.first[i + 1]) & 0x3F);
          i += 2;
        } else if (c1 > 0xDF && c1 <= 0xEF && i + 2 < lhs.first.size()) {
          codePoint1 = ((c1 & 0x0F) << 12) |
                       ((uint8_t(lhs.first[i + 1]) & 0x3F) << 6) |
                       (uint8_t(lhs.first[i + 2]) & 0x3F);
          i += 3;
        } else if (c1 > 0xEF && c1 <= 0xF7 && i + 3 < lhs.first.size()) {
          codePoint1 = ((c1 & 0x07) << 18) |
                       ((uint8_t(lhs.first[i + 1]) & 0x3F) << 12) |
                       ((uint8_t(lhs.first[i + 2]) & 0x3F) << 6) |
                       (uint8_t(lhs.first[i + 3]) & 0x3F);
          i += 4;

          codePoint1 -= 0x10000;
          uint16_t high_surrogate = uint16_t(0xD800 + (codePoint1 >> 10));
          low_surrogate1 = uint16_t(0xDC00 + (codePoint1 & 0x3FF));
          codePoint1 = high_surrogate;
        } else {
          // ASCII (c1 <= 0x7F) or truncated/invalid UTF-8: treat as raw byte
          codePoint1 = c1;
          i++;
        }
      }

      if (low_surrogate2 != 0) {
        codePoint2 = low_surrogate2;
        low_surrogate2 = 0;
      } else {
        uint8_t c2 = uint8_t(rhs.first[j]);
        if (c2 > 0x7F && c2 <= 0xDF && j + 1 < rhs.first.size()) {
          codePoint2 = ((c2 & 0x1F) << 6) | (uint8_t(rhs.first[j + 1]) & 0x3F);
          j += 2;
        } else if (c2 > 0xDF && c2 <= 0xEF && j + 2 < rhs.first.size()) {
          codePoint2 = ((c2 & 0x0F) << 12) |
                       ((uint8_t(rhs.first[j + 1]) & 0x3F) << 6) |
                       (uint8_t(rhs.first[j + 2]) & 0x3F);
          j += 3;
        } else if (c2 > 0xEF && c2 <= 0xF7 && j + 3 < rhs.first.size()) {
          codePoint2 = ((c2 & 0x07) << 18) |
                       ((uint8_t(rhs.first[j + 1]) & 0x3F) << 12) |
                       ((uint8_t(rhs.first[j + 2]) & 0x3F) << 6) |
                       (uint8_t(rhs.first[j + 3]) & 0x3F);
          j += 4;
          codePoint2 -= 0x10000;
          uint16_t high_surrogate = uint16_t(0xD800 + (codePoint2 >> 10));
          low_surrogate2 = uint16_t(0xDC00 + (codePoint2 & 0x3FF));
          codePoint2 = high_surrogate;
        } else {
          // ASCII (c2 <= 0x7F) or truncated/invalid UTF-8: treat as raw byte
          codePoint2 = c2;
          j++;
        }
      }

      if (codePoint1 != codePoint2) {
        return (codePoint1 < codePoint2);
      }
    }
    return (j < rhs.first.size() || low_surrogate2 != 0);
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

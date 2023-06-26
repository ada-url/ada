#include "ada.h"
#include "ada/url_search_params.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace ada {

void url_search_params::remove(const std::string_view key) {
  params.erase(
      std::remove_if(params.begin(), params.end(),
                     [&key](auto &param) { return param.first == key; }),
      params.end());
}

void url_search_params::remove(const std::string_view key,
                               const std::string_view value) {
  params.erase(std::remove_if(params.begin(), params.end(),
                              [&key, &value](auto &param) {
                                return param.first == key &&
                                       param.second == value;
                              }),
               params.end());
}

void url_search_params::sort() {
  std::stable_sort(params.begin(), params.end(),
                   [](const key_value_pair &lhs, const key_value_pair &rhs) {
                     return lhs.first < rhs.first;
                   });
}

void url_search_params::set(const std::string_view key,
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

std::string url_search_params::to_string() {
  std::string out{};
  for (size_t i = 0; i < params.size(); i++) {
    auto [key, value] = params[i];

    if (i != 0) {
      out += "&";
    }
    out.append(key);
    out += "=";
    out.append(value);
  }
  return out;
}

}  // namespace ada

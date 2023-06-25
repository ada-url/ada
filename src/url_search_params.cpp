#include "ada.h"
#include "ada/url_search_params.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ada {

inline void url_search_params::remove(const std::string_view key) {
  params.erase(
      std::remove_if(params.begin(), params.end(),
                     [&key](auto param) { return std::get<0>(param) == key; }),
      params.end());
}

inline void url_search_params::remove(const std::string_view key,
                                      std::string_view value) {
  params.erase(std::remove_if(params.begin(), params.end(),
                              [&key, &value](auto param) {
                                return std::get<0>(param) == key &&
                                       std::get<1>(param) == value;
                              }),
               params.end());
}

inline void url_search_params::sort() const noexcept {
  // TODO: Implement this
}

inline void url_search_params::set(const std::string_view key,
                                   const std::string_view value) {
  params.erase(
      std::remove_if(params.begin(), params.end(),
                     [&key](auto param) { return std::get<0>(param) == key; }),
      params.end());

  params.emplace_back(std::string(key), std::string(value));
}

std::string url_search_params::to_string() {
  std::string out{};
  for (size_t i = 0; i < params.size(); i++) {
    auto param = params[i];
    auto key = std::get<0>(param);
    auto value = std::get<1>(param);

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

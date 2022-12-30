#include "ada.h"
#include "scheme.cpp"

namespace ada {

  ada_really_inline std::optional<uint16_t> url::scheme_default_port() const {
    auto result = scheme::SPECIAL_SCHEME.find(scheme);

    if (result == scheme::SPECIAL_SCHEME.end()) {
      return std::nullopt;
    }

    return result->second;
  }

  ada_really_inline bool url::is_special() const {
    return scheme::SPECIAL_SCHEME.count(scheme);
  }

} // namespace ada

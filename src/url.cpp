#include "ada.h"
#include "scheme.cpp"

namespace ada {

  ada_really_inline std::optional<uint16_t> url::scheme_default_port() const {
    if (!is_special()) {
      return std::nullopt;
    }

    return scheme::SPECIAL_SCHEME.find(scheme)->second;
  }

  ada_really_inline bool url::is_special() const {
    return scheme::is_special(scheme);
  }

} // namespace ada

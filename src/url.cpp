#include "ada.h"
#include "ada/scheme.h"

namespace ada {

  ada_really_inline uint16_t url::scheme_default_port() const {
    return scheme::get_special_port(scheme);
  }

  ada_really_inline bool url::is_special() const {
    return scheme::is_special(scheme);
  }

  std::string url::to_string() {
    if (!is_valid) {
      return "null";
    }
    // TODO: make sure that this is valid JSON by encoding the strings.
    return "{\"scheme\":\"" + scheme + "\"" + ","
         + "\"username\":\"" + username + "\"" + "," + "\"password\":\"" +
         password + "\"" + "," +
         (host.has_value() ? "\"host\":\"" + host.value() + "\"" + "," : "") +
         (port.has_value() ? "\"port\":" + std::to_string(port.value()) + "" + ","
                         : "") +
         "\"path\":\"" + path + "\"" +
         (query.has_value() ? ",\"query\":\"" + query.value() + "\"" + ","
                          : "") +
         (fragment.has_value()
              ? ",\"fragment\":\"" + fragment.value() + "\"" + ","
              : "") + "}";
  }

} // namespace ada

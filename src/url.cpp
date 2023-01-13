#include "ada.h"
#include "scheme.cpp"

namespace ada {

  ada_warn_unused std::string to_string(ada::host_type type) {
    switch(type) {
    case ada::host_type::BASIC_DOMAIN : return "basic";
    case ada::host_type::IPV6_ADDRESS : return "ipv6";
    case ada::host_type::IPV4_ADDRESS : return "ipv4";
    case ada::host_type::OPAQUE_HOST : return "opaque";
    default: unreachable();
    }
  }

  ada_warn_unused std::string url_host::to_string() {
    return "{\"type\":\"" + ada::to_string(type) + "\",\"entry\":\"" + entry + "\"}";
  }

  ada_really_inline std::optional<uint16_t> url::scheme_default_port() const {
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
         (host.has_value() ? "\"host\":\"" + host.value().to_string() + "\"" + "," : "") +
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

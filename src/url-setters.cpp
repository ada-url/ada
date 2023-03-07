/**
 * @file url-setters.cpp
 * Includes all the setters of `ada::url`
 */
#include "ada.h"
#include "ada/helpers.h"

#include <optional>
#include <string>

namespace ada {

  bool url::set_host_or_hostname(const std::string_view input, bool override_hostname) {
    if (has_opaque_path) { return false; }

    std::optional<std::string> previous_host = host;
    std::optional<uint16_t> previous_port = port;

    size_t host_end_pos = input.find('#');
    std::string _host(input.data(), host_end_pos != std::string_view::npos ? host_end_pos : input.size());
    helpers::remove_ascii_tab_or_newline(_host);
    std::string_view new_host(_host);

    // If url's scheme is "file", then set state to file host state, instead of host state.
    if (type != ada::scheme::type::FILE) {
      std::string_view host_view(_host.data(), _host.length());
      auto [location,found_colon] = helpers::get_host_delimiter_location(is_special(), host_view);

      // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
      // Note: the 'found_colon' value is true if and only if a colon was encountered
      // while not inside brackets.
      if (found_colon) {
        if (override_hostname) { return false; }
        std::string_view  buffer = new_host.substr(location+1);
        if (!buffer.empty()) { set_port(buffer); }
      }
      // If url is special and host_view is the empty string, validation error, return failure.
      // Otherwise, if state override is given, host_view is the empty string,
      // and either url includes credentials or url’s port is non-null, return.
      else if (host_view.empty() && (is_special() || includes_credentials() || port.has_value())) {
        return false;
      }

      // Let host be the result of host parsing host_view with url is not special.
      if (host_view.empty()) {
        host = "";
        return true;
      }

      bool succeeded = parse_host(host_view);
      if (!succeeded) {
        host = previous_host;
        update_base_port(previous_port);
      }
      return succeeded;
    }

    size_t location = new_host.find_first_of("/\\?");
    if (location != std::string_view::npos) { new_host.remove_suffix(new_host.length() - location); }

    if (new_host.empty()) {
      // Set url’s host to the empty string.
      host = "";
    }
    else {
      // Let host be the result of host parsing buffer with url is not special.
      if (!parse_host(new_host)) {
        host = previous_host;
        update_base_port(previous_port);
        return false;
      }

      // If host is "localhost", then set host to the empty string.
      if (host.has_value() && host.value() == "localhost") {
        host = "";
      }
    }
    return true;
  }

  bool url::set_host(const std::string_view input) {
    return set_host_or_hostname(input, false);
  }

  bool url::set_hostname(const std::string_view input) {
    return set_host_or_hostname(input, true);
  }

  bool url::set_href(const std::string_view input) {
    ada::result out = ada::parse(input);

    if (out) {
      username = out->username;
      password = out->password;
      host = out->host;
      update_base_port(out->retrieve_base_port());
      path = out->path;
      query = out->query;
      fragment = out->fragment;
      type = out->type;
      non_special_scheme = out->non_special_scheme;
      has_opaque_path = out->has_opaque_path;
    }

    return out.has_value();
  }

} // namespace ada

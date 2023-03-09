#include "ada.h"
#include "ada/checkers-inl.h"
#include "ada/implementation.h"
#include "ada/url_components.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"
#include "ada/parser.h"

#include <string>
#include <string_view>

namespace ada {

bool url_aggregator::set_href(const std::string_view input) {
  ada::result<url_aggregator> out = ada::parse<url_aggregator>(input);

  if (out) {
    components = out->get_components();
    copy_scheme(*out);
  }

  return out.has_value();
}

bool url_aggregator::set_host(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

bool url_aggregator::set_hostname(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

[[nodiscard]] std::string url_aggregator::get_href() const noexcept {
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_username() const noexcept {
  bool has_authority = checkers::begins_with(buffer.substr(components.protocol_end, 3), "://");
  if (has_authority && components.username_end > components.protocol_end + 3) {
    return buffer.substr(components.protocol_end + 3, components.username_end);
  }
  return "";
}

[[nodiscard]] std::string url_aggregator::get_password() const noexcept {
  bool has_authority = checkers::begins_with(buffer.substr(components.protocol_end, 3), "://");
  if (has_authority && components.username_end != buffer.length() && buffer[components.username_end] == ':') {
    return buffer.substr(components.username_end + 1, components.host_start - 1);
  }
  return "";
}

[[nodiscard]] std::string url_aggregator::get_port() const noexcept {
  if (components.port == url_components::omitted) { return ""; }
  return std::to_string(components.port);
}

[[nodiscard]] std::string url_aggregator::get_hash() const noexcept {
  if (components.hash_start == url_components::omitted) { return ""; }
  return buffer.substr(components.hash_start);
}

[[nodiscard]] std::string url_aggregator::get_host() const noexcept {
  return buffer.substr(components.host_start, components.host_end);
}

[[nodiscard]] std::string url_aggregator::get_hostname() const noexcept {
  std::string suffix = components.port == url_components::omitted ? "" : ":" + std::to_string(components.port);
  return get_host() + suffix;
}

[[nodiscard]] std::string url_aggregator::get_pathname() const noexcept {
  if (components.pathname_start == url_components::omitted) { return ""; }
  auto ending_index = std::string_view::npos;
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  return buffer.substr(components.pathname_start, ending_index);
}

[[nodiscard]] std::string url_aggregator::get_search() const noexcept {
  if (components.search_start == url_components::omitted) { return ""; }
  auto ending_index = std::string_view::npos;
  if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  return buffer.substr(components.search_start, ending_index);
}

[[nodiscard]] std::string url_aggregator::get_protocol() const noexcept {
  return buffer.substr(0, components.protocol_end);
}

[[nodiscard]] ada_really_inline ada::url_components url_aggregator::get_components() noexcept {
  return components;
}

std::string ada::url_aggregator::to_string() const {
  return components.to_string();
}

} // namespace ada

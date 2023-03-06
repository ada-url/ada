#include "ada/url_components.h"
#include "ada/url_aggregator.h"

#include <string>
#include <string_view>

namespace ada {

bool url_aggregator::set_username(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

bool url_aggregator::set_password(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

bool url_aggregator::set_href(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

bool url_aggregator::set_port(const std::string_view input) {
  // TODO: Implement this
  void (input.size());
  return false;
}

void url_aggregator::set_search(const std::string_view input) {
  // TOOD: Implement this
  void(input.size());
}

bool url_aggregator::set_pathname(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
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

bool url_aggregator::set_protocol(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

[[nodiscard]] std::string url_aggregator::get_href() const noexcept {
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_origin() const noexcept {
  // TODO: Implement this
  return "null";
}

[[nodiscard]] std::string url_aggregator::get_username() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_password() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_port() const noexcept {
  if (components.port == url_components::omitted) { return ""; }
  return std::to_string(components.port);
}

[[nodiscard]] std::string url_aggregator::get_hash() const noexcept {
  if (components.hash_start == url_components::omitted) {
    return "";
  }
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
  if (components.hash_start == url_components::omitted) { ending_index = components.hash_start; }
  return buffer.substr(components.search_start, ending_index);
}

void url_aggregator::update_base_fragment(const std::string_view input) {
  if (components.hash_start != url_components::omitted) {
    buffer.resize(components.hash_start);
  }

  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  buffer.append(input);
}

[[nodiscard]] ada_really_inline ada::url_components url_aggregator::get_components() noexcept {
  return components;
}

} // namespace ada

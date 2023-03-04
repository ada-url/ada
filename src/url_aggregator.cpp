#include "ada/url_components.h"
#include "ada/url_aggregator.h"

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

bool set_hostname(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

bool set_protocol(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
  return false;
}

[[nodiscard]] ada_really_inline ada::url_components url_aggregator::get_components() noexcept {
  return components;
}

[[nodiscard]] std::string url_aggregator::get_origin() const noexcept {
  // TODO: Implement this
  return "null";
}

[[nodiscard]] std::string url_aggregator::get_password() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_port() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_hash() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_host() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_hostname() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_pathname() const noexcept {
  // TODO: Implement this
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_search() const noexcept {
  // TODO: Implement this
  return buffer;
}

void url_aggregator::update_base_fragment(const std::string_view input) {
  // TODO: Implement this
  void(input.size());
}

} // namespace ada

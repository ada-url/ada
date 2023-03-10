#include "ada.h"
#include "ada/implementation.h"
#include "ada/url_components.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"
#include "ada/parser.h"

#include <string>
#include <string_view>

namespace ada {
template <bool has_state_override>
[[nodiscard]] ada_really_inline bool url_aggregator::parse_scheme(const std::string_view input) {
  (void)input;
  // TODO: implement
  return true;
}

inline void url_aggregator::copy_scheme(const url_aggregator& u) noexcept {
  (void)u;
  // TODO: implement
}

inline void url_aggregator::set_scheme(std::string_view new_scheme) noexcept {
  (void)new_scheme;
  // TODO: implement
}

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

[[nodiscard]] const std::string& url_aggregator::get_href() const noexcept {
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_origin() const noexcept {
  // TODO: Implement this
  return "null";
}

[[nodiscard]] std::string_view url_aggregator::get_username() const noexcept {
  // TODO: Implement this properly
  return helpers::substring(buffer, components.protocol_end, components.username_end);
}

[[nodiscard]] std::string_view url_aggregator::get_password() const noexcept {
  // TODO: Implement this properly
  return helpers::substring(buffer, components.username_end, components.host_start);
}

[[nodiscard]] std::string_view url_aggregator::get_port() const noexcept {
  if (components.port == url_components::omitted) { return ""; }
  return helpers::substring(buffer, components.host_end, components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_hash() const noexcept {
  if (components.hash_start == url_components::omitted) { return ""; }
  return helpers::substring(buffer, components.hash_start);
}

[[nodiscard]] std::string_view url_aggregator::get_host() const noexcept {
  return helpers::substring(buffer, components.host_start, components.host_end);
}

[[nodiscard]] std::string_view url_aggregator::get_hostname() const noexcept {
  if(components.port == url_components::omitted) { return get_host(); }
  return helpers::substring(buffer, components.host_start, components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_pathname() const noexcept {
  if (components.pathname_start == url_components::omitted) { return ""; }
  auto ending_index = buffer.size();
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  return helpers::substring(buffer, components.pathname_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_search() const noexcept {
  if (components.search_start == url_components::omitted) { return ""; }
  auto ending_index = buffer.size();
  if (components.hash_start == url_components::omitted) { ending_index = components.hash_start; }
  return helpers::substring(buffer, components.search_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_protocol() const noexcept {
  return helpers::substring(buffer, 0, components.protocol_end);
}

std::string ada::url_aggregator::to_string() const {
  return components.to_string();
}

} // namespace ada

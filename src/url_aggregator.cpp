#include "ada.h"
#include "ada/checkers-inl.h"
#include "ada/checkers.h"
#include "ada/helpers.h"
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

bool url_aggregator::set_protocol(const std::string_view input) {
  (void) input;
  // TODO: Implement
  return false;
}

bool url_aggregator::set_username(const std::string_view input) {
  if (cannot_have_credentials_or_port()) { return false; }
  size_t username_start = components.protocol_end + 3;
  size_t username_length = components.username_end - username_start;
  buffer.erase(username_start, components.username_end);

  std::string encoded_input = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  buffer.append(encoded_input, username_start);

  size_t new_difference = encoded_input.size() - username_length;
  if (new_difference == 0) { return true; }

  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) { components.search_start += new_difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += new_difference; }

  return true;
}

bool url_aggregator::set_password(const std::string_view input) {
  (void) input;
  // TODO: Implement
  return false;
}

bool url_aggregator::set_port(const std::string_view input) {
  (void) input;
  // TODO: Implement
  return false;
}

bool url_aggregator::set_pathname(const std::string_view input) {
  (void) input;
  // TODO: Implement
  return false;
}

bool url_aggregator::set_search(const std::string_view input) {
  (void) input;
  // TODO: Implement
  return false;
}

bool url_aggregator::set_hash(const std::string_view input) {
  (void) input;
  // TODO: Implement
  return false;
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
  if (is_special()) {
    // Return a new opaque origin.
    if (type == scheme::FILE) { return "null"; }

    return helpers::concat(get_protocol(), "//", get_host());
  }

  if (checkers::begins_with(get_protocol(), "blob")) {
    std::string_view path = retrieve_base_pathname();
    if (path.length() > 0) {
      ada::result<ada::url> path_result = ada::parse<ada::url>(path);
      if (path_result) {
        if (path_result->is_special()) {
          return path_result->get_protocol() + "//" + path_result->get_host();
        }
      }
    }
  }

  // Return a new opaque origin.
  return "null";
}

[[nodiscard]] std::string_view url_aggregator::get_username() const noexcept {
  bool has_authority = checkers::begins_with(buffer.substr(components.protocol_end, 3), "://");
  if (has_authority && components.username_end > components.protocol_end + 3) {
    return helpers::substring(buffer, components.protocol_end + 3, components.username_end);
  }
  return "";
}

[[nodiscard]] std::string_view url_aggregator::get_password() const noexcept {
  bool has_authority = checkers::begins_with(buffer.substr(components.protocol_end, 3), "://");
  if (has_authority && components.username_end != buffer.length() && buffer[components.username_end] == ':') {
    return helpers::substring(buffer, components.username_end + 1, components.host_start - 1);
  }
  return "";
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
  if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  return helpers::substring(buffer, components.search_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_protocol() const noexcept {
  return helpers::substring(buffer, 0, components.protocol_end);
}

std::string ada::url_aggregator::to_string() const {
  return components.to_string();
}

[[nodiscard]] bool url_aggregator::has_valid_domain() const noexcept {
  // TODO: if(!base_hostname_has_value()) { return false; }
  return checkers::verify_dns_length(get_hostname());
}

} // namespace ada

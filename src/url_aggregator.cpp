#include "ada.h"
#include "ada/checkers-inl.h"
#include "ada/checkers.h"
#include "ada/helpers.h"
#include "ada/implementation.h"
#include "ada/scheme.h"
#include "ada/url_components.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"
#include "ada/parser.h"

#include <string>
#include <string_view>

namespace ada {
template <bool has_state_override>
[[nodiscard]] ada_really_inline bool url_aggregator::parse_scheme(const std::string_view input) {
  auto parsed_type = ada::scheme::get_scheme_type(input);
  bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
  /**
   * In the common case, we will immediately recognize a special scheme (e.g., http, https),
   * in which case, we can go really fast.
   **/
  if(is_input_special) { // fast path!!!
    if (has_state_override) {
      // If url’s scheme is not a special scheme and buffer is a special scheme, then return.
      if (is_special() != is_input_special) { return true; }

      // If url includes credentials or has a non-null port, and buffer is "file", then return.
      if ((includes_credentials() || components.port != url_components::omitted) && parsed_type == ada::scheme::type::FILE) { return true; }

      // If url’s scheme is "file" and its host is an empty host, then return. An empty host is the empty string.
      if (type == ada::scheme::type::FILE && components.host_start == components.host_end) { return true; }
    }

    set_scheme(input);

    if (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url’s port is url’s scheme’s default port, then set url’s port to null.
        if (components.port == urls_scheme_port) { components.port = url_components::omitted; }
      }
    }
  } else { // slow path
    std::string _buffer = std::string(input);
    // Next function is only valid if the input is ASCII and returns false
    // otherwise, but it seems that we always have ascii content so we do not need
    // to check the return value.
    unicode::to_lower_ascii(_buffer.data(), _buffer.size());

    if (has_state_override) {
      // If url’s scheme is a special scheme and buffer is not a special scheme, then return.
      // If url’s scheme is not a special scheme and buffer is a special scheme, then return.
      if (is_special() != ada::scheme::is_special(_buffer)) { return true; }

      // If url includes credentials or has a non-null port, and buffer is "file", then return.
      if ((includes_credentials() || components.port != url_components::omitted) && _buffer == "file") {
        return true;
      }

      // If url’s scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE && components.host_start == components.host_end) { return true; }
    }

    set_scheme(std::move(_buffer));

    if (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url’s port is url’s scheme’s default port, then set url’s port to null.
        if (components.port == urls_scheme_port) { components.port = url_components::omitted; }
      }
    }
  }
  return true;
}

inline void url_aggregator::copy_scheme(const url_aggregator& u) noexcept {
  uint32_t new_difference = u.components.protocol_end - components.protocol_end;
  type = u.type;
  buffer.erase(0, components.protocol_end);
  buffer.insert(0, u.buffer.substr(0, components.protocol_end));
  components.protocol_end = u.components.protocol_end;

  // No need to update the components
  if (new_difference == 0) { return; }

  // Update the rest of the components.
  components.username_end += new_difference;
  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) { components.search_start += new_difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += new_difference; }
}

inline void url_aggregator::set_scheme(std::string_view new_scheme) noexcept {
  uint32_t new_difference = uint32_t(new_scheme.size() + 1) - components.protocol_end - 1;
  type = ada::scheme::get_scheme_type(new_scheme);
  buffer.erase(0, components.protocol_end);
  buffer.insert(0, helpers::concat(new_scheme, ":"));
  components.protocol_end = uint32_t(new_scheme.size() + 1);

  // No need to update the components
  if (new_difference == 0) { return; }

  // Update the rest of the components.
  components.username_end += new_difference;
  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) { components.search_start += new_difference; }
  if (components.hash_start != url_components::omitted) { components.hash_start += new_difference; }
}

bool url_aggregator::set_protocol(const std::string_view input) {
  std::string view(input);
  helpers::remove_ascii_tab_or_newline(view);
  if (view.empty()) { return true; }

  // Schemes should start with alpha values.
  if (!checkers::is_alpha(view[0])) { return false; }

  view.append(":");

  std::string::iterator pointer = std::find_if_not(view.begin(), view.end(), unicode::is_alnum_plus);

  if (pointer != view.end() && *pointer == ':') {
    return parse_scheme<true>(std::string_view(view.data(), pointer - view.begin()));
  }
  return false;
}

bool url_aggregator::set_username(const std::string_view input) {
  if (cannot_have_credentials_or_port()) { return false; }
  size_t username_start = components.protocol_end + 3;
  size_t username_length = components.username_end - username_start;
  buffer.erase(username_start, components.username_end);

  // Optimization opportunity: Avoid temporary string creation
  std::string encoded_input = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  buffer.insert(username_start, encoded_input);

  uint32_t new_difference = uint32_t(encoded_input.size() - username_length);
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

void url_aggregator::set_hash(const std::string_view input) {
  if (input.empty()) {
    if (components.hash_start != url_components::omitted) {
      buffer.resize(components.hash_start);
      components.hash_start = url_components::omitted;
    }
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '#' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);

  if (components.hash_start != url_components::omitted) {
    buffer.resize(components.hash_start);
  }
  components.hash_start = uint32_t(buffer.size());
  buffer += "#";
  buffer.append(unicode::percent_encode(new_value, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
}

bool url_aggregator::set_href(const std::string_view input) {
  ada::result<url_aggregator> out = ada::parse<url_aggregator>(input);

  if (out) {
    // TODO: Figure out why the following line puts test to never finish.
//    buffer = out->buffer;
    components = out->get_components();
    type = out->type;
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

  if (get_protocol() == "blob:") {
    std::string_view path = retrieve_base_pathname();
    if (path.size() > 0) {
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
  if (has_authority() && components.username_end > components.protocol_end + 3) {
    return helpers::substring(buffer, components.protocol_end + 3, components.username_end);
  }
  return "";
}

[[nodiscard]] std::string_view url_aggregator::get_password() const noexcept {
  if (has_authority() && components.username_end != buffer.size() && buffer[components.username_end] == ':') {
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
  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");

  answer.append("\t\"buffer\":\"");
  helpers::encode_json(buffer, back);
  answer.append("\",\n");

  answer.append("\t\"protocol_end\":\"");
  helpers::encode_json(std::to_string(components.protocol_end), back);
  answer.append("\",\n");

  answer.append("\t\"username_end\":\"");
  helpers::encode_json(std::to_string(components.username_end), back);
  answer.append("\",\n");

  answer.append("\t\"host_start\":\"");
  helpers::encode_json(std::to_string(components.host_start), back);
  answer.append("\",\n");

  answer.append("\t\"host_end\":\"");
  helpers::encode_json(std::to_string(components.host_end), back);
  answer.append("\",\n");

  answer.append("\t\"port\":\"");
  helpers::encode_json(std::to_string(components.port), back);
  answer.append("\",\n");

  answer.append("\t\"pathname_start\":\"");
  helpers::encode_json(std::to_string(components.pathname_start), back);
  answer.append("\",\n");

  answer.append("\t\"search_start\":\"");
  helpers::encode_json(std::to_string(components.search_start), back);
  answer.append("\",\n");

  answer.append("\t\"hash_start\":\"");
  helpers::encode_json(std::to_string(components.hash_start), back);
  answer.append("\",\n");

  answer.append("\n}");
  return answer;
}

[[nodiscard]] bool url_aggregator::has_valid_domain() const noexcept {
  // TODO: if(!base_hostname_has_value()) { return false; }
  return checkers::verify_dns_length(get_hostname());
}

} // namespace ada

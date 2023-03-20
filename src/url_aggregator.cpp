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
  ada_log("url_aggregator::parse_scheme ", input);
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
  ada_log("url_aggregator::copy_scheme ", u.buffer);
  uint32_t new_difference = u.components.protocol_end - components.protocol_end;
  type = u.type;
  buffer.erase(0, components.protocol_end);
  buffer.insert(0, u.get_protocol());
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
  ada_log("url_aggregator::set_scheme ", new_scheme);
  uint32_t new_difference = uint32_t(new_scheme.size()) - components.protocol_end;

  // Optimization opportunity: Get rid of this branch
  if (new_scheme.back() != ':') { new_difference += 1; }

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
  ada_log("url_aggregator::set_protocol ", input);
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
  ada_log("url_aggregator::set_username '", input, "' ");
  if (cannot_have_credentials_or_port()) { return false; }
  // Optimization opportunity: Avoid temporary string creation
  std::string encoded_input = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  update_base_username(encoded_input);
  return true;
}

bool url_aggregator::set_password(const std::string_view input) {
  ada_log("url_aggregator::set_password '", input, "'");
  if (cannot_have_credentials_or_port()) { return false; }
  // Optimization opportunity: Avoid temporary string creation
  std::string encoded_input = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  update_base_password(encoded_input);
  return true;
}

bool url_aggregator::set_port(const std::string_view input) {
  ada_log("url_aggregator::set_port ", input);
  if (cannot_have_credentials_or_port()) { return false; }
  std::string trimmed(input);
  helpers::remove_ascii_tab_or_newline(trimmed);
  if (trimmed.empty()) { clear_base_port(); return true; }
  // Input should not start with control characters.
  if (ada::unicode::is_c0_control_or_space(trimmed.front())) { return false; }
  // Input should contain at least one ascii digit.
  if (input.find_first_of("0123456789") == std::string_view::npos) { return false; }

  // Revert changes if parse_port fails.
  uint32_t previous_port = components.port;
  parse_port(trimmed);
  if (is_valid) { return true; }
  update_base_port(previous_port);
  is_valid = true;
  return false;
}

bool url_aggregator::set_pathname(const std::string_view input) {
  ada_log("url_aggregator::set_pathname ", input);
  if (has_opaque_path) { return false; }
  clear_base_pathname();
  parse_path(input);
  return true;
}

ada_really_inline void url_aggregator::parse_path(std::string_view input) {
  ada_log("url_aggregator::parse_path ", input);

  // The next line is required for parsing URLs like "file:/c:/foo/bar.html" where
  // There isn't any hostname but protocol with a pathname. Therefore, the responsability of
  // adding "//" might belong to pathname setter.
  add_authority_slashes_if_needed();

  std::string tmp_buffer;
  std::string_view internal_input;
  if(unicode::has_tabs_or_newline(input)) {
    tmp_buffer = input;
    // Optimization opportunity: Instead of copying and then pruning, we could just directly
    // build the string from user_input.
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = input;
  }

  // If url is special, then:
  if (is_special()) {
    std::string path{};
    if(internal_input.empty()) {
      update_base_pathname("/");
      return;
    } else if((internal_input[0] == '/') || (internal_input[0] == '\\')) {
      helpers::parse_prepared_path(internal_input.substr(1), type, path);
      update_base_pathname(path);
      return;
    } else {
      helpers::parse_prepared_path(internal_input, type, path);
      update_base_pathname(path);
      return;
    }
  } else if (!internal_input.empty()) {
    std::string path{};
    if(internal_input[0] == '/') {
      helpers::parse_prepared_path(internal_input.substr(1), type, path);
      update_base_pathname(path);
      return;
    } else {
      helpers::parse_prepared_path(internal_input, type, path);
      update_base_pathname(path);
      return;
    }
  } else if(components.host_start == components.host_end) {
    update_base_pathname("/");
  }
  return;
}

void url_aggregator::set_search(const std::string_view input) {
  ada_log("url_aggregator::set_search ", input);
  if (input.empty()) {
    clear_base_search();
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '?' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);

  auto query_percent_encode_set = is_special() ?
    ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
    ada::character_sets::QUERY_PERCENT_ENCODE;

  update_base_search(new_value, query_percent_encode_set);
}

void url_aggregator::set_hash(const std::string_view input) {
  ada_log("url_aggregator::set_hash ", input);
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
  update_unencoded_base_hash(new_value);
}

bool url_aggregator::set_href(const std::string_view input) {
  ada_log("url_aggregator::set_href ", input, "[", input.size(), " bytes]");
  ada::result<url_aggregator> out = ada::parse<url_aggregator>(input);
  ada_log("url_aggregator::set_href, success :", out.has_value());

  if (out) {
     ada_log("url_aggregator::set_href, parsed ", out->to_string());
    // TODO: Figure out why the following line puts test to never finish.
    *this = *out;
  }

  return out.has_value();
}

ada_really_inline bool url_aggregator::parse_host(std::string_view input) {
  ada_log("url_aggregator:parse_host ", input, "[", input.size(), " bytes]");
  if(input.empty()) { return is_valid = false; } // technically unnecessary.
  // If input starts with U+005B ([), then:
  if (input[0] == '[') {
    // If input does not end with U+005D (]), validation error, return failure.
    if (input.back() != ']') {
      return is_valid = false;
    }
    ada_log("parse_host ipv6");

    // Return the result of IPv6 parsing input with its leading U+005B ([) and trailing U+005D (]) removed.
    input.remove_prefix(1);
    input.remove_suffix(1);
    return parse_ipv6(input);
  }

  // If isNotSpecial is true, then return the result of opaque-host parsing input.
  if (!is_special()) {
    return parse_opaque_host(input);
  }
  // Let domain be the result of running UTF-8 decode without BOM on the percent-decoding of input.
  // Let asciiDomain be the result of running domain to ASCII with domain and false.
  // The most common case is an ASCII input, in which case we do not need to call the expensive 'to_ascii'
  // if a few conditions are met: no '%' and no 'xn-' subsequence.
  std::string _buffer = std::string(input);
  // This next function checks that the result is ascii, but we are going to
  // to check anyhow with is_forbidden.
  // bool is_ascii =
  unicode::to_lower_ascii(_buffer.data(), _buffer.size());
  bool is_forbidden = unicode::contains_forbidden_domain_code_point(_buffer.data(), _buffer.size());
  if (is_forbidden == 0 && _buffer.find("xn-") == std::string_view::npos) {
    // fast path
    update_base_hostname(_buffer);
    if (checkers::is_ipv4(get_hostname())) {
      ada_log("parse_host fast path ipv4");
      return parse_ipv4(get_hostname());
    }
    ada_log("parse_host fast path ", get_hostname());
    return true;
  }
  ada_log("parse_host calling to_ascii");
  std::optional<std::string> host = std::string(get_hostname());
  is_valid = ada::unicode::to_ascii(host, input, false,  input.find('%'));
  if (!is_valid) {
    ada_log("parse_host to_ascii returns false");
    return is_valid = false;
  }

  if(std::any_of(host.value().begin(), host.value().end(), ada::unicode::is_forbidden_domain_code_point)) {
    return is_valid = false;
  }

  // If asciiDomain ends in a number, then return the result of IPv4 parsing asciiDomain.
  if(checkers::is_ipv4(host.value())) {
    ada_log("parse_host got ipv4", *host);
    return parse_ipv4(host.value());
  }

  update_base_hostname(host.value());
  return true;
}

template <bool override_hostname>
bool url_aggregator::set_host_or_hostname(const std::string_view input) {
  ada_log("url_aggregator::set_host_or_hostname ", input);
  if (has_opaque_path) { return false; }

  std::string previous_host = std::string(get_hostname());
  uint32_t previous_port = components.port;

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
      std::string_view sub_buffer = new_host.substr(location+1);
      if (!sub_buffer.empty()) { set_port(sub_buffer); }
    }
    // If url is special and host_view is the empty string, validation error, return failure.
    // Otherwise, if state override is given, host_view is the empty string,
    // and either url includes credentials or url’s port is non-null, return.
    else if (host_view.empty() && (is_special() || includes_credentials() || components.port != url_components::omitted)) {
      return false;
    }

    // Let host be the result of host parsing host_view with url is not special.
    if (host_view.empty()) {
      clear_base_hostname();
      return true;
    }

    bool succeeded = parse_host(host_view);
    if (!succeeded) {
      update_base_hostname(previous_host);
      update_base_port(previous_port);
    }
    return succeeded;
  }

  size_t location = new_host.find_first_of("/\\?");
  if (location != std::string_view::npos) { new_host.remove_suffix(new_host.length() - location); }

  if (new_host.empty()) {
    // Set url’s host to the empty string.
    clear_base_hostname();
  }
  else {
    // Let host be the result of host parsing buffer with url is not special.
    if (!parse_host(new_host)) {
      update_base_hostname(previous_host);
      update_base_port(previous_port);
      return false;
    }

    // If host is "localhost", then set host to the empty string.
    if (helpers::substring(buffer, components.host_start, components.host_end) == "localhost") {
      clear_base_hostname();
    }
  }
  return true;
}

bool url_aggregator::set_host(const std::string_view input) {
  ada_log("url_aggregator::set_host ", input);
  return set_host_or_hostname<false>(input);
}

bool url_aggregator::set_hostname(const std::string_view input) {
  ada_log("url_aggregator::set_hostname ", input);
  return set_host_or_hostname<true>(input);
}

[[nodiscard]] const std::string& url_aggregator::get_href() const noexcept {
  ada_log("url_aggregator::get_href");
  return buffer;
}

[[nodiscard]] std::string url_aggregator::get_origin() const noexcept {
  ada_log("url_aggregator::get_origin");
  if (is_special()) {
    // Return a new opaque origin.
    if (type == scheme::FILE) { return "null"; }

    return helpers::concat(get_protocol(), "//", get_host());
  }

  if (get_protocol() == "blob:") {
    std::string_view path = retrieve_base_pathname();
    if (!path.empty()) {
      ada::result<ada::url> out = ada::parse<ada::url>(path);
      if (out) {
        if (out->is_special()) {
          return out->get_protocol() + "//" + out->get_host();
        }
      }
    }
  }

  // Return a new opaque origin.
  return "null";
}

[[nodiscard]] std::string_view url_aggregator::get_username() const noexcept {
  ada_log("url_aggregator::get_username");
  /**
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *      |      |    |          | ^^^^|       |   |
   *      |      |    |          | |   |       |   `----- hash_start
   *      |      |    |          | |   |       `--------- search_start
   *      |      |    |          | |   `----------------- pathname_start
   *      |      |    |          | `--------------------- port
   *      |      |    |          `----------------------- host_end
   *      |      |    `---------------------------------- host_start
   *      |      `--------------------------------------- username_end
   *      `---------------------------------------------- protocol_end
   */
  if (components.protocol_end + 2 < components.username_end) {
    return helpers::substring(buffer, components.protocol_end + 2, components.username_end);
  }
  return "";
}

[[nodiscard]] std::string_view url_aggregator::get_password() const noexcept {
  ada_log("url_aggregator::get_password");
  /**
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *      |      |    |          | ^^^^|       |   |
   *      |      |    |          | |   |       |   `----- hash_start
   *      |      |    |          | |   |       `--------- search_start
   *      |      |    |          | |   `----------------- pathname_start
   *      |      |    |          | `--------------------- port
   *      |      |    |          `----------------------- host_end
   *      |      |    `---------------------------------- host_start
   *      |      `--------------------------------------- username_end
   *      `---------------------------------------------- protocol_end
   */
  if (buffer.size() > components.username_end && buffer[components.username_end] == ':') {
    size_t ending_index = components.host_start;
    if (buffer[ending_index] == '@') { ending_index--; }
    return helpers::substring(buffer, components.username_end + 1, components.host_start);
  }
  return "";
}

[[nodiscard]] uint32_t url_aggregator::get_password_length() const noexcept {
  ada_log("url_aggregator::get_password_length");
  /**
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *      |      |    |          | ^^^^|       |   |
   *      |      |    |          | |   |       |   `----- hash_start
   *      |      |    |          | |   |       `--------- search_start
   *      |      |    |          | |   `----------------- pathname_start
   *      |      |    |          | `--------------------- port
   *      |      |    |          `----------------------- host_end
   *      |      |    `---------------------------------- host_start
   *      |      `--------------------------------------- username_end
   *      `---------------------------------------------- protocol_end
   */
  if (components.username_end + 1 < components.host_start) {
    return components.host_start - components.username_end + 1;
  }
  return 0;
}

[[nodiscard]] std::string_view url_aggregator::get_port() const noexcept {
  ada_log("url_aggregator::get_port");
  if (components.port == url_components::omitted) { return ""; }
  return helpers::substring(buffer, components.host_end + 1, components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_hash() const noexcept {
  ada_log("url_aggregator::get_hash");
  // If this’s URL’s fragment is either null or the empty string, then return the empty string.
  // Return U+0023 (#), followed by this’s URL’s fragment.
  if (components.hash_start == url_components::omitted) { return ""; }
  if (buffer.size() - components.hash_start <= 1) { return ""; }
  return helpers::substring(buffer, components.hash_start);
}

[[nodiscard]] std::string_view url_aggregator::get_host() const noexcept {
  ada_log("url_aggregator::get_host");
  /**
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *      |      |    |          | ^^^^|       |   |
   *      |      |    |          | |   |       |   `----- hash_start
   *      |      |    |          | |   |       `--------- search_start
   *      |      |    |          | |   `----------------- pathname_start
   *      |      |    |          | `--------------------- port
   *      |      |    |          `----------------------- host_end
   *      |      |    `---------------------------------- host_start
   *      |      `--------------------------------------- username_end
   *      `---------------------------------------------- protocol_end
   */
  size_t start = components.host_start;
  if (buffer.size() > components.host_start && buffer[components.host_start] == '@') { start++; }
  return helpers::substring(buffer, start, components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_hostname() const noexcept {
  ada_log("url_aggregator::get_hostname");
  size_t start = components.host_start;
  if (buffer.size() > components.host_start && buffer[components.host_start] == '@') { start++; }
  return helpers::substring(buffer, start, components.host_end);
}

[[nodiscard]] std::string_view url_aggregator::get_pathname() const noexcept {
  ada_log("url_aggregator::get_pathname");
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) { ending_index = components.search_start; }
  else if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  return helpers::substring(buffer, components.pathname_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_search() const noexcept {
  ada_log("url_aggregator::get_search");
  // If this’s URL’s query is either null or the empty string, then return the empty string.
  // Return U+003F (?), followed by this’s URL’s query.
  if (components.search_start == url_components::omitted) { return ""; }
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.hash_start != url_components::omitted) { ending_index = components.hash_start; }
  if (ending_index - components.search_start <= 1) { return ""; }
  return helpers::substring(buffer, components.search_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_protocol() const noexcept {
  ada_log("url_aggregator::get_protocol");
  return helpers::substring(buffer, 0, components.protocol_end);
}

std::string ada::url_aggregator::to_string() const {
  ada_log("url_aggregator::to_string buffer:", buffer, "[", buffer.size(), " bytes]");

  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");

  answer.append("\t\"buffer\":\"");
  helpers::encode_json(buffer, back);
  answer.append("\",\n");

  answer.append("\t\"protocol\":\"");
  helpers::encode_json(get_protocol(), back);
  answer.append("\",\n");

  if(includes_credentials()) {
    answer.append("\t\"username\":\"");
    helpers::encode_json(get_username(), back);
    answer.append("\",\n");
    answer.append("\t\"password\":\"");
    helpers::encode_json(get_password(), back);
    answer.append("\",\n");
  }

  answer.append("\t\"host\":\"");
  helpers::encode_json(get_host(), back);
  answer.append("\",\n");

  answer.append("\t\"path\":\"");
  helpers::encode_json(get_pathname(), back);
  answer.append("\",\n");
  answer.append("\t\"opaque path\":");
  answer.append((has_opaque_path ? "true" : "false"));
  answer.append(",\n");

  if(base_search_has_value()) {
    answer.append("\t\"query\":\"");
    helpers::encode_json(get_search(), back);
    answer.append("\",\n");
  }
  if(base_fragment_has_value()) {
    answer.append("\t\"fragment\":\"");
    helpers::encode_json(get_hash(), back);
    answer.append("\",\n");
  }

  auto convert_offset_to_string = [](uint32_t offset) -> std::string {
    if(offset == url_components::omitted) {
      return "null";
    } else {
      return std::to_string(offset);
    }
  };

  answer.append("\t\"protocol_end\":");
  answer.append(convert_offset_to_string(components.protocol_end));
  answer.append(",\n");

  answer.append("\t\"username_end\":");
  answer.append(convert_offset_to_string(components.username_end));
  answer.append(",\n");

  answer.append("\t\"host_start\":");
  answer.append(convert_offset_to_string(components.host_start));
  answer.append(",\n");

  answer.append("\t\"host_end\":");
  answer.append(convert_offset_to_string(components.host_end));
  answer.append(",\n");

  answer.append("\t\"port\":");
  answer.append(convert_offset_to_string(components.port));
  answer.append(",\n");

  answer.append("\t\"pathname_start\":");
  answer.append(convert_offset_to_string(components.pathname_start));
  answer.append(",\n");

  answer.append("\t\"search_start\":");
  answer.append(convert_offset_to_string(components.search_start));
  answer.append(",\n");

  answer.append("\t\"hash_start\":");
  answer.append(convert_offset_to_string(components.hash_start));
  answer.append("\n}");

  return answer;
}

[[nodiscard]] bool url_aggregator::has_valid_domain() const noexcept {
  if (components.host_start == components.host_end) { return false; }
  return checkers::verify_dns_length(get_hostname());
}

bool url_aggregator::parse_ipv4(std::string_view input) {
  ada_log("parse_ipv4 ", input, "[", input.size(), " bytes]");
  if(input.back()=='.') {
    input.remove_suffix(1);
  }
  size_t digit_count{0};
  int pure_decimal_count = 0; // entries that are decimal
  uint64_t ipv4{0};
  // we could unroll for better performance?
  for(;(digit_count < 4) && !(input.empty()); digit_count++) {
    uint32_t segment_result{}; // If any number exceeds 32 bits, we have an error.
    bool is_hex = checkers::has_hex_prefix(input);
    if(is_hex && ((input.length() == 2)|| ((input.length() > 2) && (input[2]=='.')))) {
      // special case
      segment_result = 0;
      input.remove_prefix(2);
    } else {
      std::from_chars_result r;
      if(is_hex) {
        r = std::from_chars(input.data() + 2, input.data() + input.size(), segment_result, 16);
      } else if ((input.length() >= 2) && input[0] == '0' && checkers::is_digit(input[1])) {
        r = std::from_chars(input.data() + 1, input.data() + input.size(), segment_result, 8);
      } else {
        pure_decimal_count++;
        r = std::from_chars(input.data(), input.data() + input.size(), segment_result, 10);
      }
      if (r.ec != std::errc()) { return is_valid = false; }
      input.remove_prefix(r.ptr-input.data());
    }
    if(input.empty()) {
      // We have the last value.
      // At this stage, ipv4 contains digit_count*8 bits.
      // So we have 32-digit_count*8 bits left.
      if(segment_result > (uint64_t(1)<<(32-digit_count*8))) { return is_valid = false; }
      ipv4 <<=(32-digit_count*8);
      ipv4 |= segment_result;
      goto final;
    } else {
      // There is more, so that the value must no be larger than 255
      // and we must have a '.'.
      if ((segment_result>255) || (input[0]!='.')) { return is_valid = false; }
      ipv4 <<=8;
      ipv4 |= segment_result;
      input.remove_prefix(1); // remove '.'
    }
  }
  if((digit_count != 4) || (!input.empty())) { return is_valid = false; }
final:
  ada_log("url_aggregator::parse_ipv4 completed ", get_href(), " host: ", get_host());

  // We could also check r.ptr to see where the parsing ended.
  if(pure_decimal_count == 4) {
    // The original input was already all decimal and we validated it. So we don't need to do anything.
  } else {
    // Optimization opportunity: Get rid of unnecessary string return in ipv4 serializer.
    // TODO: This is likely a bug because it goes back update_base_hostname, not what we want to do.
    update_base_hostname(ada::serializers::ipv4(ipv4)); // We have to reserialize the address.
  }
  return true;
}

bool url_aggregator::parse_ipv6(std::string_view input) {
  ada_log("parse_ipv6 ", input, "[", input.size(), " bytes]");

  if (input.empty()) { return is_valid = false; }
  // Let address be a new IPv6 address whose IPv6 pieces are all 0.
  std::array<uint16_t, 8> address{};

  // Let pieceIndex be 0.
  int piece_index = 0;

  // Let compress be null.
  std::optional<int> compress{};

  // Let pointer be a pointer for input.
  std::string_view::iterator pointer = input.begin();

  // If c is U+003A (:), then:
  if (input[0] == ':') {
    // If remaining does not start with U+003A (:), validation error, return failure.
    if(input.size() == 1 || input[1] != ':') {
      ada_log("parse_ipv6 starts with : but the rest does not start with :");
      return is_valid = false;
    }

    // Increase pointer by 2.
    pointer += 2;

    // Increase pieceIndex by 1 and then set compress to pieceIndex.
    compress = ++piece_index;
  }

  // While c is not the EOF code point:
  while (pointer != input.end()) {
    // If pieceIndex is 8, validation error, return failure.
    if (piece_index == 8) {
      ada_log("parse_ipv6 piece_index == 8");
      return is_valid = false;
    }

    // If c is U+003A (:), then:
    if (*pointer == ':') {
      // If compress is non-null, validation error, return failure.
      if (compress.has_value()) {
        ada_log("parse_ipv6 compress is non-null");
        return is_valid = false;
      }

      // Increase pointer and pieceIndex by 1, set compress to pieceIndex, and then continue.
      pointer++;
      compress = ++piece_index;
      continue;
    }

    // Let value and length be 0.
    uint16_t value = 0, length = 0;

    // While length is less than 4 and c is an ASCII hex digit,
    // set value to value × 0x10 + c interpreted as hexadecimal number, and increase pointer and length by 1.
    while (length < 4 && pointer != input.end() && unicode::is_ascii_hex_digit(*pointer)) {
      // https://stackoverflow.com/questions/39060852/why-does-the-addition-of-two-shorts-return-an-int
      value = uint16_t(value * 0x10 + unicode::convert_hex_to_binary(*pointer));
      pointer++;
      length++;
    }

    // If c is U+002E (.), then:
    if (pointer != input.end() && *pointer == '.') {
      // If length is 0, validation error, return failure.
      if (length == 0) {
        ada_log("parse_ipv6 length is 0");
        return is_valid = false;
      }

      // Decrease pointer by length.
      pointer -= length;

      // If pieceIndex is greater than 6, validation error, return failure.
      if (piece_index > 6) {
        ada_log("parse_ipv6 piece_index > 6");
        return is_valid = false;
      }

      // Let numbersSeen be 0.
      int numbers_seen = 0;

      // While c is not the EOF code point:
      while (pointer != input.end()) {
        // Let ipv4Piece be null.
        std::optional<uint16_t> ipv4_piece{};

        // If numbersSeen is greater than 0, then:
        if (numbers_seen > 0) {
          // If c is a U+002E (.) and numbersSeen is less than 4, then increase pointer by 1.
          if (*pointer == '.' && numbers_seen < 4) { pointer++; }
          else {
            // Otherwise, validation error, return failure.
            ada_log("parse_ipv6 Otherwise, validation error, return failure");
            return is_valid = false;
          }
        }

        // If c is not an ASCII digit, validation error, return failure.
        if (pointer == input.end() || !checkers::is_digit(*pointer)) {
          ada_log("parse_ipv6 If c is not an ASCII digit, validation error, return failure");
          return is_valid = false;
        }

        // While c is an ASCII digit:
        while (pointer != input.end() && checkers::is_digit(*pointer)) {
          // Let number be c interpreted as decimal number.
          int number = *pointer - '0';

          // If ipv4Piece is null, then set ipv4Piece to number.
          if (!ipv4_piece.has_value()) {
            ipv4_piece = number;
          }
          // Otherwise, if ipv4Piece is 0, validation error, return failure.
          else if (ipv4_piece == 0) {
            ada_log("parse_ipv6 if ipv4Piece is 0, validation error");
            return is_valid = false;
          }
          // Otherwise, set ipv4Piece to ipv4Piece × 10 + number.
          else {
            ipv4_piece = *ipv4_piece * 10 + number;
          }

          // If ipv4Piece is greater than 255, validation error, return failure.
          if (ipv4_piece > 255) {
            ada_log("parse_ipv6 ipv4_piece > 255");
            return is_valid = false;
          }

          // Increase pointer by 1.
          pointer++;
        }

        // Set address[pieceIndex] to address[pieceIndex] × 0x100 + ipv4Piece.
        // https://stackoverflow.com/questions/39060852/why-does-the-addition-of-two-shorts-return-an-int
        address[piece_index] = uint16_t(address[piece_index] * 0x100 + *ipv4_piece);

        // Increase numbersSeen by 1.
        numbers_seen++;

        // If numbersSeen is 2 or 4, then increase pieceIndex by 1.
        if (numbers_seen == 2 || numbers_seen == 4) {
          piece_index++;
        }
      }

      // If numbersSeen is not 4, validation error, return failure.
      if (numbers_seen != 4) {
        return is_valid = false;
      }

      // Break.
      break;
    }
    // Otherwise, if c is U+003A (:):
    else if ((pointer != input.end()) && (*pointer == ':')) {
      // Increase pointer by 1.
      pointer++;

      // If c is the EOF code point, validation error, return failure.
      if (pointer == input.end()) {
        ada_log("parse_ipv6 If c is the EOF code point, validation error, return failure");
        return is_valid = false;
      }
    }
    // Otherwise, if c is not the EOF code point, validation error, return failure.
    else if (pointer != input.end()) {
      ada_log("parse_ipv6 Otherwise, if c is not the EOF code point, validation error, return failure");
      return is_valid = false;
    }

    // Set address[pieceIndex] to value.
    address[piece_index] = value;

    // Increase pieceIndex by 1.
    piece_index++;
  }

  // If compress is non-null, then:
  if (compress.has_value()) {
    // Let swaps be pieceIndex − compress.
    int swaps = piece_index - *compress;

    // Set pieceIndex to 7.
    piece_index = 7;

    // While pieceIndex is not 0 and swaps is greater than 0,
    // swap address[pieceIndex] with address[compress + swaps − 1], and then decrease both pieceIndex and swaps by 1.
    while (piece_index != 0 && swaps > 0) {
      std::swap(address[piece_index], address[*compress + swaps - 1]);
      piece_index--;
      swaps--;
    }
  }
  // Otherwise, if compress is null and pieceIndex is not 8, validation error, return failure.
  else if (piece_index != 8) {
    ada_log("parse_ipv6 if compress is null and pieceIndex is not 8, validation error, return failure");
    return is_valid = false;
  }
  // TODO: Optimization opportunity: Get rid of unnecessary string creation.
  // TODO: This is likely a bug because it goes back update_base_hostname, not what we want to do.
  update_base_hostname(ada::serializers::ipv6(address));
  ada_log("parse_ipv6 ", get_hostname());
  return true;
}

bool url_aggregator::parse_opaque_host(std::string_view input) {
  ada_log("parse_opaque_host ", input, "[", input.size(), " bytes]");
  if (std::any_of(input.begin(), input.end(), ada::unicode::is_forbidden_host_code_point)) {
    return is_valid = false;
  }

  // Return the result of running UTF-8 percent-encode on input using the C0 control percent-encode set.
  // TODO: Optimization opportunity: Get rid of this string creation.
  update_base_hostname(ada::unicode::percent_encode(input, ada::character_sets::C0_CONTROL_PERCENT_ENCODE));
  return true;
}

bool url_aggregator::validate() const noexcept {
  if(!is_valid) { return true; }
  auto [ok, minlength] = components.check_offset_consistency();
  return (ok && buffer.size() >= minlength);
}

ada_really_inline size_t url_aggregator::parse_port(std::string_view view, bool check_trailing_content) noexcept {
  ada_log("parse_port('", view, "') ", view.size());
  uint16_t parsed_port{};
  auto r = std::from_chars(view.data(), view.data() + view.size(), parsed_port);
  if(r.ec == std::errc::result_out_of_range) {
    ada_log("parse_port: std::errc::result_out_of_range");
    is_valid = false;
    return 0;
  }
  ada_log("parse_port: ", parsed_port);
  const size_t consumed = size_t(r.ptr - view.data());
  ada_log("parse_port: consumed ", consumed);
  if(check_trailing_content) {
    is_valid &= (consumed == view.size() || view[consumed] == '/' || view[consumed] == '?' || (is_special() && view[consumed] == '\\'));
  }
  ada_log("parse_port: is_valid = ", is_valid);
  if(is_valid) {
    if (r.ec == std::errc() && scheme_default_port() != parsed_port) {
      update_base_port(parsed_port);
    } else {
      clear_base_port();
    }
  }
  return consumed;
}

} // namespace ada

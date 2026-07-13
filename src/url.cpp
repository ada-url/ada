#include "ada/scheme-inl.h"
#include "ada/implementation.h"
#include "ada/ip_address.h"
#include "ada/log.h"
#include "ada/unicode-inl.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <numeric>
#include <ranges>
#include <string>
#include <string_view>

namespace ada {

bool url::parse_opaque_host(std::string_view input) {
  ada_log("parse_opaque_host ", input, " [", input.size(), " bytes]");
  if (std::ranges::any_of(input, ada::unicode::is_forbidden_host_code_point)) {
    return is_valid = false;
  }

  // Return the result of running UTF-8 percent-encode on input using the C0
  // control percent-encode set.
  host = ada::unicode::percent_encode(
      input, ada::character_sets::C0_CONTROL_PERCENT_ENCODE);
  return true;
}

bool url::parse_ipv4(std::string_view input) {
  ada_log("parse_ipv4 ", input, " [", input.size(), " bytes]");
  std::string_view original_input = input;
  if (!original_input.empty() && original_input.back() == '.') {
    original_input.remove_suffix(1);
  }
  uint32_t ipv4 = 0;
  int pure_decimal_count = 0;
  bool had_trailing_dot = false;
  if (!ip_address::parse_ipv4(input, ipv4, pure_decimal_count,
                              had_trailing_dot)) {
    return is_valid = false;
  }
  if (pure_decimal_count == 4) {
    // original_input already has any trailing dot stripped.
    host = original_input;
  } else {
    host = ip_address::serialize_ipv4(ipv4);
  }
  (void)had_trailing_dot;
  host_type = IPV4;
  return true;
}

bool url::parse_ipv6(std::string_view input) {
  ada_log("parse_ipv6 ", input, " [", input.size(), " bytes]");
  std::array<uint16_t, 8> address{};
  if (!ip_address::parse_ipv6(input, address)) {
    return is_valid = false;
  }
  host = ip_address::serialize_ipv6(address);
  ada_log("parse_ipv6 ", *host);
  host_type = IPV6;
  return true;
}

template <bool has_state_override>
ada_really_inline bool url::parse_scheme(const std::string_view input) {
  auto parsed_type = ada::scheme::get_scheme_type(input);
  bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
  /**
   * In the common case, we will immediately recognize a special scheme (e.g.,
   *http, https), in which case, we can go really fast.
   **/
  if (is_input_special) {  // fast path!!!
    if constexpr (has_state_override) {
      // If url's scheme is not a special scheme and buffer is a special scheme,
      // then return.
      if (is_special() != is_input_special) {
        return false;
      }

      // If url includes credentials or has a non-null port, and buffer is
      // "file", then return.
      if ((has_credentials() || port.has_value()) &&
          parsed_type == ada::scheme::type::FILE) {
        return false;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE && host.has_value() &&
          host->empty()) {
        return false;
      }
    }

    type = parsed_type;

    if constexpr (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url's port is url's scheme's default port, then set url's port to
        // null.
        if (port.has_value() && *port == urls_scheme_port) {
          port = std::nullopt;
        }
      }
    }
  } else {  // slow path
    std::string _buffer(input);
    // Next function is only valid if the input is ASCII and returns false
    // otherwise, but it seems that we always have ascii content so we do not
    // need to check the return value.
    // bool is_ascii =
    unicode::to_lower_ascii(_buffer.data(), _buffer.size());

    if constexpr (has_state_override) {
      // The state-override validation errors below ("return" in the WHATWG URL
      // parser) leave the URL unchanged. The setter contract is
      // "true on success, false if the scheme is invalid" -- the fast path
      // above already returns false here, so the slow path must agree.

      // If url's scheme is a special scheme and buffer is not a special scheme,
      // then return. If url's scheme is not a special scheme and buffer is a
      // special scheme, then return.
      if (is_special() != ada::scheme::is_special(_buffer)) {
        return false;
      }

      // If url includes credentials or has a non-null port, and buffer is
      // "file", then return.
      if ((has_credentials() || port.has_value()) && _buffer == "file") {
        return false;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE && host.has_value() &&
          host->empty()) {
        return false;
      }
    }

    set_scheme(std::move(_buffer));

    if constexpr (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url's port is url's scheme's default port, then set url's port to
        // null.
        if (port.has_value() && *port == urls_scheme_port) {
          port = std::nullopt;
        }
      }
    }
  }

  return true;
}

ada_really_inline bool url::parse_host(std::string_view input) {
  ada_log("parse_host ", input, " [", input.size(), " bytes]");
  if (input.empty()) {
    return is_valid = false;
  }  // technically unnecessary.
  // If input starts with U+005B ([), then:
  if (input[0] == '[') {
    // If input does not end with U+005D (]), validation error, return failure.
    if (input.back() != ']') {
      return is_valid = false;
    }
    ada_log("parse_host ipv6");

    // Return the result of IPv6 parsing input with its leading U+005B ([) and
    // trailing U+005D (]) removed.
    input.remove_prefix(1);
    input.remove_suffix(1);
    return parse_ipv6(input);
  }

  // If isNotSpecial is true, then return the result of opaque-host parsing
  // input.
  if (!is_special()) {
    return parse_opaque_host(input);
  }

  // Fast path: try to parse as pure decimal IPv4(a.b.c.d) first.
  const uint64_t fast_result = checkers::try_parse_ipv4_fast(input);
  if (fast_result < checkers::ipv4_fast_fail) {
    // Fast path succeeded - input is pure decimal IPv4
    if (!input.empty() && input.back() == '.') {
      host = input.substr(0, input.size() - 1);
    } else {
      host = input;
    }
    host_type = IPV4;
    is_valid = true;
    ada_log("parse_host fast path decimal ipv4");
    return true;
  }
  // Let domain be the result of running UTF-8 decode without BOM on the
  // percent-decoding of input. Let asciiDomain be the result of running domain
  // to ASCII with domain and false. The most common case is an ASCII input, in
  // which case we do not need to call the expensive 'to_ascii' if a few
  // conditions are met: no '%' and no 'xn-' subsequence.
  std::string buffer = std::string(input);
  // This next function checks that the result is ascii, but we are going to
  // to check anyhow with is_forbidden.
  // bool is_ascii =
  unicode::to_lower_ascii(buffer.data(), buffer.size());
  bool is_forbidden = unicode::contains_forbidden_domain_code_point(
      buffer.data(), buffer.size());
  static constexpr std::string_view xn_dash{"xn-", 3};
  if (is_forbidden == 0 && buffer.find(xn_dash) == std::string_view::npos) {
    // fast path
    host = std::move(buffer);

    // Check for other IPv4 formats (hex, octal, etc.)
    if (checkers::is_ipv4(host.value())) {
      ada_log("parse_host fast path ipv4");
      return parse_ipv4(host.value());
    }
    ada_log("parse_host fast path ", *host);
    is_valid = true;
    return true;
  }
  ada_log("parse_host calling to_ascii");
  is_valid = ada::unicode::to_ascii(host, input, input.find('%'));
  if (!is_valid || !host.has_value()) {
    ada_log("parse_host to_ascii returns false");
    return is_valid = false;
  }
  ada_log("parse_host to_ascii succeeded ", *host, " [", host->size(),
          " bytes]");

  if (std::any_of(host->begin(), host->end(),
                  ada::unicode::is_forbidden_domain_code_point)) {
    host = std::nullopt;
    return is_valid = false;
  }

  // If asciiDomain ends in a number, then return the result of IPv4 parsing
  // asciiDomain.
  if (checkers::is_ipv4(*host)) {
    ada_log("parse_host got ipv4 ", *host);
    return parse_ipv4(*host);
  }

  return true;
}

ada_really_inline void url::parse_path(std::string_view input) {
  ada_log("parse_path ", input);
  std::string tmp_buffer;
  std::string_view internal_input;
  if (unicode::has_tabs_or_newline(input)) {
    tmp_buffer = input;
    // Optimization opportunity: Instead of copying and then pruning, we could
    // just directly build the string from user_input.
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = input;
  }

  // If url is special, then:
  if (is_special()) {
    if (internal_input.empty()) {
      path = "/";
    } else if ((internal_input[0] == '/') || (internal_input[0] == '\\')) {
      helpers::parse_prepared_path(internal_input.substr(1), type, path);
    } else {
      helpers::parse_prepared_path(internal_input, type, path);
    }
  } else if (!internal_input.empty()) {
    if (internal_input[0] == '/') {
      helpers::parse_prepared_path(internal_input.substr(1), type, path);
    } else {
      helpers::parse_prepared_path(internal_input, type, path);
    }
  } else {
    if (!host.has_value()) {
      path = "/";
    }
  }
}

[[nodiscard]] std::string url::to_string() const {
  if (!is_valid) {
    return "null";
  }
  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");
  answer.append("\t\"protocol\":\"");
  helpers::encode_json(get_protocol(), back);
  answer.append("\",\n");
  if (has_credentials()) {
    answer.append("\t\"username\":\"");
    helpers::encode_json(username, back);
    answer.append("\",\n");
    answer.append("\t\"password\":\"");
    helpers::encode_json(password, back);
    answer.append("\",\n");
  }
  if (host.has_value()) {
    answer.append("\t\"host\":\"");
    helpers::encode_json(host.value(), back);
    answer.append("\",\n");
  }
  if (port.has_value()) {
    answer.append("\t\"port\":\"");
    answer.append(std::to_string(port.value()));
    answer.append("\",\n");
  }
  answer.append("\t\"path\":\"");
  helpers::encode_json(path, back);
  answer.append("\",\n");
  answer.append("\t\"opaque path\":");
  answer.append((has_opaque_path ? "true" : "false"));
  if (has_search()) {
    answer.append(",\n");
    answer.append("\t\"query\":\"");
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    helpers::encode_json(query.value(), back);
    answer.append("\"");
  }
  if (hash.has_value()) {
    answer.append(",\n");
    answer.append("\t\"hash\":\"");
    helpers::encode_json(hash.value(), back);
    answer.append("\"");
  }
  answer.append("\n}");
  return answer;
}

[[nodiscard]] bool url::has_valid_domain() const noexcept {
  if (!host.has_value()) {
    return false;
  }
  return checkers::verify_dns_length(*host);
}

[[nodiscard]] std::string url::get_origin() const {
  if (is_special()) {
    // Return a new opaque origin.
    if (type == scheme::FILE) {
      return "null";
    }
    return ada::helpers::concat(get_protocol(), "//", get_host());
  }

  if (non_special_scheme == "blob") {
    if (!path.empty()) {
      auto result = ada::parse<ada::url>(path);
      if (result &&
          (result->type == scheme::HTTP || result->type == scheme::HTTPS)) {
        // If pathURL's scheme is not "http" and not "https", then return a
        // new opaque origin.
        return ada::helpers::concat(result->get_protocol(), "//",
                                    result->get_host());
      }
    }
  }

  // Return a new opaque origin.
  return "null";
}

[[nodiscard]] std::string url::get_protocol() const {
  if (is_special()) {
    return helpers::concat(ada::scheme::details::is_special_list[type], ":");
  }
  // We only move the 'scheme' if it is non-special.
  return helpers::concat(non_special_scheme, ":");
}

[[nodiscard]] std::string url::get_host() const {
  // If url's host is null, then return the empty string.
  // If url's port is null, return url's host, serialized.
  // Return url's host, serialized, followed by U+003A (:) and url's port,
  // serialized.
  if (!host.has_value()) {
    return "";
  }
  if (port.has_value()) {
    return host.value() + ":" + get_port();
  }
  return host.value();
}

[[nodiscard]] std::string url::get_hostname() const {
  return host.value_or("");
}

[[nodiscard]] std::string url::get_search() const {
  // If this's URL's query is either null or the empty string, then return the
  // empty string. Return U+003F (?), followed by this's URL's query.
  return (!query.has_value() || (query->empty())) ? "" : "?" + query.value();
}

[[nodiscard]] const std::string& url::get_username() const noexcept {
  return username;
}

[[nodiscard]] const std::string& url::get_password() const noexcept {
  return password;
}

[[nodiscard]] std::string url::get_port() const {
  return port.has_value() ? std::to_string(port.value()) : "";
}

[[nodiscard]] std::string url::get_hash() const {
  // If this's URL's fragment is either null or the empty string, then return
  // the empty string. Return U+0023 (#), followed by this's URL's fragment.
  return (!hash.has_value() || (hash->empty())) ? "" : "#" + hash.value();
}

template <bool override_hostname>
bool url::set_host_or_hostname(const std::string_view input) {
  if (has_opaque_path) {
    return false;
  }

  url saved_url(*this);

  size_t host_end_pos = input.find('#');
  std::string _host(input.data(), host_end_pos != std::string_view::npos
                                      ? host_end_pos
                                      : input.size());
  helpers::remove_ascii_tab_or_newline(_host);
  std::string_view new_host(_host);

  auto check_url_size = [&]() -> bool {
    if (get_href_size() > ada::get_max_input_length()) {
      *this = std::move(saved_url);
      return false;
    }
    return true;
  };

  // If url's scheme is "file", then set state to file host state, instead of
  // host state.
  if (type != ada::scheme::type::FILE) {
    std::string_view host_view(_host.data(), _host.length());
    auto [location, found_colon] =
        helpers::get_host_delimiter_location(is_special(), host_view);

    // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
    // Note: the 'found_colon' value is true if and only if a colon was
    // encountered while not inside brackets.
    if (found_colon) {
      // If buffer is the empty string, host-missing validation error, return
      // failure.
      std::string_view buffer = host_view.substr(0, location);
      if (buffer.empty()) {
        return false;
      }

      // If state override is given and state override is hostname state, then
      // return failure.
      if constexpr (override_hostname) {
        return false;
      }

      // Let host be the result of host parsing buffer with url is not special.
      bool succeeded = parse_host(buffer);
      if (!succeeded) {
        *this = std::move(saved_url);
        return false;
      }

      // Set url's host to host, buffer to the empty string, and state to port
      // state.
      std::string_view port_buffer = new_host.substr(location + 1);
      if (!port_buffer.empty()) {
        set_port(port_buffer);
      }
      return check_url_size();
    }
    // Otherwise, if one of the following is true:
    // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
    // - url is special and c is U+005C (\)
    else {
      // If url is special and host_view is the empty string, host-missing
      // validation error, return failure.
      if (host_view.empty() && is_special()) {
        return false;
      }

      // Otherwise, if state override is given, host_view is the empty string,
      // and either url includes credentials or url's port is non-null, then
      // return failure.
      if (host_view.empty() && (has_credentials() || port.has_value())) {
        return false;
      }

      // Let host be the result of host parsing host_view with url is not
      // special.
      if (host_view.empty() && !is_special()) {
        host = "";
        return check_url_size();
      }

      bool succeeded = parse_host(host_view);
      if (!succeeded) {
        *this = std::move(saved_url);
        return false;
      }
      return check_url_size();
    }
  }

  size_t location = new_host.find_first_of("/\\?");
  if (location != std::string_view::npos) {
    new_host.remove_suffix(new_host.length() - location);
  }

  if (new_host.empty()) {
    // Set url's host to the empty string.
    host = "";
  } else {
    // Let host be the result of host parsing buffer with url is not special.
    if (!parse_host(new_host)) {
      *this = std::move(saved_url);
      return false;
    }

    // If host is "localhost", then set host to the empty string.
    if (host == "localhost") {
      host = "";
    }
  }
  return check_url_size();
}

bool url::set_host(const std::string_view input) {
  return set_host_or_hostname<false>(input);
}

bool url::set_hostname(const std::string_view input) {
  return set_host_or_hostname<true>(input);
}

bool url::set_username(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  auto previous_username = std::move(username);
  username = ada::unicode::percent_encode(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (get_href_size() > ada::get_max_input_length()) {
    username = std::move(previous_username);
    return false;
  }
  return true;
}

bool url::set_password(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  auto previous_password = std::move(password);
  password = ada::unicode::percent_encode(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (get_href_size() > ada::get_max_input_length()) {
    password = std::move(previous_password);
    return false;
  }
  return true;
}

bool url::set_port(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }

  if (input.empty()) {
    port = std::nullopt;
    return true;
  }

  std::string trimmed(input);
  helpers::remove_ascii_tab_or_newline(trimmed);

  if (trimmed.empty()) {
    return true;
  }

  // Input should not start with a non-digit character.
  if (!ada::unicode::is_ascii_digit(trimmed.front())) {
    return false;
  }

  // Find the first non-digit character to determine the length of digits
  auto first_non_digit =
      std::ranges::find_if_not(trimmed, ada::unicode::is_ascii_digit);
  std::string_view digits_to_parse =
      std::string_view(trimmed.data(), first_non_digit - trimmed.begin());

  // Revert changes if parse_port fails.
  std::optional<uint16_t> previous_port = port;
  parse_port(digits_to_parse);
  if (is_valid) {
    if (get_href_size() > ada::get_max_input_length()) {
      port = std::move(previous_port);
      return false;
    }
    return true;
  }
  port = std::move(previous_port);
  is_valid = true;
  return false;
}

void url::set_hash(const std::string_view input) {
  if (input.empty()) {
    hash = std::nullopt;
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '#' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);
  auto previous_hash = std::move(hash);
  hash = unicode::percent_encode(new_value,
                                 ada::character_sets::FRAGMENT_PERCENT_ENCODE);
  if (get_href_size() > ada::get_max_input_length()) {
    hash = std::move(previous_hash);
  }
}

void url::set_search(const std::string_view input) {
  if (input.empty()) {
    query = std::nullopt;
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '?' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);

  auto query_percent_encode_set =
      is_special() ? ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE
                   : ada::character_sets::QUERY_PERCENT_ENCODE;

  auto previous_query = std::move(query);
  query = ada::unicode::percent_encode(new_value, query_percent_encode_set);
  if (get_href_size() > ada::get_max_input_length()) {
    query = std::move(previous_query);
  }
}

bool url::set_pathname(const std::string_view input) {
  if (has_opaque_path) {
    return false;
  }
  auto previous_path = std::move(path);
  path.clear();
  parse_path(input);
  if (get_href_size() > ada::get_max_input_length()) {
    path = std::move(previous_path);
    return false;
  }
  return true;
}

bool url::set_protocol(const std::string_view input) {
  std::string view(input);
  helpers::remove_ascii_tab_or_newline(view);
  if (view.empty()) {
    return true;
  }

  // Schemes should start with alpha values.
  if (!checkers::is_alpha(view[0])) {
    return false;
  }

  view.append(":");

  std::string::iterator pointer =
      std::ranges::find_if_not(view, unicode::is_alnum_plus);

  if (pointer != view.end() && *pointer == ':') {
    url saved_url(*this);
    bool result = parse_scheme<true>(
        std::string_view(view.data(), pointer - view.begin()));
    if (result && get_href_size() > ada::get_max_input_length()) {
      *this = std::move(saved_url);
      return false;
    }
    return result;
  }
  return false;
}

bool url::set_href(const std::string_view input) {
  ada::result<ada::url> out = ada::parse<ada::url>(input);

  if (out) {
    // The parser enforces get_max_input_length() on both the input and the
    // normalized result. This is a defense-in-depth check.
    if (out->get_href_size() > ada::get_max_input_length()) {
      return false;
    }
    *this = *out;
  }

  return out.has_value();
}

}  // namespace ada

#include "ada.h"
#include "ada/checkers-inl.h"
#include "ada/checkers.h"
#include "ada/helpers.h"
#include "ada/implementation.h"
#include "ada/scheme.h"
#include "ada/unicode-inl.h"
#include "ada/url_components.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"
#include "ada/parser.h"

#include <string>
#include <string_view>

namespace ada {
template <bool has_state_override>
[[nodiscard]] ada_really_inline bool url_aggregator::parse_scheme_with_colon(
    const std::string_view input_with_colon) {
  ada_log("url_aggregator::parse_scheme_with_colon ", input_with_colon);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input_with_colon, buffer));
  std::string_view input{input_with_colon};
  input.remove_suffix(1);
  auto parsed_type = ada::scheme::get_scheme_type(input);
  bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
  /**
   * In the common case, we will immediately recognize a special scheme (e.g.,
   *http, https), in which case, we can go really fast.
   **/
  if (is_input_special) {  // fast path!!!
    if (has_state_override) {
      // If url's scheme is not a special scheme and buffer is a special scheme,
      // then return.
      if (is_special() != is_input_special) {
        return true;
      }

      // If url includes credentials or has a non-null port, and buffer is
      // "file", then return.
      if ((has_credentials() || components.port != url_components::omitted) &&
          parsed_type == ada::scheme::type::FILE) {
        return true;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE &&
          components.host_start == components.host_end) {
        return true;
      }
    }

    type = parsed_type;
    set_scheme_from_view_with_colon(input_with_colon);

    if (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      // If url's port is url's scheme's default port, then set url's port to
      // null.
      if (components.port == urls_scheme_port) {
        clear_port();
      }
    }
  } else {  // slow path
    std::string _buffer = std::string(input);
    // Next function is only valid if the input is ASCII and returns false
    // otherwise, but it seems that we always have ascii content so we do not
    // need to check the return value.
    unicode::to_lower_ascii(_buffer.data(), _buffer.size());

    if (has_state_override) {
      // If url's scheme is a special scheme and buffer is not a special scheme,
      // then return. If url's scheme is not a special scheme and buffer is a
      // special scheme, then return.
      if (is_special() != ada::scheme::is_special(_buffer)) {
        return true;
      }

      // If url includes credentials or has a non-null port, and buffer is
      // "file", then return.
      if ((has_credentials() || components.port != url_components::omitted) &&
          _buffer == "file") {
        return true;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE &&
          components.host_start == components.host_end) {
        return true;
      }
    }

    set_scheme(_buffer);

    if (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      // If url's port is url's scheme's default port, then set url's port to
      // null.
      if (components.port == urls_scheme_port) {
        clear_port();
      }
    }
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

inline void url_aggregator::copy_scheme(const url_aggregator& u) noexcept {
  ada_log("url_aggregator::copy_scheme ", u.buffer);
  ADA_ASSERT_TRUE(validate());
  // next line could overflow but unsigned arithmetic has well-defined
  // overflows.
  uint32_t new_difference = u.components.protocol_end - components.protocol_end;
  type = u.type;
  buffer.erase(0, components.protocol_end);
  buffer.insert(0, u.get_protocol());
  components.protocol_end = u.components.protocol_end;

  // No need to update the components
  if (new_difference == 0) {
    return;
  }

  // Update the rest of the components.
  components.username_end += new_difference;
  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += new_difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += new_difference;
  }
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::set_scheme_from_view_with_colon(
    std::string_view new_scheme_with_colon) noexcept {
  ada_log("url_aggregator::set_scheme_from_view_with_colon ",
          new_scheme_with_colon);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!new_scheme_with_colon.empty() &&
                  new_scheme_with_colon.back() == ':');
  // next line could overflow but unsigned arithmetic has well-defined
  // overflows.
  uint32_t new_difference =
      uint32_t(new_scheme_with_colon.size()) - components.protocol_end;

  if (buffer.empty()) {
    buffer.append(new_scheme_with_colon);
  } else {
    buffer.erase(0, components.protocol_end);
    buffer.insert(0, new_scheme_with_colon);
  }
  components.protocol_end += new_difference;

  // Update the rest of the components.
  components.username_end += new_difference;
  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += new_difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += new_difference;
  }
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::set_scheme(std::string_view new_scheme) noexcept {
  ada_log("url_aggregator::set_scheme ", new_scheme);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(new_scheme.empty() || new_scheme.back() != ':');
  // next line could overflow but unsigned arithmetic has well-defined
  // overflows.
  uint32_t new_difference =
      uint32_t(new_scheme.size()) - components.protocol_end + 1;

  type = ada::scheme::get_scheme_type(new_scheme);
  if (buffer.empty()) {
    buffer.append(helpers::concat(new_scheme, ":"));
  } else {
    buffer.erase(0, components.protocol_end);
    buffer.insert(0, helpers::concat(new_scheme, ":"));
  }
  components.protocol_end = uint32_t(new_scheme.size() + 1);

  // Update the rest of the components.
  components.username_end += new_difference;
  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != url_components::omitted) {
    components.search_start += new_difference;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start += new_difference;
  }
  ADA_ASSERT_TRUE(validate());
}

bool url_aggregator::set_protocol(const std::string_view input) {
  ada_log("url_aggregator::set_protocol ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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
      std::find_if_not(view.begin(), view.end(), unicode::is_alnum_plus);

  if (pointer != view.end() && *pointer == ':') {
    return parse_scheme_with_colon<true>(
        std::string_view(view.data(), pointer - view.begin() + 1));
  }
  return false;
}

bool url_aggregator::set_username(const std::string_view input) {
  ada_log("url_aggregator::set_username '", input, "' ");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (idx == input.size()) {
    update_base_username(input);
  } else {
    // We only create a temporary string if we have to!
    update_base_username(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::set_password(const std::string_view input) {
  ada_log("url_aggregator::set_password '", input, "'");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (idx == input.size()) {
    update_base_password(input);
  } else {
    // We only create a temporary string if we have to!
    update_base_password(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::set_port(const std::string_view input) {
  ada_log("url_aggregator::set_port ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  std::string trimmed(input);
  helpers::remove_ascii_tab_or_newline(trimmed);
  if (trimmed.empty()) {
    clear_port();
    return true;
  }
  // Input should not start with control characters.
  if (ada::unicode::is_c0_control_or_space(trimmed.front())) {
    return false;
  }
  // Input should contain at least one ascii digit.
  if (input.find_first_of("0123456789") == std::string_view::npos) {
    return false;
  }

  // Revert changes if parse_port fails.
  uint32_t previous_port = components.port;
  parse_port(trimmed);
  if (is_valid) {
    return true;
  }
  update_base_port(previous_port);
  is_valid = true;
  ADA_ASSERT_TRUE(validate());
  return false;
}

bool url_aggregator::set_pathname(const std::string_view input) {
  ada_log("url_aggregator::set_pathname ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (has_opaque_path) {
    return false;
  }
  clear_pathname();
  parse_path(input);
  if (checkers::begins_with(input, "//") && !has_authority() &&
      !has_dash_dot()) {
    buffer.insert(components.pathname_start, "/.");
    components.pathname_start += 2;
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

ada_really_inline void url_aggregator::parse_path(std::string_view input) {
  ada_log("url_aggregator::parse_path ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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
      update_base_pathname("/");
    } else if ((internal_input[0] == '/') || (internal_input[0] == '\\')) {
      consume_prepared_path(internal_input.substr(1));
    } else {
      consume_prepared_path(internal_input);
    }
  } else if (!internal_input.empty()) {
    if (internal_input[0] == '/') {
      consume_prepared_path(internal_input.substr(1));
    } else {
      consume_prepared_path(internal_input);
    }
  } else {
    // Non-special URLs with an empty host can have their paths erased
    // Path-only URLs cannot have their paths erased
    if (components.host_start == components.host_end && !has_authority()) {
      update_base_pathname("/");
    }
  }
  ADA_ASSERT_TRUE(validate());
}

void url_aggregator::set_search(const std::string_view input) {
  ada_log("url_aggregator::set_search ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (input.empty()) {
    clear_search();
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '?' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);

  auto query_percent_encode_set =
      is_special() ? ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE
                   : ada::character_sets::QUERY_PERCENT_ENCODE;

  update_base_search(new_value, query_percent_encode_set);
  ADA_ASSERT_TRUE(validate());
}

void url_aggregator::set_hash(const std::string_view input) {
  ada_log("url_aggregator::set_hash ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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
  ADA_ASSERT_TRUE(validate());
}

bool url_aggregator::set_href(const std::string_view input) {
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
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
  // Let domain be the result of running UTF-8 decode without BOM on the
  // percent-decoding of input. Let asciiDomain be the result of running domain
  // to ASCII with domain and false. The most common case is an ASCII input, in
  // which case we do not need to call the expensive 'to_ascii' if a few
  // conditions are met: no '%' and no 'xn-' subsequence.

  // Often, the input does not contain any forbidden code points, and no upper
  // case ASCII letter, then we can just copy it to the buffer. We want to
  // optimize for such a common case.
  uint8_t is_forbidden_or_upper =
      unicode::contains_forbidden_domain_code_point_or_upper(input.data(),
                                                             input.size());
  // Minor optimization opportunity:
  // contains_forbidden_domain_code_point_or_upper could be extend to check for
  // the presence of characters that cannot appear in the ipv4 address and we
  // could also check whether x and n and - are present, and so we could skip
  // some of the checks below. However, the gains are likely to be small, and
  // the code would be more complex.
  if (is_forbidden_or_upper == 0 &&
      input.find("xn-") == std::string_view::npos) {
    // fast path
    update_base_hostname(input);
    if (checkers::is_ipv4(get_hostname())) {
      ada_log("parse_host fast path ipv4");
      return parse_ipv4(get_hostname());
    }
    ada_log("parse_host fast path ", get_hostname());
    return true;
  }
  // We have encountered at least one forbidden code point or the input contains
  // 'xn-' (case insensitive), so we need to call 'to_ascii' to perform the full
  // conversion.

  ada_log("parse_host calling to_ascii");
  std::optional<std::string> host = std::string(get_hostname());
  is_valid = ada::unicode::to_ascii(host, input, input.find('%'));
  if (!is_valid) {
    ada_log("parse_host to_ascii returns false");
    return is_valid = false;
  }

  if (std::any_of(host.value().begin(), host.value().end(),
                  ada::unicode::is_forbidden_domain_code_point)) {
    return is_valid = false;
  }

  // If asciiDomain ends in a number, then return the result of IPv4 parsing
  // asciiDomain.
  if (checkers::is_ipv4(host.value())) {
    ada_log("parse_host got ipv4", *host);
    return parse_ipv4(host.value());
  }

  update_base_hostname(host.value());
  ADA_ASSERT_TRUE(validate());
  return true;
}

template <bool override_hostname>
bool url_aggregator::set_host_or_hostname(const std::string_view input) {
  ada_log("url_aggregator::set_host_or_hostname ", input);
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (has_opaque_path) {
    return false;
  }

  std::string previous_host = std::string(get_hostname());
  uint32_t previous_port = components.port;

  size_t host_end_pos = input.find('#');
  std::string _host(input.data(), host_end_pos != std::string_view::npos
                                      ? host_end_pos
                                      : input.size());
  helpers::remove_ascii_tab_or_newline(_host);
  std::string_view new_host(_host);

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
      if (override_hostname) {
        return false;
      }
      std::string_view sub_buffer = new_host.substr(location + 1);
      if (!sub_buffer.empty()) {
        set_port(sub_buffer);
      }
    }
    // If url is special and host_view is the empty string, validation error,
    // return failure. Otherwise, if state override is given, host_view is the
    // empty string, and either url includes credentials or url's port is
    // non-null, return.
    else if (host_view.empty() &&
             (is_special() || has_credentials() || has_port())) {
      return false;
    }

    // Let host be the result of host parsing host_view with url is not special.
    if (host_view.empty() && !is_special()) {
      if (has_hostname()) {
        clear_hostname();  // easy!
      } else if (has_dash_dot()) {
        add_authority_slashes_if_needed();
        delete_dash_dot();
      }
      return true;
    }

    bool succeeded = parse_host(host_view);
    if (!succeeded) {
      update_base_hostname(previous_host);
      update_base_port(previous_port);
    } else if (has_dash_dot()) {
      // Should remove dash_dot from pathname
      delete_dash_dot();
    }
    return succeeded;
  }

  size_t location = new_host.find_first_of("/\\?");
  if (location != std::string_view::npos) {
    new_host.remove_suffix(new_host.length() - location);
  }

  if (new_host.empty()) {
    // Set url's host to the empty string.
    clear_hostname();
  } else {
    // Let host be the result of host parsing buffer with url is not special.
    if (!parse_host(new_host)) {
      update_base_hostname(previous_host);
      update_base_port(previous_port);
      return false;
    }

    // If host is "localhost", then set host to the empty string.
    if (helpers::substring(buffer, components.host_start,
                           components.host_end) == "localhost") {
      clear_hostname();
    }
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::set_host(const std::string_view input) {
  ada_log("url_aggregator::set_host '", input, "'");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  return set_host_or_hostname<false>(input);
}

bool url_aggregator::set_hostname(const std::string_view input) {
  ada_log("url_aggregator::set_hostname '", input, "'");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  return set_host_or_hostname<true>(input);
}

[[nodiscard]] std::string url_aggregator::get_origin() const noexcept {
  ada_log("url_aggregator::get_origin");
  if (is_special()) {
    // Return a new opaque origin.
    if (type == scheme::FILE) {
      return "null";
    }

    return helpers::concat(get_protocol(), "//", get_host());
  }

  if (get_protocol() == "blob:") {
    std::string_view path = get_pathname();
    if (!path.empty()) {
      auto out = ada::parse<ada::url_aggregator>(path);
      if (out && (out->type == scheme::HTTP || out->type == scheme::HTTPS)) {
        // If pathURL's scheme is not "http" and not "https", then return a
        // new opaque origin.
        return helpers::concat(out->get_protocol(), "//", out->get_host());
      }
    }
  }

  // Return a new opaque origin.
  return "null";
}

[[nodiscard]] std::string_view url_aggregator::get_username() const noexcept {
  ada_log("url_aggregator::get_username");
  if (has_non_empty_username()) {
    return helpers::substring(buffer, components.protocol_end + 2,
                              components.username_end);
  }
  return "";
}

[[nodiscard]] std::string_view url_aggregator::get_password() const noexcept {
  ada_log("url_aggregator::get_password");
  if (has_non_empty_password()) {
    return helpers::substring(buffer, components.username_end + 1,
                              components.host_start);
  }
  return "";
}

[[nodiscard]] std::string_view url_aggregator::get_port() const noexcept {
  ada_log("url_aggregator::get_port");
  if (components.port == url_components::omitted) {
    return "";
  }
  return helpers::substring(buffer, components.host_end + 1,
                            components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_hash() const noexcept {
  ada_log("url_aggregator::get_hash");
  // If this's URL's fragment is either null or the empty string, then return
  // the empty string. Return U+0023 (#), followed by this's URL's fragment.
  if (components.hash_start == url_components::omitted) {
    return "";
  }
  if (buffer.size() - components.hash_start <= 1) {
    return "";
  }
  return helpers::substring(buffer, components.hash_start);
}

[[nodiscard]] std::string_view url_aggregator::get_host() const noexcept {
  ada_log("url_aggregator::get_host");
  // Technically, we should check if there is a hostname, but
  // the code below works even if there isn't.
  // if(!has_hostname()) { return ""; }
  size_t start = components.host_start;
  if (components.host_end > components.host_start &&
      buffer[components.host_start] == '@') {
    start++;
  }
  // if we have an empty host, then the space between components.host_end and
  // components.pathname_start may be occupied by /.
  if (start == components.host_end) {
    return std::string_view();
  }
  return helpers::substring(buffer, start, components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_hostname() const noexcept {
  ada_log("url_aggregator::get_hostname");
  // Technically, we should check if there is a hostname, but
  // the code below works even if there isn't.
  // if(!has_hostname()) { return ""; }
  size_t start = components.host_start;
  // So host_start is not where the host begins.
  if (components.host_end > components.host_start &&
      buffer[components.host_start] == '@') {
    start++;
  }
  return helpers::substring(buffer, start, components.host_end);
}

[[nodiscard]] std::string_view url_aggregator::get_pathname() const noexcept {
  ada_log("url_aggregator::get_pathname pathname_start = ",
          components.pathname_start, " buffer.size() = ", buffer.size(),
          " components.search_start = ", components.search_start,
          " components.hash_start = ", components.hash_start);
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.search_start != url_components::omitted) {
    ending_index = components.search_start;
  } else if (components.hash_start != url_components::omitted) {
    ending_index = components.hash_start;
  }
  return helpers::substring(buffer, components.pathname_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_search() const noexcept {
  ada_log("url_aggregator::get_search");
  // If this's URL's query is either null or the empty string, then return the
  // empty string. Return U+003F (?), followed by this's URL's query.
  if (components.search_start == url_components::omitted) {
    return "";
  }
  uint32_t ending_index = uint32_t(buffer.size());
  if (components.hash_start != url_components::omitted) {
    ending_index = components.hash_start;
  }
  if (ending_index - components.search_start <= 1) {
    return "";
  }
  return helpers::substring(buffer, components.search_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_protocol() const noexcept {
  ada_log("url_aggregator::get_protocol");
  return helpers::substring(buffer, 0, components.protocol_end);
}

[[nodiscard]] std::string ada::url_aggregator::to_string() const {
  ada_log("url_aggregator::to_string buffer:", buffer, "[", buffer.size(),
          " bytes]");
  if (!is_valid) {
    return "null";
  }

  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");

  answer.append("\t\"buffer\":\"");
  helpers::encode_json(buffer, back);
  answer.append("\",\n");

  answer.append("\t\"protocol\":\"");
  helpers::encode_json(get_protocol(), back);
  answer.append("\",\n");

  if (has_credentials()) {
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

  if (components.search_start != url_components::omitted) {
    answer.append("\t\"query\":\"");
    helpers::encode_json(get_search(), back);
    answer.append("\",\n");
  }
  if (components.hash_start != url_components::omitted) {
    answer.append("\t\"fragment\":\"");
    helpers::encode_json(get_hash(), back);
    answer.append("\",\n");
  }

  auto convert_offset_to_string = [](uint32_t offset) -> std::string {
    if (offset == url_components::omitted) {
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
  if (components.host_start == components.host_end) {
    return false;
  }
  return checkers::verify_dns_length(get_hostname());
}

bool url_aggregator::parse_ipv4(std::string_view input) {
  ada_log("parse_ipv4 ", input, "[", input.size(),
          " bytes], overlaps with buffer: ",
          helpers::overlaps(input, buffer) ? "yes" : "no");
  ADA_ASSERT_TRUE(validate());
  const bool trailing_dot = (input.back() == '.');
  if (trailing_dot) {
    input.remove_suffix(1);
  }
  size_t digit_count{0};
  int pure_decimal_count = 0;  // entries that are decimal
  uint64_t ipv4{0};
  // we could unroll for better performance?
  for (; (digit_count < 4) && !(input.empty()); digit_count++) {
    uint32_t
        segment_result{};  // If any number exceeds 32 bits, we have an error.
    bool is_hex = checkers::has_hex_prefix(input);
    if (is_hex && ((input.length() == 2) ||
                   ((input.length() > 2) && (input[2] == '.')))) {
      // special case
      segment_result = 0;
      input.remove_prefix(2);
    } else {
      std::from_chars_result r;
      if (is_hex) {
        r = std::from_chars(input.data() + 2, input.data() + input.size(),
                            segment_result, 16);
      } else if ((input.length() >= 2) && input[0] == '0' &&
                 checkers::is_digit(input[1])) {
        r = std::from_chars(input.data() + 1, input.data() + input.size(),
                            segment_result, 8);
      } else {
        pure_decimal_count++;
        r = std::from_chars(input.data(), input.data() + input.size(),
                            segment_result, 10);
      }
      if (r.ec != std::errc()) {
        return is_valid = false;
      }
      input.remove_prefix(r.ptr - input.data());
    }
    if (input.empty()) {
      // We have the last value.
      // At this stage, ipv4 contains digit_count*8 bits.
      // So we have 32-digit_count*8 bits left.
      if (segment_result > (uint64_t(1) << (32 - digit_count * 8))) {
        return is_valid = false;
      }
      ipv4 <<= (32 - digit_count * 8);
      ipv4 |= segment_result;
      goto final;
    } else {
      // There is more, so that the value must no be larger than 255
      // and we must have a '.'.
      if ((segment_result > 255) || (input[0] != '.')) {
        return is_valid = false;
      }
      ipv4 <<= 8;
      ipv4 |= segment_result;
      input.remove_prefix(1);  // remove '.'
    }
  }
  if ((digit_count != 4) || (!input.empty())) {
    return is_valid = false;
  }
final:
  ada_log("url_aggregator::parse_ipv4 completed ", get_href(),
          " host: ", get_host());

  // We could also check r.ptr to see where the parsing ended.
  if (pure_decimal_count == 4 && !trailing_dot) {
    // The original input was already all decimal and we validated it. So we
    // don't need to do anything.
  } else {
    // Optimization opportunity: Get rid of unnecessary string return in ipv4
    // serializer.
    // TODO: This is likely a bug because it goes back update_base_hostname, not
    // what we want to do.
    update_base_hostname(
        ada::serializers::ipv4(ipv4));  // We have to reserialize the address.
  }
  host_type = IPV4;
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::parse_ipv6(std::string_view input) {
  // TODO: Find a way to merge parse_ipv6 with url.cpp implementation.
  ada_log("parse_ipv6 ", input, "[", input.size(), " bytes]");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (input.empty()) {
    return is_valid = false;
  }
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
    // If remaining does not start with U+003A (:), validation error, return
    // failure.
    if (input.size() == 1 || input[1] != ':') {
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

      // Increase pointer and pieceIndex by 1, set compress to pieceIndex, and
      // then continue.
      pointer++;
      compress = ++piece_index;
      continue;
    }

    // Let value and length be 0.
    uint16_t value = 0, length = 0;

    // While length is less than 4 and c is an ASCII hex digit,
    // set value to value times 0x10 + c interpreted as hexadecimal number, and
    // increase pointer and length by 1.
    while (length < 4 && pointer != input.end() &&
           unicode::is_ascii_hex_digit(*pointer)) {
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
          // If c is a U+002E (.) and numbersSeen is less than 4, then increase
          // pointer by 1.
          if (*pointer == '.' && numbers_seen < 4) {
            pointer++;
          } else {
            // Otherwise, validation error, return failure.
            ada_log("parse_ipv6 Otherwise, validation error, return failure");
            return is_valid = false;
          }
        }

        // If c is not an ASCII digit, validation error, return failure.
        if (pointer == input.end() || !checkers::is_digit(*pointer)) {
          ada_log(
              "parse_ipv6 If c is not an ASCII digit, validation error, return "
              "failure");
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
          // Otherwise, set ipv4Piece to ipv4Piece times 10 + number.
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

        // Set address[pieceIndex] to address[pieceIndex] times 0x100 +
        // ipv4Piece.
        // https://stackoverflow.com/questions/39060852/why-does-the-addition-of-two-shorts-return-an-int
        address[piece_index] =
            uint16_t(address[piece_index] * 0x100 + *ipv4_piece);

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
        ada_log(
            "parse_ipv6 If c is the EOF code point, validation error, return "
            "failure");
        return is_valid = false;
      }
    }
    // Otherwise, if c is not the EOF code point, validation error, return
    // failure.
    else if (pointer != input.end()) {
      ada_log(
          "parse_ipv6 Otherwise, if c is not the EOF code point, validation "
          "error, return failure");
      return is_valid = false;
    }

    // Set address[pieceIndex] to value.
    address[piece_index] = value;

    // Increase pieceIndex by 1.
    piece_index++;
  }

  // If compress is non-null, then:
  if (compress.has_value()) {
    // Let swaps be pieceIndex - compress.
    int swaps = piece_index - *compress;

    // Set pieceIndex to 7.
    piece_index = 7;

    // While pieceIndex is not 0 and swaps is greater than 0,
    // swap address[pieceIndex] with address[compress + swaps - 1], and then
    // decrease both pieceIndex and swaps by 1.
    while (piece_index != 0 && swaps > 0) {
      std::swap(address[piece_index], address[*compress + swaps - 1]);
      piece_index--;
      swaps--;
    }
  }
  // Otherwise, if compress is null and pieceIndex is not 8, validation error,
  // return failure.
  else if (piece_index != 8) {
    ada_log(
        "parse_ipv6 if compress is null and pieceIndex is not 8, validation "
        "error, return failure");
    return is_valid = false;
  }
  // TODO: Optimization opportunity: Get rid of unnecessary string creation.
  // TODO: This is likely a bug because it goes back update_base_hostname, not
  // what we want to do.
  update_base_hostname(ada::serializers::ipv6(address));
  ada_log("parse_ipv6 ", get_hostname());
  ADA_ASSERT_TRUE(validate());
  host_type = IPV6;
  return true;
}

bool url_aggregator::parse_opaque_host(std::string_view input) {
  ada_log("parse_opaque_host ", input, "[", input.size(), " bytes]");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (std::any_of(input.begin(), input.end(),
                  ada::unicode::is_forbidden_host_code_point)) {
    return is_valid = false;
  }

  // Return the result of running UTF-8 percent-encode on input using the C0
  // control percent-encode set.
  size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::C0_CONTROL_PERCENT_ENCODE);
  if (idx == input.size()) {
    update_base_hostname(input);
  } else {
    // We only create a temporary string if we need to.
    update_base_hostname(ada::unicode::percent_encode(
        input, character_sets::C0_CONTROL_PERCENT_ENCODE, idx));
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

[[nodiscard]] std::string url_aggregator::to_diagram() const {
  if (!is_valid) {
    return "invalid";
  }
  std::string answer;
  answer.append(buffer);
  answer.append(" [");
  answer.append(std::to_string(buffer.size()));
  answer.append(" bytes]");
  answer.append("\n");
  // first line
  std::string line1;
  line1.resize(buffer.size(), ' ');
  if (components.hash_start != url_components::omitted) {
    line1[components.hash_start] = '|';
  }
  if (components.search_start != url_components::omitted) {
    line1[components.search_start] = '|';
  }
  if (components.pathname_start != buffer.size()) {
    line1[components.pathname_start] = '|';
  }
  if (components.host_end != buffer.size()) {
    line1[components.host_end] = '|';
  }
  if (components.host_start != buffer.size()) {
    line1[components.host_start] = '|';
  }
  if (components.username_end != buffer.size()) {
    line1[components.username_end] = '|';
  }
  if (components.protocol_end != buffer.size()) {
    line1[components.protocol_end] = '|';
  }
  answer.append(line1);
  answer.append("\n");

  std::string line2 = line1;
  if (components.hash_start != url_components::omitted) {
    line2[components.hash_start] = '`';
    line1[components.hash_start] = ' ';

    for (size_t i = components.hash_start + 1; i < line2.size(); i++) {
      line2[i] = '-';
    }
    line2.append(" hash_start");
    answer.append(line2);
    answer.append("\n");
  }

  std::string line3 = line1;
  if (components.search_start != url_components::omitted) {
    line3[components.search_start] = '`';
    line1[components.search_start] = ' ';

    for (size_t i = components.search_start + 1; i < line3.size(); i++) {
      line3[i] = '-';
    }
    line3.append(" search_start ");
    line3.append(std::to_string(components.search_start));
    answer.append(line3);
    answer.append("\n");
  }

  std::string line4 = line1;
  if (components.pathname_start != buffer.size()) {
    line4[components.pathname_start] = '`';
    line1[components.pathname_start] = ' ';
    for (size_t i = components.pathname_start + 1; i < line4.size(); i++) {
      line4[i] = '-';
    }
    line4.append(" pathname_start ");
    line4.append(std::to_string(components.pathname_start));
    answer.append(line4);
    answer.append("\n");
  }

  std::string line5 = line1;
  if (components.host_end != buffer.size()) {
    line5[components.host_end] = '`';
    line1[components.host_end] = ' ';

    for (size_t i = components.host_end + 1; i < line5.size(); i++) {
      line5[i] = '-';
    }
    line5.append(" host_end ");
    line5.append(std::to_string(components.host_end));
    answer.append(line5);
    answer.append("\n");
  }

  std::string line6 = line1;
  if (components.host_start != buffer.size()) {
    line6[components.host_start] = '`';
    line1[components.host_start] = ' ';

    for (size_t i = components.host_start + 1; i < line6.size(); i++) {
      line6[i] = '-';
    }
    line6.append(" host_start ");
    line6.append(std::to_string(components.host_start));
    answer.append(line6);
    answer.append("\n");
  }

  std::string line7 = line1;
  if (components.username_end != buffer.size()) {
    line7[components.username_end] = '`';
    line1[components.username_end] = ' ';

    for (size_t i = components.username_end + 1; i < line7.size(); i++) {
      line7[i] = '-';
    }
    line7.append(" username_end ");
    line7.append(std::to_string(components.username_end));
    answer.append(line7);
    answer.append("\n");
  }

  std::string line8 = line1;
  if (components.protocol_end != buffer.size()) {
    line8[components.protocol_end] = '`';
    line1[components.protocol_end] = ' ';

    for (size_t i = components.protocol_end + 1; i < line8.size(); i++) {
      line8[i] = '-';
    }
    line8.append(" protocol_end ");
    line8.append(std::to_string(components.protocol_end));
    answer.append(line8);
    answer.append("\n");
  }

  if (components.hash_start == url_components::omitted) {
    answer.append("note: hash omitted\n");
  }
  if (components.search_start == url_components::omitted) {
    answer.append("note: search omitted\n");
  }
  if (components.protocol_end > buffer.size()) {
    answer.append("warning: protocol_end overflows\n");
  }
  if (components.username_end > buffer.size()) {
    answer.append("warning: username_end overflows\n");
  }
  if (components.host_start > buffer.size()) {
    answer.append("warning: host_start overflows\n");
  }
  if (components.host_end > buffer.size()) {
    answer.append("warning: host_end overflows\n");
  }
  if (components.pathname_start > buffer.size()) {
    answer.append("warning: pathname_start overflows\n");
  }
  return answer;
}

[[nodiscard]] bool url_aggregator::validate() const noexcept {
  if (!is_valid) {
    return true;
  }
  if (!components.check_offset_consistency()) {
    ada_log("url_aggregator::validate inconsistent components \n",
            to_diagram());
    return false;
  }
  // We have a credible components struct, but let us investivate more
  // carefully:
  /**
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *       |     |    |          | ^^^^|       |   |
   *       |     |    |          | |   |       |   `----- hash_start
   *       |     |    |          | |   |       `--------- search_start
   *       |     |    |          | |   `----------------- pathname_start
   *       |     |    |          | `--------------------- port
   *       |     |    |          `----------------------- host_end
   *       |     |    `---------------------------------- host_start
   *       |     `--------------------------------------- username_end
   *       `--------------------------------------------- protocol_end
   */
  if (components.protocol_end == url_components::omitted) {
    ada_log("url_aggregator::validate omitted protocol_end \n", to_diagram());
    return false;
  }
  if (components.username_end == url_components::omitted) {
    ada_log("url_aggregator::validate omitted username_end \n", to_diagram());
    return false;
  }
  if (components.host_start == url_components::omitted) {
    ada_log("url_aggregator::validate omitted host_start \n", to_diagram());
    return false;
  }
  if (components.host_end == url_components::omitted) {
    ada_log("url_aggregator::validate omitted host_end \n", to_diagram());
    return false;
  }
  if (components.pathname_start == url_components::omitted) {
    ada_log("url_aggregator::validate omitted pathname_start \n", to_diagram());
    return false;
  }

  if (components.protocol_end > buffer.size()) {
    ada_log("url_aggregator::validate protocol_end overflow \n", to_diagram());
    return false;
  }
  if (components.username_end > buffer.size()) {
    ada_log("url_aggregator::validate username_end overflow \n", to_diagram());
    return false;
  }
  if (components.host_start > buffer.size()) {
    ada_log("url_aggregator::validate host_start overflow \n", to_diagram());
    return false;
  }
  if (components.host_end > buffer.size()) {
    ada_log("url_aggregator::validate host_end overflow \n", to_diagram());
    return false;
  }
  if (components.pathname_start > buffer.size()) {
    ada_log("url_aggregator::validate pathname_start overflow \n",
            to_diagram());
    return false;
  }

  if (components.protocol_end > 0) {
    if (buffer[components.protocol_end - 1] != ':') {
      ada_log(
          "url_aggregator::validate missing : at the end of the protocol \n",
          to_diagram());
      return false;
    }
  }

  if (components.username_end != buffer.size() &&
      components.username_end > components.protocol_end + 2) {
    if (buffer[components.username_end] != ':' &&
        buffer[components.username_end] != '@') {
      ada_log(
          "url_aggregator::validate missing : or @ at the end of the username "
          "\n",
          to_diagram());
      return false;
    }
  }

  if (components.host_start != buffer.size()) {
    if (components.host_start > components.username_end) {
      if (buffer[components.host_start] != '@') {
        ada_log(
            "url_aggregator::validate missing @ at the end of the password \n",
            to_diagram());
        return false;
      }
    } else if (components.host_start == components.username_end &&
               components.host_end > components.host_start) {
      if (components.host_start == components.protocol_end + 2) {
        if (buffer[components.protocol_end] != '/' ||
            buffer[components.protocol_end + 1] != '/') {
          ada_log(
              "url_aggregator::validate missing // between protocol and host "
              "\n",
              to_diagram());
          return false;
        }
      } else {
        if (components.host_start > components.protocol_end &&
            buffer[components.host_start] != '@') {
          ada_log(
              "url_aggregator::validate missing @ at the end of the username "
              "\n",
              to_diagram());
          return false;
        }
      }
    } else {
      if (components.host_end != components.host_start) {
        ada_log("url_aggregator::validate expected omitted host \n",
                to_diagram());
        return false;
      }
    }
  }
  if (components.host_end != buffer.size() &&
      components.pathname_start > components.host_end) {
    if (components.pathname_start == components.host_end + 2 &&
        buffer[components.host_end] == '/' &&
        buffer[components.host_end + 1] == '.') {
      if (components.pathname_start + 1 >= buffer.size() ||
          buffer[components.pathname_start] != '/' ||
          buffer[components.pathname_start + 1] != '/') {
        ada_log(
            "url_aggregator::validate expected the path to begin with // \n",
            to_diagram());
        return false;
      }
    } else if (buffer[components.host_end] != ':') {
      ada_log("url_aggregator::validate missing : at the port \n",
              to_diagram());
      return false;
    }
  }
  if (components.pathname_start != buffer.size() &&
      components.pathname_start < components.search_start &&
      components.pathname_start < components.hash_start && !has_opaque_path) {
    if (buffer[components.pathname_start] != '/') {
      ada_log("url_aggregator::validate missing / at the path \n",
              to_diagram());
      return false;
    }
  }
  if (components.search_start != url_components::omitted) {
    if (buffer[components.search_start] != '?') {
      ada_log("url_aggregator::validate missing ? at the search \n",
              to_diagram());
      return false;
    }
  }
  if (components.hash_start != url_components::omitted) {
    if (buffer[components.hash_start] != '#') {
      ada_log("url_aggregator::validate missing # at the hash \n",
              to_diagram());
      return false;
    }
  }

  return true;
}

void url_aggregator::delete_dash_dot() {
  ada_log("url_aggregator::delete_dash_dot");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(has_dash_dot());
  buffer.erase(components.host_end, 2);
  components.pathname_start -= 2;
  if (components.search_start != url_components::omitted) {
    components.search_start -= 2;
  }
  if (components.hash_start != url_components::omitted) {
    components.hash_start -= 2;
  }
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!has_dash_dot());
}

inline void url_aggregator::consume_prepared_path(std::string_view input) {
  ada_log("url_aggregator::consume_prepared_path ", input);
  /***
   * This is largely duplicated code from helpers::parse_prepared_path, which is
   * unfortunate. This particular function is nearly identical, except that it
   * is a method on url_aggregator. The idea is that the trivial path (which is
   * very common) merely appends to the buffer. This is the same trivial path as
   * with helpers::parse_prepared_path, except that we have the additional check
   * for is_at_path(). Otherwise, we grab a copy of the current path and we
   * modify it, and then insert it back into the buffer.
   */
  uint8_t accumulator = checkers::path_signature(input);
  // Let us first detect a trivial case.
  // If it is special, we check that we have no dot, no %,  no \ and no
  // character needing percent encoding. Otherwise, we check that we have no %,
  // no dot, and no character needing percent encoding.
  constexpr uint8_t need_encoding = 1;
  constexpr uint8_t backslash_char = 2;
  constexpr uint8_t dot_char = 4;
  constexpr uint8_t percent_char = 8;
  bool special = type != ada::scheme::NOT_SPECIAL;
  bool may_need_slow_file_handling = (type == ada::scheme::type::FILE &&
                                      checkers::is_windows_drive_letter(input));
  bool trivial_path =
      (special ? (accumulator == 0)
               : ((accumulator & (need_encoding | dot_char | percent_char)) ==
                  0)) &&
      (!may_need_slow_file_handling);
  if (accumulator == dot_char && !may_need_slow_file_handling) {
    // '4' means that we have at least one dot, but nothing that requires
    // percent encoding or decoding. The only part that is not trivial is
    // that we may have single dots and double dots path segments.
    // If we have such segments, then we either have a path that begins
    // with '.' (easy to check), or we have the sequence './'.
    // Note: input cannot be empty, it must at least contain one character ('.')
    // Note: we know that '\' is not present.
    if (input[0] != '.') {
      size_t slashdot = input.find("/.");
      if (slashdot == std::string_view::npos) {  // common case
        trivial_path = true;
      } else {  // uncommon
        // only three cases matter: /./, /.. or a final /
        trivial_path =
            !(slashdot + 2 == input.size() || input[slashdot + 2] == '.' ||
              input[slashdot + 2] == '/');
      }
    }
  }
  if (trivial_path && is_at_path()) {
    ada_log("parse_path trivial");
    buffer += '/';
    buffer += input;
    return;
  }
  std::string path = std::string(get_pathname());
  // We are going to need to look a bit at the path, but let us see if we can
  // ignore percent encoding *and* backslashes *and* percent characters.
  // Except for the trivial case, this is likely to capture 99% of paths out
  // there.
  bool fast_path =
      (special &&
       (accumulator & (need_encoding | backslash_char | percent_char)) == 0) &&
      (type != ada::scheme::type::FILE);
  if (fast_path) {
    ada_log("parse_prepared_path fast");
    // Here we don't need to worry about \ or percent encoding.
    // We also do not have a file protocol. We might have dots, however,
    // but dots must as appear as '.', and they cannot be encoded because
    // the symbol '%' is not present.
    size_t previous_location = 0;  // We start at 0.
    do {
      size_t new_location = input.find('/', previous_location);
      // std::string_view path_view = input;
      //  We process the last segment separately:
      if (new_location == std::string_view::npos) {
        std::string_view path_view = input.substr(previous_location);
        if (path_view == "..") {  // The path ends with ..
          // e.g., if you receive ".." with an empty path, you go to "/".
          if (path.empty()) {
            path = '/';
            update_base_pathname(path);
            return;
          }
          // Fast case where we have nothing to do:
          if (path.back() == '/') {
            update_base_pathname(path);
            return;
          }
          // If you have the path "/joe/myfriend",
          // then you delete 'myfriend'.
          path.resize(path.rfind('/') + 1);
          update_base_pathname(path);
          return;
        }
        path += '/';
        if (path_view != ".") {
          path.append(path_view);
        }
        update_base_pathname(path);
        return;
      } else {
        // This is a non-final segment.
        std::string_view path_view =
            input.substr(previous_location, new_location - previous_location);
        previous_location = new_location + 1;
        if (path_view == "..") {
          size_t last_delimiter = path.rfind('/');
          if (last_delimiter != std::string::npos) {
            path.erase(last_delimiter);
          }
        } else if (path_view != ".") {
          path += '/';
          path.append(path_view);
        }
      }
    } while (true);
  } else {
    ada_log("parse_path slow");
    // we have reached the general case
    bool needs_percent_encoding = (accumulator & 1);
    std::string path_buffer_tmp;
    do {
      size_t location = (special && (accumulator & 2))
                            ? input.find_first_of("/\\")
                            : input.find('/');
      std::string_view path_view = input;
      if (location != std::string_view::npos) {
        path_view.remove_suffix(path_view.size() - location);
        input.remove_prefix(location + 1);
      }
      // path_buffer is either path_view or it might point at a percent encoded
      // temporary string.
      std::string_view path_buffer =
          (needs_percent_encoding &&
           ada::unicode::percent_encode<false>(
               path_view, character_sets::PATH_PERCENT_ENCODE, path_buffer_tmp))
              ? path_buffer_tmp
              : path_view;
      if (unicode::is_double_dot_path_segment(path_buffer)) {
        if ((helpers::shorten_path(path, type) || special) &&
            location == std::string_view::npos) {
          path += '/';
        }
      } else if (unicode::is_single_dot_path_segment(path_buffer) &&
                 (location == std::string_view::npos)) {
        path += '/';
      }
      // Otherwise, if path_buffer is not a single-dot path segment, then:
      else if (!unicode::is_single_dot_path_segment(path_buffer)) {
        // If url's scheme is "file", url's path is empty, and path_buffer is a
        // Windows drive letter, then replace the second code point in
        // path_buffer with U+003A (:).
        if (type == ada::scheme::type::FILE && path.empty() &&
            checkers::is_windows_drive_letter(path_buffer)) {
          path += '/';
          path += path_buffer[0];
          path += ':';
          path_buffer.remove_prefix(2);
          path.append(path_buffer);
        } else {
          // Append path_buffer to url's path.
          path += '/';
          path.append(path_buffer);
        }
      }
      if (location == std::string_view::npos) {
        update_base_pathname(path);
        return;
      }
    } while (true);
  }
}
}  // namespace ada

#include "ada/checkers-inl.h"
#include "ada/helpers.h"
#include "ada/implementation.h"
#include "ada/scheme.h"
#include "ada/serializers.h"
#include "ada/unicode-inl.h"
#include "ada/url_components.h"
#include "ada/url_components-inl.h"
#include "ada/url_aggregator.h"
#include "ada/url_aggregator-inl.h"
#include "ada/url_ip-inl.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <ranges>
#include <string>
#include <string_view>

namespace {

ada_really_inline void apply_shifted_non_scheme_offsets(
    ada::url_components& components, uint32_t new_difference) {
  components.username_end += new_difference;
  components.host_start += new_difference;
  components.host_end += new_difference;
  components.pathname_start += new_difference;
  if (components.search_start != ada::url_components::omitted) {
    components.search_start += new_difference;
  }
  if (components.hash_start != ada::url_components::omitted) {
    components.hash_start += new_difference;
  }
}

}  // namespace

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
  const bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
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
      if ((has_credentials() || components.port != url_components::omitted) &&
          parsed_type == ada::scheme::type::FILE) {
        return false;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE &&
          components.host_start == components.host_end) {
        return false;
      }
    }

    type = parsed_type;
    set_scheme_from_view_with_colon(input_with_colon);

    if constexpr (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url's port is url's scheme's default port, then set url's port to
        // null.
        if (components.port == urls_scheme_port) {
          clear_port();
        }
      }
    }
  } else {  // slow path
    std::string _buffer(input);
    // Next function is only valid if the input is ASCII and returns false
    // otherwise, but it seems that we always have ascii content so we do not
    // need to check the return value.
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
      if ((has_credentials() || components.port != url_components::omitted) &&
          _buffer == "file") {
        return false;
      }

      // If url's scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE &&
          components.host_start == components.host_end) {
        return false;
      }
    }

    set_scheme(_buffer);

    if constexpr (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url's port is url's scheme's default port, then set url's port to
        // null.
        if (components.port == urls_scheme_port) {
          clear_port();
        }
      }
    }
  }
  ADA_ASSERT_TRUE(validate());
  return true;
}

inline void url_aggregator::copy_scheme(const url_aggregator& u) {
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

  apply_shifted_non_scheme_offsets(components, new_difference);
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::set_scheme_from_view_with_colon(
    std::string_view new_scheme_with_colon) {
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

  apply_shifted_non_scheme_offsets(components, new_difference);
  ADA_ASSERT_TRUE(validate());
}

inline void url_aggregator::set_scheme(std::string_view new_scheme) {
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

  apply_shifted_non_scheme_offsets(components, new_difference);
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
      std::ranges::find_if_not(view, unicode::is_alnum_plus);

  if (pointer != view.end() && *pointer == ':') {
    url_aggregator saved_url(*this);
    bool result = parse_scheme_with_colon<true>(
        view.substr(0, pointer - view.begin() + 1));
    if (result && buffer.size() > ada::get_max_input_length()) {
      *this = std::move(saved_url);
      return false;
    }
    return result;
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
  url_aggregator saved_url(*this);
  size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (idx == input.size()) {
    update_base_username(input);
  } else {
    // We only create a temporary string if we have to!
    update_base_username(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  if (buffer.size() > ada::get_max_input_length()) {
    *this = std::move(saved_url);
    return false;
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
  url_aggregator saved_url(*this);
  size_t idx = ada::unicode::percent_encode_index(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  if (idx == input.size()) {
    update_base_password(input);
  } else {
    // We only create a temporary string if we have to!
    update_base_password(ada::unicode::percent_encode(
        input, character_sets::USERINFO_PERCENT_ENCODE, idx));
  }
  if (buffer.size() > ada::get_max_input_length()) {
    *this = std::move(saved_url);
    return false;
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

  if (input.empty()) {
    clear_port();
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
  url_aggregator saved_url(*this);
  parse_port(digits_to_parse);
  if (is_valid) {
    if (buffer.size() > ada::get_max_input_length()) {
      *this = std::move(saved_url);
      return false;
    }
    return true;
  }
  *this = std::move(saved_url);
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
  url_aggregator saved_url(*this);
  clear_pathname();
  parse_path(input);
  if (get_pathname().starts_with("//") && !has_authority() && !has_dash_dot()) {
    buffer.insert(components.pathname_start, "/.");
    components.pathname_start += 2;
    if (components.search_start != url_components::omitted) {
      components.search_start += 2;
    }
    if (components.hash_start != url_components::omitted) {
      components.hash_start += 2;
    }
  }
  if (buffer.size() > ada::get_max_input_length()) {
    *this = std::move(saved_url);
    return false;
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

  url_aggregator saved_url(*this);
  update_base_search(new_value, query_percent_encode_set);
  if (buffer.size() > ada::get_max_input_length()) {
    *this = std::move(saved_url);
    return;
  }
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
  url_aggregator saved_url(*this);
  update_unencoded_base_hash(new_value);
  if (buffer.size() > ada::get_max_input_length()) {
    *this = std::move(saved_url);
    return;
  }
  ADA_ASSERT_TRUE(validate());
}

bool url_aggregator::set_href(const std::string_view input) {
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  ada_log("url_aggregator::set_href ", input, " [", input.size(), " bytes]");
  ada::result<url_aggregator> out = ada::parse<url_aggregator>(input);
  ada_log("url_aggregator::set_href, success :", out.has_value());

  if (out) {
    // The parser enforces get_max_input_length() on both the input and the
    // normalized result. This is a defense-in-depth check.
    if (out->buffer.size() > ada::get_max_input_length()) {
      return false;
    }
    ada_log("url_aggregator::set_href, parsed ", out->to_string());
    // TODO: Figure out why the following line puts test to never finish.
    *this = *out;
  }

  return out.has_value();
}

ada_really_inline bool url_aggregator::parse_host(std::string_view input) {
  ada_log("url_aggregator:parse_host \"", input, "\" [", input.size(),
          " bytes]");
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

  // Fast path: try to parse as pure decimal IPv4(a.b.c.d) first.
  const uint64_t fast_result = checkers::try_parse_ipv4_fast(input);
  if (fast_result < checkers::ipv4_fast_fail) {
    // Fast path succeeded - input is pure decimal IPv4
    if (!input.empty() && input.back() == '.') {
      update_base_hostname(input.substr(0, input.size() - 1));
    } else {
      update_base_hostname(input);
    }
    host_type = IPV4;
    is_valid = true;
    ada_log("parse_host fast path decimal ipv4");
    ADA_ASSERT_TRUE(validate());
    return true;
  }
  uint8_t is_forbidden_or_upper =
      unicode::contains_forbidden_domain_code_point_or_upper(input.data(),
                                                             input.size());
  // Minor optimization opportunity:
  // contains_forbidden_domain_code_point_or_upper could be extend to check for
  // the presence of characters that cannot appear in the ipv4 address and we
  // could also check whether x and n and - are present, and so we could skip
  // some of the checks below. However, the gains are likely to be small, and
  // the code would be more complex.
  static constexpr std::string_view xn_dash{"xn-", 3};
  if (is_forbidden_or_upper == 0 &&
      input.find(xn_dash) == std::string_view::npos) {
    // fast path
    update_base_hostname(input);

    // Check for other IPv4 formats (hex, octal, etc.)
    if (checkers::is_ipv4(get_hostname())) {
      ada_log("parse_host fast path ipv4");
      return parse_ipv4(get_hostname(), true);
    }
    ada_log("parse_host fast path ", get_hostname());
    is_valid = true;
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
  ada_log("parse_host to_ascii succeeded ", *host, " [", host->size(),
          " bytes]");

  if (std::ranges::any_of(host.value(),
                          ada::unicode::is_forbidden_domain_code_point)) {
    return is_valid = false;
  }

  // If asciiDomain ends in a number, then return the result of IPv4 parsing
  // asciiDomain.
  if (checkers::is_ipv4(host.value())) {
    ada_log("parse_host got ipv4 ", *host);
    return parse_ipv4(host.value(), false);
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

  url_aggregator saved_url(*this);

  size_t host_end_pos = input.find('#');
  std::string _host(input.data(), host_end_pos != std::string_view::npos
                                      ? host_end_pos
                                      : input.size());
  helpers::remove_ascii_tab_or_newline(_host);
  std::string_view new_host(_host);

  auto check_url_size = [&]() -> bool {
    if (buffer.size() > ada::get_max_input_length()) {
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
      std::string_view host_buffer = host_view.substr(0, location);
      if (host_buffer.empty()) {
        return false;
      }

      // If state override is given and state override is hostname state, then
      // return failure.
      if constexpr (override_hostname) {
        return false;
      }

      // Let host be the result of host parsing buffer with url is not special.
      bool succeeded = parse_host(host_buffer);
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
      if (host_view.empty() && (has_credentials() || has_port())) {
        return false;
      }

      // Let host be the result of host parsing host_view with url is not
      // special.
      if (host_view.empty() && !is_special()) {
        if (has_hostname()) {
          clear_hostname();  // easy!
        } else if (has_dash_dot()) {
          add_authority_slashes_if_needed();
          delete_dash_dot();
        } else {
          // The url has no authority yet (e.g. "foo:/bar"); setting an empty
          // host must still give it an (empty) authority, matching ada::url.
          add_authority_slashes_if_needed();
        }
        return check_url_size();
      }

      bool succeeded = parse_host(host_view);
      if (!succeeded) {
        *this = std::move(saved_url);
        return false;
      } else if (has_dash_dot()) {
        // Should remove dash_dot from pathname
        delete_dash_dot();
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
    clear_hostname();
  } else {
    // Let host be the result of host parsing buffer with url is not special.
    if (!parse_host(new_host)) {
      *this = std::move(saved_url);
      return false;
    }

    // If host is "localhost", then set host to the empty string.
    if (helpers::substring(buffer, components.host_start,
                           components.host_end) == "localhost") {
      clear_hostname();
    }
  }
  ADA_ASSERT_TRUE(validate());
  return check_url_size();
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

[[nodiscard]] std::string url_aggregator::get_origin() const {
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

[[nodiscard]] std::string_view url_aggregator::get_username() const
    ada_lifetime_bound {
  ada_log("url_aggregator::get_username");
  if (has_non_empty_username()) {
    return helpers::substring(buffer, components.protocol_end + 2,
                              components.username_end);
  }
  return "";
}

[[nodiscard]] std::string_view url_aggregator::get_password() const
    ada_lifetime_bound {
  ada_log("url_aggregator::get_password");
  if (has_non_empty_password()) {
    return helpers::substring(buffer, components.username_end + 1,
                              components.host_start);
  }
  return "";
}

[[nodiscard]] std::string_view url_aggregator::get_port() const
    ada_lifetime_bound {
  ada_log("url_aggregator::get_port");
  if (components.port == url_components::omitted) {
    return "";
  }
  return helpers::substring(buffer, components.host_end + 1,
                            components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_hash() const
    ada_lifetime_bound {
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

[[nodiscard]] std::string_view url_aggregator::get_host() const
    ada_lifetime_bound {
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
    return {};
  }
  return helpers::substring(buffer, start, components.pathname_start);
}

[[nodiscard]] std::string_view url_aggregator::get_hostname() const
    ada_lifetime_bound {
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

[[nodiscard]] std::string_view url_aggregator::get_search() const
    ada_lifetime_bound {
  ada_log("url_aggregator::get_search");
  // If this's URL's query is either null or the empty string, then return the
  // empty string. Return U+003F (?), followed by this's URL's query.
  if (components.search_start == url_components::omitted) {
    return "";
  }
  auto ending_index = uint32_t(buffer.size());
  if (components.hash_start != url_components::omitted) {
    ending_index = components.hash_start;
  }
  if (ending_index - components.search_start <= 1) {
    return "";
  }
  return helpers::substring(buffer, components.search_start, ending_index);
}

[[nodiscard]] std::string_view url_aggregator::get_protocol() const
    ada_lifetime_bound {
  ada_log("url_aggregator::get_protocol");
  return helpers::substring(buffer, 0, components.protocol_end);
}

[[nodiscard]] std::string ada::url_aggregator::to_string() const {
  ada_log("url_aggregator::to_string buffer:", buffer, " [", buffer.size(),
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
  // Avoid allocation: construct a string_view directly into the buffer.
  size_t start = components.host_start;
  if (components.host_end > components.host_start &&
      buffer[components.host_start] == '@') {
    start++;
  }
  return checkers::verify_dns_length(
      std::string_view(buffer.data() + start, components.host_end - start));
}

bool url_aggregator::parse_ipv4(std::string_view input, bool in_place) {
  ada_log("parse_ipv4 ", input, " [", input.size(),
          " bytes], overlaps with buffer: ",
          helpers::overlaps(input, buffer) ? "yes" : "no");
  ADA_ASSERT_TRUE(validate());
  if (input.empty()) {
    return is_valid = false;
  }
  const bool trailing_dot = (input.back() == '.');
  if (trailing_dot) {
    input.remove_suffix(1);
    if (input.empty()) {
      return is_valid = false;
    }
  }

  const uint64_t fast = checkers::try_parse_ipv4_fast(input);
  if (fast < checkers::ipv4_fast_fail) [[likely]] {
    // Pure decimal: keep the buffer when it already holds the address.
    // Otherwise write the (trailing-dot-stripped) input.
    if (!(in_place && !trailing_dot)) {
      update_base_hostname(input);
    }
    host_type = IPV4;
    ADA_ASSERT_TRUE(validate());
    return true;
  }

  const char* p = input.data();
  const char* end = p + input.size();
  uint64_t ipv4 = 0;
  int digit_count = 0;
  int pure_decimal_count = 0;

  for (; digit_count < 4 && p < end; ++digit_count) {
    uint64_t segment = 0;
    bool pure = false;
    if (!detail::parse_ipv4_number(p, end, segment, pure)) {
      return is_valid = false;
    }
    if (pure) {
      ++pure_decimal_count;
    }
    if (p >= end) {
      const unsigned shift = static_cast<unsigned>(32 - digit_count * 8);
      if (segment >= (uint64_t{1} << shift)) {
        return is_valid = false;
      }
      ipv4 = (ipv4 << shift) | segment;
      goto ipv4_done;
    }
    if (segment > 255 || *p != '.') {
      return is_valid = false;
    }
    ipv4 = (ipv4 << 8) | segment;
    ++p;
  }
  if (digit_count != 4 || p != end) {
    return is_valid = false;
  }
ipv4_done:
  ada_log("url_aggregator::parse_ipv4 completed ", get_href(),
          " host: ", get_host());
  if (in_place && pure_decimal_count == 4 && !trailing_dot) {
    ada_log(
        "url_aggregator::parse_ipv4 completed and was already correct in the "
        "buffer");
  } else {
    update_base_hostname(ada::serializers::ipv4(ipv4));
  }
  host_type = IPV4;
  ADA_ASSERT_TRUE(validate());
  return true;
}

bool url_aggregator::parse_ipv6(std::string_view input) {
  ada_log("parse_ipv6 ", input, " [", input.size(), " bytes]");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (input.empty() || input.size() > 45) [[unlikely]] {
    return is_valid = false;
  }

  std::array<uint16_t, 8> address{};
  const char* pointer = input.data();
  const char* const end = pointer + input.size();
  int piece_index = 0;
  int compress = -1;

  if (*pointer == ':') {
    if (input.size() == 1 || pointer[1] != ':') [[unlikely]] {
      return is_valid = false;
    }
    pointer += 2;
    compress = ++piece_index;
  }

  while (pointer != end) {
    if (piece_index == 8) [[unlikely]] {
      return is_valid = false;
    }
    if (*pointer == ':') {
      if (compress != -1) [[unlikely]] {
        return is_valid = false;
      }
      ++pointer;
      compress = ++piece_index;
      continue;
    }

    uint16_t value = 0;
    const int length = detail::parse_hex_piece(pointer, end, value);

    if (pointer != end && *pointer == '.') {
      if (length == 0) [[unlikely]] {
        return is_valid = false;
      }
      pointer -= length;
      if (piece_index > 6) [[unlikely]] {
        return is_valid = false;
      }

      int numbers_seen = 0;
      while (pointer != end) {
        int ipv4_piece = -1;
        if (numbers_seen > 0) {
          if (*pointer == '.' && numbers_seen < 4) {
            ++pointer;
          } else {
            return is_valid = false;
          }
        }
        if (pointer == end || *pointer < '0' || *pointer > '9') [[unlikely]] {
          return is_valid = false;
        }
        ipv4_piece = *pointer - '0';
        ++pointer;
        if (pointer != end && *pointer >= '0' && *pointer <= '9') {
          if (ipv4_piece == 0) [[unlikely]] {
            return is_valid = false;
          }
          ipv4_piece = ipv4_piece * 10 + (*pointer - '0');
          ++pointer;
          if (pointer != end && *pointer >= '0' && *pointer <= '9') {
            ipv4_piece = ipv4_piece * 10 + (*pointer - '0');
            ++pointer;
            if (ipv4_piece > 255) [[unlikely]] {
              return is_valid = false;
            }
          }
        }
        address[static_cast<size_t>(piece_index)] = static_cast<uint16_t>(
            address[static_cast<size_t>(piece_index)] * 0x100 +
            static_cast<uint16_t>(ipv4_piece));
        ++numbers_seen;
        if (numbers_seen == 2 || numbers_seen == 4) {
          ++piece_index;
        }
      }
      if (numbers_seen != 4) [[unlikely]] {
        return is_valid = false;
      }
      break;
    }

    if (length == 0) [[unlikely]] {
      return is_valid = false;
    }

    if (pointer != end && *pointer == ':') {
      ++pointer;
      if (pointer == end) [[unlikely]] {
        return is_valid = false;
      }
    } else if (pointer != end) [[unlikely]] {
      return is_valid = false;
    }

    address[static_cast<size_t>(piece_index)] = value;
    ++piece_index;
  }

  if (compress != -1) {
    const int right = piece_index - compress;
    if (right > 0) {
      const int dest = 8 - right;
      if (dest != compress) {
        for (int i = right - 1; i >= 0; --i) {
          address[static_cast<size_t>(dest + i)] =
              address[static_cast<size_t>(compress + i)];
          address[static_cast<size_t>(compress + i)] = 0;
        }
      }
    }
  } else if (piece_index != 8) [[unlikely]] {
    return is_valid = false;
  }

  // Serialize once; skip rewrite when hostname is already canonical.
  const std::string serialized = ada::serializers::ipv6(address);
  const std::string_view current = get_hostname();
  if (current.size() == serialized.size() &&
      std::memcmp(current.data(), serialized.data(), serialized.size()) == 0) {
    ada_log("parse_ipv6 in-place canonical match");
  } else {
    update_base_hostname(serialized);
  }
  ada_log("parse_ipv6 ", get_hostname());
  ADA_ASSERT_TRUE(validate());
  host_type = IPV6;
  return true;
}

bool url_aggregator::parse_opaque_host(std::string_view input) {
  ada_log("parse_opaque_host ", input, " [", input.size(), " bytes]");
  ADA_ASSERT_TRUE(validate());
  ADA_ASSERT_TRUE(!helpers::overlaps(input, buffer));
  if (std::ranges::any_of(input, ada::unicode::is_forbidden_host_code_point)) {
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
      size_t slashdot = 0;
      bool dot_is_file = true;
      for (;;) {
        slashdot = input.find("/.", slashdot);
        if (slashdot == std::string_view::npos) {  // common case
          break;
        } else {  // uncommon
          // only three cases matter: /./, /.. or a final /
          slashdot += 2;
          dot_is_file &= !(slashdot == input.size() || input[slashdot] == '.' ||
                           input[slashdot] == '/');
        }
      }
      trivial_path = dot_is_file;
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
        helpers::shorten_path(path, type);
        if (location == std::string_view::npos) {
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

#include "ada/url_pattern_helpers.h"

#include <algorithm>
#include <optional>
#include <string>

namespace ada::url_pattern_helpers {

std::tuple<std::string, std::vector<std::string>>
generate_regular_expression_and_name_list(
    std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options options) {
  // Let result be "^"
  std::string result = "^";

  // Let name list be a new list
  std::vector<std::string> name_list{};
  const std::string full_wildcard_regexp_value = ".*";

  // For each part of part list:
  for (const url_pattern_part& part : part_list) {
    // If part's type is "fixed-text":
    if (part.type == url_pattern_part_type::FIXED_TEXT) {
      // If part's modifier is "none"
      if (part.modifier == url_pattern_part_modifier::NONE) {
        // Append the result of running escape a regexp string given part's
        // value
        result += escape_regexp_string(part.value);
      } else {
        // A "fixed-text" part with a modifier uses a non capturing group
        // (?:<fixed text>)<modifier>
        // Append "(?:" to the end of result.
        result.append("(?:");
        // Append the result of running escape a regexp string given part’s
        // value to the end of result.
        result.append(escape_regexp_string(part.value));
        // Append ")" to the end of result.
        result.append(")");
        // Append the result of running convert a modifier to a string given
        // part’s modifier to the end of result.
        result.append(convert_modifier_to_string(part.modifier));
      }
      continue;
    }

    // Assert: part's name is not the empty string
    ADA_ASSERT_TRUE(!part.name.empty());

    // Append part's name to name list
    name_list.push_back(part.name);

    // Let regexp value be part's value
    std::string regexp_value = part.value;

    // If part's type is "segment-wildcard"
    if (part.type == url_pattern_part_type::SEGMENT_WILDCARD) {
      // then set regexp value to the result of running generate a segment
      // wildcard regexp given options.
      regexp_value = generate_segment_wildcard_regexp(options);
    }
    // Otherwise if part's type is "full-wildcard"
    else if (part.type == url_pattern_part_type::FULL_WILDCARD) {
      // then set regexp value to full wildcard regexp value.
      regexp_value = full_wildcard_regexp_value;
    }

    // If part's prefix is the empty string and part's suffix is the empty
    // string
    if (part.prefix.empty() && part.suffix.empty()) {
      // If part's modifier is "none" or "optional"
      if (part.modifier == url_pattern_part_modifier::NONE ||
          part.modifier == url_pattern_part_modifier::OPTIONAL) {
        // (<regexp value>)<modifier>
        result += "(" + regexp_value + ")" +
                  convert_modifier_to_string(part.modifier);
      } else {
        // ((?:<regexp value>)<modifier>)
        result += "((?:" + regexp_value + ")" +
                  convert_modifier_to_string(part.modifier) + ")";
      }
      continue;
    }

    // If part's modifier is "none" or "optional"
    if (part.modifier == url_pattern_part_modifier::NONE ||
        part.modifier == url_pattern_part_modifier::OPTIONAL) {
      // (?:<prefix>(<regexp value>)<suffix>)<modifier>
      result += "(?:" + escape_regexp_string(part.prefix) + "(" + regexp_value +
                ")" + escape_regexp_string(part.suffix) + ")" +
                convert_modifier_to_string(part.modifier);
      continue;
    }

    // Assert: part's modifier is "zero-or-more" or "one-or-more"
    ADA_ASSERT_TRUE(part.modifier == url_pattern_part_modifier::ZERO_OR_MORE ||
                    part.modifier == url_pattern_part_modifier::ONE_OR_MORE);

    // Assert: part's prefix is not the empty string or part's suffix is not the
    // empty string
    ADA_ASSERT_TRUE(!part.prefix.empty() || !part.suffix.empty());

    // (?:<prefix>((?:<regexp value>)(?:<suffix><prefix>(?:<regexp
    // value>))*)<suffix>)?
    // Append "(?:" to the end of result.
    result.append("(?:");
    // Append the result of running escape a regexp string given part’s prefix
    // to the end of result.
    result.append(escape_regexp_string(part.prefix));
    // Append "((?:" to the end of result.
    result.append("((?:");
    // Append regexp value to the end of result.
    result.append(regexp_value);
    // Append ")(?:" to the end of result.
    result.append(")(?:");
    // Append the result of running escape a regexp string given part’s suffix
    // to the end of result.
    result.append(escape_regexp_string(part.suffix));
    // Append the result of running escape a regexp string given part’s prefix
    // to the end of result.
    result.append(escape_regexp_string(part.prefix));
    // Append "(?:" to the end of result.
    result.append("(?:");
    // Append regexp value to the end of result.
    result.append(regexp_value);
    // Append "))*)" to the end of result.
    result.append("))*)");
    // Append the result of running escape a regexp string given part’s suffix
    // to the end of result.
    result.append(escape_regexp_string(part.suffix));
    // Append ")" to the end of result.
    result.append(")");

    // If part's modifier is "zero-or-more" then append "?" to the end of result
    if (part.modifier == url_pattern_part_modifier::ZERO_OR_MORE) {
      result += "?";
    }
  }

  // Append "$" to the end of result
  result += "$";

  // Return (result, name list)
  return {result, name_list};
}

bool is_ipv6_address(std::string_view input) noexcept {
  // If input’s code point length is less than 2, then return false.
  if (input.size() < 2) return false;

  // Let input code points be input interpreted as a list of code points.
  // If input code points[0] is U+005B ([), then return true.
  if (input.front() == '[') return true;
  // If input code points[0] is U+007B ({) and input code points[1] is U+005B
  // ([), then return true.
  if (input.starts_with("{[")) return true;
  // If input code points[0] is U+005C (\) and input code points[1] is U+005B
  // ([), then return true.
  return input.starts_with("\\[");
}

std::string convert_modifier_to_string(url_pattern_part_modifier modifier) {
  // TODO: Optimize this.
  switch (modifier) {
      // If modifier is "zero-or-more", then return "*".
    case url_pattern_part_modifier::ZERO_OR_MORE:
      return "*";
    // If modifier is "optional", then return "?".
    case url_pattern_part_modifier::OPTIONAL:
      return "?";
    // If modifier is "one-or-more", then return "+".
    case url_pattern_part_modifier::ONE_OR_MORE:
      return "+";
    // Return the empty string.
    default:
      return "";
  }
}

std::string generate_segment_wildcard_regexp(
    url_pattern_compile_component_options options) {
  // Let result be "[^".
  std::string result = "[^";
  // Append the result of running escape a regexp string given options’s
  // delimiter code point to the end of result.
  result.append(escape_regexp_string(options.get_delimiter()));
  // Append "]+?" to the end of result.
  result.append("]+?");
  // Return result.
  ada_log("generate_segment_wildcard_regexp result: ", result);
  return result;
}

bool protocol_component_matches_special_scheme(
    url_pattern_component& component) {
  auto regex = component.regexp;
  return std::regex_match("http", regex) || std::regex_match("https", regex) ||
         std::regex_match("ws", regex) || std::regex_match("wss", regex) ||
         std::regex_match("ftp", regex);
}

inline std::optional<errors>
constructor_string_parser::compute_protocol_matches_special_scheme_flag() {
  ada_log(
      "constructor_string_parser::compute_protocol_matches_special_scheme_"
      "flag");
  // Let protocol string be the result of running make a component string given
  // parser.
  auto protocol_string = make_component_string();
  // Let protocol component be the result of compiling a component given
  // protocol string, canonicalize a protocol, and default options.
  auto protocol_component = url_pattern_component::compile(
      protocol_string, canonicalize_protocol,
      url_pattern_compile_component_options::DEFAULT);
  if (!protocol_component) {
    ada_log("url_pattern_component::compile failed for protocol_string ",
            protocol_string);
    return protocol_component.error();
  }
  // If the result of running protocol component matches a special scheme given
  // protocol component is true, then set parser’s protocol matches a special
  // scheme flag to true.
  if (protocol_component_matches_special_scheme(*protocol_component)) {
    protocol_matches_a_special_scheme_flag = true;
  }
  return std::nullopt;
}

tl::expected<std::string, errors> canonicalize_protocol(
    std::string_view input) {
  ada_log("canonicalize_protocol called with input=", input);
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }

  // IMPORTANT: Deviation from the spec. We remove the trailing ':' here.
  if (input.ends_with(":")) {
    input.remove_suffix(1);
  }

  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // followed by "://dummy.test", with dummyURL as url.
  if (auto dummy_url = ada::parse<url_aggregator>(
          std::string(input) + "://dummy.test", nullptr)) {
    // IMPORTANT: Deviation from the spec. We remove the trailing ':' here.
    // Since URL parser always return protocols ending with `:`
    auto protocol = dummy_url->get_protocol();
    protocol.remove_suffix(1);
    return std::string(protocol);
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(errors::type_error);
}

tl::expected<std::string, errors> canonicalize_username(
    std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  auto url = ada::parse<url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  // Set the username given dummyURL and value.
  if (!url->set_username(input)) {
    return tl::unexpected(errors::type_error);
  }
  // Return dummyURL’s username.
  return std::string(url->get_username());
}

tl::expected<std::string, errors> canonicalize_password(
    std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set the password given dummyURL and value.
  auto url = ada::parse<url_aggregator>("fake://dummy.test", nullptr);

  ADA_ASSERT_TRUE(url.has_value());
  if (!url->set_password(input)) {
    return tl::unexpected(errors::type_error);
  }
  // Return dummyURL’s password.
  return std::string(url->get_password());
}

tl::expected<std::string, errors> canonicalize_hostname(
    std::string_view input) {
  ada_log("canonicalize_hostname input=", input);
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // with dummyURL as url and hostname state as state override.

  // IMPORTANT: The protocol needs to be a special protocol, otherwise the
  // hostname will not be converted using IDNA.
  auto url = ada::parse<url_aggregator>("https://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url);
  // if (!isValidHostnameInput(hostname)) return kj::none;
  if (!url->set_hostname(input)) {
    // If parseResult is failure, then throw a TypeError.
    return tl::unexpected(errors::type_error);
  }
  // Return dummyURL’s host, serialized, or empty string if it is null.
  return std::string(url->get_hostname());
}

tl::expected<std::string, errors> canonicalize_ipv6_hostname(
    std::string_view input) {
  ada_log("canonicalize_ipv6_hostname input=", input);
  // TODO: Optimization opportunity: Use lookup table to speed up checking
  if (std::ranges::any_of(input, [](char c) {
        return c != '[' && c != ']' && c != ':' &&
               !unicode::is_ascii_hex_digit(c);
      })) {
    return tl::unexpected(errors::type_error);
  }
  // Append the result of running ASCII lowercase given code point to the end of
  // result.
  auto hostname = std::string(input);
  unicode::to_lower_ascii(hostname.data(), hostname.size());
  return hostname;
}

tl::expected<std::string, errors> canonicalize_port(
    std::string_view port_value) {
  // If portValue is the empty string, return portValue.
  if (port_value.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // If protocolValue was given, then set dummyURL’s scheme to protocolValue.
  // Let parseResult be the result of running basic URL parser given portValue
  // with dummyURL as url and port state as state override.
  auto url = ada::parse<url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url);
  if (url->set_port(port_value)) {
    // Return dummyURL’s port, serialized, or empty string if it is null.
    return std::string(url->get_port());
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(errors::type_error);
}

tl::expected<std::string, errors> canonicalize_port_with_protocol(
    std::string_view port_value, std::string_view protocol) {
  // If portValue is the empty string, return portValue.
  if (port_value.empty()) [[unlikely]] {
    return "";
  }

  // TODO: Remove this
  // We have an empty protocol because get_protocol() returns an empty string
  // We should handle this in the caller rather than here.
  if (protocol.empty()) {
    protocol = "fake";
  } else if (protocol.ends_with(":")) {
    protocol.remove_suffix(1);
  }
  // Let dummyURL be a new URL record.
  // If protocolValue was given, then set dummyURL’s scheme to protocolValue.
  // Let parseResult be the result of running basic URL parser given portValue
  // with dummyURL as url and port state as state override.
  auto url = ada::parse<url_aggregator>(std::string(protocol) + "://dummy.test",
                                        nullptr);
  // TODO: Remove has_port() check.
  // This is actually a bug with url parser where set_port() returns true for
  // "invalid80" port value.
  if (url && url->set_port(port_value) && url->has_port()) {
    // Return dummyURL’s port, serialized, or empty string if it is null.
    return std::string(url->get_port());
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(errors::type_error);
}

tl::expected<std::string, errors> canonicalize_pathname(
    std::string_view input) {
  // If value is the empty string, then return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let leading slash be true if the first code point in value is U+002F (/)
  // and otherwise false.
  const bool leading_slash = input.starts_with("/");
  // Let modified value be "/-" if leading slash is false and otherwise the
  // empty string.
  const auto modified_value = leading_slash ? "" : "/-";
  const auto full_url =
      std::string("fake://fake-url") + modified_value + std::string(input);
  if (auto url = ada::parse<url_aggregator>(full_url, nullptr)) {
    const auto pathname = url->get_pathname();
    // If leading slash is false, then set result to the code point substring
    // from 2 to the end of the string within result.
    return leading_slash ? std::string(pathname)
                         : std::string(pathname.substr(2));
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(errors::type_error);
}

tl::expected<std::string, errors> canonicalize_opaque_pathname(
    std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set dummyURL’s path to the empty string.
  // Let parseResult be the result of running URL parsing given value with
  // dummyURL as url and opaque path state as state override.
  if (auto url =
          ada::parse<url_aggregator>("fake:" + std::string(input), nullptr)) {
    // Return the result of URL path serializing dummyURL.
    return std::string(url->get_pathname());
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(errors::type_error);
}

tl::expected<std::string, errors> canonicalize_search(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set dummyURL’s query to the empty string.
  // Let parseResult be the result of running basic URL parser given value with
  // dummyURL as url and query state as state override.
  auto url = ada::parse<url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  url->set_search(input);
  if (url->has_search()) {
    const auto search = url->get_search();
    return std::string(search.substr(1));
  }
  return tl::unexpected(errors::type_error);
}

tl::expected<std::string, errors> canonicalize_hash(std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Set dummyURL’s fragment to the empty string.
  // Let parseResult be the result of running basic URL parser given value with
  // dummyURL as url and fragment state as state override.
  auto url = ada::parse<url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  url->set_hash(input);
  // Return dummyURL’s fragment.
  if (url->has_hash()) {
    const auto hash = url->get_hash();
    return std::string(hash.substr(1));
  }
  return tl::unexpected(errors::type_error);
}

tl::expected<url_pattern_init, errors> constructor_string_parser::parse(
    std::string_view input) {
  ada_log("constructor_string_parser::parse input=", input);
  // Let parser be a new constructor string parser whose input is input and
  // token list is the result of running tokenize given input and "lenient".
  auto token_list = tokenize(input, token_policy::LENIENT);
  if (!token_list) {
    return tl::unexpected(token_list.error());
  }
  auto parser = constructor_string_parser(input, std::move(*token_list));

  // While parser’s token index is less than parser’s token list size:
  while (parser.token_index < parser.token_list.size()) {
    // Set parser’s token increment to 1.
    parser.token_increment = 1;

    // If parser’s token list[parser’s token index]'s type is "end" then:
    if (parser.token_list[parser.token_index].type == token_type::END) {
      // If parser’s state is "init":
      if (parser.state == State::INIT) {
        // Run rewind given parser.
        parser.rewind();
        // If the result of running is a hash prefix given parser is true, then
        // run change state given parser, "hash" and 1.
        if (parser.is_hash_prefix()) {
          parser.change_state(State::HASH, 1);
        } else if (parser.is_search_prefix()) {
          // Otherwise if the result of running is a search prefix given parser
          // is true: Run change state given parser, "search" and 1.
          parser.change_state(State::SEARCH, 1);
        } else {
          // Run change state given parser, "pathname" and 0.
          parser.change_state(State::PATHNAME, 0);
        }
        // Increment parser’s token index by parser’s token increment.
        parser.token_index += parser.token_increment;
        // Continue.
        continue;
      }

      if (parser.state == State::AUTHORITY) {
        // If parser’s state is "authority":
        // Run rewind and set state given parser, and "hostname".
        parser.rewind();
        parser.change_state(State::HOSTNAME, 0);
        // Increment parser’s token index by parser’s token increment.
        parser.token_index += parser.token_increment;
        // Continue.
        continue;
      }

      // Run change state given parser, "done" and 0.
      parser.change_state(State::DONE, 0);
      // Break.
      break;
    }

    // If the result of running is a group open given parser is true:
    if (parser.is_group_open()) {
      // Increment parser’s group depth by 1.
      parser.group_depth += 1;
      // Increment parser’s token index by parser’s token increment.
      parser.token_index += parser.token_increment;
    }

    // If parser’s group depth is greater than 0:
    if (parser.group_depth > 0) {
      // If the result of running is a group close given parser is true, then
      // decrement parser’s group depth by 1.
      if (parser.is_group_close()) {
        parser.group_depth -= 1;
      } else {
        // Increment parser’s token index by parser’s token increment.
        parser.token_index += parser.token_increment;
        continue;
      }
    }

    // Switch on parser’s state and run the associated steps:
    switch (parser.state) {
      case State::INIT: {
        // If the result of running is a protocol suffix given parser is true:
        if (parser.is_protocol_suffix()) {
          // Run rewind and set state given parser and "protocol".
          parser.rewind();
          parser.change_state(State::PROTOCOL, 0);
        }
        break;
      }
      case State::PROTOCOL: {
        // If the result of running is a protocol suffix given parser is true:
        if (parser.is_protocol_suffix()) {
          // Run compute protocol matches a special scheme flag given parser.
          if (const auto error =
                  parser.compute_protocol_matches_special_scheme_flag()) {
            ada_log("compute_protocol_matches_special_scheme_flag failed");
            return tl::unexpected(*error);
          }
          // Let next state be "pathname".
          auto next_state = State::PATHNAME;
          // Let skip be 1.
          auto skip = 1;
          // If the result of running next is authority slashes given parser is
          // true:
          if (parser.next_is_authority_slashes()) {
            // Set next state to "authority".
            next_state = State::AUTHORITY;
            // Set skip to 3.
            skip = 3;
          } else if (parser.protocol_matches_a_special_scheme_flag) {
            // Otherwise if parser’s protocol matches a special scheme flag is
            // true, then set next state to "authority".
            next_state = State::AUTHORITY;
          }

          // Run change state given parser, next state, and skip.
          parser.change_state(next_state, skip);
        }
        break;
      }
      case State::AUTHORITY: {
        // If the result of running is an identity terminator given parser is
        // true, then run rewind and set state given parser and "username".
        if (parser.is_an_identity_terminator()) {
          parser.rewind();
          parser.change_state(State::USERNAME, 0);
        } else if (parser.is_pathname_start() || parser.is_search_prefix() ||
                   parser.is_hash_prefix()) {
          // Otherwise if any of the following are true:
          // - the result of running is a pathname start given parser;
          // - the result of running is a search prefix given parser; or
          // - the result of running is a hash prefix given parser,
          // then run rewind and set state given parser and "hostname".
          parser.rewind();
          parser.change_state(State::HOSTNAME, 0);
        }
        break;
      }
      case State::USERNAME: {
        // If the result of running is a password prefix given parser is true,
        // then run change state given parser, "password", and 1.
        if (parser.is_password_prefix()) {
          parser.change_state(State::PASSWORD, 1);
        } else if (parser.is_an_identity_terminator()) {
          // Otherwise if the result of running is an identity terminator given
          // parser is true, then run change state given parser, "hostname",
          // and 1.
          parser.change_state(State::HOSTNAME, 1);
        }
        break;
      }
      case State::PASSWORD: {
        // If the result of running is an identity terminator given parser is
        // true, then run change state given parser, "hostname", and 1.
        if (parser.is_an_identity_terminator()) {
          parser.change_state(State::HOSTNAME, 1);
        }
        break;
      }
      case State::HOSTNAME: {
        // If the result of running is an IPv6 open given parser is true, then
        // increment parser’s hostname IPv6 bracket depth by 1.
        if (parser.is_an_ipv6_open()) {
          parser.hostname_ipv6_bracket_depth += 1;
        } else if (parser.is_an_ipv6_close()) {
          // Otherwise if the result of running is an IPv6 close given parser is
          // true, then decrement parser’s hostname IPv6 bracket depth by 1.
          parser.hostname_ipv6_bracket_depth -= 1;
        } else if (parser.is_port_prefix() &&
                   parser.hostname_ipv6_bracket_depth == 0) {
          // Otherwise if the result of running is a port prefix given parser is
          // true and parser’s hostname IPv6 bracket depth is zero, then run
          // change state given parser, "port", and 1.
          parser.change_state(State::PORT, 1);
        } else if (parser.is_pathname_start()) {
          // Otherwise if the result of running is a pathname start given parser
          // is true, then run change state given parser, "pathname", and 0.
          parser.change_state(State::PATHNAME, 0);
        } else if (parser.is_search_prefix()) {
          // Otherwise if the result of running is a search prefix given parser
          // is true, then run change state given parser, "search", and 1.
          parser.change_state(State::SEARCH, 1);
        } else if (parser.is_hash_prefix()) {
          // Otherwise if the result of running is a hash prefix given parser is
          // true, then run change state given parser, "hash", and 1.
          parser.change_state(State::HASH, 1);
        }

        break;
      }
      case State::PORT: {
        // If the result of running is a pathname start given parser is true,
        // then run change state given parser, "pathname", and 0.
        if (parser.is_pathname_start()) {
          parser.change_state(State::PATHNAME, 0);
        } else if (parser.is_search_prefix()) {
          // Otherwise if the result of running is a search prefix given parser
          // is true, then run change state given parser, "search", and 1.
          parser.change_state(State::SEARCH, 1);
        } else if (parser.is_hash_prefix()) {
          // Otherwise if the result of running is a hash prefix given parser is
          // true, then run change state given parser, "hash", and 1.
          parser.change_state(State::HASH, 1);
        }
        break;
      }
      case State::PATHNAME: {
        // If the result of running is a search prefix given parser is true,
        // then run change state given parser, "search", and 1.
        if (parser.is_search_prefix()) {
          parser.change_state(State::SEARCH, 1);
        } else if (parser.is_hash_prefix()) {
          // Otherwise if the result of running is a hash prefix given parser is
          // true, then run change state given parser, "hash", and 1.
          parser.change_state(State::HASH, 1);
        }
        break;
      }
      case State::SEARCH: {
        // If the result of running is a hash prefix given parser is true, then
        // run change state given parser, "hash", and 1.
        if (parser.is_hash_prefix()) {
          parser.change_state(State::HASH, 1);
        }
      }
      case State::HASH: {
        // Do nothing
        break;
      }
      default: {
        // Assert: This step is never reached.
        unreachable();
      }
    }

    // Increment parser’s token index by parser’s token increment.
    parser.token_index += parser.token_increment;
  }

  // If parser’s result contains "hostname" and not "port", then set parser’s
  // result["port"] to the empty string.
  if (parser.result.hostname && !parser.result.port) {
    parser.result.port = "";
  }

  // Return parser’s result.
  return parser.result;
}

tl::expected<std::vector<Token>, errors> tokenize(std::string_view input,
                                                  token_policy policy) {
  ada_log("tokenize input: ", input);
  // Let tokenizer be a new tokenizer.
  // Set tokenizer’s input to input.
  // Set tokenizer’s policy to policy.
  auto tokenizer = Tokenizer(input, policy);
  // While tokenizer’s index is less than tokenizer’s input's code point length:
  while (tokenizer.index < tokenizer.input.size()) {
    // Run seek and get the next code point given tokenizer and tokenizer’s
    // index.
    tokenizer.seek_and_get_next_code_point(tokenizer.index);

    // If tokenizer’s code point is U+002A (*):
    if (tokenizer.code_point == '*') {
      // Run add a token with default position and length given tokenizer and
      // "asterisk".
      tokenizer.add_token_with_defaults(token_type::ASTERISK);
      ada_log("add ASTERISK token");
      // Continue.
      continue;
    }

    // If tokenizer’s code point is U+002B (+) or U+003F (?):
    if (tokenizer.code_point == '+' || tokenizer.code_point == '?') {
      // Run add a token with default position and length given tokenizer and
      // "other-modifier".
      tokenizer.add_token_with_defaults(token_type::OTHER_MODIFIER);
      // Continue.
      continue;
    }

    // If tokenizer’s code point is U+005C (\):
    if (tokenizer.code_point == '\\') {
      // If tokenizer’s index is equal to tokenizer’s input's code point length
      // − 1:
      if (tokenizer.index == tokenizer.input.size() - 1) {
        // Run process a tokenizing error given tokenizer, tokenizer’s next
        // index, and tokenizer’s index.
        if (auto error = tokenizer.process_tokenizing_error(
                tokenizer.next_index, tokenizer.index)) {
          ada_log("process_tokenizing_error failed");
          return tl::unexpected(*error);
        }
        continue;
      }

      // Let escaped index be tokenizer’s next index.
      auto escaped_index = tokenizer.next_index;
      // Run get the next code point given tokenizer.
      tokenizer.get_next_code_point();
      // Run add a token with default length given tokenizer, "escaped-char",
      // tokenizer’s next index, and escaped index.
      tokenizer.add_token_with_default_length(
          token_type::ESCAPED_CHAR, tokenizer.next_index, escaped_index);
      ada_log("add ESCAPED_CHAR token on next_index ", tokenizer.next_index,
              " with escaped index ", escaped_index);
      // Continue.
      continue;
    }

    // If tokenizer’s code point is U+007B ({):
    if (tokenizer.code_point == '{') {
      // Run add a token with default position and length given tokenizer and
      // "open".
      tokenizer.add_token_with_defaults(token_type::OPEN);
      ada_log("add OPEN token");
      continue;
    }

    // If tokenizer’s code point is U+007D (}):
    if (tokenizer.code_point == '}') {
      // Run add a token with default position and length given tokenizer and
      // "close".
      tokenizer.add_token_with_defaults(token_type::CLOSE);
      ada_log("add CLOSE token");
      continue;
    }

    // If tokenizer’s code point is U+003A (:):
    if (tokenizer.code_point == ':') {
      // Let name position be tokenizer’s next index.
      auto name_position = tokenizer.next_index;
      // Let name start be name position.
      auto name_start = name_position;
      // While name position is less than tokenizer’s input's code point length:
      while (name_position < tokenizer.input.size()) {
        // Run seek and get the next code point given tokenizer and name
        // position.
        tokenizer.seek_and_get_next_code_point(name_position);
        // Let first code point be true if name position equals name start and
        // false otherwise.
        bool first_code_point = name_position == name_start;
        // Let valid code point be the result of running is a valid name code
        // point given tokenizer’s code point and first code point.
        auto valid_code_point =
            idna::valid_name_code_point(tokenizer.code_point, first_code_point);
        ada_log("tokenizer.code_point=", uint32_t(tokenizer.code_point),
                " first_code_point=", first_code_point,
                " valid_code_point=", valid_code_point);
        // If valid code point is false break.
        if (!valid_code_point) break;
        // Set name position to tokenizer’s next index.
        name_position = tokenizer.next_index;
      }

      // If name position is less than or equal to name start:
      if (name_position <= name_start) {
        // Run process a tokenizing error given tokenizer, name start, and
        // tokenizer’s index.
        if (auto error = tokenizer.process_tokenizing_error(name_start,
                                                            tokenizer.index)) {
          ada_log("process_tokenizing_error failed");
          return tl::unexpected(*error);
        }
        // Continue
        continue;
      }

      // Run add a token with default length given tokenizer, "name", name
      // position, and name start.
      tokenizer.add_token_with_default_length(token_type::NAME, name_position,
                                              name_start);
      continue;
    }

    // If tokenizer’s code point is U+0028 (():
    if (tokenizer.code_point == '(') {
      // Let depth be 1.
      size_t depth = 1;
      // Let regexp position be tokenizer’s next index.
      auto regexp_position = tokenizer.next_index;
      // Let regexp start be regexp position.
      auto regexp_start = regexp_position;
      // Let error be false.
      bool error = false;

      // While regexp position is less than tokenizer’s input's code point
      // length:
      while (regexp_position < tokenizer.input.size()) {
        // Run seek and get the next code point given tokenizer and regexp
        // position.
        tokenizer.seek_and_get_next_code_point(regexp_position);

        // TODO: Optimization opportunity: The next 2 if statements can be
        // merged. If the result of running is ASCII given tokenizer’s code
        // point is false:
        if (!unicode::is_ascii(tokenizer.code_point)) {
          // Run process a tokenizing error given tokenizer, regexp start, and
          // tokenizer’s index.
          if (auto process_error = tokenizer.process_tokenizing_error(
                  regexp_start, tokenizer.index)) {
            return tl::unexpected(*process_error);
          }
          // Set error to true.
          error = true;
          break;
        }

        // If regexp position equals regexp start and tokenizer’s code point is
        // U+003F (?):
        if (regexp_position == regexp_start && tokenizer.code_point == '?') {
          // Run process a tokenizing error given tokenizer, regexp start, and
          // tokenizer’s index.
          if (auto process_error = tokenizer.process_tokenizing_error(
                  regexp_start, tokenizer.index)) {
            return tl::unexpected(*process_error);
          }
          // Set error to true;
          error = true;
          break;
        }

        // If tokenizer’s code point is U+005C (\):
        if (tokenizer.code_point == '\\') {
          // If regexp position equals tokenizer’s input's code point length − 1
          if (regexp_position == tokenizer.input.size() - 1) {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index)) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Run get the next code point given tokenizer.
          tokenizer.get_next_code_point();
          // If the result of running is ASCII given tokenizer’s code point is
          // false:
          if (!unicode::is_ascii(tokenizer.code_point)) {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index);
                process_error.has_value()) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Set regexp position to tokenizer’s next index.
          regexp_position = tokenizer.next_index;
          continue;
        }

        // If tokenizer’s code point is U+0029 ()):
        if (tokenizer.code_point == ')') {
          // Decrement depth by 1.
          depth--;
          // If depth is 0:
          if (depth == 0) {
            // Set regexp position to tokenizer’s next index.
            regexp_position = tokenizer.next_index;
            // Break.
            break;
          }
        } else if (tokenizer.code_point == '(') {
          // Otherwise if tokenizer’s code point is U+0028 (():
          // Increment depth by 1.
          depth++;
          // If regexp position equals tokenizer’s input's code point length −
          // 1:
          if (regexp_position == tokenizer.input.size() - 1) {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index)) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Let temporary position be tokenizer’s next index.
          auto temporary_position = tokenizer.next_index;
          // Run get the next code point given tokenizer.
          tokenizer.get_next_code_point();
          // If tokenizer’s code point is not U+003F (?):
          if (tokenizer.code_point != '?') {
            // Run process a tokenizing error given tokenizer, regexp start, and
            // tokenizer’s index.
            if (auto process_error = tokenizer.process_tokenizing_error(
                    regexp_start, tokenizer.index)) {
              return tl::unexpected(*process_error);
            }
            // Set error to true.
            error = true;
            break;
          }
          // Set tokenizer’s next index to temporary position.
          tokenizer.next_index = temporary_position;
        }
        // Set regexp position to tokenizer’s next index.
        regexp_position = tokenizer.next_index;
      }

      // If error is true continue.
      if (error) continue;
      // If depth is not zero:
      if (depth != 0) {
        // Run process a tokenizing error given tokenizer, regexp start, and
        // tokenizer’s index.
        if (auto process_error = tokenizer.process_tokenizing_error(
                regexp_start, tokenizer.index)) {
          return tl::unexpected(*process_error);
        }
        continue;
      }
      // Let regexp length be regexp position − regexp start − 1.
      auto regexp_length = regexp_position - regexp_start - 1;
      // If regexp length is zero:
      if (regexp_length == 0) {
        // Run process a tokenizing error given tokenizer, regexp start, and
        // tokenizer’s index.
        if (auto process_error = tokenizer.process_tokenizing_error(
                regexp_start, tokenizer.index)) {
          ada_log("process_tokenizing_error failed");
          return tl::unexpected(*process_error);
        }
        continue;
      }
      // Run add a token given tokenizer, "regexp", regexp position, regexp
      // start, and regexp length.
      tokenizer.add_token(token_type::REGEXP, regexp_position, regexp_start,
                          regexp_length);
      continue;
    }
    // Run add a token with default position and length given tokenizer and
    // "char".
    tokenizer.add_token_with_defaults(token_type::CHAR);
  }
  // Run add a token with default length given tokenizer, "end", tokenizer’s
  // index, and tokenizer’s index.
  tokenizer.add_token_with_default_length(token_type::END, tokenizer.index,
                                          tokenizer.index);

  ada_log("tokenizer.token_list size is: ", tokenizer.token_list.size());
  // Return tokenizer’s token list.
  return tokenizer.token_list;
}

std::string escape_pattern_string(std::string_view input) {
  ada_log("escape_pattern_string called with input=", input);
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Assert: input is an ASCII string.
  ADA_ASSERT_TRUE(ada::idna::is_ascii(input));
  // Let result be the empty string.
  std::string result{};
  result.reserve(input.size());

  // TODO: Optimization opportunity: Use a lookup table
  constexpr auto should_escape = [](const char c) {
    return c == '+' || c == '*' || c == '?' || c == ':' || c == '{' ||
           c == '}' || c == '(' || c == ')' || c == '\\';
  };

  // While index is less than input’s length:
  for (const auto& c : input) {
    if (should_escape(c)) {
      // then append U+005C (\) to the end of result.
      result.append("\\");
    }

    // Append c to the end of result.
    result += c;
  }
  // Return result.
  return result;
}

namespace {
constexpr std::array<uint8_t, 256> escape_regexp_table = []() consteval {
  std::array<uint8_t, 256> out{};
  for (auto& c : {'.', '+', '*', '?', '^', '$', '{', '}', '(', ')', '[', ']',
                  '|', '/', '\\'}) {
    out[c] = 1;
  }
  return out;
}();

constexpr bool should_escape_regexp_char(char c) {
  return escape_regexp_table[(uint8_t)c];
}
}  // namespace

std::string escape_regexp_string(std::string_view input) {
  // Assert: input is an ASCII string.
  ADA_ASSERT_TRUE(idna::is_ascii(input));
  // Let result be the empty string.
  std::string result{};
  result.reserve(input.size());
  for (const auto& c : input) {
    // TODO: Optimize this even further
    if (should_escape_regexp_char(c)) {
      result.append(std::string("\\") + c);
    } else {
      result.push_back(c);
    }
  }
  return result;
}

std::string process_base_url_string(std::string_view input,
                                    std::string_view type) {
  // If type is not "pattern" return input.
  if (type != "pattern") {
    return std::string(input);
  }
  // Return the result of escaping a pattern string given input.
  return escape_pattern_string(input);
}

constexpr bool is_absolute_pathname(std::string_view input,
                                    std::string_view type) noexcept {
  // If input is the empty string, then return false.
  if (input.empty()) [[unlikely]] {
    return false;
  }
  // If input[0] is U+002F (/), then return true.
  if (input.starts_with("/")) return true;
  // If type is "url", then return false.
  if (type == "url") return false;
  // If input’s code point length is less than 2, then return false.
  if (input.size() < 2) return false;
  // If input[0] is U+005C (\) and input[1] is U+002F (/), then return true.
  if (input.starts_with("\\/")) return true;
  // If input[0] is U+007B ({) and input[1] is U+002F (/), then return true.
  if (input.starts_with("{/")) return true;
  // Return false.
  return false;
}

std::string generate_pattern_string(
    std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options& options) {
  // Let result be the empty string.
  std::string result{};
  // Let index list be the result of getting the indices for part list.
  // For each index of index list:
  for (size_t index = 0; index < part_list.size(); index++) {
    // Let part be part list[index].
    auto part = part_list[index];
    // Let previous part be part list[index - 1] if index is greater than 0,
    // otherwise let it be null.
    // TODO: Optimization opportunity. Find a way to avoid making a copy here.
    std::optional<url_pattern_part> previous_part =
        index == 0 ? std::nullopt : std::optional(part_list[index - 1]);
    // Let next part be part list[index + 1] if index is less than index list’s
    // size - 1, otherwise let it be null.
    std::optional<url_pattern_part> next_part =
        index < part_list.size() - 1 ? std::optional(part_list[index + 1])
                                     : std::nullopt;
    // If part’s type is "fixed-text" then:
    if (part.type == url_pattern_part_type::FIXED_TEXT) {
      // If part’s modifier is "none" then:
      if (part.modifier == url_pattern_part_modifier::NONE) {
        // Append the result of running escape a pattern string given part’s
        // value to the end of result.
        result.append(escape_pattern_string(part.value));
        continue;
      }
      // Append "{" to the end of result.
      result += "{";
      // Append the result of running escape a pattern string given part’s value
      // to the end of result.
      result.append(escape_pattern_string(part.value));
      // Append "}" to the end of result.
      result += "}";
      // Append the result of running convert a modifier to a string given
      // part’s modifier to the end of result.
      result.append(convert_modifier_to_string(part.modifier));
      continue;
    }
    // Let custom name be true if part’s name[0] is not an ASCII digit;
    // otherwise false.
    bool custom_name = !unicode::is_ascii_digit(part.name[0]);
    // Let needs grouping be true if at least one of the following are true,
    // otherwise let it be false:
    // - part’s suffix is not the empty string.
    // - part’s prefix is not the empty string and is not options’s prefix code
    // point.
    bool needs_grouping =
        !part.suffix.empty() ||
        (!part.prefix.empty() && part.prefix[0] != options.get_prefix()[0]);

    // If all of the following are true:
    // - needs grouping is false; and
    // - custom name is true; and
    // - part’s type is "segment-wildcard"; and
    // - part’s modifier is "none"; and
    // - next part is not null; and
    // - next part’s prefix is the empty string; and
    // - next part’s suffix is the empty string
    if (!needs_grouping && custom_name &&
        part.type == url_pattern_part_type::SEGMENT_WILDCARD &&
        part.modifier == url_pattern_part_modifier::NONE &&
        next_part.has_value() && next_part->prefix.empty() &&
        next_part->suffix.empty()) {
      // If next part’s type is "fixed-text":
      if (next_part->type == url_pattern_part_type::FIXED_TEXT) {
        // Set needs grouping to true if the result of running is a valid name
        // code point given next part’s value's first code point and the boolean
        // false is true.
        if (idna::valid_name_code_point(next_part->value[0], false)) {
          needs_grouping = true;
        }
      } else {
        // Set needs grouping to true if next part’s name[0] is an ASCII digit.
        needs_grouping = !next_part->name.empty() &&
                         unicode::is_ascii_digit(next_part->name[0]);
      }
    }

    // If all of the following are true:
    // - needs grouping is false; and
    // - part’s prefix is the empty string; and
    // - previous part is not null; and
    // - previous part’s type is "fixed-text"; and
    // - previous part’s value's last code point is options’s prefix code point.
    // then set needs grouping to true.
    if (!needs_grouping && part.prefix.empty() && previous_part.has_value() &&
        previous_part->type == url_pattern_part_type::FIXED_TEXT &&
        !options.get_prefix().empty() &&
        previous_part->value.at(previous_part->value.size() - 1) ==
            options.get_prefix()[0]) {
      needs_grouping = true;
    }

    // Assert: part’s name is not the empty string or null.
    ADA_ASSERT_TRUE(!part.name.empty());

    // If needs grouping is true, then append "{" to the end of result.
    if (needs_grouping) {
      result.append("{");
    }

    // Append the result of running escape a pattern string given part’s prefix
    // to the end of result.
    result.append(escape_pattern_string(part.prefix));

    // If custom name is true:
    if (custom_name) {
      // Append ":" to the end of result.
      result.append(":");
      // Append part’s name to the end of result.
      result.append(part.name);
    }

    // If part’s type is "regexp" then:
    if (part.type == url_pattern_part_type::REGEXP) {
      // Append "(" to the end of result.
      result.append("(");
      // Append part’s value to the end of result.
      result.append(part.value);
      // Append ")" to the end of result.
      result.append(")");
    } else if (part.type == url_pattern_part_type::SEGMENT_WILDCARD &&
               !custom_name) {
      // Otherwise if part’s type is "segment-wildcard" and custom name is
      // false: Append "(" to the end of result.
      result.append("(");
      // Append the result of running generate a segment wildcard regexp given
      // options to the end of result.
      result.append(generate_segment_wildcard_regexp(options));
      // Append ")" to the end of result.
      result.append(")");
    } else if (part.type == url_pattern_part_type::FULL_WILDCARD) {
      // Otherwise if part’s type is "full-wildcard":
      // If custom name is false and one of the following is true:
      // - previous part is null; or
      // - previous part’s type is "fixed-text"; or
      // - previous part’s modifier is not "none"; or
      // - needs grouping is true; or
      // - part’s prefix is not the empty string
      // - then append "*" to the end of result.
      if (!custom_name &&
          (!previous_part.has_value() ||
           previous_part->type == url_pattern_part_type::FIXED_TEXT ||
           previous_part->modifier != url_pattern_part_modifier::NONE ||
           needs_grouping || !part.prefix.empty())) {
        result.append("*");
      } else {
        // Append "(" to the end of result.
        // Append full wildcard regexp value to the end of result.
        // Append ")" to the end of result.
        result.append("(.*)");
      }
    }

    // If all of the following are true:
    // - part’s type is "segment-wildcard"; and
    // - custom name is true; and
    // - part’s suffix is not the empty string; and
    // - The result of running is a valid name code point given part’s suffix's
    // first code point and the boolean false is true then append U+005C (\) to
    // the end of result.
    if (part.type == url_pattern_part_type::SEGMENT_WILDCARD && custom_name &&
        !part.suffix.empty() &&
        idna::valid_name_code_point(part.suffix[0], false)) {
      result.append("\\");
    }

    // Append the result of running escape a pattern string given part’s suffix
    // to the end of result.
    result.append(escape_pattern_string(part.suffix));
    // If needs grouping is true, then append "}" to the end of result.
    if (needs_grouping) result.append("}");
    // Append the result of running convert a modifier to a string given part’s
    // modifier to the end of result.
    result.append(convert_modifier_to_string(part.modifier));
  }
  // Return result.
  return result;
}

}  // namespace ada::url_pattern_helpers

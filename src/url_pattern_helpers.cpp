#include "ada.h"
#include "ada/url_pattern_helpers.h"

#include <algorithm>
#include <optional>
#include <string>

namespace ada::url_pattern_helpers {

inline std::optional<url_pattern_errors>
constructor_string_parser::compute_protocol_matches_special_scheme_flag() {
  // Let protocol string be the result of running make a component string given
  // parser.
  auto protocol_string = make_component_string();
  // Let protocol component be the result of compiling a component given
  // protocol string, canonicalize a protocol, and default options.
  auto protocol_component = url_pattern_component::compile(
      protocol_string, canonicalize_protocol,
      url_pattern_compile_component_options::DEFAULT);
  if (!protocol_component) {
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

tl::expected<std::string, url_pattern_errors> canonicalize_protocol(
    std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }

  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // followed by "://dummy.test", with dummyURL as url.
  if (auto dummy_url = ada::parse<url_aggregator>(
          std::string(input) + "://dummy.test", nullptr)) {
    // Return dummyURL’s scheme.
    // Remove the trailing ':' from the protocol.
    std::string_view protocol = dummy_url->get_protocol();
    protocol.remove_suffix(1);
    return std::string(protocol);
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(url_pattern_errors::type_error);
}

tl::expected<std::string, url_pattern_errors> canonicalize_username(
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
    return tl::unexpected(url_pattern_errors::type_error);
  }
  // Return dummyURL’s username.
  return std::string(url->get_username());
}

tl::expected<std::string, url_pattern_errors> canonicalize_password(
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
    return tl::unexpected(url_pattern_errors::type_error);
  }
  // Return dummyURL’s password.
  return std::string(url->get_password());
}

tl::expected<std::string, url_pattern_errors> canonicalize_hostname(
    std::string_view input) {
  // If value is the empty string, return value.
  if (input.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // Let parseResult be the result of running the basic URL parser given value
  // with dummyURL as url and hostname state as state override.
  auto url = ada::parse<url_aggregator>("fake://dummy.test", nullptr);
  ADA_ASSERT_TRUE(url.has_value());
  // if (!isValidHostnameInput(hostname)) return kj::none;
  if (!url->set_hostname(input)) {
    // If parseResult is failure, then throw a TypeError.
    return tl::unexpected(url_pattern_errors::type_error);
  }
  const auto hostname = url->get_hostname();
  // Return dummyURL’s host, serialized, or empty string if it is null.
  return hostname.empty() ? "" : std::string(hostname);
}

tl::expected<std::string, url_pattern_errors> canonicalize_ipv6_hostname(
    std::string_view input) {
  // TODO: Optimization opportunity: Use lookup table to speed up checking
  if (std::ranges::all_of(input, [](char c) {
        return c == '[' || c == ']' || c == ':' ||
               unicode::is_ascii_hex_digit(c);
      })) {
    return tl::unexpected(url_pattern_errors::type_error);
  }
  // Append the result of running ASCII lowercase given code point to the end of
  // result.
  auto hostname = std::string(input);
  unicode::to_lower_ascii(hostname.data(), hostname.size());
  return hostname;
}

tl::expected<std::string, url_pattern_errors> canonicalize_port(
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
  if (url && url->set_port(port_value)) {
    // Return dummyURL’s port, serialized, or empty string if it is null.
    return std::string(url->get_port());
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(url_pattern_errors::type_error);
}

tl::expected<std::string, url_pattern_errors> canonicalize_port_with_protocol(
    std::string_view port_value, std::string_view protocol) {
  // If portValue is the empty string, return portValue.
  if (port_value.empty()) [[unlikely]] {
    return "";
  }
  // Let dummyURL be a new URL record.
  // If protocolValue was given, then set dummyURL’s scheme to protocolValue.
  // Let parseResult be the result of running basic URL parser given portValue
  // with dummyURL as url and port state as state override.
  auto url = ada::parse<url_aggregator>(std::string(protocol) + "://dummy.test",
                                        nullptr);
  if (url && url->set_port(port_value)) {
    // Return dummyURL’s port, serialized, or empty string if it is null.
    return std::string(url->get_port());
  }
  // If parseResult is failure, then throw a TypeError.
  return tl::unexpected(url_pattern_errors::type_error);
}

tl::expected<std::string, url_pattern_errors> canonicalize_pathname(
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
  return tl::unexpected(url_pattern_errors::type_error);
}

tl::expected<std::string, url_pattern_errors> canonicalize_opaque_pathname(
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
  return tl::unexpected(url_pattern_errors::type_error);
}

tl::expected<std::string, url_pattern_errors> canonicalize_search(
    std::string_view input) {
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
  const auto search = url->get_search();
  // Return dummyURL’s query.
  return !search.empty() ? std::string(search.substr(1)) : "";
}

tl::expected<std::string, url_pattern_errors> canonicalize_hash(
    std::string_view input) {
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
  const auto hash = url->get_hash();
  if (hash.empty()) {
    return "";
  }
  // Return dummyURL’s fragment.
  return std::string(hash.substr(1));
}

tl::expected<url_pattern_init, url_pattern_errors>
constructor_string_parser::parse(std::string_view input) {
  (void)input;
  // Let parser be a new constructor string parser whose input is input and
  // token list is the result of running tokenize given input and "lenient".
  auto token_list = tokenize(input, token_policy::LENIENT);
  if (!token_list) {
    return tl::unexpected(token_list.error());
  }
  auto parser = constructor_string_parser(input, *token_list);

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
  if (parser.result.hostname.has_value() && !parser.result.port.has_value()) {
    parser.result.port = "";
  }

  // Return parser’s result.
  return parser.result;
}

tl::expected<std::vector<Token>, url_pattern_errors> tokenize(
    std::string_view input, token_policy policy) {
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
      tokenizer.add_token(token_type::ESCAPED_CHAR, tokenizer.next_index,
                          escaped_index);
      // Continue.
      continue;
    }

    // If tokenizer’s code point is U+007B ({):
    if (tokenizer.code_point == '{') {
      // Run add a token with default position and length given tokenizer and
      // "open".
      tokenizer.add_token_with_defaults(token_type::OPEN);
      continue;
    }

    // If tokenizer’s code point is U+007D (}):
    if (tokenizer.code_point == '}') {
      // Run add a token with default position and length given tokenizer and
      // "close".
      tokenizer.add_token_with_defaults(token_type::CLOSE);
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
        auto valid_code_point = idna::valid_name_code_point(
            std::string_view{&tokenizer.code_point, 1}, first_code_point);
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
          return tl::unexpected(*error);
        }
        // Continue
        continue;
      }

      // Run add a token with default length given tokenizer, "name", name
      // position, and name start.
      tokenizer.add_token(token_type::NAME, name_position, name_start);
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
  tokenizer.add_token(token_type::END, tokenizer.index, tokenizer.index);
  // Return tokenizer’s token list.
  return std::move(tokenizer.token_list);
}

std::string escape_pattern_string(std::string_view input) {
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
  // Assert: input is not null.
  ADA_ASSERT_TRUE(!input.empty());
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

template <url_pattern_encoding_callback F>
tl::expected<std::vector<url_pattern_part>, url_pattern_errors>
parse_pattern_string(std::string_view input,
                     url_pattern_compile_component_options& options,
                     F&& encoding_callback) {
  // Let parser be a new pattern parser whose encoding callback is encoding
  // callback and segment wildcard regexp is the result of running generate a
  // segment wildcard regexp given options.
  auto parser = url_pattern_parser<F>(
      encoding_callback, generate_segment_wildcard_regexp(options));
  // Set parser’s token list to the result of running tokenize given input and
  // "strict".
  auto tokenize_result = tokenize(input, token_policy::STRICT);
  if (!tokenize_result) {
    return tl::unexpected(tokenize_result.error());
  }
  parser.tokens = std::move(*tokenize_result);

  // While parser’s index is less than parser’s token list's size:
  while (parser.index < parser.tokens.size()) {
    // Let char token be the result of running try to consume a token given
    // parser and "char".
    auto char_token = parser.try_consume_token(token_type::CHAR);
    // Let name token be the result of running try to consume a token given
    // parser and "name".
    auto name_token = parser.try_consume_token(token_type::NAME);
    // Let regexp or wildcard token be the result of running try to consume a
    // regexp or wildcard token given parser and name token.
    auto regexp_or_wildcard_token =
        parser.try_consume_regexp_or_wildcard_token(name_token);
    // If name token is not null or regexp or wildcard token is not null:
    if (name_token || regexp_or_wildcard_token) {
      // Let prefix be the empty string.
      std::string prefix{};
      // If char token is not null then set prefix to char token’s value.
      if (char_token) prefix = char_token->value;
      // If prefix is not the empty string and not options’s prefix code point:
      if (!prefix.empty() && prefix != options.get_prefix()) {
        // Append prefix to the end of parser’s pending fixed value.
        parser.pending_fixed_value.append(prefix);
        // Set prefix to the empty string.
        prefix.clear();
      }
      // Run maybe add a part from the pending fixed value given parser.
      if (auto error = parser.maybe_add_part_from_the_pending_fixed_value()) {
        return tl::unexpected(*error);
      }
      // Let modifier token be the result of running try to consume a modifier
      // token given parser.
      auto modifier_token = parser.try_consume_modifier_token();
      // Run add a part given parser, prefix, name token, regexp or wildcard
      // token, the empty string, and modifier token.
      if (auto error =
              parser.add_part(prefix, name_token, regexp_or_wildcard_token, {},
                              modifier_token)) {
        return tl::unexpected(*error);
      }
      // Continue.
      continue;
    }

    // Let fixed token be char token.
    auto fixed_token = char_token;
    // If fixed token is null, then set fixed token to the result of running try
    // to consume a token given parser and "escaped-char".
    if (!fixed_token)
      fixed_token = parser.try_consume_token(token_type::ESCAPED_CHAR);
    // If fixed token is not null:
    if (fixed_token) {
      // Append fixed token’s value to parser’s pending fixed value.
      parser.pending_fixed_value.append(fixed_token->value);
      // Continue.
      continue;
    }
    // Let open token be the result of running try to consume a token given
    // parser and "open".
    auto open_token = parser.try_consume_token(token_type::OPEN);
    // If open token is not null:
    if (open_token) {
      // Set prefix be the result of running consume text given parser.
      auto prefix_ = parser.consume_text();
      // Set name token to the result of running try to consume a token given
      // parser and "name".
      name_token = parser.try_consume_token(token_type::NAME);
      // Set regexp or wildcard token to the result of running try to consume a
      // regexp or wildcard token given parser and name token.
      regexp_or_wildcard_token =
          parser.try_consume_regexp_or_wildcard_token(name_token);
      // Let suffix be the result of running consume text given parser.
      auto suffix_ = parser.consume_text();
      // Run consume a required token given parser and "close".
      if (!parser.consume_required_token(token_type::CLOSE)) {
        return tl::unexpected(url_pattern_errors::type_error);
      }
      // Set modifier token to the result of running try to consume a modifier
      // token given parser.
      auto modifier_token = parser.try_consume_modifier_token();
      // Run add a part given parser, prefix, name token, regexp or wildcard
      // token, suffix, and modifier token.
      if (auto error =
              parser.add_part(prefix_, name_token, regexp_or_wildcard_token,
                              suffix_, modifier_token)) {
        return tl::unexpected(*error);
      }
      // Continue.
      continue;
    }
    // Run maybe add a part from the pending fixed value given parser.
    if (auto error = parser.maybe_add_part_from_the_pending_fixed_value()) {
      return tl::unexpected(*error);
    }
    // Run consume a required token given parser and "end".
    if (!parser.consume_required_token(token_type::END)) {
      return tl::unexpected(url_pattern_errors::type_error);
    }
  }
  // Return parser’s part list.
  return parser.parts;
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
        if (idna::valid_name_code_point(
                std::string_view{(next_part->value.c_str()), 1}, false)) {
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
    } else if (part.type == url_pattern_part_type::SEGMENT_WILDCARD) {
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
        idna::valid_name_code_point(std::string_view{&part.suffix[0], 1},
                                    true)) {
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

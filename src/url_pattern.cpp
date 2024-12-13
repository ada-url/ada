#include "ada.h"

#include <algorithm>
#include <optional>
#include <ranges>
#include <regex>
#include <string>

namespace ada {
// The default options is an options struct with delimiter code point set to
// the empty string and prefix code point set to the empty string.
url_pattern_compile_component_options
    url_pattern_compile_component_options::DEFAULT(std::nullopt, std::nullopt);

// The hostname options is an options struct with delimiter code point set
// "." and prefix code point set to the empty string.
url_pattern_compile_component_options
    url_pattern_compile_component_options::HOSTNAME('.', std::nullopt);

// The pathname options is an options struct with delimiter code point set
// "/" and prefix code point set to "/".
url_pattern_compile_component_options
    url_pattern_compile_component_options::PATHNAME('/', '/');

tl::expected<url_pattern_init, url_pattern_errors> url_pattern_init::process(
    url_pattern_init init, std::string type,
    std::optional<std::string_view> protocol,
    std::optional<std::string_view> username,
    std::optional<std::string_view> password,
    std::optional<std::string_view> hostname,
    std::optional<std::string_view> port,
    std::optional<std::string_view> pathname,
    std::optional<std::string_view> search,
    std::optional<std::string_view> hash) {
  // Let result be the result of creating a new URLPatternInit.
  auto result = url_pattern_init{};

  // If protocol is not null, set result["protocol"] to protocol.
  if (protocol.has_value()) {
    result.protocol = *protocol;
  }

  // If username is not null, set result["username"] to username.
  if (username.has_value()) {
    result.username = *username;
  }

  // If password is not null, set result["password"] to password.
  if (password.has_value()) {
    result.password = *password;
  }

  // If hostname is not null, set result["hostname"] to hostname.
  if (hostname.has_value()) {
    result.hostname = *hostname;
  }

  // If port is not null, set result["port"] to port.
  if (port.has_value()) {
    result.port = *port;
  }

  // If pathname is not null, set result["pathname"] to pathname.
  if (pathname.has_value()) {
    result.pathname = *pathname;
  }

  // If search is not null, set result["search"] to search.
  if (search.has_value()) {
    result.search = *search;
  }

  // If hash is not null, set result["hash"] to hash.
  if (hash.has_value()) {
    result.hash = *hash;
  }

  // Let baseURL be null.
  std::optional<url_aggregator> base_url{};

  // If init["baseURL"] exists:
  if (init.base_url.has_value()) {
    // Set baseURL to the result of parsing init["baseURL"].
    auto parsing_result = ada::parse<url_aggregator>(*init.base_url);
    // If baseURL is failure, then throw a TypeError.
    if (!parsing_result) {
      return tl::unexpected(url_pattern_errors::type_error);
    }
    base_url = std::move(parsing_result.value<url_aggregator>());

    // If init["protocol"] does not exist, then set result["protocol"] to the
    // result of processing a base URL string given baseURL’s scheme and type.
    if (!init.protocol.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      result.protocol = url_pattern_helpers::process_base_url_string(
          base_url->get_protocol(), type);
    }

    // If type is not "pattern" and init contains none of "protocol",
    // "hostname", "port" and "username", then set result["username"] to the
    // result of processing a base URL string given baseURL’s username and type.
    if (type != "pattern" && !init.protocol.has_value() &&
        !init.hostname.has_value() && !init.port.has_value() &&
        !init.username.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      result.username = url_pattern_helpers::process_base_url_string(
          base_url->get_username(), type);
    }

    // TODO: Optimization opportunity: Merge this with the previous check.
    // If type is not "pattern" and init contains none of "protocol",
    // "hostname", "port", "username" and "password", then set
    // result["password"] to the result of processing a base URL string given
    // baseURL’s password and type.
    if (type != "pattern" && !init.protocol.has_value() &&
        !init.hostname.has_value() && !init.port.has_value() &&
        !init.username.has_value() && !init.password.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      result.username = url_pattern_helpers::process_base_url_string(
          base_url->get_password(), type);
    }

    // If init contains neither "protocol" nor "hostname", then:
    if (!init.protocol.has_value() || !init.hostname.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      // Let baseHost be baseURL’s host.
      // If baseHost is null, then set baseHost to the empty string.
      auto base_host = base_url->get_host();
      // Set result["hostname"] to the result of processing a base URL string
      // given baseHost and type.
      result.hostname =
          url_pattern_helpers::process_base_url_string(base_host, type);
    }

    // If init contains none of "protocol", "hostname", and "port", then:
    if (!init.protocol.has_value() && !init.hostname.has_value() &&
        !init.port.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      // If baseURL’s port is null, then set result["port"] to the empty string.
      // Otherwise, set result["port"] to baseURL’s port, serialized.
      result.port = base_url->get_port();
    }

    // If init contains none of "protocol", "hostname", "port", and "pathname",
    // then set result["pathname"] to the result of processing a base URL string
    // given the result of URL path serializing baseURL and type.
    if (!init.protocol.has_value() && !init.hostname.has_value() &&
        !init.port.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      result.pathname = base_url->get_pathname();
    }

    // If init contains none of "protocol", "hostname", "port", "pathname", and
    // "search", then:
    if (!init.protocol.has_value() && !init.hostname.has_value() &&
        !init.port.has_value() && !init.pathname.has_value() &&
        !init.search.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      // Let baseQuery be baseURL’s query.
      auto base_query = base_url->get_search();
      // Set result["search"] to the result of processing a base URL string
      // given baseQuery and type.
      result.search =
          url_pattern_helpers::process_base_url_string(base_query, type);
    }

    // If init contains none of "protocol", "hostname", "port", "pathname",
    // "search", and "hash", then:
    if (!init.protocol.has_value() && !init.hostname.has_value() &&
        !init.port.has_value() && !init.pathname.has_value() &&
        !init.search.has_value() && !init.hash.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      // Let baseFragment be baseURL’s fragment.
      auto base_fragment = base_url->get_hash();
      // Set result["hash"] to the result of processing a base URL string given
      // baseFragment and type.
      result.hash =
          url_pattern_helpers::process_base_url_string(base_fragment, type);
    }
  }

  // If init["protocol"] exists, then set result["protocol"] to the result of
  // process protocol for init given init["protocol"] and type.
  if (init.protocol.has_value()) {
    auto process_result = process_protocol(*init.protocol, type);
    if (process_result.has_value()) {
      result.protocol = std::move(process_result.value<std::string>());
    }
    return tl::unexpected(process_result.error());
  }

  // If init["username"] exists, then set result["username"] to the result of
  // process username for init given init["username"] and type.
  if (init.username.has_value()) {
    auto process_result = process_username(*init.username, type);
    if (process_result.has_value()) {
      result.username = std::move(process_result.value<std::string>());
    }
    return tl::unexpected(process_result.error());
  }

  // If init["password"] exists, then set result["password"] to the result of
  // process password for init given init["password"] and type.
  if (init.password.has_value()) {
    auto process_result = process_password(*init.password, type);
    if (process_result.has_value()) {
      result.password = std::move(process_result.value<std::string>());
    }
    return tl::unexpected(process_result.error());
  }

  // If init["hostname"] exists, then set result["hostname"] to the result of
  // process hostname for init given init["hostname"] and type.
  if (init.hostname.has_value()) {
    auto process_result = process_hostname(*init.hostname, type);
    if (process_result.has_value()) {
      result.hostname = std::move(process_result.value<std::string>());
    }
    return tl::unexpected(process_result.error());
  }

  // If init["port"] exists, then set result["port"] to the result of process
  // port for init given init["port"], result["protocol"], and type.
  if (init.port.has_value()) {
    auto process_result =
        process_port(*init.port, result.protocol.value_or("fake"), type);
    if (process_result.has_value()) {
      result.port = std::move(process_result.value<std::string>());
    }
    return tl::unexpected(process_result.error());
  }

  // If init["pathname"] exists:
  if (init.pathname.has_value()) {
    // Set result["pathname"] to init["pathname"].
    result.pathname = init.pathname;

    // If the following are all true:
    // - baseURL is not null;
    // - baseURL has an opaque path; and
    // - the result of running is an absolute pathname given result["pathname"]
    // and type is false,
    if (base_url.has_value() && base_url->has_opaque_path &&
        !url_pattern_helpers::is_absolute_pathname(*result.pathname, type)) {
      // Let baseURLPath be the result of running process a base URL string
      // given the result of URL path serializing baseURL and type.
      std::string base_url_path = url_pattern_helpers::process_base_url_string(
          base_url->get_pathname(), type);

      // Let slash index be the index of the last U+002F (/) code point found in
      // baseURLPath, interpreted as a sequence of code points, or null if there
      // are no instances of the code point.
      auto slash_index = base_url_path.find_last_of('/');

      // If slash index is not null:
      if (slash_index != std::string::npos) {
        // Let new pathname be the code point substring from 0 to slash index +
        // 1 within baseURLPath.
        std::string new_pathname = base_url_path.substr(0, slash_index + 1);
        // Append result["pathname"] to the end of new pathname.
        ADA_ASSERT_TRUE(result.pathname.has_value());
        new_pathname.append(result.pathname.value());
        // Set result["pathname"] to new pathname.
        result.pathname = std::move(new_pathname);
      }
    }

    // Set result["pathname"] to the result of process pathname for init given
    // result["pathname"], result["protocol"], and type.
    auto pathname_processing_result = process_pathname(
        *result.pathname, result.protocol.value_or("fake"), type);
    if (!pathname_processing_result.has_value()) {
      return tl::unexpected(pathname_processing_result.error());
    }
    result.pathname =
        std::move(pathname_processing_result.value<std::string>());
  }

  // If init["search"] exists then set result["search"] to the result of process
  // search for init given init["search"] and type.
  if (init.search.has_value()) {
    auto process_result = process_search(*init.search, type);
    if (process_result.has_value()) {
      result.search = std::move(process_result.value<std::string>());
    }
    return tl::unexpected(process_result.error());
  }

  // If init["hash"] exists then set result["hash"] to the result of process
  // hash for init given init["hash"] and type.
  if (init.hash.has_value()) {
    auto process_result = process_hash(*init.hash, type);
    if (process_result.has_value()) {
      result.hash = std::move(process_result.value<std::string>());
    }
    return tl::unexpected(process_result.error());
  }
  // Return result.
  return result;
}

tl::expected<std::string, url_pattern_errors>
url_pattern_init::process_protocol(std::string_view value,
                                   std::string_view type) {
  // Let strippedValue be the given value with a single trailing U+003A (:)
  // removed, if any.
  ADA_ASSERT_TRUE(value.ends_with(":"));
  value.remove_suffix(1);
  // If type is "pattern" then return strippedValue.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a protocol given strippedValue.
  return url_pattern_helpers::canonicalize_protocol(value);
}

tl::expected<std::string, url_pattern_errors>
url_pattern_init::process_username(std::string_view value,
                                   std::string_view type) {
  // If type is "pattern" then return value.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a username given value.
  return url_pattern_helpers::canonicalize_username(value);
}

tl::expected<std::string, url_pattern_errors>
url_pattern_init::process_password(std::string_view value,
                                   std::string_view type) {
  // If type is "pattern" then return value.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a password given value.
  return url_pattern_helpers::canonicalize_password(value);
}

tl::expected<std::string, url_pattern_errors>
url_pattern_init::process_hostname(std::string_view value,
                                   std::string_view type) {
  // If type is "pattern" then return value.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a hostname given value.
  return url_pattern_helpers::canonicalize_hostname(value);
}

tl::expected<std::string, url_pattern_errors> url_pattern_init::process_port(
    std::string_view port, std::string_view protocol, std::string_view type) {
  // If type is "pattern" then return portValue.
  if (type == "pattern") {
    return std::string(port);
  }
  // Return the result of running canonicalize a port given portValue and
  // protocolValue.
  return url_pattern_helpers::canonicalize_port(port, protocol);
}

tl::expected<std::string, url_pattern_errors>
url_pattern_init::process_pathname(std::string_view value,
                                   std::string_view protocol,
                                   std::string_view type) {
  // If type is "pattern" then return pathnameValue.
  if (type == "pattern") {
    return std::string(value);
  }

  // If protocolValue is a special scheme or the empty string, then return the
  // result of running canonicalize a pathname given pathnameValue.
  if (protocol.empty() || scheme::is_special(protocol)) {
    return url_pattern_helpers::canonicalize_pathname(value);
  }

  // Return the result of running canonicalize an opaque pathname given
  // pathnameValue.
  return url_pattern_helpers::canonicalize_opaque_pathname(value);
}

tl::expected<std::string, url_pattern_errors> url_pattern_init::process_search(
    std::string_view value, std::string_view type) {
  // Let strippedValue be the given value with a single leading U+003F (?)
  // removed, if any.
  if (value.starts_with("?")) {
    value.remove_prefix(1);
  }
  ADA_ASSERT_TRUE(!value.starts_with("?"));
  // If type is "pattern" then return strippedValue.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a search given strippedValue.
  return url_pattern_helpers::canonicalize_search(value);
}

tl::expected<std::string, url_pattern_errors> url_pattern_init::process_hash(
    std::string_view value, std::string_view type) {
  // Let strippedValue be the given value with a single leading U+0023 (#)
  // removed, if any.
  if (value.starts_with("#")) {
    value.remove_prefix(1);
  }
  ADA_ASSERT_TRUE(!value.starts_with("#"));
  // If type is "pattern" then return strippedValue.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a hash given strippedValue.
  return url_pattern_helpers::canonicalize_hash(value);
}

namespace url_pattern_helpers {

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
    return std::string(dummy_url->get_protocol());
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
  // Optimization opportunity: Use lookup table to speed up checking
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
          parser.compute_protocol_matches_special_scheme_flag();
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
    if (tokenizer.code_point == "*") {
      // Run add a token with default position and length given tokenizer and
      // "asterisk".
      tokenizer.add_token_with_defaults(token_type::ASTERISK);
      continue;
    }

    // If tokenizer’s code point is U+002B (+) or U+003F (?):
    if (tokenizer.code_point == "+" || tokenizer.code_point == "?") {
      // Run add a token with default position and length given tokenizer and
      // "other-modifier".
      tokenizer.add_token_with_defaults(token_type::OTHER_MODIFIER);
      continue;
    }

    // If tokenizer’s code point is U+005C (\):
    if (tokenizer.code_point == "\\") {
      // If tokenizer’s index is equal to tokenizer’s input's code point length
      // − 1:
      if (tokenizer.index == tokenizer.input.size() - 1) {
        // Run process a tokenizing error given tokenizer, tokenizer’s next
        // index, and tokenizer’s index.
        if (auto error = tokenizer.process_tokenizing_error(
                tokenizer.next_index, tokenizer.index);
            error.has_value()) {
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
      continue;
    }

    // If tokenizer’s code point is U+007B ({):
    if (tokenizer.code_point == "{") {
      // Run add a token with default position and length given tokenizer and
      // "open".
      tokenizer.add_token_with_defaults(token_type::OPEN);
      continue;
    }

    // If tokenizer’s code point is U+007D (}):
    if (tokenizer.code_point == "}") {
      // Run add a token with default position and length given tokenizer and
      // "close".
      tokenizer.add_token_with_defaults(token_type::CLOSE);
      continue;
    }

    // If tokenizer’s code point is U+003A (:):
    if (tokenizer.code_point == ":") {
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
        auto valid_code_point = is_valid_name_code_point(
            tokenizer.code_point.at(0), first_code_point);
        // If valid code point is false break.
        if (!valid_code_point) break;
        // Set name position to tokenizer’s next index.
        name_position = tokenizer.next_index;
      }

      // If name position is less than or equal to name start:
      if (name_position <= name_start) {
        // Run process a tokenizing error given tokenizer, name start, and
        // tokenizer’s index.
        if (auto error =
                tokenizer.process_tokenizing_error(name_start, tokenizer.index);
            error.has_value()) {
          return tl::unexpected(*error);
        }
      }

      // Run add a token with default length given tokenizer, "name", name
      // position, and name start.
      tokenizer.add_token(token_type::NAME, name_position, name_start);
      continue;
    }

    // If tokenizer’s code point is U+0028 (():
    if (tokenizer.code_point == "(") {
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
        if (!idna::is_ascii(tokenizer.code_point)) {
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

        // If regexp position equals regexp start and tokenizer’s code point is
        // U+003F (?):
        if (regexp_position == regexp_start && tokenizer.code_point == "?") {
          // Run process a tokenizing error given tokenizer, regexp start, and
          // tokenizer’s index.
          if (auto process_error = tokenizer.process_tokenizing_error(
                  regexp_start, tokenizer.index);
              process_error.has_value()) {
            return tl::unexpected(*process_error);
          }
          // Set error to true;
          error = true;
          break;
        }

        // If tokenizer’s code point is U+005C (\):
        if (tokenizer.code_point == "\\") {
          // If regexp position equals tokenizer’s input's code point length − 1
          if (regexp_position == tokenizer.input.size() - 1) {
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
          // Run get the next code point given tokenizer.
          tokenizer.get_next_code_point();
          // If the result of running is ASCII given tokenizer’s code point is
          // false:
          if (!idna::is_ascii(tokenizer.code_point)) {
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
        if (tokenizer.code_point == ")") {
          // Decrement depth by 1.
          depth--;
          if (depth == 0) {
            // Set regexp position to tokenizer’s next index.
            regexp_position = tokenizer.next_index;
            break;
          }
        } else if (tokenizer.code_point == "(") {
          // Otherwise if tokenizer’s code point is U+0028 (():
          // Increment depth by 1.
          depth++;
          // If regexp position equals tokenizer’s input's code point length −
          // 1:
          if (regexp_position == tokenizer.input.size() - 1) {
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
          // Let temporary position be tokenizer’s next index.
          auto temporary_position = tokenizer.next_index;
          // Run get the next code point given tokenizer.
          tokenizer.get_next_code_point();
          // If tokenizer’s code point is not U+003F (?):
          if (tokenizer.code_point != "?") {
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
                regexp_start, tokenizer.index);
            process_error.has_value()) {
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
                regexp_start, tokenizer.index);
            process_error.has_value()) {
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
  // TODO: Optimization opportunity: This makes an unnecessary copy.
  return tokenizer.token_list;
}

std::string escape_pattern(std::string_view input) {
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
  return escape_pattern(input);
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
std::vector<url_pattern_part> parse_pattern_string(
    std::string_view pattern, url_pattern_compile_component_options& options,
    F encoding_callback) {
  (void)pattern;
  (void)options;
  (void)encoding_callback;
  // TODO: Implement this
  return {};
}

std::string generate_pattern_string(
    std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options& options) {
  // Let result be the empty string.
  std::string result{};
  // Let index list be the result of getting the indices for part list.
  // For each index of index list:
  for (size_t index : std::views::iota(0UL, part_list.size())) {
    // Let part be part list[index].
    auto part = part_list[index];
    // Let previous part be part list[index - 1] if index is greater than 0,
    // otherwise let it be null.
    // TODO: Optimization opportunity. Find a way to avoid making a copy here.
    std::optional<url_pattern_part> previous_part =
        index == 0 ? std::nullopt : std::optional(part_list.at(index - 1));
    // Let next part be part list[index + 1] if index is less than index list’s
    // size - 1, otherwise let it be null.
    std::optional<url_pattern_part> next_part =
        index < part_list.size() - 1 ? std::optional(part_list.at(index + 1))
                                     : std::nullopt;
    // If part’s type is "fixed-text" then:
    if (part.type == url_pattern_part_type::FIXED_TEXT) {
      // If part’s modifier is "none" then:
      if (part.modifier == url_pattern_part_modifier::NONE) {
        // Append the result of running escape a pattern string given part’s
        // value to the end of result.
        result.append(escape_pattern(part.value));
        continue;
      }
      // Append "{" to the end of result.
      result += "{";
      // Append the result of running escape a pattern string given part’s value
      // to the end of result.
      result.append(escape_pattern(part.value));
      // Append "}" to the end of result.
      result += "}";
      // Append the result of running convert a modifier to a string given
      // part’s modifier to the end of result.
      result.append(convert_modifier_to_string(part.modifier));
      continue;
    }
    // Let custom name be true if part’s name[0] is not an ASCII digit;
    // otherwise false.
    // TODO: Optimization opportunity: Find a way to directly check
    // is_ascii_digit.
    bool custom_name = idna::is_ascii(std::string_view(part.name.data(), 1));
    // Let needs grouping be true if at least one of the following are true,
    // otherwise let it be false:
    // - part’s suffix is not the empty string.
    // - part’s prefix is not the empty string and is not options’s prefix code
    // point.
    // TODO: part.prefix is a string, but options.prefix is a char. Which one is
    // true?
    bool needs_grouping =
        !part.suffix.empty() ||
        (!part.prefix.empty() && part.prefix[0] != options.prefix);

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
        // TODO: Implement this.
      } else {
        // Set needs grouping to true if next part’s name[0] is an ASCII digit.
        needs_grouping =
            idna::is_ascii(std::string_view(next_part->name.data(), 1));
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
        previous_part->value.at(previous_part->value.size() - 1) ==
            options.prefix.value()) {
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
    result.append(escape_pattern(part.prefix));

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
        is_valid_name_code_point(part.suffix[0], true)) {
      result.append("\\");
    }

    // Append the result of running escape a pattern string given part’s suffix
    // to the end of result.
    result.append(escape_pattern(part.suffix));
    // If needs grouping is true, then append "}" to the end of result.
    if (needs_grouping) result.append("}");
    // Append the result of running convert a modifier to a string given part’s
    // modifier to the end of result.
    result.append(convert_modifier_to_string(part.modifier));
  }
  // Return result.
  return result;
}

}  // namespace url_pattern_helpers

template <url_pattern_encoding_callback F>
url_pattern_component url_pattern_component::compile(
    std::string_view input, F encoding_callback,
    url_pattern_compile_component_options& options) {
  // Let part list be the result of running parse a pattern string given input,
  // options, and encoding callback.
  auto part_list = url_pattern_helpers::parse_pattern_string(input, options,
                                                             encoding_callback);

  // Let (regular expression string, name list) be the result of running
  // generate a regular expression and name list given part list and options.
  auto [regular_expression, name_list] =
      url_pattern_helpers::generate_regular_expression_and_name_list(part_list,
                                                                     options);

  // Let flags be an empty string.
  // If options’s ignore case is true then set flags to "vi".
  // Otherwise set flags to "v"
  // TODO: Optimization opportunity: Move this to options constructor and use
  // std::string_view to stop allocating unnecessary memory.
  std::string flags = options.ignore_case ? "vi" : "v";

  // Let regular expression be RegExpCreate(regular expression string, flags).
  // If this throws an exception, catch it, and throw a TypeError.
  // TODO: Investigate how to properly support this.

  // Let pattern string be the result of running generate a pattern string given
  // part list and options.
  auto pattern_string =
      url_pattern_helpers::generate_pattern_string(part_list, options);

  // For each part of part list:
  // - If part’s type is "regexp", then set has regexp groups to true.
  const auto has_regexp = [](const auto& part) { return part.is_regexp(); };
  const bool has_regexp_groups = std::ranges::any_of(part_list, has_regexp);

  // Return a new component whose pattern string is pattern string, regular
  // expression is regular expression, group name list is name list, and has
  // regexp groups is has regexp groups.
  return url_pattern_component(std::move(pattern_string),
                               std::move(regular_expression),
                               std::move(name_list), has_regexp_groups);
}

namespace url_pattern_helpers {
std::tuple<std::string, std::vector<std::string>>
generate_regular_expression_and_name_list(
    std::vector<url_pattern_part>& part_list,
    url_pattern_compile_component_options options) {
  // Let result be "^"
  std::string result = "^";

  // Let name list be a new list
  std::vector<std::string> name_list;
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
        result += "(?:" + escape_regexp_string(part.value) + ")" +
                  convert_modifier_to_string(part.modifier);
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
      regexp_value = generate_segment_wildcard_regexp(options);
    }
    // Otherwise if part's type is "full-wildcard"
    else if (part.type == url_pattern_part_type::FULL_WILDCARD) {
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
    result += "(?:" + escape_regexp_string(part.prefix) +
              "((?:" + regexp_value +
              ")(?:" + escape_regexp_string(part.suffix) +
              escape_regexp_string(part.prefix) + "(?:" + regexp_value +
              "))*)" + escape_regexp_string(part.suffix) + ")";

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

constexpr bool is_ipv6_address(std::string_view input) noexcept {
  // If input’s code point length is less than 2, then return false.
  if (input.size() < 2) return false;

  // Let input code points be input interpreted as a list of code points.
  // If input code points[0] is U+005B ([), then return true.
  if (input.front() == '[') return true;
  // If input code points[0] is U+007B ({) and input code points[1] is U+005B
  // ([), then return true.
  if (input.front() == '{' && input.at(1) == '[') return true;
  // If input code points[0] is U+005C (\) and input code points[1] is U+005B
  // ([), then return true.
  if (input.front() == '\\' && input.at(1) == '[') return true;
  // Return false.
  return false;
}

std::string convert_modifier_to_string(url_pattern_part_modifier modifier) {
  // TODO: Optimize this.
  switch (modifier) {
      // If modifier is "zero-or-more", then return "*".
    case url_pattern_part_modifier::ZERO_OR_MORE:
      return "*";
    // If modifier is "optional", then return "?".
    case url_pattern_part_modifier::NONE:
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
  ADA_ASSERT_TRUE(options.delimiter.has_value());
  result.append(
      escape_regexp_string(std::string_view(&options.delimiter.value(), 1)));
  // Append "]+?" to the end of result.
  result.append("]+?");
  // Return result.
  return result;
}

bool protocol_component_matches_special_scheme(std::string_view input) {
  // TODO: Optimize this.
  std::regex rx(input.begin(), input.size());
  std::cmatch cmatch;
  return std::regex_match("http", cmatch, rx) ||
         std::regex_match("https", cmatch, rx) ||
         std::regex_match("ws", cmatch, rx) ||
         std::regex_match("wss", cmatch, rx) ||
         std::regex_match("ftp", cmatch, rx);
}

}  // namespace url_pattern_helpers

tl::expected<std::optional<url_pattern_result>, url_pattern_errors>
url_pattern::exec(url_pattern_input input,
                  std::string_view* base_url = nullptr) {
  // Return the result of match given this's associated URL pattern, input, and
  // baseURL if given.
  return match(input, base_url);
}

bool url_pattern::test(url_pattern_input input,
                       std::string_view* base_url = nullptr) {
  // TODO: Optimization opportunity. Rather than returning `url_pattern_result`
  // Implement a fast path just like `can_parse()` in ada_url.
  // Let result be the result of match given this's associated URL pattern,
  // input, and baseURL if given.
  // If result is null, return false.
  if (auto result = match(input, base_url); result.has_value()) {
    return result->has_value();
  }
  return false;
}

tl::expected<std::optional<url_pattern_result>, url_pattern_errors>
url_pattern::match(url_pattern_input input, std::string_view* base_url_string) {
  std::string protocol{};
  std::string username{};
  std::string password{};
  std::string hostname{};
  std::string port{};
  std::string pathname{};
  std::string search{};
  std::string hash{};

  // Let inputs be an empty list.
  // Append input to inputs.
  std::vector inputs{input};

  // If input is a URLPatternInit then:
  if (std::holds_alternative<url_pattern_init>(input)) {
    // If baseURLString was given, throw a TypeError.
    if (base_url_string != nullptr) {
      return tl::unexpected(url_pattern_errors::type_error);
    }

    // Let applyResult be the result of process a URLPatternInit given input,
    // "url", protocol, username, password, hostname, port, pathname, search,
    // and hash.
    auto apply_result = url_pattern_init::process(
        std::get<url_pattern_init>(input), "url", protocol, username, password,
        hostname, port, pathname, search, hash);

    if (!apply_result.has_value()) {
      return tl::unexpected(apply_result.error());
    }

    // Set protocol to applyResult["protocol"].
    ADA_ASSERT_TRUE(apply_result->protocol.has_value());
    protocol = apply_result->protocol.value();

    // Set username to applyResult["username"].
    ADA_ASSERT_TRUE(apply_result->username.has_value());
    username = apply_result->username.value();

    // Set password to applyResult["password"].
    ADA_ASSERT_TRUE(apply_result->password.has_value());
    password = apply_result->password.value();

    // Set hostname to applyResult["hostname"].
    ADA_ASSERT_TRUE(apply_result->hostname.has_value());
    hostname = apply_result->hostname.value();

    // Set port to applyResult["port"].
    ADA_ASSERT_TRUE(apply_result->port.has_value());
    port = apply_result->port.value();

    // Set pathname to applyResult["pathname"].
    ADA_ASSERT_TRUE(apply_result->pathname.has_value());
    pathname = apply_result->pathname.value();

    // Set search to applyResult["search"].
    ADA_ASSERT_TRUE(apply_result->search.has_value());
    search = apply_result->search.value();

    // Set hash to applyResult["hash"].
    ADA_ASSERT_TRUE(apply_result->hash.has_value());
    hash = apply_result->hash.value();
  } else {
    // Let url be input.
    auto url = std::get<url_aggregator>(input);

    // Let baseURL be null.
    result<url_aggregator> base_url;

    // NOTE: We don't check for USVString here because we are already expecting
    // a valid UTF-8 string. If input is a USVString: If baseURLString was
    // given, then:
    if (base_url_string) {
      // Let baseURL be the result of parsing baseURLString.
      base_url = ada::parse<url_aggregator>(*base_url_string, nullptr);

      // If baseURL is failure, return null.
      if (!base_url) {
        return std::nullopt;
      }

      // Append baseURLString to inputs.
      inputs.emplace_back(*base_url);
    }

    url_aggregator* base_url_value =
        base_url.has_value() ? &*base_url : nullptr;

    // Set url to the result of parsing input given baseURL.
    auto parsed_url =
        ada::parse<url_aggregator>(url.get_href(), base_url_value);

    // If url is failure, return null.
    if (!parsed_url) {
      return std::nullopt;
    }

    url = parsed_url.value();

    // Set protocol to url’s scheme.
    protocol = url.get_protocol();
    // Set username to url’s username.
    username = url.get_username();
    // Set password to url’s password.
    password = url.get_password();
    // Set hostname to url’s host, serialized, or the empty string if the value
    // is null.
    hostname = url.get_hostname();
    // Set port to url’s port, serialized, or the empty string if the value is
    // null.
    port = url.get_port();
    // Set pathname to the result of URL path serializing url.
    pathname = url.get_pathname();
    // Set search to url’s query or the empty string if the value is null.
    search = url.get_search();
    // Set hash to url’s fragment or the empty string if the value is null.
    hash = url.get_hash();
  }

  // TODO: Make this function pluggable using a parameter.
  // Let protocolExecResult be RegExpBuiltinExec(urlPattern’s protocol
  // component's regular expression, protocol). auto protocol_exec_result =
  // RegExpBuiltinExec(url_pattern.protocol.get_regexp(), protocol);

  // Let usernameExecResult be RegExpBuiltinExec(urlPattern’s username
  // component's regular expression, username). auto username_exec_result =
  // RegExpBuiltinExec(url_pattern.username.get_regexp(), username);

  // Let passwordExecResult be RegExpBuiltinExec(urlPattern’s password
  // component's regular expression, password). auto password_exec_result =
  // RegExpBuiltinExec(url_pattern.password.get_regexp(), password);

  // Let hostnameExecResult be RegExpBuiltinExec(urlPattern’s hostname
  // component's regular expression, hostname). auto hostname_exec_result =
  // RegExpBuiltinExec(url_pattern.hostname.get_regexp(), hostname);

  // Let portExecResult be RegExpBuiltinExec(urlPattern’s port component's
  // regular expression, port). auto port_exec_result =
  // RegExpBuiltinExec(url_pattern.port.get_regexp(), port);

  // Let pathnameExecResult be RegExpBuiltinExec(urlPattern’s pathname
  // component's regular expression, pathname). auto pathname_exec_result =
  // RegExpBuiltinExec(url_pattern.pathname.get_regexp(), pathname);

  // Let searchExecResult be RegExpBuiltinExec(urlPattern’s search component's
  // regular expression, search). auto search_exec_result =
  // RegExpBuiltinExec(url_pattern.search.get_regexp(), search);

  // Let hashExecResult be RegExpBuiltinExec(urlPattern’s hash component's
  // regular expression, hash). auto hash_exec_result =
  // RegExpBuiltinExec(url_pattern.hash.get_regexp(), hash);

  // If protocolExecResult, usernameExecResult, passwordExecResult,
  // hostnameExecResult, portExecResult, pathnameExecResult, searchExecResult,
  // or hashExecResult are null then return null. if
  // (!protocol_exec_result.has_value() || !username_exec_result.has_value() ||
  // !password_exec_result.has_value() || !hostname_exec_result.has_value() ||
  // !port_exec_result.has_value() || !pathname_exec_result.has_value() ||
  // !search_exec_result.has_value() || !hash_exec_result.has_value()) {
  //   return tl::unexpected(url_pattern_errors::null);
  // }

  // Let result be a new URLPatternResult.
  auto result = url_pattern_result{};
  // Set result["inputs"] to inputs.
  // result.inputs = std::move(inputs);
  // Set result["protocol"] to the result of creating a component match result
  // given urlPattern’s protocol component, protocol, and protocolExecResult.
  // result.protocol =
  // protocol_component.create_component_match_result(protocol,
  // protocol_exec_result.value());

  // Set result["username"] to the result of creating a component match result
  // given urlPattern’s username component, username, and usernameExecResult.
  // result.username =
  // username_component.create_component_match_result(username,
  // username_exec_result.value());

  // Set result["password"] to the result of creating a component match result
  // given urlPattern’s password component, password, and passwordExecResult.
  // result.password =
  // password_component.create_component_match_result(password,
  // password_exec_result.value());

  // Set result["hostname"] to the result of creating a component match result
  // given urlPattern’s hostname component, hostname, and hostnameExecResult.
  // result.hostname =
  // hostname_component.create_component_match_result(hostname,
  // hostname_exec_result.value());

  // Set result["port"] to the result of creating a component match result given
  // urlPattern’s port component, port, and portExecResult. result.port =
  // port_component.create_component_match_result(port,
  // port_exec_result.value());

  // Set result["pathname"] to the result of creating a component match result
  // given urlPattern’s pathname component, pathname, and pathnameExecResult.
  // result.pathname =
  // pathname_component.create_component_match_result(pathname,
  // pathname_exec_result.value());

  // Set result["search"] to the result of creating a component match result
  // given urlPattern’s search component, search, and searchExecResult.
  // result.search = search_component.create_component_match_result(search,
  // search_exec_result.value());

  // Set result["hash"] to the result of creating a component match result given
  // urlPattern’s hash component, hash, and hashExecResult. result.hash =
  // hash_component.create_component_match_result(hash,
  // hash_exec_result.value());

  return result;
}

}  // namespace ada

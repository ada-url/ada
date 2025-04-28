/**
 * @file parser-inl.h
 */
#ifndef ADA_PARSER_INL_H
#define ADA_PARSER_INL_H

#include "ada/expected.h"
#include "ada/url_pattern.h"
#include "ada/url_pattern_helpers.h"
#include "ada/parser.h"

#include <string>
#include <string_view>
#include <variant>

namespace ada::parser {
#if ADA_INCLUDE_URL_PATTERN
template <url_pattern_regex::regex_concept regex_provider>
tl::expected<url_pattern<regex_provider>, errors> parse_url_pattern_impl(
    std::variant<std::string_view, url_pattern_init>&& input,
    const std::string_view* base_url, const url_pattern_options* options) {
  // Let init be null.
  url_pattern_init init;

  // If input is a scalar value string then:
  if (std::holds_alternative<std::string_view>(input)) {
    // Set init to the result of running parse a constructor string given input.
    auto parse_result =
        url_pattern_helpers::constructor_string_parser<regex_provider>::parse(
            std::get<std::string_view>(input));
    if (!parse_result) {
      ada_log("constructor_string_parser::parse failed");
      return tl::unexpected(parse_result.error());
    }
    init = std::move(*parse_result);
    // If baseURL is null and init["protocol"] does not exist, then throw a
    // TypeError.
    if (!base_url && !init.protocol) {
      ada_log("base url is null and protocol is not set");
      return tl::unexpected(errors::type_error);
    }

    // If baseURL is not null, set init["baseURL"] to baseURL.
    if (base_url) {
      init.base_url = std::string(*base_url);
    }
  } else {
    // Assert: input is a URLPatternInit.
    ADA_ASSERT_TRUE(std::holds_alternative<url_pattern_init>(input));
    // If baseURL is not null, then throw a TypeError.
    if (base_url) {
      ada_log("base url is not null");
      return tl::unexpected(errors::type_error);
    }
    // Optimization: Avoid copy by moving the input value.
    // Set init to input.
    init = std::move(std::get<url_pattern_init>(input));
  }

  // Let processedInit be the result of process a URLPatternInit given init,
  // "pattern", null, null, null, null, null, null, null, and null.
  auto processed_init =
      url_pattern_init::process(init, url_pattern_init::process_type::pattern);
  if (!processed_init) {
    ada_log("url_pattern_init::process failed for init and 'pattern'");
    return tl::unexpected(processed_init.error());
  }

  // For each componentName of  "protocol", "username", "password", "hostname",
  // "port", "pathname", "search", "hash" If processedInit[componentName] does
  // not exist, then set processedInit[componentName] to "*".
  ADA_ASSERT_TRUE(processed_init.has_value());
  if (!processed_init->protocol) processed_init->protocol = "*";
  if (!processed_init->username) processed_init->username = "*";
  if (!processed_init->password) processed_init->password = "*";
  if (!processed_init->hostname) processed_init->hostname = "*";
  if (!processed_init->port) processed_init->port = "*";
  if (!processed_init->pathname) processed_init->pathname = "*";
  if (!processed_init->search) processed_init->search = "*";
  if (!processed_init->hash) processed_init->hash = "*";

  ada_log("-- processed_init->protocol: ", processed_init->protocol.value());
  ada_log("-- processed_init->username: ", processed_init->username.value());
  ada_log("-- processed_init->password: ", processed_init->password.value());
  ada_log("-- processed_init->hostname: ", processed_init->hostname.value());
  ada_log("-- processed_init->port: ", processed_init->port.value());
  ada_log("-- processed_init->pathname: ", processed_init->pathname.value());
  ada_log("-- processed_init->search: ", processed_init->search.value());
  ada_log("-- processed_init->hash: ", processed_init->hash.value());

  // If processedInit["protocol"] is a special scheme and processedInit["port"]
  // is a string which represents its corresponding default port in radix-10
  // using ASCII digits then set processedInit["port"] to the empty string.
  // TODO: Optimization opportunity.
  if (scheme::is_special(*processed_init->protocol)) {
    std::string_view port = processed_init->port.value();
    if (std::to_string(scheme::get_special_port(*processed_init->protocol)) ==
        port) {
      processed_init->port->clear();
    }
  }

  // Let urlPattern be a new URL pattern.
  url_pattern<regex_provider> url_pattern_{};

  // Set urlPattern's protocol component to the result of compiling a component
  // given processedInit["protocol"], canonicalize a protocol, and default
  // options.
  auto protocol_component = url_pattern_component<regex_provider>::compile(
      processed_init->protocol.value(),
      url_pattern_helpers::canonicalize_protocol,
      url_pattern_compile_component_options::DEFAULT);
  if (!protocol_component) {
    ada_log("url_pattern_component::compile failed for protocol ",
            processed_init->protocol.value());
    return tl::unexpected(protocol_component.error());
  }
  url_pattern_.protocol_component = std::move(*protocol_component);

  // Set urlPattern's username component to the result of compiling a component
  // given processedInit["username"], canonicalize a username, and default
  // options.
  auto username_component = url_pattern_component<regex_provider>::compile(
      processed_init->username.value(),
      url_pattern_helpers::canonicalize_username,
      url_pattern_compile_component_options::DEFAULT);
  if (!username_component) {
    ada_log("url_pattern_component::compile failed for username ",
            processed_init->username.value());
    return tl::unexpected(username_component.error());
  }
  url_pattern_.username_component = std::move(*username_component);

  // Set urlPattern's password component to the result of compiling a component
  // given processedInit["password"], canonicalize a password, and default
  // options.
  auto password_component = url_pattern_component<regex_provider>::compile(
      processed_init->password.value(),
      url_pattern_helpers::canonicalize_password,
      url_pattern_compile_component_options::DEFAULT);
  if (!password_component) {
    ada_log("url_pattern_component::compile failed for password ",
            processed_init->password.value());
    return tl::unexpected(password_component.error());
  }
  url_pattern_.password_component = std::move(*password_component);

  // TODO: Optimization opportunity. The following if statement can be
  // simplified.
  // If the result running hostname pattern is an IPv6 address given
  // processedInit["hostname"] is true, then set urlPattern's hostname component
  // to the result of compiling a component given processedInit["hostname"],
  // canonicalize an IPv6 hostname, and hostname options.
  if (url_pattern_helpers::is_ipv6_address(processed_init->hostname.value())) {
    ada_log("processed_init->hostname is ipv6 address");
    // then set urlPattern's hostname component to the result of compiling a
    // component given processedInit["hostname"], canonicalize an IPv6 hostname,
    // and hostname options.
    auto hostname_component = url_pattern_component<regex_provider>::compile(
        processed_init->hostname.value(),
        url_pattern_helpers::canonicalize_ipv6_hostname,
        url_pattern_compile_component_options::DEFAULT);
    if (!hostname_component) {
      ada_log("url_pattern_component::compile failed for ipv6 hostname ",
              processed_init->hostname.value());
      return tl::unexpected(hostname_component.error());
    }
    url_pattern_.hostname_component = std::move(*hostname_component);
  } else {
    // Otherwise, set urlPattern's hostname component to the result of compiling
    // a component given processedInit["hostname"], canonicalize a hostname, and
    // hostname options.
    auto hostname_component = url_pattern_component<regex_provider>::compile(
        processed_init->hostname.value(),
        url_pattern_helpers::canonicalize_hostname,
        url_pattern_compile_component_options::HOSTNAME);
    if (!hostname_component) {
      ada_log("url_pattern_component::compile failed for hostname ",
              processed_init->hostname.value());
      return tl::unexpected(hostname_component.error());
    }
    url_pattern_.hostname_component = std::move(*hostname_component);
  }

  // Set urlPattern's port component to the result of compiling a component
  // given processedInit["port"], canonicalize a port, and default options.
  auto port_component = url_pattern_component<regex_provider>::compile(
      processed_init->port.value(), url_pattern_helpers::canonicalize_port,
      url_pattern_compile_component_options::DEFAULT);
  if (!port_component) {
    ada_log("url_pattern_component::compile failed for port ",
            processed_init->port.value());
    return tl::unexpected(port_component.error());
  }
  url_pattern_.port_component = std::move(*port_component);

  // Let compileOptions be a copy of the default options with the ignore case
  // property set to options["ignoreCase"].
  auto compile_options = url_pattern_compile_component_options::DEFAULT;
  if (options) {
    compile_options.ignore_case = options->ignore_case;
  }

  // TODO: Optimization opportunity: Simplify this if statement.
  // If the result of running protocol component matches a special scheme given
  // urlPattern's protocol component is true, then:
  if (url_pattern_helpers::protocol_component_matches_special_scheme<
          regex_provider>(url_pattern_.protocol_component)) {
    // Let pathCompileOptions be copy of the pathname options with the ignore
    // case property set to options["ignoreCase"].
    auto path_compile_options = url_pattern_compile_component_options::PATHNAME;
    if (options) {
      path_compile_options.ignore_case = options->ignore_case;
    }

    // Set urlPattern's pathname component to the result of compiling a
    // component given processedInit["pathname"], canonicalize a pathname, and
    // pathCompileOptions.
    auto pathname_component = url_pattern_component<regex_provider>::compile(
        processed_init->pathname.value(),
        url_pattern_helpers::canonicalize_pathname, path_compile_options);
    if (!pathname_component) {
      ada_log("url_pattern_component::compile failed for pathname ",
              processed_init->pathname.value());
      return tl::unexpected(pathname_component.error());
    }
    url_pattern_.pathname_component = std::move(*pathname_component);
  } else {
    // Otherwise set urlPattern's pathname component to the result of compiling
    // a component given processedInit["pathname"], canonicalize an opaque
    // pathname, and compileOptions.
    auto pathname_component = url_pattern_component<regex_provider>::compile(
        processed_init->pathname.value(),
        url_pattern_helpers::canonicalize_opaque_pathname, compile_options);
    if (!pathname_component) {
      ada_log("url_pattern_component::compile failed for opaque pathname ",
              processed_init->pathname.value());
      return tl::unexpected(pathname_component.error());
    }
    url_pattern_.pathname_component = std::move(*pathname_component);
  }

  // Set urlPattern's search component to the result of compiling a component
  // given processedInit["search"], canonicalize a search, and compileOptions.
  auto search_component = url_pattern_component<regex_provider>::compile(
      processed_init->search.value(), url_pattern_helpers::canonicalize_search,
      compile_options);
  if (!search_component) {
    ada_log("url_pattern_component::compile failed for search ",
            processed_init->search.value());
    return tl::unexpected(search_component.error());
  }
  url_pattern_.search_component = std::move(*search_component);

  // Set urlPattern's hash component to the result of compiling a component
  // given processedInit["hash"], canonicalize a hash, and compileOptions.
  auto hash_component = url_pattern_component<regex_provider>::compile(
      processed_init->hash.value(), url_pattern_helpers::canonicalize_hash,
      compile_options);
  if (!hash_component) {
    ada_log("url_pattern_component::compile failed for hash ",
            processed_init->hash.value());
    return tl::unexpected(hash_component.error());
  }
  url_pattern_.hash_component = std::move(*hash_component);

  // Return urlPattern.
  return url_pattern_;
}
#endif  // ADA_INCLUDE_URL_PATTERN

}  // namespace ada::parser

#endif  // ADA_PARSER_INL_H

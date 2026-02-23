/**
 * @file url_pattern-inl.h
 * @brief Declaration for the URLPattern inline functions.
 */
#ifndef ADA_URL_PATTERN_INL_H
#define ADA_URL_PATTERN_INL_H

#include "ada/common_defs.h"
#include "ada/url_pattern_helpers.h"
#include "ada/url_pattern.h"

#include <algorithm>
#include <string_view>
#include <utility>

#if ADA_INCLUDE_URL_PATTERN
namespace ada {

inline bool url_pattern_init::operator==(const url_pattern_init& other) const {
  return protocol == other.protocol && username == other.username &&
         password == other.password && hostname == other.hostname &&
         port == other.port && search == other.search && hash == other.hash &&
         pathname == other.pathname;
}

inline bool url_pattern_component_result::operator==(
    const url_pattern_component_result& other) const {
  return input == other.input && groups == other.groups;
}

template <url_pattern_regex::regex_concept regex_provider>
url_pattern_component_result
url_pattern_component<regex_provider>::create_component_match_result(
    std::string&& input,
    std::vector<std::optional<std::string>>&& exec_result) {
  // Let result be a new URLPatternComponentResult.
  // Set result["input"] to input.
  // Let groups be a record<USVString, (USVString or undefined)>.
  auto result =
      url_pattern_component_result{.input = std::move(input), .groups = {}};

  // We explicitly start iterating from 0 even though the spec
  // says we should start from 1. This case is handled by the
  // std_regex_provider which removes the full match from index 0.
  ADA_ASSERT_EQUAL(exec_result.size(), group_name_list.size(), "exec_result and group_name_list size mismatch");
  const size_t size = exec_result.size();
  result.groups.reserve(size);
  for (size_t index = 0; index < size; index++) {
    result.groups.emplace(group_name_list[index],
                          std::move(exec_result[index]));
  }
  return result;
}

template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_protocol() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's protocol component's pattern string.
  return protocol_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_username() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's username component's pattern string.
  return username_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_password() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's password component's pattern string.
  return password_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_hostname() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's hostname component's pattern string.
  return hostname_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_port() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's port component's pattern string.
  return port_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_pathname() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's pathname component's pattern string.
  return pathname_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_search() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's search component's pattern string.
  return search_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_hash() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's hash component's pattern string.
  return hash_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
bool url_pattern<regex_provider>::ignore_case() const {
  return ignore_case_;
}
template <url_pattern_regex::regex_concept regex_provider>
bool url_pattern<regex_provider>::has_regexp_groups() const {
  // If this's associated URL pattern's has regexp groups, then return true.
  return protocol_component.has_regexp_groups ||
         username_component.has_regexp_groups ||
         password_component.has_regexp_groups ||
         hostname_component.has_regexp_groups ||
         port_component.has_regexp_groups ||
         pathname_component.has_regexp_groups ||
         search_component.has_regexp_groups || hash_component.has_regexp_groups;
}

inline bool url_pattern_part::is_regexp() const noexcept {
  return type == url_pattern_part_type::REGEXP;
}

inline std::string_view url_pattern_compile_component_options::get_delimiter()
    const {
  if (delimiter) {
    return {&delimiter.value(), 1};
  }
  return {};
}

inline std::string_view url_pattern_compile_component_options::get_prefix()
    const {
  if (prefix) {
    return {&prefix.value(), 1};
  }
  return {};
}

template <url_pattern_regex::regex_concept regex_provider>
template <url_pattern_encoding_callback F>
tl::expected<url_pattern_component<regex_provider>, errors>
url_pattern_component<regex_provider>::compile(
    std::string_view input, F& encoding_callback,
    url_pattern_compile_component_options& options) {
  ada_log("url_pattern_component::compile input: ", input);
  // Let part list be the result of running parse a pattern string given input,
  // options, and encoding callback.
  auto part_list = url_pattern_helpers::parse_pattern_string(input, options,
                                                             encoding_callback);

  if (!part_list) {
    ada_log("parse_pattern_string failed");
    return tl::unexpected(part_list.error());
  }

  // Detect pattern type early to potentially skip expensive regex compilation
  const auto has_regexp = [](const auto& part) { return part.is_regexp(); };
  const bool has_regexp_groups = std::ranges::any_of(*part_list, has_regexp);

  url_pattern_component_type component_type =
      url_pattern_component_type::REGEXP;
  std::string exact_match_value{};

  if (part_list->empty()) {
    component_type = url_pattern_component_type::EMPTY;
  } else if (part_list->size() == 1) {
    const auto& part = (*part_list)[0];
    if (part.type == url_pattern_part_type::FIXED_TEXT &&
        part.modifier == url_pattern_part_modifier::none &&
        !options.ignore_case) {
      component_type = url_pattern_component_type::EXACT_MATCH;
      exact_match_value = part.value;
    } else if (part.type == url_pattern_part_type::FULL_WILDCARD &&
               part.modifier == url_pattern_part_modifier::none &&
               part.prefix.empty() && part.suffix.empty()) {
      component_type = url_pattern_component_type::FULL_WILDCARD;
    }
  }

  // For simple patterns, skip regex generation and compilation entirely
  if (component_type != url_pattern_component_type::REGEXP) {
    auto pattern_string =
        url_pattern_helpers::generate_pattern_string(*part_list, options);
    // For FULL_WILDCARD, we need the group name from
    // generate_regular_expression
    std::vector<std::string> name_list;
    if (component_type == url_pattern_component_type::FULL_WILDCARD &&
        !part_list->empty()) {
      name_list.push_back((*part_list)[0].name);
    }
    return url_pattern_component<regex_provider>(
        std::move(pattern_string), typename regex_provider::regex_type{},
        std::move(name_list), has_regexp_groups, component_type,
        std::move(exact_match_value));
  }

  // Generate regex for complex patterns
  auto [regular_expression_string, name_list] =
      url_pattern_helpers::generate_regular_expression_and_name_list(*part_list,
                                                                     options);
  auto pattern_string =
      url_pattern_helpers::generate_pattern_string(*part_list, options);

  std::optional<typename regex_provider::regex_type> regular_expression =
      regex_provider::create_instance(regular_expression_string,
                                      options.ignore_case);
  if (!regular_expression) {
    return tl::unexpected(errors::type_error);
  }

  return url_pattern_component<regex_provider>(
      std::move(pattern_string), std::move(*regular_expression),
      std::move(name_list), has_regexp_groups, component_type,
      std::move(exact_match_value));
}

template <url_pattern_regex::regex_concept regex_provider>
bool url_pattern_component<regex_provider>::fast_test(
    std::string_view input) const noexcept {
  // Fast path for simple patterns - avoid regex evaluation
  // Using if-else for better branch prediction on common cases
  if (type == url_pattern_component_type::FULL_WILDCARD) {
    return true;
  }
  if (type == url_pattern_component_type::EXACT_MATCH) {
    return input == exact_match_value;
  }
  if (type == url_pattern_component_type::EMPTY) {
    return input.empty();
  }
  // type == REGEXP
  return regex_provider::regex_match(input, regexp);
}

template <url_pattern_regex::regex_concept regex_provider>
std::optional<std::vector<std::optional<std::string>>>
url_pattern_component<regex_provider>::fast_match(
    std::string_view input) const {
  // Handle each type directly without redundant checks
  if (type == url_pattern_component_type::FULL_WILDCARD) {
    // FULL_WILDCARD always matches - capture the input (even if empty)
    // If there's no group name, return empty groups
    if (group_name_list.empty()) {
      return std::vector<std::optional<std::string>>{};
    }
    // Capture the matched input (including empty strings)
    return std::vector<std::optional<std::string>>{std::string(input)};
  }
  if (type == url_pattern_component_type::EXACT_MATCH) {
    if (input == exact_match_value) {
      return std::vector<std::optional<std::string>>{};
    }
    return std::nullopt;
  }
  if (type == url_pattern_component_type::EMPTY) {
    if (input.empty()) {
      return std::vector<std::optional<std::string>>{};
    }
    return std::nullopt;
  }
  // type == REGEXP - use regex
  return regex_provider::regex_search(input, regexp);
}

template <url_pattern_regex::regex_concept regex_provider>
result<std::optional<url_pattern_result>> url_pattern<regex_provider>::exec(
    const url_pattern_input& input, const std::string_view* base_url) {
  // Return the result of match given this's associated URL pattern, input, and
  // baseURL if given.
  return match(input, base_url);
}

template <url_pattern_regex::regex_concept regex_provider>
bool url_pattern<regex_provider>::test_components(
    std::string_view protocol, std::string_view username,
    std::string_view password, std::string_view hostname, std::string_view port,
    std::string_view pathname, std::string_view search,
    std::string_view hash) const {
  return protocol_component.fast_test(protocol) &&
         username_component.fast_test(username) &&
         password_component.fast_test(password) &&
         hostname_component.fast_test(hostname) &&
         port_component.fast_test(port) &&
         pathname_component.fast_test(pathname) &&
         search_component.fast_test(search) && hash_component.fast_test(hash);
}

template <url_pattern_regex::regex_concept regex_provider>
result<bool> url_pattern<regex_provider>::test(
    const url_pattern_input& input, const std::string_view* base_url_string) {
  // If input is a URLPatternInit
  if (std::holds_alternative<url_pattern_init>(input)) {
    if (base_url_string) {
      return tl::unexpected(errors::type_error);
    }

    std::string protocol{}, username{}, password{}, hostname{};
    std::string port{}, pathname{}, search{}, hash{};

    auto apply_result = url_pattern_init::process(
        std::get<url_pattern_init>(input), url_pattern_init::process_type::url,
        protocol, username, password, hostname, port, pathname, search, hash);

    if (!apply_result) {
      return false;
    }

    std::string_view search_view = *apply_result->search;
    if (search_view.starts_with("?")) {
      search_view.remove_prefix(1);
    }

    return test_components(*apply_result->protocol, *apply_result->username,
                           *apply_result->password, *apply_result->hostname,
                           *apply_result->port, *apply_result->pathname,
                           search_view, *apply_result->hash);
  }

  // URL string input path
  result<url_aggregator> base_url;
  if (base_url_string) {
    base_url = ada::parse<url_aggregator>(*base_url_string, nullptr);
    if (!base_url) {
      return false;
    }
  }

  auto url =
      ada::parse<url_aggregator>(std::get<std::string_view>(input),
                                 base_url.has_value() ? &*base_url : nullptr);
  if (!url) {
    return false;
  }

  // Extract components as string_view
  auto protocol_view = url->get_protocol();
  if (protocol_view.ends_with(":")) {
    protocol_view.remove_suffix(1);
  }

  auto search_view = url->get_search();
  if (search_view.starts_with("?")) {
    search_view.remove_prefix(1);
  }

  auto hash_view = url->get_hash();
  if (hash_view.starts_with("#")) {
    hash_view.remove_prefix(1);
  }

  return test_components(protocol_view, url->get_username(),
                         url->get_password(), url->get_hostname(),
                         url->get_port(), url->get_pathname(), search_view,
                         hash_view);
}

template <url_pattern_regex::regex_concept regex_provider>
result<std::optional<url_pattern_result>> url_pattern<regex_provider>::match(
    const url_pattern_input& input, const std::string_view* base_url_string) {
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
    ada_log(
        "url_pattern::match called with url_pattern_init and base_url_string=",
        base_url_string);
    // If baseURLString was given, throw a TypeError.
    if (base_url_string) {
      ada_log("failed to match because base_url_string was given");
      return tl::unexpected(errors::type_error);
    }

    // Let applyResult be the result of process a URLPatternInit given input,
    // "url", protocol, username, password, hostname, port, pathname, search,
    // and hash.
    auto apply_result = url_pattern_init::process(
        std::get<url_pattern_init>(input), url_pattern_init::process_type::url,
        protocol, username, password, hostname, port, pathname, search, hash);

    // If this throws an exception, catch it, and return null.
    if (!apply_result.has_value()) {
      ada_log("match returned std::nullopt because process threw");
      return std::nullopt;
    }

    // Set protocol to applyResult["protocol"].
    ADA_ASSERT_TRUE(apply_result->protocol.has_value());
    protocol = std::move(apply_result->protocol.value());

    // Set username to applyResult["username"].
    ADA_ASSERT_TRUE(apply_result->username.has_value());
    username = std::move(apply_result->username.value());

    // Set password to applyResult["password"].
    ADA_ASSERT_TRUE(apply_result->password.has_value());
    password = std::move(apply_result->password.value());

    // Set hostname to applyResult["hostname"].
    ADA_ASSERT_TRUE(apply_result->hostname.has_value());
    hostname = std::move(apply_result->hostname.value());

    // Set port to applyResult["port"].
    ADA_ASSERT_TRUE(apply_result->port.has_value());
    port = std::move(apply_result->port.value());

    // Set pathname to applyResult["pathname"].
    ADA_ASSERT_TRUE(apply_result->pathname.has_value());
    pathname = std::move(apply_result->pathname.value());

    // Set search to applyResult["search"].
    ADA_ASSERT_TRUE(apply_result->search.has_value());
    if (apply_result->search->starts_with("?")) {
      search = apply_result->search->substr(1);
    } else {
      search = std::move(apply_result->search.value());
    }

    // Set hash to applyResult["hash"].
    ADA_ASSERT_TRUE(apply_result->hash.has_value());
    ADA_ASSERT_TRUE(!apply_result->hash->starts_with("#"));
    hash = std::move(apply_result->hash.value());
  } else {
    ADA_ASSERT_TRUE(std::holds_alternative<std::string_view>(input));

    // Let baseURL be null.
    result<url_aggregator> base_url;

    // If baseURLString was given, then:
    if (base_url_string) {
      // Let baseURL be the result of parsing baseURLString.
      base_url = ada::parse<url_aggregator>(*base_url_string, nullptr);

      // If baseURL is failure, return null.
      if (!base_url) {
        ada_log("match returned std::nullopt because failed to parse base_url=",
                *base_url_string);
        return std::nullopt;
      }

      // Append baseURLString to inputs.
      inputs.emplace_back(*base_url_string);
    }

    url_aggregator* base_url_value =
        base_url.has_value() ? &*base_url : nullptr;

    // Set url to the result of parsing input given baseURL.
    auto url = ada::parse<url_aggregator>(std::get<std::string_view>(input),
                                          base_url_value);

    // If url is failure, return null.
    if (!url) {
      ada_log("match returned std::nullopt because url failed");
      return std::nullopt;
    }

    // Set protocol to url's scheme.
    // IMPORTANT: Not documented on the URLPattern spec, but protocol suffix ':'
    // is removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2038
    protocol = url->get_protocol().substr(0, url->get_protocol().size() - 1);
    // Set username to url's username.
    username = url->get_username();
    // Set password to url's password.
    password = url->get_password();
    // Set hostname to url's host, serialized, or the empty string if the value
    // is null.
    hostname = url->get_hostname();
    // Set port to url's port, serialized, or the empty string if the value is
    // null.
    port = url->get_port();
    // Set pathname to the result of URL path serializing url.
    pathname = url->get_pathname();
    // Set search to url's query or the empty string if the value is null.
    // IMPORTANT: Not documented on the URLPattern spec, but search prefix '?'
    // is removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2232
    if (url->has_search()) {
      auto view = url->get_search();
      search = view.starts_with("?") ? url->get_search().substr(1) : view;
    }
    // Set hash to url's fragment or the empty string if the value is null.
    // IMPORTANT: Not documented on the URLPattern spec, but hash prefix '#' is
    // removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2242
    if (url->has_hash()) {
      auto view = url->get_hash();
      hash = view.starts_with("#") ? url->get_hash().substr(1) : view;
    }
  }

  // Use fast_match which skips regex for simple patterns (EMPTY, EXACT_MATCH,
  // FULL_WILDCARD) and only falls back to regex for complex REGEXP patterns.

  // Let protocolExecResult be RegExpBuiltinExec(urlPattern's protocol
  // component's regular expression, protocol).
  auto protocol_exec_result = protocol_component.fast_match(protocol);
  if (!protocol_exec_result) {
    return std::nullopt;
  }

  // Let usernameExecResult be RegExpBuiltinExec(urlPattern's username
  // component's regular expression, username).
  auto username_exec_result = username_component.fast_match(username);
  if (!username_exec_result) {
    return std::nullopt;
  }

  // Let passwordExecResult be RegExpBuiltinExec(urlPattern's password
  // component's regular expression, password).
  auto password_exec_result = password_component.fast_match(password);
  if (!password_exec_result) {
    return std::nullopt;
  }

  // Let hostnameExecResult be RegExpBuiltinExec(urlPattern's hostname
  // component's regular expression, hostname).
  auto hostname_exec_result = hostname_component.fast_match(hostname);
  if (!hostname_exec_result) {
    return std::nullopt;
  }

  // Let portExecResult be RegExpBuiltinExec(urlPattern's port component's
  // regular expression, port).
  auto port_exec_result = port_component.fast_match(port);
  if (!port_exec_result) {
    return std::nullopt;
  }

  // Let pathnameExecResult be RegExpBuiltinExec(urlPattern's pathname
  // component's regular expression, pathname).
  auto pathname_exec_result = pathname_component.fast_match(pathname);
  if (!pathname_exec_result) {
    return std::nullopt;
  }

  // Let searchExecResult be RegExpBuiltinExec(urlPattern's search component's
  // regular expression, search).
  auto search_exec_result = search_component.fast_match(search);
  if (!search_exec_result) {
    return std::nullopt;
  }

  // Let hashExecResult be RegExpBuiltinExec(urlPattern's hash component's
  // regular expression, hash).
  auto hash_exec_result = hash_component.fast_match(hash);
  if (!hash_exec_result) {
    return std::nullopt;
  }

  // Let result be a new URLPatternResult.
  auto result = url_pattern_result{};
  // Set result["inputs"] to inputs.
  result.inputs = std::move(inputs);
  // Set result["protocol"] to the result of creating a component match result
  // given urlPattern's protocol component, protocol, and protocolExecResult.
  result.protocol = protocol_component.create_component_match_result(
      std::move(protocol), std::move(*protocol_exec_result));

  // Set result["username"] to the result of creating a component match result
  // given urlPattern's username component, username, and usernameExecResult.
  result.username = username_component.create_component_match_result(
      std::move(username), std::move(*username_exec_result));

  // Set result["password"] to the result of creating a component match result
  // given urlPattern's password component, password, and passwordExecResult.
  result.password = password_component.create_component_match_result(
      std::move(password), std::move(*password_exec_result));

  // Set result["hostname"] to the result of creating a component match result
  // given urlPattern's hostname component, hostname, and hostnameExecResult.
  result.hostname = hostname_component.create_component_match_result(
      std::move(hostname), std::move(*hostname_exec_result));

  // Set result["port"] to the result of creating a component match result given
  // urlPattern's port component, port, and portExecResult.
  result.port = port_component.create_component_match_result(
      std::move(port), std::move(*port_exec_result));

  // Set result["pathname"] to the result of creating a component match result
  // given urlPattern's pathname component, pathname, and pathnameExecResult.
  result.pathname = pathname_component.create_component_match_result(
      std::move(pathname), std::move(*pathname_exec_result));

  // Set result["search"] to the result of creating a component match result
  // given urlPattern's search component, search, and searchExecResult.
  result.search = search_component.create_component_match_result(
      std::move(search), std::move(*search_exec_result));

  // Set result["hash"] to the result of creating a component match result given
  // urlPattern's hash component, hash, and hashExecResult.
  result.hash = hash_component.create_component_match_result(
      std::move(hash), std::move(*hash_exec_result));

  return result;
}

}  // namespace ada
#endif  // ADA_INCLUDE_URL_PATTERN
#endif

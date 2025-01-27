/**
 * @file url_pattern-inl.h
 * @brief Declaration for the URLPattern inline functions.
 */
#ifndef ADA_URL_PATTERN_INL_H
#define ADA_URL_PATTERN_INL_H

#include "ada/common_defs.h"
#include "ada/url_pattern_helpers.h"
#include "ada/url_pattern.h"

#include <string_view>

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
    std::string_view input,
    std::vector<std::optional<std::string>>&& exec_result) {
  // Let result be a new URLPatternComponentResult.
  // Set result["input"] to input.
  // Let groups be a record<USVString, (USVString or undefined)>.
  auto result =
      url_pattern_component_result{.input = std::string(input), .groups = {}};

  // Optimization: Let's reserve the size.
  result.groups.reserve(exec_result.size());

  // We explicitly start iterating from 0 even though the spec
  // says we should start from 1. This case is handled by the
  // std_regex_provider.
  for (size_t index = 0; index < exec_result.size(); index++) {
    result.groups.insert({
        group_name_list[index],
        std::move(exec_result[index]),
    });
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

  // Let (regular expression string, name list) be the result of running
  // generate a regular expression and name list given part list and options.
  auto [regular_expression_string, name_list] =
      url_pattern_helpers::generate_regular_expression_and_name_list(*part_list,
                                                                     options);

  ada_log("regular expression string: ", regular_expression_string);

  // Let pattern string be the result of running generate a pattern
  // string given part list and options.
  auto pattern_string =
      url_pattern_helpers::generate_pattern_string(*part_list, options);

  // Let regular expression be RegExpCreate(regular expression string,
  // flags). If this throws an exception, catch it, and throw a
  // TypeError.
  std::optional<typename regex_provider::regex_type> regular_expression =
      regex_provider::create_instance(regular_expression_string,
                                      options.ignore_case);

  if (!regular_expression) {
    return tl::unexpected(errors::type_error);
  }

  // For each part of part list:
  // - If part’s type is "regexp", then set has regexp groups to true.
  const auto has_regexp = [](const auto& part) { return part.is_regexp(); };
  const bool has_regexp_groups = std::ranges::any_of(*part_list, has_regexp);

  ada_log("has regexp groups: ", has_regexp_groups);

  // Return a new component whose pattern string is pattern string, regular
  // expression is regular expression, group name list is name list, and has
  // regexp groups is has regexp groups.
  return url_pattern_component<regex_provider>(
      std::move(pattern_string), std::move(*regular_expression),
      std::move(name_list), has_regexp_groups);
}

template <url_pattern_regex::regex_concept regex_provider>
result<std::optional<url_pattern_result>> url_pattern<regex_provider>::exec(
    const url_pattern_input& input, std::string_view* base_url) {
  // Return the result of match given this's associated URL pattern, input, and
  // baseURL if given.
  return match(input, base_url);
}

template <url_pattern_regex::regex_concept regex_provider>
result<bool> url_pattern<regex_provider>::test(const url_pattern_input& input,
                                               std::string_view* base_url) {
  // TODO: Optimization opportunity. Rather than returning `url_pattern_result`
  // Implement a fast path just like `can_parse()` in ada_url.
  // Let result be the result of match given this's associated URL pattern,
  // input, and baseURL if given.
  // If result is null, return false.
  if (auto result = match(input, base_url); result.has_value()) {
    return result->has_value();
  }
  return tl::unexpected(errors::type_error);
}

template <url_pattern_regex::regex_concept regex_provider>
result<std::optional<url_pattern_result>> url_pattern<regex_provider>::match(
    const url_pattern_input& input, std::string_view* base_url_string) {
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
        std::get<url_pattern_init>(input), "url", protocol, username, password,
        hostname, port, pathname, search, hash);

    // If this throws an exception, catch it, and return null.
    if (!apply_result.has_value()) {
      ada_log("match returned std::nullopt because process threw");
      return std::nullopt;
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
    if (apply_result->search->starts_with("?")) {
      search = apply_result->search->substr(1);
    } else {
      search = apply_result->search.value();
    }

    // Set hash to applyResult["hash"].
    ADA_ASSERT_TRUE(apply_result->hash.has_value());
    ADA_ASSERT_TRUE(!apply_result->hash->starts_with("#"));
    hash = apply_result->hash.value();
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
        base_url.has_value() ? &base_url.value() : nullptr;

    // Set url to the result of parsing input given baseURL.
    auto url = ada::parse<url_aggregator>(std::get<std::string_view>(input),
                                          base_url_value);

    // If url is failure, return null.
    if (!url) {
      ada_log("match returned std::nullopt because url failed");
      return std::nullopt;
    }

    // Set protocol to url’s scheme.
    // IMPORTANT: Not documented on the URLPattern spec, but protocol suffix ':'
    // is removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2038
    protocol = url->get_protocol().substr(0, url->get_protocol().size() - 1);
    // Set username to url’s username.
    username = url->get_username();
    // Set password to url’s password.
    password = url->get_password();
    // Set hostname to url’s host, serialized, or the empty string if the value
    // is null.
    hostname = url->get_hostname();
    // Set port to url’s port, serialized, or the empty string if the value is
    // null.
    port = url->get_port();
    // Set pathname to the result of URL path serializing url.
    pathname = url->get_pathname();
    // Set search to url’s query or the empty string if the value is null.
    // IMPORTANT: Not documented on the URLPattern spec, but search prefix '?'
    // is removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2232
    if (url->has_search()) {
      ADA_ASSERT_TRUE(url->get_search().starts_with("?"));
      search = url->get_search().substr(1);
    } else {
      search = "";
    }
    // Set hash to url’s fragment or the empty string if the value is null.
    // IMPORTANT: Not documented on the URLPattern spec, but hash prefix '#' is
    // removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2242
    if (url->has_hash()) {
      ADA_ASSERT_TRUE(url->get_hash().starts_with("#"));
      hash = url->get_hash().substr(1);
    } else {
      hash = "";
    }
  }

  // Let protocolExecResult be RegExpBuiltinExec(urlPattern’s protocol
  // component's regular expression, protocol).
  auto protocol_exec_result =
      regex_provider::regex_search(protocol, protocol_component.regexp);

  // Let usernameExecResult be RegExpBuiltinExec(urlPattern’s username
  // component's regular expression, username).
  auto username_exec_result =
      regex_provider::regex_search(username, username_component.regexp);

  // Let passwordExecResult be RegExpBuiltinExec(urlPattern’s password
  // component's regular expression, password).
  auto password_exec_result =
      regex_provider::regex_search(password, password_component.regexp);

  // Let hostnameExecResult be RegExpBuiltinExec(urlPattern’s hostname
  // component's regular expression, hostname).
  auto hostname_exec_result =
      regex_provider::regex_search(hostname, hostname_component.regexp);

  // Let portExecResult be RegExpBuiltinExec(urlPattern’s port component's
  // regular expression, port).
  auto port_exec_result =
      regex_provider::regex_search(port, port_component.regexp);

  // Let pathnameExecResult be RegExpBuiltinExec(urlPattern’s pathname
  // component's regular expression, pathname).
  auto pathname_exec_result =
      regex_provider::regex_search(pathname, pathname_component.regexp);

  // Let searchExecResult be RegExpBuiltinExec(urlPattern’s search component's
  // regular expression, search).
  auto search_exec_result =
      regex_provider::regex_search(search, search_component.regexp);

  // Let hashExecResult be RegExpBuiltinExec(urlPattern’s hash component's
  // regular expression, hash).
  auto hash_exec_result =
      regex_provider::regex_search(hash, hash_component.regexp);

  // If protocolExecResult, usernameExecResult, passwordExecResult,
  // hostnameExecResult, portExecResult, pathnameExecResult, searchExecResult,
  // or hashExecResult are null then return null.
  if (!protocol_exec_result || !username_exec_result || !password_exec_result ||
      !hostname_exec_result || !port_exec_result || !pathname_exec_result ||
      !search_exec_result || !hash_exec_result) {
    return std::nullopt;
  }

  // Let result be a new URLPatternResult.
  auto result = url_pattern_result{};
  // Set result["inputs"] to inputs.
  result.inputs = std::move(inputs);
  // Set result["protocol"] to the result of creating a component match result
  // given urlPattern’s protocol component, protocol, and protocolExecResult.
  result.protocol = protocol_component.create_component_match_result(
      protocol, std::move(*protocol_exec_result));

  // Set result["username"] to the result of creating a component match result
  // given urlPattern’s username component, username, and usernameExecResult.
  result.username = username_component.create_component_match_result(
      username, std::move(*username_exec_result));

  // Set result["password"] to the result of creating a component match result
  // given urlPattern’s password component, password, and passwordExecResult.
  result.password = password_component.create_component_match_result(
      password, std::move(*password_exec_result));

  // Set result["hostname"] to the result of creating a component match result
  // given urlPattern’s hostname component, hostname, and hostnameExecResult.
  result.hostname = hostname_component.create_component_match_result(
      hostname, std::move(*hostname_exec_result));

  // Set result["port"] to the result of creating a component match result given
  // urlPattern’s port component, port, and portExecResult.
  result.port = port_component.create_component_match_result(
      port, std::move(*port_exec_result));

  // Set result["pathname"] to the result of creating a component match result
  // given urlPattern’s pathname component, pathname, and pathnameExecResult.
  result.pathname = pathname_component.create_component_match_result(
      pathname, std::move(*pathname_exec_result));

  // Set result["search"] to the result of creating a component match result
  // given urlPattern’s search component, search, and searchExecResult.
  result.search = search_component.create_component_match_result(
      search, std::move(*search_exec_result));

  // Set result["hash"] to the result of creating a component match result given
  // urlPattern’s hash component, hash, and hashExecResult.
  result.hash = hash_component.create_component_match_result(
      hash, std::move(*hash_exec_result));

  return result;
}

}  // namespace ada

#endif

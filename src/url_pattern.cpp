#include "ada/url_pattern-inl.h"

#include <algorithm>
#include <optional>
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

tl::expected<url_pattern_init, errors> url_pattern_init::process(
    url_pattern_init init, std::string_view type,
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
  if (protocol.has_value()) result.protocol = *protocol;

  // If username is not null, set result["username"] to username.
  if (username.has_value()) result.username = *username;

  // If password is not null, set result["password"] to password.
  if (password.has_value()) result.password = *password;

  // If hostname is not null, set result["hostname"] to hostname.
  if (hostname.has_value()) result.hostname = *hostname;

  // If port is not null, set result["port"] to port.
  if (port.has_value()) result.port = *port;

  // If pathname is not null, set result["pathname"] to pathname.
  if (pathname.has_value()) result.pathname = *pathname;

  // If search is not null, set result["search"] to search.
  if (search.has_value()) result.search = *search;

  // If hash is not null, set result["hash"] to hash.
  if (hash.has_value()) result.hash = *hash;

  // Let baseURL be null.
  std::optional<url_aggregator> base_url{};

  // If init["baseURL"] exists:
  if (init.base_url.has_value()) {
    // Set baseURL to the result of parsing init["baseURL"].
    auto parsing_result = ada::parse<url_aggregator>(*init.base_url);
    // If baseURL is failure, then throw a TypeError.
    if (!parsing_result) {
      return tl::unexpected(errors::type_error);
    }
    base_url = std::move(*parsing_result);

    // If init["protocol"] does not exist, then set result["protocol"] to the
    // result of processing a base URL string given baseURL’s scheme and type.
    if (!init.protocol.has_value()) {
      ADA_ASSERT_TRUE(base_url.has_value());
      std::string_view base_url_protocol = base_url->get_protocol();
      if (base_url_protocol.ends_with(":")) base_url_protocol.remove_suffix(1);
      result.protocol =
          url_pattern_helpers::process_base_url_string(base_url_protocol, type);
    }

    // If type is not "pattern" and init contains none of "protocol",
    // "hostname", "port" and "username", then set result["username"] to the
    // result of processing a base URL string given baseURL’s username and type.
    if (type != "pattern" && !init.protocol && !init.hostname && !init.port &&
        !init.username) {
      result.username = url_pattern_helpers::process_base_url_string(
          base_url->get_username(), type);
    }

    // TODO: Optimization opportunity: Merge this with the previous check.
    // If type is not "pattern" and init contains none of "protocol",
    // "hostname", "port", "username" and "password", then set
    // result["password"] to the result of processing a base URL string given
    // baseURL’s password and type.
    if (type != "pattern" && !init.protocol && !init.hostname && !init.port &&
        !init.username && !init.password) {
      result.password = url_pattern_helpers::process_base_url_string(
          base_url->get_password(), type);
    }

    // If init contains neither "protocol" nor "hostname", then:
    if (!init.protocol && !init.hostname) {
      // Let baseHost be baseURL’s host.
      // If baseHost is null, then set baseHost to the empty string.
      auto base_host = base_url->get_hostname();
      // Set result["hostname"] to the result of processing a base URL string
      // given baseHost and type.
      result.hostname =
          url_pattern_helpers::process_base_url_string(base_host, type);
    }

    // If init contains none of "protocol", "hostname", and "port", then:
    if (!init.protocol && !init.hostname && !init.port) {
      // If baseURL’s port is null, then set result["port"] to the empty string.
      // Otherwise, set result["port"] to baseURL’s port, serialized.
      result.port = base_url->get_port();
    }

    // If init contains none of "protocol", "hostname", "port", and "pathname",
    // then set result["pathname"] to the result of processing a base URL string
    // given the result of URL path serializing baseURL and type.
    if (!init.protocol && !init.hostname && !init.port && !init.pathname) {
      result.pathname = url_pattern_helpers::process_base_url_string(
          base_url->get_pathname(), type);
    }

    // If init contains none of "protocol", "hostname", "port", "pathname", and
    // "search", then:
    if (!init.protocol && !init.hostname && !init.port && !init.pathname &&
        !init.search) {
      // Let baseQuery be baseURL’s query.
      // Set result["search"] to the result of processing a base URL string
      // given baseQuery and type.
      result.search = url_pattern_helpers::process_base_url_string(
          base_url->get_search(), type);
    }

    // If init contains none of "protocol", "hostname", "port", "pathname",
    // "search", and "hash", then:
    if (!init.protocol && !init.hostname && !init.port && !init.pathname &&
        !init.search && !init.hash) {
      // Let baseFragment be baseURL’s fragment.
      // Set result["hash"] to the result of processing a base URL string given
      // baseFragment and type.
      result.hash = url_pattern_helpers::process_base_url_string(
          base_url->get_hash(), type);
    }
  }

  // If init["protocol"] exists, then set result["protocol"] to the result of
  // process protocol for init given init["protocol"] and type.
  if (init.protocol) {
    auto process_result = process_protocol(*init.protocol, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.protocol = std::move(*process_result);
  }

  // If init["username"] exists, then set result["username"] to the result of
  // process username for init given init["username"] and type.
  if (init.username.has_value()) {
    auto process_result = process_username(*init.username, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.username = std::move(*process_result);
  }

  // If init["password"] exists, then set result["password"] to the result of
  // process password for init given init["password"] and type.
  if (init.password.has_value()) {
    auto process_result = process_password(*init.password, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.password = std::move(*process_result);
  }

  // If init["hostname"] exists, then set result["hostname"] to the result of
  // process hostname for init given init["hostname"] and type.
  if (init.hostname.has_value()) {
    auto process_result = process_hostname(*init.hostname, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.hostname = std::move(*process_result);
  }

  // If init["port"] exists, then set result["port"] to the result of process
  // port for init given init["port"], result["protocol"], and type.
  if (init.port) {
    auto process_result =
        process_port(*init.port, result.protocol.value_or("fake"), type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.port = std::move(*process_result);
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
    if (base_url && base_url->has_opaque_path &&
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
    auto pathname_processing_result =
        process_pathname(*result.pathname, result.protocol.value_or(""), type);
    if (!pathname_processing_result) {
      return tl::unexpected(pathname_processing_result.error());
    }
    result.pathname = std::move(*pathname_processing_result);
  }

  // If init["search"] exists then set result["search"] to the result of process
  // search for init given init["search"] and type.
  if (init.search) {
    auto process_result = process_search(*init.search, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.search = std::move(*process_result);
  }

  // If init["hash"] exists then set result["hash"] to the result of process
  // hash for init given init["hash"] and type.
  if (init.hash) {
    auto process_result = process_hash(*init.hash, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.hash = std::move(*process_result);
  }
  // Return result.
  return result;
}

tl::expected<std::string, errors> url_pattern_init::process_protocol(
    std::string_view value, std::string_view type) {
  ada_log("process_protocol=", value, " [", type, "]");
  // Let strippedValue be the given value with a single trailing U+003A (:)
  // removed, if any.
  if (value.ends_with(":")) {
    value.remove_suffix(1);
  }
  // If type is "pattern" then return strippedValue.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a protocol given strippedValue.
  return url_pattern_helpers::canonicalize_protocol(value);
}

tl::expected<std::string, errors> url_pattern_init::process_username(
    std::string_view value, std::string_view type) {
  // If type is "pattern" then return value.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a username given value.
  return url_pattern_helpers::canonicalize_username(value);
}

tl::expected<std::string, errors> url_pattern_init::process_password(
    std::string_view value, std::string_view type) {
  // If type is "pattern" then return value.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a password given value.
  return url_pattern_helpers::canonicalize_password(value);
}

tl::expected<std::string, errors> url_pattern_init::process_hostname(
    std::string_view value, std::string_view type) {
  ada_log("process_hostname value=", value, " type=", type);
  // If type is "pattern" then return value.
  if (type == "pattern") {
    return std::string(value);
  }
  // Return the result of running canonicalize a hostname given value.
  return url_pattern_helpers::canonicalize_hostname(value);
}

tl::expected<std::string, errors> url_pattern_init::process_port(
    std::string_view port, std::string_view protocol, std::string_view type) {
  // If type is "pattern" then return portValue.
  if (type == "pattern") {
    return std::string(port);
  }
  // Return the result of running canonicalize a port given portValue and
  // protocolValue.
  return url_pattern_helpers::canonicalize_port_with_protocol(port, protocol);
}

tl::expected<std::string, errors> url_pattern_init::process_pathname(
    std::string_view value, std::string_view protocol, std::string_view type) {
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

tl::expected<std::string, errors> url_pattern_init::process_search(
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

tl::expected<std::string, errors> url_pattern_init::process_hash(
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

std::string url_pattern_options::to_string() const {
  std::string answer;
  answer.append("{\n");
  answer.append("\t\"ignore_case\":\"");
  answer.append(ignore_case ? "true" : "false");
  answer.append("\",\n");
  answer.append("}");
  return answer;
}

std::string url_pattern_init::to_string() const {
  std::string answer;
  auto back = std::back_insert_iterator(answer);
  answer.append("{\n");

  if (protocol.has_value()) {
    answer.append("\t\"protocol\":\"");
    helpers::encode_json(protocol.value(), back);
    answer.append("\",\n");
  }

  if (username.has_value()) {
    answer.append("\t\"username\":\"");
    helpers::encode_json(username.value(), back);
    answer.append("\",\n");
  }

  if (password.has_value()) {
    answer.append("\t\"password\":\"");
    helpers::encode_json(password.value(), back);
    answer.append("\",\n");
  }

  if (hostname.has_value()) {
    answer.append("\t\"hostname\":\"");
    helpers::encode_json(hostname.value(), back);
    answer.append("\",\n");
  }

  if (port.has_value()) {
    answer.append("\t\"port\":\"");
    helpers::encode_json(port.value(), back);
    answer.append("\",\n");
  }

  if (pathname.has_value()) {
    answer.append("\t\"pathname\":\"");
    helpers::encode_json(pathname.value(), back);
    answer.append("\",\n");
  }

  if (search.has_value()) {
    answer.append("\t\"search\":\"");
    helpers::encode_json(search.value(), back);
    answer.append("\",\n");
  }

  if (hash.has_value()) {
    answer.append("\t\"hash\":\"");
    helpers::encode_json(hash.value(), back);
    answer.append("\",\n");
  }

  if (base_url.has_value()) {
    answer.append("\t\"base_url\":\"");
    helpers::encode_json(base_url.value(), back);
    answer.append("\",\n");
  }

  answer.append("}");
  return answer;
}

template <url_pattern_encoding_callback F>
tl::expected<url_pattern_component, errors> url_pattern_component::compile(
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

  // Let flags be an empty string.
  // If options’s ignore case is true then set flags to "vi".
  // Otherwise set flags to "v"
  auto flags = options.ignore_case
                   ? std::regex::icase | std::regex_constants::ECMAScript
                   : std::regex_constants::ECMAScript;

  // Let pattern string be the result of running generate a pattern
  // string given part list and options.
  auto pattern_string =
      url_pattern_helpers::generate_pattern_string(*part_list, options);

  // Let regular expression be RegExpCreate(regular expression string,
  // flags). If this throws an exception, catch it, and throw a
  // TypeError.
  std::regex regular_expression;
  try {
    regular_expression = std::regex(regular_expression_string, flags);
  } catch (std::regex_error& error) {
    (void)error;
    ada_log("std::regex_error: ", error.what());
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
  return url_pattern_component(std::move(pattern_string),
                               std::move(regular_expression), flags,
                               std::move(name_list), has_regexp_groups);
}

result<std::optional<url_pattern_result>> url_pattern::exec(
    const url_pattern_input& input, std::string_view* base_url = nullptr) {
  // Return the result of match given this's associated URL pattern, input, and
  // baseURL if given.
  return match(input, base_url);
}

bool url_pattern::test(const url_pattern_input& input,
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

result<std::optional<url_pattern_result>> url_pattern::match(
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
    search = apply_result->search.value();

    // Set hash to applyResult["hash"].
    ADA_ASSERT_TRUE(apply_result->hash.has_value());
    hash = apply_result->hash.value();
  } else {
    ADA_ASSERT_TRUE(std::holds_alternative<std::string_view>(input));
    auto url_input = std::get<std::string_view>(input);
    auto url = ada::parse<url_aggregator>(url_input);
    if (!url) {
      return tl::unexpected(errors::type_error);
    }

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
      inputs.emplace_back(*base_url_string);
    }

    url_aggregator* base_url_value =
        base_url.has_value() ? &base_url.value() : nullptr;

    // Set url to the result of parsing input given baseURL.
    auto parsed_url =
        ada::parse<url_aggregator>(url->get_href(), base_url_value);

    // If url is failure, return null.
    if (!parsed_url) {
      return std::nullopt;
    }

    url = parsed_url.value();

    // Set protocol to url’s scheme.
    // IMPORTANT: Not documented on the URLPattern spec, but protocol suffix ':'
    // is removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2038
    protocol = url->get_protocol().substr(0, url->get_protocol().size() - 2);
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
      search = url->get_search().substr(1);
    } else {
      search = "";
    }
    // Set hash to url’s fragment or the empty string if the value is null.
    // IMPORTANT: Not documented on the URLPattern spec, but hash prefix '#' is
    // removed. Similar work was done on workerd:
    // https://github.com/cloudflare/workerd/blob/8620d14012513a6ce04d079e401d3becac3c67bd/src/workerd/jsg/url.c%2B%2B#L2242
    if (url->has_hash()) {
      hash = url->get_hash().substr(1);
    } else {
      hash = "";
    }
  }

  // Let protocolExecResult be RegExpBuiltinExec(urlPattern’s protocol
  // component's regular expression, protocol).
  std::smatch protocol_exec_result_value;
  auto protocol_exec_result =
      !protocol.empty() &&
      std::regex_match(protocol, protocol_exec_result_value,
                       protocol_component.regexp);

  // Let usernameExecResult be RegExpBuiltinExec(urlPattern’s username
  // component's regular expression, username).
  std::smatch username_exec_result_value;
  auto username_exec_result =
      !username.empty() &&
      std::regex_match(username, username_exec_result_value,
                       username_component.regexp);

  // Let passwordExecResult be RegExpBuiltinExec(urlPattern’s password
  // component's regular expression, password).
  std::smatch password_exec_result_value;
  auto password_exec_result =
      !password.empty() &&
      std::regex_match(password, password_exec_result_value,
                       password_component.regexp);

  // Let hostnameExecResult be RegExpBuiltinExec(urlPattern’s hostname
  // component's regular expression, hostname).
  std::smatch hostname_exec_result_value;
  auto hostname_exec_result =
      !hostname.empty() &&
      std::regex_match(hostname, hostname_exec_result_value,
                       hostname_component.regexp);

  // Let portExecResult be RegExpBuiltinExec(urlPattern’s port component's
  // regular expression, port).
  std::smatch port_exec_result_value;
  auto port_exec_result =
      !port.empty() &&
      std::regex_match(port, port_exec_result_value, port_component.regexp);

  // Let pathnameExecResult be RegExpBuiltinExec(urlPattern’s pathname
  // component's regular expression, pathname).
  std::smatch pathname_exec_result_value;
  auto pathname_exec_result =
      !pathname.empty() &&
      std::regex_match(pathname, pathname_exec_result_value,
                       pathname_component.regexp);

  // Let searchExecResult be RegExpBuiltinExec(urlPattern’s search component's
  // regular expression, search).
  std::smatch search_exec_result_value;
  auto search_exec_result =
      !search.empty() && std::regex_match(search, search_exec_result_value,
                                          search_component.regexp);

  // Let hashExecResult be RegExpBuiltinExec(urlPattern’s hash component's
  // regular expression, hash).
  std::smatch hash_exec_result_value;
  auto hash_exec_result =
      std::regex_match(hash, hash_exec_result_value, hash_component.regexp);

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
      protocol, protocol_exec_result_value);

  // Set result["username"] to the result of creating a component match result
  // given urlPattern’s username component, username, and usernameExecResult.
  result.username = username_component.create_component_match_result(
      username, username_exec_result_value);

  // Set result["password"] to the result of creating a component match result
  // given urlPattern’s password component, password, and passwordExecResult.
  result.password = password_component.create_component_match_result(
      password, password_exec_result_value);

  // Set result["hostname"] to the result of creating a component match result
  // given urlPattern’s hostname component, hostname, and hostnameExecResult.
  result.hostname = hostname_component.create_component_match_result(
      hostname, hostname_exec_result_value);

  // Set result["port"] to the result of creating a component match result given
  // urlPattern’s port component, port, and portExecResult.
  result.port = port_component.create_component_match_result(
      port, port_exec_result_value);

  // Set result["pathname"] to the result of creating a component match result
  // given urlPattern’s pathname component, pathname, and pathnameExecResult.
  result.pathname = pathname_component.create_component_match_result(
      pathname, pathname_exec_result_value);

  // Set result["search"] to the result of creating a component match result
  // given urlPattern’s search component, search, and searchExecResult.
  result.search = search_component.create_component_match_result(
      search, search_exec_result_value);

  // Set result["hash"] to the result of creating a component match result given
  // urlPattern’s hash component, hash, and hashExecResult.
  result.hash = hash_component.create_component_match_result(
      hash, hash_exec_result_value);

  return result;
}

}  // namespace ada

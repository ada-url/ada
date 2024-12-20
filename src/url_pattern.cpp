#include "ada.h"

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
      // TODO: Look into why we need this.
      // We need to remove the trailing ':' from the protocol or
      // canonicalize_port will fail.
      std::string_view protocol_view = base_url->get_protocol();
      protocol_view.remove_suffix(1);
      result.protocol =
          url_pattern_helpers::process_base_url_string(protocol_view, type);
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
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.protocol = std::move(process_result.value<std::string>());
  }

  // If init["username"] exists, then set result["username"] to the result of
  // process username for init given init["username"] and type.
  if (init.username.has_value()) {
    auto process_result = process_username(*init.username, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.username = std::move(process_result.value<std::string>());
  }

  // If init["password"] exists, then set result["password"] to the result of
  // process password for init given init["password"] and type.
  if (init.password.has_value()) {
    auto process_result = process_password(*init.password, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.password = std::move(process_result.value<std::string>());
  }

  // If init["hostname"] exists, then set result["hostname"] to the result of
  // process hostname for init given init["hostname"] and type.
  if (init.hostname.has_value()) {
    auto process_result = process_hostname(*init.hostname, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.hostname = std::move(process_result.value<std::string>());
  }

  // If init["port"] exists, then set result["port"] to the result of process
  // port for init given init["port"], result["protocol"], and type.
  if (init.port.has_value()) {
    auto process_result =
        process_port(*init.port, result.protocol.value_or("fake"), type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.port = std::move(process_result.value<std::string>());
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
    if (!pathname_processing_result) {
      return tl::unexpected(pathname_processing_result.error());
    }
    result.pathname =
        std::move(pathname_processing_result.value<std::string>());
  }

  // If init["search"] exists then set result["search"] to the result of process
  // search for init given init["search"] and type.
  if (init.search.has_value()) {
    auto process_result = process_search(*init.search, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.search = std::move(process_result.value<std::string>());
  }

  // If init["hash"] exists then set result["hash"] to the result of process
  // hash for init given init["hash"] and type.
  if (init.hash.has_value()) {
    auto process_result = process_hash(*init.hash, type);
    if (!process_result) {
      return tl::unexpected(process_result.error());
    }
    result.hash = std::move(process_result.value<std::string>());
  }
  // Return result.
  return result;
}

tl::expected<std::string, url_pattern_errors>
url_pattern_init::process_protocol(std::string_view value,
                                   std::string_view type) {
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
  return url_pattern_helpers::canonicalize_port_with_protocol(port, protocol);
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
tl::expected<url_pattern_component, url_pattern_errors>
url_pattern_component::compile(std::string_view input, F encoding_callback,
                               url_pattern_compile_component_options& options) {
  // Let part list be the result of running parse a pattern string given input,
  // options, and encoding callback.
  auto part_list = url_pattern_helpers::parse_pattern_string(input, options,
                                                             encoding_callback);

  if (!part_list) {
    return tl::unexpected(part_list.error());
  }

  // Let (regular expression string, name list) be the result of running
  // generate a regular expression and name list given part list and options.
  auto [regular_expression_string, name_list] =
      url_pattern_helpers::generate_regular_expression_and_name_list(*part_list,
                                                                     options);

  // Let flags be an empty string.
  // If options’s ignore case is true then set flags to "vi".
  // Otherwise set flags to "v"
  std::string flags = options.ignore_case ? "vi" : "v";

  // Let regular expression be RegExpCreate(regular expression string, flags).
  // If this throws an exception, catch it, and throw a TypeError.
  // Note: We don't implement this, since we expect library users to use their
  // own regular expression engine.

  // Let pattern string be the result of running generate a pattern string given
  // part list and options.
  auto pattern_string =
      url_pattern_helpers::generate_pattern_string(*part_list, options);

  // For each part of part list:
  // - If part’s type is "regexp", then set has regexp groups to true.
  const auto has_regexp = [](const auto& part) { return part.is_regexp(); };
  const bool has_regexp_groups = std::ranges::any_of(*part_list, has_regexp);

  // Return a new component whose pattern string is pattern string, regular
  // expression is regular expression, group name list is name list, and has
  // regexp groups is has regexp groups.
  return url_pattern_component(std::move(pattern_string), std::move(flags),
                               std::move(regular_expression_string),
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
  if (input.front() == '{' && input[1] == '[') return true;
  // If input code points[0] is U+005C (\) and input code points[1] is U+005B
  // ([), then return true.
  if (input.front() == '\\' && input[1] == '[') return true;
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
  result.append(escape_regexp_string(options.get_delimiter()));
  // Append "]+?" to the end of result.
  result.append("]+?");
  // Return result.
  return result;
}

bool protocol_component_matches_special_scheme(std::string_view input) {
  // TODO: Optimize this.
  std::regex rx(input.data(), input.size());
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
  if (auto result = match(std::move(input), base_url); result.has_value()) {
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

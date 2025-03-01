#if ADA_INCLUDE_URL_PATTERN

#include "ada/url_pattern-inl.h"

#include <algorithm>
#include <optional>
#include <string>

namespace ada {

tl::expected<url_pattern_init, errors> url_pattern_init::process(
    url_pattern_init init, url_pattern_init::process_type type,
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
    if (type != process_type::pattern && !init.protocol && !init.hostname &&
        !init.port && !init.username) {
      result.username = url_pattern_helpers::process_base_url_string(
          base_url->get_username(), type);
    }

    // TODO: Optimization opportunity: Merge this with the previous check.
    // If type is not "pattern" and init contains none of "protocol",
    // "hostname", "port", "username" and "password", then set
    // result["password"] to the result of processing a base URL string given
    // baseURL’s password and type.
    if (type != process_type::pattern && !init.protocol && !init.hostname &&
        !init.port && !init.username && !init.password) {
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
    if (base_url && !base_url->has_opaque_path &&
        !url_pattern_helpers::is_absolute_pathname(*result.pathname, type)) {
      // Let baseURLPath be the result of running process a base URL string
      // given the result of URL path serializing baseURL and type.
      // TODO: Optimization opportunity: Avoid returning a string if no slash
      // exist.
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
        base_url_path.resize(slash_index + 1);
        // Append result["pathname"] to the end of new pathname.
        ADA_ASSERT_TRUE(result.pathname.has_value());
        base_url_path.append(std::move(*result.pathname));
        // Set result["pathname"] to new pathname.
        result.pathname = std::move(base_url_path);
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
    std::string_view value, process_type type) {
  ada_log("process_protocol=", value, " [", type, "]");
  // Let strippedValue be the given value with a single trailing U+003A (:)
  // removed, if any.
  if (value.ends_with(":")) {
    value.remove_suffix(1);
  }
  // If type is "pattern" then return strippedValue.
  if (type == process_type::pattern) {
    return std::string(value);
  }
  // Return the result of running canonicalize a protocol given strippedValue.
  return url_pattern_helpers::canonicalize_protocol(value);
}

tl::expected<std::string, errors> url_pattern_init::process_username(
    std::string_view value, process_type type) {
  // If type is "pattern" then return value.
  if (type == process_type::pattern) {
    return std::string(value);
  }
  // Return the result of running canonicalize a username given value.
  return url_pattern_helpers::canonicalize_username(value);
}

tl::expected<std::string, errors> url_pattern_init::process_password(
    std::string_view value, process_type type) {
  // If type is "pattern" then return value.
  if (type == process_type::pattern) {
    return std::string(value);
  }
  // Return the result of running canonicalize a password given value.
  return url_pattern_helpers::canonicalize_password(value);
}

tl::expected<std::string, errors> url_pattern_init::process_hostname(
    std::string_view value, process_type type) {
  ada_log("process_hostname value=", value, " type=", type);
  // If type is "pattern" then return value.
  if (type == process_type::pattern) {
    return std::string(value);
  }
  // Return the result of running canonicalize a hostname given value.
  return url_pattern_helpers::canonicalize_hostname(value);
}

tl::expected<std::string, errors> url_pattern_init::process_port(
    std::string_view port, std::string_view protocol, process_type type) {
  // If type is "pattern" then return portValue.
  if (type == process_type::pattern) {
    return std::string(port);
  }
  // Return the result of running canonicalize a port given portValue and
  // protocolValue.
  return url_pattern_helpers::canonicalize_port_with_protocol(port, protocol);
}

tl::expected<std::string, errors> url_pattern_init::process_pathname(
    std::string_view value, std::string_view protocol, process_type type) {
  // If type is "pattern" then return pathnameValue.
  if (type == process_type::pattern) {
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
    std::string_view value, process_type type) {
  // Let strippedValue be the given value with a single leading U+003F (?)
  // removed, if any.
  if (value.starts_with("?")) {
    value.remove_prefix(1);
  }
  ADA_ASSERT_TRUE(!value.starts_with("?"));
  // If type is "pattern" then return strippedValue.
  if (type == process_type::pattern) {
    return std::string(value);
  }
  // Return the result of running canonicalize a search given strippedValue.
  return url_pattern_helpers::canonicalize_search(value);
}

tl::expected<std::string, errors> url_pattern_init::process_hash(
    std::string_view value, process_type type) {
  // Let strippedValue be the given value with a single leading U+0023 (#)
  // removed, if any.
  if (value.starts_with("#")) {
    value.remove_prefix(1);
  }
  ADA_ASSERT_TRUE(!value.starts_with("#"));
  // If type is "pattern" then return strippedValue.
  if (type == process_type::pattern) {
    return std::string(value);
  }
  // Return the result of running canonicalize a hash given strippedValue.
  return url_pattern_helpers::canonicalize_hash(value);
}

}  // namespace ada

#endif  // ADA_INCLUDE_URL_PATTERN

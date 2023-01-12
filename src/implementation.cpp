#include <utility>

#include "ada.h"
#include "character_sets.cpp"

namespace ada {

  ada_warn_unused url parse(std::string input,
                            std::optional<ada::url> base_url,
                            ada::encoding_type encoding,
                            std::optional<ada::state> state) noexcept {

    return ada::parser::parse_url(std::move(input), std::move(base_url), encoding, std::nullopt, state);
  }

  ada_warn_unused url parse(std::string_view input) noexcept {
    return ada::parser::parse_url(std::string(input));
  }

  /*
   * The protocol setter steps are to basic URL parse the given value, followed by U+003A (:),
   * with this’s URL as url and scheme start state as state override.
   *
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   */
  void set_scheme(ada::url &base, std::string input, ada::encoding_type encoding) noexcept {
    if (!input.empty()) {
      input.append(":");
    }

    auto result = ada::parser::parse_url(input, std::nullopt, encoding, base, SCHEME_START);

    if (result.is_valid) {
      base.scheme = result.scheme;
    }
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-username
   */
  void set_username(ada::url &base, std::string input) noexcept {
    // If this’s URL cannot have a username/password/port, then return.
    if (base.cannot_have_credentials_or_port()) {
      return;
    }

    // Set the username given this’s URL and the given value.
    // To set the username given a url and username, set url’s username to the result of running UTF-8 percent-encode
    // on username using the userinfo percent-encode set.
    base.username = ada::unicode::percent_encode(std::string_view(input), character_sets::USERINFO_PERCENT_ENCODE);
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-password
   */
  void set_password(ada::url &base, std::string input) noexcept {
    // If this’s URL cannot have a username/password/port, then return.
    if (base.cannot_have_credentials_or_port()) {
      return;
    }

    // Set the username given this’s URL and the given value.
    // To set the password given a url and password, set url’s password to the result of running UTF-8 percent-encode
    // on password using the userinfo percent-encode set.
    base.password = unicode::percent_encode(std::string_view(input), character_sets::USERINFO_PERCENT_ENCODE);
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-host
   */
  void set_host(ada::url &base, std::string input, ada::encoding_type encoding) noexcept {
    // If this’s URL has an opaque path, then return.
    if (base.has_opaque_path) {
      return;
    }

    // Basic URL parse the given value with this’s URL as url and host state as state override.
    auto result = ada::parser::parse_url(input, std::nullopt, encoding, base, HOST);

    if (result.is_valid) {
      base.host = result.host;
    }
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-port
   */
  void set_port(ada::url &base, std::string input, ada::encoding_type encoding) noexcept {
    // If this’s URL cannot have a username/password/port, then return.
    if (base.cannot_have_credentials_or_port()) {
      return;
    }

    // If the given value is the empty string, then set this’s URL’s port to null.
    if (input.empty()) {
      base.port = std::nullopt;
    }
    // Otherwise, basic URL parse the given value with this’s URL as url and port state as state override.
    else {
      auto result = ada::parser::parse_url(input, std::nullopt, encoding, base, PORT);

      if (result.is_valid) {
        base.port = result.port;
      }
    }
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  void set_pathname(ada::url &base, std::string input, ada::encoding_type encoding) noexcept {
    // If this’s URL has an opaque path, then return.
    if (base.has_opaque_path) {
      return;
    }

    // Empty this’s URL’s path.
    base.path = "";

    // Basic URL parse the given value with this’s URL as url and path start state as state override.
    auto result = ada::parser::parse_url(input, std::nullopt, encoding, base, PATH_START);

    if (result.is_valid) {
      base.path = result.path;
      base.has_opaque_path = result.has_opaque_path;
    }
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-search
   */
  void set_search(ada::url &base, std::string input, ada::encoding_type encoding) noexcept {
    // If the given value is the empty string:
    if (input.empty()) {
      // Set url’s query to null.
      base.query = std::nullopt;

      // Empty this’s query object’s list.
      // TODO: Implement this if/when we have URLSearchParams.

      // Potentially strip trailing spaces from an opaque path with this.

      return;
    }

    // Let input be the given value with a single leading U+003F (?) removed, if any.
    auto new_value = input[0] == '?' ? input.substr(1) : input;

    // Set url’s query to the empty string.
    base.query = "";

    // Basic URL parse input with url as url and query state as state override.
    auto result = ada::parser::parse_url(new_value, std::nullopt, encoding, base, QUERY);

    if (result.is_valid) {
      base.query = result.query;
    }

    // Set this’s query object’s list to the result of parsing input.
    // TODO: Implement this if/when we have URLSearchParams.
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-hash
   */
  void set_hash(ada::url &base, std::string input) noexcept {
    // If the given value is the empty string:
    if (input.empty()) {
      // Set this’s URL’s fragment to null
      base.fragment = std::nullopt;

      // Potentially strip trailing spaces from an opaque path with this.

      return;
    }

    // Let input be the given value with a single leading U+0023 (#) removed, if any.
    auto new_value = input[0] == '#' ? input.substr(1) : input;

    // TODO: Remove tabs and newlines

    // Set this’s URL’s fragment to the empty string.
    // Basic URL parse input with this’s URL as url and fragment state as state override.
    base.fragment = unicode::percent_encode(new_value,
                                            ada::character_sets::FRAGMENT_PERCENT_ENCODE);
  }

} // namespace ada

#include <charconv>
#include <iostream>
#include <string_view>
#include <utility>

#include "ada.h"
#include "ada/character_sets.h"
#include "ada/checkers.h"
#include "ada/common_defs.h"
#include "ada/parser.h"
#include "ada/state.h"
#include "ada/url.h"

namespace ada {

  ada_warn_unused std::string to_string(ada::encoding_type type) {
    switch(type) {
    case ada::encoding_type::UTF8 : return "UTF-8";
    case ada::encoding_type::UTF_16LE : return "UTF-16LE";
    case ada::encoding_type::UTF_16BE : return "UTF-16BE";
    default: unreachable();
    }
  }

  ada_warn_unused url parse(std::string_view input,
                            std::optional<ada::url> base_url,
                            ada::encoding_type encoding,
                            std::optional<ada::state> state) noexcept {
    if(encoding != encoding_type::UTF8) {
      // todo: unsupported !
    }
    // TODO std::move(base_url) might be unwise. Check.
    return ada::parser::parse_url(input, std::move(base_url), encoding, std::nullopt, state);
  }

  /*
   * The protocol setter steps are to basic URL parse the given value, followed by U+003A (:),
   * with this’s URL as url and scheme start state as state override.
   *
   * TODO: This should probably a method in the struct ada::url.
   *
   * return true on success.
   *
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   */
  bool set_scheme(ada::url& base, std::string input, ada::encoding_type encoding) noexcept {
    if(encoding != encoding_type::UTF8) {
      return false; // unsupported !
    }
    if (!input.empty()) {
      input.append(":");
    } else {
      // Empty schemes are not allowed according to spec.
      return false;
    }

    // Schemes should start with alpha values.
    if (!checkers::is_alpha(input[0])) {
      return false;
    }

    std::string::iterator pointer = std::find_if_not(input.begin(), input.end(), unicode::is_alnum_plus);

    if (pointer != input.end() && *pointer == ':') {
      return base.parse_scheme<true>(std::string_view(input.data(), pointer - input.begin()));
    }

    return false;
  }

  /**
   * TODO: This should probably a method in the struct ada::url.
   *
   * @see https://url.spec.whatwg.org/#dom-url-username
   */
  void set_username(ada::url &base, std::string_view input) noexcept {
    // If this’s URL cannot have a username/password/port, then return.
    if (base.cannot_have_credentials_or_port()) {
      return;
    }

    // Set the username given this’s URL and the given value.
    // To set the username given a url and username, set url’s username to the result of running UTF-8 percent-encode
    // on username using the userinfo percent-encode set.
    base.username = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  }

  /**
   * TODO: This should probably a method in the struct ada::url.
   *
   * @see https://url.spec.whatwg.org/#dom-url-password
   */
  void set_password(ada::url &base, std::string_view input) noexcept {
    // If this’s URL cannot have a username/password/port, then return.
    if (base.cannot_have_credentials_or_port()) {
      return;
    }

    // Set the username given this’s URL and the given value.
    // To set the password given a url and password, set url’s password to the result of running UTF-8 percent-encode
    // on password using the userinfo percent-encode set.
    base.password = unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  }

  /**
   * TODO: This should probably a method in the struct ada::url.
   *
   * Return true on success.
   *
   * @see https://url.spec.whatwg.org/#dom-url-host
   */
  bool set_host(ada::url& base, std::string_view input, ada::encoding_type encoding) noexcept {
    if(encoding != encoding_type::UTF8) {
      return false; // unsupported !
    }
    // If this’s URL has an opaque path, then return.
    if (base.has_opaque_path) {
      return true;
    }

    std::string_view::iterator pointer_start = input.begin();
    if (!input.empty() && input[0] == '#') { pointer_start++; }
    std::string_view::iterator pointer_end = std::find(pointer_start, input.end(), '#');

    std::string _host(pointer_start, std::distance(pointer_start, pointer_end));
    helpers::remove_ascii_tab_or_newline(_host);
    std::string_view host(_host);

    // If url's scheme is "file", then set state to file host state, instead of host state.
    if (base.get_scheme_type() != ada::scheme::type::FILE) {
      std::string_view::iterator pointer = host.begin();
      std::string_view host_view(_host.data(), _host.length());
      bool inside_brackets{false};
      size_t location = helpers::get_host_delimiter_location(base, host_view, inside_brackets);
      pointer = (location != std::string_view::npos) ? pointer + location : host.end();

      // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
      // Note: we cannot access *pointer safely if (pointer == pointer_end).
      if ((pointer != pointer_end) && (*pointer == ':') && !inside_brackets) {
        // If buffer is the empty string, validation error, return failure.
        return false;
      }
      // Otherwise, if one of the following is true:
      // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
      // - url is special and c is U+005C (\)
      else if (pointer == pointer_end || *pointer == '/' || *pointer == '?' || (base.is_special() && *pointer == '\\')) {
        // If url is special and host_view is the empty string, validation error, return failure.
        // Otherwise, if state override is given, host_view is the empty string,
        // and either url includes credentials or url’s port is non-null, return.
        if (host_view.empty() && (base.is_special() || base.includes_credentials() || base.port.has_value())) {
          return false;
        }

        // Let host be the result of host parsing host_view with url is not special.
        if (host_view.empty()) {
          base.host = "";
          return true;
        } else {
          base.parse_host(host_view);
          return true;
        }
      }
    }

    ada::state state = base.get_scheme_type() == ada::scheme::type::FILE ? state::FILE_HOST : state::HOST;

    /**
     * TODO: This needs to be reengineered. The next line calls
     * a large function just to later update the host. We should
     * specialize and just call what is needed: a host computation.
     */
    // Basic URL parse the given value with this’s URL as url and host state as state override.
    auto result = ada::parser::parse_url(std::string_view(pointer_start, pointer_end - pointer_start), std::nullopt, encoding,
#if ADA_DEVELOP_MODE
    base.oh_no_we_need_to_copy_url(),
#else
    base,
#endif
    state);

    if (result.is_valid) {
      base.host = result.host;
    }
    return true;
  }

  /**
   * TODO: This should probably a method in the struct ada::url.
   *
   * return true on success.
   *
   * @see https://url.spec.whatwg.org/#dom-url-port
   */
  bool set_port(ada::url& base, std::string_view input) noexcept {
    // If this’s URL cannot have a username/password/port, then return.
    if (base.cannot_have_credentials_or_port()) {
      return false;
    }
    return base.parse_port(input);
  }

  /**
   * Return true on success.
   * TODO: This should probably a method in the struct ada::url.
   *
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   */
  bool set_pathname(ada::url& base, std::string_view input, ada::encoding_type encoding) noexcept {

    if(encoding != encoding_type::UTF8) {
      return false; // unsupported !
    }
    // If this’s URL has an opaque path, then return.
    if (base.has_opaque_path) {
      return true;
    }
    // Empty this’s URL’s path.
    base.path = "";
    return base.parse_path(input);
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-search
   */
  void set_search(ada::url &base, std::string_view input) noexcept {
    // If the given value is the empty string:
    if (input.empty()) {
      // Set url’s query to null.
      base.query = std::nullopt;

      // Empty this’s query object’s list.
      // TODO: Implement this if/when we have URLSearchParams.

      // Potentially strip trailing spaces from an opaque path with this.

      return;
    }

    std::string new_value;
    new_value = input[0] == '?' ? input.substr(1) : input;
    helpers::remove_ascii_tab_or_newline(new_value);

    auto query_percent_encode_set = base.is_special() ?
      ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
      ada::character_sets::QUERY_PERCENT_ENCODE;

    // Percent-encode after encoding, with encoding, buffer, and queryPercentEncodeSet,
    // and append the result to url’s query.
    base.query = ada::unicode::percent_encode(std::string_view(new_value), query_percent_encode_set);

    // Set this’s query object’s list to the result of parsing input.
    // TODO: Implement this if/when we have URLSearchParams.
  }

  /**
   * @see https://url.spec.whatwg.org/#dom-url-hash
   */
  void set_hash(ada::url &base, std::string_view input) noexcept {
    // If the given value is the empty string:
    if (input.empty()) {
      // Set this’s URL’s fragment to null
      base.fragment = std::nullopt;

      // Potentially strip trailing spaces from an opaque path with this.

      return;
    }

    // Let input be the given value with a single leading U+0023 (#) removed, if any.
    std::string new_value;
    new_value = input[0] == '#' ? input.substr(1) : input;
    helpers::remove_ascii_tab_or_newline(new_value);

    // Set this’s URL’s fragment to the empty string.
    // Basic URL parse input with this’s URL as url and fragment state as state override.
    base.fragment = unicode::percent_encode(new_value,
                                            ada::character_sets::FRAGMENT_PERCENT_ENCODE);
  }

} // namespace ada

#include "ada.h"
#include "ada/common_defs.h"
#include "ada/character_sets-inl.h"
#include "ada/unicode.h"
#include "ada/url-inl.h"
#include "ada/log.h"
#include "ada/parser.h"

#include <numeric>
#include <limits>

namespace ada::parser {

template <class result_type>
result_type parse_url(std::string_view user_input,
                      const result_type* base_url) {
  // We can specialize the implementation per type.
  // Important: result_type_is_ada_url is evaluated at *compile time*. This
  // means that doing if constexpr(result_type_is_ada_url) { something } else {
  // something else } is free (at runtime). This means that ada::url_aggregator
  // and ada::url **do not have to support the exact same API**.
  constexpr bool result_type_is_ada_url =
      std::is_same<ada::url, result_type>::value;
  constexpr bool result_type_is_ada_url_aggregator =
      std::is_same<ada::url_aggregator, result_type>::value;
  static_assert(result_type_is_ada_url ||
                result_type_is_ada_url_aggregator);  // We don't support
                                                     // anything else for now.

  ada_log("ada::parser::parse_url('", user_input, "' [", user_input.size(),
          " bytes],", (base_url != nullptr ? base_url->to_string() : "null"),
          ")");

  ada::state state = ada::state::SCHEME_START;
  result_type url{};

  // We refuse to parse URL strings that exceed 4GB. Such strings are almost
  // surely the result of a bug or are otherwise a security concern.
  if (user_input.size() > std::numeric_limits<uint32_t>::max()) {
    url.is_valid = false;
  }
  // Going forward, user_input.size() is in [0,
  // std::numeric_limits<uint32_t>::max). If we are provided with an invalid
  // base, or the optional_url was invalid, we must return.
  if (base_url != nullptr) {
    url.is_valid &= base_url->is_valid;
  }
  if (!url.is_valid) {
    return url;
  }
  if constexpr (result_type_is_ada_url_aggregator) {
    // Most of the time, we just need user_input.size().
    // In some instances, we may need a bit more.
    ///////////////////////////
    // This is *very* important. This line should *not* be removed
    // hastily. There are principled reasons why reserve is important
    // for performance. If you have a benchmark with small inputs,
    // it may not matter, but in other instances, it could.
    ////
    // This rounds up to the next power of two.
    // We know that user_input.size() is in [0,
    // std::numeric_limits<uint32_t>::max).
    uint32_t reserve_capacity =
        (0xFFFFFFFF >>
         helpers::leading_zeroes(uint32_t(1 | user_input.size()))) +
        1;
    url.reserve(reserve_capacity);
    //
    //
    //
  }
  std::string tmp_buffer;
  std::string_view internal_input;
  if (unicode::has_tabs_or_newline(user_input)) {
    tmp_buffer = user_input;
    // Optimization opportunity: Instead of copying and then pruning, we could
    // just directly build the string from user_input.
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = user_input;
  }

  // Leading and trailing control characters are uncommon and easy to deal with
  // (no performance concern).
  std::string_view url_data = internal_input;
  helpers::trim_c0_whitespace(url_data);

  // Optimization opportunity. Most websites do not have fragment.
  std::optional<std::string_view> fragment = helpers::prune_hash(url_data);
  // We add it last so that an implementation like ada::url_aggregator
  // can append it last to its internal buffer, thus improving performance.

  // Here url_data no longer has its fragment.
  // We are going to access the data from url_data (it is immutable).
  // At any given time, we are pointing at byte 'input_position' in url_data.
  // The input_position variable should range from 0 to input_size.
  // It is illegal to access url_data at input_size.
  size_t input_position = 0;
  const size_t input_size = url_data.size();
  // Keep running the following state machine by switching on state.
  // If after a run pointer points to the EOF code point, go to the next step.
  // Otherwise, increase pointer by 1 and continue with the state machine.
  // We never decrement input_position.
  while (input_position <= input_size) {
    ada_log("In parsing at ", input_position, " out of ", input_size,
            " in state ", ada::to_string(state));
    switch (state) {
      case ada::state::SCHEME_START: {
        ada_log("SCHEME_START ", helpers::substring(url_data, input_position));
        // If c is an ASCII alpha, append c, lowercased, to buffer, and set
        // state to scheme state.
        if ((input_position != input_size) &&
            checkers::is_alpha(url_data[input_position])) {
          state = ada::state::SCHEME;
          input_position++;
        } else {
          // Otherwise, if state override is not given, set state to no scheme
          // state and decrease pointer by 1.
          state = ada::state::NO_SCHEME;
        }
        break;
      }
      case ada::state::SCHEME: {
        ada_log("SCHEME ", helpers::substring(url_data, input_position));
        // If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.),
        // append c, lowercased, to buffer.
        while ((input_position != input_size) &&
               (ada::unicode::is_alnum_plus(url_data[input_position]))) {
          input_position++;
        }
        // Otherwise, if c is U+003A (:), then:
        if ((input_position != input_size) &&
            (url_data[input_position] == ':')) {
          ada_log("SCHEME the scheme should be ",
                  url_data.substr(0, input_position));
          if constexpr (result_type_is_ada_url) {
            if (!url.parse_scheme(url_data.substr(0, input_position))) {
              return url;
            }
          } else {
            // we pass the colon along instead of painfully adding it back.
            if (!url.parse_scheme_with_colon(
                    url_data.substr(0, input_position + 1))) {
              return url;
            }
          }
          ada_log("SCHEME the scheme is ", url.get_protocol());

          // If url's scheme is "file", then:
          if (url.type == ada::scheme::type::FILE) {
            // Set state to file state.
            state = ada::state::FILE;
          }
          // Otherwise, if url is special, base is non-null, and base's scheme
          // is url's scheme: Note: Doing base_url->scheme is unsafe if base_url
          // != nullptr is false.
          else if (url.is_special() && base_url != nullptr &&
                   base_url->type == url.type) {
            // Set state to special relative or authority state.
            state = ada::state::SPECIAL_RELATIVE_OR_AUTHORITY;
          }
          // Otherwise, if url is special, set state to special authority
          // slashes state.
          else if (url.is_special()) {
            state = ada::state::SPECIAL_AUTHORITY_SLASHES;
          }
          // Otherwise, if remaining starts with an U+002F (/), set state to
          // path or authority state and increase pointer by 1.
          else if (input_position + 1 < input_size &&
                   url_data[input_position + 1] == '/') {
            state = ada::state::PATH_OR_AUTHORITY;
            input_position++;
          }
          // Otherwise, set url's path to the empty string and set state to
          // opaque path state.
          else {
            state = ada::state::OPAQUE_PATH;
          }
        }
        // Otherwise, if state override is not given, set buffer to the empty
        // string, state to no scheme state, and start over (from the first code
        // point in input).
        else {
          state = ada::state::NO_SCHEME;
          input_position = 0;
          break;
        }
        input_position++;
        break;
      }
      case ada::state::NO_SCHEME: {
        ada_log("NO_SCHEME ", helpers::substring(url_data, input_position));
        // If base is null, or base has an opaque path and c is not U+0023 (#),
        // validation error, return failure.
        if (base_url == nullptr ||
            (base_url->has_opaque_path && !fragment.has_value())) {
          ada_log("NO_SCHEME validation error");
          url.is_valid = false;
          return url;
        }
        // Otherwise, if base has an opaque path and c is U+0023 (#),
        // set url's scheme to base's scheme, url's path to base's path, url's
        // query to base's query, and set state to fragment state.
        else if (base_url->has_opaque_path && fragment.has_value() &&
                 input_position == input_size) {
          ada_log("NO_SCHEME opaque base with fragment");
          url.copy_scheme(*base_url);
          url.has_opaque_path = base_url->has_opaque_path;

          if constexpr (result_type_is_ada_url) {
            url.path = base_url->path;
            url.query = base_url->query;
          } else {
            url.update_base_pathname(base_url->get_pathname());
            url.update_base_search(base_url->get_search());
          }
          url.update_unencoded_base_hash(*fragment);
          return url;
        }
        // Otherwise, if base's scheme is not "file", set state to relative
        // state and decrease pointer by 1.
        else if (base_url->type != ada::scheme::type::FILE) {
          ada_log("NO_SCHEME non-file relative path");
          state = ada::state::RELATIVE_SCHEME;
        }
        // Otherwise, set state to file state and decrease pointer by 1.
        else {
          ada_log("NO_SCHEME file base type");
          state = ada::state::FILE;
        }
        break;
      }
      case ada::state::AUTHORITY: {
        ada_log("AUTHORITY ", helpers::substring(url_data, input_position));
        // most URLs have no @. Having no @ tells us that we don't have to worry
        // about AUTHORITY. Of course, we could have @ and still not have to
        // worry about AUTHORITY.
        // TODO: Instead of just collecting a bool, collect the location of the
        // '@' and do something useful with it.
        // TODO: We could do various processing early on, using a single pass
        // over the string to collect information about it, e.g., telling us
        // whether there is a @ and if so, where (or how many).
        const bool contains_ampersand =
            (url_data.find('@', input_position) != std::string_view::npos);

        if (!contains_ampersand) {
          state = ada::state::HOST;
          break;
        }
        bool at_sign_seen{false};
        bool password_token_seen{false};
        /**
         * We expect something of the sort...
         * https://user:pass@example.com:1234/foo/bar?baz#quux
         * --------^
         */
        do {
          std::string_view view = helpers::substring(url_data, input_position);
          // The delimiters are @, /, ? \\.
          size_t location =
              url.is_special() ? helpers::find_authority_delimiter_special(view)
                               : helpers::find_authority_delimiter(view);
          std::string_view authority_view(view.data(), location);
          size_t end_of_authority = input_position + authority_view.size();
          // If c is U+0040 (@), then:
          if ((end_of_authority != input_size) &&
              (url_data[end_of_authority] == '@')) {
            // If atSignSeen is true, then prepend "%40" to buffer.
            if (at_sign_seen) {
              if (password_token_seen) {
                if constexpr (result_type_is_ada_url) {
                  url.password += "%40";
                } else {
                  url.append_base_password("%40");
                }
              } else {
                if constexpr (result_type_is_ada_url) {
                  url.username += "%40";
                } else {
                  url.append_base_username("%40");
                }
              }
            }

            at_sign_seen = true;

            if (!password_token_seen) {
              size_t password_token_location = authority_view.find(':');
              password_token_seen =
                  password_token_location != std::string_view::npos;

              if (!password_token_seen) {
                if constexpr (result_type_is_ada_url) {
                  url.username += unicode::percent_encode(
                      authority_view, character_sets::USERINFO_PERCENT_ENCODE);
                } else {
                  url.append_base_username(unicode::percent_encode(
                      authority_view, character_sets::USERINFO_PERCENT_ENCODE));
                }
              } else {
                if constexpr (result_type_is_ada_url) {
                  url.username += unicode::percent_encode(
                      authority_view.substr(0, password_token_location),
                      character_sets::USERINFO_PERCENT_ENCODE);
                  url.password += unicode::percent_encode(
                      authority_view.substr(password_token_location + 1),
                      character_sets::USERINFO_PERCENT_ENCODE);
                } else {
                  url.append_base_username(unicode::percent_encode(
                      authority_view.substr(0, password_token_location),
                      character_sets::USERINFO_PERCENT_ENCODE));
                  url.append_base_password(unicode::percent_encode(
                      authority_view.substr(password_token_location + 1),
                      character_sets::USERINFO_PERCENT_ENCODE));
                }
              }
            } else {
              if constexpr (result_type_is_ada_url) {
                url.password += unicode::percent_encode(
                    authority_view, character_sets::USERINFO_PERCENT_ENCODE);
              } else {
                url.append_base_password(unicode::percent_encode(
                    authority_view, character_sets::USERINFO_PERCENT_ENCODE));
              }
            }
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          else if (end_of_authority == input_size ||
                   url_data[end_of_authority] == '/' ||
                   url_data[end_of_authority] == '?' ||
                   (url.is_special() && url_data[end_of_authority] == '\\')) {
            // If atSignSeen is true and authority_view is the empty string,
            // validation error, return failure.
            if (at_sign_seen && authority_view.empty()) {
              url.is_valid = false;
              return url;
            }
            state = ada::state::HOST;
            break;
          }
          if (end_of_authority == input_size) {
            if (fragment.has_value()) {
              url.update_unencoded_base_hash(*fragment);
            }
            return url;
          }
          input_position = end_of_authority + 1;
        } while (true);

        break;
      }
      case ada::state::SPECIAL_RELATIVE_OR_AUTHORITY: {
        ada_log("SPECIAL_RELATIVE_OR_AUTHORITY ",
                helpers::substring(url_data, input_position));

        // If c is U+002F (/) and remaining starts with U+002F (/),
        // then set state to special authority ignore slashes state and increase
        // pointer by 1.
        std::string_view view = helpers::substring(url_data, input_position);
        if (ada::checkers::begins_with(view, "//")) {
          state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
          input_position += 2;
        } else {
          // Otherwise, validation error, set state to relative state and
          // decrease pointer by 1.
          state = ada::state::RELATIVE_SCHEME;
        }

        break;
      }
      case ada::state::PATH_OR_AUTHORITY: {
        ada_log("PATH_OR_AUTHORITY ",
                helpers::substring(url_data, input_position));

        // If c is U+002F (/), then set state to authority state.
        if ((input_position != input_size) &&
            (url_data[input_position] == '/')) {
          state = ada::state::AUTHORITY;
          input_position++;
        } else {
          // Otherwise, set state to path state, and decrease pointer by 1.
          state = ada::state::PATH;
        }

        break;
      }
      case ada::state::RELATIVE_SCHEME: {
        ada_log("RELATIVE_SCHEME ",
                helpers::substring(url_data, input_position));

        // Set url's scheme to base's scheme.
        url.copy_scheme(*base_url);

        // If c is U+002F (/), then set state to relative slash state.
        if ((input_position != input_size) &&
            (url_data[input_position] == '/')) {
          ada_log(
              "RELATIVE_SCHEME if c is U+002F (/), then set state to relative "
              "slash state");
          state = ada::state::RELATIVE_SLASH;
        } else if (url.is_special() && (input_position != input_size) &&
                   (url_data[input_position] == '\\')) {
          // Otherwise, if url is special and c is U+005C (\), validation error,
          // set state to relative slash state.
          ada_log(
              "RELATIVE_SCHEME  if url is special and c is U+005C, validation "
              "error, set state to relative slash state");
          state = ada::state::RELATIVE_SLASH;
        } else {
          ada_log("RELATIVE_SCHEME otherwise");
          // Set url's username to base's username, url's password to base's
          // password, url's host to base's host, url's port to base's port,
          // url's path to a clone of base's path, and url's query to base's
          // query.
          if constexpr (result_type_is_ada_url) {
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            // cloning the base path includes cloning the has_opaque_path flag
            url.has_opaque_path = base_url->has_opaque_path;
            url.path = base_url->path;
            url.query = base_url->query;
          } else {
            url.update_base_authority(base_url->get_href(),
                                      base_url->get_components());
            // TODO: Get rid of set_hostname and replace it with
            // update_base_hostname
            url.set_hostname(base_url->get_hostname());
            url.update_base_port(base_url->retrieve_base_port());
            // cloning the base path includes cloning the has_opaque_path flag
            url.has_opaque_path = base_url->has_opaque_path;
            url.update_base_pathname(base_url->get_pathname());
            url.update_base_search(base_url->get_search());
          }

          url.has_opaque_path = base_url->has_opaque_path;

          // If c is U+003F (?), then set url's query to the empty string, and
          // state to query state.
          if ((input_position != input_size) &&
              (url_data[input_position] == '?')) {
            state = ada::state::QUERY;
          }
          // Otherwise, if c is not the EOF code point:
          else if (input_position != input_size) {
            // Set url's query to null.
            url.clear_search();
            if constexpr (result_type_is_ada_url) {
              // Shorten url's path.
              helpers::shorten_path(url.path, url.type);
            } else {
              std::string_view path = url.get_pathname();
              if (helpers::shorten_path(path, url.type)) {
                url.update_base_pathname(std::string(path));
              }
            }
            // Set state to path state and decrease pointer by 1.
            state = ada::state::PATH;
            break;
          }
        }
        input_position++;
        break;
      }
      case ada::state::RELATIVE_SLASH: {
        ada_log("RELATIVE_SLASH ",
                helpers::substring(url_data, input_position));

        // If url is special and c is U+002F (/) or U+005C (\), then:
        if (url.is_special() && (input_position != input_size) &&
            (url_data[input_position] == '/' ||
             url_data[input_position] == '\\')) {
          // Set state to special authority ignore slashes state.
          state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
        }
        // Otherwise, if c is U+002F (/), then set state to authority state.
        else if ((input_position != input_size) &&
                 (url_data[input_position] == '/')) {
          state = ada::state::AUTHORITY;
        }
        // Otherwise, set
        // - url's username to base's username,
        // - url's password to base's password,
        // - url's host to base's host,
        // - url's port to base's port,
        // - state to path state, and then, decrease pointer by 1.
        else {
          if constexpr (result_type_is_ada_url) {
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
          } else {
            url.update_base_authority(base_url->get_href(),
                                      base_url->get_components());
            // TODO: Get rid of set_hostname and replace it with
            // update_base_hostname
            url.set_hostname(base_url->get_hostname());
            url.update_base_port(base_url->retrieve_base_port());
          }
          state = ada::state::PATH;
          break;
        }

        input_position++;
        break;
      }
      case ada::state::SPECIAL_AUTHORITY_SLASHES: {
        ada_log("SPECIAL_AUTHORITY_SLASHES ",
                helpers::substring(url_data, input_position));

        // If c is U+002F (/) and remaining starts with U+002F (/),
        // then set state to special authority ignore slashes state and increase
        // pointer by 1.
        std::string_view view = helpers::substring(url_data, input_position);
        if (ada::checkers::begins_with(view, "//")) {
          input_position += 2;
        }

        [[fallthrough]];
      }
      case ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES: {
        ada_log("SPECIAL_AUTHORITY_IGNORE_SLASHES ",
                helpers::substring(url_data, input_position));

        // If c is neither U+002F (/) nor U+005C (\), then set state to
        // authority state and decrease pointer by 1.
        while ((input_position != input_size) &&
               ((url_data[input_position] == '/') ||
                (url_data[input_position] == '\\'))) {
          input_position++;
        }
        state = ada::state::AUTHORITY;

        break;
      }
      case ada::state::QUERY: {
        ada_log("QUERY ", helpers::substring(url_data, input_position));
        // Let queryPercentEncodeSet be the special-query percent-encode set if
        // url is special; otherwise the query percent-encode set.
        const uint8_t* query_percent_encode_set =
            url.is_special() ? ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE
                             : ada::character_sets::QUERY_PERCENT_ENCODE;

        // Percent-encode after encoding, with encoding, buffer, and
        // queryPercentEncodeSet, and append the result to url's query.
        url.update_base_search(helpers::substring(url_data, input_position),
                               query_percent_encode_set);
        ada_log("QUERY update_base_search completed ");
        if (fragment.has_value()) {
          url.update_unencoded_base_hash(*fragment);
        }
        return url;
      }
      case ada::state::HOST: {
        ada_log("HOST ", helpers::substring(url_data, input_position));

        std::string_view host_view =
            helpers::substring(url_data, input_position);
        auto [location, found_colon] =
            helpers::get_host_delimiter_location(url.is_special(), host_view);
        input_position = (location != std::string_view::npos)
                             ? input_position + location
                             : input_size;
        // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
        // Note: the 'found_colon' value is true if and only if a colon was
        // encountered while not inside brackets.
        if (found_colon) {
          // If buffer is the empty string, validation error, return failure.
          // Let host be the result of host parsing buffer with url is not
          // special.
          ada_log("HOST parsing ", host_view);
          if (!url.parse_host(host_view)) {
            return url;
          }
          ada_log("HOST parsing results in ", url.get_hostname());
          // Set url's host to host, buffer to the empty string, and state to
          // port state.
          state = ada::state::PORT;
          input_position++;
        }
        // Otherwise, if one of the following is true:
        // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
        // - url is special and c is U+005C (\)
        // The get_host_delimiter_location function either brings us to
        // the colon outside of the bracket, or to one of those characters.
        else {
          // If url is special and host_view is the empty string, validation
          // error, return failure.
          if (url.is_special() && host_view.empty()) {
            url.is_valid = false;
            return url;
          }
          ada_log("HOST parsing ", host_view, " href=", url.get_href());
          // Let host be the result of host parsing host_view with url is not
          // special.
          if (host_view.empty()) {
            url.update_base_hostname("");
          } else if (!url.parse_host(host_view)) {
            return url;
          }
          ada_log("HOST parsing results in ", url.get_hostname(),
                  " href=", url.get_href());

          // Set url's host to host, and state to path start state.
          state = ada::state::PATH_START;
        }

        break;
      }
      case ada::state::OPAQUE_PATH: {
        ada_log("OPAQUE_PATH ", helpers::substring(url_data, input_position));
        std::string_view view = helpers::substring(url_data, input_position);
        // If c is U+003F (?), then set url's query to the empty string and
        // state to query state.
        size_t location = view.find('?');
        if (location != std::string_view::npos) {
          view.remove_suffix(view.size() - location);
          state = ada::state::QUERY;
          input_position += location + 1;
        } else {
          input_position = input_size + 1;
        }
        url.has_opaque_path = true;
        // This is a really unlikely scenario in real world. We should not seek
        // to optimize it.
        url.update_base_pathname(unicode::percent_encode(
            view, character_sets::C0_CONTROL_PERCENT_ENCODE));
        break;
      }
      case ada::state::PORT: {
        ada_log("PORT ", helpers::substring(url_data, input_position));
        std::string_view port_view =
            helpers::substring(url_data, input_position);
        size_t consumed_bytes = url.parse_port(port_view, true);
        input_position += consumed_bytes;
        if (!url.is_valid) {
          return url;
        }
        state = state::PATH_START;
        [[fallthrough]];
      }
      case ada::state::PATH_START: {
        ada_log("PATH_START ", helpers::substring(url_data, input_position));

        // If url is special, then:
        if (url.is_special()) {
          // Set state to path state.
          state = ada::state::PATH;

          // Optimization: Avoiding going into PATH state improves the
          // performance of urls ending with /.
          if (input_position == input_size) {
            url.update_base_pathname("/");
            if (fragment.has_value()) {
              url.update_unencoded_base_hash(*fragment);
            }
            return url;
          }
          // If c is neither U+002F (/) nor U+005C (\), then decrease pointer
          // by 1. We know that (input_position == input_size) is impossible
          // here, because of the previous if-check.
          if ((url_data[input_position] != '/') &&
              (url_data[input_position] != '\\')) {
            break;
          }
        }
        // Otherwise, if state override is not given and c is U+003F (?),
        // set url's query to the empty string and state to query state.
        else if ((input_position != input_size) &&
                 (url_data[input_position] == '?')) {
          state = ada::state::QUERY;
        }
        // Otherwise, if c is not the EOF code point:
        else if (input_position != input_size) {
          // Set state to path state.
          state = ada::state::PATH;

          // If c is not U+002F (/), then decrease pointer by 1.
          if (url_data[input_position] != '/') {
            break;
          }
        }

        input_position++;
        break;
      }
      case ada::state::PATH: {
        std::string_view view = helpers::substring(url_data, input_position);
        ada_log("PATH ", helpers::substring(url_data, input_position));

        // Most time, we do not need percent encoding.
        // Furthermore, we can immediately locate the '?'.
        size_t locofquestionmark = view.find('?');
        if (locofquestionmark != std::string_view::npos) {
          state = ada::state::QUERY;
          view.remove_suffix(view.size() - locofquestionmark);
          input_position += locofquestionmark + 1;
        } else {
          input_position = input_size + 1;
        }
        if constexpr (result_type_is_ada_url) {
          helpers::parse_prepared_path(view, url.type, url.path);
        } else {
          url.consume_prepared_path(view);
          ADA_ASSERT_TRUE(url.validate());
        }
        break;
      }
      case ada::state::FILE_SLASH: {
        ada_log("FILE_SLASH ", helpers::substring(url_data, input_position));

        // If c is U+002F (/) or U+005C (\), then:
        if ((input_position != input_size) &&
            (url_data[input_position] == '/' ||
             url_data[input_position] == '\\')) {
          ada_log("FILE_SLASH c is U+002F or U+005C");
          // Set state to file host state.
          state = ada::state::FILE_HOST;
          input_position++;
        } else {
          ada_log("FILE_SLASH otherwise");
          // If base is non-null and base's scheme is "file", then:
          // Note: it is unsafe to do base_url->scheme unless you know that
          // base_url_has_value() is true.
          if (base_url != nullptr &&
              base_url->type == ada::scheme::type::FILE) {
            // Set url's host to base's host.
            if constexpr (result_type_is_ada_url) {
              url.host = base_url->host;
            } else {
              // TODO: Optimization opportunity.
              url.set_host(base_url->get_host());
            }
            // If the code point substring from pointer to the end of input does
            // not start with a Windows drive letter and base's path[0] is a
            // normalized Windows drive letter, then append base's path[0] to
            // url's path.
            if (!base_url->get_pathname().empty()) {
              if (!checkers::is_windows_drive_letter(
                      helpers::substring(url_data, input_position))) {
                std::string_view first_base_url_path =
                    base_url->get_pathname().substr(1);
                size_t loc = first_base_url_path.find('/');
                if (loc != std::string_view::npos) {
                  helpers::resize(first_base_url_path, loc);
                }
                if (checkers::is_normalized_windows_drive_letter(
                        first_base_url_path)) {
                  if constexpr (result_type_is_ada_url) {
                    url.path += '/';
                    url.path += first_base_url_path;
                  } else {
                    url.append_base_pathname(
                        helpers::concat("/", first_base_url_path));
                  }
                }
              }
            }
          }

          // Set state to path state, and decrease pointer by 1.
          state = ada::state::PATH;
        }

        break;
      }
      case ada::state::FILE_HOST: {
        std::string_view view = helpers::substring(url_data, input_position);
        ada_log("FILE_HOST ", helpers::substring(url_data, input_position));

        size_t location = view.find_first_of("/\\?");
        std::string_view file_host_buffer(
            view.data(),
            (location != std::string_view::npos) ? location : view.size());

        if (checkers::is_windows_drive_letter(file_host_buffer)) {
          state = ada::state::PATH;
        } else if (file_host_buffer.empty()) {
          // Set url's host to the empty string.
          if constexpr (result_type_is_ada_url) {
            url.host = "";
          } else {
            url.update_base_hostname("");
          }
          // Set state to path start state.
          state = ada::state::PATH_START;
        } else {
          size_t consumed_bytes = file_host_buffer.size();
          input_position += consumed_bytes;
          // Let host be the result of host parsing buffer with url is not
          // special.
          if (!url.parse_host(file_host_buffer)) {
            return url;
          }

          if constexpr (result_type_is_ada_url) {
            // If host is "localhost", then set host to the empty string.
            if (url.host.has_value() && url.host.value() == "localhost") {
              url.host = "";
            }
          } else {
            if (url.get_hostname() == "localhost") {
              url.update_base_hostname("");
            }
          }

          // Set buffer to the empty string and state to path start state.
          state = ada::state::PATH_START;
        }

        break;
      }
      case ada::state::FILE: {
        ada_log("FILE ", helpers::substring(url_data, input_position));
        std::string_view file_view =
            helpers::substring(url_data, input_position);

        url.set_protocol_as_file();
        if constexpr (result_type_is_ada_url) {
          // Set url's host to the empty string.
          url.host = "";
        } else {
          url.update_base_hostname("");
        }
        // If c is U+002F (/) or U+005C (\), then:
        if (input_position != input_size &&
            (url_data[input_position] == '/' ||
             url_data[input_position] == '\\')) {
          ada_log("FILE c is U+002F or U+005C");
          // Set state to file slash state.
          state = ada::state::FILE_SLASH;
        }
        // Otherwise, if base is non-null and base's scheme is "file":
        else if (base_url != nullptr &&
                 base_url->type == ada::scheme::type::FILE) {
          // Set url's host to base's host, url's path to a clone of base's
          // path, and url's query to base's query.
          ada_log("FILE base non-null");
          if constexpr (result_type_is_ada_url) {
            url.host = base_url->host;
            url.path = base_url->path;
            url.query = base_url->query;
          } else {
            // TODO: Get rid of set_hostname and replace it with
            // update_base_hostname
            url.set_hostname(base_url->get_hostname());
            url.update_base_pathname(base_url->get_pathname());
            url.update_base_search(base_url->get_search());
          }
          url.has_opaque_path = base_url->has_opaque_path;

          // If c is U+003F (?), then set url's query to the empty string and
          // state to query state.
          if (input_position != input_size && url_data[input_position] == '?') {
            state = ada::state::QUERY;
          }
          // Otherwise, if c is not the EOF code point:
          else if (input_position != input_size) {
            // Set url's query to null.
            url.clear_search();
            // If the code point substring from pointer to the end of input does
            // not start with a Windows drive letter, then shorten url's path.
            if (!checkers::is_windows_drive_letter(file_view)) {
              if constexpr (result_type_is_ada_url) {
                helpers::shorten_path(url.path, url.type);
              } else {
                std::string_view path = url.get_pathname();
                if (helpers::shorten_path(path, url.type)) {
                  url.update_base_pathname(std::string(path));
                }
              }
            }
            // Otherwise:
            else {
              // Set url's path to an empty list.
              url.clear_pathname();
              url.has_opaque_path = true;
            }

            // Set state to path state and decrease pointer by 1.
            state = ada::state::PATH;
            break;
          }
        }
        // Otherwise, set state to path state, and decrease pointer by 1.
        else {
          ada_log("FILE go to path");
          state = ada::state::PATH;
          break;
        }

        input_position++;
        break;
      }
      default:
        ada::unreachable();
    }
  }
  if (fragment.has_value()) {
    url.update_unencoded_base_hash(*fragment);
  }
  return url;
}

template url parse_url<url>(std::string_view user_input,
                            const url* base_url = nullptr);
template url_aggregator parse_url<url_aggregator>(
    std::string_view user_input, const url_aggregator* base_url = nullptr);

}  // namespace ada::parser

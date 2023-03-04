#include "ada.h"
#include "ada/character_sets-inl.h"
#include "ada/checkers-inl.h"
#include "ada/unicode.h"
#include "ada/url-inl.h"
#include "ada/log.h"

#include <iostream>
#include <limits>
#include <optional>
#include <string_view>

namespace ada::parser {

  template <class result_type>
  result_type parse_url(std::string_view user_input,
                        const ada::url* base_url,
                        ada::encoding_type encoding) {
    ada_log("ada::parser::parse_url('", user_input,
     "' [", user_input.size()," bytes],", (base_url != nullptr ? base_url->to_string() : "null"),
     ",", ada::to_string(encoding), ")");

    ada::state state = ada::state::SCHEME_START;
    result_type url{};

    // We refuse to parse URL strings that exceed 4GB. Such strings are almost
    // surely the result of a bug or are otherwise a security concern.
    if(user_input.size()  >= std::string_view::size_type(std::numeric_limits<uint32_t>::max)) { url.is_valid = false; }

    // If we are provided with an invalid base, or the optional_url was invalid,
    // we must return.
    if(base_url != nullptr) { url.is_valid &= base_url->is_valid; }
    if(!url.is_valid) { return url; }

    std::string tmp_buffer;
    std::string_view internal_input;
    if(unicode::has_tabs_or_newline(user_input)) {
      tmp_buffer = user_input;
      // Optimization opportunity: Instead of copying and then pruning, we could just directly
      // build the string from user_input.
      helpers::remove_ascii_tab_or_newline(tmp_buffer);
      internal_input = tmp_buffer;
    } else {
      internal_input = user_input;
    }

    // Leading and trailing control characters are uncommon and easy to deal with (no performance concern).
    std::string_view url_data = internal_input;
    helpers::trim_c0_whitespace(url_data);

    // Optimization opportunity. Most websites do not have fragment.
    std::optional<std::string_view> fragment = helpers::prune_fragment(url_data);
    if(fragment.has_value()) {
      url.fragment = unicode::percent_encode(*fragment,
                                             ada::character_sets::FRAGMENT_PERCENT_ENCODE);
    }

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
    while(input_position <= input_size) {
      switch (state) {
        case ada::state::SCHEME_START: {
          ada_log("SCHEME_START ", helpers::substring(url_data, input_position));
          // If c is an ASCII alpha, append c, lowercased, to buffer, and set state to scheme state.
          if ((input_position != input_size) && checkers::is_alpha(url_data[input_position])) {
            state = ada::state::SCHEME;
            input_position++;
          } else {
            // Otherwise, if state override is not given, set state to no scheme state and decrease pointer by 1.
            state = ada::state::NO_SCHEME;
          }
          break;
        }
        case ada::state::SCHEME: {
          ada_log("SCHEME ", helpers::substring(url_data, input_position));
          // If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.), append c, lowercased, to buffer.
          while((input_position != input_size) && (ada::unicode::is_alnum_plus(url_data[input_position]))) {
            input_position++;
          }
          // Otherwise, if c is U+003A (:), then:
          if ((input_position != input_size) && (url_data[input_position] == ':')) {
            ada_log("SCHEME the scheme should be ", url_data.substr(0,input_position));
            if(!url.parse_scheme(url_data.substr(0,input_position))) { return url; }
            ada_log("SCHEME the scheme is ", url.get_scheme());

            // If url’s scheme is "file", then:
            if (url.get_scheme_type() == ada::scheme::type::FILE) {
              // Set state to file state.
              state = ada::state::FILE;
            }
            // Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme:
            // Note: Doing base_url->scheme is unsafe if base_url != nullptr is false.
            else if (url.is_special() && base_url != nullptr && base_url->get_scheme_type() == url.get_scheme_type()) {
              // Set state to special relative or authority state.
              state = ada::state::SPECIAL_RELATIVE_OR_AUTHORITY;
            }
            // Otherwise, if url is special, set state to special authority slashes state.
            else if (url.is_special()) {
              state = ada::state::SPECIAL_AUTHORITY_SLASHES;
            }
            // Otherwise, if remaining starts with an U+002F (/), set state to path or authority state
            // and increase pointer by 1.
            else if (input_position + 1 < input_size && url_data[input_position + 1] == '/') {
              state = ada::state::PATH_OR_AUTHORITY;
              input_position++;
            }
            // Otherwise, set url’s path to the empty string and set state to opaque path state.
            else {
              state = ada::state::OPAQUE_PATH;
            }
          }
          // Otherwise, if state override is not given, set buffer to the empty string, state to no scheme state,
          // and start over (from the first code point in input).
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
          // If base is null, or base has an opaque path and c is not U+0023 (#), validation error, return failure.
          if (base_url == nullptr || (base_url->has_opaque_path && !fragment.has_value())) {
            ada_log("NO_SCHEME validation error");
            url.is_valid = false;
            return url;
          }
          // Otherwise, if base has an opaque path and c is U+0023 (#),
          // set url’s scheme to base’s scheme, url’s path to base’s path, url’s query to base’s query,
          // url’s fragment to the empty string, and set state to fragment state.
          else if (base_url->has_opaque_path && url.fragment.has_value() && input_position == input_size) {
            ada_log("NO_SCHEME opaque base with fragment");
            url.copy_scheme(*base_url);
            url.path = base_url->path;
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;
            return url;
          }
          // Otherwise, if base’s scheme is not "file", set state to relative state and decrease pointer by 1.
          else if (base_url->get_scheme_type() != ada::scheme::type::FILE) {
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
          // most URLs have no @. Having no @ tells us that we don't have to worry about AUTHORITY. Of course,
          // we could have @ and still not have to worry about AUTHORITY.
          // TODO: Instead of just collecting a bool, collect the location of the '@' and do something useful with it.
          // TODO: We could do various processing early on, using a single pass over the string to collect
          // information about it, e.g., telling us whether there is a @ and if so, where (or how many).
          const bool contains_ampersand = (url_data.find('@', input_position) != std::string_view::npos);

          if(!contains_ampersand) {
            state = ada::state::HOST;
            break;
          }
          bool at_sign_seen{false};
          bool password_token_seen{false};
          do {
            std::string_view view = helpers::substring(url_data, input_position);
            size_t location = url.is_special() ? helpers::find_authority_delimiter_special(view) : helpers::find_authority_delimiter(view);
            std::string_view authority_view(view.data(), location);
            size_t end_of_authority = input_position + authority_view.size();
            // If c is U+0040 (@), then:
            if ((end_of_authority != input_size) && (url_data[end_of_authority] == '@')) {
              // If atSignSeen is true, then prepend "%40" to buffer.
              if (at_sign_seen) {
                if (password_token_seen) {
                  url.password += "%40";
                } else {
                  url.username += "%40";
                }
              }

              at_sign_seen = true;

              if (!password_token_seen) {
                size_t password_token_location = authority_view.find(':');
                password_token_seen = password_token_location != std::string_view::npos;

                if (!password_token_seen) {
                  url.username += unicode::percent_encode(authority_view, character_sets::USERINFO_PERCENT_ENCODE);
                } else {
                  url.username += unicode::percent_encode(authority_view.substr(0,password_token_location), character_sets::USERINFO_PERCENT_ENCODE);
                  url.password += unicode::percent_encode(authority_view.substr(password_token_location+1), character_sets::USERINFO_PERCENT_ENCODE);
                }
              }
              else {
                url.password += unicode::percent_encode(authority_view, character_sets::USERINFO_PERCENT_ENCODE);
              }
            }
            // Otherwise, if one of the following is true:
            // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
            // - url is special and c is U+005C (\)
            else if (end_of_authority == input_size || url_data[end_of_authority] == '/' || url_data[end_of_authority] == '?' || (url.is_special() && url_data[end_of_authority] == '\\')) {
              // If atSignSeen is true and authority_view is the empty string, validation error, return failure.
              if (at_sign_seen && authority_view.empty()) {
                url.is_valid = false;
                return url;
              }
              state = ada::state::HOST;
              break;
            }
            if(end_of_authority == input_size) { return url; }
            input_position = end_of_authority + 1;
          } while(true);

          break;
        }
        case ada::state::SPECIAL_RELATIVE_OR_AUTHORITY: {
          ada_log("SPECIAL_RELATIVE_OR_AUTHORITY ", helpers::substring(url_data, input_position));

          // If c is U+002F (/) and remaining starts with U+002F (/),
          // then set state to special authority ignore slashes state and increase pointer by 1.
          std::string_view view  = helpers::substring(url_data, input_position);
          if (ada::checkers::begins_with(view, "//")) {
            state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
            input_position += 2;
          } else {
            // Otherwise, validation error, set state to relative state and decrease pointer by 1.
            state = ada::state::RELATIVE_SCHEME;
          }

          break;
        }
        case ada::state::PATH_OR_AUTHORITY: {
          ada_log("PATH_OR_AUTHORITY ", helpers::substring(url_data, input_position));

          // If c is U+002F (/), then set state to authority state.
          if ((input_position != input_size) && (url_data[input_position] == '/')) {
            state = ada::state::AUTHORITY;
            input_position++;
          } else {
            // Otherwise, set state to path state, and decrease pointer by 1.
            state = ada::state::PATH;
          }

          break;
        }
        case ada::state::RELATIVE_SCHEME: {
          ada_log("RELATIVE_SCHEME ", helpers::substring(url_data, input_position));

          // Set url’s scheme to base’s scheme.
          url.copy_scheme(*base_url);

          // If c is U+002F (/), then set state to relative slash state.
          if ((input_position != input_size) && (url_data[input_position] == '/')) {
            ada_log("RELATIVE_SCHEME if c is U+002F (/), then set state to relative slash state");
            state = ada::state::RELATIVE_SLASH;
          } else if (url.is_special() && (input_position != input_size) && (url_data[input_position] == '\\')) {
            // Otherwise, if url is special and c is U+005C (\), validation error, set state to relative slash state.
            ada_log("RELATIVE_SCHEME  if url is special and c is U+005C, validation error, set state to relative slash state");
            state = ada::state::RELATIVE_SLASH;
          } else {
            ada_log("RELATIVE_SCHEME otherwise");
            // Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host,
            // url’s port to base’s port, url’s path to a clone of base’s path, and url’s query to base’s query.
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            url.path = base_url->path;
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;

            // If c is U+003F (?), then set url’s query to the empty string, and state to query state.
            if ((input_position != input_size) && (url_data[input_position] == '?')) {
              state = ada::state::QUERY;
            }
            // Otherwise, if c is not the EOF code point:
            else if (input_position != input_size) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // Shorten url’s path.
              helpers::shorten_path(url.path, url.get_scheme_type());

              // Set state to path state and decrease pointer by 1.
              state = ada::state::PATH;
              break;
            }
          }
          input_position++;
          break;
        }
        case ada::state::RELATIVE_SLASH: {
          ada_log("RELATIVE_SLASH ", helpers::substring(url_data, input_position));

          // If url is special and c is U+002F (/) or U+005C (\), then:
          if (url.is_special() && (input_position != input_size) && (url_data[input_position] == '/' || url_data[input_position] =='\\')) {
            // Set state to special authority ignore slashes state.
            state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
          }
          // Otherwise, if c is U+002F (/), then set state to authority state.
          else if ((input_position != input_size) && (url_data[input_position] == '/')) {
            state = ada::state::AUTHORITY;
          }
          // Otherwise, set
          // - url’s username to base’s username,
          // - url’s password to base’s password,
          // - url’s host to base’s host,
          // - url’s port to base’s port,
          // - state to path state, and then, decrease pointer by 1.
          else {
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            state = ada::state::PATH;
            break;
          }

          input_position++;
          break;
        }
        case ada::state::SPECIAL_AUTHORITY_SLASHES: {
          ada_log("SPECIAL_AUTHORITY_SLASHES ", helpers::substring(url_data, input_position));

          // If c is U+002F (/) and remaining starts with U+002F (/),
          // then set state to special authority ignore slashes state and increase pointer by 1.
          state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
          std::string_view view = helpers::substring(url_data, input_position);
          if (ada::checkers::begins_with(view, "//")) {
            input_position += 2;
          }

          [[fallthrough]];
        }
        case ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES: {
          ada_log("SPECIAL_AUTHORITY_IGNORE_SLASHES ", helpers::substring(url_data, input_position));

          // If c is neither U+002F (/) nor U+005C (\), then set state to authority state and decrease pointer by 1.
          while ((input_position != input_size) && ((url_data[input_position] == '/') || (url_data[input_position] == '\\'))) {
            input_position++;
          }
          state = ada::state::AUTHORITY;

          break;
        }
        case ada::state::QUERY: {
          ada_log("QUERY ", helpers::substring(url_data, input_position));
          // If encoding is not UTF-8 and one of the following is true:
          // - url is not special
          // - url’s scheme is "ws" or "wss"
          if (encoding != ada::encoding_type::UTF8) {
            if (!url.is_special() || url.get_scheme_type() == ada::scheme::type::WS || url.get_scheme_type() == ada::scheme::type::WSS) {
              // then set encoding to UTF-8.
              encoding = ada::encoding_type::UTF8;
            }
          }
          // Let queryPercentEncodeSet be the special-query percent-encode set if url is special;
          // otherwise the query percent-encode set.
          auto query_percent_encode_set = url.is_special() ?
                                ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
                                ada::character_sets::QUERY_PERCENT_ENCODE;

          // Percent-encode after encoding, with encoding, buffer, and queryPercentEncodeSet,
          // and append the result to url’s query.
          url.query = ada::unicode::percent_encode(helpers::substring(url_data, input_position), query_percent_encode_set);

          return url;
        }
        case ada::state::HOST: {
          ada_log("HOST ", helpers::substring(url_data, input_position));

          std::string_view host_view = helpers::substring(url_data, input_position);
          auto [location, found_colon] = helpers::get_host_delimiter_location(url.is_special(), host_view);
          input_position = (location != std::string_view::npos) ? input_position + location : input_size;
          // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
          // Note: the 'found_colon' value is true if and only if a colon was encountered
          // while not inside brackets.
          if (found_colon) {
            // If buffer is the empty string, validation error, return failure.
            // Let host be the result of host parsing buffer with url is not special.
            ada_log("HOST parsing ", host_view);
            if(!url.parse_host(host_view)) { return url; }
            ada_log("HOST parsing results in ", url.host.has_value() ? "none" : url.host.value());
            // Set url’s host to host, buffer to the empty string, and state to port state.
            state = ada::state::PORT;
            input_position++;
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          // The get_host_delimiter_location function either brings us to
          // the colon outside of the bracket, or to one of those characters.
          else {

            // If url is special and host_view is the empty string, validation error, return failure.
            if (url.is_special() && host_view.empty()) {
              url.is_valid = false;
              return url;
            }

            // Let host be the result of host parsing host_view with url is not special.
            if (host_view.empty()) {
              url.host = "";
            } else {
              if(!url.parse_host(host_view)) { return url; }
            }
            // Set url’s host to host, and state to path start state.
            state = ada::state::PATH_START;
          }

          break;
        }
        case ada::state::OPAQUE_PATH: {
          ada_log("OPAQUE_PATH ", helpers::substring(url_data, input_position));
          std::string_view view = helpers::substring(url_data, input_position);
          // If c is U+003F (?), then set url’s query to the empty string and state to query state.
          size_t location = view.find('?');
          if(location != std::string_view::npos) {
            view.remove_suffix(view.size() - location);
            state = ada::state::QUERY;
            input_position += location + 1;
          } else {
            input_position = input_size + 1;
          }
          url.has_opaque_path = true;
          url.path = unicode::percent_encode(view, character_sets::C0_CONTROL_PERCENT_ENCODE);
          break;
        }
        case ada::state::PORT: {
          ada_log("PORT ", helpers::substring(url_data, input_position));
          std::string_view port_view = helpers::substring(url_data, input_position);
          size_t consumed_bytes = url.parse_port(port_view, true);
          input_position += consumed_bytes;
          if(!url.is_valid) { return url; }
          state = state::PATH_START;
          [[fallthrough]];
        }
        case ada::state::PATH_START: {
          ada_log("PATH_START ", helpers::substring(url_data, input_position));

          // If url is special, then:
          if (url.is_special()) {
            // Set state to path state.
            state = ada::state::PATH;

            // Optimization: Avoiding going into PATH state improves the performance of urls ending with /.
            if (input_position == input_size) {
              url.path = "/";
              return url;
            }
            // If c is neither U+002F (/) nor U+005C (\), then decrease pointer by 1.
            // We know that (input_position == input_size) is impossible here, because of the previous if-check.
            if ((url_data[input_position] != '/') && (url_data[input_position] != '\\')) {
              break;
            }
          }
          // Otherwise, if state override is not given and c is U+003F (?),
          // set url’s query to the empty string and state to query state.
          else if ((input_position != input_size) && (url_data[input_position] == '?')) {
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
          if(locofquestionmark != std::string_view::npos) {
            state = ada::state::QUERY;
            view.remove_suffix(view.size()-locofquestionmark);
            input_position += locofquestionmark + 1;
          } else {
            input_position = input_size + 1;
          }
          if(!helpers::parse_prepared_path(view, url.get_scheme_type(), url.path)) { return url; }
          break;
        }
        case ada::state::FILE_SLASH: {
          ada_log("FILE_SLASH ", helpers::substring(url_data, input_position));

          // If c is U+002F (/) or U+005C (\), then:
          if ((input_position != input_size) && (url_data[input_position] == '/' || url_data[input_position] == '\\')) {
            ada_log("FILE_SLASH c is U+002F or U+005C");
            // Set state to file host state.
            state = ada::state::FILE_HOST;
            input_position++;
          } else {
            ada_log("FILE_SLASH otherwise");
            // If base is non-null and base’s scheme is "file", then:
            // Note: it is unsafe to do base_url->scheme unless you know that
            // base_url_has_value() is true.
            if (base_url != nullptr && base_url->get_scheme_type() == ada::scheme::type::FILE) {
              // Set url’s host to base’s host.
              url.host = base_url->host;

              // If the code point substring from pointer to the end of input does not start with
              // a Windows drive letter and base’s path[0] is a normalized Windows drive letter,
              // then append base’s path[0] to url’s path.
              if (!base_url->path.empty()) {
                if (!checkers::is_windows_drive_letter(helpers::substring(url_data, input_position))) {
                  std::string_view first_base_url_path = base_url->path;
                  first_base_url_path.remove_prefix(1);
                  size_t loc = first_base_url_path.find('/');
                  if(loc != std::string_view::npos) {
                    first_base_url_path.remove_suffix(first_base_url_path.size() - loc);
                  }
                  if (checkers::is_normalized_windows_drive_letter(first_base_url_path)) {
                    url.path += '/';
                    url.path += first_base_url_path;
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
          std::string_view file_host_buffer(view.data(), (location != std::string_view::npos) ? location : view.size());

          if (checkers::is_windows_drive_letter(file_host_buffer)) {
            state = ada::state::PATH;
          } else if (file_host_buffer.empty()) {
            // Set url’s host to the empty string.
            url.host = "";
            // Set state to path start state.
            state = ada::state::PATH_START;
          } else {
            size_t consumed_bytes = file_host_buffer.size();
            input_position += consumed_bytes;
            // Let host be the result of host parsing buffer with url is not special.
            if(!url.parse_host(file_host_buffer)) { return url; }

            // If host is "localhost", then set host to the empty string.
            if (url.host.has_value() && url.host.value() == "localhost") {
              url.host = "";
            }

            // Set buffer to the empty string and state to path start state.
            state = ada::state::PATH_START;
          }

          break;
        }
        case ada::state::FILE: {
          ada_log("FILE ", helpers::substring(url_data, input_position));
          std::string_view file_view = helpers::substring(url_data, input_position);

          // Set url’s scheme to "file".
          url.set_scheme("file");

          // Set url’s host to the empty string.
          url.host = "";

          // If c is U+002F (/) or U+005C (\), then:
          if (input_position != input_size && (url_data[input_position] == '/' || url_data[input_position] == '\\')) {
            ada_log("FILE c is U+002F or U+005C");
            // Set state to file slash state.
            state = ada::state::FILE_SLASH;
          }
          // Otherwise, if base is non-null and base’s scheme is "file":
          else if (base_url != nullptr && base_url->get_scheme_type() == ada::scheme::type::FILE) {
            // Set url’s host to base’s host, url’s path to a clone of base’s path, and url’s query to base’s query.
            ada_log("FILE base non-null");
            url.host = base_url->host;
            url.path = base_url->path;
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;

            // If c is U+003F (?), then set url’s query to the empty string and state to query state.
            if (input_position != input_size && url_data[input_position] == '?') {
              state = ada::state::QUERY;
            }
            // Otherwise, if c is not the EOF code point:
            else if (input_position != input_size) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // If the code point substring from pointer to the end of input does not start with a
              // Windows drive letter, then shorten url’s path.
              if (!checkers::is_windows_drive_letter(file_view)) {
                helpers::shorten_path(url.path, url.get_scheme_type());
              }
              // Otherwise:
              else {
                // Set url’s path to an empty list.
                url.path.clear();
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
    ada_log("returning ", url.to_string());
    return url;
  }

} // namespace ada::parser

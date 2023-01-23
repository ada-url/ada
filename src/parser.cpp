#include "ada.h"
#include "ada/character_sets.h"
#include "ada/checkers.h"
#include "ada/unicode.h"
#include "ada/url.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <numeric>

#include <optional>
#include <string_view>

namespace ada::parser {

  url parse_url(std::string_view user_input,
                std::optional<ada::url> base_url,
                ada::encoding_type encoding,
                std::optional<ada::url> optional_url) {
    // Let state be state override if given, or scheme start state otherwise.
    ada::state state = ada::state::SCHEME_START;

    /**
     * Design concern: We take an optional_url as a parameter. Yet optional_url
     * is only ever used on the next line.
     */

    // If we have anything in optional_url, then it was copied there.
    // As much as possible, we do not want relatively expensive constructor in our
    // main function (parse_url).
    ada::url url = optional_url.has_value() ? std::move(optional_url.value()) : ada::url();
    // From this point forward, optional_url should not be used.

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

    // @todo Find a better way to trim from leading and trailing.
    std::string_view::iterator pointer_start = std::find_if_not(internal_input.begin(), internal_input.end(), ada::unicode::is_c0_control_or_space);
    if (pointer_start == internal_input.end()) { pointer_start = internal_input.begin(); }
    std::string_view::iterator pointer_end = std::find_if_not(internal_input.rbegin(), std::make_reverse_iterator(pointer_start), ada::unicode::is_c0_control_or_space).base();

    std::string_view url_data(&*pointer_start, pointer_end - pointer_start);

    // Optimization opportunity. Most websites does not have fragment.
    std::optional<std::string_view> fragment = helpers::prune_fragment(url_data);
    if(fragment.has_value()) {
      url.fragment = unicode::percent_encode(*fragment,
                                             ada::character_sets::FRAGMENT_PERCENT_ENCODE);
    }

    // Here url_data no longer has its fragment.
    // The rest of the code might work with std::string_view, not pointers, it would
    // be easier to follow. But because we don't want to change everything, let us
    // bring back the pointers.
    pointer_start = url_data.begin();
    pointer_end = url_data.end();

    // Let pointer be a pointer for input.
    std::string_view::iterator pointer = pointer_start;
    // Keep running the following state machine by switching on state.
    // If after a run pointer points to the EOF code point, go to the next step.
    // Otherwise, increase pointer by 1 and continue with the state machine.
    for (; pointer <= pointer_end; pointer++) {
      ///////////////////////////////////////////////////////////////////////
      // Important: we can't have 'pointer == pointer_end' and then dereference
      // the pointer so the loop condition pointer <= pointer_end is a problem.
      //
      // The terrible thing is that dereferencing a pointer that is out of
      // range may work in practice, maybe almost always, and then we
      // end up with a random non-reproducible crash or bug.
      ///////////////////////////////////////////////////////////////////////
      switch (state) {
        case ada::state::SCHEME_START: {
          // If c is an ASCII alpha, append c, lowercased, to buffer, and set state to scheme state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && checkers::is_alpha(*pointer)) {
            state = ada::state::SCHEME;
            goto goto_scheme;
          }
          // Otherwise, if state override is not given, set state to no scheme state and decrease pointer by 1.
          else {
            state = ada::state::NO_SCHEME;
            goto goto_no_scheme;;
          }

          break;
        }
        case ada::state::SCHEME: {
          goto_scheme:
          // If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.), append c, lowercased, to buffer.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          pointer = std::find_if_not(pointer, pointer_end, ada::unicode::is_alnum_plus);

          // Otherwise, if c is U+003A (:), then:
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == ':')) {
            url.parse_scheme(std::string_view(&*pointer_start, pointer - pointer_start));
            // If url’s scheme is "file", then:
            if (url.get_scheme_type() == ada::scheme::type::FILE) {
              // Set state to file state.
              state = ada::state::FILE;
            }
            // Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme:
            // Note: Doing base_url->scheme is unsafe if base_url.has_value() is false.
            else if (url.is_special() && base_url.has_value() && base_url->get_scheme_type() == url.get_scheme_type()) {
              // Set state to special relative or authority state.
              state = ada::state::SPECIAL_RELATIVE_OR_AUTHORITY;
            }
            // Otherwise, if url is special, set state to special authority slashes state.
            else if (url.is_special()) {
              state = ada::state::SPECIAL_AUTHORITY_SLASHES;
            }
            // Otherwise, if remaining starts with an U+002F (/), set state to path or authority state
            // and increase pointer by 1.
            else if (std::distance(pointer, pointer_end) > 0 && pointer[1] == '/') {
              state = ada::state::PATH_OR_AUTHORITY;
              pointer++;
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
            pointer = pointer_start;
            goto goto_no_scheme;
          }

          break;
        }
        case ada::state::NO_SCHEME: {
          goto_no_scheme:
          // If base is null, or base has an opaque path and c is not U+0023 (#), validation error, return failure.
          if (!base_url.has_value() || (base_url->has_opaque_path && (pointer != pointer_end))) {
            url.is_valid = false;
            return url;
          }
          // Otherwise, if base has an opaque path and c is U+0023 (#),
          // set url’s scheme to base’s scheme, url’s path to base’s path, url’s query to base’s query,
          // url’s fragment to the empty string, and set state to fragment state.
          else if (base_url->has_opaque_path && url.fragment.has_value() && pointer == pointer_end) {
            url.copy_scheme(base_url.value());
            url.path = base_url->path;
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;
            return url;
          }
          // Otherwise, if base’s scheme is not "file", set state to relative state and decrease pointer by 1.
          else if (base_url->get_scheme_type() != ada::scheme::type::FILE) {
            state = ada::state::RELATIVE_SCHEME;
            goto goto_relative_scheme;
          }
          // Otherwise, set state to file state and decrease pointer by 1.
          else {
            state = ada::state::FILE;
            goto goto_file;
          }

          break;
        }
        case ada::state::AUTHORITY: {
          goto_authority:
          // most URLs have no @. Having no @ tells us that we don't have to worry about AUTHORITY. Of course,
          // we could have @ and still not have to worry about AUTHORITY.
          // TODO: Instead of just collecting a bool, collect the location of the '@' and do something useful with it.
          // TODO: We could do various processing early on, using a single pass over the string to collect
          // information about it, e.g., telling us whether there is a @ and if so, where (or how many).
          const bool contains_ampersand = (std::find(pointer, pointer_end, '@') != pointer_end);

          if(!contains_ampersand) {
            // TODO: This is a waste of time, we should never have arrived here.
            state = ada::state::HOST;
            goto goto_host;
          }
          bool at_sign_seen{false};
          bool password_token_seen{false};
          do {
            std::string_view view(&*pointer, size_t(pointer_end-pointer));
            size_t location = url.is_special() ? view.find_first_of("@/?\\") : view.find_first_of("@/?");
            std::string_view authority_view(view.data(), (location != std::string_view::npos) ? location : view.size());
            pointer = (location == std::string_view::npos) ? pointer_end : pointer + location;

            // If c is U+0040 (@), then:
            // Note: we cannot access *pointer safely if (pointer == pointer_end).
            if ((pointer != pointer_end) && (*pointer == '@')) {
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
                  url.username += unicode::percent_encode(std::string_view(&*authority_view.begin(), password_token_location), character_sets::USERINFO_PERCENT_ENCODE);
                  url.password += unicode::percent_encode(std::string_view(&*authority_view.begin() + password_token_location + 1, size_t(authority_view.length() - password_token_location - 1)), character_sets::USERINFO_PERCENT_ENCODE);
                }
              }
              else {
                url.password += unicode::percent_encode(authority_view, character_sets::USERINFO_PERCENT_ENCODE);
              }
            }
            // Otherwise, if one of the following is true:
            // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
            // - url is special and c is U+005C (\)
            else if (pointer == pointer_end || *pointer == '/' || *pointer == '?' || (url.is_special() && *pointer == '\\')) {
              // If atSignSeen is true and authority_view is the empty string, validation error, return failure.
              if (at_sign_seen && authority_view.empty()) {
                url.is_valid = false;
                return url;
              }
              // Decrease pointer by the number of code points in buffer plus one,
              // set buffer to the empty string, and set state to host state.
              pointer -= authority_view.length() + 1;
              state = ada::state::HOST;
              break;
            }

            if(pointer == pointer_end) { break; }
            pointer++;
          } while(true);

          break;
        }
        case ada::state::SPECIAL_RELATIVE_OR_AUTHORITY: {
          // If c is U+002F (/) and remaining starts with U+002F (/),
          // then set state to special authority ignore slashes state and increase pointer by 1.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          std::string_view view (&*pointer, size_t(pointer_end-pointer));
          if (ada::checkers::begins_with(view, "//")) {
            state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
            pointer++;
          }
          // Otherwise, validation error, set state to relative state and decrease pointer by 1.
          else {
            state = ada::state::RELATIVE_SCHEME;
            goto goto_relative_scheme;
          }

          break;
        }
        case ada::state::PATH_OR_AUTHORITY: {
          // If c is U+002F (/), then set state to authority state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == '/')) {
            state = ada::state::AUTHORITY;
          }
          // Otherwise, set state to path state, and decrease pointer by 1.
          else {
            state = ada::state::PATH;
            goto goto_path;
          }

          break;
        }
        case ada::state::RELATIVE_SCHEME: {
          goto_relative_scheme:
          // Set url’s scheme to base’s scheme.
#if ADA_DEVELOP_MODE
          ///////
          // next line is for development purposes, to ensure safety.
          ///////
          if(!base_url.has_value()) { throw std::runtime_error("Internal error.\n"); }
#endif
          url.copy_scheme(base_url.value());

          // If c is U+002F (/), then set state to relative slash state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == '/')) {
            state = ada::state::RELATIVE_SLASH;
          }
          // Otherwise, if url is special and c is U+005C (\), validation error, set state to relative slash state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          else if (url.is_special() && (pointer != pointer_end) && (*pointer == '\\')) {
            state = ada::state::RELATIVE_SLASH;
          }
          // Otherwise:
          else {
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
            if (*pointer == '?') {
              url.query = "";
              state = ada::state::QUERY;
            }
            // Otherwise, if c is not the EOF code point:
            else if (pointer != pointer_end) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // Shorten url’s path.
              helpers::shorten_path(url);

              // Set state to path state and decrease pointer by 1.
              state = ada::state::PATH;
              goto goto_path;
            }
          }

          break;
        }
        case ada::state::RELATIVE_SLASH: {
          // If url is special and c is U+002F (/) or U+005C (\), then:
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if (url.is_special() && (pointer != pointer_end) && (*pointer == '/' || *pointer =='\\')) {
            // Set state to special authority ignore slashes state.
            state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
          }
          // Otherwise, if c is U+002F (/), then set state to authority state.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          else if ((pointer != pointer_end) && (*pointer == '/')) {
            state = ada::state::AUTHORITY;
          }
          // Otherwise, set
          // - url’s username to base’s username,
          // - url’s password to base’s password,
          // - url’s host to base’s host,
          // - url’s port to base’s port,
          // - state to path state, and then, decrease pointer by 1.
          else {
#if ADA_DEVELOP_MODE
            //////////
            ///// For development purposes, to ensure safey:
            /////////////
            if(!base_url.has_value()) { throw std::runtime_error("Internal error.\n"); }
#endif
            url.username = base_url->username;
            url.password = base_url->password;
            url.host = base_url->host;
            url.port = base_url->port;
            state = ada::state::PATH;
            goto goto_path;
          }

          break;
        }
        case ada::state::SPECIAL_AUTHORITY_SLASHES: {
          // If c is U+002F (/) and remaining starts with U+002F (/),
          // then set state to special authority ignore slashes state and increase pointer by 1.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          state = ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES;
          std::string_view view (&*pointer, size_t(pointer_end-pointer));
          if (ada::checkers::begins_with(view, "//")) {
            pointer++;
          }
          // Otherwise, validation error, set state to special authority ignore slashes state and decrease pointer by 1.
          else {
            goto goto_special_authority_ignore_slashes;
          }


          break; /** Here we should just fall through !!! */
        }
        case ada::state::SPECIAL_AUTHORITY_IGNORE_SLASHES: {
          goto_special_authority_ignore_slashes:
          // If c is neither U+002F (/) nor U+005C (\), then set state to authority state and decrease pointer by 1.
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          while(true) {
            if ((pointer == pointer_end) || ((*pointer != '/') && (*pointer != '\\'))) {
              state = ada::state::AUTHORITY;
              goto goto_authority;
            }
            pointer++;
          }

          break;
        }
        case ada::state::QUERY: {
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
          url.query = ada::unicode::percent_encode(std::string_view(&*pointer, pointer_end-pointer), query_percent_encode_set);

          return url;
        }
        case ada::state::HOST: {
          goto_host:
          std::string_view host_view(&*pointer, pointer_end - pointer);
          bool inside_brackets{false};
          size_t location = helpers::get_host_delimiter_location(url, host_view, inside_brackets);
          pointer = (location != std::string_view::npos) ? pointer + location : pointer_end;

          // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
          // Note: we cannot access *pointer safely if (pointer == pointer_end).
          if ((pointer != pointer_end) && (*pointer == ':') && !inside_brackets) {
            // If buffer is the empty string, validation error, return failure.
            // Let host be the result of host parsing buffer with url is not special.
            url.parse_host(host_view);

            // Set url’s host to host, buffer to the empty string, and state to port state.
            state = ada::state::PORT;
          }
          // Otherwise, if one of the following is true:
          // - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
          // - url is special and c is U+005C (\)
          else if (pointer == pointer_end || *pointer == '/' || *pointer == '?' || (url.is_special() && *pointer == '\\')) {
            // then decrease pointer by 1, and then:
            // pointer--;

            // If url is special and host_view is the empty string, validation error, return failure.
            if (url.is_special() && host_view.empty()) {
              url.is_valid = false;
              return url;
            }

            // Let host be the result of host parsing host_view with url is not special.
            if (host_view.empty()) {
              url.host = "";
            } else {
              url.parse_host(host_view);
            }

            // Set url’s host to host, and state to path start state.
            state = ada::state::PATH_START;
            goto goto_path_start;
          }
          break;
        }
        case ada::state::OPAQUE_PATH: {
          // If c is U+003F (?), then set url’s query to the empty string and state to query state.
          std::string_view view(&*pointer, size_t(pointer_end-pointer));
          size_t location = view.find('?');
          if(location != std::string_view::npos) {
            view.remove_suffix(location);
            state = ada::state::QUERY;
            pointer += location;
          } else {
            // TODO: we can probably just exit here.
            pointer = pointer_end;
          }
          url.has_opaque_path = true;
          url.path = unicode::percent_encode(view, character_sets::C0_CONTROL_PERCENT_ENCODE);
          break;
        }
        case ada::state::PORT: {
          pointer += url.parse_port(std::string_view(&*pointer, size_t(pointer_end-pointer)));
          if(!url.is_valid) { return url; }
          pointer_start--;
          state = ada::state::PATH_START;
          break;
        }
        case ada::state::PATH_START: {
          goto_path_start:
          // If url is special, then:
          if (url.is_special()) {

            // Set state to path state.
            state = ada::state::PATH;

            // Optimization: Avoiding going into PATH state improves the performance of urls ending with /.
            if (pointer == pointer_end) {
              url.path = "/";
              return url;
            }
            // If c is neither U+002F (/) nor U+005C (\), then decrease pointer by 1.
            if ((pointer == pointer_end) || ((*pointer != '/') && (*pointer != '\\'))) {
              goto goto_path;
            }

          }
          // Otherwise, if state override is not given and c is U+003F (?),
          // set url’s query to the empty string and state to query state.
          else if (*pointer == '?') {
            state = ada::state::QUERY;
          }
          // Otherwise, if c is not the EOF code point:
          else if (pointer != pointer_end) {
            // Set state to path state.
            state = ada::state::PATH;

            // If c is not U+002F (/), then decrease pointer by 1.
            if (*pointer != '/') {
              goto goto_path;
            }
          }

          break;
        }
        case ada::state::PATH: {
          goto_path:
          // Most time, we do not need percent encoding.
          // Furthermore, we can immediately locate the '?'.
          std::string_view view(&*pointer, size_t(pointer_end-pointer));
          size_t locofquestionmark = view.find('?');
          auto end_of_path = (locofquestionmark != std::string_view::npos) ? pointer + locofquestionmark: pointer_end;
          if(end_of_path != pointer_end) {
            state = ada::state::QUERY;
            view.remove_suffix(pointer_end-end_of_path);
          }
          url.parse_prepared_path(view);
          pointer = end_of_path;
          break;
        }
        case ada::state::FILE_SLASH: {
          // If c is U+002F (/) or U+005C (\), then:
          if (*pointer == '/' || *pointer == '\\') {
            // Set state to file host state.
            state = ada::state::FILE_HOST;
          }
          // Otherwise:
          else {
            // If base is non-null and base’s scheme is "file", then:
            // Note: it is unsafe to do base_url->scheme unless you know that
            // base_url_has_value() is true.
            if (base_url.has_value() && base_url.has_value() && base_url->get_scheme_type() == ada::scheme::type::FILE) {
              // Set url’s host to base’s host.
              url.host = base_url->host;

              // If the code point substring from pointer to the end of input does not start with
              // a Windows drive letter and base’s path[0] is a normalized Windows drive letter,
              // then append base’s path[0] to url’s path.
              if (std::distance(pointer, pointer_end) > 0 && !base_url->path.empty()) {
                if (!checkers::is_windows_drive_letter({&*pointer, size_t(pointer_end - pointer)})) {
                  std::string first_base_url_path = base_url->path.substr(1, base_url->path.find_first_of('/', 1));

                  // Optimization opportunity: Get rid of initializing a std::string
                  if (checkers::is_normalized_windows_drive_letter(first_base_url_path)) {
                    url.path += '/';
                    url.path += first_base_url_path;
                  }
                }
              }
            }

            // Set state to path state, and decrease pointer by 1.
            state = ada::state::PATH;
            goto goto_path;
          }

          break;
        }
        case ada::state::FILE_HOST: {
          std::string_view view(&*pointer, size_t(pointer_end-pointer));
          size_t location = view.find_first_of("/\\?");
          std::string_view file_host_buffer(view.data(), (location != std::string_view::npos) ? location : view.size());
          pointer += location - 1;

          if (checkers::is_windows_drive_letter(file_host_buffer)) {
            state = ada::state::PATH;
          }
          else if (file_host_buffer.empty()) {
            // Set url’s host to the empty string.
            url.host = "";

            // Set state to path start state.
            state = ada::state::PATH_START;
          }
          else {
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
          goto_file:
          // Set url’s scheme to "file".
          url.set_scheme("file");

          // Set url’s host to the empty string.
          url.host = "";

          // If c is U+002F (/) or U+005C (\), then:
          if (*pointer == '/' || *pointer == '\\') {
            // Set state to file slash state.
            state = ada::state::FILE_SLASH;
          }
          // Otherwise, if base is non-null and base’s scheme is "file":
          else if (base_url.has_value() && base_url->get_scheme_type() == ada::scheme::type::FILE) {
            // Set url’s host to base’s host, url’s path to a clone of base’s path, and url’s query to base’s query.
            url.host = base_url->host;
            url.path = base_url->path;
            url.has_opaque_path = base_url->has_opaque_path;
            url.query = base_url->query;

            // If c is U+003F (?), then set url’s query to the empty string and state to query state.
            if (*pointer == '?') {
              state = ada::state::QUERY;
            }
            // Otherwise, if c is not the EOF code point:
            else if (pointer != pointer_end) {
              // Set url’s query to null.
              url.query = std::nullopt;

              // If the code point substring from pointer to the end of input does not start with a
              // Windows drive letter, then shorten url’s path.
              if (std::distance(pointer, pointer_end) >= 2 && !checkers::is_windows_drive_letter(std::string_view(&*pointer, 2))) {
                helpers::shorten_path(url);
              }
              // Otherwise:
              else {
                // Set url’s path to an empty list.
                url.path = "";
                url.has_opaque_path = true;
              }

              // Set state to path state and decrease pointer by 1.
              state = ada::state::PATH;
              goto goto_path;
            }
          }
          // Otherwise, set state to path state, and decrease pointer by 1.
          else {
            state = ada::state::PATH;
            goto goto_path;
          }

          break;
        }
        default:
          ada::unreachable();
      }
    }

    return url;
  }

} // namespace ada::parser

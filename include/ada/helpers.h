/**
 * @file helpers.h
 * @brief Definitions for helper functions used within Ada.
 */
#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include "ada/common_defs.h"
#include "ada/url.h"
#include "ada/state.h"

#include <string_view>
#include <optional>

namespace ada::helpers {

  /**
   * This function is used to prune a fragment from a url, and returning the removed string if input has fragment.
   *
   * @details prune_fragment seeks the first '#' and returns everything after it as a
   * string_view, and modifies (in place) the input so that it points at everything
   * before the '#'. If no '#' is found, the input is left unchanged and std::nullopt is returned.
   *
   * @attention The function is non-allocating and it does not throw.
   * @returns Note that the returned string_view might be empty!
   */
  ada_really_inline std::optional<std::string_view> prune_fragment(std::string_view& input) noexcept;

  /**
   * Defined by the URL specification, shorten a URLs paths.
   * @see https://url.spec.whatwg.org/#shorten-a-urls-path
   */
  ada_really_inline void shorten_path(std::string& path, ada::scheme::type type) noexcept;


 /**
  * @private
  *
  * Parse the path from the provided input and append to the existing
  * (possibly empty) path. The input cannot contain tabs and spaces: it
  * is the user's responsibility to check.
  *
  * The input is expected to be UTF-8.
  *
  * @return true on success.
  * @see https://url.spec.whatwg.org/
  */
  ada_really_inline bool parse_prepared_path(const std::string_view input, ada::scheme::type type, std::string& path);

  /**
   * Remove and mutate all ASCII tab or newline characters from an input.
   */
  ada_really_inline void remove_ascii_tab_or_newline(std::string& input) noexcept;

  /**
   * Return the substring from input going from index pos to the end. If pos > input.size(),
   * it returns an empty string_view. This function cannot throw.
   */
  ada_really_inline std::string_view substring(std::string_view input, size_t pos) noexcept;

  /**
   * Returns a host's delimiter location depending on the state of the instance.
   * Used by the host parser.
   */
  ada_really_inline size_t get_host_delimiter_location(const ada::url& url, std::string_view& view, bool& inside_brackets) noexcept;

  /**
   * Removes leading and trailing C0 control and whitespace characters from string.
   */
  ada_really_inline void trim_c0_whitespace(std::string_view& input) noexcept;

} // namespace ada::helpers

#endif // ADA_HELPERS_H

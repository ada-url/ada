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
  ada_really_inline void shorten_path(ada::url &url) noexcept;

  /**
   * Remove and mutate all ASCII tab or newline characters from an input.
   */
  ada_really_inline void remove_ascii_tab_or_newline(std::string& input) noexcept;

  /**
   * Returns a host's delimiter location depending on the state of the instance.
   * Used by the host parser.
   */
  ada_really_inline size_t get_host_delimiter_location(const ada::url& url, std::string_view& view, bool& inside_brackets) noexcept;

} // namespace ada::helpers

#endif // ADA_HELPERS_H

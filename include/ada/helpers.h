/**
 * @file helpers.h
 * @brief Definitions for helper functions used within Ada.
 */
#ifndef ADA_HELPERS_H
#define ADA_HELPERS_H

#include "ada/common_defs.h"
#include "ada/state.h"
#include "ada/url_base.h"

#include <string_view>
#include <optional>

/**
 * These functions are not part of our public API and may
 * change at any time.
 *
 * @private
 * @namespace ada::helpers
 * @brief Includes the definitions for helper functions
 */
namespace ada::helpers {

/**
 * @private
 */
template <typename out_iter>
void encode_json(std::string_view view, out_iter out);

/**
 * @private
 * This function is used to prune a fragment from a url, and returning the
 * removed string if input has fragment.
 *
 * @details prune_hash seeks the first '#' and returns everything after it
 * as a string_view, and modifies (in place) the input so that it points at
 * everything before the '#'. If no '#' is found, the input is left unchanged
 * and std::nullopt is returned.
 *
 * @attention The function is non-allocating and it does not throw.
 * @returns Note that the returned string_view might be empty!
 */
ada_really_inline std::optional<std::string_view> prune_hash(
    std::string_view& input) noexcept;

/**
 * @private
 * Defined by the URL specification, shorten a URLs paths.
 * @see https://url.spec.whatwg.org/#shorten-a-urls-path
 * @returns Returns true if path is shortened.
 */
ada_really_inline bool shorten_path(std::string& path,
                                    ada::scheme::type type) noexcept;

/**
 * @private
 * Defined by the URL specification, shorten a URLs paths.
 * @see https://url.spec.whatwg.org/#shorten-a-urls-path
 * @returns Returns true if path is shortened.
 */
ada_really_inline bool shorten_path(std::string_view& path,
                                    ada::scheme::type type) noexcept;

/**
 * @private
 *
 * Parse the path from the provided input and append to the existing
 * (possibly empty) path. The input cannot contain tabs and spaces: it
 * is the user's responsibility to check.
 *
 * The input is expected to be UTF-8.
 *
 * @see https://url.spec.whatwg.org/
 */
ada_really_inline void parse_prepared_path(std::string_view input,
                                           ada::scheme::type type,
                                           std::string& path);

/**
 * @private
 * Remove and mutate all ASCII tab or newline characters from an input.
 */
ada_really_inline void remove_ascii_tab_or_newline(std::string& input) noexcept;

/**
 * @private
 * Return the substring from input going from index pos to the end.
 * This function cannot throw.
 */
ada_really_inline std::string_view substring(std::string_view input,
                                             size_t pos) noexcept;

/**
 * @private
 * Returns true if the string_view points within the string.
 */
bool overlaps(std::string_view input1, const std::string& input2) noexcept;

/**
 * @private
 * Return the substring from input going from index pos1 to the pos2 (non
 * included). The length of the substring is pos2 - pos1.
 */
ada_really_inline std::string_view substring(const std::string& input,
                                             size_t pos1,
                                             size_t pos2) noexcept {
#if ADA_DEVELOPMENT_CHECKS
  if (pos2 < pos1) {
    std::cerr << "Negative-length substring: [" << pos1 << " to " << pos2 << ")"
              << std::endl;
    abort();
  }
#endif
  return std::string_view(input.data() + pos1, pos2 - pos1);
}

/**
 * @private
 * Modify the string_view so that it has the new size pos, assuming that pos <=
 * input.size(). This function cannot throw.
 */
ada_really_inline void resize(std::string_view& input, size_t pos) noexcept;

/**
 * @private
 * Returns a host's delimiter location depending on the state of the instance,
 * and whether a colon was found outside brackets. Used by the host parser.
 */
ada_really_inline std::pair<size_t, bool> get_host_delimiter_location(
    const bool is_special, std::string_view& view) noexcept;

/**
 * @private
 * Removes leading and trailing C0 control and whitespace characters from
 * string.
 */
ada_really_inline void trim_c0_whitespace(std::string_view& input) noexcept;

/**
 * @private
 * @see
 * https://url.spec.whatwg.org/#potentially-strip-trailing-spaces-from-an-opaque-path
 */
template <class url_type>
ada_really_inline void strip_trailing_spaces_from_opaque_path(
    url_type& url) noexcept;

/**
 * @private
 * Finds the delimiter of a view in authority state.
 */
ada_really_inline size_t
find_authority_delimiter_special(std::string_view view) noexcept;

/**
 * @private
 * Finds the delimiter of a view in authority state.
 */
ada_really_inline size_t
find_authority_delimiter(std::string_view view) noexcept;

/**
 * @private
 */
template <typename T, typename... Args>
inline void inner_concat(std::string& buffer, T t) {
  buffer.append(t);
}

/**
 * @private
 */
template <typename T, typename... Args>
inline void inner_concat(std::string& buffer, T t, Args... args) {
  buffer.append(t);
  return inner_concat(buffer, args...);
}

/**
 * @private
 * Concatenate the arguments and return a string.
 * @returns a string
 */
template <typename... Args>
std::string concat(Args... args) {
  std::string answer;
  inner_concat(answer, args...);
  return answer;
}

/**
 * @private
 * @return Number of leading zeroes.
 */
inline int leading_zeroes(uint32_t input_num) noexcept {
#if ADA_REGULAR_VISUAL_STUDIO
  unsigned long leading_zero(0);
  unsigned long in(input_num);
  return _BitScanReverse(&leading_zero, in) ? int(31 - leading_zero) : 32;
#else
  return __builtin_clz(input_num);
#endif  // ADA_REGULAR_VISUAL_STUDIO
}

/**
 * @private
 * Counts the number of decimal digits necessary to represent x.
 * faster than std::to_string(x).size().
 * @return digit count
 */
inline int fast_digit_count(uint32_t x) noexcept {
  auto int_log2 = [](uint32_t z) -> int {
    return 31 - ada::helpers::leading_zeroes(z | 1);
  };
  // Compiles to very few instructions. Note that the
  // table is static and thus effectively a constant.
  // We leave it inside the function because it is meaningless
  // outside of it (this comes at no performance cost).
  const static uint64_t table[] = {
      4294967296,  8589934582,  8589934582,  8589934582,  12884901788,
      12884901788, 12884901788, 17179868184, 17179868184, 17179868184,
      21474826480, 21474826480, 21474826480, 21474826480, 25769703776,
      25769703776, 25769703776, 30063771072, 30063771072, 30063771072,
      34349738368, 34349738368, 34349738368, 34349738368, 38554705664,
      38554705664, 38554705664, 41949672960, 41949672960, 41949672960,
      42949672960, 42949672960};
  return int((x + table[int_log2(x)]) >> 32);
}
}  // namespace ada::helpers

#endif  // ADA_HELPERS_H

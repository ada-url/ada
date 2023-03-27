/**
 * @file scheme.h
 * @brief Declarations for the URL scheme.
 */
#ifndef ADA_SCHEME_H
#define ADA_SCHEME_H

#include "ada/common_defs.h"

#include <array>
#include <optional>
#include <string>

/**
 * @namespace ada::scheme
 * @brief Includes the scheme declarations
 */
namespace ada::scheme {

/**
 * Type of the scheme as an enum.
 * Using strings to represent a scheme type is not ideal because
 * checking for types involves string comparisons. It is faster to use
 * a simple integer.
 * In C++11, we are allowed to specify the underlying type of the enum.
 * We pick an 8-bit integer (which allows up to 256 types). Specifying the
 * type of the enum may help integration with other systems if the type
 * variable is exposed (since its value will not depend on the compiler).
 */
enum type : uint8_t {
  HTTP = 0,
  NOT_SPECIAL = 1,
  HTTPS = 2,
  WS = 3,
  FTP = 4,
  WSS = 5,
  FILE = 6
};

/**
 * A special scheme is an ASCII string that is listed in the first column of the
 * following table. The default port for a special scheme is listed in the
 * second column on the same row. The default port for any other ASCII string is
 * null.
 *
 * @see https://url.spec.whatwg.org/#url-miscellaneous
 * @param scheme
 * @return If scheme is a special scheme
 */
ada_really_inline constexpr bool is_special(std::string_view scheme);

/**
 * A special scheme is an ASCII string that is listed in the first column of the
 * following table. The default port for a special scheme is listed in the
 * second column on the same row. The default port for any other ASCII string is
 * null.
 *
 * @see https://url.spec.whatwg.org/#url-miscellaneous
 * @param scheme
 * @return The special port
 */
constexpr uint16_t get_special_port(std::string_view scheme) noexcept;

/**
 * Returns the port number of a special scheme.
 * @see https://url.spec.whatwg.org/#special-scheme
 */
constexpr uint16_t get_special_port(ada::scheme::type type) noexcept;
/**
 * Returns the scheme of an input, or NOT_SPECIAL if it's not a special scheme
 * defined by the spec.
 */
constexpr ada::scheme::type get_scheme_type(std::string_view scheme) noexcept;

}  // namespace ada::scheme

#endif  // ADA_SCHEME_H

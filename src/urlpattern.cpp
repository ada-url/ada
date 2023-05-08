#include "ada/urlpattern.h"
#include "common_defs.h"

namespace ada {
ada_really_inline bool is_valid_name_code_point(const char32_t& c,
                                                bool is_first) {
  // To perform is a valid name code point given a Unicode code point and a
  // boolean first: If first is true return the result of checking if code

  // is contained in the IdentifierStart set of code points.
  if (is_first) {
    return c <= 255 ? unicode::is_identifier_start(c) : false;
  }
  return c <= 255 ? unicode::is_identifier_part(c) : false;
}

}  // namespace ada
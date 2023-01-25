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

  ada_warn_unused url parse(std::string_view input,
                            std::optional<ada::url> base_url,
                            ada::encoding_type encoding) {
    if(encoding != encoding_type::UTF8) {
      // @todo Add support for non UTF8 input
    }
    // @todo std::move(base_url) might be unwise. Check.
    return ada::parser::parse_url(input, std::move(base_url), encoding);
  }

  /*
   * @todo This should probably a method in the struct ada::url.
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

  ada_warn_unused std::string to_string(ada::encoding_type type) {
    switch(type) {
    case ada::encoding_type::UTF8 : return "UTF-8";
    case ada::encoding_type::UTF_16LE : return "UTF-16LE";
    case ada::encoding_type::UTF_16BE : return "UTF-16BE";
    default: unreachable();
    }
  }

} // namespace ada

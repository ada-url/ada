#ifndef ADA_IMPLEMENTATION_H
#define ADA_IMPLEMENTATION_H

#include <string>
#include <optional>

#include "ada/common_defs.h"
#include "ada/encoding_type.h"
#include "ada/url.h"

namespace ada {

  /**
   * The URL parser takes a scalar value string input, with an optional null or base URL base (default null)
   * and an optional encoding encoding (default UTF-8).
   * @param input the string input to analyze.
   * @param base_url the optional string input to use as a base url.
   * @param encoding encoding (default to UTF-8)
   */
  ada_warn_unused ada::url parse(std::string& input,
                                 /* Passing std::optional<ada::url> by copy likely forces a copy of the ada::url instance. */
                                 std::optional<ada::url> base_url = std::nullopt,
                                 ada::encoding_type encoding = UTF8) noexcept;
  ada_warn_unused ada::url parse(std::string_view input,
                                 /* Passing std::optional<ada::url> by copy likely forces a copy of the ada::url instance. */
                                 std::optional<ada::url> base_url = std::nullopt,
                                 ada::encoding_type encoding = UTF8) noexcept;

}

#endif // ADA_IMPLEMENTATION_H

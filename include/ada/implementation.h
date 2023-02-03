/**
 * @file implementation.h
 *
 * @brief Definitions for user facing functions for parsing URL and it's components.
 */
#ifndef ADA_IMPLEMENTATION_H
#define ADA_IMPLEMENTATION_H

#include <string>
#include <optional>

#include "ada/common_defs.h"
#include "ada/encoding_type.h"
#include "ada/url.h"
#include "ada/state.h"

namespace ada {
  enum class errors {
    generic_error
  };

  /**
   * The URL parser takes a scalar value string input, with an optional null or base URL base (default null)
   * and an optional encoding encoding (default UTF-8).
   *
   * @param input the string input to analyze.
   * @param base_url the optional string input to use as a base url.
   * @param encoding encoding (default to UTF-8)
   * @return a parsed URL.
   *
   * @example
   *
   * ```cpp
   * auto url = ada::url parse("https://www.google.com");
   * ```
   */
  ada_warn_unused tl::expected<ada::url,ada::errors> parse(std::string_view input,
                                 const ada::url* base_url = nullptr,
                                 ada::encoding_type encoding = ada::encoding_type::UTF8);

}

#endif // ADA_IMPLEMENTATION_H

/**
 * @file implementation.h
 * @brief Definitions for user facing functions for parsing URL and it's components.
 */
#ifndef ADA_IMPLEMENTATION_H
#define ADA_IMPLEMENTATION_H

#include <string>
#include <optional>

#include "ada/parser.h"
#include "ada/common_defs.h"
#include "ada/encoding_type.h"
#include "ada/url.h"
#include "ada/state.h"
#include "ada/url_aggregator.h"

namespace ada {
  enum class errors {
    generic_error
  };

  template <class result_type = ada::url>
  using result = tl::expected<result_type, ada::errors>;

  /**
   * The URL parser takes a scalar value string input, with an optional null or base URL base (default null)
   * and an optional encoding encoding (default UTF-8).
   *
   * @param input the string input to analyze.
   * @param base_url the optional string input to use as a base url.
   * @return a parsed URL.
   */
  template <class result_type = ada::url>
  ada_warn_unused ada::result<result_type> parse(std::string_view input, const result_type* base_url = nullptr);

  extern template ada::result<url> parse<url>(std::string_view input, const url* base_url);
  extern template ada::result<url_aggregator> parse<url_aggregator>(std::string_view input, const url_aggregator* base_url);

  /**
   * Computes a href string from a file path.
   * @return a href string (starts with file:://)
   */
  std::string href_from_file(std::string_view path);
}

#endif // ADA_IMPLEMENTATION_H

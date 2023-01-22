/**
 * @file implementation.h
 *
 * @brief Definitions for user facing functions for parsing URL and it's components.
 */
#ifndef ADA_IMPLEMENTATION_H
#define ADA_IMPLEMENTATION_H

#include <string>
#include <optional>

#include "common_defs.h"
#include "encoding_type.h"
#include "url.h"
#include "state.h"

namespace ada {

  /**
   * The URL parser takes a scalar value string input, with an optional null or base URL base (default null)
   * and an optional encoding encoding (default UTF-8).
   *
   * @param input the string input to analyze.
   * @param base_url the optional string input to use as a base url.
   * @param encoding encoding (default to UTF-8)
   *
   * @example
   *
   * ```cpp
   * auto url = ada::url parse("https://www.google.com");
   * ```
   */
  ada_warn_unused ada::url parse(std::string_view input,
                                 std::optional<ada::url> base_url = std::nullopt,
                                 ada::encoding_type encoding = ada::encoding_type::UTF8);

  /**
   * Scheme setter is used to override the scheme of an ada::url instance.
   * It will only update if the input is valid within the context of the base url.
   *
   * @see https://url.spec.whatwg.org/#dom-url-protocol
   * @return Returns true if setter is successful.
   */
  bool set_scheme(ada::url &base, std::string input, ada::encoding_type encoding = ada::encoding_type::UTF8) noexcept;

  /**
   * Username setter is used for overriding the username of an ada::url instance.
   *
   * @see https://url.spec.whatwg.org/#dom-url-username
   */
  void set_username(ada::url &base, std::string_view input) noexcept;

  /**
   * Password setter is used for overriding the username of an ada::url instance.
   *
   * @see https://url.spec.whatwg.org/#dom-url-password
   */
  void set_password(ada::url &base, std::string_view input) noexcept;

  /**
   * Update the hostname of an existing ada::url instance.
   * It will only update if the input is valid within the context of the base url.
   *
   * @see https://url.spec.whatwg.org/#dom-url-host
   * @return Returns true if setter is successful.
   */
  bool set_host(ada::url &base, std::string_view input, ada::encoding_type encoding = ada::encoding_type::UTF8) noexcept;

  /**
   * Update the port of an existing ada::url instance.
   * It will only update if the input is valid within the context of the base url.
   *
   * @see https://url.spec.whatwg.org/#dom-url-port
   * @return Returns true if setter is successful.
   */
  bool set_port(ada::url &base, std::string_view input) noexcept;

  /**
   * Update the pathname of an existing ada::url instance.
   * It will only update if the input is valid within the context of the base url.
   *
   * @see https://url.spec.whatwg.org/#dom-url-pathname
   * @return Returns true if setter is successful.
   */
  bool set_pathname(ada::url &base, std::string_view input, ada::encoding_type encoding = ada::encoding_type::UTF8) noexcept;

  /**
   * Update the query/search of an existing ada::url instance.
   *
   * @see https://url.spec.whatwg.org/#dom-url-search
   */
  void set_search(ada::url &base, std::string_view input) noexcept;

  /**
   * Update the hash/fragment of an existing ada::url instance.
   *
   * @see https://url.spec.whatwg.org/#dom-url-hash
   */
  void set_hash(ada::url &base, std::string_view input) noexcept;

}

#endif // ADA_IMPLEMENTATION_H

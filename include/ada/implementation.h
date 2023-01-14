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
   * @param input the string input to analyze.
   * @param base_url the optional string input to use as a base url.
   * @param encoding encoding (default to UTF-8)
   */
  //
  // TODO: As a user-facing function, this has poor usability. Users typically have
  // a ada::url base_url. To call this function they need to *copy* it to an
  // std::optional<ada::url> instance.
  //
  // Specifically, the current syntax requires the user to do:
  // ada::parse(input, std::optional<ada::url>(std::move(base_url)));
  // if there is a base_url.
  //
  ada_warn_unused ada::url parse(std::string_view input,
                                 std::optional<ada::url> base_url = std::nullopt,
                                 ada::encoding_type encoding = ada::encoding_type::UTF8,
                                 std::optional<ada::state> state = std::nullopt) noexcept;

  void set_scheme(ada::url &base, std::string input, ada::encoding_type encoding = ada::encoding_type::UTF8) noexcept;
  void set_username(ada::url &base, std::string input) noexcept;
  void set_password(ada::url &base, std::string input) noexcept;
  void set_host(ada::url &base, std::string_view input, ada::encoding_type encoding = ada::encoding_type::UTF8) noexcept;
  void set_port(ada::url &base, std::string input, ada::encoding_type encoding = ada::encoding_type::UTF8) noexcept;
  void set_pathname(ada::url &base, std::string input, ada::encoding_type encoding = ada::encoding_type::UTF8) noexcept;
  void set_search(ada::url &base, std::string input) noexcept;
  void set_hash(ada::url &base, std::string input) noexcept;
}

#endif // ADA_IMPLEMENTATION_H

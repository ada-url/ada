#include "ada/implementation-inl.h"

#include <optional>
#include <string_view>

#include "ada/checkers-inl.h"
#include "ada/checkers.h"
#include "ada/common_defs.h"
#include "ada/parser.h"
#include "ada/scheme.h"
#include "ada/unicode-inl.h"
#include "ada/url.h"
#include "ada/url_aggregator.h"

namespace ada {

namespace {

// @private
// Fast-path validator for can_parse.
//
// Validates absolute special (non-file) URLs without constructing any
// url_aggregator object and without running the state machine.
// Performs a single forward scan over the input bytes.
//
// Returns:
//   true      -- URL is structurally valid
//   false     -- URL is definitely invalid
//   nullopt   -- edge case; fall through to the full parser
//               (credentials, IDNA, IPv4/6, tabs/newlines, relative URLs, ...)
std::optional<bool> try_can_parse_absolute_fast(
    std::string_view input) noexcept {
  const uint8_t* b = reinterpret_cast<const uint8_t*>(input.data());
  size_t len = input.size();

  // -- Inline C0 whitespace trim (no allocation) --------------------------
  while (len > 0 && b[0] <= 0x20) {
    b++;
    len--;
  }
  while (len > 0 && b[len - 1] <= 0x20) {
    len--;
  }
  if (len == 0) return false;

  // Tabs/newlines are rare and require tmp_buffer allocation; defer to full
  // parser.
  if (unicode::has_tabs_or_newline({reinterpret_cast<const char*>(b), len})) {
    return std::nullopt;
  }

  // -- Scheme detection -----------------------------------------------------
  if (!checkers::is_alpha(static_cast<char>(b[0]))) return false;

  // Scan for ':' within the first 7 bytes. All special schemes are <= 5 chars
  // ("https"), so any URL whose first ':' is beyond byte 6 is either
  // non-special or relative -- both require the full parser.
  size_t colon_pos = 0;
  for (size_t i = 1;; ++i) {
    if (i >= 7 || i >= len) return std::nullopt;
    const char c = static_cast<char>(b[i]);
    if (c == ':') {
      colon_pos = i;
      break;
    }
    if (!unicode::is_alnum_plus(c)) return false;
  }

  // Lowercase scheme bytes inline and classify via the existing perfect hash.
  char scheme_buf[6];
  scheme_buf[0] = static_cast<char>(b[0] | 0x20);
  for (size_t i = 1; i < colon_pos; ++i)
    scheme_buf[i] = static_cast<char>(b[i] | 0x20);

  const ada::scheme::type scheme_type =
      ada::scheme::get_scheme_type({scheme_buf, colon_pos});

  // Only handle special, non-file schemes.
  if (scheme_type == ada::scheme::NOT_SPECIAL) return std::nullopt;
  if (scheme_type == ada::scheme::FILE) return std::nullopt;

  // Per WHATWG, special URLs don't require "//": "http:example.com" is valid
  // (SPECIAL_AUTHORITY_IGNORE_SLASHES just skips leading slashes and proceeds
  // to AUTHORITY).  Defer to the inline fallback for any input without "://".
  size_t pos = colon_pos + 1;
  if (pos + 2 > len || b[pos] != '/' || b[pos + 1] != '/') {
    return std::nullopt;
  }
  pos += 2;

  // SPECIAL_AUTHORITY_IGNORE_SLASHES: the full parser skips any additional
  // leading '/' or '\' after the initial "//".  Mirror that here so we don't
  // mis-identify the host as empty when there are extra slashes.
  while (pos < len && (b[pos] == '/' || b[pos] == '\\')) {
    ++pos;
  }

  // -- Single-pass authority scan --------------------------------------------
  const size_t auth_start = pos;
  size_t auth_end = pos;
  size_t port_colon = SIZE_MAX;
  bool has_x = false;

  for (; auth_end < len; ++auth_end) {
    const uint8_t c = b[auth_end];
    if (c == '/' || c == '?' || c == '#' || c == '\\') break;
    if (c == '@') return std::nullopt;   // credentials -> full parse
    if (c >= 0x80) return std::nullopt;  // non-ASCII -> IDNA -> full parse
    if (c == '%')
      return std::nullopt;  // percent-encoded -> needs to_ascii -> full parse
    if (c == ':') {
      if (port_colon == SIZE_MAX) port_colon = auth_end;
      continue;
    }
    if (c == 'x' || c == 'X') has_x = true;
  }

  // IPv6 literal
  if (auth_start < auth_end && b[auth_start] == '[') return std::nullopt;

  const size_t host_end = (port_colon != SIZE_MAX) ? port_colon : auth_end;

  // Empty host is invalid for special URLs.
  if (auth_start == host_end) return false;

  const char* host_ptr = reinterpret_cast<const char*>(b + auth_start);
  const size_t host_len = host_end - auth_start;

  // -- Host validation -------------------------------------------------------
  // Bit 0x01: forbidden domain code point -> invalid.
  // Bit 0x02: uppercase letter -> still valid (parser lowercases), not checked
  // here.
  const uint8_t domain_check =
      unicode::contains_forbidden_domain_code_point_or_upper(host_ptr,
                                                             host_len);
  if (domain_check & 0x01) return false;

  // xn-- labels require full IDNA validation.
  if (has_x) {
    for (size_t i = 0; i + 4 <= host_len; ++i) {
      if ((host_ptr[i] | 0x20) == 'x' && (host_ptr[i + 1] | 0x20) == 'n' &&
          host_ptr[i + 2] == '-' && host_ptr[i + 3] == '-') {
        return std::nullopt;
      }
    }
  }

  // IPv4 detection: all-decimal-and-dot host -> try the fast IPv4 parser.
  {
    bool all_dec_dots = true;
    for (size_t i = 0; i < host_len && all_dec_dots; ++i) {
      const uint8_t c = static_cast<uint8_t>(host_ptr[i]);
      if (c != '.' && (c < '0' || c > '9')) all_dec_dots = false;
    }
    if (all_dec_dots) {
      // If the fast IPv4 parser accepts it, the host is a valid decimal IPv4.
      if (checkers::try_parse_ipv4_fast({host_ptr, host_len}) !=
          checkers::ipv4_fast_fail) {
        return true;
      }
      // Fast IPv4 parsing failed (e.g. host is ".", "..", "1.2.3.500").
      // Such hosts may still be valid domain names; defer to the full parser.
      return std::nullopt;
    }

    // Last-significant-character heuristic for non-decimal IPv4 (hex/octal):
    // if the last non-dot char is a digit, 'a'-'f', or 'x' the host might be
    // an IPv4 address that the fast path can't validate -- fall through.
    uint8_t last = 0;
    for (size_t i = host_len; i > 0; --i) {
      if (host_ptr[i - 1] != '.') {
        last = static_cast<uint8_t>(host_ptr[i - 1]);
        break;
      }
    }
    const uint8_t lc = last | 0x20;
    if ((last >= '0' && last <= '9') || (lc >= 'a' && lc <= 'f') || lc == 'x') {
      return std::nullopt;
    }
  }

  // -- Port validation -------------------------------------------------------
  if (port_colon != SIZE_MAX) {
    const uint8_t* pp = b + port_colon + 1;
    const size_t pl = auth_end - port_colon - 1;
    if (pl > 0) {
      if (pl > 5) return false;  // > 99999 cannot be a valid port
      uint32_t pv = 0;
      for (size_t i = 0; i < pl; ++i) {
        if (pp[i] < '0' || pp[i] > '9') return false;
        pv = pv * 10 + (pp[i] - '0');
      }
      if (pv > 65535) return false;
    }
  }

  // Path, query, and fragment are structurally always valid for can_parse --
  // the parser would encode whatever is there.
  return true;
}

}  // namespace

template <class result_type>
ada_warn_unused tl::expected<result_type, errors> parse(
    std::string_view input, const result_type* base_url) {
  result_type u = ada::parser::parse_url_impl<result_type>(input, base_url);
  if (!u.is_valid) {
    return tl::unexpected(errors::type_error);
  }
  return u;
}

template ada::result<url> parse<url>(std::string_view input,
                                     const url* base_url = nullptr);
template ada::result<url_aggregator> parse<url_aggregator>(
    std::string_view input, const url_aggregator* base_url = nullptr);

std::string href_from_file(std::string_view input) {
  // This is going to be much faster than constructing a URL.
  std::string tmp_buffer;
  std::string_view internal_input;
  if (unicode::has_tabs_or_newline(input)) {
    tmp_buffer = input;
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = input;
  }
  std::string path;
  if (internal_input.empty()) {
    path = "/";
  } else if ((internal_input[0] == '/') || (internal_input[0] == '\\')) {
    helpers::parse_prepared_path(internal_input.substr(1),
                                 ada::scheme::type::FILE, path);
  } else {
    helpers::parse_prepared_path(internal_input, ada::scheme::type::FILE, path);
  }
  return "file://" + path;
}

bool can_parse(std::string_view input, const std::string_view* base_input) {
  // Fast path: handles the overwhelming majority of inputs -- absolute special
  // URLs with an ASCII domain, no credentials, and no base -- with a single
  // forward scan and zero allocations.
  if (base_input == nullptr) {
    if (const auto r = try_can_parse_absolute_fast(input)) {
      return *r;
    }
  }

  // Fallback: run the parser in validation-only mode (store_values=false),
  // which skips all the expensive work that isn't needed to determine validity:
  // buffer reservation, credential encoding, path normalisation, query and
  // fragment percent-encoding.  The host is still fully validated (IDNA, IPv4,
  // IPv6) because parse_host() must run for correctness.
  ada::url_aggregator base_agg;
  ada::url_aggregator* base_ptr = nullptr;
  if (base_input != nullptr) {
    base_agg = ada::parser::parse_url_impl<ada::url_aggregator, false>(
        *base_input, nullptr);
    if (!base_agg.is_valid) return false;
    base_ptr = &base_agg;
  }
  return ada::parser::parse_url_impl<ada::url_aggregator, false>(input,
                                                                 base_ptr)
      .is_valid;
}

ada_warn_unused std::string_view to_string(ada::encoding_type type) {
  switch (type) {
    case ada::encoding_type::UTF8:
      return "UTF-8";
    case ada::encoding_type::UTF_16LE:
      return "UTF-16LE";
    case ada::encoding_type::UTF_16BE:
      return "UTF-16BE";
    default:
      unreachable();
  }
}

}  // namespace ada

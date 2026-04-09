#include "ada/implementation-inl.h"

#include <atomic>
#include <limits>
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

static std::atomic<uint32_t> max_input_length_{
    std::numeric_limits<uint32_t>::max()};

void set_max_input_length(uint32_t length) {
  max_input_length_.store(length, std::memory_order_relaxed);
}

uint32_t get_max_input_length() {
  return max_input_length_.load(std::memory_order_relaxed);
}

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
  // Note: \t (0x09), \n (0x0a), \r (0x0d) are all <= 0x20, so any
  // leading/trailing tabs or newlines are correctly stripped here, matching
  // the WHATWG spec's "remove leading/trailing C0 control and space" step.
  while (len > 0 && b[0] <= 0x20) {
    b++;
    len--;
  }
  while (len > 0 && b[len - 1] <= 0x20) {
    len--;
  }
  if (len == 0) return false;

  // -- Scheme detection -----------------------------------------------------
  // Fast path for HTTP and HTTPS (covers ~90%+ of real-world URLs).
  // Avoids the general scheme loop, buffer copy, and perfect hash lookup.
  // We know HTTP and HTTPS are special non-file schemes, so no further
  // scheme_type checks are needed on the fast path -- only `pos` matters.
  size_t pos;

  if (len >= 7 && (b[0] | 0x20) == 'h' && (b[1] | 0x20) == 't' &&
      (b[2] | 0x20) == 't' && (b[3] | 0x20) == 'p') {
    if (b[4] == ':' && b[5] == '/' && b[6] == '/') {
      pos = 7;
      goto skip_extra_slashes;
    }
    if (len >= 8 && (b[4] | 0x20) == 's' && b[5] == ':' && b[6] == '/' &&
        b[7] == '/') {
      pos = 8;
      goto skip_extra_slashes;
    }
    // Fall through: could be "httpe://", tabs in scheme, etc.
  }

  {
    // General scheme detection for ws, wss, ftp, and edge cases.
    if (!checkers::is_alpha(static_cast<char>(b[0]))) return false;

    // Scan for ':' within the first 7 bytes. All special schemes are <= 5
    // chars ("https"), so any URL whose first ':' is beyond byte 6 is either
    // non-special or relative -- both require the full parser.
    size_t colon_pos = 0;
    for (size_t i = 1;; ++i) {
      if (i >= 7 || i >= len) return std::nullopt;
      const char c = static_cast<char>(b[i]);
      if (c == ':') {
        colon_pos = i;
        break;
      }
      // Tabs/newlines in the scheme require the full parser to strip them.
      if (c == '\t' || c == '\n' || c == '\r') return std::nullopt;
      if (!unicode::is_alnum_plus(c)) return false;
    }

    // Lowercase scheme bytes inline and classify via the existing perfect
    // hash.
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
    // (SPECIAL_AUTHORITY_IGNORE_SLASHES just skips leading slashes and
    // proceeds to AUTHORITY).  Defer to the inline fallback for any input
    // without "://".
    pos = colon_pos + 1;
    if (pos + 2 > len || b[pos] != '/' || b[pos + 1] != '/') {
      return std::nullopt;
    }
    pos += 2;
  }

skip_extra_slashes:
  // SPECIAL_AUTHORITY_IGNORE_SLASHES: the full parser skips any additional
  // leading '/' or '\' after the initial "//".  Mirror that here so we don't
  // mis-identify the host as empty when there are extra slashes.
  while (pos < len && (b[pos] == '/' || b[pos] == '\\')) {
    ++pos;
  }

  // Early IPv6 bail-out: if the authority starts with '[', it's an IPv6
  // literal which requires the full parser.  Checking here avoids scanning
  // the entire bracketed address only to bail out afterward.
  if (pos < len && b[pos] == '[') return std::nullopt;

  // -- Merged authority + host scan ------------------------------------------
  // A single forward pass over the authority bytes that simultaneously:
  //   - finds the authority end and port colon
  //   - validates host characters (forbidden domain code points)
  //   - tracks IPv4 indicators (all-decimal-dots, last non-dot char)
  //   - detects xn-- prefixes (IDNA punycode)
  //   - detects tabs/newlines (which require the full parser to strip)
  // This replaces 4 separate scans over the host bytes.
  const size_t auth_start = pos;
  size_t auth_end = pos;
  size_t port_colon = SIZE_MAX;
  bool all_dec_dots = true;
  uint8_t last_non_dot = 0;

  for (; auth_end < len; ++auth_end) {
    const uint8_t c = b[auth_end];

    // Non-ASCII -> needs IDNA processing -> full parser.
    if (c >= 0x80) return std::nullopt;

    // Authority delimiters.
    if (c == '/' || c == '?' || c == '#' || c == '\\') break;

    // Port separator.
    if (c == ':') {
      if (port_colon == SIZE_MAX) port_colon = auth_end;
      continue;
    }

    // Credentials or percent-encoding -> full parser.
    if (c == '@' || c == '%') return std::nullopt;

    // Tabs/newlines anywhere in the authority require the full parser to
    // strip them before validation.  Without this, a tab in the port (e.g.
    // "http://host:8\t0/") would be mis-rejected by port validation.
    if (c == '\t' || c == '\n' || c == '\r') return std::nullopt;

    // Skip remaining host-specific checks for port bytes.  Port digits are
    // validated separately below, and no forbidden-domain-code-point check
    // is needed on port characters.
    if (port_colon != SIZE_MAX) continue;

    // -- Host byte validation (inlined) ------------------------------------
    // Forbidden domain code points that are not already caught above:
    //   C0 controls and space (0x00-0x20), DEL (0x7F), <, >, [, ], ^, |.
    // At this stage, the input may still be userinfo or be normalized later
    // (e.g., percent-encoded), so we do not reject here and defer to the
    // parser. Characters already caught: >= 0x80 (non-ASCII), '/' '?' '#' '\\'
    // (delimiters), ':' (port), '@' '%' (bail), '\t' '\n' '\r' (bail).
    if (c <= 0x20 || c == 0x7F || c == '<' || c == '>' || c == '[' ||
        c == ']' || c == '^' || c == '|') {
      return std::nullopt;
    }

    // Track whether host is all decimal digits and dots (potential IPv4).
    if (c != '.' && (c < '0' || c > '9')) all_dec_dots = false;

    // Track last non-dot character for the IPv4 hex/octal heuristic.
    if (c != '.') last_non_dot = c;

    // Detect xn-- prefix inline (IDNA punycode -> needs full parser).
    // Checking at every position mirrors the original behavior: any
    // occurrence of "xn--" in the host (not just at label boundaries)
    // triggers a bail-out to the full IDNA validator.
    if ((c | 0x20) == 'x' && auth_end + 4 <= len &&
        (b[auth_end + 1] | 0x20) == 'n' && b[auth_end + 2] == '-' &&
        b[auth_end + 3] == '-') {
      return std::nullopt;
    }
  }

  const size_t host_end = (port_colon != SIZE_MAX) ? port_colon : auth_end;

  // Empty host is invalid for special URLs.
  if (auth_start == host_end) return false;

  // -- IPv4 handling ---------------------------------------------------------
  const char* host_ptr = reinterpret_cast<const char*>(b + auth_start);
  const size_t host_len = host_end - auth_start;

  if (all_dec_dots) {
    // Host is all decimal digits and dots -> try the fast IPv4 parser.
    if (checkers::try_parse_ipv4_fast({host_ptr, host_len}) !=
        checkers::ipv4_fast_fail) {
      // Valid decimal IPv4 host.  Do NOT return true yet: the port still
      // needs to be validated below before we can declare the URL valid.
      goto validate_port;
    }
    // Fast IPv4 parsing failed (e.g. host is ".", "..", "1.2.3.500").
    // Such hosts may still be valid domain names; defer to the full parser.
    return std::nullopt;
  }

  // Last-significant-character heuristic for non-decimal IPv4 (hex/octal):
  // if the last non-dot char is a digit, 'a'-'f', or 'x' the host might be
  // an IPv4 address that the fast path can't validate -- fall through.
  // last_non_dot was tracked during the authority scan above.
  {
    const uint8_t lc = last_non_dot | 0x20;
    if ((last_non_dot >= '0' && last_non_dot <= '9') ||
        (lc >= 'a' && lc <= 'f') || lc == 'x') {
      return std::nullopt;
    }
  }

  // -- Port validation -------------------------------------------------------
validate_port:
  if (port_colon != SIZE_MAX) {
    const uint8_t* pp = b + port_colon + 1;
    size_t pl = auth_end - port_colon - 1;
    if (pl > 0) {
      // Strip leading zeros: "0000001" == 1, "0000000000000" == 0, both valid.
      // Only the significant digits count toward the 5-digit maximum.
      while (pl > 0 && *pp == '0') {
        ++pp;
        --pl;
      }
      if (pl > 5) return false;  // significant digits > 99999
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

  // Reject inputs that exceed the configurable maximum length.
  // This check is placed after the fast path so the common case (default 4 GB
  // limit, absolute URLs) pays no overhead.
  // Note: can_parse() does not perform normalization (percent-encoding, IDNA),
  // so it cannot detect cases where a short input normalizes into a long URL.
  // In such edge cases can_parse() may return true while parse() fails.
  const uint32_t max_length = ada::get_max_input_length();
  if (input.size() > max_length) {
    return false;
  }
  if (base_input != nullptr && base_input->size() > max_length) {
    return false;
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

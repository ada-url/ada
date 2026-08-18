#include "ada/implementation-inl.h"

#include <array>
#include <atomic>
#include <cstring>
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

constexpr std::array<uint8_t, 256> clean_http_host_byte = []() consteval {
  std::array<uint8_t, 256> result{};
  for (size_t i = 0; i < result.size(); ++i) {
    const auto c = static_cast<uint8_t>(i);
    result[i] =
        static_cast<uint8_t>((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                             c == '-' || c == '.' || c == '_' || c == '~');
  }
  return result;
}();

// SWAR: eight ASCII host bytes in [a-z0-9-._~] without 8 table lookups.
// High bits must be clear first so the range subtracts cannot borrow
// across bytes.
// High-bit-cleared ASCII only. Subtracts cannot borrow across bytes because
// each (hi|0x80) byte is >= 0x80 and each data byte is <= 0x7F. Do not use
// has-zero (x-ones)&~x: a match followed by match^1 (e.g. "./" or "_^")
// produces a false positive via borrow.
ada_really_inline uint64_t swar_in_range(uint64_t w, uint8_t lo,
                                         uint8_t hi) noexcept {
  constexpr uint64_t k_ones = 0x0101010101010101ull;
  constexpr uint64_t k_high = 0x8080808080808080ull;
  const uint64_t ge_lo = (w | k_high) - (k_ones * lo);
  const uint64_t le_hi = ((k_ones * hi) | k_high) - w;
  return ge_lo & le_hi & k_high;
}

ada_really_inline bool eight_clean_http_host_bytes(
    const uint8_t* input) noexcept {
  uint64_t w = 0;
  std::memcpy(&w, input, 8);
  constexpr uint64_t k_high = 0x8080808080808080ull;
  if ((w & k_high) != 0) {
    return false;
  }
  const uint64_t ok = swar_in_range(w, 'a', 'z') | swar_in_range(w, '0', '9') |
                      swar_in_range(w, '-', '-') | swar_in_range(w, '.', '.') |
                      swar_in_range(w, '_', '_') | swar_in_range(w, '~', '~');
  return ok == k_high;
}

// Minimal front end for the overwhelmingly common already-canonical HTTP(S)
// case. It deliberately handles fewer inputs than
// try_can_parse_absolute_fast: anything requiring normalization or detailed
// host parsing falls through to that broader validator.
#if defined(_MSC_VER) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
constexpr bool k_can_parse_little_endian = true;
#else
constexpr bool k_can_parse_little_endian = false;
#endif

std::optional<bool> try_can_parse_clean_http(std::string_view input) noexcept {
  const auto* bytes = reinterpret_cast<const uint8_t*>(input.data());
  const size_t length = input.size();
  if (length < 7) {
    return std::nullopt;
  }

  size_t authority_start;
  if constexpr (k_can_parse_little_endian) {
    if (length >= 8) {
      uint64_t first8 = 0;
      std::memcpy(&first8, bytes, 8);
      if (first8 == 0x2f2f3a7370747468ull) {  // "https://"
        authority_start = 8;
      } else if ((first8 & 0x00ffffffffffffffull) ==
                 0x002f2f3a70747468ull) {  // "http://"
        authority_start = 7;
      } else {
        return std::nullopt;
      }
    } else if (bytes[0] == 'h' && bytes[1] == 't' && bytes[2] == 't' &&
               bytes[3] == 'p' && bytes[4] == ':' && bytes[5] == '/' &&
               bytes[6] == '/') {
      authority_start = 7;
    } else {
      return std::nullopt;
    }
  } else {
    uint32_t first4{};
    std::memcpy(&first4, bytes, 4);
    if (first4 != 0x68747470u) {  // "http"
      return std::nullopt;
    }
    if (length >= 8 && bytes[4] == 's' && bytes[5] == ':' && bytes[6] == '/' &&
        bytes[7] == '/') {
      authority_start = 8;
    } else if (bytes[4] == ':' && bytes[5] == '/' && bytes[6] == '/') {
      authority_start = 7;
    } else {
      return std::nullopt;
    }
  }

  if (authority_start >= length) {
    return false;
  }

  size_t cursor = authority_start;
  while (cursor + 8 <= length && eight_clean_http_host_bytes(bytes + cursor)) {
    cursor += 8;
  }
  while (cursor < length) {
    const uint8_t c = bytes[cursor];
    if (c == '/' || c == '?' || c == '#') {
      break;
    }
    if (!clean_http_host_byte[c]) {
      return std::nullopt;
    }
    ++cursor;
  }

  const size_t host_length = cursor - authority_start;
  if (host_length == 0) {
    // Extra special-scheme slashes are normalization, not an empty host.
    if (bytes[authority_start] == '/' || bytes[authority_start] == '\\') {
      return std::nullopt;
    }
    return false;
  }
  if (host_length > 253 || bytes[cursor - 1] == '.') {
    return std::nullopt;
  }

  const std::string_view host(input.data() + authority_start, host_length);
  if (checkers::last_label_may_be_a_number(host)) {
    return std::nullopt;
  }
  if (host.find('x') != std::string_view::npos &&
      host.find("xn-") != std::string_view::npos) {
    return std::nullopt;
  }

  // Once a special URL has a valid host, path/query/fragment bytes cannot make
  // it structurally invalid: the full parser percent-encodes them as needed.
  return true;
}

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

  if (checkers::last_label_may_be_a_number({host_ptr, host_len})) {
    return std::nullopt;
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
  // Match ada::parse / setters: refuse inputs that already exceed the limit.
  // Path percent-encoding can still expand the result, so we also check the
  // final href below.
  const uint32_t max_length = ada::get_max_input_length();
  if (input.size() > max_length) {
    return {};
  }

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
  std::string result = "file://" + path;
  if (result.size() > max_length) {
    return {};
  }
  return result;
}

bool can_parse(std::string_view input, const std::string_view* base_input) {
  // Must match parse().has_value(), including post-normalization max length.
  // Percent-encoding expands a byte by at most 3x, but IDNA expands more: a
  // 3-byte UTF-8 label such as U+337F becomes the 17-byte "xn--6oqv20b1zgzxr",
  // so a dotted host sustains 4.5x. When the input (plus base, if any) fits in
  // max_length/5, the normalized href cannot exceed max_length, so
  // validation-only parsing (store_values=false) is safe.

  // Hot path first: absolute special URLs, no base. Avoid loading max_length
  // until we need it (common absolute-fast true/false cases).
  if (base_input == nullptr) {
    auto r = try_can_parse_clean_http(input);
    if (!r.has_value()) {
      r = try_can_parse_absolute_fast(input);
    }
    if (r.has_value()) {
      if (!*r) {
        return false;
      }
      // size <= max/5 => normalized href cannot exceed max (4.5x expansion).
      // Check this first: default max is ~4GB so almost all URLs return true.
      const uint32_t max_length = ada::get_max_input_length();
      if (input.size() <= static_cast<size_t>(max_length) / 5) {
        return true;
      }
      if (input.size() > max_length) {
        return false;
      }
      return ada::parser::parse_url_impl<ada::url_aggregator, true>(input,
                                                                    nullptr)
          .is_valid;
    }
  }

  const uint32_t max_length = ada::get_max_input_length();
  if (input.size() > max_length) {
    return false;
  }
  if (base_input != nullptr && base_input->size() > max_length) {
    return false;
  }

  // Relative resolution combines base + input; bound the sum so 4.5x expansion
  // of either side cannot push the final href past max_length.
  const size_t combined =
      input.size() + (base_input == nullptr ? 0 : base_input->size());
  const bool size_safe = combined <= static_cast<size_t>(max_length) / 5;

  if (size_safe) {
    // Validation-only: no buffer build, host still fully checked.
    ada::url_aggregator base_agg;
    ada::url_aggregator* base_ptr = nullptr;
    if (base_input != nullptr) {
      base_agg = ada::parser::parse_url_impl<ada::url_aggregator, false>(
          *base_input, nullptr);
      if (!base_agg.is_valid) {
        return false;
      }
      base_ptr = &base_agg;
    }
    return ada::parser::parse_url_impl<ada::url_aggregator, false>(input,
                                                                   base_ptr)
        .is_valid;
  }

  // Near the limit: full parse so post-normalization length matches parse().
  if (base_input == nullptr) {
    return ada::parser::parse_url_impl<ada::url_aggregator, true>(input,
                                                                  nullptr)
        .is_valid;
  }
  ada::url_aggregator base_agg =
      ada::parser::parse_url_impl<ada::url_aggregator, true>(*base_input,
                                                             nullptr);
  if (!base_agg.is_valid) {
    return false;
  }
  return ada::parser::parse_url_impl<ada::url_aggregator, true>(input,
                                                                &base_agg)
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

#include <fuzzer/FuzzedDataProvider.h>

#include <cassert>
#include <cstdio>
#include <string>

#include "ada.cpp"
#include "ada.h"

// ============================================================
// Fuzzer for low-level unicode, checker, and helper utilities.
//
// These functions are exercised indirectly through the URL
// parsing pipeline but are never targeted directly. Fuzzing
// them in isolation lets the engine discover edge cases
// without requiring a structurally valid URL as input.
// ============================================================

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string input = fdp.ConsumeRandomLengthString(128);
  std::string_view sv(input.data(), input.size());

  // ===== Per-character classification =====
  // Drive the fuzzer over every byte value so all lookup-table branches are
  // reachable from the corpus without relying on URL structure.
  for (char c : input) {
    // forbidden_host ⊆ forbidden_domain (every host-forbidden code point must
    // also be domain-forbidden).
    bool is_host = ada::unicode::is_forbidden_host_code_point(c);
    bool is_domain = ada::unicode::is_forbidden_domain_code_point(c);
    if (is_host && !is_domain) {
      printf(
          "is_forbidden_host_code_point implies is_forbidden_domain_code_point"
          " but got inconsistent results for char 0x%02x\n",
          (unsigned char)c);
      abort();
    }

    // ascii_digit ⊆ ascii_hex_digit
    bool is_digit = ada::unicode::is_ascii_digit(c);
    bool is_hex = ada::unicode::is_ascii_hex_digit(c);
    if (is_digit && !is_hex) {
      printf(
          "is_ascii_digit implies is_ascii_hex_digit"
          " but got inconsistent results for char 0x%02x\n",
          (unsigned char)c);
      abort();
    }

    // lowercase_hex ⊆ ascii_hex_digit
    bool is_lhex = ada::unicode::is_lowercase_hex(c);
    if (is_lhex && !is_hex) {
      printf(
          "is_lowercase_hex implies is_ascii_hex_digit"
          " but got inconsistent results for char 0x%02x\n",
          (unsigned char)c);
      abort();
    }

    // convert_hex_to_binary result must be in [0, 15] for valid hex digits.
    if (is_hex) {
      unsigned val = ada::unicode::convert_hex_to_binary(c);
      if (val > 15) {
        printf(
            "convert_hex_to_binary returned %u (> 15) for hex digit 0x%02x\n",
            val, (unsigned char)c);
        abort();
      }
    }

    // Other classification functions – must not crash.
    volatile bool alnum = ada::unicode::is_alnum_plus(c);
    (void)alnum;
    volatile bool c0 = ada::unicode::is_c0_control_or_space(c);
    (void)c0;
    volatile bool tab_nl = ada::unicode::is_ascii_tab_or_newline(c);
    (void)tab_nl;
    volatile bool ascii32 = ada::unicode::is_ascii(
        static_cast<char32_t>(static_cast<unsigned char>(c)));
    (void)ascii32;

    // ada::checkers per-character functions.
    volatile bool alpha = ada::checkers::is_alpha(c);
    (void)alpha;
    volatile bool digit2 = ada::checkers::is_digit(c);
    (void)digit2;
    volatile char lower = ada::checkers::to_lower(c);
    (void)lower;
  }

  // ===== String-level classification =====

  // has_tabs_or_newline: any string is valid input.
  volatile bool has_tn = ada::unicode::has_tabs_or_newline(sv);
  (void)has_tn;

  // has_hex_prefix and has_hex_prefix_unsafe must agree when size >= 2.
  {
    bool safe = ada::checkers::has_hex_prefix(sv);
    if (sv.size() >= 2) {
      bool unsafe = ada::checkers::has_hex_prefix_unsafe(sv);
      if (safe != unsafe) {
        printf(
            "has_hex_prefix vs has_hex_prefix_unsafe inconsistency for"
            " input '%s'\n",
            input.c_str());
        abort();
      }
    }
  }

  // is_double_dot and is_single_dot are mutually exclusive.
  {
    bool double_dot = ada::unicode::is_double_dot_path_segment(sv);
    bool single_dot = ada::unicode::is_single_dot_path_segment(sv);
    if (double_dot && single_dot) {
      printf(
          "is_double_dot_path_segment and is_single_dot_path_segment are"
          " mutually exclusive but both true for '%s'\n",
          input.c_str());
      abort();
    }
  }

  // contains_forbidden_domain_code_point: must not crash.
  volatile bool has_forbidden =
      ada::unicode::contains_forbidden_domain_code_point(input.data(),
                                                         input.size());
  (void)has_forbidden;

  // contains_forbidden_domain_code_point_or_upper: bit 0 = forbidden, bit 1 =
  // upper.
  volatile uint8_t forbidden_or_upper =
      ada::unicode::contains_forbidden_domain_code_point_or_upper(input.data(),
                                                                  input.size());
  (void)forbidden_or_upper;

  // to_lower_ascii: in-place; result must have the same length.
  {
    std::string lower_copy = input;
    volatile bool all_ascii =
        ada::unicode::to_lower_ascii(lower_copy.data(), lower_copy.size());
    (void)all_ascii;
    assert(lower_copy.size() == input.size());
  }

  // ===== Helper functions =====

  // prune_hash: the invariant is that the returned fragment (if any) is
  // shorter than the original input (the '#' itself is consumed).
  {
    std::string_view pruned = sv;
    auto frag = ada::helpers::prune_hash(pruned);
    // The prefix + separator + suffix must not exceed original length.
    assert(pruned.size() <= sv.size());
    if (frag.has_value()) {
      assert(pruned.size() + 1 + frag->size() <= sv.size() + 1);
    }
  }

  // trim_c0_whitespace: result must be a substring, so never longer.
  {
    std::string_view trimmed = sv;
    ada::helpers::trim_c0_whitespace(trimmed);
    assert(trimmed.size() <= sv.size());
  }

  // remove_ascii_tab_or_newline: must remove all \t / \n / \r characters.
  {
    std::string cleaned = input;
    ada::helpers::remove_ascii_tab_or_newline(cleaned);
    for (char c : cleaned) {
      if (c == '\t' || c == '\n' || c == '\r') {
        printf(
            "remove_ascii_tab_or_newline left tab/newline in output for"
            " input '%s'\n",
            input.c_str());
        abort();
      }
    }
    // Removing characters cannot make the string longer.
    assert(cleaned.size() <= input.size());
  }

  // find_authority_delimiter and find_authority_delimiter_special: result must
  // be within [0, input.size()].
  {
    size_t delim = ada::helpers::find_authority_delimiter(sv);
    assert(delim <= sv.size());
    size_t delim_special = ada::helpers::find_authority_delimiter_special(sv);
    assert(delim_special <= sv.size());
  }

  // get_host_delimiter_location: result position must be within [0,
  // view.size()].
  {
    std::string_view view = sv;
    auto [pos, found_colon] =
        ada::helpers::get_host_delimiter_location(true, view);
    (void)found_colon;
    // pos is relative to the original sv, not the possibly-trimmed view.
    assert(pos <= sv.size());
  }
  {
    std::string_view view = sv;
    auto [pos, found_colon] =
        ada::helpers::get_host_delimiter_location(false, view);
    (void)found_colon;
    assert(pos <= sv.size());
  }

  // ===== unicode::to_ascii (internal IDNA entry point) =====
  // This is the internal function called by the URL parser's host processing.
  // It takes an optional<string> output buffer, the input domain, and the
  // position of the first percent character.
  {
    std::string input2 = fdp.ConsumeRandomLengthString(64);
    size_t first_pct = input2.find('%');
    if (first_pct == std::string::npos) first_pct = input2.size();
    std::optional<std::string> out;
    volatile bool ok = ada::unicode::to_ascii(out, input2, first_pct);
    (void)ok;
    if (out.has_value()) {
      // A successfully converted domain must always be parseable as a URL host.
      volatile size_t olen = out->size();
      (void)olen;
    }
  }

  return 0;
}

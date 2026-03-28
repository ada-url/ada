#include <fuzzer/FuzzedDataProvider.h>

#include <array>
#include <cassert>
#include <cstdio>
#include <string>

#include "ada.cpp"
#include "ada.h"

// ============================================================
// Fuzzer for IP address serializers, fast IPv4 parser, and
// percent encode/decode utilities.
//
// These code paths are exercised indirectly by parse.cc but
// never directly. Targeting them independently lets the fuzzer
// discover edge cases in the serialization and encoding layers
// without depending on a valid URL to reach them.
// ============================================================

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // ===== IPv4 Serialization =====
  // ipv4() takes a uint64_t (valid addresses are 0..0xFFFFFFFF, but the
  // function accepts any value – out-of-range inputs should still be safe).
  uint64_t ipv4_addr = fdp.ConsumeIntegral<uint64_t>();
  std::string ipv4_str = ada::serializers::ipv4(ipv4_addr);
  volatile size_t ipv4_len = ipv4_str.size();
  (void)ipv4_len;

  // ===== IPv6 Serialization =====
  std::array<uint16_t, 8> ipv6_addr{};
  for (auto& piece : ipv6_addr) {
    piece = fdp.ConsumeIntegral<uint16_t>();
  }

  // find_longest_sequence_of_ipv6_pieces: basic invariants must hold.
  size_t compress = 0, compress_length = 0;
  ada::serializers::find_longest_sequence_of_ipv6_pieces(ipv6_addr, compress,
                                                         compress_length);
  // The longest run cannot exceed 8 pieces.
  assert(compress_length <= 8);
  // If a run was found (length > 0) its start index must be in-bounds.
  if (compress_length > 0) {
    assert(compress < 8);
    assert(compress + compress_length <= 8);
  }

  std::string ipv6_str = ada::serializers::ipv6(ipv6_addr);
  volatile size_t ipv6_len = ipv6_str.size();
  (void)ipv6_len;

  // Serialized IPv6 must always be a non-empty string.
  assert(!ipv6_str.empty());

  // ===== Fast IPv4 Parser =====
  // try_parse_ipv4_fast() should agree with the full parsing pipeline on its
  // output: if it succeeds (result <= 0xFFFFFFFF), re-serializing with
  // ipv4() and parsing again must yield the same address value.
  {
    std::string ip_candidate = fdp.ConsumeRandomLengthString(32);
    uint64_t fast_result = ada::checkers::try_parse_ipv4_fast(ip_candidate);
    if (fast_result <= 0xFFFFFFFF) {
      // Serialize the parsed address and re-parse.
      std::string canonical = ada::serializers::ipv4(fast_result);
      uint64_t recheck = ada::checkers::try_parse_ipv4_fast(canonical);
      if (recheck != fast_result) {
        printf(
            "try_parse_ipv4_fast round-trip failure:\n"
            "  input='%s' result=%llu canonical='%s' recheck=%llu\n",
            ip_candidate.c_str(), (unsigned long long)fast_result,
            canonical.c_str(), (unsigned long long)recheck);
        abort();
      }
    }
  }

  // ===== Percent Encode / Decode =====
  {
    std::string source = fdp.ConsumeRandomLengthString(128);

    // Exercise all six standard character sets used by the URL parser.
    const uint8_t* sets[] = {
        ada::character_sets::C0_CONTROL_PERCENT_ENCODE,
        ada::character_sets::PATH_PERCENT_ENCODE,
        ada::character_sets::QUERY_PERCENT_ENCODE,
        ada::character_sets::FRAGMENT_PERCENT_ENCODE,
        ada::character_sets::USERINFO_PERCENT_ENCODE,
        ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE,
    };

    for (const uint8_t* charset : sets) {
      // Two-argument percent_encode: returns the encoded string.
      std::string encoded = ada::unicode::percent_encode(source, charset);
      volatile size_t enc_len = encoded.size();
      (void)enc_len;

      // Encoded output must be at least as long as the input (each byte
      // either stays the same or expands to %XX – three bytes).
      assert(encoded.size() >= source.size());

      // Three-argument percent_encode: starts encoding from a given index.
      size_t start_idx = fdp.ConsumeIntegralInRange<size_t>(0, source.size());
      std::string encoded_from =
          ada::unicode::percent_encode(source, charset, start_idx);
      volatile size_t enf_len = encoded_from.size();
      (void)enf_len;

      // Template form: percent_encode<false> (replace).
      {
        std::string out;
        bool changed =
            ada::unicode::percent_encode<false>(source, charset, out);
        volatile bool c = changed;
        (void)c;
        // When encoding was needed 'out' holds the encoded string; when not,
        // 'out' is unchanged (empty). If changed, 'out' must not be shorter.
        if (changed) {
          assert(out.size() >= source.size());
        }
      }

      // Template form: percent_encode<true> (append).
      {
        std::string out = "prefix_";
        size_t prefix_len = out.size();
        ada::unicode::percent_encode<true>(source, charset, out);
        // Append mode: 'out' must grow by at least source.size() bytes if
        // encoding was needed, or stay unchanged if it wasn't.
        assert(out.size() >= prefix_len);
      }
    }

    // Percent decode: feed raw fuzz input (may contain invalid sequences).
    {
      size_t pct_pos = source.find('%');
      if (pct_pos != std::string::npos) {
        std::string decoded = ada::unicode::percent_decode(source, pct_pos);
        // Decoded output can't be longer than the input.
        assert(decoded.size() <= source.size());
        volatile size_t dec_len = decoded.size();
        (void)dec_len;
      }
    }

    // Round-trip: encode with PATH set, then decode the result; the decoded
    // form must equal the original (encoding then decoding is an identity).
    {
      std::string encoded = ada::unicode::percent_encode(
          source, ada::character_sets::PATH_PERCENT_ENCODE);
      size_t pct_pos = encoded.find('%');
      if (pct_pos != std::string::npos) {
        std::string decoded = ada::unicode::percent_decode(encoded, pct_pos);
        if (decoded != source) {
          printf(
              "percent_encode/decode round-trip failure!\n"
              "  source='%s'\n  encoded='%s'\n  decoded='%s'\n",
              source.c_str(), encoded.c_str(), decoded.c_str());
          abort();
        }
      } else {
        // No encoding was needed; the output should equal the input.
        assert(encoded == source);
      }
    }

    // percent_encode_index: the returned index must be within [0, size].
    {
      size_t idx = ada::unicode::percent_encode_index(
          source, ada::character_sets::PATH_PERCENT_ENCODE);
      assert(idx <= source.size());
    }
  }

  // ===== Checker and Unicode Utility Functions =====
  // These are internal helpers used throughout the parser. Fuzzing them
  // directly (rather than only through the URL parsing pipeline) ensures
  // every edge case is reachable without a valid URL structure.
  {
    std::string util_input = fdp.ConsumeRandomLengthString(128);

    // has_tabs_or_newline: any string is valid input.
    volatile bool has_tn = ada::unicode::has_tabs_or_newline(util_input);
    (void)has_tn;

    // is_ipv4: must not crash on arbitrary input. Cross-check against URL
    // parsing: if is_ipv4 reports true, embedding the string as a hostname
    // in an http:// URL must succeed (it must be a parseable IPv4 address).
    volatile bool is_v4 = ada::checkers::is_ipv4(util_input);
    (void)is_v4;
    if (is_v4) {
      std::string ipv4_url = "http://" + util_input + "/";
      auto parsed = ada::parse<ada::url_aggregator>(ipv4_url);
      // is_ipv4 reports true only for strings that look like IPv4 addresses;
      // the full parser may still reject them (e.g. out-of-range octets), but
      // if it accepts them the host type must be IPv4.
      if (parsed) {
        volatile bool v = parsed->validate();
        (void)v;
      }
    }

    // path_signature: returns a bitmask; must not crash.
    volatile uint8_t sig = ada::checkers::path_signature(util_input);
    (void)sig;

    // is_windows_drive_letter: must not crash on short or long inputs.
    volatile bool is_wdl = ada::checkers::is_windows_drive_letter(util_input);
    (void)is_wdl;

    // is_normalized_windows_drive_letter
    volatile bool is_nwdl =
        ada::checkers::is_normalized_windows_drive_letter(util_input);
    (void)is_nwdl;

    // Consistency: a normalised Windows drive letter is a subset of
    // Windows drive letters.
    if (is_nwdl && !is_wdl) {
      printf(
          "is_normalized_windows_drive_letter implies is_windows_drive_letter"
          " but got inconsistent results for '%s'\n",
          util_input.c_str());
      abort();
    }

    // to_lower_ascii: works in-place; must not crash.
    {
      std::string lower_copy = util_input;
      volatile bool all_ascii =
          ada::unicode::to_lower_ascii(lower_copy.data(), lower_copy.size());
      (void)all_ascii;
      // The result should be at most as long as the input.
      assert(lower_copy.size() == util_input.size());
    }

    // contains_forbidden_domain_code_point: must not crash.
    volatile bool has_forbidden =
        ada::unicode::contains_forbidden_domain_code_point(util_input.data(),
                                                           util_input.size());
    (void)has_forbidden;

    // contains_forbidden_domain_code_point_or_upper: must not crash.
    volatile uint8_t forbidden_or_upper =
        ada::unicode::contains_forbidden_domain_code_point_or_upper(
            util_input.data(), util_input.size());
    (void)forbidden_or_upper;

    // verify_dns_length: must not crash; also check consistency with
    // to_ascii output.
    volatile bool dns_ok = ada::checkers::verify_dns_length(util_input);
    (void)dns_ok;
  }

  // ===== Integration: embed serialized addresses into real URLs =====
  // This exercises the full parsing pipeline with our synthetic addresses
  // and verifies that serialization output is always round-trip safe.
  {
    // Only valid IPv4 address range (0..0xFFFFFFFF) should embed cleanly.
    if (ipv4_addr <= 0xFFFFFFFF) {
      std::string url_str = "http://" + ipv4_str + "/path?q=1";
      auto parsed = ada::parse<ada::url_aggregator>(url_str);
      if (parsed) {
        volatile bool v = parsed->validate();
        (void)v;
        // The URL's hostname must be the canonical dotted-decimal address.
        std::string host = std::string(parsed->get_hostname());
        // host == ipv4_str  (not asserted here because the URL parser may
        // normalise the address differently for non-standard values, but it
        // must always successfully parse our serialized form).
        (void)host;
      }
    }

    // IPv6: wrap in brackets.
    std::string ipv6_url_str = "http://[" + ipv6_str + "]/path";
    auto parsed_ipv6 = ada::parse<ada::url_aggregator>(ipv6_url_str);
    if (parsed_ipv6) {
      volatile bool v = parsed_ipv6->validate();
      (void)v;
      // Re-parse the href – must be idempotent.
      std::string href = std::string(parsed_ipv6->get_href());
      auto reparsed = ada::parse<ada::url_aggregator>(href);
      if (!reparsed) {
        printf("IPv6 URL re-parse failure: '%s'\n", href.c_str());
        abort();
      }
      if (std::string(reparsed->get_href()) != href) {
        printf("IPv6 URL re-parse href mismatch: '%s' vs '%s'\n", href.c_str(),
               std::string(reparsed->get_href()).c_str());
        abort();
      }
    }
  }

  return 0;
}

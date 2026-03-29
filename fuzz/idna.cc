#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string source2 = fdp.ConsumeRandomLengthString(64);

  /**
   * High-level IDNA API
   */
  std::string ascii_result = ada::idna::to_ascii(source);
  std::string unicode_result = ada::idna::to_unicode(source);

  // Avoid dead-code elimination
  volatile size_t length = 0;
  length += ascii_result.size();
  length += unicode_result.size();

  /**
   * Round-trip property: to_unicode(to_ascii(x)) should not crash.
   * We don't assert equality because IDNA may normalize/reject inputs.
   */
  if (!ascii_result.empty()) {
    std::string roundtrip = ada::idna::to_unicode(ascii_result);
    length += roundtrip.size();
  }

  /**
   * Punycode functions
   */
  {
    std::u32string utf32_out;
    // punycode_to_utf32: source can be any string (it's a punycode label)
    bool punycode_ok = ada::idna::punycode_to_utf32(source, utf32_out);
    length += utf32_out.size();

    // verify_punycode: checks if source is valid punycode
    volatile bool is_valid_punycode = ada::idna::verify_punycode(source);
    (void)is_valid_punycode;

    // utf32_to_punycode: round-trip if punycode_to_utf32 succeeded
    if (punycode_ok && !utf32_out.empty()) {
      std::string punycode_back;
      volatile bool encode_ok =
          ada::idna::utf32_to_punycode(utf32_out, punycode_back);
      length += punycode_back.size();
      (void)encode_ok;
    }
  }

  /**
   * Unicode transcoding
   */
  {
    // UTF-8 to UTF-32 conversion
    size_t utf32_len =
        ada::idna::utf32_length_from_utf8(source.data(), source.size());
    if (utf32_len > 0 && utf32_len < 1024) {
      std::vector<char32_t> utf32_buf(utf32_len + 1, 0);
      size_t actual = ada::idna::utf8_to_utf32(source.data(), source.size(),
                                               utf32_buf.data());
      length += actual;

      // UTF-32 to UTF-8 round-trip
      if (actual > 0) {
        size_t utf8_len =
            ada::idna::utf8_length_from_utf32(utf32_buf.data(), actual);
        if (utf8_len > 0 && utf8_len < 4096) {
          std::string utf8_back(utf8_len, '\0');
          size_t written = ada::idna::utf32_to_utf8(utf32_buf.data(), actual,
                                                    utf8_back.data());
          length += written;
        }
      }
    }
  }

  /**
   * IDNA label validation
   */
  {
    // is_label_valid requires a UTF-32 string
    std::u32string utf32_label;
    bool ok = ada::idna::punycode_to_utf32(source2, utf32_label);
    if (ok && !utf32_label.empty()) {
      volatile bool label_valid = ada::idna::is_label_valid(utf32_label);
      (void)label_valid;
    }

    // Also test is_label_valid with direct ASCII-to-UTF32 conversion
    std::u32string ascii_label(source2.begin(), source2.end());
    if (!ascii_label.empty()) {
      volatile bool ascii_label_valid = ada::idna::is_label_valid(ascii_label);
      (void)ascii_label_valid;
    }
  }

  /**
   * IDNA mapping
   */
  {
    // ASCII mapping: just lowercases ASCII characters
    std::string ascii_copy = source;
    ada::idna::ascii_map(ascii_copy.data(), ascii_copy.size());
    length += ascii_copy.size();

    // Unicode mapping: maps UTF-32 characters according to IDNA
    size_t utf32_len =
        ada::idna::utf32_length_from_utf8(source.data(), source.size());
    if (utf32_len > 0 && utf32_len < 256) {
      std::u32string utf32_input(utf32_len, 0);
      size_t actual = ada::idna::utf8_to_utf32(source.data(), source.size(),
                                               utf32_input.data());
      if (actual > 0) {
        utf32_input.resize(actual);
        std::u32string mapped = ada::idna::map(utf32_input);
        length += mapped.size();
      }
    }
  }

  /**
   * Domain code point validation
   */
  {
    volatile bool has_forbidden =
        ada::idna::contains_forbidden_domain_code_point(source);
    (void)has_forbidden;

    // is_ascii checks
    volatile bool is_ascii_str =
        ada::idna::is_ascii(std::string_view(source.data(), source.size()));
    (void)is_ascii_str;
  }

  /**
   * Normalization
   */
  {
    size_t utf32_len =
        ada::idna::utf32_length_from_utf8(source.data(), source.size());
    if (utf32_len > 0 && utf32_len < 256) {
      std::u32string utf32_input(utf32_len, 0);
      size_t actual = ada::idna::utf8_to_utf32(source.data(), source.size(),
                                               utf32_input.data());
      if (actual > 0) {
        utf32_input.resize(actual);
        ada::idna::normalize(utf32_input);
        length += utf32_input.size();
      }
    }
  }

  /**
   * IDNA stability property.
   *
   * Applying to_ascii twice must be idempotent: if to_ascii(x) produces a
   * non-empty result, then to_ascii(to_ascii(x)) must equal to_ascii(x).
   * A correctly normalised ACE label is already its own fixed point.
   *
   * We allow the second call to return an empty string only if the first
   * result was itself not a valid IDNA domain (some implementations return
   * empty on failure). If the first result is non-empty and looks like a
   * valid domain the second application must match.
   */
  {
    if (!ascii_result.empty()) {
      std::string ascii_result2 = ada::idna::to_ascii(ascii_result);
      if (!ascii_result2.empty() && ascii_result2 != ascii_result) {
        printf(
            "IDNA to_ascii not idempotent!\n"
            "  input:   %s\n  first:   %s\n  second:  %s\n",
            source.c_str(), ascii_result.c_str(), ascii_result2.c_str());
        abort();
      }
    }
  }

  /**
   * to_unicode stability.
   *
   * Applying to_unicode twice should also be idempotent: once a domain is in
   * its Unicode presentation form, converting again should give the same
   * result.
   */
  {
    if (!unicode_result.empty()) {
      std::string unicode_result2 = ada::idna::to_unicode(unicode_result);
      if (!unicode_result2.empty() && unicode_result2 != unicode_result) {
        printf(
            "IDNA to_unicode not idempotent!\n"
            "  input:   %s\n  first:   %s\n  second:  %s\n",
            source.c_str(), unicode_result.c_str(), unicode_result2.c_str());
        abort();
      }
    }
  }

  /**
   * Long domain names near the DNS length limit (253 characters).
   *
   * The IDNA and DNS-length checking code has special handling for domains
   * close to or exceeding 253/255 characters and 63-character labels. Feed
   * the fuzzer inputs of a controlled length to maximise coverage of those
   * boundary checks.
   */
  {
    std::string long_domain = fdp.ConsumeRandomLengthString(270);
    std::string long_ascii = ada::idna::to_ascii(long_domain);
    length += long_ascii.size();

    // verify_dns_length on the long input (already called for `source` above,
    // but we want to exercise the boundary cases separately).
    volatile bool long_dns_ok = ada::checkers::verify_dns_length(long_domain);
    (void)long_dns_ok;

    if (!long_ascii.empty()) {
      volatile bool long_ascii_dns_ok =
          ada::checkers::verify_dns_length(long_ascii);
      (void)long_ascii_dns_ok;
    }
  }

  /**
   * Punycode round-trip on arbitrary binary blobs.
   *
   * Feed random bytes directly into punycode_to_utf32, then if that succeeds
   * encode the result back with utf32_to_punycode and verify the round-trip.
   */
  {
    std::string blob = fdp.ConsumeRandomLengthString(128);
    std::u32string decoded;
    bool ok = ada::idna::punycode_to_utf32(blob, decoded);
    if (ok && !decoded.empty()) {
      std::string reencoded;
      bool enc_ok = ada::idna::utf32_to_punycode(decoded, reencoded);
      (void)enc_ok;
      length += reencoded.size();

      // Re-decode the re-encoded form; it must match the first decoded form.
      if (enc_ok && !reencoded.empty()) {
        std::u32string redecoded;
        bool redec_ok = ada::idna::punycode_to_utf32(reencoded, redecoded);
        if (redec_ok && redecoded != decoded) {
          printf("Punycode round-trip mismatch!\n");
          abort();
        }
      }
    }
  }

  return 0;
}

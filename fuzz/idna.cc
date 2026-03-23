#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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

  return 0;
}

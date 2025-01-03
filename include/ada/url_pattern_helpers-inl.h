/**
 * @file url_pattern_helpers-inl.h
 * @brief Declaration for the URLPattern helpers.
 */
#ifndef ADA_URL_PATTERN_HELPERS_INL_H
#define ADA_URL_PATTERN_HELPERS_INL_H

#include "ada/common_defs.h"
#include "ada/expected.h"
#include "ada/url_pattern_helpers.h"
#include "ada/implementation.h"

namespace ada::url_pattern_helpers {

inline void Tokenizer::get_next_code_point() {
  ada_log("Tokenizer::get_next_code_point called with next_index=", next_index);
  ADA_ASSERT_TRUE(next_index < input.size());
  // this assumes that we have a valid, non-truncated UTF-8 stream.
  code_point = 0;
  size_t number_bytes = 0;
  unsigned char first_byte = input[next_index];

  if ((first_byte & 0x80) == 0) {
    // 1-byte character (ASCII)
    next_index++;
    code_point = first_byte;
    ada_log("Tokenizer::get_next_code_point returning ASCII code point=",
            uint32_t(code_point));
    ada_log("Tokenizer::get_next_code_point next_index =", next_index,
            " input.size()=", input.size());
    return;
  }
  ada_log("Tokenizer::get_next_code_point read first byte=",
          uint32_t(first_byte));
  if ((first_byte & 0xE0) == 0xC0) {
    code_point = first_byte & 0x1F;
    number_bytes = 2;
    ada_log("Tokenizer::get_next_code_point two bytes");
  } else if ((first_byte & 0xF0) == 0xE0) {
    code_point = first_byte & 0x0F;
    number_bytes = 3;
    ada_log("Tokenizer::get_next_code_point three bytes");
  } else if ((first_byte & 0xF8) == 0xF0) {
    code_point = first_byte & 0x07;
    number_bytes = 4;
    ada_log("Tokenizer::get_next_code_point four bytes");
  }
  ADA_ASSERT_TRUE(number_bytes + next_index <= input.size());

  for (size_t i = 1 + next_index; i < number_bytes + next_index; ++i) {
    unsigned char byte = input[i];
    ada_log("Tokenizer::get_next_code_point read byte=", uint32_t(byte));
    code_point = (code_point << 6) | (byte & 0x3F);
  }
  ada_log("Tokenizer::get_next_code_point returning non-ASCII code point=",
          uint32_t(code_point));
  ada_log("Tokenizer::get_next_code_point next_index =", next_index,
          " input.size()=", input.size());
  next_index += number_bytes;
}

inline void Tokenizer::seek_and_get_next_code_point(size_t new_index) {
  ada_log("Tokenizer::seek_and_get_next_code_point called with new_index=",
          new_index);
  // Set tokenizer’s next index to index.
  next_index = new_index;
  // Run get the next code point given tokenizer.
  get_next_code_point();
}

inline void Tokenizer::add_token(token_type type, size_t next_position,
                                 size_t value_position, size_t value_length) {
  ADA_ASSERT_TRUE(next_position >= value_position);

  // Let token be a new token.
  // Set token’s type to type.
  // Set token’s index to tokenizer’s index.
  // Set token’s value to the code point substring from value position with
  // length value length within tokenizer’s input.
  // Append token to the back of tokenizer’s token list.
  token_list.emplace_back(type, index,
                          input.substr(value_position, value_length));
  // Set tokenizer’s index to next position.
  index = next_position;
}

inline void Tokenizer::add_token_with_default_length(token_type type,
                                                     size_t next_position,
                                                     size_t value_position) {
  // Let computed length be next position − value position.
  auto computed_length = next_position - value_position;
  // Run add a token given tokenizer, type, next position, value position, and
  // computed length.
  add_token(type, next_position, value_position, computed_length);
}

inline void Tokenizer::add_token_with_defaults(token_type type) {
  // Run add a token with default length given tokenizer, type, tokenizer’s next
  // index, and tokenizer’s index.
  add_token_with_default_length(type, next_index, index);
}

inline ada_warn_unused std::optional<errors>
Tokenizer::process_tokenizing_error(size_t next_position,
                                    size_t value_position) {
  // If tokenizer’s policy is "strict", then throw a TypeError.
  if (policy == token_policy::STRICT) {
    ada_log("process_tokenizing_error failed with next_position=",
            next_position, " value_position=", value_position);
    return errors::type_error;
  }
  // Assert: tokenizer’s policy is "lenient".
  ADA_ASSERT_TRUE(policy == token_policy::LENIENT);
  // Run add a token with default length given tokenizer, "invalid-char", next
  // position, and value position.
  add_token_with_default_length(token_type::INVALID_CHAR, next_position,
                                value_position);
  return std::nullopt;
}
}  // namespace ada::url_pattern_helpers
#endif

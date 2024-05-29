#include <fuzzer/FuzzedDataProvider.h>

#include <cstdio>
#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

bool is_valid_utf8_string(const char *buf, size_t len) {
  const uint8_t *data = reinterpret_cast<const uint8_t *>(buf);
  uint64_t pos = 0;
  uint32_t code_point = 0;
  while (pos < len) {
    uint64_t next_pos = pos + 16;
    if (next_pos <= len) {  // if it is safe to read 16 more bytes, check that
                            // they are ascii
      uint64_t v1;
      std::memcpy(&v1, data + pos, sizeof(uint64_t));
      uint64_t v2;
      std::memcpy(&v2, data + pos + sizeof(uint64_t), sizeof(uint64_t));
      uint64_t v{v1 | v2};
      if ((v & 0x8080808080808080) == 0) {
        pos = next_pos;
        continue;
      }
    }
    unsigned char byte = data[pos];
    while (byte < 0b10000000) {
      if (++pos == len) {
        return true;
      }
      byte = data[pos];
    }

    if ((byte & 0b11100000) == 0b11000000) {
      next_pos = pos + 2;
      if (next_pos > len) {
        return false;
      }
      if ((data[pos + 1] & 0b11000000) != 0b10000000) {
        return false;
      }
      code_point = (byte & 0b00011111) << 6 | (data[pos + 1] & 0b00111111);
      if ((code_point < 0x80) || (0x7ff < code_point)) {
        return false;
      }
    } else if ((byte & 0b11110000) == 0b11100000) {
      next_pos = pos + 3;
      if (next_pos > len) {
        return false;
      }
      if ((data[pos + 1] & 0b11000000) != 0b10000000) {
        return false;
      }
      if ((data[pos + 2] & 0b11000000) != 0b10000000) {
        return false;
      }
      code_point = (byte & 0b00001111) << 12 |
                   (data[pos + 1] & 0b00111111) << 6 |
                   (data[pos + 2] & 0b00111111);
      if ((code_point < 0x800) || (0xffff < code_point) ||
          (0xd7ff < code_point && code_point < 0xe000)) {
        return false;
      }
    } else if ((byte & 0b11111000) == 0b11110000) {  // 0b11110000
      next_pos = pos + 4;
      if (next_pos > len) {
        return false;
      }
      if ((data[pos + 1] & 0b11000000) != 0b10000000) {
        return false;
      }
      if ((data[pos + 2] & 0b11000000) != 0b10000000) {
        return false;
      }
      if ((data[pos + 3] & 0b11000000) != 0b10000000) {
        return false;
      }
      code_point =
          (byte & 0b00000111) << 18 | (data[pos + 1] & 0b00111111) << 12 |
          (data[pos + 2] & 0b00111111) << 6 | (data[pos + 3] & 0b00111111);
      if (code_point <= 0xffff || 0x10ffff < code_point) {
        return false;
      }
    } else {
      return false;
    }
    pos = next_pos;
  }
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);

  // volatile forces the compiler to store the results without undue
  // optimizations
  volatile size_t length = 0;

  auto parse_url = ada::parse<ada::url>(source);
  auto parse_url_aggregator = ada::parse<ada::url_aggregator>(source);

  if (is_valid_utf8_string(source.data(), source.length())) {
    if (parse_url.has_value() ^ parse_url_aggregator.has_value()) {
      printf("Source used to parse: %s", source.c_str());
      abort();
    }
  }

  if (parse_url) {
    length += parse_url->get_href().size();
  }

  if (parse_url_aggregator) {
    length += parse_url_aggregator->get_href().size();

    assert(parse_url->get_protocol() == parse_url_aggregator->get_protocol());
    assert(parse_url->get_href() == parse_url_aggregator->get_href());

    parse_url->set_href(source);
    parse_url_aggregator->set_href(source);
    assert(parse_url->get_href() == parse_url_aggregator->get_href());
  }

  /**
   * ada::parse<ada::url>
   */
  auto out_url = ada::parse<ada::url>("https://www.ada-url.com");

  if (out_url) {
    out_url->set_protocol(source);
    out_url->set_username(source);
    out_url->set_password(source);
    out_url->set_hostname(source);
    out_url->set_host(source);
    out_url->set_pathname(source);
    out_url->set_search(source);
    out_url->set_hash(source);
    out_url->set_port(source);

    // getters
    length += out_url->get_protocol().size();
    length += out_url->get_username().size();
    length += out_url->get_password().size();
    length += out_url->get_hostname().size();
    length += out_url->get_host().size();
    length += out_url->get_pathname().size();
    length += out_url->get_search().size();
    length += out_url->get_hash().size();
    length += out_url->get_origin().size();
    length += out_url->get_port().size();

    length += out_url->to_string().size();
  }

  /**
   * ada::parse<ada::url_aggregator>
   */
  auto out_aggregator =
      ada::parse<ada::url_aggregator>("https://www.ada-url.com");

  if (out_aggregator) {
    out_aggregator->set_protocol(source);
    out_aggregator->set_username(source);
    out_aggregator->set_password(source);
    out_aggregator->set_hostname(source);
    out_aggregator->set_host(source);
    out_aggregator->set_pathname(source);
    out_aggregator->set_search(source);
    out_aggregator->set_hash(source);
    out_aggregator->set_port(source);

    // getters
    length += out_aggregator->get_protocol().size();
    length += out_aggregator->get_username().size();
    length += out_aggregator->get_password().size();
    length += out_aggregator->get_hostname().size();
    length += out_aggregator->get_host().size();
    length += out_aggregator->get_pathname().size();
    length += out_aggregator->get_search().size();
    length += out_aggregator->get_hash().size();
    length += out_aggregator->get_origin().size();
    length += out_aggregator->get_port().size();

    volatile bool is_output_valid = false;
    length += out_aggregator->to_string().size();
    is_output_valid = out_aggregator->validate();

    // Printing due to dead-code elimination
    printf("diagram %s\n", out_aggregator->to_diagram().c_str());

    // clear methods
    out_aggregator->clear_port();
    out_aggregator->clear_search();
    out_aggregator->clear_hash();
  }

  /**
   * Node.js specific
   */
  length += ada::href_from_file(source).size();

  /**
   * Others
   */
  bool is_valid = ada::checkers::verify_dns_length(source);

  // Only used for avoiding dead-code elimination
  if (is_valid) {
    printf("dns length is valid\n");
  }

  // Only used for avoiding dead-code elimination
  printf("length of url is %d\n", length);

  return 0;
}  // extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

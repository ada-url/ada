#include <fuzzer/FuzzedDataProvider.h>

#include <cassert>
#include <cstdio>
#include <memory>
#include <string>

#include "ada.cpp"
#include "ada.h"

bool is_valid_utf8_string(const char* buf, size_t len) {
  const uint8_t* data = reinterpret_cast<const uint8_t*>(buf);
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

// Exercise all getters and boolean predicates on ada::url
static void exercise_url_predicates(const ada::url& u) {
  volatile size_t length = 0;
  length += u.get_href().size();
  length += u.get_origin().size();
  length += u.get_protocol().size();
  length += u.get_username().size();
  length += u.get_password().size();
  length += u.get_host().size();
  length += u.get_hostname().size();
  length += u.get_pathname().size();
  length += u.get_search().size();
  length += u.get_hash().size();
  length += u.get_port().size();
  length += u.to_string().size();
  length += u.get_pathname_length();
  (void)u.has_valid_domain();
  (void)u.has_credentials();
  (void)u.has_empty_hostname();
  (void)u.has_hostname();
  (void)u.has_port();
  (void)u.has_hash();
  (void)u.has_search();
  (void)u.get_components();
}

// Exercise all getters and boolean predicates on ada::url_aggregator
static void exercise_aggregator_predicates(const ada::url_aggregator& u) {
  volatile size_t length = 0;
  length += u.get_href().size();
  length += u.get_origin().size();
  length += u.get_protocol().size();
  length += u.get_username().size();
  length += u.get_password().size();
  length += u.get_host().size();
  length += u.get_hostname().size();
  length += u.get_pathname().size();
  length += u.get_search().size();
  length += u.get_hash().size();
  length += u.get_port().size();
  length += u.to_string().size();
  length += u.get_pathname_length();
  (void)u.has_valid_domain();
  (void)u.has_credentials();
  (void)u.has_empty_hostname();
  (void)u.has_hostname();
  (void)u.has_non_empty_username();
  (void)u.has_non_empty_password();
  (void)u.has_password();
  (void)u.has_port();
  (void)u.has_hash();
  (void)u.has_search();
  (void)u.get_components();
  volatile bool is_valid = u.validate();
  (void)is_valid;
  (void)u.to_diagram();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string source = fdp.ConsumeRandomLengthString(256);
  std::string base = fdp.ConsumeRandomLengthString(256);

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
    length += parse_url->get_origin().size();
  }

  if (parse_url_aggregator) {
    length += parse_url_aggregator->get_href().size();
    length += parse_url_aggregator->get_origin().size();

    volatile bool is_parse_url_aggregator_output_valid = false;
    is_parse_url_aggregator_output_valid = parse_url_aggregator->validate();

    assert(parse_url->get_protocol() == parse_url_aggregator->get_protocol());
    assert(parse_url->get_href() == parse_url_aggregator->get_href());
    assert(std::string(parse_url->get_hostname()) ==
           std::string(parse_url_aggregator->get_hostname()));
    assert(std::string(parse_url->get_pathname()) ==
           std::string(parse_url_aggregator->get_pathname()));
    assert(std::string(parse_url->get_search()) ==
           std::string(parse_url_aggregator->get_search()));
    assert(std::string(parse_url->get_hash()) ==
           std::string(parse_url_aggregator->get_hash()));
    assert(std::string(parse_url->get_port()) ==
           std::string(parse_url_aggregator->get_port()));
    assert(parse_url->get_username() ==
           std::string(parse_url_aggregator->get_username()));
    assert(parse_url->get_password() ==
           std::string(parse_url_aggregator->get_password()));
    assert(std::string(parse_url->get_host()) ==
           std::string(parse_url_aggregator->get_host()));

    // Exercise all predicates on both types
    exercise_url_predicates(*parse_url);
    exercise_aggregator_predicates(*parse_url_aggregator);

    // Test set_href consistency
    parse_url->set_href(source);
    parse_url_aggregator->set_href(source);
    assert(parse_url->get_href() == parse_url_aggregator->get_href());
  }

  /**
   * Test copy and move semantics
   */
  if (parse_url) {
    // Copy constructor
    ada::url copied_url = *parse_url;
    assert(copied_url.get_href() == parse_url->get_href());

    // Copy assignment
    ada::url assigned_url;
    assigned_url = *parse_url;
    assert(assigned_url.get_href() == parse_url->get_href());

    // Move constructor
    ada::url moved_url = std::move(copied_url);
    assert(moved_url.get_href() == parse_url->get_href());
  }

  if (parse_url_aggregator) {
    // Copy constructor
    ada::url_aggregator copied_agg = *parse_url_aggregator;
    assert(std::string(copied_agg.get_href()) ==
           std::string(parse_url_aggregator->get_href()));

    // Copy assignment
    ada::url_aggregator assigned_agg;
    assigned_agg = *parse_url_aggregator;
    assert(std::string(assigned_agg.get_href()) ==
           std::string(parse_url_aggregator->get_href()));

    // Move constructor
    ada::url_aggregator moved_agg = std::move(copied_agg);
    assert(std::string(moved_agg.get_href()) ==
           std::string(parse_url_aggregator->get_href()));

    // Move assignment
    ada::url_aggregator move_assigned_agg;
    move_assigned_agg = std::move(assigned_agg);
    assert(std::string(move_assigned_agg.get_href()) ==
           std::string(parse_url_aggregator->get_href()));
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
    length += out_url->get_pathname_length();

    length += out_url->to_string().size();

    // boolean predicates after setters
    (void)out_url->has_valid_domain();
    (void)out_url->has_credentials();
    (void)out_url->has_empty_hostname();
    (void)out_url->has_hostname();
    (void)out_url->has_port();
    (void)out_url->has_hash();
    (void)out_url->has_search();
    (void)out_url->get_components();
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
    length += out_aggregator->get_pathname_length();

    length += out_aggregator->to_string().size();

    volatile bool is_output_valid = false;
    is_output_valid = out_aggregator->validate();

    (void)out_aggregator->to_diagram();

    // boolean predicates after setters
    (void)out_aggregator->has_valid_domain();
    (void)out_aggregator->has_credentials();
    (void)out_aggregator->has_empty_hostname();
    (void)out_aggregator->has_hostname();
    (void)out_aggregator->has_non_empty_username();
    (void)out_aggregator->has_non_empty_password();
    (void)out_aggregator->has_password();
    (void)out_aggregator->has_port();
    (void)out_aggregator->has_hash();
    (void)out_aggregator->has_search();
    (void)out_aggregator->get_components();

    // clear methods + postcondition assertions
    out_aggregator->clear_port();
    if (out_aggregator->has_port()) {
      printf("clear_port() did not clear has_port()\n");
      abort();
    }
    if (!out_aggregator->get_port().empty()) {
      printf("clear_port() left non-empty get_port()\n");
      abort();
    }

    out_aggregator->clear_search();
    if (out_aggregator->has_search()) {
      printf("clear_search() did not clear has_search()\n");
      abort();
    }
    if (!out_aggregator->get_search().empty()) {
      printf("clear_search() left non-empty get_search()\n");
      abort();
    }

    out_aggregator->clear_hash();
    if (out_aggregator->has_hash()) {
      printf("clear_hash() did not clear has_hash()\n");
      abort();
    }
    if (!out_aggregator->get_hash().empty()) {
      printf("clear_hash() left non-empty get_hash()\n");
      abort();
    }
  }

  /**
   * Relative URL parsing with base (tests the base URL resolution code path)
   */
  auto base_url = ada::parse<ada::url>(base);
  auto base_agg = ada::parse<ada::url_aggregator>(base);

  if (base_url) {
    auto result = ada::parse<ada::url>(source, &*base_url);
    if (result) {
      length += result->get_href().size();
      length += result->get_origin().size();
      exercise_url_predicates(*result);
    }
  }

  if (base_agg) {
    auto result = ada::parse<ada::url_aggregator>(source, &*base_agg);
    if (result) {
      length += result->get_href().size();
      length += result->get_origin().size();
      exercise_aggregator_predicates(*result);
    }
  }

  // Cross-type consistency: relative URL parsing with a base should agree
  // between url and url_aggregator representations for valid UTF-8 inputs.
  if (is_valid_utf8_string(source.data(), source.length()) &&
      is_valid_utf8_string(base.data(), base.length()) && base_url &&
      base_agg) {
    auto res_url = ada::parse<ada::url>(source, &*base_url);
    auto res_agg = ada::parse<ada::url_aggregator>(source, &*base_agg);
    if (res_url.has_value() ^ res_agg.has_value()) {
      printf("Relative parse inconsistency for source=%s base=%s\n",
             source.c_str(), base.c_str());
      abort();
    }
    if (res_url && res_agg) {
      if (res_url->get_href() != std::string(res_agg->get_href())) {
        printf("Relative parse href mismatch for source=%s base=%s\n",
               source.c_str(), base.c_str());
        abort();
      }
    }
  }

  /**
   * Chained relative URL resolution: parse source against base, then use the
   * result as the base for a second parse. Exercises multi-level inheritance.
   */
  if (base_agg) {
    auto level1 = ada::parse<ada::url_aggregator>(source, &*base_agg);
    if (level1) {
      std::string input2 = fdp.ConsumeRandomLengthString(128);
      auto level2 = ada::parse<ada::url_aggregator>(input2, &*level1);
      if (level2) {
        length += level2->get_href().size();
        volatile bool v = level2->validate();
        (void)v;
      }
    }
  }

  /**
   * Known-good base URL with fuzzed relative input. Using a fixed valid base
   * lets the fuzzer focus entropy entirely on the relative-input code paths
   * (path resolution, query/fragment inheritance, scheme-relative URLs, etc.)
   */
  {
    auto known_base =
        ada::parse<ada::url_aggregator>("https://example.com/a/b/c?query#hash");
    if (known_base) {
      auto result = ada::parse<ada::url_aggregator>(source, &*known_base);
      if (result) {
        length += result->get_href().size();
        exercise_aggregator_predicates(*result);
      }
    }
  }

  /**
   * Node.js specific
   */
  length += ada::href_from_file(source).size();

  /**
   * Others
   */
  bool is_valid = ada::checkers::verify_dns_length(source);

  (void)is_valid;

  /**
   * Sequential setter interactions with FDP-controlled ordering.
   *
   * The existing code calls every setter with the same `source` value in a
   * fixed order. Here we let the fuzzer choose an arbitrary sequence of
   * setter/value pairs, checking that url and url_aggregator stay in sync
   * after every step. This exercises setter-interaction state bugs that
   * fixed-order testing would miss.
   */
  {
    auto url_seq = ada::parse<ada::url>(
        "https://user:pass@example.com:8080/path?query=1#hash");
    auto agg_seq = ada::parse<ada::url_aggregator>(
        "https://user:pass@example.com:8080/path?query=1#hash");
    if (url_seq && agg_seq) {
      int steps = fdp.ConsumeIntegralInRange(1, 8);
      for (int i = 0; i < steps; ++i) {
        std::string val = fdp.ConsumeRandomLengthString(64);
        int which = fdp.ConsumeIntegralInRange(0, 8);
        switch (which) {
          case 0:
            url_seq->set_protocol(val);
            agg_seq->set_protocol(val);
            break;
          case 1:
            url_seq->set_username(val);
            agg_seq->set_username(val);
            break;
          case 2:
            url_seq->set_password(val);
            agg_seq->set_password(val);
            break;
          case 3:
            url_seq->set_hostname(val);
            agg_seq->set_hostname(val);
            break;
          case 4:
            url_seq->set_host(val);
            agg_seq->set_host(val);
            break;
          case 5:
            url_seq->set_pathname(val);
            agg_seq->set_pathname(val);
            break;
          case 6:
            url_seq->set_search(val);
            agg_seq->set_search(val);
            break;
          case 7:
            url_seq->set_hash(val);
            agg_seq->set_hash(val);
            break;
          case 8:
            url_seq->set_port(val);
            agg_seq->set_port(val);
            break;
        }
        // After every setter both representations must agree on href.
        if (url_seq->get_href() != std::string(agg_seq->get_href())) {
          printf(
              "Sequential setter href mismatch after setter=%d val='%s'\n"
              "  url:  %s\n  agg:  %s\n",
              which, val.c_str(), url_seq->get_href().c_str(),
              std::string(agg_seq->get_href()).c_str());
          abort();
        }
        // url_aggregator internal invariant must still hold.
        volatile bool v = agg_seq->validate();
        (void)v;
      }
    }
  }

  /**
   * Re-parse idempotency.
   *
   * If parse(source) succeeds, then parse(href) must also succeed and
   * produce the same href. Serialization and parsing must be consistent:
   * a normalized URL is always its own fixed point.
   */
  if (parse_url_aggregator) {
    std::string href1 = std::string(parse_url_aggregator->get_href());
    auto reparsed = ada::parse<ada::url_aggregator>(href1);
    if (!reparsed) {
      printf("Re-parse of href failed unexpectedly: '%s'\n", href1.c_str());
      abort();
    }
    std::string href2 = std::string(reparsed->get_href());
    if (href1 != href2) {
      printf(
          "Re-parse idempotency failure!\n"
          "  href1: %s\n  href2: %s\n",
          href1.c_str(), href2.c_str());
      abort();
    }
  }

  /**
   * URL search params round-trip via URL integration.
   *
   * Construct a URL whose query is the fuzz source, extract the search
   * component as a url_search_params, mutate it, serialise it back, and
   * set it on the URL. Exercises the interaction between URL objects and
   * url_search_params and verifies that the combined pipeline doesn't crash.
   *
   * Also verifies the url_search_params serialisation idempotency property:
   *   url_search_params(sp.to_string()).to_string() == sp.to_string()
   */
  {
    std::string search_url = "https://example.com/?" + source;
    auto url_with_search = ada::parse<ada::url_aggregator>(search_url);
    if (url_with_search) {
      // Extract the search string (may include leading '?').
      std::string search_raw = std::string(url_with_search->get_search());
      std::string_view search_view = search_raw;
      if (!search_view.empty() && search_view[0] == '?') {
        search_view = search_view.substr(1);
      }

      ada::url_search_params sp(search_view);

      // Mutate with additional entries from the fuzz corpus.
      sp.append(source, base);

      std::string serialized = sp.to_string();

      // Idempotency: re-parsing the serialised form must yield the same string.
      ada::url_search_params sp2(serialized);
      std::string serialized2 = sp2.to_string();
      if (serialized2 != serialized) {
        printf(
            "url_search_params serialisation not idempotent!\n"
            "  first:  %s\n  second: %s\n",
            serialized.c_str(), serialized2.c_str());
        abort();
      }

      // Set the serialised params back on the URL.
      url_with_search->set_search(serialized);
      volatile bool v = url_with_search->validate();
      (void)v;
    }
  }

  return 0;
}  // extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

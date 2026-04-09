#include "ada.h"
#include <iostream>
#include <memory>
#include <bit>
#include <cstring>

extern "C" {
#include "ada_c.h"
}

static constexpr size_t kUrlExamplesCount = 20;
std::string url_examples[] = {
    "https://www.google.com/"
    "webhp?hl=en&amp;ictx=2&amp;sa=X&amp;ved=0ahUKEwil_"
    "oSxzJj8AhVtEFkFHTHnCGQQPQgI",
    "https://support.google.com/websearch/"
    "?p=ws_results_help&amp;hl=en-CA&amp;fg=1",
    "https://en.wikipedia.org/wiki/Dog#Roles_with_humans",
    "https://www.tiktok.com/@aguyandagolden/video/7133277734310038830",
    "https://business.twitter.com/en/help/troubleshooting/"
    "how-twitter-ads-work.html?ref=web-twc-ao-gbl-adsinfo&utm_source=twc&utm_"
    "medium=web&utm_campaign=ao&utm_content=adsinfo",
    "https://images-na.ssl-images-amazon.com/images/I/"
    "41Gc3C8UysL.css?AUIClients/AmazonGatewayAuiAssets",
    "https://www.reddit.com/?after=t3_zvz1ze",
    "https://www.reddit.com/login/?dest=https%3A%2F%2Fwww.reddit.com%2F",
    "postgresql://other:9818274x1!!@localhost:5432/"
    "otherdb?connect_timeout=10&application_name=myapp",
    "http://192.168.1.1",             // ipv4
    "http://[2606:4700:4700::1111]",  // ipv6
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/js/"
    "polyfills.js",
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/"
    "css/orbit-v5-ltr.min.css",
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/js/"
    "require.min.js",
    "https://static.files.bbci.co.uk/fonts/reith/2.512/BBCReithSans_W_Rg.woff2",
    "https://nav.files.bbci.co.uk/searchbox/c8bfe8595e453f2b9483fda4074e9d15/"
    "css/box.css",
    "https://static.files.bbci.co.uk/cookies/d3bb303e79f041fec95388e04f84e716/"
    "cookie-banner/cookie-library.bundle.js",
    "https://static.files.bbci.co.uk/account/id-cta/597/style/id-cta.css",
    "https://gn-web-assets.api.bbc.com/wwhp/"
    "20220908-1153-091014d07889c842a7bdc06e00fa711c9e04f049/responsive/css/"
    "old-ie.min.css",
    "https://gn-web-assets.api.bbc.com/wwhp/"
    "20220908-1153-091014d07889c842a7bdc06e00fa711c9e04f049/modules/vendor/"
    "bower/modernizr/modernizr.js"};

static_assert(sizeof(url_examples) / sizeof(std::string) == kUrlExamplesCount,
              "update kUrlExamplesCount");

// This function copies your input onto a memory buffer that
// has just the necessary size. This will entice tools to detect
// an out-of-bound access.
template <class result>
ada::result<result> ada_parse(std::string_view view) {
  std::unique_ptr<char[]> buffer(new char[view.size()]);
  memcpy(buffer.get(), view.data(), view.size());
  return ada::parse<result>(std::string_view(buffer.get(), view.size()));
}

template <class result>
size_t fancy_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    std::string copy =
        url_examples[(seed++) % (sizeof(url_examples) / sizeof(std::string))];
    auto url = ada::parse<result>(copy);
    while (url) {
      // mutate the string.
      int k = ((321321 * counter++) % 3);
      switch (k) {
        case 0:
          copy.erase((11134 * counter++) % copy.size());
          break;
        case 1:
          copy.insert(copy.begin() + (211311 * counter) % copy.size(),
                      char((counter + 1) * 777));
          counter += 2;
          break;
        case 2:
          copy[(13134 * counter++) % copy.size()] = char(counter++ * 71117);
          break;
        default:
          break;
      }
      url = ada_parse<result>(copy);
    }
  }
  return counter;
}

template <class result>
size_t simple_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    std::string copy =
        url_examples[(seed++) % (sizeof(url_examples) / sizeof(std::string))];
    auto url = ada::parse<result>(copy);
    while (url) {
      // mutate the string.
      copy[(13134 * counter++) % copy.size()] = char(counter++ * 71117);
      url = ada_parse<result>(copy);
    }
  }
  return counter;
}

template <class result>
size_t roller_fuzz(size_t N) {
  size_t valid{};

  for (std::string copy : url_examples) {
    for (size_t index = 0; index < copy.size(); index++) {
      char orig = copy[index];
      for (unsigned int value = 0; value < 255; value++) {
        copy[index] = char(value);
        auto url = ada_parse<result>(copy);
        if (url) {
          valid++;
        }
      }
      copy[index] = orig;
    }
  }
  return valid;
}

// ============================================================================
// C API fuzzing
// ============================================================================

// Pool of setter mutation values covering a range of valid and invalid inputs.
static const char* const kSetterMutations[] = {
    "",
    "x",
    "new-host.example.com",
    "changed.example.org",
    "localhost",
    "127.0.0.1",
    "[::1]",
    "https:",
    "http:",
    "ftp:",
    "ws:",
    "wss:",
    "file:",
    "/new-path",
    "/path/to/resource",
    "?new-query",
    "?key=value&other=123",
    "#new-hash",
    "#",
    "user",
    "p%40ss",
    "8080",
    "443",
    "0",
    "65535",
    "99999",
    "-1",
    "notaport",
};
static constexpr size_t kSetterMutationsCount =
    sizeof(kSetterMutations) / sizeof(kSetterMutations[0]);

// Exercises every getter, predicate, and component accessor on a URL.
// Deliberately discards all return values: the goal is to catch
// buffer-overreads / crashes / undefined behaviour on valid and mutated URLs.
static void c_api_exercise_all_reads(ada_url url) {
  if (!ada_is_valid(url)) {
    return;
  }

  // Getters that return an owned (heap-allocated) string.
  ada_owned_string origin = ada_get_origin(url);
  ada_free_owned_string(origin);

  // Getters that return non-owning views into the URL buffer.
  (void)ada_get_href(url);
  (void)ada_get_username(url);
  (void)ada_get_password(url);
  (void)ada_get_port(url);
  (void)ada_get_hash(url);
  (void)ada_get_host(url);
  (void)ada_get_hostname(url);
  (void)ada_get_pathname(url);
  (void)ada_get_search(url);
  (void)ada_get_protocol(url);

  // Type accessors.
  (void)ada_get_host_type(url);
  (void)ada_get_scheme_type(url);

  // Component offsets struct.
  (void)ada_get_components(url);

  // Boolean predicates.
  (void)ada_has_credentials(url);
  (void)ada_has_empty_hostname(url);
  (void)ada_has_hostname(url);
  (void)ada_has_non_empty_username(url);
  (void)ada_has_non_empty_password(url);
  (void)ada_has_port(url);
  (void)ada_has_password(url);
  (void)ada_has_hash(url);
  (void)ada_has_search(url);
}

// Mutates `copy` in one of three ways and returns the updated counter.
static size_t mutate_string(std::string& copy, size_t counter) {
  if (copy.empty()) {
    copy = "https://example.com/";
    return counter + 1;
  }
  int k = static_cast<int>((321321 * counter++) % 3);
  switch (k) {
    case 0:
      copy.erase((11134 * counter++) % copy.size());
      break;
    case 1:
      copy.insert(copy.begin() +
                      static_cast<std::ptrdiff_t>((211311 * counter) %
                                                  copy.size()),
                  static_cast<char>((counter + 1) * 777));
      counter += 2;
      break;
    case 2:
      copy[(13134 * counter++) % copy.size()] =
          static_cast<char>(counter++ * 71117);
      break;
    default:
      break;
  }
  return counter;
}

/**
 * Parses mutations of URL examples via the C API and exercises every getter
 * and predicate on each valid result.  Mirrors fancy_fuzz() but uses the
 * C API throughout.
 */
size_t c_api_getters_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    std::string copy = url_examples[seed++ % kUrlExamplesCount];
    ada_url url = ::ada_parse(copy.data(), copy.size());
    while (ada_is_valid(url)) {
      c_api_exercise_all_reads(url);
      ada_free(url);
      counter = mutate_string(copy, counter);
      url = ::ada_parse(copy.data(), copy.size());
    }
    ada_free(url);
  }
  return counter;
}

/**
 * Parses URL examples via the C API, applies each setter with a mutation
 * value, then exercises all getters/predicates on the result.  Also tests
 * all three clear() operations.
 */
size_t c_api_setters_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    std::string copy = url_examples[seed++ % kUrlExamplesCount];
    ada_url url = ::ada_parse(copy.data(), copy.size());
    if (!ada_is_valid(url)) {
      ada_free(url);
      continue;
    }

    const char* mutation = kSetterMutations[counter++ % kSetterMutationsCount];
    size_t mlen = std::strlen(mutation);

    // Exercise every setter in turn.
    switch (counter++ % 10) {
      case 0:
        ada_set_href(url, mutation, mlen);
        break;
      case 1:
        ada_set_host(url, mutation, mlen);
        break;
      case 2:
        ada_set_hostname(url, mutation, mlen);
        break;
      case 3:
        ada_set_protocol(url, mutation, mlen);
        break;
      case 4:
        ada_set_username(url, mutation, mlen);
        break;
      case 5:
        ada_set_password(url, mutation, mlen);
        break;
      case 6:
        ada_set_port(url, mutation, mlen);
        break;
      case 7:
        ada_set_pathname(url, mutation, mlen);
        break;
      case 8:
        ada_set_search(url, mutation, mlen);
        break;
      case 9:
        ada_set_hash(url, mutation, mlen);
        break;
      default:
        break;
    }

    c_api_exercise_all_reads(url);

    // Clear operations.
    ada_clear_port(url);
    c_api_exercise_all_reads(url);

    ada_clear_hash(url);
    c_api_exercise_all_reads(url);

    ada_clear_search(url);
    c_api_exercise_all_reads(url);

    // Copy the URL and verify that the copy is independent.
    ada_url copy_url = ada_copy(url);
    if (ada_is_valid(copy_url)) {
      // Snapshot the copy's href content before mutating the original.
      ada_string before = ada_get_href(copy_url);
      std::string copy_content(before.data, before.length);

      ada_set_href(url, "https://mutated.example.com/", 27);

      // The copy's content must be unchanged.
      ada_string after = ada_get_href(copy_url);
      if (after.length != copy_content.size() ||
          std::memcmp(after.data, copy_content.data(),
                      copy_content.size()) != 0) {
        std::cerr << "FATAL: ada_copy independence violated\n";
        return 1;
      }
    }
    ada_free(copy_url);
    ada_free(url);
  }
  return counter;
}

/**
 * Exercises every search-params operation (append, set, remove, remove_value,
 * has, has_value, get, get_all, sort, reset, to_string) and iterates through
 * the keys, values, and entries iterators on a range of query strings.
 */
size_t c_api_search_params_fuzz(size_t N, size_t seed = 0) {
  static const char* const kParamInputs[] = {
      "a=b&c=d&c=e&f=g",
      "key=value&foo=bar&baz=qux",
      "x=1&x=2&x=3",
      "",
      "encoded=hello%20world&plus=a+b",
      "multi=a&multi=b&multi=c",
      "empty=&no-val",
      "unicode=%E2%9C%93",
  };
  static constexpr size_t kParamInputsCount =
      sizeof(kParamInputs) / sizeof(kParamInputs[0]);

  static const char* const kKeys[] = {"a",       "key",     "x",    "multi",
                                      "missing", "encoded", "empty", ""};
  static constexpr size_t kKeysCount = sizeof(kKeys) / sizeof(kKeys[0]);

  static const char* const kValues[] = {"b", "value", "1", "new-value",
                                        "a+b", ""};
  static constexpr size_t kValuesCount = sizeof(kValues) / sizeof(kValues[0]);

  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    const char* input = kParamInputs[counter++ % kParamInputsCount];
    ada_url_search_params params =
        ada_parse_search_params(input, std::strlen(input));

    // Size and serialisation.
    (void)ada_search_params_size(params);
    ada_owned_string str = ada_search_params_to_string(params);
    ada_free_owned_string(str);

    const char* key = kKeys[counter++ % kKeysCount];
    const char* val = kValues[counter++ % kValuesCount];
    size_t key_len = std::strlen(key);
    size_t val_len = std::strlen(val);

    // Query operations.
    (void)ada_search_params_has(params, key, key_len);
    (void)ada_search_params_has_value(params, key, key_len, val, val_len);
    (void)ada_search_params_get(params, key, key_len);

    ada_strings all = ada_search_params_get_all(params, key, key_len);
    size_t all_size = ada_strings_size(all);
    for (size_t i = 0; i < all_size; i++) {
      (void)ada_strings_get(all, i);
    }
    ada_free_strings(all);

    // Mutation operations.
    ada_search_params_append(params, key, key_len, val, val_len);
    ada_search_params_set(params, key, key_len, val, val_len);
    ada_search_params_sort(params);

    // Iterator: keys.
    ada_url_search_params_keys_iter keys_iter =
        ada_search_params_get_keys(params);
    while (ada_search_params_keys_iter_has_next(keys_iter)) {
      (void)ada_search_params_keys_iter_next(keys_iter);
    }
    ada_free_search_params_keys_iter(keys_iter);

    // Iterator: values.
    ada_url_search_params_values_iter values_iter =
        ada_search_params_get_values(params);
    while (ada_search_params_values_iter_has_next(values_iter)) {
      (void)ada_search_params_values_iter_next(values_iter);
    }
    ada_free_search_params_values_iter(values_iter);

    // Iterator: entries.
    ada_url_search_params_entries_iter entries_iter =
        ada_search_params_get_entries(params);
    while (ada_search_params_entries_iter_has_next(entries_iter)) {
      (void)ada_search_params_entries_iter_next(entries_iter);
    }
    ada_free_search_params_entries_iter(entries_iter);

    // Remove operations.
    ada_search_params_remove(params, key, key_len);
    ada_search_params_remove_value(params, key, key_len, val, val_len);

    // Reset to a new query string.
    const char* reset_input = kParamInputs[counter++ % kParamInputsCount];
    ada_search_params_reset(params, reset_input, std::strlen(reset_input));

    ada_free_search_params(params);
  }
  return counter;
}

/**
 * Parses every URL example with the C API then exercises ada_can_parse and
 * ada_can_parse_with_base on mutations.
 */
size_t c_api_can_parse_fuzz(size_t N, size_t seed = 0) {
  size_t counter = seed;
  static const char* const kBases[] = {
      "https://example.com/",
      "http://localhost:8080/base",
      "file:///usr/local/",
  };
  static constexpr size_t kBasesCount = sizeof(kBases) / sizeof(kBases[0]);

  for (size_t trial = 0; trial < N; trial++) {
    std::string copy = url_examples[seed++ % kUrlExamplesCount];
    // can_parse without base
    (void)ada_can_parse(copy.data(), copy.size());
    // can_parse with base
    const char* base = kBases[counter++ % kBasesCount];
    (void)ada_can_parse_with_base(copy.data(), copy.size(), base,
                                  std::strlen(base));
    counter = mutate_string(copy, counter);
  }
  return counter;
}

/**
 * Exercises ada_idna_to_unicode and ada_idna_to_ascii on a small set of
 * domain names including ASCII-only, punycode, and multi-label inputs.
 */
size_t c_api_idna_fuzz(size_t N, size_t seed = 0) {
  static const char* const kDomains[] = {
      "example.com",
      "xn--strae-oqa.de",
      "xn--nxasmq6b.com",
      "sub.xn--ls8h.la",
      "",
      "localhost",
      "192.168.1.1",
  };
  static constexpr size_t kDomainsCount =
      sizeof(kDomains) / sizeof(kDomains[0]);

  size_t counter = seed;
  for (size_t trial = 0; trial < N; trial++) {
    const char* domain = kDomains[counter++ % kDomainsCount];
    size_t dlen = std::strlen(domain);

    ada_owned_string unicode = ada_idna_to_unicode(domain, dlen);
    ada_free_owned_string(unicode);

    ada_owned_string ascii = ada_idna_to_ascii(domain, dlen);
    ada_free_owned_string(ascii);
  }
  return counter;
}

int main() {
  if (std::endian::native == std::endian::big) {
    std::cout << "You have big-endian system." << std::endl;
  } else {
    std::cout << "You have little-endian system." << std::endl;
  }
  std::cout << "Running basic fuzzer.\n";

  // ---- C++ API ----
  std::cout << "[fancy]  Executed " << fancy_fuzz<ada::url>(100000)
            << " mutations.\n";
  std::cout << "[simple] Executed " << simple_fuzz<ada::url>(40000)
            << " mutations.\n";
  std::cout << "[roller] Executed " << roller_fuzz<ada::url>(40000)
            << " correct cases.\n";
  std::cout << "[fancy]  Executed " << fancy_fuzz<ada::url_aggregator>(100000)
            << " mutations.\n";
  std::cout << "[simple] Executed " << simple_fuzz<ada::url_aggregator>(40000)
            << " mutations.\n";
  std::cout << "[roller] Executed " << roller_fuzz<ada::url_aggregator>(40000)
            << " correct cases.\n";

  // ---- C API ----
  std::cout << "[c_api getters]      Executed " << c_api_getters_fuzz(100000)
            << " mutations.\n";
  std::cout << "[c_api setters]      Executed " << c_api_setters_fuzz(100000)
            << " mutations.\n";
  std::cout << "[c_api search_params] Executed "
            << c_api_search_params_fuzz(100000) << " mutations.\n";
  std::cout << "[c_api can_parse]    Executed " << c_api_can_parse_fuzz(100000)
            << " mutations.\n";
  std::cout << "[c_api idna]         Executed " << c_api_idna_fuzz(10000)
            << " mutations.\n";

  return EXIT_SUCCESS;
}


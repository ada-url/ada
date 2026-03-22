/**
 * @file bench_c_api.cpp
 * @brief Google Benchmark-based benchmarks for the ada C API (ada_c.h).
 *
 * Mirrors the structure of bench.cpp / benchmark_template.cpp but exercises
 * the pure-C entry points (ada_parse, ada_can_parse, getters, setters, search
 * params) so their performance can be compared directly with the C++ API.
 */
#include "benchmark_header.h"

extern "C" {
#include "ada_c.h"
}

// ---------------------------------------------------------------------------
// URL dataset (shared with the existing C++ benchmarks)
// ---------------------------------------------------------------------------

std::string c_api_url_examples_default[] = {
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
    "http://192.168.1.1",
    "http://[2606:4700:4700::1111]",
};

std::vector<std::string> c_api_url_examples;
double c_api_url_examples_bytes = 0.0;

// Called once from main() via BENCHMARK (see below).
size_t c_api_init_data() {
  if (!c_api_url_examples.empty()) return c_api_url_examples.size();
  for (const std::string& s : c_api_url_examples_default) {
    c_api_url_examples.emplace_back(s);
  }
  for (const std::string& s : c_api_url_examples) {
    c_api_url_examples_bytes += static_cast<double>(s.size());
  }
  return c_api_url_examples.size();
}

// ---------------------------------------------------------------------------
// Helper: emit standard throughput counters, matching benchmark_template.cpp
// ---------------------------------------------------------------------------

static void add_throughput_counters(benchmark::State& state,
                                    double bytes,
                                    size_t n_urls) {
  state.counters["time/byte"] = benchmark::Counter(
      bytes, benchmark::Counter::kIsIterationInvariantRate |
                 benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
      static_cast<double>(n_urls),
      benchmark::Counter::kIsIterationInvariantRate |
          benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
      static_cast<double>(n_urls),
      benchmark::Counter::kIsIterationInvariantRate);
}

// ---------------------------------------------------------------------------
// ada_parse + ada_get_href  (C equivalent of BasicBench_AdaURL_aggregator_href)
// ---------------------------------------------------------------------------

static void BasicBench_C_API_parse_href(benchmark::State& state) {
  c_api_init_data();
  volatile size_t success = 0;
  volatile size_t href_size = 0;

  for (auto _ : state) {
    for (const std::string& url_string : c_api_url_examples) {
      ada_url url = ada_parse(url_string.data(), url_string.size());
      if (ada_is_valid(url)) {
        success++;
        href_size += ada_get_href(url).length;
      }
      ada_free(url);
    }
  }
  (void)success;
  (void)href_size;
  add_throughput_counters(state, c_api_url_examples_bytes,
                          c_api_url_examples.size());
}
BENCHMARK(BasicBench_C_API_parse_href);

// ---------------------------------------------------------------------------
// ada_can_parse  (C equivalent of BasicBench_AdaURL_CanParse)
// ---------------------------------------------------------------------------

static void BasicBench_C_API_can_parse(benchmark::State& state) {
  c_api_init_data();
  volatile size_t success = 0;

  for (auto _ : state) {
    for (const std::string& url_string : c_api_url_examples) {
      if (ada_can_parse(url_string.data(), url_string.size())) {
        success++;
      }
    }
  }
  (void)success;
  add_throughput_counters(state, c_api_url_examples_bytes,
                          c_api_url_examples.size());
}
BENCHMARK(BasicBench_C_API_can_parse);

// ---------------------------------------------------------------------------
// ada_parse + all getters
// ---------------------------------------------------------------------------

static void BasicBench_C_API_parse_all_getters(benchmark::State& state) {
  c_api_init_data();
  volatile size_t total = 0;

  for (auto _ : state) {
    for (const std::string& url_string : c_api_url_examples) {
      ada_url url = ada_parse(url_string.data(), url_string.size());
      if (ada_is_valid(url)) {
        total += ada_get_href(url).length;
        total += ada_get_protocol(url).length;
        total += ada_get_username(url).length;
        total += ada_get_password(url).length;
        total += ada_get_host(url).length;
        total += ada_get_hostname(url).length;
        total += ada_get_port(url).length;
        total += ada_get_pathname(url).length;
        total += ada_get_search(url).length;
        total += ada_get_hash(url).length;
        ada_owned_string origin = ada_get_origin(url);
        total += origin.length;
        ada_free_owned_string(origin);
      }
      ada_free(url);
    }
  }
  (void)total;
  add_throughput_counters(state, c_api_url_examples_bytes,
                          c_api_url_examples.size());
}
BENCHMARK(BasicBench_C_API_parse_all_getters);

// ---------------------------------------------------------------------------
// ada_parse + ada_set_href  (setter round-trip)
// ---------------------------------------------------------------------------

static void BasicBench_C_API_set_href(benchmark::State& state) {
  c_api_init_data();
  volatile size_t success = 0;
  static const char kNewHref[] = "https://example.com/new?q=bench#frag";
  static const size_t kNewHrefLen = sizeof(kNewHref) - 1;

  for (auto _ : state) {
    for (const std::string& url_string : c_api_url_examples) {
      ada_url url = ada_parse(url_string.data(), url_string.size());
      if (ada_is_valid(url)) {
        if (ada_set_href(url, kNewHref, kNewHrefLen)) {
          success++;
        }
      }
      ada_free(url);
    }
  }
  (void)success;
  add_throughput_counters(state, c_api_url_examples_bytes,
                          c_api_url_examples.size());
}
BENCHMARK(BasicBench_C_API_set_href);

// ---------------------------------------------------------------------------
// ada_parse_search_params + iterate entries
// ---------------------------------------------------------------------------

static void BasicBench_C_API_search_params(benchmark::State& state) {
  static const char kQuery[] =
      "key1=value1&key2=value2&key3=value3&key4=value4&key5=value5";
  static const size_t kQueryLen = sizeof(kQuery) - 1;

  volatile size_t total = 0;

  for (auto _ : state) {
    ada_url_search_params params = ada_parse_search_params(kQuery, kQueryLen);
    total += ada_search_params_size(params);

    ada_url_search_params_entries_iter iter =
        ada_search_params_get_entries(params);
    while (ada_search_params_entries_iter_has_next(iter)) {
      ada_string_pair pair = ada_search_params_entries_iter_next(iter);
      total += pair.key.length + pair.value.length;
    }
    ada_free_search_params_entries_iter(iter);
    ada_free_search_params(params);
  }
  (void)total;
  state.counters["params/s"] = benchmark::Counter(
      5.0, benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_C_API_search_params);

// ---------------------------------------------------------------------------
// ada_parse + ada_copy independence
// ---------------------------------------------------------------------------

static void BasicBench_C_API_copy(benchmark::State& state) {
  c_api_init_data();
  volatile size_t success = 0;

  for (auto _ : state) {
    for (const std::string& url_string : c_api_url_examples) {
      ada_url url = ada_parse(url_string.data(), url_string.size());
      if (ada_is_valid(url)) {
        ada_url copy = ada_copy(url);
        if (ada_is_valid(copy)) {
          success += ada_get_href(copy).length;
        }
        ada_free(copy);
      }
      ada_free(url);
    }
  }
  (void)success;
  add_throughput_counters(state, c_api_url_examples_bytes,
                          c_api_url_examples.size());
}
BENCHMARK(BasicBench_C_API_copy);

BENCHMARK_MAIN();

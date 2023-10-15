#include "benchmark_header.h"
#include "simdjson.h"

using namespace simdjson;

double url_examples_bytes{};

std::vector<std::pair<std::string, std::string>> url_examples;

size_t init_data(const char *source) {
  ondemand::parser parser;
  std::vector<std::pair<std::string, std::string>> answer;

  if (!file_exists(source)) {
    return 0;
  }
  padded_string json = padded_string::load(source);
  ondemand::document doc = parser.iterate(json);
  for (auto element : doc.get_array()) {
    if (element.type() == ondemand::json_type::object) {
      std::string_view input;
      if (element["input"].get_string(true).get(input) != simdjson::SUCCESS) {
        printf("missing input.\n");
      }
      std::string_view base;
      if (element["base"].get_string(true).get(base) != simdjson::SUCCESS) {
      }
      url_examples.push_back({std::string(input), std::string(base)});
      url_examples_bytes += input.size() + base.size();
    }
  }
  return url_examples.size();
}

template <class result>
static void BasicBench_AdaURL(benchmark::State &state) {
  // volatile to prevent optimizations.
  volatile size_t href_size = 0;

  for (auto _ : state) {
    for (const std::pair<std::string, std::string> &url_strings :
         url_examples) {
      ada::result<result> base;
      result *base_ptr = nullptr;
      if (!url_strings.second.empty()) {
        base = ada::parse<result>(url_strings.second);
        if (base) {
          base_ptr = &*base;
        } else {
          continue;
        }
      }
      auto url = ada::parse(url_strings.first, base_ptr);
      if (url) {
        href_size += url->get_href().size();
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (const std::pair<std::string, std::string> &url_strings :
           url_examples) {
        ada::result<result> base;
        result *base_ptr = nullptr;
        if (!url_strings.second.empty()) {
          base = ada::parse<result>(url_strings.second);
          if (base) {
            base_ptr = &*base;
          } else {
            continue;
          }
        }
        auto url = ada::parse(url_strings.first, base_ptr);
        if (url) {
          href_size += url->get_href().size();
        }
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] =
        aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] =
        aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] =
        aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] =
        aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] =
        aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] =
        aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] =
        aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] =
      benchmark::Counter(double(std::size(url_examples)),
                         benchmark::Counter::kIsIterationInvariantRate |
                             benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] =
      benchmark::Counter(double(std::size(url_examples)),
                         benchmark::Counter::kIsIterationInvariantRate);
}
auto BasicBench_AdaURL_url = BasicBench_AdaURL<ada::url>;
BENCHMARK(BasicBench_AdaURL_url);
auto BasicBench_AdaURL_url_aggregator = BasicBench_AdaURL<ada::url_aggregator>;
BENCHMARK(BasicBench_AdaURL_url_aggregator);

#if ADA_url_whatwg_ENABLED

#include <upa/url.h>

static void BasicBench_whatwg(benchmark::State &state) {
  volatile size_t success{};
  for (auto _ : state) {
    for (const std::pair<std::string, std::string> &url_strings :
         url_examples) {
      upa::url base;
      upa::url *base_ptr = nullptr;
      if (!url_strings.second.empty()) {
        if (upa::success(base.parse(url_strings.second, nullptr))) {
          base_ptr = &base;
        }
      }
      upa::url url;
      if (upa::success(url.parse(url_strings.first, base_ptr))) {
        success++;
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (const std::pair<std::string, std::string> &url_strings :
           url_examples) {
        upa::url base;
        upa::url *base_ptr = nullptr;
        if (!url_strings.second.empty()) {
          if (upa::success(base.parse(url_strings.second, nullptr))) {
            base_ptr = &base;
          }
        }
        upa::url url;
        if (upa::success(url.parse(url_strings.first, base_ptr))) {
          success++;
        }
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    (void)success;
    state.counters["cycles/url"] =
        aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] =
        aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] =
        aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] =
        aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] =
        aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] =
        aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] =
        aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] =
      benchmark::Counter(double(std::size(url_examples)),
                         benchmark::Counter::kIsIterationInvariantRate |
                             benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] =
      benchmark::Counter(double(std::size(url_examples)),
                         benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_whatwg);
#endif  // ADA_url_whatwg_ENABLED

int main(int argc, char **argv) {
  if (argc == 1 || !init_data(argv[1])) {
    std::cout
        << "pass the path to the file wpt/urltestdata.json as a parameter."
        << std::endl;
    std::cout
        << "E.g., './build/benchmarks/wpt_bench tests/wpt/urltestdata.json'"
        << std::endl;
    return EXIT_SUCCESS;
  }
#if defined(ADA_RUST_VERSION)
  benchmark::AddCustomContext("rust version ", ADA_RUST_VERSION);
#endif
#if (__APPLE__ && __aarch64__) || defined(__linux__)
  if (!collector.has_events()) {
    benchmark::AddCustomContext("performance counters",
                                "No privileged access (sudo may help).");
  }
#else
  if (!collector.has_events()) {
    benchmark::AddCustomContext("performance counters", "Unsupported system.");
  }
#endif

  if (collector.has_events()) {
    benchmark::AddCustomContext("performance counters", "Enabled");
  }
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}

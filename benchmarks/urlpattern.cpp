#include "benchmark_header.h"

std::vector<std::pair<std::string_view, std::string>> url_pattern_examples = {
    {"https://example.com/foo/bar", "/foo/bar"},
    {"https://example.com/foo/bar/baz", "/foo/bar"},
    {"https://example.com/foo.html", ":name.html"},
    {"https://sub.example.com/foo/bar",
     "http{s}?://{*.}?example.com/:product/:endpoint"},
    {"https://example.com/?foo", "https://example.com?foo"},
    {"https://example.com:8080/?foo", "https://example.com:8080?foo"},
    {"https://example.com/?foo", "https://example.com/*\\?foo"},
    {"https://example.com/bar?foo", "https://example.com/:name?foo"}};

double url_examples_bytes;

const char* default_file = nullptr;

size_t init_data(const char* input = default_file) {
  // compute the number of bytes.
  auto compute = []() -> double {
    size_t bytes{0};
    for (const auto& [base, input] : url_pattern_examples) {
      bytes += base.size() + input.size();
    }
    return double(bytes);
  };

  url_examples_bytes = compute();
  return url_pattern_examples.size();
}

static void BasicBench_AdaURL_URLPattern(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t success = 0;

  for (auto _ : state) {
    for (const auto& [base, input] : url_pattern_examples) {
      auto result =
          ada::parse_url_pattern<ada::url_pattern_regex::std_regex_provider>(
              input, &base, nullptr);
      if (result) {
        success++;
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (const auto& [base, input] : url_pattern_examples) {
        auto result =
            ada::parse_url_pattern<ada::url_pattern_regex::std_regex_provider>(
                input, &base, nullptr);
        if (result) {
          success++;
        }
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] =
        aggregate.best.cycles() / std::size(url_pattern_examples);
    state.counters["instructions/url"] =
        aggregate.best.instructions() / std::size(url_pattern_examples);
    state.counters["instructions/cycle"] =
        aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] =
        aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] =
        aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] =
        aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] =
        aggregate.best.elapsed_ns() / std::size(url_pattern_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  (void)success;
  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] =
      benchmark::Counter(double(std::size(url_pattern_examples)),
                         benchmark::Counter::kIsIterationInvariantRate |
                             benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] =
      benchmark::Counter(double(std::size(url_pattern_examples)),
                         benchmark::Counter::kIsIterationInvariantRate);
}

BENCHMARK(BasicBench_AdaURL_URLPattern);

int main(int argc, char** argv) {
  init_data();
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
  benchmark::AddCustomContext("input bytes",
                              std::to_string(size_t(url_examples_bytes)));
  benchmark::AddCustomContext("number of URLs",
                              std::to_string(std::size(url_pattern_examples)));
  benchmark::AddCustomContext(
      "bytes/URL",
      std::to_string(url_examples_bytes / std::size(url_pattern_examples)));
  if (collector.has_events()) {
    benchmark::AddCustomContext("performance counters", "Enabled");
  }
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}

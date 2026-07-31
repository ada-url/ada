#include <memory>

#include "ada.h"
#include "ada/character_sets.h"
#include "ada/unicode.h"
#include "counters/event_counter.h"
counters::event_collector collector;
size_t N = 1000;

#include <benchmark/benchmark.h>

std::string examples[] = {
    "utm_source=twc%20mobile&name=John%20Doe&ref=web-twc-ao-gbl",
    "https%3A%2F%2Fexample.com%2Fpath%3Fa%3D1%26b%3D2%26c%3D3%26d%3D4",
    "the/quick/brown/fox/jumps/over/the/lazy/dog%2Ehtml",
    "caf%C3%A9%20%E4%BD%A0%E5%A5%BD%20%F0%9F%98%80%20done"};

void init_data() {}

double examples_bytes = []() -> double {
  size_t bytes{0};
  for (std::string& url_string : examples) {
    bytes += url_string.size();
  }
  return double(bytes);
}();

static void Decode(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(
          ada::unicode::percent_decode(url_string, url_string.find('%')));
    }
  }
  if (collector.has_events()) {
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(
            ada::unicode::percent_decode(url_string, url_string.find('%')));
      }
      std::atomic_thread_fence(std::memory_order_release);
      counters::event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["instructions/url"] =
        aggregate.best.instructions() / std::size(examples);
    state.counters["instructions/cycle"] =
        aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["instructions/byte"] =
        aggregate.best.instructions() / examples_bytes;
    state.counters["GHz"] =
        aggregate.total.cycles() / aggregate.total.elapsed_ns();
  }
  state.counters["time/byte"] = benchmark::Counter(
      examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                          benchmark::Counter::kInvert);
  state.counters["time/url"] =
      benchmark::Counter(double(std::size(examples)),
                         benchmark::Counter::kIsIterationInvariantRate |
                             benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] =
      benchmark::Counter(double(std::size(examples)),
                         benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(Decode);

int main(int argc, char** argv) {
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

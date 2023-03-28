#include <memory>

#include "ada.h"
#include "ada/character_sets.h"
#include "ada/unicode.h"
#include "performancecounters/event_counter.h"
event_collector collector;
size_t N = 1000;

#include <benchmark/benchmark.h>

std::string examples[] = {"á|", "other:9818274x1!!",
                          "ref=web-twc-ao-gbl-adsinfo&utm_source=twc&utm_",
                          "connect_timeout=10&application_name=myapp"};

void init_data() {}

double examples_bytes = []() -> double {
  size_t bytes{0};
  for (std::string& url_string : examples) {
    bytes += url_string.size();
  }
  return double(bytes);
}();

static void Fragment(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
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
BENCHMARK(Fragment);

static void Query(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::QUERY_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::QUERY_PERCENT_ENCODE));
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
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
BENCHMARK(Query);

static void SpecialQuery(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE));
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
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
BENCHMARK(SpecialQuery);

static void UserInfo(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::USERINFO_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::USERINFO_PERCENT_ENCODE));
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
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
BENCHMARK(UserInfo);

static void C0Control(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::C0_CONTROL_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::C0_CONTROL_PERCENT_ENCODE));
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
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
BENCHMARK(C0Control);

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

#include <memory>
#include <string>

#include "ada.h"
#include "counters/event_counter.h"
counters::event_collector collector;
size_t N = 1000;

#include <benchmark/benchmark.h>

// A representative absolute URL that every setter mutates in place. These
// benchmarks measure that per-call cost so the guard can be optimized safely.
static const std::string base_url =
    "https://user:pass@www.example.com:8080/path/to/"
    "resource?foo=bar&baz=qux#section";

void init_data() {}

// Runs `op` once per iteration and when hardware performance counters are
// available, collects instruction/cycle stats
template <typename F>
static void run_setter(benchmark::State& state, F op) {
  for (auto _ : state) {
    op();
  }
  if (collector.has_events()) {
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      op();
      std::atomic_thread_fence(std::memory_order_release);
      counters::event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["instructions/op"] = aggregate.best.instructions();
    state.counters["instructions/cycle"] =
        aggregate.total.instructions() / aggregate.total.cycles();
    state.counters["GHz"] =
        aggregate.total.cycles() / aggregate.total.elapsed_ns();
  }
  state.counters["time/op"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate |
                                benchmark::Counter::kInvert);
  state.counters["ops/s"] =
      benchmark::Counter(1, benchmark::Counter::kIsIterationInvariantRate);
}

static void SetProtocol(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, [&] { benchmark::DoNotOptimize(url.set_protocol("wss")); });
}
BENCHMARK(SetProtocol);

static void SetUsername(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state,
             [&] { benchmark::DoNotOptimize(url.set_username("newuser")); });
}
BENCHMARK(SetUsername);

static void SetPassword(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state,
             [&] { benchmark::DoNotOptimize(url.set_password("newpass")); });
}
BENCHMARK(SetPassword);

static void SetPort(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, [&] { benchmark::DoNotOptimize(url.set_port("9090")); });
}
BENCHMARK(SetPort);

static void SetPathname(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, [&] {
    benchmark::DoNotOptimize(url.set_pathname("/some/other/path/here"));
  });
}
BENCHMARK(SetPathname);

static void SetSearch(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, [&] { url.set_search("?a=1&b=2&c=3&d=4"); });
}
BENCHMARK(SetSearch);

static void SetHash(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, [&] { url.set_hash("#newfragment"); });
}
BENCHMARK(SetHash);

static void SetHostname(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, [&] {
    benchmark::DoNotOptimize(url.set_hostname("www.newhost.example.org"));
  });
}
BENCHMARK(SetHostname);

static void SetHref(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, [&] { benchmark::DoNotOptimize(url.set_href(base_url)); });
}
BENCHMARK(SetHref);

int main(int argc, char** argv) {
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

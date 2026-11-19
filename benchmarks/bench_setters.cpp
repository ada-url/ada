#include <cstdio>
#include <cstdlib>
#include <string>

#include "ada.h"
#include "counters/event_counter.h"
counters::event_collector collector;
size_t N = 1000;

#include <benchmark/benchmark.h>

// A representative absolute URL. Every timed iteration is a round trip that
// restores this URL (or a fixed component established before the loop), so
// CodSpeed's single iteration measures the same steady-state work as the
// later iterations a wall-clock run averages. One untimed warmup absorbs the
// first capacity change.
static const std::string base_url =
    "https://user:pass@www.example.com:8080/path/to/"
    "resource?foo=bar&baz=qux#section";

void init_data() {}

// Runs `op` once per iteration. `op` must restore `url` to the href it
// started from. When hardware performance counters are available, collects
// instruction/cycle stats over the same round trip.
template <typename F>
static void run_setter(benchmark::State& state, ada::url_aggregator& url,
                       const char* name, F op) {
  op();
  const std::string before(url.get_href());
  op();
  const std::string after(url.get_href());
  if (before != after) {
    std::fprintf(stderr,
                 "%s is not iteration-invariant:\n  before: %s\n  after:  %s\n",
                 name, before.c_str(), after.c_str());
    std::abort();
  }
  for (auto _ : state) {
    op();
    benchmark::DoNotOptimize(url);
    benchmark::ClobberMemory();
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
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_protocol("wss"));
    benchmark::DoNotOptimize(url.set_protocol("https"));
  });
}
BENCHMARK(SetProtocol);

static void SetUsername(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_username("newuser"));
    benchmark::DoNotOptimize(url.set_username("user"));
  });
}
BENCHMARK(SetUsername);

static void SetUsernameAlternatingLength(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  benchmark::DoNotOptimize(url.set_username("x"));
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_username("a-much-longer-username"));
    benchmark::DoNotOptimize(url.set_username("x"));
  });
}
BENCHMARK(SetUsernameAlternatingLength);

static void SetPassword(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_password("newpass"));
    benchmark::DoNotOptimize(url.set_password("pass"));
  });
}
BENCHMARK(SetPassword);

static void SetPasswordAlternatingLength(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  benchmark::DoNotOptimize(url.set_password("y"));
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_password("a-much-longer-password"));
    benchmark::DoNotOptimize(url.set_password("y"));
  });
}
BENCHMARK(SetPasswordAlternatingLength);

static void SetPasswordInsertAndClear(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  benchmark::DoNotOptimize(url.set_password(""));
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_password("newpass"));
    benchmark::DoNotOptimize(url.set_password(""));
  });
}
BENCHMARK(SetPasswordInsertAndClear);

static void SetPort(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_port("9090"));
    benchmark::DoNotOptimize(url.set_port("8080"));
  });
}
BENCHMARK(SetPort);

static void SetPathname(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_pathname("/some/other/path/here"));
    benchmark::DoNotOptimize(url.set_pathname("/path/to/resource"));
  });
}
BENCHMARK(SetPathname);

static void SetSearch(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__, [&] {
    url.set_search("?a=1&b=2&c=3&d=4");
    benchmark::DoNotOptimize(url);
    url.set_search("?foo=bar&baz=qux");
    benchmark::DoNotOptimize(url);
  });
}
BENCHMARK(SetSearch);

static void SetSearchAlternatingLength(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  url.set_search("?x=1");
  benchmark::DoNotOptimize(url);
  run_setter(state, url, __func__, [&] {
    url.set_search("?a=much-longer-query-value");
    benchmark::DoNotOptimize(url);
    url.set_search("?x=1");
    benchmark::DoNotOptimize(url);
  });
}
BENCHMARK(SetSearchAlternatingLength);

static void SetSearchEncodedAlternatingLength(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  url.set_search("?x= ");
  benchmark::DoNotOptimize(url);
  run_setter(state, url, __func__, [&] {
    url.set_search("?a=much longer query value");
    benchmark::DoNotOptimize(url);
    url.set_search("?x= ");
    benchmark::DoNotOptimize(url);
  });
}
BENCHMARK(SetSearchEncodedAlternatingLength);

static void SetSearchInsertAndClear(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  url.set_search("");
  benchmark::DoNotOptimize(url);
  run_setter(state, url, __func__, [&] {
    url.set_search("?a=1&b=2");
    benchmark::DoNotOptimize(url);
    url.set_search("");
    benchmark::DoNotOptimize(url);
  });
}
BENCHMARK(SetSearchInsertAndClear);

static void SetHash(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__, [&] {
    url.set_hash("#newfragment");
    benchmark::DoNotOptimize(url);
    url.set_hash("#section");
    benchmark::DoNotOptimize(url);
  });
}
BENCHMARK(SetHash);

static void SetHostname(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__, [&] {
    benchmark::DoNotOptimize(url.set_hostname("www.newhost.example.org"));
    benchmark::DoNotOptimize(url.set_hostname("www.example.com"));
  });
}
BENCHMARK(SetHostname);

static void SetHref(benchmark::State& state) {
  auto url = ada::parse<ada::url_aggregator>(base_url).value();
  run_setter(state, url, __func__,
             [&] { benchmark::DoNotOptimize(url.set_href(base_url)); });
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

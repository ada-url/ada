#include <memory>

#include "ada.h"
#include "ada/character_sets.h"
#include "ada/unicode.h"
#include "counters/event_counter.h"
counters::event_collector collector;
size_t N = 1000;

#include <benchmark/benchmark.h>

std::string examples[] = {"\xE1|", "other:9818274x1!!",
                          "ref=web-twc-ao-gbl-adsinfo&utm_source=twc&utm_",
                          "connect_timeout=10&application_name=myapp"};

std::string long_examples[] = {
    "connect timeout=10 application name=myapp server=db host internal "
    "database=production analytics read preference=secondary preferred "
    "ssl=true retry writes=true w=majority max pool size=50",
    "ref=web twc ao gbl adsinfo utm source=twc utm medium=cpc "
    "utm campaign=brand awareness q4 2024 utm content=banner 300x250 "
    "utm term=weather forecast today gclid=Cj0KCQiA3Y ABhCnARIsAK",
};

std::string decode_examples[] = {
    "%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C%20%21%22%23%24%25%26%27",
    "connect_timeout%3D10%26application_name%3Dmyapp%26server%3Ddb.host",
    "%68%65%6C%6C%6F%20%77%6F%72%6C%64%20%74%68%69%73%20%69%73%20"
    "%61%20%70%65%72%63%65%6E%74%20%68%65%61%76%79%20%73%74%72%69"
    "%6E%67",
    "%2Fapi%2Fv1%2Fusers%2F12345%2Fposts%3Fpage%3D1%26limit%3D50%26"
    "sort%3Dcreated%26order%3Ddesc%26fields%3Did%2Ctitle%2Cbody%26"
    "filter%3Dstatus%253Dpublished",
};

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
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
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
BENCHMARK(Fragment);

static void Query(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::QUERY_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::QUERY_PERCENT_ENCODE));
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
BENCHMARK(Query);

static void SpecialQuery(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE));
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
BENCHMARK(SpecialQuery);

static void UserInfo(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::USERINFO_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::USERINFO_PERCENT_ENCODE));
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
BENCHMARK(UserInfo);

static void C0Control(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& url_string : examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          url_string, ada::character_sets::C0_CONTROL_PERCENT_ENCODE));
    }
  }
  if (collector.has_events()) {
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : examples) {
        benchmark::DoNotOptimize(ada::unicode::percent_encode(
            url_string, ada::character_sets::C0_CONTROL_PERCENT_ENCODE));
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
BENCHMARK(C0Control);

double long_examples_bytes = []() -> double {
  size_t bytes{0};
  for (std::string& s : long_examples) {
    bytes += s.size();
  }
  return double(bytes);
}();

static void LongFragment(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& s : long_examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          s, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
    }
  }
  state.counters["speed"] = benchmark::Counter(
      long_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(LongFragment);

static void LongQuery(benchmark::State& state) {
  for (auto _ : state) {
    for (std::string& s : long_examples) {
      benchmark::DoNotOptimize(ada::unicode::percent_encode(
          s, ada::character_sets::QUERY_PERCENT_ENCODE));
    }
  }
  state.counters["speed"] = benchmark::Counter(
      long_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(LongQuery);

double decode_examples_bytes = []() -> double {
  size_t bytes{0};
  for (std::string& s : decode_examples) {
    bytes += s.size();
  }
  return double(bytes);
}();

const size_t decode_first_pct[] = {
    decode_examples[0].find('%'),
    decode_examples[1].find('%'),
    decode_examples[2].find('%'),
    decode_examples[3].find('%'),
};

static void Decode(benchmark::State& state) {
  for (auto _ : state) {
    for (size_t i = 0; i < std::size(decode_examples); i++) {
      benchmark::DoNotOptimize(ada::unicode::percent_decode(
          decode_examples[i], decode_first_pct[i]));
    }
  }
  state.counters["speed"] = benchmark::Counter(
      decode_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(Decode);

static void DecodeClean(benchmark::State& state) {
  std::string clean(200, 'a');
  for (auto _ : state) {
    benchmark::DoNotOptimize(
        ada::unicode::percent_decode(clean, std::string_view::npos));
  }
  state.counters["speed"] =
      benchmark::Counter(200.0, benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(DecodeClean);

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

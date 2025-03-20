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
};

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

size_t count_urlpattern_parse_invalid() {
  size_t how_many = 0;
  for (const auto& [base, input] : url_pattern_examples) {
    auto result =
        ada::parse_url_pattern<ada::url_pattern_regex::std_regex_provider>(
            input, &base, nullptr);
    if (!result) {
      how_many++;
    }
  }

  return how_many;
}

size_t count_urlpattern_exec_invalid() {
  size_t how_many = 0;
  auto pattern =
      ada::parse_url_pattern<ada::url_pattern_regex::std_regex_provider>(
          "https://*example.com/*");
  if (!pattern) {
    return std::size(url_examples);
  }

  for (const std::string& url_example : url_examples) {
    auto result = pattern->exec(url_example);
    if (!result) {
      how_many++;
    }
  }

  return how_many;
}

size_t count_urlpattern_test_invalid() {
  size_t how_many = 0;
  auto pattern =
      ada::parse_url_pattern<ada::url_pattern_regex::std_regex_provider>(
          "https://*example.com/*");
  if (!pattern) {
    return std::size(url_examples);
  }

  for (const std::string& url_example : url_examples) {
    auto result = pattern->test(url_example);
    if (!result) {
      how_many++;
    }
  }

  return how_many;
}

static void BasicBench_AdaURL_URLPattern_Parse(benchmark::State& state) {
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

BENCHMARK(BasicBench_AdaURL_URLPattern_Parse);

static void BasicBench_AdaURL_URLPattern_Exec(benchmark::State& state) {
  auto pattern =
      ada::parse_url_pattern<ada::url_pattern_regex::std_regex_provider>(
          "https://*example.com/*");
  if (!pattern) {
    state.SkipWithError("Failed to parse test pattern");
    return;
  }

  // volatile to prevent optimizations.
  volatile size_t success = 0;

  for (auto _ : state) {
    for (std::string& url_example : url_examples) {
      auto result = pattern->exec(url_example);
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
      for (std::string& url_example : url_examples) {
        auto result = pattern->exec(url_example);
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

BENCHMARK(BasicBench_AdaURL_URLPattern_Exec);

static void BasicBench_AdaURL_URLPattern_Test(benchmark::State& state) {
  auto pattern =
      ada::parse_url_pattern<ada::url_pattern_regex::std_regex_provider>(
          "https://*example.com/*");
  if (!pattern) {
    state.SkipWithError("Failed to parse test pattern");
    return;
  }

  // volatile to prevent optimizations.
  volatile size_t success = 0;

  for (auto _ : state) {
    for (std::string& url_example : url_examples) {
      auto result = pattern->test(url_example);
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
      for (std::string& url_example : url_examples) {
        auto result = pattern->test(url_example);
        if (result) {
          success++;
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
  (void)success;
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

BENCHMARK(BasicBench_AdaURL_URLPattern_Test);

int main(int argc, char** argv) {
  init_data();
  size_t urlpattern_parse_bad_urls = count_urlpattern_parse_invalid();
  size_t urlpattern_exec_bad_urls = count_urlpattern_exec_invalid();
  size_t urlpattern_test_bad_urls = count_urlpattern_test_invalid();

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

  std::stringstream badcounts;
  badcounts << "---------------------\n";
  badcounts << "urlpattern-parse---count of bad URLs      "
            << std::to_string(urlpattern_parse_bad_urls) << "\n";
  badcounts << "urlpattern-exec---count of bad URLs       "
            << std::to_string(urlpattern_exec_bad_urls) << "\n";
  badcounts << "urlpattern-test---count of bad URLs       "
            << std::to_string(urlpattern_test_bad_urls) << "\n";
  benchmark::AddCustomContext("bad url patterns", badcounts.str());

  if (collector.has_events()) {
    benchmark::AddCustomContext("performance counters", "Enabled");
  }

  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}

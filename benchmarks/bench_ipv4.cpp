#include "benchmark_header.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <numeric>
#include <string_view>
#include <vector>
#include <random>
#include <fstream>
#include <iostream>

namespace {

const std::string_view kIpv4NonDecimalUrls[] = {
    "http://0x7f.0x0.0x0.0x1",
    "http://0177.000.000.001",
    "http://0x7f.1.2.03",
    "http://0x7f.000.00.000",
    "http://000.000.000.000",
    "http://0x.0x.0x.0x",
    "http://0300.0250.0001.0001",
    "http://0xc0.0xa8.0x01.0x01",
    "http://3232235777",
    "http://0xc0a80101",
    "http://030052000401",
    "http://127.1",
    "http://127.0.1",
    "http://0x7f.1",
    "http://0177.1",
    "http://0300.0xa8.1.1",
    "http://192.168.0x1.01",
    "http://0x0.0x0.0x0.0x0",
    "http://0.0.0.0x0",
    "http://022.022.022.022",
    "http://0x12.0x12.0x12.0x12",
    "http://0xff.0xff.0xff.0xff",
    "http://0377.0377.0377.0377",
    "http://4294967295",
    "http://0xffffffff",
    "http://0x00.0x00.0x00.0x00",
    "http://00000.00000.00000.00000",
    "http://1.0x2.03.4",
    "http://0x1.2.0x3.4",
    "http://0.01.0x02.3"};

const std::string_view kDnsFallbackUrls[] = {
    "http://example.com",       "http://www.google.com",
    "http://localhost",         "http://foo.bar",
    "http://github.com",        "http://microsoft.com",
    "http://aws.amazon.com",    "http://adaparser.com",
    "http://www.wikipedia.org", "http://www.apple.com",
    "http://www.amazon.com",    "http://www.facebook.com",
    "http://www.twitter.com",   "http://www.instagram.com",
    "http://www.linkedin.com",  "http://www.reddit.com",
    "http://www.netflix.com",   "http://www.youtube.com",
    "http://www.bing.com",      "http://www.yahoo.com"};

#ifdef ADA_URL_FILE
const char* default_dns_file = ADA_URL_FILE;
#else
const char* default_dns_file = nullptr;
#endif

double bytes_for(const std::vector<std::string_view>& urls) {
  size_t bytes = 0;
  for (auto url : urls) {
    bytes += url.size();
  }
  return double(bytes);
}

std::vector<size_t> make_permutation(size_t count, uint64_t seed) {
  std::vector<size_t> order(count);
  std::iota(order.begin(), order.end(), 0);
  if (count < 2) return order;

  std::mt19937_64 rng(seed);
  std::shuffle(order.begin(), order.end(), rng);
  return order;
}

std::vector<size_t> make_strides(size_t count) {
  std::vector<size_t> strides;
  if (count > 1) {
    for (size_t s = 1; s < std::min(count, size_t(100)); ++s) {
      if (std::gcd(s, count) == 1) strides.push_back(s);
    }
  }
  if (strides.empty()) strides.push_back(1);
  return strides;
}

bool file_exists(const char* filename) {
  std::ifstream file(filename);
  return file.good();
}

std::string read_file(const char* filename) {
  std::ifstream file(filename);
  if (!file.is_open()) {
    return "";
  }
  return std::string((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
}

std::vector<std::string> split_string(const std::string& s,
                                      char delimiter = '\n') {
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream tokenStream(s);
  while (std::getline(tokenStream, token, delimiter)) {
    if (!token.empty()) {
      tokens.push_back(token);
    }
  }
  return tokens;
}

template <class ResultType>
void run_benchmark(benchmark::State& state,
                   const std::vector<std::string_view>& urls) {
  if (urls.empty()) return;

  double bytes = bytes_for(urls);
  size_t count = urls.size();

  auto order = make_permutation(count, 0x12345678);
  auto strides = make_strides(count);

  size_t iter = 0;
  volatile size_t success = 0;
  for (auto _ : state) {
    size_t stride = strides[iter % strides.size()];
    size_t pos = iter % count;

    for (size_t i = 0; i < count; ++i) {
      auto result = ada::parse<ResultType>(urls[order[pos]]);
      if (result) {
        success++;
      }
      benchmark::DoNotOptimize(result);

      pos += stride;
      if (pos >= count) pos -= count;
    }
    benchmark::ClobberMemory();
    ++iter;
  }
  (void)success;

  if (collector.has_events()) {
    counters::event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      size_t stride = strides[i % strides.size()];
      size_t pos = i % count;
      for (size_t j = 0; j < count; ++j) {
        auto result = ada::parse<ResultType>(urls[order[pos]]);
        if (result) {
          success++;
        }
        benchmark::DoNotOptimize(result);
        pos += stride;
        if (pos >= count) pos -= count;
      }
      std::atomic_thread_fence(std::memory_order_release);
      counters::event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["branch_misses/url"] =
        aggregate.best.branch_misses() / count;
    state.counters["branches/url"] = aggregate.best.branches() / count;
    state.counters["cycles/url"] = aggregate.best.cycles() / count;
    state.counters["instructions/url"] = aggregate.best.instructions() / count;
    state.counters["instructions/cycle"] =
        aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] = aggregate.best.instructions() / bytes;
    state.counters["instructions/ns"] =
        aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] =
        aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] = aggregate.best.elapsed_ns() / count;
    state.counters["cycle/byte"] = aggregate.best.cycles() / bytes;
  }

  state.counters["time/byte"] =
      benchmark::Counter(bytes, benchmark::Counter::kIsIterationInvariantRate |
                                    benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
      double(count), benchmark::Counter::kIsIterationInvariantRate |
                         benchmark::Counter::kInvert);
  state.counters["speed"] =
      benchmark::Counter(bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
      double(count), benchmark::Counter::kIsIterationInvariantRate);
}

struct DataGenerator {
  std::vector<std::string> storage;
  std::vector<std::string_view> views;

  static const std::vector<std::string_view>& GetDecimalWorkload() {
    static DataGenerator instance = []() {
      DataGenerator gen;
      constexpr size_t count = 5000;
      std::mt19937 rng(42);
      std::uniform_int_distribution<int> octet(0, 255);

      gen.storage.reserve(count);
      gen.views.reserve(count);

      for (size_t i = 0; i < count; ++i) {
        std::string ip = "http://" + std::to_string(octet(rng)) + "." +
                         std::to_string(octet(rng)) + "." +
                         std::to_string(octet(rng)) + "." +
                         std::to_string(octet(rng));
        gen.storage.push_back(std::move(ip));
        gen.views.push_back(gen.storage.back());
      }
      return gen;
    }();
    return instance.views;
  }

  static const std::vector<std::string_view>& GetNonDecimalWorkload() {
    static DataGenerator instance = []() {
      DataGenerator gen;
      constexpr size_t count = 2000;
      size_t src_len = std::size(kIpv4NonDecimalUrls);
      gen.views.reserve(count);
      for (size_t i = 0; i < count; ++i) {
        gen.views.push_back(kIpv4NonDecimalUrls[i % src_len]);
      }
      return gen;
    }();
    return instance.views;
  }

  static const std::vector<std::string_view>& GetDnsWorkload() {
    static DataGenerator instance = []() {
      DataGenerator gen;

      // Try to load from file
      if (default_dns_file && file_exists(default_dns_file)) {
        std::cout << "# Loading DNS data from: " << default_dns_file
                  << std::endl;
        std::string content = read_file(default_dns_file);
        gen.storage = split_string(content);
        gen.views.reserve(gen.storage.size());
        for (const auto& s : gen.storage) {
          gen.views.push_back(s);
        }
      }

      // Fallback if file load failed or empty
      if (gen.views.empty()) {
        std::cout << "# Loading built-in DNS fallback data" << std::endl;
        size_t count = 2000;
        size_t src_len = std::size(kDnsFallbackUrls);
        gen.views.reserve(count);
        for (size_t i = 0; i < count; ++i) {
          gen.views.push_back(kDnsFallbackUrls[i % src_len]);
        }
      }

      return gen;
    }();
    return instance.views;
  }
};

}  // namespace

static void Bench_IPv4_Decimal_AdaURL(benchmark::State& state) {
  run_benchmark<ada::url>(state, DataGenerator::GetDecimalWorkload());
}
BENCHMARK(Bench_IPv4_Decimal_AdaURL);

static void Bench_IPv4_Decimal_Aggregator(benchmark::State& state) {
  run_benchmark<ada::url_aggregator>(state,
                                     DataGenerator::GetDecimalWorkload());
}
BENCHMARK(Bench_IPv4_Decimal_Aggregator);

static void Bench_IPv4_NonDecimal_AdaURL(benchmark::State& state) {
  run_benchmark<ada::url>(state, DataGenerator::GetNonDecimalWorkload());
}
BENCHMARK(Bench_IPv4_NonDecimal_AdaURL);

static void Bench_IPv4_NonDecimal_Aggregator(benchmark::State& state) {
  run_benchmark<ada::url_aggregator>(state,
                                     DataGenerator::GetNonDecimalWorkload());
}
BENCHMARK(Bench_IPv4_NonDecimal_Aggregator);

static void Bench_DNS_AdaURL(benchmark::State& state) {
  run_benchmark<ada::url>(state, DataGenerator::GetDnsWorkload());
}
BENCHMARK(Bench_DNS_AdaURL);

static void Bench_DNS_Aggregator(benchmark::State& state) {
  run_benchmark<ada::url_aggregator>(state, DataGenerator::GetDnsWorkload());
}
BENCHMARK(Bench_DNS_Aggregator);

int main(int argc, char** argv) {
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}

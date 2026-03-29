/**
 * Reference:
 * Daniel Lemire, "Quickly checking that a string belongs to a small set," in
 * Daniel Lemire's blog, December 30, 2022,
 * https://lemire.me/blog/2022/12/30/quickly-checking-that-a-string-belongs-to-a-small-set/.
 */

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include "ada.h"
#include "counters/bench.h"

template <class Function1, class Function2>
counters::event_aggregate shuffle_bench(Function1&& function1,
                                        Function2&& function2,
                                        size_t min_repeat = 300,
                                        size_t min_time_ns = 400'000'000,
                                        size_t max_repeat = 1000000,
                                        size_t min_time_per_inner_ns = 30000) {
  static thread_local counters::event_collector collector;
  auto fn = std::forward<Function1>(function1);
  auto fn2 = std::forward<Function2>(function2);
  size_t N = min_repeat;
  // Measurement
  counters::event_aggregate aggregate{};
  for (size_t i = 0; i < N; i++) {
    collector.start();
    fn();
    counters::event_count allocate_count = collector.end();
    aggregate << allocate_count;
    fn2();
  }
  return aggregate;
}

enum class SchemeType : uint8_t {
  HTTP = 0,        /**< http:// scheme (port 80) */
  NOT_SPECIAL = 1, /**< Non-special scheme (no default port) */
  HTTPS = 2,       /**< https:// scheme (port 443) */
  WS = 3,          /**< ws:// WebSocket scheme (port 80) */
  FTP = 4,         /**< ftp:// scheme (port 21) */
  WSS = 5,         /**< wss:// secure WebSocket scheme (port 443) */
  FILE = 6         /**< file:// scheme (no default port) */
};

namespace details {
constexpr std::string_view is_special_list[] = {"http", " ",   "https", "ws",
                                                "ftp",  "wss", "file",  " "};

constexpr uint64_t make_key(std::string_view sv) {
  uint64_t val = 0;
  for (size_t i = 0; i < sv.size(); i++)
    val |= (uint64_t)(uint8_t)sv[i] << (i * 8);
  return val;
}

constexpr uint64_t scheme_keys[] = {
    make_key("http"),   // 0: HTTP
    0,                  // 1: sentinel
    make_key("https"),  // 2: HTTPS
    make_key("ws"),     // 3: WS
    make_key("ftp"),    // 4: FTP
    make_key("wss"),    // 5: WSS
    make_key("file"),   // 6: FILE
    0,                  // 7: sentinel
};

// branchless load of up to 5 characters into a uint64_t, padding with zeros if
// n < 5
inline uint64_t branchless_load5(const char* p, size_t n) {
  uint64_t input = (uint8_t)p[0];
  input |= ((uint64_t)(uint8_t)p[n > 1] << 8) & (0 - (uint64_t)(n > 1));
  input |= ((uint64_t)(uint8_t)p[(n > 2) * 2] << 16) & (0 - (uint64_t)(n > 2));
  input |= ((uint64_t)(uint8_t)p[(n > 3) * 3] << 24) & (0 - (uint64_t)(n > 3));
  input |= ((uint64_t)(uint8_t)p[(n > 4) * 4] << 32) & (0 - (uint64_t)(n > 4));
  return input;
}
}  // namespace details

// This is the original implementation of get_scheme_type
std::optional<SchemeType> get_scheme_type_legacy(
    std::string_view scheme) noexcept {
  if (scheme.empty() || scheme.size() > 5) {
    return std::nullopt;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  const std::string_view target = details::is_special_list[hash_value];
  if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
    return static_cast<SchemeType>(hash_value);
  }
  return std::nullopt;
}

// This is the new implementation of get_scheme_type using a hand-tuned hash
// function It avoid mispredictions.
std::optional<SchemeType> get_scheme_type(std::string_view scheme) noexcept {
  constexpr auto make_key = [](std::string_view sv) {
    uint64_t val = 0;
    for (size_t i = 0; i < sv.size(); i++)
      val |= (uint64_t)(uint8_t)sv[i] << (i * 8);
    return val;
  };
  constexpr static uint64_t scheme_keys[] = {
      make_key("http"),   // 0: HTTP
      0,                  // 1: sentinel
      make_key("https"),  // 2: HTTPS
      make_key("ws"),     // 3: WS
      make_key("ftp"),    // 4: FTP
      make_key("wss"),    // 5: WSS
      make_key("file"),   // 6: FILE
      0,                  // 7: sentinel
  };
  if (scheme.empty() || scheme.size() > 5) {
    return std::nullopt;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  uint64_t input = details::branchless_load5(scheme.data(), scheme.size());
  if (scheme.size() == scheme.size() && input == scheme_keys[hash_value]) {
    return static_cast<SchemeType>(hash_value);
  }
  return std::nullopt;
}

double pretty_print(const std::string& name, size_t num_values,
                    counters::event_aggregate agg) {
  printf("%-50s : ", name.c_str());
  printf(" %5.3f ns ", agg.fastest_elapsed_ns() / double(num_values));
  printf(" %5.2f Gv/s ", double(num_values) / agg.fastest_elapsed_ns());
  if (counters::has_performance_counters()) {
    printf(" %5.2f GHz ", agg.cycles() / double(agg.elapsed_ns()));
    printf(" %5.2f c ", agg.fastest_cycles() / double(num_values));
    printf(" %5.2f i ", agg.fastest_instructions() / double(num_values));
    printf(" %5.2f i/c ",
           agg.fastest_instructions() / double(agg.fastest_cycles()));
    printf(" %5.2f bm ", agg.fastest_branch_misses() / double(num_values));
  }
  printf("\n");
  return double(num_values) / agg.fastest_elapsed_ns();
}

std::vector<std::string_view> populate(size_t length) {
  std::mt19937_64 gen(std::random_device{}());
  // we generate a distribution where http is more common
  std::discrete_distribution<> d({20, 10, 10, 5, 5, 5});
  const static std::string_view options[] = {"http", "https", "ftp",
                                             "ws",   "wss",   "file"};
  std::vector<std::string_view> answer;
  answer.reserve(length);
  for (size_t pos = 0; pos < length; pos++) {
    std::string_view picked{options[d(gen)]};
    answer.emplace_back(picked);
  }
  return answer;
}

std::optional<SchemeType> get_scheme_type_naive(std::string_view input) {
  if (input == "http")
    return SchemeType::HTTP;
  else if (input == "https")
    return SchemeType::HTTPS;
  else if (input == "ftp")
    return SchemeType::FTP;
  else if (input == "ws")
    return SchemeType::WS;
  else if (input == "wss")
    return SchemeType::WSS;
  else if (input == "file")
    return SchemeType::FILE;
  else
    return std::nullopt;
}

void collect_benchmark_results(size_t number_strings) {
  std::vector<std::string_view> strings = populate(number_strings);
  std::vector<SchemeType> expected_types(strings.size(),
                                         SchemeType::NOT_SPECIAL);
  static const std::map<std::string_view, SchemeType> std_map = {
      {"http", SchemeType::HTTP}, {"https", SchemeType::HTTPS},
      {"ftp", SchemeType::FTP},   {"ws", SchemeType::WS},
      {"wss", SchemeType::WSS},   {"file", SchemeType::FILE}};

  static const std::unordered_map<std::string_view, SchemeType> unordered_map =
      {{"http", SchemeType::HTTP}, {"https", SchemeType::HTTPS},
       {"ftp", SchemeType::FTP},   {"ws", SchemeType::WS},
       {"wss", SchemeType::WSS},   {"file", SchemeType::FILE}};
  std::mt19937_64 gen(42);  // fixed seed for reproducibility

  auto shuffle = [&strings, &gen]() {
    std::shuffle(strings.begin(), strings.end(), gen);
  };

  auto count_naive = [&strings, &expected_types]() {
    for (size_t i = 0; i < strings.size(); i++) {
      auto opt = get_scheme_type_naive(strings[i]);
      if (opt) {
        expected_types[i] = *opt;
      }
    }
  };
  pretty_print("naive", number_strings, shuffle_bench(count_naive, shuffle));

  gen.seed(42);  // reset seed to ensure same shuffle for all benchmarks
  auto count_legacy = [&strings, &expected_types]() {
    for (size_t i = 0; i < strings.size(); i++) {
      auto opt = get_scheme_type_legacy(strings[i]);
      if (opt) {
        expected_types[i] = *opt;
      }
    }
  };
  pretty_print("legacy", number_strings, shuffle_bench(count_legacy, shuffle));
  gen.seed(42);  // reset seed to ensure same shuffle for all benchmarks

  gen.seed(42);  // reset seed to ensure same shuffle for all benchmarks
  auto count_classic = [&strings, &expected_types]() {
    for (size_t i = 0; i < strings.size(); i++) {
      auto opt = get_scheme_type(strings[i]);
      if (opt) {
        expected_types[i] = *opt;
      }
    }
  };

  pretty_print("hand-tuned hash", number_strings,
               shuffle_bench(count_classic, shuffle));
  gen.seed(42);  // reset seed to ensure same shuffle for all benchmarks

  auto count_ada = [&strings, &expected_types]() {
    for (size_t i = 0; i < strings.size(); i++) {
      auto type = ada::scheme::get_scheme_type(strings[i]);
      expected_types[i] = static_cast<SchemeType>(type);
    }
  };
  pretty_print("ada", number_strings, shuffle_bench(count_ada, shuffle));
  gen.seed(42);  // reset seed to ensure same shuffle for all benchmarks

  auto count_std_map = [&strings, &expected_types]() {
    for (size_t i = 0; i < strings.size(); i++) {
      auto it = std_map.find(strings[i]);
      if (it != std_map.end()) {
        expected_types[i] = it->second;
      }
    }
  };
  pretty_print("std::map", number_strings,
               shuffle_bench(count_std_map, shuffle));
  gen.seed(42);  // reset seed to ensure same shuffle for all benchmarks

  auto count_unordered_map = [&strings, &expected_types]() {
    for (size_t i = 0; i < strings.size(); i++) {
      auto it = unordered_map.find(strings[i]);
      if (it != unordered_map.end()) {
        expected_types[i] = it->second;
      }
    }
  };
  pretty_print("std::unordered_map", number_strings,
               shuffle_bench(count_unordered_map, shuffle));
  gen.seed(42);  // reset seed to ensure same shuffle for all benchmarks
}

int main(int argc, char** argv) {
  if (!counters::has_performance_counters()) {
    printf(
        "Performance counters not available, you may need to run with sudo.\n");
  }
  collect_benchmark_results(200000);
  return EXIT_SUCCESS;
}

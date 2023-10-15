/**
 * The main benchmark is to take an input string, and convert it into a
 * normalized URL (or 'href').
 */

size_t count_ada_invalid() {
  size_t how_many = 0;
  for (std::string& url_string : url_examples) {
    auto url = ada::parse(url_string);
    if (!url) {
      how_many++;
    }
  }
  return how_many;
}

enum { JUST_PARSE = 1, PARSE_AND_HREF = 0 };

template <bool just_parse = PARSE_AND_HREF,
          class result_type = ada::url_aggregator>
static void BasicBench_AdaURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t success = 0;
  volatile size_t href_size = 0;

  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      ada::result<result_type> url = ada::parse<result_type>(url_string);
      if (url) {
        success++;
        if constexpr (!just_parse) {
          href_size += url->get_href().size();
        }
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        ada::result<result_type> url = ada::parse<result_type>(url_string);
        if (url) {
          success++;
          if constexpr (!just_parse) {
            href_size += url->get_href().size();
          }
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

auto BasicBench_AdaURL_href = BasicBench_AdaURL<PARSE_AND_HREF, ada::url>;
BENCHMARK(BasicBench_AdaURL_href);
auto BasicBench_AdaURL_aggregator_href =
    BasicBench_AdaURL<PARSE_AND_HREF, ada::url_aggregator>;
BENCHMARK(BasicBench_AdaURL_aggregator_href);

#if ADA_url_whatwg_ENABLED
size_t count_whatwg_invalid() {
  size_t how_many = 0;
  for (std::string& url_string : url_examples) {
    upa::url url;
    if (!upa::success(url.parse(url_string, nullptr))) {
      how_many++;
    }
  }
  return how_many;
}

template <bool just_parse = PARSE_AND_HREF>
static void BasicBench_whatwg(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t success = 0;
  volatile size_t href_size = 0;
  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      upa::url url;
      if (upa::success(url.parse(url_string, nullptr))) {
        success++;
        if (!just_parse) {
          href_size += url.href().size();
        }
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        upa::url url;
        if (upa::success(url.parse(url_string, nullptr))) {
          success++;
          if (!just_parse) {
            href_size += url.href().size();
          }
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
  (void)href_size;
  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate |
                                   benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_whatwg);
// There is no need for BasicBench_whatwg_just_parse because whatwg appears to
// provide the href at a minimal cost, probably because it is already
// materialized. auto BasicBench_whatwg_just_parse =
// BasicBench_whatwg<JUST_PARSE>; BENCHMARK(BasicBench_whatwg_just_parse);

#endif  // ADA_url_whatwg_ENABLED

#if ADA_CURL_ENABLED
#include <curl/curl.h>

size_t count_curl_invalid() {
  size_t how_many = 0;
  CURLU* url = curl_url();
  for (std::string& url_string : url_examples) {
    CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
    // Returns a CURLUcode error value, which is (0) if everything went fine.
    if (rc != 0) {
      how_many++;
    }
  }
  curl_url_cleanup(url);
  return how_many;
}

// curl follows RFC3986+
template <bool just_parse = false>
static void BasicBench_CURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t success = 0;
  volatile size_t href_size = 0;

  CURLU* url = curl_url();
  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
      // Returns a CURLUcode error value, which is (0) if everything went fine.
      if (rc == 0) {
        success++;
        if (!just_parse) {
          char* buffer;
          // When asked to return the full URL, curl_url_get will return a
          // normalized and possibly cleaned up version of what was previously
          // parsed.
          rc = curl_url_get(url, CURLUPART_URL, &buffer, 0);
          if (rc == 0) {
            href_size += strlen(buffer);
            curl_free(buffer);
          }
        }
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
        // Returns a CURLUcode error value, which is (0) if everything went
        // fine.
        if (!just_parse) {
          char* buffer;
          rc = curl_url_get(url, CURLUPART_URL, &buffer, 0);
          if (rc == 0) {
            href_size += strlen(buffer);
            curl_free(buffer);
          }
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
  curl_url_cleanup(url);
  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate |
                                   benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_CURL);
// 'just parsing' is faster with curl, but maybe not so important for us.
// auto BasicBench_CURL_just_parse = BasicBench_CURL<JUST_PARSE>;
// BENCHMARK(BasicBench_CURL_just_parse);
#endif

#if ADA_BOOST_ENABLED
#include <boost/url/src.hpp>
using namespace boost::urls;

size_t count_boosturl_invalid() {
  size_t how_many = 0;
  for (std::string& url_string : url_examples) {
    try {
      url u(url_string);
      u.normalize();
    } catch (...) {
      how_many++;
    }
  }
  return how_many;
}

// Boost URL follows RFC3986
template <bool just_parse = false>
static void BasicBench_BoostURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t success = 0;
  volatile size_t href_size = 0;

  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      try {
        url u(url_string);
        u.normalize();
        success++;
        if (!just_parse) {
          href_size += u.buffer().size();
        }
      } catch (...) {
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        try {
          url u(url_string);
          u.normalize();
          success++;
          if (!just_parse) {
            href_size += u.buffer().size();
          }
        } catch (...) {
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
  (void)href_size;

  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate |
                                   benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate);
}
BENCHMARK(BasicBench_BoostURL);
// There is no need for 'just_parse' because BoostURL materializes the href.
// auto BasicBench_BoostURL_just_parse = BasicBench_BoostURL<JUST_PARSE>;
// BENCHMARK(BasicBench_BoostURL_just_parse);
#endif  // ADA_BOOST_ENABLED

#if ADA_ZURI_ENABLED
#include <zuri.h>

size_t count_zuri_invalid() {
  size_t how_many = 0;
  for (std::string& url_string : url_examples) {
    struct zuri2k uri;
    zuri_error err = zuri_parse2k(&uri, url_string.c_str());
    if (err) how_many++;
  }
  return how_many;
}

// ZURI follows RFC3986
template <bool just_parse = false>
static void BasicBench_ZURI(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t success = 0;
  volatile size_t href_size = 0;

  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      struct zuri2k uri;
      benchmark::DoNotOptimize(uri);
      zuri_error err = zuri_parse2k(&uri, url_string.c_str());
      if (!err) {
        success++;
        if constexpr (!just_parse) {
          char buf[2048];
          benchmark::DoNotOptimize(href_size +=
                                   zuri_read2k(&uri, &buf[0], sizeof(buf)));
        }
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        struct zuri2k uri;
        benchmark::DoNotOptimize(uri);
        zuri_error err = zuri_parse2k(&uri, url_string.c_str());
        if (!err) {
          success++;
          if constexpr (!just_parse) {
            char buf[2048];
            benchmark::DoNotOptimize(href_size +=
                                     zuri_read2k(&uri, &buf[0], sizeof(buf)));
          }
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
  (void)href_size;

  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate |
                                   benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] = benchmark::Counter(
      std::size(url_examples), benchmark::Counter::kIsIterationInvariantRate);
}

BENCHMARK(BasicBench_ZURI);
#endif  // ADA_ZURI_ENABLED

#if ADA_VARIOUS_COMPETITION_ENABLED
static void BasicBench_uriparser_just_parse(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;
  const char* errorPos;
  UriUriA uri;
  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      is_valid &= (uriParseSingleUriA(&uri, url_string.c_str(), &errorPos) ==
                   URI_SUCCESS);
    }
  }
  if (!is_valid) {
    std::cout << "uri-parser: invalid? " << std::endl;
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        is_valid &= (uriParseSingleUriA(&uri, url_string.c_str(), &errorPos) ==
                     URI_SUCCESS);
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
  uriFreeUriMembersA(&uri);

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
BENCHMARK(BasicBench_uriparser_just_parse);
#endif  // ADA_VARIOUS_COMPETITION_ENABLED

#if ADA_VARIOUS_COMPETITION_ENABLED
static void BasicBench_urlparser_just_parse(benchmark::State& state) {
  // volatile to prevent optimizations.
  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      std::unique_ptr<EdUrlParser> url(EdUrlParser::parseUrl(url_string));
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        std::unique_ptr<EdUrlParser> url(EdUrlParser::parseUrl(url_string));
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
BENCHMARK(BasicBench_urlparser_just_parse);
#endif  // ADA_VARIOUS_COMPETITION_ENABLED

#if ADA_VARIOUS_COMPETITION_ENABLED
static void BasicBench_http_parser_just_parse(benchmark::State& state) {
  volatile bool is_valid{true};
  struct http_parser_url u;
  http_parser_url_init(&u);
  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      is_valid &=
          !http_parser_parse_url(url_string.data(), url_string.size(), 0, &u);
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        is_valid &=
            !http_parser_parse_url(url_string.data(), url_string.size(), 0, &u);
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

  if (!is_valid) {
    std::cout << "http_parser: invalid? " << std::endl;
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
BENCHMARK(BasicBench_http_parser_just_parse);
#endif  // ADA_VARIOUS_COMPETITION_ENABLED

#if defined(ADA_RUST_VERSION)
#include "competitors/servo-url/servo_url.h"
size_t count_rust_invalid() {
  size_t how_many = 0;
  for (std::string& url_string : url_examples) {
    servo_url::Url* url =
        servo_url::parse_url(url_string.c_str(), url_string.length());
    servo_url::free_url(url);
    if (!url) {
      how_many++;
    }
  }
  return how_many;
}

// Emilio from Mozilla recommended that using an opaque-pointer will improve the
// performance of this benchmark. It has indeed improved but with the cost of
// validating the output. Reference:
// https://twitter.com/ecbos_/status/1627494441656238082?s=61&t=vCdcfSGWHH056CBdklWfCg
static void BasicBench_ServoUrl(benchmark::State& state) {
  // Other benchmarks copy the 'standard url' to a structure.
  // We try to mimic the effect.
  volatile size_t success = 0;

  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      // benchmark::DoNotOptimize is unnecessary and potentially misleading.
      const char* url_href =
          servo_url::parse_url_to_href(url_string.c_str(), url_string.length());
      if (url_href) {
        // if you'd like you could print it: printf("%s\n", url_href);
        success++;
        servo_url::free_string(url_href);
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        const char* url_href = servo_url::parse_url_to_href(
            url_string.c_str(), url_string.length());
        if (url_href) {
          success++;
          servo_url::free_string(url_href);
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
BENCHMARK(BasicBench_ServoUrl);
#endif  // ADA_RUST

int main(int argc, char** argv) {
  if (argc > 1 && file_exists(argv[1])) {
    init_data(argv[1]);
  } else {
    init_data();
  }
  benchmark::AddCustomContext("ada spec", "Ada follows whatwg/url");
  size_t ada_bad_url = count_ada_invalid();
#if ADA_url_whatwg_ENABLED
  size_t whatwg_bad_url = count_whatwg_invalid();
#endif
#if defined(ADA_RUST_VERSION)
  benchmark::AddCustomContext("rust version ", ADA_RUST_VERSION);
  size_t servo_bad_url = count_rust_invalid();
#endif
#if ADA_CURL_ENABLED
  // the curl dependency will depend on the system.
  benchmark::AddCustomContext("curl version ", LIBCURL_VERSION);
  benchmark::AddCustomContext("curl spec",
                              "Curl follows RFC3986, not whatwg/url");
  size_t curl_bad_url = count_curl_invalid();
#else
  benchmark::AddCustomContext("curl ", "OMITTED");
#endif
#if ADA_BOOST_ENABLED
  benchmark::AddCustomContext("boost-url spec",
                              "Boost URL follows RFC3986, not whatwg/url");
  size_t boost_bad_url = count_boosturl_invalid();
#endif
#if ADA_ZURI_ENABLED
  benchmark::AddCustomContext("zuri spec",
                              "Zuri follows RFC3986, not whatwg/url");
  size_t zuri_bad_url = count_zuri_invalid();
#else
  benchmark::AddCustomContext("zuri ", "OMITTED");
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
  benchmark::AddCustomContext("input bytes",
                              std::to_string(size_t(url_examples_bytes)));
  benchmark::AddCustomContext("number of URLs",
                              std::to_string(std::size(url_examples)));
  benchmark::AddCustomContext(
      "bytes/URL",
      std::to_string(url_examples_bytes / std::size(url_examples)));
#if ADA_VARIOUS_COMPETITION_ENABLED
  benchmark::AddCustomContext("WARNING",
                              "BasicBench_urlparser and BasicBench_uriparser "
                              "do not use a normalized task.");
#endif
  if (collector.has_events()) {
    benchmark::AddCustomContext("performance counters", "Enabled");
  }
  std::stringstream badcounts;
  badcounts << "---------------------\n";
  badcounts << "ada---count of bad URLs       " << std::to_string(ada_bad_url)
            << "\n";
#if defined(ADA_RUST_VERSION)
  badcounts << "servo/url---count of bad URLs " << std::to_string(servo_bad_url)
            << "\n";
#endif
#if ADA_url_whatwg_ENABLED
  badcounts << "whatwg---count of bad URLs    "
            << std::to_string(whatwg_bad_url) << "\n";
#endif
#if ADA_CURL_ENABLED
  badcounts << "curl---count of bad URLs      " << std::to_string(curl_bad_url)
            << "\n";
#endif
#if ADA_BOOST_ENABLED
  badcounts << "boost-url---count of bad URLs " << std::to_string(boost_bad_url)
            << "\n";
#endif
#if ADA_ZURI_ENABLED
  badcounts << "zuri---count of bad URLs      " << std::to_string(zuri_bad_url)
            << "\n";
#endif
  badcounts << "-------------------------------\n";
  benchmark::AddCustomContext("bad urls", badcounts.str());

  if (size_t(url_examples_bytes) > 1000000) {
    N = 10;
  }

  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}

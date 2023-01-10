#include <iostream>
#include <memory>
#include <uriparser/Uri.h>
#include <EdUrlParser.h>
#include <http_parser.h>

#include "ada.h"

#include <benchmark/benchmark.h>


/**
 * Realistic URL examples collected on the actual web.
 */
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
    "postgresql://other:9818274x1!!@localhost:5432/otherdb?connect_timeout=10&application_name=myapp",
    "http://192.168.1.1", // ipv4
    "http://[2606:4700:4700::1111]", // ipv6
};

double url_examples_bytes =  []() {
    size_t bytes{0};
    for(std::string& url_string : url_examples) { bytes += url_string.size(); }
    return bytes;
  }();

#if BOOST_ENABLED
#include <boost/url/src.hpp>
using namespace boost::urls;

static void BasicBench_BoostURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;

  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
        url_view uv(url_string);
        numbers_of_parameters += uv.params().size();
    }
  }
  (void)numbers_of_parameters;

  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
}
BENCHMARK(BasicBench_BoostURL);
#endif


#if CURL_ENABLED
#include <curl/curl.h>

static void BasicBench_CURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid{true};
  CURLU *url = curl_url();
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_string.c_str(), 0);
      if(rc) { is_valid = false; }
    }
  }
  curl_url_cleanup(url);


  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
}
BENCHMARK(BasicBench_CURL);
#endif

static void BasicBench_uriparser(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;
  const char * errorPos;
  UriUriA uri;
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
        is_valid &= (uriParseSingleUriA(&uri, url_string.c_str(), &errorPos) == URI_SUCCESS);
    }
  }
  uriFreeUriMembersA(&uri);
  if(!is_valid) { std::cout << "uri-parser: invalid? " << std::endl; }
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
}
BENCHMARK(BasicBench_uriparser);


static void BasicBench_urlparser(benchmark::State& state) {
  // volatile to prevent optimizations.
  const char * errorPos;
  UriUriA uri;
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      std::unique_ptr<EdUrlParser> url(EdUrlParser::parseUrl(url_string));
    }
  }
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
}
BENCHMARK(BasicBench_urlparser);

static void BasicBench_http_parser(benchmark::State& state) {
  volatile bool is_valid{true};
  struct http_parser_url u;
  http_parser_url_init(&u);
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
      is_valid &= !http_parser_parse_url(url_string.data(), url_string.size(), 0, &u);
    }
  }
  if(!is_valid) { std::cout << "http_parser: invalid? " << std::endl; }
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
}
BENCHMARK(BasicBench_http_parser);

static void BasicBench_AdaURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;
  for (auto _ : state) {
    for(std::string& url_string : url_examples) {
        auto url = ada::parser::parse_url(url_string, std::nullopt);
        is_valid &= url.is_valid;
    }
  }
  if(!is_valid) { std::cout << "ada: invalid? " << std::endl; }
  state.counters["time/byte"] = benchmark::Counter(
	        url_examples_bytes,
          benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
}
BENCHMARK(BasicBench_AdaURL);

int main(int argc, char **argv) {
#if CURL_ENABLED
    // the curl dependency will depend on the system.
    benchmark::AddCustomContext("curl version ", LIBCURL_VERSION);
#else
    benchmark::AddCustomContext("curl ", "OMITTED");
#endif
#if !BOOST_ENABLED
    benchmark::AddCustomContext("boost ", "OMITTED");
#endif
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
}

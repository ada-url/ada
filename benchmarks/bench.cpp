#include <iostream>
#include <boost/url/src.hpp>
#include <uriparser/Uri.h>

#include "ada.h"

#include <benchmark/benchmark.h>
using namespace boost::urls;


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
    "https://www.reddit.com/login/?dest=https%3A%2F%2Fwww.reddit.com%2F"};




static void BasicBench_BoostURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t numbers_of_parameters = 0;
  for (auto _ : state) {
    for(std::string url_string : url_examples) {
        url_view uv(url_string);
        numbers_of_parameters += uv.params().size();
    }
  }
  (void)numbers_of_parameters;
}
BENCHMARK(BasicBench_BoostURL);

static void BasicBench_uriparser(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;
  const char * errorPos;
  UriUriA uri;
  for (auto _ : state) {
    for(std::string url_string : url_examples) {
        is_valid &= (uriParseSingleUriA(&uri, url_string.c_str(), &errorPos) == URI_SUCCESS);
    }
  }
  uriFreeUriMembersA(&uri);
  if(!is_valid) { std::cout << "invalid? " << std::endl; }
}
BENCHMARK(BasicBench_uriparser);

static void BasicBench_AdaURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile bool is_valid = true;
  for (auto _ : state) {
    for(std::string url_string : url_examples) {
        auto url = ada::parser::parse_url(url_string, std::nullopt);
        is_valid &= url.is_valid;
    }
  }
  if(!is_valid) { std::cout << "invalid? " << std::endl; }
}
BENCHMARK(BasicBench_AdaURL);

BENCHMARK_MAIN();

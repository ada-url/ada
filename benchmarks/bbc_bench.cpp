#include "benchmark_header.h"

/**
 * Realistic URL examples collected from the BBC homepage.
 */
std::string url_examples[] = {
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/js/"
    "polyfills.js",
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/"
    "css/orbit-v5-ltr.min.css",
    "https://static.files.bbci.co.uk/orbit/737a4ee2bed596eb65afc4d2ce9af568/js/"
    "require.min.js",
    "https://static.files.bbci.co.uk/fonts/reith/2.512/BBCReithSans_W_Rg.woff2",
    "https://nav.files.bbci.co.uk/searchbox/c8bfe8595e453f2b9483fda4074e9d15/"
    "css/box.css",
    "https://static.files.bbci.co.uk/cookies/d3bb303e79f041fec95388e04f84e716/"
    "cookie-banner/cookie-library.bundle.js",
    "https://static.files.bbci.co.uk/account/id-cta/597/style/id-cta.css",
    "https://gn-web-assets.api.bbc.com/wwhp/"
    "20220908-1153-091014d07889c842a7bdc06e00fa711c9e04f049/responsive/css/"
    "old-ie.min.css",
    "https://gn-web-assets.api.bbc.com/wwhp/"
    "20220908-1153-091014d07889c842a7bdc06e00fa711c9e04f049/modules/vendor/"
    "bower/modernizr/modernizr.js"};

void init_data(const char* v = nullptr) {}

double url_examples_bytes = []() -> double {
  size_t bytes{0};
  for (std::string& url_string : url_examples) {
    bytes += url_string.size();
  }
  return double(bytes);
}();

#include "benchmark_template.cpp"

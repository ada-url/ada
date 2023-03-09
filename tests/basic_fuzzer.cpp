
#include "ada.h"
#include <iostream>
#include <memory>

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
    "bower/modernizr/modernizr.js"
};

// This function copies your input onto a memory buffer that
// has just the necessary size. This will entice tools to detect
// an out-of-bound access.
ada::result<ada::url> ada_parse(std::string_view view) {
  std::unique_ptr<char[]> buffer(new char[view.size()]);
  memcpy(buffer.get(), view.data(), view.size());
  return ada::parse(std::string_view(buffer.get(), view.size()));
}

size_t fancy_fuzz(size_t N, size_t seed = 0) {
    size_t counter = seed;
    for(size_t trial = 0; trial < N; trial++) {
        std::string copy = url_examples[(seed++)%(sizeof(url_examples)/sizeof(std::string))];
        auto url = ada::parse(copy);
        while(url) {
            // mutate the string.
            int k = ((321321*counter++) %3);
            switch(k) {
                case 0:
                  copy.erase((11134*counter++)%copy.size());
                  break;
                case 1:
                  copy.insert(copy.begin()+(211311*counter)%copy.size(), char((counter+1)*777)); counter += 2;
                  break;
                case 2:
                  copy[(13134*counter++)%copy.size()] = char(counter++*71117);
                  break;
                default:
                  break;
            }
            url = ada_parse(copy);
        }
    }
    return counter;
}

size_t simple_fuzz(size_t N, size_t seed = 0) {
    size_t counter = seed;
    for(size_t trial = 0; trial < N; trial++) {
        std::string copy = url_examples[(seed++)%(sizeof(url_examples)/sizeof(std::string))];
        auto url = ada::parse(copy);
        while(url) {
            // mutate the string.
            copy[(13134*counter++)%copy.size()] = char(counter++*71117);
            url = ada_parse(copy);
        }
    }
    return counter;
}


size_t roller_fuzz(size_t N) {
    size_t valid{};

    for(std::string copy : url_examples) {
        for(int index = 0; index < copy.size(); index++) {
            char orig = copy[index];
            for(unsigned int value = 0; value < 255; value++) {
              copy[index] = char(value);
              auto url = ada_parse(copy);
              if(url) { valid++; }
            }
            copy[index] = orig;
        }
    }
    return valid;
}

int main() {
#if ADA_HAS_ICU
  std::cout << "We are using ICU."<< std::endl;
#else
  std::cout << "We are not using ICU."<< std::endl;
#endif
#if ADA_IS_BIG_ENDIAN
  std::cout << "You have big-endian system."<< std::endl;
#else
  std::cout << "You have litte-endian system."<< std::endl;
#endif
  std::cout << "Running basic fuzzer.\n";
  std::cout << "[fancy]  Executed " << fancy_fuzz(100000) << " mutations.\n";
#if ADA_HAS_ICU
  std::cout << "[simple] Executed " << simple_fuzz(40000) << " mutations.\n";
#endif
  std::cout << "[roller] Executed " << roller_fuzz(40000) << " correct cases.\n";
  return EXIT_SUCCESS;
}

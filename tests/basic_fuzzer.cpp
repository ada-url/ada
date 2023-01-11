
#include "ada.h"
#include <iostream>

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
size_t fuzz(size_t N, size_t seed = 0) {
    size_t counter = seed;
    for(size_t trial = 0; trial < N; trial++) {
        std::string copy = url_examples[(seed++)%(sizeof(url_examples)/sizeof(std::string))];
        auto url = ada::parser::parse_url(copy, std::nullopt);
        while(url.is_valid) {
            // mutate the string.
            int k = ((321321*counter++) %3);
            switch(k) {
                case 0:
                  copy.erase((11134*counter++)%copy.size());
                  break;
                case 1:
                  copy.insert(copy.begin()+(211311*counter++)%copy.size(), char(counter++*777));
                  break;
                case 2:
                  copy[(13134*counter++)%copy.size()] = char(counter++*71117);
                  break;
                default:
                  break;
            }
            url = ada::parser::parse_url(copy, std::nullopt);
        }
    }
    return counter;
}

int main() {
  std::cout << "Running basic fuzzer.\n";
  std::cout << "Excuted " << fuzz(200000) << " mutations.\n";
  return EXIT_SUCCESS;
}

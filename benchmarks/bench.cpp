#include "benchmark_header.h"

/**
 * Realistic URL examples collected on the actual web.
 */
std::string url_examples_default[] = {
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

std::vector<std::string> url_examples;

double url_examples_bytes = []() -> double {
  size_t bytes{0};
  for (std::string& url_string : url_examples) {
    bytes += url_string.size();
  }
  return double(bytes);
}();

#ifdef ADA_URL_FILE
const char* default_file = ADA_URL_FILE;
#else
const char* default_file = nullptr;
#endif

size_t init_data(const char* input = default_file) {
  // compute the number of bytes.
  auto compute = []() -> double {
    size_t bytes{0};
    for (std::string& url_string : url_examples) {
      bytes += url_string.size();
    }
    return double(bytes);
  };
  if (input == nullptr) {
    for (const std::string& s : url_examples_default) {
      url_examples.emplace_back(s);
    }
    url_examples_bytes = compute();
    return url_examples.size();
  }

  if (!file_exists(input)) {
    std::cout << "File not found !" << input << std::endl;
    for (const std::string& s : url_examples_default) {
      url_examples.emplace_back(s);
    }
  } else {
    std::cout << "Loading " << input << std::endl;
    url_examples = split_string(read_file(input));
  }
  url_examples_bytes = compute();
  return url_examples.size();
}
#include "benchmark_template.cpp"

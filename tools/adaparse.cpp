#include <cstdlib>
#include <iostream>
#include <string_view>

#include "ada.h"
/**
 * @private
 *
 * Running this executable, you can quickly test ada:
 *
 * $ adaparse "http://www.google.com/bal?a==11#fddfds"
 * {
 *       "buffer":"http://www.google.com/bal?a==11#fddfds",
 *       "protocol":"http:",
 *       "host":"www.google.com",
 *       "path":"/bal",
 *       "opaque path":false,
 *       "query":"?a==11",
 *       "fragment":"#fddfds",
 *       "protocol_end":5,
 *       "username_end":7,
 *       "host_start":7,
 *       "host_end":21,
 *       "port":null,
 *       "pathname_start":21,
 *       "search_start":25,
 *       "hash_start":31
 * }
 *
 * $ ./buildbench/tools/adaparse -d http://www.google.com/bal\?a\=\=11\#fddfds
 * http://www.google.com/bal?a==11#fddfds [38 bytes]
 *      | |             |   |     |
 *      | |             |   |     `------ hash_start
 *      | |             |   `------------ search_start 25
 *      | |             `---------------- pathname_start 21
 *      | |             `---------------- host_end 21
 *      | `------------------------------ host_start 7
 *      | `------------------------------ username_end 7
 *      `-------------------------------- protocol_end 5
 **/
int main(int argc, char** argv) {
  if (argc < 2) {
    std::cout << "use a URL as a parameter." << std::endl;
    return EXIT_SUCCESS;
  }
  std::string url_string = argv[1];
  bool to_diagram = false;
  if (argc > 2) {
    if (std::string_view(argv[1]) == "-d") {
      url_string = argv[2];
      to_diagram = true;
    }
  }
  ada::result<ada::url_aggregator> url = ada::parse(url_string);
  if (!url) {
    std::cerr << "Invalid." << std::endl;
    return EXIT_FAILURE;
  }
  if (to_diagram) {
    std::cout << url->to_diagram() << std::endl;
  } else {
    std::cout << *url << std::endl;
  }
  return EXIT_SUCCESS;
}

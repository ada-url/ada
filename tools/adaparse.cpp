#include <cstdlib>
#include <iostream>
#include <string_view>
#include <cxxopts.hpp>
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
  cxxopts::Options options("adaparse",
                           "Command-line version of the Ada URL parser");

  options.add_options()("d,diagram", "Print a diagram of the result",
                        cxxopts::value<bool>()->default_value("false"))(
      "u,url", "URL Parameter (required)", cxxopts::value<std::string>())(
      "h,help", "Print usage");
  options.parse_positional({"url"});

  auto result = options.parse(argc, argv);
  // the first argument without an option name will be parsed into file
  if (result.count("help") || !result.count("url")) {
    std::cout << options.help() << std::endl;
    return EXIT_SUCCESS;
  }
  std::string url_string = result["url"].as<std::string>();
  bool to_diagram = result["diagram"].as<bool>();
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

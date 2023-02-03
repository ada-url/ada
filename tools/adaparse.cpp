#include <cstdlib>
#include <iostream>

#include "ada.h"
/**
 * @private
 *
 * Running this executable, you can quickly test ada:
 *
 * $ adaparse "http://www.google.com/bal?a==11#fddfds"
 * {
 *       "scheme":"http",
 *       "host":"www.google.com",
 *       "path":"/bal",
 *       "opaque path":false,
 *       "query":"a==11",
 *       "fragment":"fddfds"
 * }
 **/
int main(int argc, char**argv) {
    if(argc<2) {
        std::cout << "use a URL as a parameter." << std::endl;
        return EXIT_SUCCESS;
    }
    auto url = ada::parse(argv[1]);
    if(!url) { std::cerr << "Invalid." << std::endl; return EXIT_FAILURE; }
    std::cout << *url << std::endl;
    return EXIT_SUCCESS;
}

#include <cstring>
#include <arpa/inet.h>

namespace ada::serializers {

  std::string ipv6(std::string_view input) {
    char output[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, input.begin(), output, sizeof(output));
    return output;
  }

} // namespace ada::serializers

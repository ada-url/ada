#include "ada/serializers.h"
#include "ada/ip_address.h"

#include <array>
#include <string>

namespace ada::serializers {

void find_longest_sequence_of_ipv6_pieces(
    const std::array<uint16_t, 8>& address, size_t& compress,
    size_t& compress_length) noexcept {
  compress = 0;
  compress_length = 0;
  for (size_t i = 0; i < 8; i++) {
    if (address[i] == 0) {
      size_t next = i + 1;
      while (next != 8 && address[next] == 0) ++next;
      const size_t count = next - i;
      if (compress_length < count) {
        compress_length = count;
        compress = i;
        if (next == 8) break;
        i = next;
      }
    }
  }
}

std::string ipv6(const std::array<uint16_t, 8>& address) {
  return ip_address::serialize_ipv6(address);
}

std::string ipv4(const uint64_t address) {
  return ip_address::serialize_ipv4(static_cast<uint32_t>(address));
}

}  // namespace ada::serializers

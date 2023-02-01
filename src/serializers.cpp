#include "ada.h"

#include <array>
#include <string>

namespace ada::serializers {

  void find_longest_sequence_of_ipv6_pieces(const std::array<uint16_t, 8>& address, size_t& compress, size_t& compress_length) noexcept {
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

  std::string ipv6(const std::array<uint16_t, 8>& address) noexcept {
    size_t compress_length = 0;
    size_t compress = 0;
    find_longest_sequence_of_ipv6_pieces(address, compress, compress_length);

    if (compress_length <= 1) {
      // Optimization opportunity: Find a faster way then snprintf for imploding and return here.
      compress = compress_length = 8;
    }

    std::string output{};
    size_t piece_index = 0;
    char buf[5];

    while (true) {
      if (piece_index == compress) {
        output.append("::", piece_index == 0 ? 2 : 1);
        if ((piece_index = piece_index + compress_length) == 8) break;
      }

      // Optimization opportunity: Get rid of snprintf.
      snprintf(buf, 5, "%x", address[piece_index]);
      output += buf;
      if (++piece_index == 8) break;
      output.push_back(':');
    }

    return "[" + output + "]";
  }

  std::string ipv4(const uint64_t address) noexcept {
    std::string output(15, '\0');
    char *point = output.data();
    char *point_end = output.data() + output.size();
    point = std::to_chars(point, point_end, uint8_t(address >> 24)).ptr;
    for (int i = 2; i >= 0; i--) {
     *point++ = '.';
     point = std::to_chars(point, point_end, uint8_t(address >> (i * 8))).ptr;
    }
    output.resize(point - output.data());
    return output;
  }

} // namespace ada::serializers

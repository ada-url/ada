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
    // Let output be the empty string.
    std::string output{};

    // Let n be the value of address.
    auto n = address;

    // For each i in the range 1 to 4, inclusive:
    for (size_t i = 1; i <= 4; i++) {
      // Prepend n % 256, serialized, to output.
      output.insert(0, std::to_string(n % 256));

      // If i is not 4, then prepend U+002E (.) to output.
      if (i != 4) {
        output.insert(0, ".");
      }

      // Set n to floor(n / 256).
      n >>= 8;
    }

    // Return output.
    return output;
  }

} // namespace ada::serializers

#include <array>
#include <string>

namespace ada::serializers {

  size_t find_longest_sequence_of_ipv6_pieces(const std::array<uint16_t, 8>& address) noexcept {
    size_t last_count = 1;
    size_t result = -1;
    for (size_t i = 0; i < 8; i++) {
      if (address[i] == 0) {
        size_t next = i + 1;
        while (next != 8 && address[next] == 0) ++next;
        const size_t count = next - i;
        if (last_count < count) {
          last_count = count;
          result = i;
          if (next == 8) break;
          i = next;
        }
      }
    }
    return result;
  }

  std::string ipv6(const std::array<uint16_t, 8>& address) noexcept {
    // Let output be the empty string.
    std::string output{};

    // Let compress be an index to the first IPv6 piece in the first longest sequences of address’s IPv6 pieces that are 0.
    size_t compress = find_longest_sequence_of_ipv6_pieces(address);

    // Let ignore0 be false.
    bool ignore_0{false};

    // For each pieceIndex in the range 0 to 7, inclusive:
    for (size_t piece_index = 0; piece_index < 8; piece_index++) {
      // If ignore0 is true and address[pieceIndex] is 0, then continue.
      if (ignore_0 && address[piece_index] == 0) {
        continue;
      }
      // Otherwise, if ignore0 is true, set ignore0 to false.
      else if (ignore_0) {
        ignore_0 = false;
      }

      // If compress is pieceIndex, then:
      if (compress == piece_index) {
        // Let separator be "::" if pieceIndex is 0, and U+003A (:) otherwise.
        // Append separator to output.
        output += (piece_index == 0) ? "::" : ":";

        // Set ignore0 to true and continue.
        ignore_0 = true;
        continue;
      }

      // Append address[pieceIndex], represented as the shortest possible lowercase hexadecimal number, to output.
      char buf[5];
      snprintf(buf, sizeof(buf), "%x", address[piece_index]);
      output += buf;

      // If pieceIndex is not 7, then append U+003A (:) to output.
      if (piece_index < 7) {
        output += ':';
      }
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

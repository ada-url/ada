#include <array>
#include <cmath>
#include <cstring>

namespace ada::serializers {

  std::optional<size_t> find_longest_sequence_of_ipv6_pieces(const std::array<uint16_t, 8> address) noexcept {
    std::optional<size_t> max_index{};
    size_t max_length = 1;
    std::optional<size_t> current_start{};
    size_t current_length = 0;

    for (size_t i = 0; i < address.size(); i++) {
      if (address[i] != 0) {
        if (current_length > max_length) {
          max_index = current_start;
          max_length = current_length;
        }

        current_start = std::nullopt;
        current_length = 0;
      } else {
        current_start = current_start.value_or(i);
        current_length++;
      }
    }

    if (current_length > max_length) {
      return current_start;
    }

    return max_index;
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv6-serializer
   */
  std::string ipv6(const std::array<uint16_t, 8> address) noexcept {
    // Let output be the empty string.
    std::string output{};

    // Let compress be an index to the first IPv6 piece in the first longest sequences of address’s IPv6 pieces that are 0.
    // If there is no sequence of address’s IPv6 pieces that are 0 that is longer than 1, then set compress to null.
    std::optional<size_t> compress = find_longest_sequence_of_ipv6_pieces(address);

    // Let ignore0 be false.
    bool ignore_0{};

    // For each pieceIndex in the range 0 to 7, inclusive:
    for (size_t piece_index = 0; piece_index < address.size(); piece_index++) {
      // If ignore0 is true and address[pieceIndex] is 0, then continue.
      if (ignore_0 && address[piece_index] == 0) {
        continue;
      }

      // Otherwise, if ignore0 is true, set ignore0 to false.
      ignore_0 = false;

      // If compress is pieceIndex, then:
      if (compress.has_value() && *compress == piece_index) {
        // Let separator be "::" if pieceIndex is 0, and U+003A (:) otherwise.
        std::string separator = (piece_index == 0) ? "::" : ":";

        // Append separator to output.
        output += separator;

        // Set ignore0 to true and continue.
        ignore_0 = true;
        continue;
      }

      // Append address[pieceIndex], represented as the shortest possible lowercase hexadecimal number, to output.
      std::string piece_index_output{};
      ada::helpers::from_decimal(piece_index_output, 16, address[piece_index]);
      output += piece_index_output;

      // If pieceIndex is not 7, then append U+003A (:) to output.
      if (piece_index != 7) {
        output += ':';
      }
    }

    return "[" + output + "]";
  }

  /**
   * @see https://url.spec.whatwg.org/#concept-ipv4-serializer
   */
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
      n = static_cast<uint64_t>(floor((double)n / 256));
    }

    // Return output.
    return output;
  }

} // namespace ada::serializers

#include "ada/serializers.h"
#include "ada/common_defs.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace ada::serializers {
namespace {

// Digit pair LUT for fast decimal write: index 0..99 -> two chars.
constexpr std::array<char, 200> make_digit_pairs() noexcept {
  std::array<char, 200> t{};
  for (size_t i = 0; i < 100; ++i) {
    t[i * 2] = static_cast<char>('0' + i / 10);
    t[i * 2 + 1] = static_cast<char>('0' + i % 10);
  }
  return t;
}

constexpr auto digit_pairs = make_digit_pairs();

ada_really_inline char* write_u8(char* p, uint8_t v) noexcept {
  if (v < 10) {
    *p++ = static_cast<char>('0' + v);
  } else if (v < 100) {
    std::memcpy(p, &digit_pairs[static_cast<size_t>(v) * 2], 2);
    p += 2;
  } else {
    *p++ = static_cast<char>('0' + v / 100);
    std::memcpy(p, &digit_pairs[static_cast<size_t>(v % 100) * 2], 2);
    p += 2;
  }
  return p;
}

ada_really_inline char* write_hex_u16(char* p, uint16_t v) noexcept {
  static constexpr char kHex[] = "0123456789abcdef";
  if (v >= 0x1000) {
    *p++ = kHex[(v >> 12) & 0xf];
    *p++ = kHex[(v >> 8) & 0xf];
    *p++ = kHex[(v >> 4) & 0xf];
    *p++ = kHex[v & 0xf];
  } else if (v >= 0x100) {
    *p++ = kHex[(v >> 8) & 0xf];
    *p++ = kHex[(v >> 4) & 0xf];
    *p++ = kHex[v & 0xf];
  } else if (v >= 0x10) {
    *p++ = kHex[(v >> 4) & 0xf];
    *p++ = kHex[v & 0xf];
  } else {
    *p++ = kHex[v & 0xf];
  }
  return p;
}

}  // namespace

void find_longest_sequence_of_ipv6_pieces(
    const std::array<uint16_t, 8>& address, size_t& compress,
    size_t& compress_length) noexcept {
  compress = 0;
  compress_length = 0;
  size_t i = 0;
  while (i < 8) {
    if (address[i] != 0) {
      ++i;
      continue;
    }
    size_t next = i + 1;
    while (next < 8 && address[next] == 0) {
      ++next;
    }
    const size_t count = next - i;
    if (count > compress_length) {
      compress_length = count;
      compress = i;
    }
    i = next;
  }
}

std::string ipv6(const std::array<uint16_t, 8>& address) {
  size_t compress = 0;
  size_t compress_length = 0;
  find_longest_sequence_of_ipv6_pieces(address, compress, compress_length);

  // Skip compression when the longest zero run is a single piece.
  if (compress_length <= 1) {
    compress = compress_length = 8;
  }

  // Max: '[' + 8*4 hex + 7 ':' + ']' = 41
  std::string output(4 * 8 + 7 + 2, '\0');
  char* point = output.data();
  *point++ = '[';
  size_t piece_index = 0;
  while (true) {
    if (piece_index == compress) {
      *point++ = ':';
      // If we skip a value initially, we need to write '::'.
      if (piece_index == 0) {
        *point++ = ':';
      }
      piece_index += compress_length;
      if (piece_index == 8) {
        break;
      }
    }
    point = write_hex_u16(point, address[piece_index]);
    ++piece_index;
    if (piece_index == 8) {
      break;
    }
    *point++ = ':';
  }
  *point++ = ']';
  output.resize(static_cast<size_t>(point - output.data()));
  return output;
}

std::string ipv4(const uint64_t address) {
  std::string output(15, '\0');
  char* point = output.data();
  point = write_u8(point, static_cast<uint8_t>(address >> 24));
  *point++ = '.';
  point = write_u8(point, static_cast<uint8_t>(address >> 16));
  *point++ = '.';
  point = write_u8(point, static_cast<uint8_t>(address >> 8));
  *point++ = '.';
  point = write_u8(point, static_cast<uint8_t>(address));
  output.resize(static_cast<size_t>(point - output.data()));
  return output;
}

}  // namespace ada::serializers

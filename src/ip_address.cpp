#include "ada/ip_address.h"
#include "ada/ip_address-inl.h"
#include "ada/checkers-inl.h"
#include "ada/common_defs.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace ada::ip_address {
namespace {

// 256-entry: 0xff = not hex, else nibble value.
constexpr std::array<uint8_t, 256> make_hex_nibble_table() noexcept {
  std::array<uint8_t, 256> t{};
  for (size_t i = 0; i < 256; ++i) {
    t[i] = 0xff;
  }
  for (int d = 0; d < 10; ++d) {
    t[static_cast<size_t>('0' + d)] = static_cast<uint8_t>(d);
  }
  for (int d = 0; d < 6; ++d) {
    t[static_cast<size_t>('a' + d)] = static_cast<uint8_t>(10 + d);
    t[static_cast<size_t>('A' + d)] = static_cast<uint8_t>(10 + d);
  }
  return t;
}

constexpr auto hex_nibble = make_hex_nibble_table();

// Digit pair LUT for fast decimal write: index 0..99 -> two chars.
constexpr std::array<char, 200> make_digit_pairs() noexcept {
  std::array<char, 200> t{};
  for (int i = 0; i < 100; ++i) {
    t[static_cast<size_t>(i * 2)] = static_cast<char>('0' + i / 10);
    t[static_cast<size_t>(i * 2 + 1)] = static_cast<char>('0' + i % 10);
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
    const uint8_t rem = static_cast<uint8_t>(v % 100);
    std::memcpy(p, &digit_pairs[static_cast<size_t>(rem) * 2], 2);
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

// ---- IPv4 segment parser (hand-rolled, no from_chars) --------------------

ada_really_inline bool parse_ipv4_number(const char*& p, const char* end,
                                         uint64_t& value,
                                         bool& is_pure_decimal) noexcept {
  is_pure_decimal = false;
  if (p >= end) {
    return false;
  }

  // Hex: 0x / 0X
  if (end - p >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
    p += 2;
    if (p == end || *p == '.') {
      value = 0;
      return true;
    }
    uint64_t v = 0;
    int digits = 0;
    while (p < end && *p != '.') {
      const uint8_t nib = hex_nibble[static_cast<unsigned char>(*p)];
      if (nib == 0xff) {
        return false;
      }
      v = (v << 4) | nib;
      if (v > 0xFFFFFFFFULL) {
        return false;
      }
      ++p;
      ++digits;
    }
    if (digits == 0) {
      return false;
    }
    value = v;
    return true;
  }

  // Octal: leading 0 followed by a digit
  if (end - p >= 2 && p[0] == '0' && p[1] >= '0' && p[1] <= '9') {
    ++p;
    uint64_t v = 0;
    while (p < end && *p != '.') {
      const char c = *p;
      if (c < '0' || c > '7') {
        return false;
      }
      v = v * 8u + static_cast<uint64_t>(c - '0');
      if (v > 0xFFFFFFFFULL) {
        return false;
      }
      ++p;
    }
    value = v;
    return true;
  }

  // Decimal (including single "0")
  if (*p < '0' || *p > '9') {
    return false;
  }
  is_pure_decimal = true;
  uint64_t v = 0;
  while (p < end && *p != '.') {
    const char c = *p;
    if (c < '0' || c > '9') {
      return false;
    }
    v = v * 10u + static_cast<uint64_t>(c - '0');
    if (v > 0xFFFFFFFFULL) {
      return false;
    }
    ++p;
  }
  value = v;
  return true;
}

// ---- Optimized WHATWG IPv6 parser ----------------------------------------
// Raw pointers, int compress sentinel (-1), compress expansion without swaps.

bool parse_ipv6_impl(std::string_view input,
                     std::array<uint16_t, 8>& address) noexcept {
  if (input.empty() || input.size() > 45) {
    return false;
  }
  address.fill(0);

  const char* pointer = input.data();
  const char* const end = pointer + input.size();
  int piece_index = 0;
  int compress = -1;

  // Leading ':' must be part of '::'
  if (*pointer == ':') {
    if (input.size() == 1 || pointer[1] != ':') {
      return false;
    }
    pointer += 2;
    compress = ++piece_index;
  }

  while (pointer != end) {
    if (piece_index == 8) {
      return false;
    }
    if (*pointer == ':') {
      if (compress != -1) {
        return false;
      }
      ++pointer;
      compress = ++piece_index;
      continue;
    }

    // Collect up to 4 hex digits
    uint16_t value = 0;
    int length = 0;
    while (length < 4 && pointer != end) {
      const uint8_t nib = hex_nibble[static_cast<unsigned char>(*pointer)];
      if (nib == 0xff) {
        break;
      }
      value = static_cast<uint16_t>((value << 4) | nib);
      ++pointer;
      ++length;
    }

    // IPv4 tail: c is '.'
    if (pointer != end && *pointer == '.') {
      if (length == 0) {
        return false;
      }
      // Rewind the hex digits — they were actually decimal digits of IPv4
      pointer -= length;
      if (piece_index > 6) {
        return false;
      }

      int numbers_seen = 0;
      while (pointer != end) {
        int ipv4_piece = -1;
        if (numbers_seen > 0) {
          if (*pointer == '.' && numbers_seen < 4) {
            ++pointer;
          } else {
            return false;
          }
        }
        if (pointer == end || *pointer < '0' || *pointer > '9') {
          return false;
        }
        while (pointer != end && *pointer >= '0' && *pointer <= '9') {
          const int number = *pointer - '0';
          if (ipv4_piece < 0) {
            ipv4_piece = number;
          } else if (ipv4_piece == 0) {
            return false;  // leading zero
          } else {
            ipv4_piece = ipv4_piece * 10 + number;
          }
          if (ipv4_piece > 255) {
            return false;
          }
          ++pointer;
        }
        if (ipv4_piece < 0) {
          return false;
        }
        address[static_cast<size_t>(piece_index)] = static_cast<uint16_t>(
            address[static_cast<size_t>(piece_index)] * 0x100 +
            static_cast<uint16_t>(ipv4_piece));
        ++numbers_seen;
        if (numbers_seen == 2 || numbers_seen == 4) {
          ++piece_index;
        }
      }
      if (numbers_seen != 4) {
        return false;
      }
      break;
    }

    // Otherwise, if c is ':'
    if (pointer != end && *pointer == ':') {
      ++pointer;
      if (pointer == end) {
        return false;
      }
    } else if (pointer != end) {
      return false;
    }

    address[static_cast<size_t>(piece_index)] = value;
    ++piece_index;
  }

  // Expand compress: place the right-hand pieces at the end in one pass.
  if (compress != -1) {
    // Pieces [compress, piece_index) are the "right" side and should land at
    // the end of the address. The gap [compress, 8 - right) becomes zeros
    // (already zeroed). Move right pieces from the end of the filled region
    // to the end of the array, going right-to-left to avoid clobbering.
    const int right = piece_index - compress;
    if (right > 0) {
      for (int i = 1; i <= right; ++i) {
        address[static_cast<size_t>(8 - i)] =
            address[static_cast<size_t>(piece_index - i)];
        if (8 - i != piece_index - i) {
          address[static_cast<size_t>(piece_index - i)] = 0;
        }
      }
    }
  } else if (piece_index != 8) {
    return false;
  }
  return true;
}

void longest_zero_run(const std::array<uint16_t, 8>& address, size_t& start,
                      size_t& length) noexcept {
  start = 0;
  length = 0;
  for (size_t i = 0; i < 8; ++i) {
    if (address[i] == 0) {
      size_t next = i + 1;
      while (next != 8 && address[next] == 0) {
        ++next;
      }
      const size_t count = next - i;
      if (length < count) {
        length = count;
        start = i;
      }
      i = next - 1;
    }
  }
  if (length < 2) {
    length = 0;
  }
}

}  // namespace

bool parse_ipv4(std::string_view input, uint32_t& address,
                int& pure_decimal_count, bool& had_trailing_dot) noexcept {
  pure_decimal_count = 0;
  had_trailing_dot = false;
  if (input.empty()) {
    return false;
  }
  if (input.back() == '.') {
    had_trailing_dot = true;
    input.remove_suffix(1);
    if (input.empty()) {
      return false;
    }
  }

  // Hot path: pure decimal a.b.c.d (and variants handled by fast path)
  {
    // Fast path does not strip trailing dots itself for the 4-octet form when
    // already stripped above. Re-run on stripped input.
    const uint64_t fast = try_parse_ipv4_fast(input);
    if (fast < checkers::ipv4_fast_fail) {
      address = static_cast<uint32_t>(fast);
      pure_decimal_count = 4;
      return true;
    }
  }

  const char* p = input.data();
  const char* end = p + input.size();
  uint64_t ipv4 = 0;
  int digit_count = 0;

  for (; digit_count < 4 && p < end; ++digit_count) {
    uint64_t segment = 0;
    bool pure = false;
    if (!parse_ipv4_number(p, end, segment, pure)) {
      return false;
    }
    if (pure) {
      ++pure_decimal_count;
    }
    if (p >= end) {
      if (segment >= (uint64_t(1) << (32 - digit_count * 8))) {
        return false;
      }
      ipv4 <<= (32 - digit_count * 8);
      ipv4 |= segment;
      address = static_cast<uint32_t>(ipv4);
      return true;
    }
    if (segment > 255 || *p != '.') {
      return false;
    }
    ipv4 = (ipv4 << 8) | segment;
    ++p;
  }
  if (digit_count != 4 || p != end) {
    return false;
  }
  address = static_cast<uint32_t>(ipv4);
  return true;
}

bool parse_ipv6(std::string_view input,
                std::array<uint16_t, 8>& address) noexcept {
  return parse_ipv6_impl(input, address);
}

size_t serialize_ipv4_to(uint32_t address, char* out) noexcept {
  char* p = out;
  p = write_u8(p, static_cast<uint8_t>(address >> 24));
  *p++ = '.';
  p = write_u8(p, static_cast<uint8_t>(address >> 16));
  *p++ = '.';
  p = write_u8(p, static_cast<uint8_t>(address >> 8));
  *p++ = '.';
  p = write_u8(p, static_cast<uint8_t>(address));
  return static_cast<size_t>(p - out);
}

size_t serialize_ipv6_to(const std::array<uint16_t, 8>& address,
                         char* out) noexcept {
  size_t compress = 0;
  size_t compress_length = 0;
  longest_zero_run(address, compress, compress_length);

  char* p = out;
  size_t piece_index = 0;
  while (true) {
    if (compress_length > 0 && piece_index == compress) {
      *p++ = ':';
      if (piece_index == 0) {
        *p++ = ':';
      }
      piece_index += compress_length;
      if (piece_index == 8) {
        break;
      }
    }
    p = write_hex_u16(p, address[piece_index]);
    ++piece_index;
    if (piece_index == 8) {
      break;
    }
    *p++ = ':';
  }
  return static_cast<size_t>(p - out);
}

std::string serialize_ipv4(uint32_t address) {
  char buf[15];
  const size_t n = serialize_ipv4_to(address, buf);
  return std::string(buf, n);
}

std::string serialize_ipv6(const std::array<uint16_t, 8>& address) {
  char buf[41];
  buf[0] = '[';
  const size_t n = serialize_ipv6_to(address, buf + 1);
  buf[1 + n] = ']';
  return std::string(buf, n + 2);
}

bool ipv4_is_canonical(std::string_view serialized, uint32_t address) noexcept {
  char buf[15];
  const size_t n = serialize_ipv4_to(address, buf);
  return serialized.size() == n && std::memcmp(serialized.data(), buf, n) == 0;
}

bool ipv6_is_canonical(std::string_view serialized,
                       const std::array<uint16_t, 8>& address) noexcept {
  char body[39];
  const size_t n = serialize_ipv6_to(address, body);
  if (serialized.size() == n + 2 && serialized.front() == '[' &&
      serialized.back() == ']') {
    return std::memcmp(serialized.data() + 1, body, n) == 0;
  }
  if (serialized.size() == n) {
    return std::memcmp(serialized.data(), body, n) == 0;
  }
  return false;
}

}  // namespace ada::ip_address

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
  for (size_t d = 0; d < 10; ++d) {
    t[size_t{'0'} + d] = static_cast<uint8_t>(d);
  }
  for (size_t d = 0; d < 6; ++d) {
    t[size_t{'a'} + d] = static_cast<uint8_t>(10 + d);
    t[size_t{'A'} + d] = static_cast<uint8_t>(10 + d);
  }
  return t;
}

constexpr auto hex_nibble = make_hex_nibble_table();

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

// Hex digit count for values 0..0xffff via clz (at least one digit).
ada_really_inline int hex_digit_count(uint16_t v) noexcept {
  if (v == 0) {
    return 1;
  }
#if defined(__GNUC__) || defined(__clang__)
  // 16-bit value in low half of 32-bit: clz of v gives bits above the msb.
  // Digit count = (15 - msb) / 4 + 1, with msb = 31 - clz(v) for 32-bit.
  return static_cast<int>((31 - __builtin_clz(static_cast<unsigned>(v))) / 4) +
         1;
#else
  if (v >= 0x1000) {
    return 4;
  }
  if (v >= 0x100) {
    return 3;
  }
  if (v >= 0x10) {
    return 2;
  }
  return 1;
#endif
}

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
  const int digits = hex_digit_count(v);
  // Write from most-significant nibble of the used width.
  switch (digits) {
    case 4:
      *p++ = kHex[(v >> 12) & 0xf];
      *p++ = kHex[(v >> 8) & 0xf];
      *p++ = kHex[(v >> 4) & 0xf];
      *p++ = kHex[v & 0xf];
      break;
    case 3:
      *p++ = kHex[(v >> 8) & 0xf];
      *p++ = kHex[(v >> 4) & 0xf];
      *p++ = kHex[v & 0xf];
      break;
    case 2:
      *p++ = kHex[(v >> 4) & 0xf];
      *p++ = kHex[v & 0xf];
      break;
    default:
      *p++ = kHex[v & 0xf];
      break;
  }
  return p;
}

// ---- IPv4 segment parser (hand-rolled, no from_chars) --------------------

ada_really_inline bool parse_ipv4_number(const char*& p, const char* end,
                                         uint64_t& value,
                                         bool& is_pure_decimal) noexcept {
  is_pure_decimal = false;
  if (p >= end) [[unlikely]] {
    return false;
  }

  // Hex: 0x / 0X
  if (end - p >= 2 && p[0] == '0' && ((p[1] | 0x20) == 'x')) {
    p += 2;
    if (p == end || *p == '.') {
      value = 0;
      return true;
    }
    uint64_t v = 0;
    int digits = 0;
    while (p < end && *p != '.') {
      const uint8_t nib = hex_nibble[static_cast<unsigned char>(*p)];
      if (nib == 0xff) [[unlikely]] {
        return false;
      }
      // Cap at 8 hex digits; overflow beyond 32 bits is failure.
      if (digits >= 8) [[unlikely]] {
        return false;
      }
      v = (v << 4) | nib;
      ++p;
      ++digits;
    }
    if (digits == 0) [[unlikely]] {
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
      if (c < '0' || c > '7') [[unlikely]] {
        return false;
      }
      // 11 octal digits can exceed 32 bits; check cheaply.
      if (v > (0xFFFFFFFFULL >> 3)) [[unlikely]] {
        return false;
      }
      v = (v << 3) | static_cast<uint64_t>(c - '0');
      ++p;
    }
    value = v;
    return true;
  }

  // Decimal (including single "0")
  if (*p < '0' || *p > '9') [[unlikely]] {
    return false;
  }
  is_pure_decimal = true;
  uint64_t v = static_cast<uint64_t>(*p - '0');
  ++p;
  while (p < end && *p != '.') {
    const char c = *p;
    if (c < '0' || c > '9') [[unlikely]] {
      return false;
    }
    // 10 decimal digits can exceed 32 bits.
    if (v > 429496729ULL) [[unlikely]] {  // floor((2^32-1)/10)
      return false;
    }
    v = v * 10u + static_cast<uint64_t>(c - '0');
    if (v > 0xFFFFFFFFULL) [[unlikely]] {
      return false;
    }
    ++p;
  }
  value = v;
  return true;
}

// ---- Optimized WHATWG IPv6 parser ----------------------------------------

// Parse up to 4 hex digits. Returns number of digits consumed (0 if none).
// Sets value. Does not consume a following separator.
ada_really_inline int parse_hex_piece_fast(const char*& pointer,
                                           const char* end,
                                           uint16_t& value) noexcept {
  if (pointer == end) {
    return 0;
  }
  const uint8_t n0 = hex_nibble[static_cast<unsigned char>(*pointer)];
  if (n0 == 0xff) {
    return 0;
  }
  uint32_t v = n0;
  ++pointer;
  int length = 1;
  // Unroll remaining up to 3 digits.
  if (pointer != end) {
    const uint8_t n1 = hex_nibble[static_cast<unsigned char>(*pointer)];
    if (n1 != 0xff) {
      v = (v << 4) | n1;
      ++pointer;
      ++length;
      if (pointer != end) {
        const uint8_t n2 = hex_nibble[static_cast<unsigned char>(*pointer)];
        if (n2 != 0xff) {
          v = (v << 4) | n2;
          ++pointer;
          ++length;
          if (pointer != end) {
            const uint8_t n3 = hex_nibble[static_cast<unsigned char>(*pointer)];
            if (n3 != 0xff) {
              v = (v << 4) | n3;
              ++pointer;
              ++length;
            }
          }
        }
      }
    }
  }
  value = static_cast<uint16_t>(v);
  return length;
}

bool parse_ipv6_impl(std::string_view input,
                     std::array<uint16_t, 8>& address) noexcept {
  if (input.empty() || input.size() > 45) [[unlikely]] {
    return false;
  }
  // Zero-init once via value initialization of the out-param by caller is
  // not guaranteed; fill here.
  address.fill(0);

  const char* pointer = input.data();
  const char* const end = pointer + input.size();
  int piece_index = 0;
  int compress = -1;

  // Leading ':' must be part of '::'
  if (*pointer == ':') {
    if (input.size() == 1 || pointer[1] != ':') [[unlikely]] {
      return false;
    }
    pointer += 2;
    compress = ++piece_index;
  }

  while (pointer != end) {
    if (piece_index == 8) [[unlikely]] {
      return false;
    }
    if (*pointer == ':') {
      if (compress != -1) [[unlikely]] {
        return false;
      }
      ++pointer;
      compress = ++piece_index;
      continue;
    }

    uint16_t value = 0;
    const int length = parse_hex_piece_fast(pointer, end, value);

    // IPv4 tail: c is '.'
    if (pointer != end && *pointer == '.') {
      if (length == 0) [[unlikely]] {
        return false;
      }
      // Rewind the hex digits - they were actually decimal digits of IPv4
      pointer -= length;
      if (piece_index > 6) [[unlikely]] {
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
        if (pointer == end || *pointer < '0' || *pointer > '9') [[unlikely]] {
          return false;
        }
        // First digit
        ipv4_piece = *pointer - '0';
        ++pointer;
        // Up to two more digits, reject leading zero expansion
        if (pointer != end && *pointer >= '0' && *pointer <= '9') {
          if (ipv4_piece == 0) [[unlikely]] {
            return false;
          }
          ipv4_piece = ipv4_piece * 10 + (*pointer - '0');
          ++pointer;
          if (pointer != end && *pointer >= '0' && *pointer <= '9') {
            ipv4_piece = ipv4_piece * 10 + (*pointer - '0');
            ++pointer;
            if (ipv4_piece > 255) [[unlikely]] {
              return false;
            }
          }
        }
        address[static_cast<size_t>(piece_index)] = static_cast<uint16_t>(
            address[static_cast<size_t>(piece_index)] * 0x100 +
            static_cast<uint16_t>(ipv4_piece));
        ++numbers_seen;
        if (numbers_seen == 2 || numbers_seen == 4) {
          ++piece_index;
        }
      }
      if (numbers_seen != 4) [[unlikely]] {
        return false;
      }
      break;
    }

    // length == 0 and not '.' means invalid (unless we had empty piece via :)
    if (length == 0) [[unlikely]] {
      return false;
    }

    // Otherwise, if c is ':'
    if (pointer != end && *pointer == ':') {
      ++pointer;
      if (pointer == end) [[unlikely]] {
        return false;
      }
    } else if (pointer != end) [[unlikely]] {
      return false;
    }

    address[static_cast<size_t>(piece_index)] = value;
    ++piece_index;
  }

  // Expand compress: place the right-hand pieces at the end in one pass.
  if (compress != -1) {
    const int right = piece_index - compress;
    if (right > 0) {
      // dest starts at 8 - right; src starts at compress. Ranges may only
      // overlap when already right-justified (compress + right == 8), in
      // which case the copy is a no-op for each element.
      const int dest = 8 - right;
      if (dest != compress) {
        // Move right-to-left when ranges could theoretically overlap.
        for (int i = right - 1; i >= 0; --i) {
          address[static_cast<size_t>(dest + i)] =
              address[static_cast<size_t>(compress + i)];
          address[static_cast<size_t>(compress + i)] = 0;
        }
      }
    }
  } else if (piece_index != 8) [[unlikely]] {
    return false;
  }
  return true;
}

void longest_zero_run(const std::array<uint16_t, 8>& address, size_t& start,
                      size_t& length) noexcept {
  start = 0;
  length = 0;
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
    if (count > length) {
      length = count;
      start = i;
    }
    i = next;
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
  if (input.empty()) [[unlikely]] {
    return false;
  }
  if (input.back() == '.') {
    had_trailing_dot = true;
    input.remove_suffix(1);
    if (input.empty()) [[unlikely]] {
      return false;
    }
  }

  // Hot path: pure decimal a.b.c.d
  const uint64_t fast = try_parse_ipv4_fast(input);
  if (fast < checkers::ipv4_fast_fail) [[likely]] {
    address = static_cast<uint32_t>(fast);
    pure_decimal_count = 4;
    return true;
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
      // Last value may use remaining bits
      const unsigned shift = static_cast<unsigned>(32 - digit_count * 8);
      if (segment >= (uint64_t{1} << shift)) {
        return false;
      }
      ipv4 = (ipv4 << shift) | segment;
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

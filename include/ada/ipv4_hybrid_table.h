/**
 * @file ipv4_hybrid_table.h
 * @brief Compile-time lookup table for parse_ipv4_hybrid (checkers-inl.h).
 *
 * An address is 7-15 chars, so its first 8 chars (head) always hold "A.B."
 * and its last 8 (tail) always hold ".C.D": the table has a low half indexed
 * by the head and a high half indexed by the tail. The pext masks keep only
 * bits that tell digits from dots, so each half's index says where its dots
 * are: 9 shapes (1-3 digits per octet) among 32 indices. An entry is 16 B: a
 * pshufb pattern moving each digit to a fixed lane for pmaddubsw, and a
 * per-lane offset (sub) for the range check, 1 on leading digits to reject
 * leading zeros and the dot's value on dot lanes. Byte 5 of the pattern also
 * holds the half's share of the address length, in bits pshufb ignores: the
 * parser requires the two shares to add up to the real length, so a read that
 * isn't a real entry gets rejected. That lets the halves overlap and keeps the
 * table small.
 */
#ifndef ADA_IPV4_HYBRID_TABLE_H
#define ADA_IPV4_HYBRID_TABLE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace ada::checkers::detail::ipv4_hybrid {

inline constexpr size_t entries_per_half = 32;

// Bit 7 of char 0 is always clear, so the index comes out doubled for the
// 16-byte entries.
inline constexpr uint64_t head_digit_bits = 0x0010101010001080;
inline constexpr uint64_t tail_digit_bits = 0x0010001010101080;

// The dot lane of the half's second octet (B or D), see place_octet.
inline constexpr size_t share_byte = 5;

enum half : size_t { high = 0, low = 1 };

using slot = std::array<uint8_t, 8>;

constexpr slot splat(uint8_t value) noexcept {
  slot result{};
  for (uint8_t& byte : result) {
    byte = value;
  }
  return result;
}

struct entry {
  slot pattern = splat(0x80);
  slot sub{};
};

// Not constexpr: reaching it while the table is built stops compilation.
inline void table_check_failed() noexcept {}

constexpr void table_check(bool ok) noexcept {
  if (!ok) {
    table_check_failed();
  }
}

// Within a half's 8 bytes, a lane pair holds tens and ones at 2 * pair and
// 2 * pair + 1, hundreds and dot at 4 + 2 * pair and 5 + 2 * pair. The half's
// first octet takes pair 1 and its second pair 0, so the octets come out last
// to first: the packed address, with no byte swap.
constexpr void place_octet(entry& e, size_t pair, size_t start, size_t digits,
                           bool dot) noexcept {
  const size_t lanes[3] = {4 + 2 * pair, 2 * pair, 2 * pair + 1};
  const size_t* digit_lanes = lanes + (3 - digits);
  for (size_t i = 0; i < digits; ++i) {
    e.pattern[digit_lanes[i]] = static_cast<uint8_t>(start + i);
  }
  if (digits > 1) {
    e.sub[digit_lanes[0]] = 1;
  }

  const size_t dot_lane = 5 + 2 * pair;
  if (dot) {
    e.pattern[dot_lane] = static_cast<uint8_t>(start + digits);
    e.sub[dot_lane] = static_cast<uint8_t>('.' - '0');
  }
}

constexpr entry low_entry(size_t a_digits, size_t b_digits) noexcept {
  entry e;
  place_octet(e, 1, 0, a_digits, true);
  place_octet(e, 0, a_digits + 1, b_digits, true);
  // B's dot lane doubles as the low length share: pshufb ignores the 0x10.
  e.pattern[share_byte] += 0x10;
  return e;
}

constexpr entry high_entry(size_t c_digits, size_t d_digits) noexcept {
  entry e;
  // The tail is right-aligned, ending at byte 16 of head_tail.
  place_octet(e, 1, 16 - d_digits - 1 - c_digits, c_digits, true);
  place_octet(e, 0, 16 - d_digits, d_digits, false);
  // D has no dot, so its dot lane holds the high length share instead,
  // negative so pshufb zeroes the lane; with the low's +16, the two shares add
  // up to the address length.
  e.pattern[share_byte] =
      static_cast<uint8_t>(static_cast<int>(c_digits + 1 + d_digits) - 15);
  return e;
}

// _pext_u64 isn't constexpr on every compiler.
constexpr size_t pext(const char* chars, uint64_t mask) noexcept {
  uint64_t word = 0;
  for (size_t i = 0; i < 8; ++i) {
    word |= uint64_t(static_cast<uint8_t>(chars[i])) << (8 * i);
  }
  size_t index = 0;
  size_t bit = 0;
  for (uint64_t remaining = mask; remaining != 0;
       remaining &= remaining - 1, ++bit) {
    if ((word & remaining & (~remaining + 1)) != 0) {
      index |= size_t(1) << bit;
    }
  }
  return index;
}

constexpr int length_sum(uint8_t low_share, uint8_t high_share) noexcept {
  return int(low_share) + int(static_cast<int8_t>(high_share));
}

using half_entries = std::array<std::optional<entry>, entries_per_half>;

constexpr void set(half_entries& entries, size_t doubled_index,
                   const entry& e) noexcept {
  table_check(doubled_index % 2 == 0);

  std::optional<entry>& existing = entries[doubled_index / 2];
  if (existing) {
    table_check(existing->pattern == e.pattern && existing->sub == e.sub);
  }
  existing = e;
}

// One sample address per shape (1-3 digits per octet, 81 shapes), hashed by
// head and tail like the parser does: octets A.B go to the low half, C.D to
// the high half. The hash only tells digits from dots, so any digit works.
// Result: two halves of 32 entries, empty where no shape lands.
constexpr std::array<half_entries, 2> compute_entries() noexcept {
  std::array<half_entries, 2> entries{};
  for (size_t a = 1; a <= 3; ++a) {
    for (size_t b = 1; b <= 3; ++b) {
      for (size_t c = 1; c <= 3; ++c) {
        for (size_t d = 1; d <= 3; ++d) {
          char address[15] = {};
          size_t len = 0;
          const size_t digits[4] = {a, b, c, d};
          for (size_t octet = 0; octet < 4; ++octet) {
            for (size_t i = 0; i < digits[octet]; ++i) {
              address[len++] = '1';
            }
            if (octet < 3) {
              address[len++] = '.';
            }
          }
          // parse_ipv4_seven_chars never reads the table.
          if (len == 7) {
            continue;
          }

          const entry low_e = low_entry(a, b);
          const entry high_e = high_entry(c, d);
          table_check(length_sum(low_e.pattern[share_byte],
                                 high_e.pattern[share_byte]) == int(len));

          set(entries[low], pext(address, head_digit_bits), low_e);
          set(entries[high], pext(address + len - 8, tail_digit_bits), high_e);
        }
      }
    }
  }
  return entries;
}

inline constexpr std::array<half_entries, 2> entries = compute_entries();

// High goes first, low starts right where high's last entry ends, minus its
// own unused leading indices: those overlap high's entries, harmless since
// spare indices fail the length check.
// Result: each half's first slot.
constexpr std::array<size_t, 2> compute_starts() noexcept {
  size_t high_end = 0;
  for (size_t index = 0; index < entries_per_half; ++index) {
    if (entries[high][index]) {
      high_end = 2 * index + 2;
    }
  }
  size_t low_first = 0;
  while (!entries[low][low_first]) {
    ++low_first;
  }

  std::array<size_t, 2> starts{};
  starts[high] = 0;
  starts[low] = high_end - 2 * low_first;
  return starts;
}

inline constexpr std::array<size_t, 2> starts = compute_starts();

// The extra slot is for an odd index (non-ASCII first char), which reads one
// slot past the last entry.
inline constexpr size_t slot_count = starts[low] + 2 * entries_per_half + 1;

struct table {
  alignas(64) std::array<slot, slot_count> slots{};

  template <half h>
  constexpr const slot* get(size_t doubled_index) const noexcept {
    return &slots[starts[h] + doubled_index];
  }

  // The low share is read zero-extended, the high one sign-extended.
  template <half h>
  constexpr uint64_t get_length(size_t doubled_index) const noexcept {
    const uint8_t share = (*get<h>(doubled_index))[share_byte];
    if constexpr (h == low) {
      return share;
    } else {
      return static_cast<uint64_t>(int64_t(static_cast<int8_t>(share)));
    }
  }
};

// Each entry becomes two slots, pattern then sub, at its half's start +
// doubled index. Then any pair of reads the parser can make, odd and spare
// indices included, must fail the length check unless both are real entries,
// or leftover bytes could accept an invalid address.
constexpr table compute_table() noexcept {
  table result;
  for (size_t h = 0; h < 2; ++h) {
    for (size_t index = 0; index < entries_per_half; ++index) {
      if (const std::optional<entry>& e = entries[h][index]) {
        result.slots[starts[h] + 2 * index] = e->pattern;
        result.slots[starts[h] + 2 * index + 1] = e->sub;
      }
    }
  }

  for (size_t index_low = 0; index_low < 2 * entries_per_half; ++index_low) {
    for (size_t index_high = 0; index_high < 2 * entries_per_half;
         ++index_high) {
      const uint64_t sum = result.get_length<low>(index_low) +
                           result.get_length<high>(index_high);
      const bool both_entries =
          index_low % 2 == 0 && entries[low][index_low / 2] &&
          index_high % 2 == 0 && entries[high][index_high / 2];
      if (sum >= 7 && sum <= 15) {
        table_check(both_entries);
      }
    }
  }
  return result;
}

inline constexpr table hybrid_table = compute_table();

}  // namespace ada::checkers::detail::ipv4_hybrid

#endif  // ADA_IPV4_HYBRID_TABLE_H

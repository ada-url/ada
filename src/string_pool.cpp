/**
 * @file string_pool.cpp
 * @brief Implementation of the bounded thread-local string freelist.
 */

#include "ada/string_pool.h"

#include <cstdint>
#include <string>

namespace ada::string_pool {
namespace {

/**
 * Per-thread spare list. Kept in this TU so the freelist is a single
 * instance shared by the library (not duplicated across translation units).
 */
struct freelist {
  std::string slots[kSlotCount];
  uint8_t count{0};
};

freelist& thread_freelist() {
  thread_local freelist list;
  return list;
}

/** True when capacity is worth keeping in the pool. */
constexpr bool is_retainable(size_t capacity) noexcept {
  return capacity >= kMinCapacity && capacity <= kMaxCapacity;
}

/**
 * Remove slot @p idx by swapping with the last live slot and clearing it.
 * Precondition: idx < list.count.
 */
void erase_slot(freelist& list, uint8_t idx) {
  const uint8_t last = static_cast<uint8_t>(list.count - 1);
  if (idx != last) {
    list.slots[idx].swap(list.slots[last]);
  }
  list.slots[last].clear();
  list.count = last;
}

/** Index of the spare with the smallest capacity (list must be full). */
uint8_t index_of_smallest(const freelist& list) noexcept {
  uint8_t min_i = 0;
  size_t min_c = list.slots[0].capacity();
  for (uint8_t i = 1; i < kSlotCount; ++i) {
    const size_t c = list.slots[i].capacity();
    if (c < min_c) {
      min_c = c;
      min_i = i;
    }
  }
  return min_i;
}

}  // namespace

void adopt(std::string& dest, size_t min_capacity) {
  freelist& list = thread_freelist();

  // Most recently recycled spares are at the end; try those first so a
  // steady-state parse size tends to hit immediately.
  for (uint8_t i = list.count; i > 0; --i) {
    const uint8_t idx = static_cast<uint8_t>(i - 1);
    if (list.slots[idx].capacity() >= min_capacity) {
      dest.swap(list.slots[idx]);
      dest.clear();
      // list.slots[idx] now holds dest's prior (usually empty) string.
      erase_slot(list, idx);
      return;
    }
  }

  if (dest.capacity() < min_capacity) {
    dest.reserve(min_capacity);
  }
}

void recycle(std::string& s) noexcept {
  const size_t cap = s.capacity();
  if (!is_retainable(cap)) {
    return;
  }

  freelist& list = thread_freelist();

  if (list.count < kSlotCount) {
    s.clear();
    list.slots[list.count].swap(s);
    ++list.count;
    return;
  }

  // Pool full: keep the larger capacity, drop the smaller spare.
  const uint8_t min_i = index_of_smallest(list);
  if (cap <= list.slots[min_i].capacity()) {
    return;
  }
  s.clear();
  list.slots[min_i].swap(s);
}

}  // namespace ada::string_pool

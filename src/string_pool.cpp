/**
 * @file string_pool.cpp
 * @brief Single thread-local string spare (bounded freelist of size 1).
 */

#include "ada/string_pool.h"

namespace ada::string_pool {
namespace {

thread_local std::string t_spare;

bool retainable(size_t capacity) noexcept {
  return capacity >= kMinCapacity && capacity <= kMaxCapacity;
}

}  // namespace

void adopt(std::string& dest, size_t min_capacity) {
  if (t_spare.capacity() >= min_capacity) {
    dest.swap(t_spare);
    dest.clear();
    t_spare.clear();
    return;
  }
  if (dest.capacity() < min_capacity) {
    dest.reserve(min_capacity);
  }
}

void recycle(std::string& s) noexcept {
  const size_t cap = s.capacity();
  if (!retainable(cap) || cap <= t_spare.capacity()) {
    return;
  }
  s.clear();
  t_spare.swap(s);
}

}  // namespace ada::string_pool

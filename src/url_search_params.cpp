#include "ada/url_search_params.h"

#include <limits>

namespace {

[[nodiscard]] constexpr size_t saturating_add(size_t left,
                                              size_t right) noexcept {
  constexpr size_t max = std::numeric_limits<size_t>::max();
  return right > max - left ? max : left + right;
}

[[nodiscard]] constexpr size_t saturating_multiply(size_t left,
                                                   size_t right) noexcept {
  constexpr size_t max = std::numeric_limits<size_t>::max();
  return left != 0 && right > max / left ? max : left * right;
}

static_assert(saturating_add(std::numeric_limits<size_t>::max(), 1) ==
              std::numeric_limits<size_t>::max());
static_assert(saturating_multiply(std::numeric_limits<size_t>::max(), 2) ==
              std::numeric_limits<size_t>::max());

}  // namespace

namespace ada {

size_t url_search_params::estimated_memory_usage() const noexcept {
  size_t estimate =
      saturating_multiply(params.capacity(), sizeof(key_value_pair));
  for (const auto& [key, value] : params) {
    estimate = saturating_add(estimate, key.capacity());
    estimate = saturating_add(estimate, value.capacity());
  }
  return estimate;
}

}  // namespace ada

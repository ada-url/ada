/**
 * @file string_pool.h
 * @brief Bounded thread-local freelist for `std::string` heap capacity.
 *
 * @private Not part of the public Ada API; may change at any time.
 *
 * The parse hot path allocates short-lived URL buffers on every call. This
 * pool lets a thread reuse a small number of heap buffers across
 * parse/destroy cycles, avoiding malloc/free on the steady-state path while
 * keeping retention bounded.
 *
 * Policy:
 * - Only capacities in [kMinCapacity, kMaxCapacity] are retained.
 *   Below kMinCapacity is typical SSO; recycling would thrash. Above
 *   kMaxCapacity would retain oversized rare URLs indefinitely.
 * - At most kSlotCount buffers are kept per thread.
 * - adopt() prefers a recycled buffer that already has enough capacity;
 *   otherwise it grows the destination with reserve().
 * - recycle() returns capacity to the pool (or replaces a smaller spare).
 */
#ifndef ADA_STRING_POOL_H
#define ADA_STRING_POOL_H

#include <cstddef>
#include <string>

namespace ada::string_pool {

/** Do not retain buffers at or below typical std::string SSO size. */
inline constexpr size_t kMinCapacity = 24;

/** Hard cap on retained capacity (bytes). */
inline constexpr size_t kMaxCapacity = 1024;

/** Maximum number of spare buffers held per thread. */
inline constexpr size_t kSlotCount = 4;

/**
 * Ensure @p dest can hold at least @p min_capacity bytes, preferably by
 * swapping in a recycled spare (retaining heap capacity without malloc).
 *
 * On return, @p dest is empty and has capacity >= min_capacity when a spare
 * was available or after reserve().
 */
void adopt(std::string& dest, size_t min_capacity);

/**
 * Offer @p s's heap capacity back to the pool.
 *
 * Clears and stores @p s when its capacity is within [kMinCapacity,
 * kMaxCapacity] and useful to the pool; otherwise leaves @p s alone (its
 * destructor will free as usual). Noexcept: never allocates.
 */
void recycle(std::string& s) noexcept;

}  // namespace ada::string_pool

#endif  // ADA_STRING_POOL_H

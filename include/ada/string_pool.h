/**
 * @file string_pool.h
 * @brief Single thread-local spare for `std::string` heap capacity.
 *
 * @private Not part of the public Ada API; may change at any time.
 *
 * One spare buffer per thread. Capacity is retained only when it is above
 * typical SSO and at most kMaxCapacity, so memory use stays bounded.
 */
#ifndef ADA_STRING_POOL_H
#define ADA_STRING_POOL_H

#include <cstddef>
#include <string>

namespace ada::string_pool {

/** Do not retain SSO-sized buffers. */
inline constexpr size_t kMinCapacity = 24;

/** Hard cap on retained capacity (bytes). */
inline constexpr size_t kMaxCapacity = 1024;

/** Prefer a recycled spare with capacity >= min_capacity; else reserve. */
void adopt(std::string& dest, size_t min_capacity);

/** Return capacity to the spare when within [kMinCapacity, kMaxCapacity]. */
void recycle(std::string& s) noexcept;

}  // namespace ada::string_pool

#endif  // ADA_STRING_POOL_H

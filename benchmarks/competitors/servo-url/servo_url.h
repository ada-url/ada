#ifndef servo_url_ffi_h
#define servo_url_ffi_h

/* This file was modified manually. */

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

namespace servo_url {

/// A parsed URL record.
struct Url;

extern "C" {

Url *parse_url(const char *raw_input, size_t raw_input_length);

void free_url(Url *raw);

const char *parse_url_to_href(const char *raw_input, size_t raw_input_length);

void free_string(const char *);
}  // extern "C"

}  // namespace servo_url

#endif  // servo_url_ffi_h

/* Generated with cbindgen:0.24.3 */

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

namespace servo_url {

struct StandardUrl;

extern "C" {

StandardUrl *parse_url(const char *raw_input, size_t raw_input_length);

void free_standard_url(StandardUrl *raw);

} // extern "C"

} // namespace servo_url

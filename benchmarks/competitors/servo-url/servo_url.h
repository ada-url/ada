/* Generated with cbindgen:0.24.3 */

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

namespace servo_url {

struct StandardUrl {
  uint16_t port;
  char *scheme;
  char *username;
  char *password;
  char *host;
  char *query;
  char *fragment;
  char *path;
  char *href;
};

extern "C" {

StandardUrl parse_url(const char *raw_input, uintptr_t raw_input_length);

} // extern "C"

} // namespace servo_url

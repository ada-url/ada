/**
 * @file ada_c.h
 * @brief Includes the C definitions for Ada.
 */
#ifndef ADA_C_H
#define ADA_C_H

struct ada_string {
  const char* data;
  size_t length;

  static ada_string create(const char* data, size_t length) {
    ada_string out{};
    out.data = data;
    out.length = length;
    return out;
  }
};

struct ada_url_components {
  uint32_t protocol_end;
  uint32_t username_end;
  uint32_t host_start;
  uint32_t host_end;
  uint32_t port;
  uint32_t pathname_start;
  uint32_t search_start;
  uint32_t hash_start;
};

extern "C" {
typedef void* ada_url;

// input should be a null terminated C string
// you must call ada_free on the returned pointer
ada_url ada_parse(const char* string) noexcept;

// input and base should be a null terminated C strings
bool ada_can_parse(const char* input, const char* base) noexcept;

void ada_free(ada_url result) noexcept;

bool ada_is_valid(ada_url result) noexcept;

// url_aggregator getters
// if ada_is_valid(result)) is false, an empty string is returned
ada_string ada_get_origin(ada_url result) noexcept;
ada_string ada_get_href(ada_url result) noexcept;
ada_string ada_get_username(ada_url result) noexcept;
ada_string ada_get_password(ada_url result) noexcept;
ada_string ada_get_port(ada_url result) noexcept;
ada_string ada_get_hash(ada_url result) noexcept;
ada_string ada_get_host(ada_url result) noexcept;
ada_string ada_get_hostname(ada_url result) noexcept;
ada_string ada_get_pathname(ada_url result) noexcept;
ada_string ada_get_search(ada_url result) noexcept;
ada_string ada_get_protocol(ada_url result) noexcept;

// url_aggregator setters
// if ada_is_valid(result)) is false, the setters have no effect
// input should be a null terminated C string
bool ada_set_href(ada_url result, const char* input) noexcept;
bool ada_set_host(ada_url result, const char* input) noexcept;
bool ada_set_hostname(ada_url result, const char* input) noexcept;
bool ada_set_protocol(ada_url result, const char* input) noexcept;
bool ada_set_username(ada_url result, const char* input) noexcept;
bool ada_set_password(ada_url result, const char* input) noexcept;
bool ada_set_port(ada_url result, const char* input) noexcept;
bool ada_set_pathname(ada_url result, const char* input) noexcept;
void ada_set_search(ada_url result, const char* input) noexcept;
void ada_set_hash(ada_url result, const char* input) noexcept;

// url_aggregator functions
// if ada_is_valid(result) is false, functions below will return false
bool ada_has_credentials(ada_url result) noexcept;
bool ada_has_empty_hostname(ada_url result) noexcept;
bool ada_has_hostname(ada_url result) noexcept;
bool ada_has_non_empty_username(ada_url result) noexcept;
bool ada_has_non_empty_password(ada_url result) noexcept;
bool ada_has_port(ada_url result) noexcept;
bool ada_has_password(ada_url result) noexcept;
bool ada_has_hash(ada_url result) noexcept;
bool ada_has_search(ada_url result) noexcept;

// returns a pointer to the internal url_aggregator::url_components
const ada_url_components* ada_get_components(ada_url result) noexcept;
}
#endif  // ADA_C_H

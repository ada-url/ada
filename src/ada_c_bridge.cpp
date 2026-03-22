// NOLINTBEGIN(bugprone-exception-escape,
// bugprone-suspicious-stringview-data-usage)
/**
 * @file ada_c_bridge.cpp
 * @brief C++ bridge functions for the pure-C ada_c.c implementation.
 *
 * This file is compiled as C++ and linked into the ada library. It provides
 * extern "C" functions that ada_c.c calls whenever C++ logic is required
 * (URL parsing, hostname normalisation, IDNA, search params, etc.).
 *
 * Data exchange uses ada_url_aggregator_t: the C struct whose buffer is
 * malloc'd so that C code can free() it without knowing anything about C++.
 *
 * Only public ada::url_aggregator APIs are used; no private field access.
 */
#include "ada/url_aggregator-inl.h"
#include "ada/url_search_params-inl.h"
#include "ada/url_aggregator_c.h"
#include "ada/implementation.h"

#include <cstdlib>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// Internal helpers (use only public API of ada::url_aggregator)
// ---------------------------------------------------------------------------

/**
 * Copies a C++ url_aggregator into a freshly malloc'd C struct.
 * Uses only public accessor methods (get_href, get_components).
 */
static ada_url_aggregator_t* to_c_aggregator(
    const ada::url_aggregator& agg) noexcept {
  auto* out =
      static_cast<ada_url_aggregator_t*>(malloc(sizeof(ada_url_aggregator_t)));
  if (!out) return nullptr;

  // get_href() returns a string_view over the entire internal buffer.
  std::string_view href = agg.get_href();
  const uint32_t len = static_cast<uint32_t>(href.size());
  out->buffer = static_cast<char*>(malloc(static_cast<size_t>(len) + 1));
  if (!out->buffer) {
    free(out);
    return nullptr;
  }
  std::memcpy(out->buffer, href.data(), len);
  out->buffer[len] = '\0';
  out->buffer_length = len;
  out->buffer_capacity = len + 1;

  // get_components() returns a const-ref to the url_components struct.
  const ada::url_components& c = agg.get_components();
  out->protocol_end = c.protocol_end;
  out->username_end = c.username_end;
  out->host_start = c.host_start;
  out->host_end = c.host_end;
  out->port = c.port;
  out->pathname_start = c.pathname_start;
  out->search_start = c.search_start;
  out->hash_start = c.hash_start;

  // These fields are public on url_base.
  out->is_valid = static_cast<uint8_t>(agg.is_valid ? 1 : 0);
  out->has_opaque_path = static_cast<uint8_t>(agg.has_opaque_path ? 1 : 0);
  out->host_type = static_cast<uint8_t>(agg.host_type);
  out->scheme_type = static_cast<uint8_t>(agg.type);

  return out;
}

/**
 * Rebuilds a C++ url_aggregator from the buffer stored in the C struct.
 *
 * The buffer is always a normalized (already-parsed) URL, so re-parsing it
 * through parse_url_impl is idempotent and produces the exact same state.
 * This avoids any need to access the private buffer/components fields.
 */
static ada::url_aggregator from_c_aggregator(
    const ada_url_aggregator_t* in) noexcept {
  return ada::parser::parse_url_impl<ada::url_aggregator>(
      std::string_view(in->buffer, in->buffer_length));
}

/**
 * Updates a C struct in-place from a C++ url_aggregator after a mutation.
 * Uses only public accessor methods.
 */
static void sync_c_from_aggregator(ada_url_aggregator_t* out,
                                   const ada::url_aggregator& agg) noexcept {
  std::string_view href = agg.get_href();
  const uint32_t len = static_cast<uint32_t>(href.size());
  if (static_cast<size_t>(len) + 1 > out->buffer_capacity) {
    char* nb =
        static_cast<char*>(realloc(out->buffer, static_cast<size_t>(len) + 1));
    if (!nb) {
      /* realloc failed; out->buffer still valid, leave struct unchanged. */
      return;
    }
    out->buffer = nb;
    out->buffer_capacity = len + 1;
  }
  std::memcpy(out->buffer, href.data(), len);
  out->buffer[len] = '\0';
  out->buffer_length = len;

  const ada::url_components& c = agg.get_components();
  out->protocol_end = c.protocol_end;
  out->username_end = c.username_end;
  out->host_start = c.host_start;
  out->host_end = c.host_end;
  out->port = c.port;
  out->pathname_start = c.pathname_start;
  out->search_start = c.search_start;
  out->hash_start = c.hash_start;

  out->is_valid = static_cast<uint8_t>(agg.is_valid ? 1 : 0);
  out->has_opaque_path = static_cast<uint8_t>(agg.has_opaque_path ? 1 : 0);
  out->host_type = static_cast<uint8_t>(agg.host_type);
  out->scheme_type = static_cast<uint8_t>(agg.type);
}

// ---------------------------------------------------------------------------
// Bridge functions (extern "C" so they are callable from C)
// ---------------------------------------------------------------------------
extern "C" {

// ---- Parsing ----------------------------------------------------------------

ada_url_aggregator_t* ada_parse_impl(const char* input,
                                     size_t length) noexcept {
  ada::url_aggregator agg = ada::parser::parse_url_impl<ada::url_aggregator>(
      std::string_view(input, length));
  return to_c_aggregator(agg);
}

ada_url_aggregator_t* ada_parse_with_base_impl(const char* input,
                                               size_t input_length,
                                               const char* base,
                                               size_t base_length) noexcept {
  ada::url_aggregator base_agg =
      ada::parser::parse_url_impl<ada::url_aggregator>(
          std::string_view(base, base_length));
  if (!base_agg.is_valid) {
    return to_c_aggregator(base_agg);
  }
  ada::url_aggregator agg = ada::parser::parse_url_impl<ada::url_aggregator>(
      std::string_view(input, input_length), &base_agg);
  return to_c_aggregator(agg);
}

bool ada_can_parse_impl(const char* input, size_t length) noexcept {
  return ada::can_parse(std::string_view(input, length));
}

bool ada_can_parse_with_base_impl(const char* input, size_t input_length,
                                   const char* base,
                                   size_t base_length) noexcept {
  std::string_view base_sv(base, base_length);
  return ada::can_parse(std::string_view(input, input_length), &base_sv);
}

// ---- Setters ----------------------------------------------------------------

bool ada_set_href_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_href(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

bool ada_set_host_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_host(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

bool ada_set_hostname_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_hostname(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

bool ada_set_protocol_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_protocol(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

bool ada_set_username_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_username(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

bool ada_set_password_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_password(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

bool ada_set_port_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_port(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

bool ada_set_pathname_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  bool ok = agg.set_pathname(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
  return ok;
}

void ada_set_search_impl(ada_url_aggregator_t* url, const char* input,
                         size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  agg.set_search(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
}

void ada_set_hash_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  agg.set_hash(std::string_view(input, length));
  sync_c_from_aggregator(url, agg);
}

void ada_clear_port_impl(ada_url_aggregator_t* url) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  agg.clear_port();
  sync_c_from_aggregator(url, agg);
}

void ada_clear_hash_impl(ada_url_aggregator_t* url) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  agg.clear_hash();
  sync_c_from_aggregator(url, agg);
}

void ada_clear_search_impl(ada_url_aggregator_t* url) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  agg.clear_search();
  sync_c_from_aggregator(url, agg);
}

// ---- Origin -----------------------------------------------------------------

char* ada_get_origin_impl(const ada_url_aggregator_t* url,
                          size_t* out_length) noexcept {
  ada::url_aggregator agg = from_c_aggregator(url);
  std::string origin = agg.get_origin();
  *out_length = origin.size();
  char* result = static_cast<char*>(malloc(origin.size() + 1));
  if (!result) {
    *out_length = 0;
    return nullptr;
  }
  std::memcpy(result, origin.data(), origin.size());
  result[origin.size()] = '\0';
  return result;
}

// ---- IDNA -------------------------------------------------------------------

char* ada_idna_to_unicode_impl(const char* input, size_t length,
                               size_t* out_length) noexcept {
  std::string out = ada::idna::to_unicode(std::string_view(input, length));
  *out_length = out.size();
  char* result = static_cast<char*>(malloc(out.size() + 1));
  if (!result) {
    *out_length = 0;
    return nullptr;
  }
  std::memcpy(result, out.data(), out.size());
  result[out.size()] = '\0';
  return result;
}

char* ada_idna_to_ascii_impl(const char* input, size_t length,
                             size_t* out_length) noexcept {
  std::string out = ada::idna::to_ascii(std::string_view(input, length));
  *out_length = out.size();
  char* result = static_cast<char*>(malloc(out.size() + 1));
  if (!result) {
    *out_length = 0;
    return nullptr;
  }
  std::memcpy(result, out.data(), out.size());
  result[out.size()] = '\0';
  return result;
}

// ---- Search params ----------------------------------------------------------

void* ada_parse_search_params_impl(const char* input, size_t length) noexcept {
  return new ada::url_search_params(std::string_view(input, length));
}

void ada_free_search_params_impl(void* result) noexcept {
  delete static_cast<ada::url_search_params*>(result);
}

char* ada_search_params_to_string_impl(void* result,
                                       size_t* out_length) noexcept {
  std::string out = static_cast<ada::url_search_params*>(result)->to_string();
  *out_length = out.size();
  char* buf = static_cast<char*>(malloc(out.size() + 1));
  if (!buf) {
    *out_length = 0;
    return nullptr;
  }
  std::memcpy(buf, out.data(), out.size());
  buf[out.size()] = '\0';
  return buf;
}

size_t ada_search_params_size_impl(void* result) noexcept {
  return static_cast<ada::url_search_params*>(result)->size();
}

void ada_search_params_sort_impl(void* result) noexcept {
  static_cast<ada::url_search_params*>(result)->sort();
}

void ada_search_params_reset_impl(void* result, const char* input,
                                  size_t length) noexcept {
  static_cast<ada::url_search_params*>(result)->reset(
      std::string_view(input, length));
}

void ada_search_params_append_impl(void* result, const char* key,
                                   size_t key_length, const char* value,
                                   size_t value_length) noexcept {
  static_cast<ada::url_search_params*>(result)->append(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

void ada_search_params_set_impl(void* result, const char* key,
                                size_t key_length, const char* value,
                                size_t value_length) noexcept {
  static_cast<ada::url_search_params*>(result)->set(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

void ada_search_params_remove_impl(void* result, const char* key,
                                   size_t key_length) noexcept {
  static_cast<ada::url_search_params*>(result)->remove(
      std::string_view(key, key_length));
}

void ada_search_params_remove_value_impl(void* result, const char* key,
                                         size_t key_length, const char* value,
                                         size_t value_length) noexcept {
  static_cast<ada::url_search_params*>(result)->remove(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

bool ada_search_params_has_impl(void* result, const char* key,
                                size_t key_length) noexcept {
  return static_cast<ada::url_search_params*>(result)->has(
      std::string_view(key, key_length));
}

bool ada_search_params_has_value_impl(void* result, const char* key,
                                      size_t key_length, const char* value,
                                      size_t value_length) noexcept {
  return static_cast<ada::url_search_params*>(result)->has(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

const char* ada_search_params_get_impl(void* result, const char* key,
                                       size_t key_length,
                                       size_t* out_length) noexcept {
  auto found = static_cast<ada::url_search_params*>(result)->get(
      std::string_view(key, key_length));
  if (!found.has_value()) {
    *out_length = 0;
    return nullptr;
  }
  *out_length = found->size();
  return found->data();
}

void* ada_search_params_get_all_impl(void* result, const char* key,
                                     size_t key_length) noexcept {
  return new std::vector<std::string>(
      static_cast<ada::url_search_params*>(result)->get_all(
          std::string_view(key, key_length)));
}

void* ada_search_params_get_keys_impl(void* result) noexcept {
  return new ada::url_search_params_keys_iter(
      static_cast<ada::url_search_params*>(result)->get_keys());
}

void* ada_search_params_get_values_impl(void* result) noexcept {
  return new ada::url_search_params_values_iter(
      static_cast<ada::url_search_params*>(result)->get_values());
}

void* ada_search_params_get_entries_impl(void* result) noexcept {
  return new ada::url_search_params_entries_iter(
      static_cast<ada::url_search_params*>(result)->get_entries());
}

// ---- Strings (get_all results) ---------------------------------------------

void ada_free_strings_impl(void* result) noexcept {
  delete static_cast<std::vector<std::string>*>(result);
}

size_t ada_strings_size_impl(void* result) noexcept {
  return static_cast<std::vector<std::string>*>(result)->size();
}

const char* ada_strings_get_impl(void* result, size_t index,
                                 size_t* out_length) noexcept {
  const std::string& s =
      static_cast<std::vector<std::string>*>(result)->at(index);
  *out_length = s.size();
  return s.data();
}

// ---- Keys iterator ---------------------------------------------------------

void ada_free_search_params_keys_iter_impl(void* result) noexcept {
  delete static_cast<ada::url_search_params_keys_iter*>(result);
}

const char* ada_search_params_keys_iter_next_impl(void* result,
                                                   size_t* out_length) noexcept {
  auto next = static_cast<ada::url_search_params_keys_iter*>(result)->next();
  if (!next.has_value()) {
    *out_length = 0;
    return nullptr;
  }
  *out_length = next->size();
  return next->data();
}

bool ada_search_params_keys_iter_has_next_impl(void* result) noexcept {
  return static_cast<ada::url_search_params_keys_iter*>(result)->has_next();
}

// ---- Values iterator -------------------------------------------------------

void ada_free_search_params_values_iter_impl(void* result) noexcept {
  delete static_cast<ada::url_search_params_values_iter*>(result);
}

const char* ada_search_params_values_iter_next_impl(
    void* result, size_t* out_length) noexcept {
  auto next =
      static_cast<ada::url_search_params_values_iter*>(result)->next();
  if (!next.has_value()) {
    *out_length = 0;
    return nullptr;
  }
  *out_length = next->size();
  return next->data();
}

bool ada_search_params_values_iter_has_next_impl(void* result) noexcept {
  return static_cast<ada::url_search_params_values_iter*>(result)->has_next();
}

// ---- Entries iterator ------------------------------------------------------

void ada_free_search_params_entries_iter_impl(void* result) noexcept {
  delete static_cast<ada::url_search_params_entries_iter*>(result);
}

void ada_search_params_entries_iter_next_impl(void* result, const char** key,
                                               size_t* key_length,
                                               const char** value,
                                               size_t* value_length) noexcept {
  auto next =
      static_cast<ada::url_search_params_entries_iter*>(result)->next();
  if (!next.has_value()) {
    *key = nullptr;
    *key_length = 0;
    *value = nullptr;
    *value_length = 0;
    return;
  }
  *key = next->first.data();
  *key_length = next->first.size();
  *value = next->second.data();
  *value_length = next->second.size();
}

bool ada_search_params_entries_iter_has_next_impl(void* result) noexcept {
  return static_cast<ada::url_search_params_entries_iter*>(result)->has_next();
}

// ---- Version ----------------------------------------------------------------

const char* ada_get_version_impl(void) noexcept { return ADA_VERSION; }

void ada_get_version_components_impl(int* major, int* minor,
                                     int* revision) noexcept {
  *major = ada::ADA_VERSION_MAJOR;
  *minor = ada::ADA_VERSION_MINOR;
  *revision = ada::ADA_VERSION_REVISION;
}

}  // extern "C"
// NOLINTEND(bugprone-exception-escape,
// bugprone-suspicious-stringview-data-usage)

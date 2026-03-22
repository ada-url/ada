// NOLINTBEGIN(bugprone-exception-escape,
// bugprone-suspicious-stringview-data-usage)
#include "ada/parser.h"
#include "ada/url_aggregator-inl.h"
#include "ada/url_search_params-inl.h"

/**
 * Efficient C API implementation for ada URL parser.
 *
 * Each opaque handle is a raw pointer to the underlying C++ object, with no
 * tl::expected<> wrapper layer.  Validity is tracked via
 * url_aggregator::is_valid (inherited from url_base) rather than through the
 * result type, which eliminates one heap allocation and one variant-copy per
 * parse call.
 *
 *   ada_url               -> ada::url_aggregator*
 *   ada_url_search_params -> ada::url_search_params*
 *   ada_strings           -> std::vector<std::string>*
 *   ada_url_search_params_*_iter -> ada::url_search_params_*_iter*
 */

static inline ada::url_aggregator& get_instance(void* result) noexcept {
  return *static_cast<ada::url_aggregator*>(result);
}

extern "C" {
typedef void* ada_url;
typedef void* ada_url_search_params;
typedef void* ada_strings;
typedef void* ada_url_search_params_keys_iter;
typedef void* ada_url_search_params_values_iter;
typedef void* ada_url_search_params_entries_iter;

struct ada_string {
  const char* data;
  size_t length;
};

struct ada_owned_string {
  const char* data;
  size_t length;
};

struct ada_string_pair {
  ada_string key;
  ada_string value;
};

static inline ada_string ada_string_create(const char* data,
                                           size_t length) noexcept {
  ada_string out{};
  out.data = data;
  out.length = length;
  return out;
}

struct ada_url_components {
  /*
   * By using 32-bit integers, we implicitly assume that the URL string
   * cannot exceed 4 GB.
   *
   * https://user:pass@example.com:1234/foo/bar?baz#quux
   *       |     |    |          | ^^^^|       |   |
   *       |     |    |          | |   |       |   `----- hash_start
   *       |     |    |          | |   |       `--------- search_start
   *       |     |    |          | |   `----------------- pathname_start
   *       |     |    |          | `--------------------- port
   *       |     |    |          `----------------------- host_end
   *       |     |    `---------------------------------- host_start
   *       |     `--------------------------------------- username_end
   *       `--------------------------------------------- protocol_end
   */
  uint32_t protocol_end;
  /**
   * Username end is not `omitted` by default (-1) to make username and password
   * getters less costly to implement.
   */
  uint32_t username_end;
  uint32_t host_start;
  uint32_t host_end;
  uint32_t port;
  uint32_t pathname_start;
  uint32_t search_start;
  uint32_t hash_start;
};

ada_url ada_parse(const char* input, size_t length) noexcept {
  return new ada::url_aggregator(
      ada::parser::parse_url_impl<ada::url_aggregator>(
          std::string_view(input, length)));
}

ada_url ada_parse_with_base(const char* input, size_t input_length,
                            const char* base, size_t base_length) noexcept {
  ada::url_aggregator base_url =
      ada::parser::parse_url_impl<ada::url_aggregator>(
          std::string_view(base, base_length));
  if (!base_url.is_valid) {
    return new ada::url_aggregator(std::move(base_url));
  }
  return new ada::url_aggregator(
      ada::parser::parse_url_impl<ada::url_aggregator>(
          std::string_view(input, input_length), &base_url));
}

bool ada_can_parse(const char* input, size_t length) noexcept {
  return ada::can_parse(std::string_view(input, length));
}

bool ada_can_parse_with_base(const char* input, size_t input_length,
                             const char* base, size_t base_length) noexcept {
  std::string_view base_view(base, base_length);
  return ada::can_parse(std::string_view(input, input_length), &base_view);
}

void ada_free(ada_url result) noexcept {
  delete static_cast<ada::url_aggregator*>(result);
}

ada_url ada_copy(ada_url input) noexcept {
  return new ada::url_aggregator(get_instance(input));
}

bool ada_is_valid(ada_url result) noexcept {
  return get_instance(result).is_valid;
}

// caller must free the result with ada_free_owned_string
ada_owned_string ada_get_origin(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  ada_owned_string owned{};
  if (!r.is_valid) {
    owned.data = nullptr;
    owned.length = 0;
    return owned;
  }
  std::string out = r.get_origin();
  owned.length = out.size();
  owned.data = new char[owned.length];
  memcpy((void*)owned.data, out.data(), owned.length);
  return owned;
}

void ada_free_owned_string(ada_owned_string owned) noexcept {
  delete[] owned.data;
}

ada_string ada_get_href(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_href();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_username(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_username();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_password(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_password();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_port(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_port();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_hash(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_hash();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_host(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_host();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_hostname(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_hostname();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_pathname(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_pathname();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_search(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_search();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_protocol(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r.get_protocol();
  return ada_string_create(out.data(), out.length());
}

uint8_t ada_get_host_type(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return 0;
  }
  return r.host_type;
}

uint8_t ada_get_scheme_type(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return 0;
  }
  return r.type;
}

bool ada_set_href(ada_url result, const char* input, size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_href(std::string_view(input, length));
}

bool ada_set_host(ada_url result, const char* input, size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_host(std::string_view(input, length));
}

bool ada_set_hostname(ada_url result, const char* input,
                      size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_hostname(std::string_view(input, length));
}

bool ada_set_protocol(ada_url result, const char* input,
                      size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_protocol(std::string_view(input, length));
}

bool ada_set_username(ada_url result, const char* input,
                      size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_username(std::string_view(input, length));
}

bool ada_set_password(ada_url result, const char* input,
                      size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_password(std::string_view(input, length));
}

bool ada_set_port(ada_url result, const char* input, size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_port(std::string_view(input, length));
}

bool ada_set_pathname(ada_url result, const char* input,
                      size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.set_pathname(std::string_view(input, length));
}

/**
 * Update the search/query of the URL.
 *
 * If a URL has `?` as the search value, passing empty string to this function
 * does not remove the attribute. If you need to remove it, please use
 * `ada_clear_search` method.
 */
void ada_set_search(ada_url result, const char* input, size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (r.is_valid) {
    r.set_search(std::string_view(input, length));
  }
}

/**
 * Update the hash/fragment of the URL.
 *
 * If a URL has `#` as the hash value, passing empty string to this function
 * does not remove the attribute. If you need to remove it, please use
 * `ada_clear_hash` method.
 */
void ada_set_hash(ada_url result, const char* input, size_t length) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (r.is_valid) {
    r.set_hash(std::string_view(input, length));
  }
}

void ada_clear_port(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (r.is_valid) {
    r.clear_port();
  }
}

/**
 * Removes the hash of the URL.
 *
 * Despite `ada_set_hash` method, this function allows the complete
 * removal of the hash attribute, even if it has a value of `#`.
 */
void ada_clear_hash(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (r.is_valid) {
    r.clear_hash();
  }
}

/**
 * Removes the search of the URL.
 *
 * Despite `ada_set_search` method, this function allows the complete
 * removal of the search attribute, even if it has a value of `?`.
 */
void ada_clear_search(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (r.is_valid) {
    r.clear_search();
  }
}

bool ada_has_credentials(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_credentials();
}

bool ada_has_empty_hostname(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_empty_hostname();
}

bool ada_has_hostname(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_hostname();
}

bool ada_has_non_empty_username(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_non_empty_username();
}

bool ada_has_non_empty_password(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_non_empty_password();
}

bool ada_has_port(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_port();
}

bool ada_has_password(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_password();
}

bool ada_has_hash(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_hash();
}

bool ada_has_search(ada_url result) noexcept {
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return false;
  }
  return r.has_search();
}

// returns a pointer to the internal url_aggregator::url_components
const ada_url_components* ada_get_components(ada_url result) noexcept {
  static_assert(sizeof(ada_url_components) == sizeof(ada::url_components));
  ada::url_aggregator& r = get_instance(result);
  if (!r.is_valid) {
    return nullptr;
  }
  return reinterpret_cast<const ada_url_components*>(&r.get_components());
}

ada_owned_string ada_idna_to_unicode(const char* input, size_t length) {
  std::string out = ada::idna::to_unicode(std::string_view(input, length));
  ada_owned_string owned{};
  owned.length = out.length();
  owned.data = new char[owned.length];
  memcpy((void*)owned.data, out.data(), owned.length);
  return owned;
}

ada_owned_string ada_idna_to_ascii(const char* input, size_t length) {
  std::string out = ada::idna::to_ascii(std::string_view(input, length));
  ada_owned_string owned{};
  owned.length = out.size();
  owned.data = new char[owned.length];
  memcpy((void*)owned.data, out.data(), owned.length);
  return owned;
}

ada_url_search_params ada_parse_search_params(const char* input,
                                              size_t length) {
  return new ada::url_search_params(std::string_view(input, length));
}

void ada_free_search_params(ada_url_search_params result) {
  delete static_cast<ada::url_search_params*>(result);
}

ada_owned_string ada_search_params_to_string(ada_url_search_params result) {
  ada::url_search_params& r = *static_cast<ada::url_search_params*>(result);
  std::string out = r.to_string();
  ada_owned_string owned{};
  owned.length = out.size();
  owned.data = new char[owned.length];
  memcpy((void*)owned.data, out.data(), owned.length);
  return owned;
}

size_t ada_search_params_size(ada_url_search_params result) {
  return static_cast<ada::url_search_params*>(result)->size();
}

void ada_search_params_sort(ada_url_search_params result) {
  static_cast<ada::url_search_params*>(result)->sort();
}

void ada_search_params_reset(ada_url_search_params result, const char* input,
                             size_t length) {
  static_cast<ada::url_search_params*>(result)->reset(
      std::string_view(input, length));
}

void ada_search_params_append(ada_url_search_params result, const char* key,
                              size_t key_length, const char* value,
                              size_t value_length) {
  static_cast<ada::url_search_params*>(result)->append(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

void ada_search_params_set(ada_url_search_params result, const char* key,
                           size_t key_length, const char* value,
                           size_t value_length) {
  static_cast<ada::url_search_params*>(result)->set(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

void ada_search_params_remove(ada_url_search_params result, const char* key,
                              size_t key_length) {
  static_cast<ada::url_search_params*>(result)->remove(
      std::string_view(key, key_length));
}

void ada_search_params_remove_value(ada_url_search_params result,
                                    const char* key, size_t key_length,
                                    const char* value, size_t value_length) {
  static_cast<ada::url_search_params*>(result)->remove(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

bool ada_search_params_has(ada_url_search_params result, const char* key,
                           size_t key_length) {
  return static_cast<ada::url_search_params*>(result)->has(
      std::string_view(key, key_length));
}

bool ada_search_params_has_value(ada_url_search_params result, const char* key,
                                 size_t key_length, const char* value,
                                 size_t value_length) {
  return static_cast<ada::url_search_params*>(result)->has(
      std::string_view(key, key_length), std::string_view(value, value_length));
}

ada_string ada_search_params_get(ada_url_search_params result, const char* key,
                                 size_t key_length) {
  auto found = static_cast<ada::url_search_params*>(result)->get(
      std::string_view(key, key_length));
  if (!found.has_value()) {
    return ada_string_create(nullptr, 0);
  }
  return ada_string_create(found->data(), found->length());
}

ada_strings ada_search_params_get_all(ada_url_search_params result,
                                      const char* key, size_t key_length) {
  return new std::vector<std::string>(
      static_cast<ada::url_search_params*>(result)->get_all(
          std::string_view(key, key_length)));
}

ada_url_search_params_keys_iter ada_search_params_get_keys(
    ada_url_search_params result) {
  return new ada::url_search_params_keys_iter(
      static_cast<ada::url_search_params*>(result)->get_keys());
}

ada_url_search_params_values_iter ada_search_params_get_values(
    ada_url_search_params result) {
  return new ada::url_search_params_values_iter(
      static_cast<ada::url_search_params*>(result)->get_values());
}

ada_url_search_params_entries_iter ada_search_params_get_entries(
    ada_url_search_params result) {
  return new ada::url_search_params_entries_iter(
      static_cast<ada::url_search_params*>(result)->get_entries());
}

void ada_free_strings(ada_strings result) {
  delete static_cast<std::vector<std::string>*>(result);
}

size_t ada_strings_size(ada_strings result) {
  return static_cast<std::vector<std::string>*>(result)->size();
}

ada_string ada_strings_get(ada_strings result, size_t index) {
  std::string_view view =
      static_cast<std::vector<std::string>*>(result)->at(index);
  return ada_string_create(view.data(), view.length());
}

void ada_free_search_params_keys_iter(ada_url_search_params_keys_iter result) {
  delete static_cast<ada::url_search_params_keys_iter*>(result);
}

ada_string ada_search_params_keys_iter_next(
    ada_url_search_params_keys_iter result) {
  auto next =
      static_cast<ada::url_search_params_keys_iter*>(result)->next();
  if (!next.has_value()) {
    return ada_string_create(nullptr, 0);
  }
  return ada_string_create(next->data(), next->length());
}

bool ada_search_params_keys_iter_has_next(
    ada_url_search_params_keys_iter result) {
  return static_cast<ada::url_search_params_keys_iter*>(result)->has_next();
}

void ada_free_search_params_values_iter(
    ada_url_search_params_values_iter result) {
  delete static_cast<ada::url_search_params_values_iter*>(result);
}

ada_string ada_search_params_values_iter_next(
    ada_url_search_params_values_iter result) {
  auto next =
      static_cast<ada::url_search_params_values_iter*>(result)->next();
  if (!next.has_value()) {
    return ada_string_create(nullptr, 0);
  }
  return ada_string_create(next->data(), next->length());
}

bool ada_search_params_values_iter_has_next(
    ada_url_search_params_values_iter result) {
  return static_cast<ada::url_search_params_values_iter*>(result)->has_next();
}

void ada_free_search_params_entries_iter(
    ada_url_search_params_entries_iter result) {
  delete static_cast<ada::url_search_params_entries_iter*>(result);
}

ada_string_pair ada_search_params_entries_iter_next(
    ada_url_search_params_entries_iter result) {
  auto next =
      static_cast<ada::url_search_params_entries_iter*>(result)->next();
  if (!next.has_value()) {
    return {ada_string_create(nullptr, 0), ada_string_create(nullptr, 0)};
  }
  return ada_string_pair{
      ada_string_create(next->first.data(), next->first.length()),
      ada_string_create(next->second.data(), next->second.length())};
}

bool ada_search_params_entries_iter_has_next(
    ada_url_search_params_entries_iter result) {
  return static_cast<ada::url_search_params_entries_iter*>(result)->has_next();
}

typedef struct {
  int major;
  int minor;
  int revision;
} ada_version_components;

const char* ada_get_version() { return ADA_VERSION; }

ada_version_components ada_get_version_components() {
  return ada_version_components{
      .major = ada::ADA_VERSION_MAJOR,
      .minor = ada::ADA_VERSION_MINOR,
      .revision = ada::ADA_VERSION_REVISION,
  };
}

}  // extern "C"
// NOLINTEND(bugprone-exception-escape,
// bugprone-suspicious-stringview-data-usage)

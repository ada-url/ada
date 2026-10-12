// NOLINTBEGIN(bugprone-exception-escape,
// bugprone-suspicious-stringview-data-usage)
#include "ada/url_aggregator-inl.h"
#include "ada/url_search_params-inl.h"

#include <cstring>
#include <string>
#include <utility>
#include <vector>

// Every handle allocated here is a handle_box. The C typedefs stay void*, so
// existing callers keep compiling. The leading kind word lets ada_free_*
// ignore a pointer of the wrong kind instead of deleting it.
enum class handle_kind : uint32_t {
  url = 0x41646101u,
  search_params = 0x41646102u,
  strings = 0x41646103u,
  keys_iter = 0x41646104u,
  values_iter = 0x41646105u,
  entries_iter = 0x41646106u,
};

struct handle_header {
  uint32_t kind;
};

template <typename T>
struct handle_box : handle_header {
  T value;
  handle_box(uint32_t k, T&& v) : handle_header{k}, value(std::move(v)) {}
};

template <handle_kind Kind, typename T>
void* box_new(T value) {
  return new handle_box<T>(static_cast<uint32_t>(Kind), std::move(value));
}

template <handle_kind Kind, typename T>
T* box_get(void* pointer) noexcept {
  if (pointer == nullptr) {
    return nullptr;
  }
  if (static_cast<handle_header*>(pointer)->kind !=
      static_cast<uint32_t>(Kind)) {
    return nullptr;
  }
  return &static_cast<handle_box<T>*>(pointer)->value;
}

template <handle_kind Kind, typename T>
void box_delete(void* pointer) {
  if (box_get<Kind, T>(pointer) == nullptr) {
    return;
  }
  delete static_cast<handle_box<T>*>(pointer);
}

// A mismatched or null handle behaves like an invalid result: getters return
// empty values and setters do nothing. The static is never mutated.
template <handle_kind Kind, typename T>
T& instance_of(void* pointer) noexcept {
  if (T* value = box_get<Kind, T>(pointer)) {
    return *value;
  }
  static T invalid{tl::unexpected(ada::errors::type_error)};
  return invalid;
}

using url_result = ada::result<ada::url_aggregator>;
using params_result = ada::result<ada::url_search_params>;
using strings_result = ada::result<std::vector<std::string>>;
using keys_iter_result = ada::result<ada::url_search_params_keys_iter>;
using values_iter_result = ada::result<ada::url_search_params_values_iter>;
using entries_iter_result = ada::result<ada::url_search_params_entries_iter>;

url_result& get_instance(void* result) noexcept {
  return instance_of<handle_kind::url, url_result>(result);
}

params_result& search_params_of(void* result) noexcept {
  return instance_of<handle_kind::search_params, params_result>(result);
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

ada_string ada_string_create(const char* data, size_t length) {
  ada_string out{};
  out.data = data;
  out.length = length;
  return out;
}

ada_owned_string copy_owned(std::string_view out) {
  ada_owned_string owned{};
  owned.length = out.size();
  char* buffer = new char[out.size() + 1];
  if (!out.empty()) {
    memcpy(buffer, out.data(), out.size());
  }
  buffer[out.size()] = '\0';
  owned.data = buffer;
  return owned;
}

ada_owned_string empty_owned() {
  ada_owned_string owned{};
  owned.data = nullptr;
  owned.length = 0;
  return owned;
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

ada_url ada_parse(const char* input, size_t length) noexcept try {
  return box_new<handle_kind::url>(url_result(
      ada::parse<ada::url_aggregator>(std::string_view(input, length))));
} catch (...) {
  return nullptr;
}

ada_url ada_parse_with_base(const char* input, size_t input_length,
                            const char* base, size_t base_length) noexcept try {
  auto base_out =
      ada::parse<ada::url_aggregator>(std::string_view(base, base_length));

  if (!base_out) {
    return box_new<handle_kind::url>(url_result(std::move(base_out)));
  }

  return box_new<handle_kind::url>(url_result(ada::parse<ada::url_aggregator>(
      std::string_view(input, input_length), &base_out.value())));
} catch (...) {
  return nullptr;
}

bool ada_can_parse(const char* input, size_t length) noexcept try {
  return ada::can_parse(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_can_parse_with_base(const char* input, size_t input_length,
                             const char* base, size_t base_length) noexcept
    try {
  std::string_view base_view(base, base_length);
  return ada::can_parse(std::string_view(input, input_length), &base_view);
} catch (...) {
  return false;
}

void ada_free(ada_url result) noexcept try {
  box_delete<handle_kind::url, url_result>(result);
} catch (...) {
}

ada_url ada_copy(ada_url input) noexcept try {
  url_result& r = get_instance(input);
  return box_new<handle_kind::url>(url_result(r));
} catch (...) {
  return nullptr;
}

bool ada_is_valid(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  return r.has_value();
} catch (...) {
  return false;
}

// caller must free the result with ada_free_owned_string
ada_owned_string ada_get_origin(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return empty_owned();
  }
  return copy_owned(r->get_origin());
} catch (...) {
  return empty_owned();
}

void ada_free_owned_string(ada_owned_string owned) noexcept try {
  delete[] owned.data;
} catch (...) {
}

ada_string ada_get_href(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_href();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_username(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_username();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_password(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_password();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_port(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_port();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_hash(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_hash();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_host(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_host();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_hostname(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_hostname();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_pathname(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_pathname();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_search(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_search();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_string ada_get_protocol(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  std::string_view out = r->get_protocol();
  return ada_string_create(out.data(), out.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

uint8_t ada_get_host_type(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return 0;
  }
  return r->host_type;
} catch (...) {
  return 0;
}

uint8_t ada_get_scheme_type(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return 0;
  }
  return r->type;
} catch (...) {
  return 0;
}

bool ada_set_href(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_href(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_set_host(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_host(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_set_hostname(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_hostname(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_set_protocol(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_protocol(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_set_username(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_username(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_set_password(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_password(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_set_port(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_port(std::string_view(input, length));
} catch (...) {
  return false;
}

bool ada_set_pathname(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_pathname(std::string_view(input, length));
} catch (...) {
  return false;
}

/**
 * Update the search/query of the URL.
 *
 * If a URL has `?` as the search value, passing empty string to this function
 * does not remove the attribute. If you need to remove it, please use
 * `ada_clear_search` method.
 */
void ada_set_search(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (r) {
    r->set_search(std::string_view(input, length));
  }
} catch (...) {
}

/**
 * Update the hash/fragment of the URL.
 *
 * If a URL has `#` as the hash value, passing empty string to this function
 * does not remove the attribute. If you need to remove it, please use
 * `ada_clear_hash` method.
 */
void ada_set_hash(ada_url result, const char* input, size_t length) noexcept
    try {
  url_result& r = get_instance(result);
  if (r) {
    r->set_hash(std::string_view(input, length));
  }
} catch (...) {
}

void ada_clear_port(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (r) {
    r->clear_port();
  }
} catch (...) {
}

/**
 * Removes the hash of the URL.
 *
 * Despite `ada_set_hash` method, this function allows the complete
 * removal of the hash attribute, even if it has a value of `#`.
 */
void ada_clear_hash(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (r) {
    r->clear_hash();
  }
} catch (...) {
}

/**
 * Removes the search of the URL.
 *
 * Despite `ada_set_search` method, this function allows the complete
 * removal of the search attribute, even if it has a value of `?`.
 */
void ada_clear_search(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (r) {
    r->clear_search();
  }
} catch (...) {
}

bool ada_has_credentials(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_credentials();
} catch (...) {
  return false;
}

bool ada_has_empty_hostname(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_empty_hostname();
} catch (...) {
  return false;
}

bool ada_has_hostname(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_hostname();
} catch (...) {
  return false;
}

bool ada_has_non_empty_username(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_non_empty_username();
} catch (...) {
  return false;
}

bool ada_has_non_empty_password(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_non_empty_password();
} catch (...) {
  return false;
}

bool ada_has_port(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_port();
} catch (...) {
  return false;
}

bool ada_has_password(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_password();
} catch (...) {
  return false;
}

bool ada_has_hash(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_hash();
} catch (...) {
  return false;
}

bool ada_has_search(ada_url result) noexcept try {
  url_result& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_search();
} catch (...) {
  return false;
}

// returns a pointer to the internal url_aggregator::url_components
const ada_url_components* ada_get_components(ada_url result) noexcept try {
  static_assert(sizeof(ada_url_components) == sizeof(ada::url_components));
  url_result& r = get_instance(result);
  if (!r) {
    return nullptr;
  }
  return reinterpret_cast<const ada_url_components*>(&r->get_components());
} catch (...) {
  return nullptr;
}

ada_owned_string ada_idna_to_unicode(const char* input, size_t length) try {
  return copy_owned(ada::idna::to_unicode(std::string_view(input, length)));
} catch (...) {
  return empty_owned();
}

ada_owned_string ada_idna_to_ascii(const char* input, size_t length) try {
  return copy_owned(ada::idna::to_ascii(std::string_view(input, length)));
} catch (...) {
  return empty_owned();
}

ada_url_search_params ada_parse_search_params(const char* input,
                                              size_t length) try {
  return box_new<handle_kind::search_params>(
      params_result(ada::url_search_params(std::string_view(input, length))));
} catch (...) {
  return nullptr;
}

void ada_free_search_params(ada_url_search_params result) try {
  box_delete<handle_kind::search_params, params_result>(result);
} catch (...) {
}

ada_owned_string ada_search_params_to_string(ada_url_search_params result) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return empty_owned();
  }
  return copy_owned(r->to_string());
} catch (...) {
  return empty_owned();
}

size_t ada_search_params_size(ada_url_search_params result) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return 0;
  }
  return r->size();
} catch (...) {
  return 0;
}

void ada_search_params_sort(ada_url_search_params result) try {
  params_result& r = search_params_of(result);
  if (r) {
    r->sort();
  }
} catch (...) {
}

void ada_search_params_reset(ada_url_search_params result, const char* input,
                             size_t length) try {
  params_result& r = search_params_of(result);
  if (r) {
    r->reset(std::string_view(input, length));
  }
} catch (...) {
}

void ada_search_params_append(ada_url_search_params result, const char* key,
                              size_t key_length, const char* value,
                              size_t value_length) try {
  params_result& r = search_params_of(result);
  if (r) {
    r->append(std::string_view(key, key_length),
              std::string_view(value, value_length));
  }
} catch (...) {
}

void ada_search_params_set(ada_url_search_params result, const char* key,
                           size_t key_length, const char* value,
                           size_t value_length) try {
  params_result& r = search_params_of(result);
  if (r) {
    r->set(std::string_view(key, key_length),
           std::string_view(value, value_length));
  }
} catch (...) {
}

void ada_search_params_remove(ada_url_search_params result, const char* key,
                              size_t key_length) try {
  params_result& r = search_params_of(result);
  if (r) {
    r->remove(std::string_view(key, key_length));
  }
} catch (...) {
}

void ada_search_params_remove_value(ada_url_search_params result,
                                    const char* key, size_t key_length,
                                    const char* value,
                                    size_t value_length) try {
  params_result& r = search_params_of(result);
  if (r) {
    r->remove(std::string_view(key, key_length),
              std::string_view(value, value_length));
  }
} catch (...) {
}

bool ada_search_params_has(ada_url_search_params result, const char* key,
                           size_t key_length) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return false;
  }
  return r->has(std::string_view(key, key_length));
} catch (...) {
  return false;
}

bool ada_search_params_has_value(ada_url_search_params result, const char* key,
                                 size_t key_length, const char* value,
                                 size_t value_length) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return false;
  }
  return r->has(std::string_view(key, key_length),
                std::string_view(value, value_length));
} catch (...) {
  return false;
}

ada_string ada_search_params_get(ada_url_search_params result, const char* key,
                                 size_t key_length) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return ada_string_create(nullptr, 0);
  }
  auto found = r->get(std::string_view(key, key_length));
  if (!found.has_value()) {
    return ada_string_create(nullptr, 0);
  }
  return ada_string_create(found->data(), found->length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

ada_strings ada_search_params_get_all(ada_url_search_params result,
                                      const char* key, size_t key_length) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return box_new<handle_kind::strings>(
        strings_result(std::vector<std::string>()));
  }
  return box_new<handle_kind::strings>(
      strings_result(r->get_all(std::string_view(key, key_length))));
} catch (...) {
  return nullptr;
}

ada_url_search_params_keys_iter ada_search_params_get_keys(
    ada_url_search_params result) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return box_new<handle_kind::keys_iter>(
        keys_iter_result(ada::url_search_params_keys_iter()));
  }
  return box_new<handle_kind::keys_iter>(keys_iter_result(r->get_keys()));
} catch (...) {
  return nullptr;
}

ada_url_search_params_values_iter ada_search_params_get_values(
    ada_url_search_params result) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return box_new<handle_kind::values_iter>(
        values_iter_result(ada::url_search_params_values_iter()));
  }
  return box_new<handle_kind::values_iter>(values_iter_result(r->get_values()));
} catch (...) {
  return nullptr;
}

ada_url_search_params_entries_iter ada_search_params_get_entries(
    ada_url_search_params result) try {
  params_result& r = search_params_of(result);
  if (!r) {
    return box_new<handle_kind::entries_iter>(
        entries_iter_result(ada::url_search_params_entries_iter()));
  }
  return box_new<handle_kind::entries_iter>(
      entries_iter_result(r->get_entries()));
} catch (...) {
  return nullptr;
}

void ada_free_strings(ada_strings result) try {
  box_delete<handle_kind::strings, strings_result>(result);
} catch (...) {
}

size_t ada_strings_size(ada_strings result) try {
  strings_result* r = box_get<handle_kind::strings, strings_result>(result);
  if (r == nullptr || !*r) {
    return 0;
  }
  return (*r)->size();
} catch (...) {
  return 0;
}

ada_string ada_strings_get(ada_strings result, size_t index) try {
  strings_result* r = box_get<handle_kind::strings, strings_result>(result);
  if (r == nullptr || !*r || index >= (*r)->size()) {
    return ada_string_create(nullptr, 0);
  }
  const std::string& view = (*r)->operator[](index);
  return ada_string_create(view.data(), view.length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

void ada_free_search_params_keys_iter(
    ada_url_search_params_keys_iter result) try {
  box_delete<handle_kind::keys_iter, keys_iter_result>(result);
} catch (...) {
}

ada_string ada_search_params_keys_iter_next(
    ada_url_search_params_keys_iter result) try {
  keys_iter_result* r =
      box_get<handle_kind::keys_iter, keys_iter_result>(result);
  if (r == nullptr || !*r) {
    return ada_string_create(nullptr, 0);
  }
  auto next = (*r)->next();
  if (!next.has_value()) {
    return ada_string_create(nullptr, 0);
  }
  return ada_string_create(next->data(), next->length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

bool ada_search_params_keys_iter_has_next(
    ada_url_search_params_keys_iter result) try {
  keys_iter_result* r =
      box_get<handle_kind::keys_iter, keys_iter_result>(result);
  if (r == nullptr || !*r) {
    return false;
  }
  return (*r)->has_next();
} catch (...) {
  return false;
}

void ada_free_search_params_values_iter(
    ada_url_search_params_values_iter result) try {
  box_delete<handle_kind::values_iter, values_iter_result>(result);
} catch (...) {
}

ada_string ada_search_params_values_iter_next(
    ada_url_search_params_values_iter result) try {
  values_iter_result* r =
      box_get<handle_kind::values_iter, values_iter_result>(result);
  if (r == nullptr || !*r) {
    return ada_string_create(nullptr, 0);
  }
  auto next = (*r)->next();
  if (!next.has_value()) {
    return ada_string_create(nullptr, 0);
  }
  return ada_string_create(next->data(), next->length());
} catch (...) {
  return ada_string_create(nullptr, 0);
}

bool ada_search_params_values_iter_has_next(
    ada_url_search_params_values_iter result) try {
  values_iter_result* r =
      box_get<handle_kind::values_iter, values_iter_result>(result);
  if (r == nullptr || !*r) {
    return false;
  }
  return (*r)->has_next();
} catch (...) {
  return false;
}

void ada_free_search_params_entries_iter(
    ada_url_search_params_entries_iter result) try {
  box_delete<handle_kind::entries_iter, entries_iter_result>(result);
} catch (...) {
}

ada_string_pair ada_search_params_entries_iter_next(
    ada_url_search_params_entries_iter result) try {
  entries_iter_result* r =
      box_get<handle_kind::entries_iter, entries_iter_result>(result);
  if (r == nullptr || !*r) {
    return {ada_string_create(nullptr, 0), ada_string_create(nullptr, 0)};
  }
  auto next = (*r)->next();
  if (!next.has_value()) {
    return {ada_string_create(nullptr, 0), ada_string_create(nullptr, 0)};
  }
  return ada_string_pair{
      ada_string_create(next->first.data(), next->first.length()),
      ada_string_create(next->second.data(), next->second.length())};
} catch (...) {
  return {ada_string_create(nullptr, 0), ada_string_create(nullptr, 0)};
}

bool ada_search_params_entries_iter_has_next(
    ada_url_search_params_entries_iter result) try {
  entries_iter_result* r =
      box_get<handle_kind::entries_iter, entries_iter_result>(result);
  if (r == nullptr || !*r) {
    return false;
  }
  return (*r)->has_next();
} catch (...) {
  return false;
}

void ada_set_max_input_length(uint32_t length) noexcept {
  ada::set_max_input_length(length);
}

uint32_t ada_get_max_input_length() noexcept {
  return ada::get_max_input_length();
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

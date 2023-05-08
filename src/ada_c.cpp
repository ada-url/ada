#include "ada.h"

ada::result<ada::url_aggregator>& get_instance(void* result) noexcept {
  return *(ada::result<ada::url_aggregator>*)result;
}

extern "C" {
typedef void* ada_url;

struct ada_string {
  const char* data;
  size_t length;
};

struct ada_owned_string {
  const char* data;
  size_t length;
};

ada_string ada_string_create(const char* data, size_t length) {
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

ada_url ada_parse(const char* input) noexcept {
  return new ada::result<ada::url_aggregator>(
      ada::parse<ada::url_aggregator>(input));
}

bool ada_can_parse(const char* input, const char* base) noexcept {
  if (base == nullptr) {
    return ada::can_parse(input);
  }
  std::string_view sv(base);
  return ada::can_parse(input, &sv);
}

void ada_free(ada_url result) noexcept {
  ada::result<ada::url_aggregator>* r =
      (ada::result<ada::url_aggregator>*)result;
  delete r;
}

bool ada_is_valid(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  return r.has_value();
}

// caller must free the result with ada_free_owned_string
ada_owned_string ada_get_origin(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  ada_owned_string owned;
  if (!r) {
    owned.data = nullptr;
    owned.length = 0;
    return owned;
  }
  std::string out = r->get_origin();
  owned.length = out.size();
  owned.data = new char[owned.length];
  memcpy((void*)owned.data, out.data(), owned.length);
  return owned;
}

void ada_free_owned_string(ada_owned_string owned) noexcept {
  delete[] owned.data;
  owned.data = nullptr;
  owned.length = 0;
}

ada_string ada_get_href(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_href();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_username(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_username();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_password(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_password();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_port(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_port();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_hash(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_hash();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_host(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_host();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_hostname(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_hostname();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_pathname(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_pathname();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_search(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_search();
  return ada_string_create(out.data(), out.length());
}

ada_string ada_get_protocol(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string_create(NULL, 0);
  }
  std::string_view out = r->get_protocol();
  return ada_string_create(out.data(), out.length());
}

bool ada_set_href(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_href(input);
}

bool ada_set_host(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_host(input);
}

bool ada_set_hostname(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_hostname(input);
}

bool ada_set_protocol(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_protocol(input);
}

bool ada_set_username(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_username(input);
}

bool ada_set_password(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_password(input);
}

bool ada_set_port(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_port(input);
}

bool ada_set_pathname(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->set_pathname(input);
}

void ada_set_search(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (r) {
    r->set_search(input);
  }
}

void ada_set_hash(ada_url result, const char* input) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (r) {
    r->set_hash(input);
  }
}

bool ada_has_credentials(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_credentials();
}

bool ada_has_empty_hostname(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_empty_hostname();
}

bool ada_has_hostname(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_hostname();
}

bool ada_has_non_empty_username(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_non_empty_username();
}

bool ada_has_non_empty_password(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_non_empty_password();
}

bool ada_has_port(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_port();
}

bool ada_has_password(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_password();
}

bool ada_has_hash(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_hash();
}

bool ada_has_search(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return false;
  }
  return r->has_search();
}

// returns a pointer to the internal url_aggregator::url_components
const ada_url_components* ada_get_components(ada_url result) noexcept {
  static_assert(sizeof(ada_url_components) == sizeof(ada::url_components));
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return nullptr;
  }
  return reinterpret_cast<const ada_url_components*>(&r->get_components());
}
}  // extern "C"

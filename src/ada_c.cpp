#include "ada.h"

ada::result<ada::url_aggregator>& get_instance(ada_url result) noexcept {
  return *(ada::result<ada::url_aggregator>*)result;
}

extern "C" {
typedef void* ada_url;

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

ada_string ada_get_origin(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string out = r->get_origin();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_href(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_href();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_username(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_username();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_password(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_password();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_port(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_port();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_hash(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_hash();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_host(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_host();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_hostname(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_hostname();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_pathname(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_pathname();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_search(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_search();
  return ada_string::create(out.data(), out.length());
}

ada_string ada_get_protocol(ada_url result) noexcept {
  ada::result<ada::url_aggregator>& r = get_instance(result);
  if (!r) {
    return ada_string::create(NULL, 0);
  }
  std::string_view out = r->get_protocol();
  return ada_string::create(out.data(), out.length());
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

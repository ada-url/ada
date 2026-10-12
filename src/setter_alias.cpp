#if defined(NDEBUG)
// <iostream> installs a process-wide ios_base::Init in every translation unit
// that includes it, and helpers.h pulls <iostream> in. Release builds do not
// need that initializer here. Debug builds do: the development checks call
// std::cerr.
#include <ostream>
#define _GLIBCXX_IOSTREAM 1
#endif

#include "ada/parser.h"
#include "ada/url.h"
#include "ada/url_aggregator.h"
#include "ada/implementation.h"

#include <cstdint>
#include <string>
#include <string_view>

extern "C" {
#include "ada_c.h"
}

namespace ada {

// parse_port is inline and invoked from the class definition. This unit never
// calls it. A visible definition keeps -Werror happy; because nothing odr-uses
// it, the compiler does not emit it, so it cannot displace the real body.
ada_really_inline size_t url::parse_port(std::string_view, bool) noexcept {
  return 0;
}
ada_really_inline size_t url_aggregator::parse_port(std::string_view, bool) {
  return 0;
}

// The unity translation unit's setter bodies are renamed to these symbols.
// Calling convention matches the member functions: the URL is the first
// argument.
bool outline_aggregator_set_username(url_aggregator& self,
                                     std::string_view input);
bool outline_aggregator_set_pathname(url_aggregator& self,
                                     std::string_view input);
// The unity body keeps its original name when the padding patch applies, so
// this reference stays unresolved there. Other builds rename that body here.
__attribute__((weak)) bool outline_aggregator_set_password(
    url_aggregator& self, std::string_view input);
bool outline_url_set_username(url& self, std::string_view input);
bool outline_url_set_password(url& self, std::string_view input);
bool outline_url_set_pathname(url& self, std::string_view input);

namespace {

// Same predicate as helpers::overlaps, inlined so the fast path does not call
// out.
bool aliases(std::string_view input, const std::string& member) noexcept {
  return !input.empty() && !member.empty() && input.data() >= member.data() &&
         input.data() < member.data() + member.size();
}

// The owning string must not live in the setter. Its destructor forces a stack
// canary onto the fast path.
template <typename T>
ada_never_inline bool call_on_copy(T& self, std::string_view input,
                                   bool (*impl)(T&, std::string_view)) {
  const std::string copy(input);
  return impl(self, copy);
}

}  // namespace

bool url_aggregator::set_username(std::string_view input) {
  if (aliases(input, buffer)) {
    return call_on_copy(*this, input, outline_aggregator_set_username);
  }
  return outline_aggregator_set_username(*this, input);
}

bool url_aggregator::set_pathname(std::string_view input) {
  if (aliases(input, buffer)) {
    return call_on_copy(*this, input, outline_aggregator_set_pathname);
  }
  return outline_aggregator_set_pathname(*this, input);
}

// noipa: this definition must stay a real call, so a strong set_password in
// the unity object (the padding patch) is the one that actually runs.
__attribute__((noinline, noipa, weak)) bool url_aggregator::set_password(
    std::string_view input) {
  if (aliases(input, buffer)) {
    return call_on_copy(*this, input, outline_aggregator_set_password);
  }
  return outline_aggregator_set_password(*this, input);
}

bool url::set_username(std::string_view input) {
  if (aliases(input, username)) {
    return call_on_copy(*this, input, outline_url_set_username);
  }
  return outline_url_set_username(*this, input);
}

bool url::set_password(std::string_view input) {
  if (aliases(input, password)) {
    return call_on_copy(*this, input, outline_url_set_password);
  }
  return outline_url_set_password(*this, input);
}

bool url::set_pathname(std::string_view input) {
  if (aliases(input, path)) {
    return call_on_copy(*this, input, outline_url_set_pathname);
  }
  return outline_url_set_pathname(*this, input);
}

}  // namespace ada

// The copies inside the unity translation unit call the renamed bodies and
// would skip this check. These definitions are the ones other translation
// units, including C callers, actually link.
extern "C" {

bool ada_set_username(ada_url result, const char* input, size_t length) {
  auto& r = *static_cast<ada::result<ada::url_aggregator>*>(result);
  if (!r) {
    return false;
  }
  return r->set_username(std::string_view(input, length));
}

bool ada_set_password(ada_url result, const char* input, size_t length) {
  auto& r = *static_cast<ada::result<ada::url_aggregator>*>(result);
  if (!r) {
    return false;
  }
  return r->set_password(std::string_view(input, length));
}

bool ada_set_pathname(ada_url result, const char* input, size_t length) {
  auto& r = *static_cast<ada::result<ada::url_aggregator>*>(result);
  if (!r) {
    return false;
  }
  return r->set_pathname(std::string_view(input, length));
}

}  // extern "C"

#if defined(NDEBUG)
// Keep this translation unit from installing another ios_base::Init.
#include <ostream>
#define _GLIBCXX_IOSTREAM 1
#endif

#include "ada/parser.h"
#include "ada/url.h"
#include "ada/url_aggregator.h"

#include <string>
#include <string_view>

namespace ada {

// parse_port is referenced from the class definitions and never called here.
ada_really_inline size_t url::parse_port(std::string_view, bool) noexcept {
  return 0;
}
ada_really_inline size_t url_aggregator::parse_port(std::string_view, bool) {
  return 0;
}

}  // namespace ada

// Same registers as url_aggregator::set_password. The copy does not overlap
// the buffer, so the patched setter falls through into its original body.
extern "C" __attribute__((noinline, visibility("hidden"))) bool
ada_agg_set_password_alias(ada::url_aggregator& self, std::string_view input) {
  const std::string copy(input);
  return self.set_password(copy);
}

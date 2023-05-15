#include "ada/unicode.h"
#include "ada/urlpattern.h"
#include "ada/urlpattern_tokenizer.h"
#include "ada/ada_idna.h"
#include "ada/implementation.h"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>
#include <string_view>
#include <cassert>

namespace ada::urlpattern {

// The new URLPattern(input, baseURL, options) constructor steps are:
// Run initialize given this, input, baseURL, and options.
urlpattern::urlpattern(std::string_view input,
                       std::optional<std::string_view> base_url,
                       std::optional<urlpattern_options> &options) {
  // convert input to utf32
}

}  // namespace ada::urlpattern

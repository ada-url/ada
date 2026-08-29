#include "ada/implementation-inl.h"

#include <atomic>
#include <limits>
#include <string>
#include <string_view>

#include "ada/common_defs.h"
#include "ada/helpers.h"
#include "ada/parser.h"
#include "ada/scheme.h"
#include "ada/unicode.h"
#include "ada/url_aggregator.h"

namespace ada {

static std::atomic<uint32_t> max_input_length_{
    std::numeric_limits<uint32_t>::max()};

// parse() / parse_url_impl read this instead of always hitting the atomic.
// Restored to false when the limit is set back to the ~4 GB default.
bool max_input_length_customized = false;

void set_max_input_length(uint32_t length) {
  max_input_length_.store(length, std::memory_order_relaxed);
  max_input_length_customized = length != std::numeric_limits<uint32_t>::max();
}

uint32_t get_max_input_length() {
  return max_input_length_.load(std::memory_order_relaxed);
}

bool can_parse_fallback(std::string_view input,
                        const std::string_view* base_input) {
  const uint32_t max_length = get_max_input_length();
  if (input.size() > max_length) {
    return false;
  }
  if (base_input != nullptr && base_input->size() > max_length) {
    return false;
  }

  const size_t combined =
      input.size() + (base_input == nullptr ? 0 : base_input->size());
  const bool size_safe = combined <= static_cast<size_t>(max_length) / 5;

  if (size_safe) {
    url_aggregator base_agg;
    url_aggregator* base_ptr = nullptr;
    if (base_input != nullptr) {
      base_agg =
          parser::parse_url_impl<url_aggregator, false>(*base_input, nullptr);
      if (!base_agg.is_valid) {
        return false;
      }
      base_ptr = &base_agg;
    }
    return parser::parse_url_impl<url_aggregator, false>(input, base_ptr)
        .is_valid;
  }

  if (base_input == nullptr) {
    return parser::parse_url_impl<url_aggregator, true>(input, nullptr)
        .is_valid;
  }
  url_aggregator base_agg =
      parser::parse_url_impl<url_aggregator, true>(*base_input, nullptr);
  if (!base_agg.is_valid) {
    return false;
  }
  return parser::parse_url_impl<url_aggregator, true>(input, &base_agg)
      .is_valid;
}

std::string href_from_file(std::string_view input) {
  // Match ada::parse / setters: refuse inputs that already exceed the limit.
  // Path percent-encoding can still expand the result, so we also check the
  // final href below.
  const uint32_t max_length = ada::get_max_input_length();
  if (input.size() > max_length) {
    return {};
  }

  // This is going to be much faster than constructing a URL.
  std::string tmp_buffer;
  std::string_view internal_input;
  if (unicode::has_tabs_or_newline(input)) {
    tmp_buffer = input;
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = input;
  }
  std::string path;
  if (internal_input.empty()) {
    path = "/";
  } else if ((internal_input[0] == '/') || (internal_input[0] == '\\')) {
    helpers::parse_prepared_path(internal_input.substr(1),
                                 ada::scheme::type::FILE, path);
  } else {
    helpers::parse_prepared_path(internal_input, ada::scheme::type::FILE, path);
  }
  std::string result = "file://" + path;
  if (result.size() > max_length) {
    return {};
  }
  return result;
}

ada_warn_unused std::string_view to_string(ada::encoding_type type) {
  switch (type) {
    case ada::encoding_type::UTF8:
      return "UTF-8";
    case ada::encoding_type::UTF_16LE:
      return "UTF-16LE";
    case ada::encoding_type::UTF_16BE:
      return "UTF-16BE";
    default:
      unreachable();
  }
}

}  // namespace ada

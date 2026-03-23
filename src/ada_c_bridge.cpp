// NOLINTBEGIN(bugprone-exception-escape,
// bugprone-suspicious-stringview-data-usage)
/**
 * @file ada_c_bridge.cpp
 * @brief C++ bridge functions for the pure-C ada_c.c implementation.
 *
 * Provides only: URL parsing and IDNA.
 * All setters, clears, and other operations are implemented in pure C in
 * ada_c.c.
 */
#include "ada/url_aggregator-inl.h"
#include "ada/url_aggregator_c.h"
#include "ada/implementation.h"

#include <cstdlib>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static ada_url_aggregator_t* to_c_aggregator(
    const ada::url_aggregator& agg) noexcept {
  auto* out =
      static_cast<ada_url_aggregator_t*>(malloc(sizeof(ada_url_aggregator_t)));
  if (!out) return nullptr;

  std::string_view href = agg.get_href();
  const uint32_t len = static_cast<uint32_t>(href.size());
  out->buffer = static_cast<char*>(malloc(static_cast<size_t>(len) + 1));
  if (!out->buffer) { free(out); return nullptr; }
  std::memcpy(out->buffer, href.data(), len);
  out->buffer[len]   = '\0';
  out->buffer_length   = len;
  out->buffer_capacity = len + 1;

  const ada::url_components& c = agg.get_components();
  out->protocol_end  = c.protocol_end;
  out->username_end  = c.username_end;
  out->host_start    = c.host_start;
  out->host_end      = c.host_end;
  out->port          = c.port;
  out->pathname_start = c.pathname_start;
  out->search_start  = c.search_start;
  out->hash_start    = c.hash_start;

  out->is_valid       = static_cast<uint8_t>(agg.is_valid ? 1 : 0);
  out->has_opaque_path = static_cast<uint8_t>(agg.has_opaque_path ? 1 : 0);
  out->host_type      = static_cast<uint8_t>(agg.host_type);
  out->scheme_type    = static_cast<uint8_t>(agg.type);

  return out;
}

// ---------------------------------------------------------------------------
// extern "C" bridge functions
// ---------------------------------------------------------------------------
extern "C" {

// ---- Parsing ---------------------------------------------------------------

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
  ada::url_aggregator agg = ada::parser::parse_url_impl<ada::url_aggregator>(
      std::string_view(input, input_length), &base_agg);
  return to_c_aggregator(agg);
}

// ---- IDNA ------------------------------------------------------------------

char* ada_idna_to_unicode_impl(const char* input, size_t length,
                               size_t* out_length) noexcept {
  std::string out = ada::idna::to_unicode(std::string_view(input, length));
  *out_length = out.size();
  char* result = static_cast<char*>(malloc(out.size() + 1));
  if (!result) { *out_length = 0; return nullptr; }
  std::memcpy(result, out.data(), out.size());
  result[out.size()] = '\0';
  return result;
}

char* ada_idna_to_ascii_impl(const char* input, size_t length,
                             size_t* out_length) noexcept {
  std::string out = ada::idna::to_ascii(std::string_view(input, length));
  *out_length = out.size();
  char* result = static_cast<char*>(malloc(out.size() + 1));
  if (!result) { *out_length = 0; return nullptr; }
  std::memcpy(result, out.data(), out.size());
  result[out.size()] = '\0';
  return result;
}

}  // extern "C"
// NOLINTEND(bugprone-exception-escape,
// bugprone-suspicious-stringview-data-usage)

/*
 * ada_c.c - Pure C implementation of the ada URL parser C API.
 *
 * The URL aggregator is represented as a plain C struct (ada_url_aggregator_t)
 * defined in include/ada/url_aggregator_c.h. Parsing and mutation operations
 * that require C++ logic are delegated to bridge functions implemented in
 * ada_c_bridge.cpp. All read-only operations (getters and predicates) are
 * implemented directly in C using pointer arithmetic on the buffer.
 *
 * SIMD acceleration:
 *   ada_c_has_tabs_or_newline() mirrors unicode::has_tabs_or_newline() from
 *   unicode.cpp and uses the same ADA_C_SSSE3 / ADA_C_NEON / ADA_C_SSE2
 *   code paths.  It is used in ada_can_parse / ada_can_parse_with_base to
 *   provide a fast SIMD pre-scan of the input before delegating to the C++
 *   bridge, matching the approach used by ada::url_aggregator.
 */
#include "ada_c.h"
#include "ada/url_aggregator_c.h"

#include <stdlib.h>
#include <string.h>

/* ---- SIMD includes -------------------------------------------------------- */
#if ADA_C_SSSE3
#  include <tmmintrin.h>
#elif ADA_C_SSE2
#  include <emmintrin.h>
#elif ADA_C_NEON
#  include <arm_neon.h>
#endif

/* ---- Portable "maybe-unused" annotation (avoids -Wunused-function) ------- */
#if defined(__GNUC__) || defined(__clang__)
#  define ADA_C_MAYBE_UNUSED __attribute__((unused))
#else
#  define ADA_C_MAYBE_UNUSED
#endif

/* -------------------------------------------------------------------------- */
/* SIMD-accelerated tab/newline detection                                      */
/*                                                                             */
/* Mirrors unicode::has_tabs_or_newline() in src/unicode.cpp using the same   */
/* ADA_C_SSSE3 / ADA_C_NEON / ADA_C_SSE2 / scalar code paths.                */
/*                                                                             */
/* Used in ada_parse / ada_can_parse to take a SIMD-verified fast path when   */
/* the input is known to have no tabs or newlines (the common case).          */
/* -------------------------------------------------------------------------- */

#if ADA_C_SSSE3
ADA_C_MAYBE_UNUSED
static int ada_c_has_tabs_or_newline(const char* data, size_t length) {
  if (length < 16) {
    for (size_t i = 0; i < length; i++) {
      unsigned char c = (unsigned char)data[i];
      if (c == '\t' || c == '\n' || c == '\r') return 1;
    }
    return 0;
  }
  /* Lookup table: position 9='\t', 10='\n', 13='\r'; all others != input. */
  const __m128i rnt =
      _mm_setr_epi8(1, 0, 0, 0, 0, 0, 0, 0, 0, 9, 10, 0, 0, 13, 0, 0);
  __m128i running = _mm_setzero_si128();
  size_t i = 0;
  for (; i + 15 < length; i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(data + i));
    __m128i shuffled = _mm_shuffle_epi8(rnt, word);
    running = _mm_or_si128(running, _mm_cmpeq_epi8(shuffled, word));
  }
  if (i < length) {
    __m128i word = _mm_loadu_si128((const __m128i*)(data + length - 16));
    __m128i shuffled = _mm_shuffle_epi8(rnt, word);
    running = _mm_or_si128(running, _mm_cmpeq_epi8(shuffled, word));
  }
  return _mm_movemask_epi8(running) != 0;
}

#elif ADA_C_NEON
static int ada_c_has_tabs_or_newline(const char* data, size_t length) {
  if (length < 16) {
    for (size_t i = 0; i < length; i++) {
      unsigned char c = (unsigned char)data[i];
      if (c == '\t' || c == '\n' || c == '\r') return 1;
    }
    return 0;
  }
  static const uint8_t rnt_array[16] = {1, 0, 0,  0, 0, 0,  0, 0,
                                        0, 9, 10, 0, 0, 13, 0, 0};
  const uint8x16_t rnt = vld1q_u8(rnt_array);
  uint8x16_t running = vdupq_n_u8(0);
  size_t i = 0;
  for (; i + 15 < length; i += 16) {
    uint8x16_t word = vld1q_u8((const uint8_t*)data + i);
    running = vorrq_u8(running, vceqq_u8(vqtbl1q_u8(rnt, word), word));
  }
  if (i < length) {
    uint8x16_t word = vld1q_u8((const uint8_t*)data + length - 16);
    running = vorrq_u8(running, vceqq_u8(vqtbl1q_u8(rnt, word), word));
  }
  return vmaxvq_u32(vreinterpretq_u32_u8(running)) != 0;
}

#elif ADA_C_SSE2
static int ada_c_has_tabs_or_newline(const char* data, size_t length) {
  if (length < 16) {
    for (size_t i = 0; i < length; i++) {
      unsigned char c = (unsigned char)data[i];
      if (c == '\t' || c == '\n' || c == '\r') return 1;
    }
    return 0;
  }
  const __m128i mask_r = _mm_set1_epi8('\r');
  const __m128i mask_n = _mm_set1_epi8('\n');
  const __m128i mask_t = _mm_set1_epi8('\t');
  __m128i running = _mm_setzero_si128();
  size_t i = 0;
  for (; i + 15 < length; i += 16) {
    __m128i word = _mm_loadu_si128((const __m128i*)(data + i));
    running = _mm_or_si128(
        _mm_or_si128(running, _mm_or_si128(_mm_cmpeq_epi8(word, mask_r),
                                           _mm_cmpeq_epi8(word, mask_n))),
        _mm_cmpeq_epi8(word, mask_t));
  }
  if (i < length) {
    __m128i word = _mm_loadu_si128((const __m128i*)(data + length - 16));
    running = _mm_or_si128(
        _mm_or_si128(running, _mm_or_si128(_mm_cmpeq_epi8(word, mask_r),
                                           _mm_cmpeq_epi8(word, mask_n))),
        _mm_cmpeq_epi8(word, mask_t));
  }
  return _mm_movemask_epi8(running) != 0;
}

#else
/* Scalar fallback: 8-byte-at-a-time broadcast scan. */
static int ada_c_has_tabs_or_newline(const char* data, size_t length) {
  /* Build 8-byte broadcast masks for '\r', '\n', '\t'. */
  uint64_t m_r, m_n, m_t;
  memset(&m_r, '\r', sizeof(m_r));
  memset(&m_n, '\n', sizeof(m_n));
  memset(&m_t, '\t', sizeof(m_t));
  size_t i = 0;
  for (; i + 7 < length; i += 8) {
    uint64_t w;
    memcpy(&w, data + i, 8);
    uint64_t x1 = w ^ m_r, x2 = w ^ m_n, x3 = w ^ m_t;
    /* has_zero_byte(v): true iff any byte of v is zero. */
#define HZB(v) (((v) - UINT64_C(0x0101010101010101)) & ~(v) & UINT64_C(0x8080808080808080))
    if (HZB(x1) | HZB(x2) | HZB(x3)) return 1;
#undef HZB
  }
  for (; i < length; i++) {
    unsigned char c = (unsigned char)data[i];
    if (c == '\t' || c == '\n' || c == '\r') return 1;
  }
  return 0;
}
#endif /* ADA_C_SSSE3 / ADA_C_NEON / ADA_C_SSE2 / scalar */

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

static inline ada_url_aggregator_t* get_url(ada_url r) {
  return (ada_url_aggregator_t*)r;
}

static inline ada_string make_string(const char* data, size_t length) {
  ada_string s;
  s.data = data;
  s.length = length;
  return s;
}

/* Return a zero-length string_view anchored inside the buffer. */
static inline ada_string empty_string(const ada_url_aggregator_t* r) {
  return make_string(r->buffer, 0);
}

/* Return buffer[start..end); empty (zero-length) if start >= end. */
static inline ada_string substring(const ada_url_aggregator_t* r,
                                    uint32_t start, uint32_t end) {
  if (start >= end) {
    return make_string(r->buffer + start, 0);
  }
  return make_string(r->buffer + start, (size_t)(end - start));
}

/* -------------------------------------------------------------------------- */
/* Lifecycle                                                                   */
/* -------------------------------------------------------------------------- */

ada_url ada_parse(const char* input, size_t length) {
  return (ada_url)ada_parse_impl(input, length);
}

ada_url ada_parse_with_base(const char* input, size_t input_length,
                             const char* base, size_t base_length) {
  return (ada_url)ada_parse_with_base_impl(input, input_length, base,
                                           base_length);
}

bool ada_can_parse(const char* input, size_t length) {
  /* Use the allocation-free bridge that calls ada::can_parse directly.
   * ada_c_has_tabs_or_newline() is available as C-level SIMD infrastructure
   * matching the C++ unicode::has_tabs_or_newline() for future fast paths. */
  return ada_can_parse_impl(input, length);
}

bool ada_can_parse_with_base(const char* input, size_t input_length,
                              const char* base, size_t base_length) {
  return ada_can_parse_with_base_impl(input, input_length, base, base_length);
}

void ada_free(ada_url result) {
  ada_url_aggregator_t* r = get_url(result);
  if (r) {
    free(r->buffer);
    free(r);
  }
}

ada_url ada_copy(ada_url input) {
  const ada_url_aggregator_t* src = get_url(input);
  if (!src) return NULL;

  ada_url_aggregator_t* dst =
      (ada_url_aggregator_t*)malloc(sizeof(ada_url_aggregator_t));
  if (!dst) return NULL;

  /* Shallow copy of all scalar fields. */
  *dst = *src;

  /* Deep copy of the buffer. */
  dst->buffer = (char*)malloc((size_t)src->buffer_capacity);
  if (!dst->buffer) {
    free(dst);
    return NULL;
  }
  /* Copy including the null terminator. */
  memcpy(dst->buffer, src->buffer, (size_t)src->buffer_length + 1);
  return (ada_url)dst;
}

bool ada_is_valid(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  return r && r->is_valid;
}

/* -------------------------------------------------------------------------- */
/* Origin (allocated string)                                                   */
/* -------------------------------------------------------------------------- */

ada_owned_string ada_get_origin(ada_url result) {
  ada_owned_string owned;
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) {
    owned.data = NULL;
    owned.length = 0;
    return owned;
  }
  owned.data = ada_get_origin_impl(r, &owned.length);
  return owned;
}

void ada_free_owned_string(ada_owned_string owned) {
  free((void*)owned.data);
}

/* -------------------------------------------------------------------------- */
/* Getters (pure C, no C++ needed)                                             */
/* -------------------------------------------------------------------------- */

ada_string ada_get_href(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  return make_string(r->buffer, (size_t)r->buffer_length);
}

ada_string ada_get_protocol(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  return make_string(r->buffer, (size_t)r->protocol_end);
}

ada_string ada_get_username(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  /* has_non_empty_username: username_end > protocol_end + 2 */
  if (r->username_end <= r->protocol_end + 2) return empty_string(r);
  /* username is at [protocol_end+2, username_end) */
  uint32_t start = r->protocol_end + 2;
  return substring(r, start, r->username_end);
}

ada_string ada_get_password(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  /*
   * has_non_empty_password: host_start > username_end
   * password is at [username_end+1, host_start)
   * The +1 skips the ':' separator; host_start points to '@'.
   */
  if (r->host_start <= r->username_end) return empty_string(r);
  return substring(r, r->username_end + 1, r->host_start);
}

ada_string ada_get_host(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  /*
   * host_start may point to '@' when credentials are present.
   * Skip it to get the actual start of the hostname.
   * End is always pathname_start (includes port text if present).
   */
  uint32_t start = r->host_start;
  if (r->host_end > r->host_start && r->buffer[r->host_start] == '@') {
    start++;
  }
  if (start == r->host_end) return empty_string(r);
  return substring(r, start, r->pathname_start);
}

ada_string ada_get_hostname(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  /*
   * host_start may point to '@' when credentials are present.
   * Skip it to get the actual start of the hostname.
   */
  uint32_t start = r->host_start;
  if (r->host_end > r->host_start && r->buffer[r->host_start] == '@') {
    start++;
  }
  return substring(r, start, r->host_end);
}

ada_string ada_get_port(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  if (r->port == ADA_URL_OMITTED) return empty_string(r);
  /* Port text is at [host_end+1, pathname_start) (the +1 skips ':') */
  return substring(r, r->host_end + 1, r->pathname_start);
}

ada_string ada_get_pathname(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  uint32_t start = r->pathname_start;
  uint32_t end = r->buffer_length;
  if (r->search_start != ADA_URL_OMITTED) {
    end = r->search_start;
  } else if (r->hash_start != ADA_URL_OMITTED) {
    end = r->hash_start;
  }
  return substring(r, start, end);
}

ada_string ada_get_search(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  if (r->search_start == ADA_URL_OMITTED) return empty_string(r);
  uint32_t start = r->search_start;
  uint32_t end = (r->hash_start != ADA_URL_OMITTED) ? r->hash_start
                                                      : r->buffer_length;
  /* Return empty if search is just "?" with nothing after it. */
  if (end <= start + 1) return empty_string(r);
  return substring(r, start, end);
}

ada_string ada_get_hash(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  if (r->hash_start == ADA_URL_OMITTED) return empty_string(r);
  /* Return empty if hash is just "#" with nothing after it. */
  if (r->buffer_length - r->hash_start <= 1) return empty_string(r);
  return substring(r, r->hash_start, r->buffer_length);
}

/* -------------------------------------------------------------------------- */
/* Type accessors                                                               */
/* -------------------------------------------------------------------------- */

uint8_t ada_get_host_type(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return 0;
  return r->host_type;
}

uint8_t ada_get_scheme_type(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return 0;
  return r->scheme_type;
}

/* -------------------------------------------------------------------------- */
/* URL components struct                                                        */
/* -------------------------------------------------------------------------- */

const ada_url_components* ada_get_components(ada_url result) {
  /*
   * ada_url_components (public) and the component fields in
   * ada_url_aggregator_t have identical layout and values.
   * We return a pointer to the first component field.
   */
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return NULL;
  /*
   * The layout of ada_url_aggregator_t places the eight component uint32_t
   * fields (protocol_end ... hash_start) contiguously after buffer_capacity.
   * Cast to ada_url_components* is safe because both structs have the same
   * eight-field layout with the same types and order.
   */
  return (const ada_url_components*)&r->protocol_end;
}

/* -------------------------------------------------------------------------- */
/* Predicates (pure C)                                                         */
/* -------------------------------------------------------------------------- */

bool ada_has_credentials(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  /* has_credentials = has_non_empty_username || has_non_empty_password */
  bool has_user = r->username_end > r->protocol_end + 2;
  /* has_non_empty_password: host_start > username_end */
  bool has_pass = r->host_start > r->username_end;
  return has_user || has_pass;
}

bool ada_has_empty_hostname(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  if (!ada_has_hostname(result)) return false;
  if (r->host_start == r->host_end) return true;
  if (r->host_end > r->host_start + 1) return false;
  return r->username_end != r->host_start;
}

bool ada_has_hostname(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  /* has_hostname = has_authority */
  return r->protocol_end + 2 <= r->host_start &&
         r->buffer_length >= r->protocol_end + 2 &&
         r->buffer[r->protocol_end] == '/' &&
         r->buffer[r->protocol_end + 1] == '/';
}

bool ada_has_non_empty_username(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return r->username_end > r->protocol_end + 2;
}

bool ada_has_non_empty_password(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  /* has_non_empty_password: host_start > username_end */
  return r->host_start > r->username_end;
}

bool ada_has_port(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  /* has_port = has_hostname && pathname_start != host_end */
  return ada_has_hostname(result) &&
         r->pathname_start != r->host_end;
}

bool ada_has_password(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  /* has_password: host_start > username_end AND buffer[username_end] == ':' */
  return r->host_start > r->username_end &&
         r->buffer[r->username_end] == ':';
}

bool ada_has_hash(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return r->hash_start != ADA_URL_OMITTED;
}

bool ada_has_search(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return r->search_start != ADA_URL_OMITTED;
}

/* -------------------------------------------------------------------------- */
/* Setters (delegate to C++ bridge)                                            */
/* -------------------------------------------------------------------------- */

bool ada_set_href(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_href_impl(r, input, length);
}

bool ada_set_host(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_host_impl(r, input, length);
}

bool ada_set_hostname(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_hostname_impl(r, input, length);
}

bool ada_set_protocol(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_protocol_impl(r, input, length);
}

bool ada_set_username(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_username_impl(r, input, length);
}

bool ada_set_password(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_password_impl(r, input, length);
}

bool ada_set_port(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_port_impl(r, input, length);
}

bool ada_set_pathname(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_set_pathname_impl(r, input, length);
}

void ada_set_search(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (r && r->is_valid) ada_set_search_impl(r, input, length);
}

void ada_set_hash(ada_url result, const char* input, size_t length) {
  ada_url_aggregator_t* r = get_url(result);
  if (r && r->is_valid) ada_set_hash_impl(r, input, length);
}

void ada_clear_port(ada_url result) {
  ada_url_aggregator_t* r = get_url(result);
  if (r && r->is_valid) ada_clear_port_impl(r);
}

void ada_clear_hash(ada_url result) {
  ada_url_aggregator_t* r = get_url(result);
  if (r && r->is_valid) ada_clear_hash_impl(r);
}

void ada_clear_search(ada_url result) {
  ada_url_aggregator_t* r = get_url(result);
  if (r && r->is_valid) ada_clear_search_impl(r);
}

/* -------------------------------------------------------------------------- */
/* IDNA                                                                        */
/* -------------------------------------------------------------------------- */

ada_owned_string ada_idna_to_unicode(const char* input, size_t length) {
  ada_owned_string owned;
  owned.data = ada_idna_to_unicode_impl(input, length, &owned.length);
  return owned;
}

ada_owned_string ada_idna_to_ascii(const char* input, size_t length) {
  ada_owned_string owned;
  owned.data = ada_idna_to_ascii_impl(input, length, &owned.length);
  return owned;
}

/* -------------------------------------------------------------------------- */
/* Search params                                                                */
/* -------------------------------------------------------------------------- */

ada_url_search_params ada_parse_search_params(const char* input, size_t length) {
  return (ada_url_search_params)ada_parse_search_params_impl(input, length);
}

void ada_free_search_params(ada_url_search_params result) {
  ada_free_search_params_impl(result);
}

ada_owned_string ada_search_params_to_string(ada_url_search_params result) {
  ada_owned_string owned;
  owned.data =
      ada_search_params_to_string_impl(result, &owned.length);
  return owned;
}

size_t ada_search_params_size(ada_url_search_params result) {
  return ada_search_params_size_impl(result);
}

void ada_search_params_sort(ada_url_search_params result) {
  ada_search_params_sort_impl(result);
}

void ada_search_params_reset(ada_url_search_params result, const char* input,
                              size_t length) {
  ada_search_params_reset_impl(result, input, length);
}

void ada_search_params_append(ada_url_search_params result, const char* key,
                               size_t key_length, const char* value,
                               size_t value_length) {
  ada_search_params_append_impl(result, key, key_length, value, value_length);
}

void ada_search_params_set(ada_url_search_params result, const char* key,
                            size_t key_length, const char* value,
                            size_t value_length) {
  ada_search_params_set_impl(result, key, key_length, value, value_length);
}

void ada_search_params_remove(ada_url_search_params result, const char* key,
                               size_t key_length) {
  ada_search_params_remove_impl(result, key, key_length);
}

void ada_search_params_remove_value(ada_url_search_params result,
                                     const char* key, size_t key_length,
                                     const char* value, size_t value_length) {
  ada_search_params_remove_value_impl(result, key, key_length, value,
                                      value_length);
}

bool ada_search_params_has(ada_url_search_params result, const char* key,
                            size_t key_length) {
  return ada_search_params_has_impl(result, key, key_length);
}

bool ada_search_params_has_value(ada_url_search_params result, const char* key,
                                  size_t key_length, const char* value,
                                  size_t value_length) {
  return ada_search_params_has_value_impl(result, key, key_length, value,
                                          value_length);
}

ada_string ada_search_params_get(ada_url_search_params result, const char* key,
                                  size_t key_length) {
  size_t len = 0;
  const char* data =
      ada_search_params_get_impl(result, key, key_length, &len);
  return make_string(data, len);
}

ada_strings ada_search_params_get_all(ada_url_search_params result,
                                       const char* key, size_t key_length) {
  return (ada_strings)ada_search_params_get_all_impl(result, key, key_length);
}

ada_url_search_params_keys_iter ada_search_params_get_keys(
    ada_url_search_params result) {
  return (ada_url_search_params_keys_iter)ada_search_params_get_keys_impl(
      result);
}

ada_url_search_params_values_iter ada_search_params_get_values(
    ada_url_search_params result) {
  return (ada_url_search_params_values_iter)
      ada_search_params_get_values_impl(result);
}

ada_url_search_params_entries_iter ada_search_params_get_entries(
    ada_url_search_params result) {
  return (ada_url_search_params_entries_iter)
      ada_search_params_get_entries_impl(result);
}

/* -------------------------------------------------------------------------- */
/* String collection (get_all result)                                          */
/* -------------------------------------------------------------------------- */

void ada_free_strings(ada_strings result) {
  ada_free_strings_impl(result);
}

size_t ada_strings_size(ada_strings result) {
  return ada_strings_size_impl(result);
}

ada_string ada_strings_get(ada_strings result, size_t index) {
  size_t len = 0;
  const char* data = ada_strings_get_impl(result, index, &len);
  return make_string(data, len);
}

/* -------------------------------------------------------------------------- */
/* Keys iterator                                                                */
/* -------------------------------------------------------------------------- */

void ada_free_search_params_keys_iter(
    ada_url_search_params_keys_iter result) {
  ada_free_search_params_keys_iter_impl(result);
}

ada_string ada_search_params_keys_iter_next(
    ada_url_search_params_keys_iter result) {
  size_t len = 0;
  const char* data =
      ada_search_params_keys_iter_next_impl(result, &len);
  return make_string(data, len);
}

bool ada_search_params_keys_iter_has_next(
    ada_url_search_params_keys_iter result) {
  return ada_search_params_keys_iter_has_next_impl(result);
}

/* -------------------------------------------------------------------------- */
/* Values iterator                                                              */
/* -------------------------------------------------------------------------- */

void ada_free_search_params_values_iter(
    ada_url_search_params_values_iter result) {
  ada_free_search_params_values_iter_impl(result);
}

ada_string ada_search_params_values_iter_next(
    ada_url_search_params_values_iter result) {
  size_t len = 0;
  const char* data =
      ada_search_params_values_iter_next_impl(result, &len);
  return make_string(data, len);
}

bool ada_search_params_values_iter_has_next(
    ada_url_search_params_values_iter result) {
  return ada_search_params_values_iter_has_next_impl(result);
}

/* -------------------------------------------------------------------------- */
/* Entries iterator                                                             */
/* -------------------------------------------------------------------------- */

void ada_free_search_params_entries_iter(
    ada_url_search_params_entries_iter result) {
  ada_free_search_params_entries_iter_impl(result);
}

ada_string_pair ada_search_params_entries_iter_next(
    ada_url_search_params_entries_iter result) {
  ada_string_pair pair;
  const char *key = NULL, *value = NULL;
  size_t key_len = 0, value_len = 0;
  ada_search_params_entries_iter_next_impl(result, &key, &key_len, &value,
                                            &value_len);
  pair.key = make_string(key, key_len);
  pair.value = make_string(value, value_len);
  return pair;
}

bool ada_search_params_entries_iter_has_next(
    ada_url_search_params_entries_iter result) {
  return ada_search_params_entries_iter_has_next_impl(result);
}

/* -------------------------------------------------------------------------- */
/* Version                                                                      */
/* -------------------------------------------------------------------------- */

const char* ada_get_version(void) { return ada_get_version_impl(); }

ada_version_components ada_get_version_components(void) {
  ada_version_components v;
  ada_get_version_components_impl(&v.major, &v.minor, &v.revision);
  return v;
}

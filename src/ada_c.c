/*
 * ada_c.c - Pure C implementation of the ada URL parser C API.
 *
 * The URL aggregator is represented as a plain C struct (ada_url_aggregator_t)
 * defined in include/ada/url_aggregator_c.h. Parsing and mutation operations
 * that require C++ logic are delegated to bridge functions implemented in
 * ada_c_bridge.cpp. All read-only operations (getters and predicates) are
 * implemented directly in C using pointer arithmetic on the buffer.
 */
#include "ada_c.h"
#include "ada/url_aggregator_c.h"
#include "ada/ada_version.h"

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

/* ---- Portable "maybe-unused" annotation ---------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#  define ADA_C_MAYBE_UNUSED __attribute__((unused))
#else
#  define ADA_C_MAYBE_UNUSED
#endif

/* -------------------------------------------------------------------------- */
/* SIMD-accelerated tab/newline detection                                      */
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
static int ada_c_has_tabs_or_newline(const char* data, size_t length) {
  uint64_t m_r, m_n, m_t;
  memset(&m_r, '\r', sizeof(m_r));
  memset(&m_n, '\n', sizeof(m_n));
  memset(&m_t, '\t', sizeof(m_t));
  size_t i = 0;
  for (; i + 7 < length; i += 8) {
    uint64_t w;
    memcpy(&w, data + i, 8);
    uint64_t x1 = w ^ m_r, x2 = w ^ m_n, x3 = w ^ m_t;
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
#endif

/* -------------------------------------------------------------------------- */
/* Internal search params structs (not exported)                               */
/* -------------------------------------------------------------------------- */

typedef struct {
  char*  key;
  size_t key_len;
  char*  value;
  size_t value_len;
} ada_kv_pair_t;

typedef struct {
  ada_kv_pair_t* pairs;
  size_t         count;
  size_t         capacity;
} ada_search_params_impl_t;

typedef struct {
  char**  data;
  size_t* lengths;
  size_t  count;
} ada_strings_impl_t;

typedef struct {
  const ada_search_params_impl_t* sp;
  size_t                          pos;
} ada_search_params_iter_impl_t;

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

static inline ada_string empty_string(const ada_url_aggregator_t* r) {
  return make_string(r->buffer, 0);
}

static inline ada_string substring(const ada_url_aggregator_t* r,
                                    uint32_t start, uint32_t end) {
  if (start >= end) return make_string(r->buffer + start, 0);
  return make_string(r->buffer + start, (size_t)(end - start));
}

/* -------------------------------------------------------------------------- */
/* Percent encode / decode (application/x-www-form-urlencoded)                */
/* -------------------------------------------------------------------------- */

static const char sp_hex_upper[] = "0123456789ABCDEF";

static int sp_is_safe(unsigned char c) {
  return c == '*' || c == '-' || c == '.' || c == '_' ||
         (c >= '0' && c <= '9') ||
         (c >= 'A' && c <= 'Z') ||
         (c >= 'a' && c <= 'z');
}

static char* sp_percent_encode(const char* input, size_t len, size_t* out_len) {
  char* out = (char*)malloc(len * 3 + 1);
  if (!out) { *out_len = 0; return NULL; }
  size_t o = 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)input[i];
    if (c == ' ') {
      out[o++] = '+';
    } else if (sp_is_safe(c)) {
      out[o++] = (char)c;
    } else {
      out[o++] = '%';
      out[o++] = sp_hex_upper[c >> 4];
      out[o++] = sp_hex_upper[c & 0x0F];
    }
  }
  out[o] = '\0';
  *out_len = o;
  return out;
}

static char* sp_percent_decode(const char* input, size_t len, size_t* out_len) {
  char* out = (char*)malloc(len + 1);
  if (!out) { *out_len = 0; return NULL; }
  size_t o = 0;
  for (size_t i = 0; i < len; ) {
    unsigned char c = (unsigned char)input[i];
    if (c == '+') {
      out[o++] = ' ';
      i++;
    } else if (c == '%' && i + 2 < len) {
      unsigned char hi_c = (unsigned char)input[i + 1];
      unsigned char lo_c = (unsigned char)input[i + 2];
      int hi = (hi_c >= '0' && hi_c <= '9') ? (hi_c - '0') :
               (hi_c >= 'A' && hi_c <= 'F') ? (hi_c - 'A' + 10) :
               (hi_c >= 'a' && hi_c <= 'f') ? (hi_c - 'a' + 10) : -1;
      int lo = (lo_c >= '0' && lo_c <= '9') ? (lo_c - '0') :
               (lo_c >= 'A' && lo_c <= 'F') ? (lo_c - 'A' + 10) :
               (lo_c >= 'a' && lo_c <= 'f') ? (lo_c - 'a' + 10) : -1;
      if (hi >= 0 && lo >= 0) {
        out[o++] = (char)((hi << 4) | lo);
        i += 3;
      } else {
        out[o++] = (char)c;
        i++;
      }
    } else {
      out[o++] = (char)c;
      i++;
    }
  }
  out[o] = '\0';
  *out_len = o;
  return out;
}

/* -------------------------------------------------------------------------- */
/* Search params helpers                                                        */
/* -------------------------------------------------------------------------- */

static int sp_append_raw(ada_search_params_impl_t* sp,
                          char* key, size_t key_len,
                          char* value, size_t value_len) {
  if (sp->count >= sp->capacity) {
    size_t new_cap = sp->capacity ? sp->capacity * 2 : 4;
    ada_kv_pair_t* np =
        (ada_kv_pair_t*)realloc(sp->pairs, new_cap * sizeof(ada_kv_pair_t));
    if (!np) return 0;
    sp->pairs    = np;
    sp->capacity = new_cap;
  }
  sp->pairs[sp->count].key       = key;
  sp->pairs[sp->count].key_len   = key_len;
  sp->pairs[sp->count].value     = value;
  sp->pairs[sp->count].value_len = value_len;
  sp->count++;
  return 1;
}

static void sp_initialize(ada_search_params_impl_t* sp,
                           const char* input, size_t len) {
  if (len > 0 && input[0] == '?') { input++; len--; }

  while (len > 0) {
    size_t amp = 0;
    while (amp < len && input[amp] != '&') amp++;

    if (amp > 0) {
      size_t eq = amp;
      for (size_t k = 0; k < amp; k++) {
        if (input[k] == '=') { eq = k; break; }
      }
      const char* key_raw     = input;
      size_t      key_raw_len = eq;
      const char* val_raw     = (eq < amp) ? (input + eq + 1) : (input + amp);
      size_t      val_raw_len = (eq < amp) ? (amp - eq - 1) : 0;

      size_t key_dec_len, val_dec_len;
      char*  key = sp_percent_decode(key_raw, key_raw_len, &key_dec_len);
      char*  val = sp_percent_decode(val_raw, val_raw_len, &val_dec_len);

      if (!key || !val || !sp_append_raw(sp, key, key_dec_len, val, val_dec_len)) {
        free(key); free(val);
      }
    }

    if (amp < len) { input += amp + 1; len -= amp + 1; }
    else break;
  }
}

static void sp_clear(ada_search_params_impl_t* sp) {
  for (size_t i = 0; i < sp->count; i++) {
    free(sp->pairs[i].key);
    free(sp->pairs[i].value);
  }
  sp->count = 0;
}

/* -------------------------------------------------------------------------- */
/* Stable merge sort by UTF-16 code-unit key order                             */
/* -------------------------------------------------------------------------- */

static void sp_next_utf16_unit(const char* str, size_t len, size_t* pos,
                                uint32_t* cp, uint32_t* pending_low) {
  if (*pending_low) { *cp = *pending_low; *pending_low = 0; return; }
  if (*pos >= len) { *cp = 0; return; }
  unsigned char c = (unsigned char)str[*pos];
  if (c <= 0x7F) {
    *cp = c; (*pos)++;
  } else if (c <= 0xDF && *pos + 1 < len) {
    *cp = (uint32_t)(c & 0x1F) << 6 | ((unsigned char)str[*pos + 1] & 0x3F);
    *pos += 2;
  } else if (c <= 0xEF && *pos + 2 < len) {
    *cp = (uint32_t)(c & 0x0F) << 12 |
          (uint32_t)((unsigned char)str[*pos + 1] & 0x3F) << 6 |
          ((unsigned char)str[*pos + 2] & 0x3F);
    *pos += 3;
  } else if (*pos + 3 < len) {
    uint32_t full = (uint32_t)(c & 0x07) << 18 |
                    (uint32_t)((unsigned char)str[*pos + 1] & 0x3F) << 12 |
                    (uint32_t)((unsigned char)str[*pos + 2] & 0x3F) << 6 |
                    ((unsigned char)str[*pos + 3] & 0x3F);
    *pos += 4;
    full -= 0x10000u;
    *cp          = 0xD800u + (full >> 10);
    *pending_low = 0xDC00u + (full & 0x3FFu);
  } else {
    /* Truncated or invalid sequence: treat as single byte. */
    *cp = c; (*pos)++;
  }
}

static int sp_key_cmp(const ada_kv_pair_t* lhs, const ada_kv_pair_t* rhs) {
  size_t i = 0, j = 0;
  uint32_t low1 = 0, low2 = 0;
  while ((i < lhs->key_len || low1) && (j < rhs->key_len || low2)) {
    uint32_t cp1 = 0, cp2 = 0;
    sp_next_utf16_unit(lhs->key, lhs->key_len, &i, &cp1, &low1);
    sp_next_utf16_unit(rhs->key, rhs->key_len, &j, &cp2, &low2);
    if (cp1 != cp2) return (cp1 < cp2) ? -1 : 1;
  }
  if (j < rhs->key_len || low2) return -1;
  if (i < lhs->key_len || low1) return  1;
  return 0;
}

static void sp_merge(ada_kv_pair_t* arr, ada_kv_pair_t* tmp,
                      size_t lo, size_t mid, size_t hi) {
  memcpy(tmp + lo, arr + lo, (hi - lo) * sizeof(ada_kv_pair_t));
  size_t l = lo, r = mid, k = lo;
  while (l < mid && r < hi) {
    arr[k++] = (sp_key_cmp(&tmp[l], &tmp[r]) <= 0) ? tmp[l++] : tmp[r++];
  }
  while (l < mid) arr[k++] = tmp[l++];
  while (r < hi)  arr[k++] = tmp[r++];
}

static void sp_merge_sort(ada_kv_pair_t* arr, ada_kv_pair_t* tmp,
                           size_t lo, size_t hi) {
  if (hi - lo <= 1) return;
  size_t mid = lo + (hi - lo) / 2;
  sp_merge_sort(arr, tmp, lo, mid);
  sp_merge_sort(arr, tmp, mid, hi);
  sp_merge(arr, tmp, lo, mid, hi);
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
  ada_url_aggregator_t* r = ada_parse_impl(input, length);
  if (!r) return false;
  bool valid = (bool)r->is_valid;
  free(r->buffer);
  free(r);
  return valid;
}

bool ada_can_parse_with_base(const char* input, size_t input_length,
                              const char* base, size_t base_length) {
  ada_url_aggregator_t* r =
      ada_parse_with_base_impl(input, input_length, base, base_length);
  if (!r) return false;
  bool valid = (bool)r->is_valid;
  free(r->buffer);
  free(r);
  return valid;
}

void ada_free(ada_url result) {
  ada_url_aggregator_t* r = get_url(result);
  if (r) { free(r->buffer); free(r); }
}

ada_url ada_copy(ada_url input) {
  const ada_url_aggregator_t* src = get_url(input);
  if (!src) return NULL;
  ada_url_aggregator_t* dst =
      (ada_url_aggregator_t*)malloc(sizeof(ada_url_aggregator_t));
  if (!dst) return NULL;
  *dst = *src;
  dst->buffer = (char*)malloc((size_t)src->buffer_capacity);
  if (!dst->buffer) { free(dst); return NULL; }
  memcpy(dst->buffer, src->buffer, (size_t)src->buffer_length + 1);
  return (ada_url)dst;
}

bool ada_is_valid(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  return r && r->is_valid;
}

/* -------------------------------------------------------------------------- */
/* Origin (pure C)                                                             */
/* -------------------------------------------------------------------------- */

static ada_owned_string make_scheme_host_origin(
    const ada_url_aggregator_t* r) {
  ada_owned_string owned;
  uint32_t host_start = r->host_start;
  if (r->buffer[host_start] == '@') host_start++;
  size_t proto_len = (size_t)r->protocol_end;
  size_t host_len  = (r->pathname_start > host_start)
                         ? (size_t)(r->pathname_start - host_start) : 0;
  size_t total = proto_len + 2 + host_len;
  char*  s = (char*)malloc(total + 1);
  if (!s) { owned.data = NULL; owned.length = 0; return owned; }
  memcpy(s, r->buffer, proto_len);
  s[proto_len]     = '/';
  s[proto_len + 1] = '/';
  if (host_len) memcpy(s + proto_len + 2, r->buffer + host_start, host_len);
  s[total] = '\0';
  owned.data = s; owned.length = total;
  return owned;
}

static ada_owned_string make_null_origin(void) {
  ada_owned_string owned;
  char* s = (char*)malloc(5);
  if (!s) { owned.data = NULL; owned.length = 0; return owned; }
  memcpy(s, "null", 5);
  owned.data = s; owned.length = 4;
  return owned;
}

ada_owned_string ada_get_origin(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) {
    ada_owned_string e; e.data = NULL; e.length = 0; return e;
  }
  /* scheme_type: HTTP=0, NOT_SPECIAL=1, HTTPS=2, WS=3, FTP=4, WSS=5, FILE=6 */
  if (r->scheme_type != 1) {
    if (r->scheme_type == 6) return make_null_origin();
    return make_scheme_host_origin(r);
  }
  /* Check for blob: scheme (NOT_SPECIAL but path is a URL) */
  if (r->protocol_end == 5 &&
      r->buffer[0] == 'b' && r->buffer[1] == 'l' &&
      r->buffer[2] == 'o' && r->buffer[3] == 'b' && r->buffer[4] == ':') {
    uint32_t path_start = r->pathname_start;
    uint32_t path_end   = (r->search_start != ADA_URL_OMITTED) ? r->search_start
                          : (r->hash_start  != ADA_URL_OMITTED) ? r->hash_start
                          : r->buffer_length;
    size_t path_len = (path_end > path_start)
                          ? (size_t)(path_end - path_start) : 0;
    ada_url_aggregator_t* inner = ada_parse_impl(r->buffer + path_start,
                                                  path_len);
    if (inner && inner->is_valid &&
        (inner->scheme_type == 0 || inner->scheme_type == 2)) {
      ada_owned_string origin = make_scheme_host_origin(inner);
      free(inner->buffer); free(inner);
      return origin;
    }
    if (inner) { free(inner->buffer); free(inner); }
  }
  return make_null_origin();
}

void ada_free_owned_string(ada_owned_string owned) {
  free((void*)owned.data);
}

/* -------------------------------------------------------------------------- */
/* Getters (pure C)                                                            */
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
  if (r->username_end <= r->protocol_end + 2) return empty_string(r);
  return substring(r, r->protocol_end + 2, r->username_end);
}

ada_string ada_get_password(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  if (r->host_start <= r->username_end) return empty_string(r);
  return substring(r, r->username_end + 1, r->host_start);
}

ada_string ada_get_host(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  uint32_t start = r->host_start;
  if (r->host_end > r->host_start && r->buffer[r->host_start] == '@') start++;
  if (start == r->host_end) return empty_string(r);
  return substring(r, start, r->pathname_start);
}

ada_string ada_get_hostname(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  uint32_t start = r->host_start;
  if (r->host_end > r->host_start && r->buffer[r->host_start] == '@') start++;
  return substring(r, start, r->host_end);
}

ada_string ada_get_port(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  if (r->port == ADA_URL_OMITTED) return empty_string(r);
  return substring(r, r->host_end + 1, r->pathname_start);
}

ada_string ada_get_pathname(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  uint32_t end = r->buffer_length;
  if (r->search_start != ADA_URL_OMITTED)     end = r->search_start;
  else if (r->hash_start != ADA_URL_OMITTED)  end = r->hash_start;
  return substring(r, r->pathname_start, end);
}

ada_string ada_get_search(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  if (r->search_start == ADA_URL_OMITTED) return empty_string(r);
  uint32_t end = (r->hash_start != ADA_URL_OMITTED) ? r->hash_start
                                                     : r->buffer_length;
  if (end <= r->search_start + 1) return empty_string(r);
  return substring(r, r->search_start, end);
}

ada_string ada_get_hash(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return make_string(NULL, 0);
  if (r->hash_start == ADA_URL_OMITTED) return empty_string(r);
  if (r->buffer_length - r->hash_start <= 1) return empty_string(r);
  return substring(r, r->hash_start, r->buffer_length);
}

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

const ada_url_components* ada_get_components(ada_url result) {
  ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return NULL;
  return (const ada_url_components*)&r->protocol_end;
}

/* -------------------------------------------------------------------------- */
/* Predicates (pure C)                                                         */
/* -------------------------------------------------------------------------- */

bool ada_has_credentials(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return (r->username_end > r->protocol_end + 2) ||
         (r->host_start > r->username_end);
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
  return r->host_start > r->username_end;
}

bool ada_has_port(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
  return ada_has_hostname(result) && r->pathname_start != r->host_end;
}

bool ada_has_password(ada_url result) {
  const ada_url_aggregator_t* r = get_url(result);
  if (!r || !r->is_valid) return false;
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
/* Setters (C++ bridge)                                                        */
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
/* Search params (pure C)                                                      */
/* -------------------------------------------------------------------------- */

ada_url_search_params ada_parse_search_params(const char* input,
                                               size_t length) {
  ada_search_params_impl_t* sp =
      (ada_search_params_impl_t*)calloc(1, sizeof(ada_search_params_impl_t));
  if (!sp) return NULL;
  sp_initialize(sp, input, length);
  return (ada_url_search_params)sp;
}

void ada_free_search_params(ada_url_search_params result) {
  ada_search_params_impl_t* sp = (ada_search_params_impl_t*)result;
  if (!sp) return;
  sp_clear(sp);
  free(sp->pairs);
  free(sp);
}

size_t ada_search_params_size(ada_url_search_params result) {
  const ada_search_params_impl_t* sp =
      (const ada_search_params_impl_t*)result;
  return sp ? sp->count : 0;
}

void ada_search_params_sort(ada_url_search_params result) {
  ada_search_params_impl_t* sp = (ada_search_params_impl_t*)result;
  if (!sp || sp->count <= 1) return;
  ada_kv_pair_t* tmp =
      (ada_kv_pair_t*)malloc(sp->count * sizeof(ada_kv_pair_t));
  if (!tmp) return;
  sp_merge_sort(sp->pairs, tmp, 0, sp->count);
  free(tmp);
}

ada_owned_string ada_search_params_to_string(ada_url_search_params result) {
  const ada_search_params_impl_t* sp =
      (const ada_search_params_impl_t*)result;
  ada_owned_string owned;

  if (!sp || sp->count == 0) {
    char* s = (char*)malloc(1);
    if (s) s[0] = '\0';
    owned.data = s; owned.length = 0;
    return owned;
  }

  size_t cap = 64;
  char*  out = (char*)malloc(cap);
  if (!out) { owned.data = NULL; owned.length = 0; return owned; }
  size_t o = 0;

  for (size_t i = 0; i < sp->count; i++) {
    size_t key_enc_len, val_enc_len;
    char*  key_enc = sp_percent_encode(sp->pairs[i].key,
                                        sp->pairs[i].key_len, &key_enc_len);
    char*  val_enc = sp_percent_encode(sp->pairs[i].value,
                                        sp->pairs[i].value_len, &val_enc_len);
    if (!key_enc || !val_enc) {
      free(key_enc); free(val_enc); free(out);
      owned.data = NULL; owned.length = 0; return owned;
    }
    size_t need = (i > 0 ? 1u : 0u) + key_enc_len + 1u + val_enc_len;
    while (o + need + 1 > cap) {
      cap *= 2;
      char* nr = (char*)realloc(out, cap);
      if (!nr) {
        free(out); free(key_enc); free(val_enc);
        owned.data = NULL; owned.length = 0; return owned;
      }
      out = nr;
    }
    if (i > 0) out[o++] = '&';
    memcpy(out + o, key_enc, key_enc_len); o += key_enc_len;
    out[o++] = '=';
    memcpy(out + o, val_enc, val_enc_len); o += val_enc_len;
    free(key_enc); free(val_enc);
  }
  out[o] = '\0';
  owned.data = out; owned.length = o;
  return owned;
}

void ada_search_params_reset(ada_url_search_params result,
                              const char* input, size_t length) {
  ada_search_params_impl_t* sp = (ada_search_params_impl_t*)result;
  if (!sp) return;
  sp_clear(sp);
  sp_initialize(sp, input, length);
}

void ada_search_params_append(ada_url_search_params result,
                               const char* key, size_t key_length,
                               const char* value, size_t value_length) {
  ada_search_params_impl_t* sp = (ada_search_params_impl_t*)result;
  if (!sp) return;
  char* k = (char*)malloc(key_length + 1);
  char* v = (char*)malloc(value_length + 1);
  if (!k || !v) { free(k); free(v); return; }
  memcpy(k, key,   key_length);   k[key_length]   = '\0';
  memcpy(v, value, value_length); v[value_length] = '\0';
  if (!sp_append_raw(sp, k, key_length, v, value_length)) {
    free(k); free(v);
  }
}

void ada_search_params_set(ada_url_search_params result,
                            const char* key, size_t key_length,
                            const char* value, size_t value_length) {
  ada_search_params_impl_t* sp = (ada_search_params_impl_t*)result;
  if (!sp) return;

  size_t first = sp->count;
  for (size_t i = 0; i < sp->count; i++) {
    if (sp->pairs[i].key_len == key_length &&
        memcmp(sp->pairs[i].key, key, key_length) == 0) {
      first = i; break;
    }
  }
  if (first == sp->count) {
    ada_search_params_append(result, key, key_length, value, value_length);
    return;
  }
  char* new_v = (char*)malloc(value_length + 1);
  if (new_v) {
    free(sp->pairs[first].value);
    memcpy(new_v, value, value_length); new_v[value_length] = '\0';
    sp->pairs[first].value     = new_v;
    sp->pairs[first].value_len = value_length;
  }
  size_t write = first + 1;
  for (size_t i = first + 1; i < sp->count; i++) {
    if (sp->pairs[i].key_len == key_length &&
        memcmp(sp->pairs[i].key, key, key_length) == 0) {
      free(sp->pairs[i].key); free(sp->pairs[i].value);
    } else {
      sp->pairs[write++] = sp->pairs[i];
    }
  }
  sp->count = write;
}

void ada_search_params_remove(ada_url_search_params result,
                               const char* key, size_t key_length) {
  ada_search_params_impl_t* sp = (ada_search_params_impl_t*)result;
  if (!sp) return;
  size_t write = 0;
  for (size_t i = 0; i < sp->count; i++) {
    if (sp->pairs[i].key_len == key_length &&
        memcmp(sp->pairs[i].key, key, key_length) == 0) {
      free(sp->pairs[i].key); free(sp->pairs[i].value);
    } else {
      sp->pairs[write++] = sp->pairs[i];
    }
  }
  sp->count = write;
}

void ada_search_params_remove_value(ada_url_search_params result,
                                     const char* key, size_t key_length,
                                     const char* value, size_t value_length) {
  ada_search_params_impl_t* sp = (ada_search_params_impl_t*)result;
  if (!sp) return;
  size_t write = 0;
  for (size_t i = 0; i < sp->count; i++) {
    if (sp->pairs[i].key_len   == key_length &&
        sp->pairs[i].value_len == value_length &&
        memcmp(sp->pairs[i].key,   key,   key_length)   == 0 &&
        memcmp(sp->pairs[i].value, value, value_length) == 0) {
      free(sp->pairs[i].key); free(sp->pairs[i].value);
    } else {
      sp->pairs[write++] = sp->pairs[i];
    }
  }
  sp->count = write;
}

bool ada_search_params_has(ada_url_search_params result,
                            const char* key, size_t key_length) {
  const ada_search_params_impl_t* sp =
      (const ada_search_params_impl_t*)result;
  if (!sp) return false;
  for (size_t i = 0; i < sp->count; i++) {
    if (sp->pairs[i].key_len == key_length &&
        memcmp(sp->pairs[i].key, key, key_length) == 0) return true;
  }
  return false;
}

bool ada_search_params_has_value(ada_url_search_params result,
                                  const char* key, size_t key_length,
                                  const char* value, size_t value_length) {
  const ada_search_params_impl_t* sp =
      (const ada_search_params_impl_t*)result;
  if (!sp) return false;
  for (size_t i = 0; i < sp->count; i++) {
    if (sp->pairs[i].key_len   == key_length &&
        sp->pairs[i].value_len == value_length &&
        memcmp(sp->pairs[i].key,   key,   key_length)   == 0 &&
        memcmp(sp->pairs[i].value, value, value_length) == 0) return true;
  }
  return false;
}

ada_string ada_search_params_get(ada_url_search_params result,
                                  const char* key, size_t key_length) {
  const ada_search_params_impl_t* sp =
      (const ada_search_params_impl_t*)result;
  if (!sp) return make_string(NULL, 0);
  for (size_t i = 0; i < sp->count; i++) {
    if (sp->pairs[i].key_len == key_length &&
        memcmp(sp->pairs[i].key, key, key_length) == 0) {
      return make_string(sp->pairs[i].value, sp->pairs[i].value_len);
    }
  }
  return make_string(NULL, 0);
}

ada_strings ada_search_params_get_all(ada_url_search_params result,
                                       const char* key, size_t key_length) {
  const ada_search_params_impl_t* sp =
      (const ada_search_params_impl_t*)result;
  ada_strings_impl_t* out =
      (ada_strings_impl_t*)calloc(1, sizeof(ada_strings_impl_t));
  if (!out) return NULL;
  if (!sp) return (ada_strings)out;

  size_t count = 0;
  for (size_t i = 0; i < sp->count; i++) {
    if (sp->pairs[i].key_len == key_length &&
        memcmp(sp->pairs[i].key, key, key_length) == 0) count++;
  }
  if (count == 0) return (ada_strings)out;

  out->data    = (char**)malloc(count * sizeof(char*));
  out->lengths = (size_t*)malloc(count * sizeof(size_t));
  if (!out->data || !out->lengths) {
    free(out->data); free(out->lengths); free(out); return NULL;
  }
  size_t idx = 0;
  for (size_t i = 0; i < sp->count && idx < count; i++) {
    if (sp->pairs[i].key_len == key_length &&
        memcmp(sp->pairs[i].key, key, key_length) == 0) {
      char* v = (char*)malloc(sp->pairs[i].value_len + 1);
      if (!v) continue;
      memcpy(v, sp->pairs[i].value, sp->pairs[i].value_len);
      v[sp->pairs[i].value_len] = '\0';
      out->data[idx]    = v;
      out->lengths[idx] = sp->pairs[i].value_len;
      idx++;
    }
  }
  out->count = idx;
  return (ada_strings)out;
}

/* -------------------------------------------------------------------------- */
/* String collection                                                            */
/* -------------------------------------------------------------------------- */

void ada_free_strings(ada_strings result) {
  ada_strings_impl_t* s = (ada_strings_impl_t*)result;
  if (!s) return;
  for (size_t i = 0; i < s->count; i++) free(s->data[i]);
  free(s->data); free(s->lengths); free(s);
}

size_t ada_strings_size(ada_strings result) {
  const ada_strings_impl_t* s = (const ada_strings_impl_t*)result;
  return s ? s->count : 0;
}

ada_string ada_strings_get(ada_strings result, size_t index) {
  const ada_strings_impl_t* s = (const ada_strings_impl_t*)result;
  if (!s || index >= s->count) return make_string(NULL, 0);
  return make_string(s->data[index], s->lengths[index]);
}

/* -------------------------------------------------------------------------- */
/* Iterators                                                                    */
/* -------------------------------------------------------------------------- */

ada_url_search_params_keys_iter ada_search_params_get_keys(
    ada_url_search_params result) {
  ada_search_params_iter_impl_t* it = (ada_search_params_iter_impl_t*)malloc(
      sizeof(ada_search_params_iter_impl_t));
  if (!it) return NULL;
  it->sp = (const ada_search_params_impl_t*)result; it->pos = 0;
  return (ada_url_search_params_keys_iter)it;
}

ada_url_search_params_values_iter ada_search_params_get_values(
    ada_url_search_params result) {
  ada_search_params_iter_impl_t* it = (ada_search_params_iter_impl_t*)malloc(
      sizeof(ada_search_params_iter_impl_t));
  if (!it) return NULL;
  it->sp = (const ada_search_params_impl_t*)result; it->pos = 0;
  return (ada_url_search_params_values_iter)it;
}

ada_url_search_params_entries_iter ada_search_params_get_entries(
    ada_url_search_params result) {
  ada_search_params_iter_impl_t* it = (ada_search_params_iter_impl_t*)malloc(
      sizeof(ada_search_params_iter_impl_t));
  if (!it) return NULL;
  it->sp = (const ada_search_params_impl_t*)result; it->pos = 0;
  return (ada_url_search_params_entries_iter)it;
}

void ada_free_search_params_keys_iter(ada_url_search_params_keys_iter r) {
  free(r);
}
ada_string ada_search_params_keys_iter_next(
    ada_url_search_params_keys_iter result) {
  ada_search_params_iter_impl_t* it = (ada_search_params_iter_impl_t*)result;
  if (!it || it->pos >= it->sp->count) return make_string(NULL, 0);
  const ada_kv_pair_t* p = &it->sp->pairs[it->pos++];
  return make_string(p->key, p->key_len);
}
bool ada_search_params_keys_iter_has_next(
    ada_url_search_params_keys_iter result) {
  const ada_search_params_iter_impl_t* it =
      (const ada_search_params_iter_impl_t*)result;
  return it && it->pos < it->sp->count;
}

void ada_free_search_params_values_iter(
    ada_url_search_params_values_iter r) {
  free(r);
}
ada_string ada_search_params_values_iter_next(
    ada_url_search_params_values_iter result) {
  ada_search_params_iter_impl_t* it = (ada_search_params_iter_impl_t*)result;
  if (!it || it->pos >= it->sp->count) return make_string(NULL, 0);
  const ada_kv_pair_t* p = &it->sp->pairs[it->pos++];
  return make_string(p->value, p->value_len);
}
bool ada_search_params_values_iter_has_next(
    ada_url_search_params_values_iter result) {
  const ada_search_params_iter_impl_t* it =
      (const ada_search_params_iter_impl_t*)result;
  return it && it->pos < it->sp->count;
}

void ada_free_search_params_entries_iter(
    ada_url_search_params_entries_iter r) {
  free(r);
}
ada_string_pair ada_search_params_entries_iter_next(
    ada_url_search_params_entries_iter result) {
  ada_string_pair pair;
  ada_search_params_iter_impl_t* it = (ada_search_params_iter_impl_t*)result;
  if (!it || it->pos >= it->sp->count) {
    pair.key = make_string(NULL, 0); pair.value = make_string(NULL, 0);
    return pair;
  }
  const ada_kv_pair_t* kv = &it->sp->pairs[it->pos++];
  pair.key   = make_string(kv->key,   kv->key_len);
  pair.value = make_string(kv->value, kv->value_len);
  return pair;
}
bool ada_search_params_entries_iter_has_next(
    ada_url_search_params_entries_iter result) {
  const ada_search_params_iter_impl_t* it =
      (const ada_search_params_iter_impl_t*)result;
  return it && it->pos < it->sp->count;
}

/* -------------------------------------------------------------------------- */
/* Version                                                                      */
/* -------------------------------------------------------------------------- */

const char* ada_get_version(void) { return ADA_VERSION; }

ada_version_components ada_get_version_components(void) {
  ada_version_components v;
  v.major    = ADA_VERSION_MAJOR_NUM;
  v.minor    = ADA_VERSION_MINOR_NUM;
  v.revision = ADA_VERSION_REVISION_NUM;
  return v;
}

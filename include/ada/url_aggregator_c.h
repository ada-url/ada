/**
 * @file url_aggregator_c.h
 * @brief C-compatible representation of the ada URL aggregator.
 *
 * Defines the internal C struct used by the C API implementation (ada_c.c)
 * and the C++ bridge (ada_c_bridge.cpp). This header is the single source of
 * truth for the memory layout of the ada_url handle.
 *
 * The design mirrors ada::url_aggregator: a single heap-allocated string
 * buffer holds the serialized URL, and a set of uint32_t offsets describes
 * the boundaries of each component within that buffer.
 */
#ifndef ADA_URL_AGGREGATOR_C_H
#define ADA_URL_AGGREGATOR_C_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---- SIMD capability detection (mirrors ada/common_defs.h for C code) ---- */
#if defined(__SSSE3__)
#  define ADA_C_SSSE3 1
#endif
#if defined(__SSE2__) || defined(__x86_64__) || defined(__x86_64) || \
    (defined(_M_AMD64) || defined(_M_X64) ||                         \
     (defined(_M_IX86_FP) && _M_IX86_FP == 2))
#  define ADA_C_SSE2 1
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
#  define ADA_C_NEON 1
#endif

/* Sentinel: indicates a URL component is absent (same as url_components::omitted). */
#define ADA_URL_OMITTED 0xffffffffu

/**
 * C representation of a parsed URL.
 *
 * Component layout in the buffer:
 *   https://user:pass@example.com:1234/foo/bar?baz#quux
 *         |     |    |          | ^^^^|       |   |
 *         |     |    |          | |   |       |   `----- hash_start
 *         |     |    |          | |   |       `--------- search_start
 *         |     |    |          | |   `----------------- pathname_start
 *         |     |    |          | `--------------------- port (numeric)
 *         |     |    |          `----------------------- host_end
 *         |     |    `---------------------------------- host_start
 *         |     `--------------------------------------- username_end
 *         `--------------------------------------------- protocol_end
 */
typedef struct ada_url_aggregator_t {
  char*    buffer;           /**< Heap-allocated, null-terminated URL string. */
  uint32_t buffer_length;    /**< Length of the URL string (bytes, not including NUL). */
  uint32_t buffer_capacity;  /**< Allocated capacity of buffer (>= buffer_length + 1). */

  /* Component offsets into buffer. */
  uint32_t protocol_end;     /**< Offset past the "scheme:" portion. */
  uint32_t username_end;     /**< Offset past the username. */
  uint32_t host_start;       /**< Offset of first byte of host. */
  uint32_t host_end;         /**< Offset past the host (before port colon). */
  uint32_t port;             /**< Numeric port value, or ADA_URL_OMITTED. */
  uint32_t pathname_start;   /**< Offset of first byte of path. */
  uint32_t search_start;     /**< Offset of '?', or ADA_URL_OMITTED. */
  uint32_t hash_start;       /**< Offset of '#', or ADA_URL_OMITTED. */

  /* Metadata. */
  uint8_t  is_valid;         /**< Non-zero if URL is valid. */
  uint8_t  has_opaque_path;  /**< Non-zero if URL has an opaque path. */
  uint8_t  host_type;        /**< 0=domain, 1=IPv4, 2=IPv6 (ada::url_host_type). */
  uint8_t  scheme_type;      /**< Scheme type (values from ada::scheme::type). */
} ada_url_aggregator_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Convenience: suppress noexcept in C, use it in C++ for safety. */
#ifndef ADA_NOEXCEPT
#  ifdef __cplusplus
#    define ADA_NOEXCEPT noexcept
#  else
#    define ADA_NOEXCEPT
#  endif
#endif

/* ---- Bridge functions implemented in ada_c_bridge.cpp -------------------- */
/* These are called by the pure-C ada_c.c when C++ logic is required.        */

ada_url_aggregator_t* ada_parse_impl(const char* input,
                                     size_t length) ADA_NOEXCEPT;
ada_url_aggregator_t* ada_parse_with_base_impl(const char* input,
                                               size_t input_length,
                                               const char* base,
                                               size_t base_length) ADA_NOEXCEPT;

bool ada_set_href_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) ADA_NOEXCEPT;
bool ada_set_host_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) ADA_NOEXCEPT;
bool ada_set_hostname_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) ADA_NOEXCEPT;
bool ada_set_protocol_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) ADA_NOEXCEPT;
bool ada_set_username_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) ADA_NOEXCEPT;
bool ada_set_password_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) ADA_NOEXCEPT;
bool ada_set_port_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) ADA_NOEXCEPT;
bool ada_set_pathname_impl(ada_url_aggregator_t* url, const char* input,
                           size_t length) ADA_NOEXCEPT;
void ada_set_search_impl(ada_url_aggregator_t* url, const char* input,
                         size_t length) ADA_NOEXCEPT;
void ada_set_hash_impl(ada_url_aggregator_t* url, const char* input,
                       size_t length) ADA_NOEXCEPT;
void ada_clear_port_impl(ada_url_aggregator_t* url) ADA_NOEXCEPT;
void ada_clear_hash_impl(ada_url_aggregator_t* url) ADA_NOEXCEPT;
void ada_clear_search_impl(ada_url_aggregator_t* url) ADA_NOEXCEPT;

/* IDNA bridge. Returns a heap-allocated string; caller must free() it.      */
char* ada_idna_to_unicode_impl(const char* input, size_t length,
                               size_t* out_length) ADA_NOEXCEPT;
char* ada_idna_to_ascii_impl(const char* input, size_t length,
                             size_t* out_length) ADA_NOEXCEPT;

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* ADA_URL_AGGREGATOR_C_H */

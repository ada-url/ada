/**
 * @file common_defs.h
 * @brief Common definitions for cross-platform compiler support.
 */
#ifndef ADA_COMMON_DEFS_H
#define ADA_COMMON_DEFS_H

#ifdef _MSC_VER
#define ADA_VISUAL_STUDIO 1
/**
 * We want to differentiate carefully between
 * clang under visual studio and regular visual
 * studio.
 */
#ifdef __clang__
// clang under visual studio
#define ADA_CLANG_VISUAL_STUDIO 1
#else
// just regular visual studio (best guess)
#define ADA_REGULAR_VISUAL_STUDIO 1
#endif // __clang__
#endif // _MSC_VER


#if defined(__GNUC__)
  // Marks a block with a name so that MCA analysis can see it.
  #define ADA_BEGIN_DEBUG_BLOCK(name) __asm volatile("# LLVM-MCA-BEGIN " #name);
  #define ADA_END_DEBUG_BLOCK(name) __asm volatile("# LLVM-MCA-END " #name);
  #define ADA_DEBUG_BLOCK(name, block) BEGIN_DEBUG_BLOCK(name); block; END_DEBUG_BLOCK(name);
#else
  #define ADA_BEGIN_DEBUG_BLOCK(name)
  #define ADA_END_DEBUG_BLOCK(name)
  #define ADA_DEBUG_BLOCK(name, block)
#endif

// Align to N-byte boundary
#define ADA_ROUNDUP_N(a, n) (((a) + ((n)-1)) & ~((n)-1))
#define ADA_ROUNDDOWN_N(a, n) ((a) & ~((n)-1))

#define ADA_ISALIGNED_N(ptr, n) (((uintptr_t)(ptr) & ((n)-1)) == 0)

#if defined(ADA_REGULAR_VISUAL_STUDIO)

  #define ada_really_inline __forceinline
  #define ada_never_inline __declspec(noinline)

  #define ada_unused
  #define ada_warn_unused

  #ifndef ada_likely
  #define ada_likely(x) x
  #endif
  #ifndef ada_unlikely
  #define ada_unlikely(x) x
  #endif

  #define ADA_PUSH_DISABLE_WARNINGS __pragma(warning( push ))
  #define ADA_PUSH_DISABLE_ALL_WARNINGS __pragma(warning( push, 0 ))
  #define ADA_DISABLE_VS_WARNING(WARNING_NUMBER) __pragma(warning( disable : WARNING_NUMBER ))
  // Get rid of Intellisense-only warnings (Code Analysis)
  // Though __has_include is C++17, it is supported in Visual Studio 2017 or better (_MSC_VER>=1910).
  #ifdef __has_include
  #if __has_include(<CppCoreCheck\Warnings.h>)
  #include <CppCoreCheck\Warnings.h>
  #define ADA_DISABLE_UNDESIRED_WARNINGS ADA_DISABLE_VS_WARNING(ALL_CPPCORECHECK_WARNINGS)
  #endif
  #endif

  #ifndef ADA_DISABLE_UNDESIRED_WARNINGS
  #define ADA_DISABLE_UNDESIRED_WARNINGS
  #endif

  #define ADA_DISABLE_DEPRECATED_WARNING ADA_DISABLE_VS_WARNING(4996)
  #define ADA_DISABLE_STRICT_OVERFLOW_WARNING
  #define ADA_POP_DISABLE_WARNINGS __pragma(warning( pop ))

#else // ADA_REGULAR_VISUAL_STUDIO

  #define ada_really_inline inline __attribute__((always_inline))
  #define ada_never_inline inline __attribute__((noinline))

  #define ada_unused __attribute__((unused))
  #define ada_warn_unused __attribute__((warn_unused_result))

  #ifndef ada_likely
  #define ada_likely(x) __builtin_expect(!!(x), 1)
  #endif
  #ifndef ada_unlikely
  #define ada_unlikely(x) __builtin_expect(!!(x), 0)
  #endif

  #define ADA_PUSH_DISABLE_WARNINGS _Pragma("GCC diagnostic push")
  // gcc doesn't seem to disable all warnings with all and extra, add warnings here as necessary
  #define ADA_PUSH_DISABLE_ALL_WARNINGS ADA_PUSH_DISABLE_WARNINGS \
    ADA_DISABLE_GCC_WARNING(-Weffc++) \
    ADA_DISABLE_GCC_WARNING(-Wall) \
    ADA_DISABLE_GCC_WARNING(-Wconversion) \
    ADA_DISABLE_GCC_WARNING(-Wextra) \
    ADA_DISABLE_GCC_WARNING(-Wattributes) \
    ADA_DISABLE_GCC_WARNING(-Wimplicit-fallthrough) \
    ADA_DISABLE_GCC_WARNING(-Wnon-virtual-dtor) \
    ADA_DISABLE_GCC_WARNING(-Wreturn-type) \
    ADA_DISABLE_GCC_WARNING(-Wshadow) \
    ADA_DISABLE_GCC_WARNING(-Wunused-parameter) \
    ADA_DISABLE_GCC_WARNING(-Wunused-variable)
  #define ADA_PRAGMA(P) _Pragma(#P)
  #define ADA_DISABLE_GCC_WARNING(WARNING) ADA_PRAGMA(GCC diagnostic ignored #WARNING)
  #if defined(ADA_CLANG_VISUAL_STUDIO)
  #define ADA_DISABLE_UNDESIRED_WARNINGS ADA_DISABLE_GCC_WARNING(-Wmicrosoft-include)
  #else
  #define ADA_DISABLE_UNDESIRED_WARNINGS
  #endif
  #define ADA_DISABLE_DEPRECATED_WARNING ADA_DISABLE_GCC_WARNING(-Wdeprecated-declarations)
  #define ADA_DISABLE_STRICT_OVERFLOW_WARNING ADA_DISABLE_GCC_WARNING(-Wstrict-overflow)
  #define ADA_POP_DISABLE_WARNINGS _Pragma("GCC diagnostic pop")

#endif // MSC_VER

#if defined(ADA_VISUAL_STUDIO)
    /**
     * It does not matter here whether you are using
     * the regular visual studio or clang under visual
     * studio.
     */
    #if ADA_USING_LIBRARY
    #define ADA_DLLIMPORTEXPORT __declspec(dllimport)
    #else
    #define ADA_DLLIMPORTEXPORT __declspec(dllexport)
    #endif
#else
    #define ADA_DLLIMPORTEXPORT
#endif

/// If EXPR is an error, returns it.
#define ADA_TRY(EXPR) { auto _err = (EXPR); if (_err) { return _err; } }

// __has_cpp_attribute is part of C++20
#if !defined(__has_cpp_attribute)
#define __has_cpp_attribute(x) 0
#endif


#if __has_cpp_attribute(gnu::noinline)
#define ADA_ATTRIBUTE_NOINLINE [[gnu::noinline]]
#else
#define ADA_ATTRIBUTE_NOINLINE
#endif

namespace ada {
  [[noreturn]] inline void unreachable() {
#ifdef __GNUC__
    __builtin_unreachable();
#elif defined(_MSC_VER)
    __assume(false);
#else
#endif
  }
}



#if defined(__GNUC__) && !defined(__clang__)
#if __GNUC__ <= 8
#define ADA_OLD_GCC 1
#endif //  __GNUC__ <= 8
#endif // defined(__GNUC__) && !defined(__clang__)

#if ADA_OLD_GCC
#define ada_constexpr
#else
#define ada_constexpr constexpr
#endif

 #if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
 #define ADA_IS_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
 #elif defined(_WIN32)
 #define ADA_IS_BIG_ENDIAN 0
 #else
 #if defined(__APPLE__) || defined(__FreeBSD__) // defined __BYTE_ORDER__ && defined __ORDER_BIG_ENDIAN__
 #include <machine/endian.h>
 #elif defined(sun) || defined(__sun) // defined(__APPLE__) || defined(__FreeBSD__)
 #include <sys/byteorder.h>
 #else  // defined(__APPLE__) || defined(__FreeBSD__)

 #ifdef __has_include
 #if __has_include(<endian.h>)
 #include <endian.h>
 #endif //__has_include(<endian.h>)
 #endif //__has_include

 #endif // defined(__APPLE__) || defined(__FreeBSD__)


 #ifndef !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__)
 #define ADA_IS_BIG_ENDIAN 0
 #endif

 #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 #define ADA_IS_BIG_ENDIAN 0
 #else // __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 #define ADA_IS_BIG_ENDIAN 1
 #endif // __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

 #endif // defined __BYTE_ORDER__ && defined __ORDER_BIG_ENDIAN__


#ifndef ADA_HAS_ICU
#if __has_include(<unicode/uidna.h>)
#define ADA_HAS_ICU 1
#else
#define ADA_HAS_ICU 0
#endif // __has_include(<unicode/uidna.h>)
#endif // ADA_HAS_ICU

#if ADA_HAS_ICU
#include <unicode/utypes.h>
#include <unicode/uidna.h>
#include <unicode/utf8.h>
#endif // ADA_HAS_ICU

#define ADA_WINDOWS_TO_ASCII_FALLBACK 0 // we never use anything but ICU. No fallback.

#endif // ADA_COMMON_DEFS_H

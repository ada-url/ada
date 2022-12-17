#ifndef ADA_COMMON_DEFS_H
#define ADA_COMMON_DEFS_H

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

#endif // ADA_COMMON_DEFS_H

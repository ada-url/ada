#ifndef ADA_SIMD_X86_64_V2_H
#define ADA_SIMD_X86_64_V2_H

#include "ada/common_defs.h"

#include <string_view>

// Wide x86-64-v2 kernels live in simd_x86_64_v2.cpp so the unity ada.cpp
// translation unit stays free of target() functions. gcc will not
// always_inline a targeted SSSE3 function into an SSE2 caller, and keeping
// those kernels in ada.cpp also blows the setter inlining budget (CodSpeed
// SetHash).
namespace ada::simd {

#if ADA_SSSE3
// Precondition: user_input.size() >= 16.
bool has_tabs_or_newline_wide(std::string_view user_input) noexcept;
// Precondition: view.size() - location >= 16.
size_t find_next_host_delimiter_special_wide(std::string_view view,
                                             size_t location) noexcept;
size_t find_next_host_delimiter_wide(std::string_view view,
                                     size_t location) noexcept;
// Precondition: view.size() >= 16.
size_t find_authority_delimiter_special_wide(std::string_view view) noexcept;
size_t find_authority_delimiter_wide(std::string_view view) noexcept;
#endif

}  // namespace ada::simd

#endif  // ADA_SIMD_X86_64_V2_H

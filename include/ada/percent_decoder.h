#pragma once

#include <iostream>
#include <array>
#include <vector>
#include <optional>
#include <memory>
#include <cstring>
#include <charconv>

#ifdef __x86_64__
#include <immintrin.h>
#endif

#ifdef ENABLE_VECTORSCAN
#include <hs.h>
#include <fast_float/fast_float.h>
#endif

namespace percent_decoder {

constexpr bool is_valid(int32_t mask) {
    int32_t last_percent_index = -3;
    int32_t remaining = mask;
    for (int32_t i = 0; i < 16; ++i) {
        if (remaining & 1) {
            if (i - last_percent_index < 3) {
                return false;
            }
            last_percent_index = i;
        }
        remaining >>= 1;
    }
    return true;
}

constexpr size_t calculate_n_valid_vectors() {
    size_t ret = 0;
    for (int i = 0; i < 16384; ++i) {
        if (is_valid(i)) {
            ++ret;
        }
    }
    return ret;
}

constexpr size_t n_valid_vectors = calculate_n_valid_vectors();

constexpr std::array<uint16_t, 16384> calculate_vector_indexes() {
    std::array<uint16_t, 16384> ret{};
    int n = 0;
    for (int i = 0; i < 16384; ++i) {
        ret[i] = is_valid(i) ? n++ : -1;
    }
    return ret;
}

constexpr auto vector_indexes = calculate_vector_indexes();

constexpr std::array<std::byte, n_valid_vectors*16> calculate_shuffle_vectors() {
    std::array<std::byte, n_valid_vectors*16> ret{};
    int n = 0;
    for (int i = 0; i < 16384; ++i) {
        if (is_valid(i)) {
            int32_t remaining = i;
            int skip = 0;
            for (int j = 0; j < 16; ++j) {
                ret[n * 16 + j] = static_cast<std::byte>(j + skip + (remaining & 1));
                if (remaining & 1) {
                    remaining >>= 3;
                    skip += 2;
                } else {
                    remaining >>= 1;
                }
            }
            ++n;
        }
    }
    return ret;
}

alignas(16) constexpr auto shuffle_vectors_array = calculate_shuffle_vectors();


constexpr bool is_ascii_hex_digit(const char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
           (c >= 'a' && c <= 'f');
}

unsigned constexpr convert_hex_to_binary(const char c) noexcept {
    // this code can be optimized.
    if (c <= '9') {
        return c - '0';
    }
    char del = c >= 'a' ? 'a' : 'A';
    return 10 + (c - del);
}

size_t percent_decode_slow(char const* in, size_t len, char* out) {
    const char* end = in + len;
    char const* init_out = out;
    // Optimization opportunity: if the following code gets
    // called often, it can be optimized quite a bit.
    while (in < end) {
        const char ch = in[0];
        size_t remaining = end - in - 1;
        if (ch == '+') {
            *out = ' ';
            ++out;
            ++in;
        } else if (ch != '%' || remaining < 2 ||
                   (  // ch == '%' && // It is unnecessary to check that ch == '%'.
                       (!is_ascii_hex_digit(in[1]) ||
                        !is_ascii_hex_digit(in[2])))) {
            *out = ch;
            ++out;
            ++in;
        } else {
            unsigned a = convert_hex_to_binary(in[1]);
            unsigned b = convert_hex_to_binary(in[2]);
            char c = static_cast<char>(a * 16 + b);
            *out = c;
            ++out;
            in += 3;
        }
    }
    return out - init_out;
}

#if defined(__x86_64__)

__m128i const* const shuffle_vectors = reinterpret_cast<__m128i const*>(shuffle_vectors_array.data());

void print_m128i(__m128i i) {
    //    char* c = reinterpret_cast<char*>(&i);
    //    printf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);
}

[[gnu::target("sse,sse2,sse3,ssse3,sse4,sse4.1,sse4.2,avx,avx2,popcnt")]]
static uint64_t percent_decode_16(char const* in, char* out,
                                  uint64_t mask, uint64_t* chars_read) {
    __m128i byte_plus = _mm_set1_epi8('+');
    __m128i byte_space = _mm_set1_epi8(' ');
    __m128i byte_percent = _mm_set1_epi8('%');

    __m128i chunk = _mm_lddqu_si128(reinterpret_cast<__m128i const*>(in));
    print_m128i(chunk);

    // Replace plus (+) with space
    __m128i pluses = _mm_cmpeq_epi8(chunk, byte_plus);
    chunk = _mm_blendv_epi8(chunk, byte_space, pluses);
    print_m128i(chunk);

    size_t shift_next = ((mask >> 15) & 1) | ((mask >> 13) & 2);
    if (!(mask & 0x3FFF)) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), chunk);
        *chars_read = 16 - shift_next;
        return *chars_read;
    }

    // Locate percent symbol
    __m128i found = _mm_cmpeq_epi8(chunk, byte_percent);

    // Decode hex

    // compute mask of which characters are numbers and convert number characters to 0-9
    __m128i numbers = _mm_sub_epi8(chunk, _mm_set1_epi8('0' + 128));
    __m128i number_mask = _mm_cmplt_epi8(numbers, _mm_set1_epi8(-128 + 10));
    __m128i binary_numbers = _mm_sub_epi8(chunk, _mm_set1_epi8('0'));

    // set the 6th bit (0x20) to convert uppercase characters to lowercase
    __m128i lower_mask = _mm_set1_epi8(0b00100000);
    __m128i binary_letters = _mm_or_si128(chunk, lower_mask);

    // mask out any percent chars that aren't followed by two hex chars
    __m128i letters = _mm_sub_epi8(binary_letters, _mm_set1_epi8('a' + 128));
    __m128i letter_mask = _mm_cmplt_epi8(letters, _mm_set1_epi8(-128 + 6));
    __m128i hex_chars = _mm_or_si128(number_mask, letter_mask);
    __m128i valid_mask = _mm_and_si128(found, _mm_srli_si128(hex_chars, 1));
    valid_mask = _mm_and_si128(valid_mask, _mm_srli_si128(hex_chars, 2));
    __m128i mask1 = _mm_slli_si128(valid_mask, 1);
    uint32_t found_mask = _mm_movemask_epi8(valid_mask);

    // convert lowercase letter characters to [10-15]
    binary_letters = _mm_sub_epi8(binary_letters, _mm_set1_epi8('a' - 10));

    // Merge first hex digit transforms
    __m128i first_and_second = _mm_blendv_epi8(binary_letters, binary_numbers, number_mask);
    first_and_second = _mm_and_si128(first_and_second, _mm_set1_epi8(0xF));
    print_m128i(first_and_second);

    __m128i first1 = _mm_slli_epi16(first_and_second, 4);

    // Second hex digit
    __m128i second1 = _mm_srli_si128(first_and_second, 1);

    // Merge hex digits into place and position after the percent
    __m128i hex = _mm_or_si128(first1, second1);
    print_m128i(hex);

    // Squash hex and original data together with mask
    hex = _mm_blendv_epi8(chunk, hex, mask1);
    print_m128i(hex);

    uint16_t vector_index = vector_indexes[found_mask];
    __m128i shuffle_vector = shuffle_vectors[vector_index];

    hex = _mm_shuffle_epi8(hex, shuffle_vector);
    print_m128i(hex);

    // Copy to dst
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), hex);
    uint32_t num_percent = __builtin_popcount(found_mask);
    uint32_t num_junk = 2 * num_percent;
    *chars_read = 16 - shift_next - num_junk;
    return 16 - shift_next;
}

struct AVX2 {
    [[gnu::target("sse,sse2,sse3,ssse3,sse4,sse4.1,sse4.2,avx,avx2,popcnt")]]
    static size_t percent_decode(const char *in, size_t inputsize, char *out) {
        size_t consumed = 0; // number of bytes read
        char *initout = out;

        uint64_t sig = 0;

        __m256i byte_percent_256 = _mm256_set1_epi8('%');
        __m128i byte_percent = _mm_set1_epi8('%');

        size_t availablebytes = 0;
        if (96 < inputsize) {
            size_t scanned = 0;

            __m256i low = _mm256_loadu_si256((__m256i *) (in + scanned));
            __m256i found1 = _mm256_cmpeq_epi8(low, byte_percent_256);
            uint32_t lowSig = _mm256_movemask_epi8(found1);

            // excess verbosity to avoid problems with sign extension on conversions
            // better to think about what's happening and make it clearer
            __m128i high = _mm_loadu_si128((__m128i *) (in + scanned + 32));
            __m128i found3 = _mm_cmpeq_epi8(high, byte_percent);
            uint32_t highSig = _mm_movemask_epi8(found3);
            uint64_t nextSig = highSig;
            nextSig <<= 32;
            nextSig |= lowSig;
            scanned += 48;

            do {
                uint64_t thisSig = nextSig;

                low = _mm256_loadu_si256((__m256i *) (in + scanned));
                found1 = _mm256_cmpeq_epi8(low, byte_percent_256);
                lowSig = _mm256_movemask_epi8(found1);

                high = _mm_loadu_si128((__m128i *) (in + scanned + 32));
                found3 = _mm_cmpeq_epi8(high, byte_percent);
                highSig = _mm_movemask_epi8(found3);
                nextSig = highSig;
                nextSig <<= 32;
                nextSig |= lowSig;

                uint64_t remaining = scanned - (consumed + 48);
                sig = (thisSig << remaining) | sig;

                uint64_t reload = scanned - 16;
                scanned += 48;

                //            size_t prefetch = consumed;
                //            uint64_t prefetch_sig = sig;
                //            while (prefetch < reload) {
                //                uint32_t found_mask = prefetch_sig & 0x3FFF;
                //                _mm_prefetch(&vector_indexes[found_mask], _MM_HINT_NTA);
                //                size_t shift_next = ((prefetch_sig >> 15) & 1) | ((prefetch_sig >> 13) & 2);
                //                uint64_t bytes = 16 - shift_next;
                //                prefetch_sig >>= bytes;
                //                prefetch += bytes;
                //            }

                // need to reload when less than 16 scanned bytes remain in sig
                while (consumed < reload) {
                    uint64_t chars_read;
                    uint64_t bytes = percent_decode_16(in + consumed,
                                                       out, sig, &chars_read);
                    sig >>= bytes;

                    // seems like this might force the compiler to prioritize shifting sig >>= bytes
                    if (sig == 0xFFFFFFFFFFFFFFFF)
                      return 0; // fake check to force earliest evaluation

                    consumed += bytes;
                    out += chars_read;
                }
            } while (scanned + 112 < inputsize);  // 112 == 48 + 48 ahead for scanning + up to 16 remaining in sig
            sig = (nextSig << (scanned - consumed - 48)) | sig;
            availablebytes = scanned - consumed;
        }
        while (true) {
            if (availablebytes < 16) {
                if (availablebytes + consumed + 31 < inputsize) {
                    uint64_t newsigavx = (uint32_t) _mm256_movemask_epi8(_mm256_cmpeq_epi8(
                        _mm256_loadu_si256((__m256i *) (in + availablebytes + consumed)),
                        byte_percent_256));
                    sig |= (newsigavx << availablebytes);
                    availablebytes += 32;
                } else if (availablebytes + consumed + 15 < inputsize) {
                    int newsig = _mm_movemask_epi8(_mm_cmpeq_epi8(
                        _mm_lddqu_si128(
                            (const __m128i *) (in + availablebytes
                                                  + consumed)), byte_percent));
                    sig |= newsig << availablebytes;
                    availablebytes += 16;
                } else {
                    break;
                }
            }
            uint64_t chars_read;
            uint64_t bytes = percent_decode_16(in + consumed, out,
                                               sig, &chars_read);
            consumed += bytes;
            availablebytes -= bytes;
            sig >>= bytes;
            out += chars_read;
        }
        if (consumed < inputsize) {
            out += percent_decode_slow(in + consumed, inputsize - consumed, out);
        }
        return out - initout;
    }
};

[[gnu::target("avx512f,avx512bw,avx512vbmi,avx512vbmi2")]] void print_m512i(__m512i m) {
//    unsigned char* c = reinterpret_cast<unsigned char*>(&m);
//    for (int i = 0; i < 64; ++i) {
//        if (c[i] < 32 || c[i] > 126) {
//            printf(" 0x%02x ", c[i]);
//        } else {
//            printf("%c", c[i]);
//        }
//    }
//    printf("\n");
}
struct AVX512 {
    [[gnu::target("avx512f,avx512bw,avx512vbmi,avx512vbmi2")]] static size_t
    percent_decode(char const *in, size_t inputsize, char *out) {
        const __m512i byte_plus = _mm512_set1_epi8('+');
        const __m512i byte_percent = _mm512_set1_epi8('%');

        char const *end = in + inputsize;
        char *const init_out = out;
        while (in < end) {
            size_t valid_bytes = std::min(static_cast<size_t>(end - in), 64ul);
            uint64_t load_mask = ~0ull >> (64 - valid_bytes);
            __m512i chunk = _mm512_maskz_loadu_epi8(load_mask, in);

            // Replace plus (+) with space
            uint64_t plus_mask = _mm512_cmpeq_epu8_mask(chunk, byte_plus);
            if (plus_mask) {
                const __m512i byte_space = _mm512_set1_epi8(' ');
                chunk = _mm512_mask_blend_epi8(plus_mask, chunk, byte_space);
            }
            print_m512i(chunk);

            // Locate percent symbol
            uint64_t mask = _mm512_cmpeq_epu8_mask(chunk, byte_percent);

            if (!mask) {
                _mm512_mask_storeu_epi8(out, load_mask, chunk);
                in += valid_bytes;
                out += valid_bytes;
                continue;
            }

            uint64_t found_mask = mask & 0x3FFFFFFFFFFFFFFFull;
            size_t shift_next = ((mask >> 63) & 1) | ((mask >> 61) & 2);

            if (!found_mask) {
                size_t output_bytes = valid_bytes - shift_next;
                uint64_t store_mask = load_mask >> shift_next;
                _mm512_mask_storeu_epi8(out, store_mask, chunk);
                in += output_bytes;
                out += output_bytes;
                continue;
            }

            // ascii to hex conversion can be done in two instructions as
            // follows, but it seems a tiny bit slower on my benchmarks. this
            // will likely change in the future if _mm512_permutexvar_epi8
            // becomes faster.
//            const __m512i ascii_to_hex = _mm512_set_epi8(
//                0,  0,  0,  0,  0,  0,  0,  0,
//                0,  0,  0,  0,  0,  0,  0,  0,
//                0,  0,  0,  0,  0,  0,  0,  0,
//                0,  0,  0,  0,  0,  0,  0,  0,
//                0,  0,  0,  0,  0,  0,  9,  8,
//                7,  6,  5,  4,  3,  2,  1,  0,
//                0,  0,  0,  0,  0,  0,  0,  0,
//                0, 15, 14, 13, 12, 11, 10,  0);
//
//            __m512i first_and_second = _mm512_and_si512(chunk, _mm512_set1_epi8(0x1F));
//            first_and_second = _mm512_permutexvar_epi8(first_and_second, ascii_to_hex);

            // Number hex
            __m512i binary_numbers = _mm512_sub_epi8(chunk, _mm512_set1_epi8('0'));
            uint64_t number_mask = _mm512_cmplt_epu8_mask(binary_numbers, _mm512_set1_epi8(10));
            print_m512i(binary_numbers);

            // set the 6th bit (0x20) to convert uppercase characters to lowercase
            __m512i uppercase_mask = _mm512_set1_epi8(0b00100000);
            __m512i binary_letters = _mm512_or_si512(chunk, uppercase_mask);

            //this is just for validation
            __m512i letters = _mm512_sub_epi8(binary_letters, _mm512_set1_epi8('a'));
            uint64_t letter_mask = _mm512_cmplt_epu8_mask(letters, _mm512_set1_epi8(6));
            uint64_t hex_chars = number_mask | letter_mask;
            uint64_t valid_mask = (((hex_chars >> 1) & hex_chars) >> 1) & mask;

            // lowercase hex
            binary_letters = _mm512_sub_epi8(binary_letters, _mm512_set1_epi8('a' - 10));
            print_m512i(binary_letters);

            // Merge first hex digit transforms
            __m512i first_and_second = _mm512_mask_blend_epi8(number_mask, binary_letters, binary_numbers);
            first_and_second = _mm512_and_si512(first_and_second, _mm512_set1_epi8(0xF));
            print_m512i(first_and_second);

            const __m512i srli_1_shuffle_vector = _mm512_set_epi64(
                    0xFF3F3E3D3C3B3A39ull,
                    0x3837363534333231ull,
                    0x302F2E2D2C2B2A29ull,
                    0x2827262524232221ull,
                    0x201F1E1D1C1B1A19ull,
                    0x1817161514131211ull,
                    0x100F0E0D0C0B0A09ull,
                    0x0807060504030201ull);

            __m512i first1 = _mm512_slli_epi16(first_and_second, 4);
            print_m512i(first1);

            // Second hex digit
            __m512i second1 = _mm512_permutexvar_epi8(srli_1_shuffle_vector, first_and_second);
            print_m512i(second1);

            // Merge hex digits into place and position after the percent
            __m512i hex = _mm512_or_si512(first1, second1);
            print_m512i(hex);

            // Squash hex and original data together with mask
            hex = _mm512_mask_blend_epi8(valid_mask << 1, chunk, hex);
            print_m512i(hex);

            // Copy to dst
            uint64_t keep_bytes = ~(valid_mask | (valid_mask << 2));
            uint64_t store_mask = load_mask >> shift_next;
            _mm512_mask_compressstoreu_epi8(out, store_mask & keep_bytes, hex);

            uint32_t num_percent = __builtin_popcountll(valid_mask & 0x3FFFFFFFFFFFFFFFull);
            uint32_t num_junk = 2 * num_percent;
            size_t input_bytes_consumed = valid_bytes - shift_next;
            size_t output_bytes = input_bytes_consumed - num_junk;
            in += input_bytes_consumed;
            out += output_bytes;
        }
        return out - init_out;
    }
};
#endif

auto find_best_percent_decode() {
#ifdef __x86_64__
    __builtin_cpu_init();
    if (
        __builtin_cpu_supports("avx512f") &&
        __builtin_cpu_supports("avx512bw") &&
        __builtin_cpu_supports("avx512vbmi") &&
        __builtin_cpu_supports("avx512vbmi2")
    ) {
        return AVX512::percent_decode;
    } else if (__builtin_cpu_supports("avx2")) {
        return AVX2::percent_decode;
    }
#endif
    return percent_decode_slow;
}

const auto percent_decode = find_best_percent_decode();

#ifdef ENABLE_VECTORSCAN

struct ScratchSpace {
    std::unique_ptr<hs_scratch_t, hs_error_t(*)(hs_scratch_t*)> scratch;
    std::vector<int32_t> string_value_lengths;
    std::vector<int64_t> long_values;
    std::vector<double> double_values;
    std::string input_buffer{};
    std::string percent_decode_buffer{};
    std::u16string string_value_data{};

    ScratchSpace(hs_scratch_t* scratch, size_t num_string_params, size_t num_long_params, size_t num_double_params) : scratch(scratch, hs_free_scratch), string_value_lengths(num_string_params, -1), long_values(num_long_params, 0), double_values(num_double_params, NAN) {}
};

struct Projector {
    std::unique_ptr<hs_database_t, hs_error_t(*)(hs_database_t*)> db;
    size_t num_string_params;
    size_t num_long_params;
    size_t num_double_params;

    Projector(hs_database_t* db, size_t num_string_params, size_t num_long_params, size_t num_double_params) :
            db(db, hs_free_database),
            num_string_params(num_string_params),
            num_long_params(num_long_params),
            num_double_params(num_double_params) {}

    template <typename S, typename L, typename D>
    struct MatchContext {
        Projector const& db;
        S& string_callback;
        L& long_callback;
        D& double_callback;
        std::string& out;
        char const* next_start;
        char const* const end;
        bool matched = true;

        MatchContext(Projector const& db, S& string_callback, L& long_callback, D& double_callback, std::string& out, std::string_view input) :
                db(db),
                string_callback(string_callback),
                long_callback(long_callback),
                double_callback(double_callback),
                out(out),
                next_start(input.data()),
                end(input.data() + input.size()) {}
    };

    [[nodiscard]] std::unique_ptr<ScratchSpace> allocate_scratch() const {
        hs_scratch_t* raw_scratch = nullptr;
        auto err2 = hs_alloc_scratch(db.get(), &raw_scratch);
        if (err2 != HS_SUCCESS) {
            std::terminate();
        }
        return std::make_unique<ScratchSpace>(raw_scratch, num_string_params, num_long_params, num_double_params);
    }

    template <typename Impl, typename S, typename L, typename D>
    hs_error_t parse_params(std::string_view input, ScratchSpace& scratch, S&& string_callback, L&& long_callback, D&& double_callback) const {
        auto match_handler = [](unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context) -> int {
            MatchContext<S, L, D>& mc = *static_cast<MatchContext<S, L, D>*>(context);
            char const* value_start = mc.next_start + to;
            mc.next_start = static_cast<char const*>(memchr(value_start, '&', mc.end - value_start));
            if (mc.next_start == nullptr) {
                return 1;
            }
            mc.matched = true;
            size_t input_size = mc.next_start - value_start;
            if (mc.out.size() < input_size) {
                mc.out.resize(std::max(input_size, mc.out.size() * 2));
            }
            size_t size = Impl::percent_decode(value_start, mc.out.data(), input_size);
            if (id < mc.db.num_string_params) {
                mc.string_callback(std::as_const(id), std::string_view(mc.out.data(), size));
                return 1;
            }
            id -= mc.db.num_string_params;
            if (id < mc.db.num_long_params) {
                int64_t value;
                std::from_chars_result res = std::from_chars(mc.out.data(), mc.out.data() + size, value);
                if (res.ec == std::errc()) {
                    mc.long_callback(std::as_const(id), std::as_const(value));
                } else {
                    std::cerr << "Could not parse " << std::string_view(mc.out.data(), size) << " as int64_t!" << std::endl;
                }
                return 1;
            }
            id -= mc.db.num_long_params;
            double value;
            fast_float::from_chars_result res = fast_float::from_chars(mc.out.data(), mc.out.data() + size, value);
            if (res.ec == std::errc()) {
                mc.double_callback(std::as_const(id), std::as_const(value));
            } else {
                std::cerr << "Could not parse " << std::string_view(mc.out.data(), size) << " as double!" << std::endl;
            }
            return 1;
        };
        MatchContext<S, L, D> context(*this, string_callback, long_callback, double_callback, scratch.percent_decode_buffer, input);
        while (context.matched) {
            context.matched = false;
            hs_error_t err = hs_scan(db.get(), context.next_start, context.end - context.next_start, 0, scratch.scratch.get(), match_handler, (void*) &context);
            if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
                return err;
            }
        }
        return HS_SUCCESS;
    }
};

template<typename It1>
static void add_expressions(It1 begin, size_t n, std::vector<std::string>& expressions,
                            std::vector<const char *>& c_strings, std::vector<unsigned int>& ids, size_t& param_index) {
    for (unsigned int i = 0; i < n; ++i) {
        std::string_view sv(*begin);
        expressions[param_index].reserve(7 + sv.size());
        expressions[param_index] += "(^|&)";
        expressions[param_index] += sv;
        expressions[param_index] += '=';
        c_strings[param_index] = expressions[param_index].c_str();
        ids[param_index] = param_index;
        ++begin;
        ++param_index;
    }
}

template <typename It1, typename It2, typename It3>
[[nodiscard]] static std::optional<std::unique_ptr<Projector>> compile_param_database(
        It1 begin_string_params, size_t num_string_params,
        It2 begin_long_params, size_t num_long_params,
        It3 begin_double_params, size_t num_double_params
) {
    size_t num_params = num_string_params + num_long_params + num_double_params;
    std::vector<std::string> expressions(num_params);
    std::vector<char const*> c_strings(num_params);
    std::vector<unsigned int> ids(num_params);
    size_t param_index = 0;
    add_expressions(begin_string_params, num_string_params, expressions, c_strings, ids, param_index);
    add_expressions(begin_long_params, num_long_params, expressions, c_strings, ids, param_index);
    add_expressions(begin_double_params, num_double_params, expressions, c_strings, ids, param_index);
    hs_database_t* raw_db = nullptr;
    hs_compile_error_t* compile_error = nullptr;
    if (HS_SUCCESS != hs_compile_multi(c_strings.data(), nullptr, ids.data(), num_params, HS_MODE_BLOCK, nullptr, &raw_db, &compile_error)) {
        fprintf(stderr, "%s %d\n", compile_error->message, compile_error->expression);
        hs_free_compile_error(compile_error);
        return std::nullopt;
    }
    return std::make_unique<Projector>(raw_db, num_string_params, num_long_params, num_double_params);
}

template <typename T1, typename T2, typename T3>
static std::optional<std::unique_ptr<Projector>> compile_param_database(T1 const& string_params, T2 const& long_params, T3 const& double_params) {
    return compile_param_database(
            string_params.begin(), string_params.size(),
            long_params.begin(), long_params.size(),
            double_params.begin(), double_params.size());
}

#endif

template <typename Impl, typename F>
static void parse_all_params(std::string_view input, F&& callback, std::string& buffer) {
    char const* position = input.data();
    char const* end = input.data() + input.size();
    while (position < end) {
        char const* param_name_end = static_cast<char const*>(memchr(position, '=', end - position));
        if (param_name_end == nullptr ) {
            break;
        }
        char const* value_start = param_name_end + 1;
        char const* value_end = static_cast<char const*>(memchr(value_start, '&', end - value_start));
        if (value_end == nullptr) {
            break;
        }
        size_t input_size = value_end - value_start;
        if (buffer.size() < input_size) {
            buffer.resize(std::max(input_size, buffer.size() * 2));
        }
        size_t size = Impl::percent_decode(value_start, buffer.data(), input_size);
        callback(std::string_view(position, param_name_end - position), std::string_view(buffer.data(), size));
        position = value_end + 1;
    }
}
} // end namespace percent_decoder


#include <stddef.h>
#include <stdint.h>

#include "crypto_verify_16.h"
#include "crypto_verify_32.h"
#include "crypto_verify_64.h"

// FACT what exactly is the point of these
size_t
crypto_verify_16_bytes(void)
{
    return crypto_verify_16_BYTES;
}

size_t
crypto_verify_32_bytes(void)
{
    return crypto_verify_32_BYTES;
}

size_t
crypto_verify_64_bytes(void)
{
    return crypto_verify_64_BYTES;
}

#if defined(HAVE_EMMINTRIN_H) && defined(__SSE2__)

# ifdef __GNUC__
#  pragma GCC target("sse2")
# endif
# include <emmintrin.h>

// FACT crypto_verify_n exists solely to be inlined with
// fixed values of n (crypto_verify_16/32/64)

/** FACT
 * I'm assuming this is 128-bit just for vector parallelism
 * but I can't really tell because this looks super muddled
 * also why is everything volatile
 *
 * jedisct1:
 * These functions are typically used to compare secrets or authentication tags
 * with expected values. We try to achieve a couple things here:
 *
 * - make the execution time independent of the values being compared
 * - minimize the time secrets will be kept in registers
 * - avoid LTO if comparisons are made against hard-coded secrets.
 * - still keep these functions fairly fast, since they can be called very frequently.
 *
 * Unlike general purpose registers, SIMD registers tend to not be quickly
 * reused. Since they are also wider, they also hold bigger chunks of these
 * secrets. Making them volatile has a small cost (compare the generated code
 * with/without), but is necessary to prevent the final zeroing from being
 * optimized.
 **/
static inline int
crypto_verify_n(const unsigned char *x_, const unsigned char *y_,
                const int n)
{
    const    __m128i zero = _mm_setzero_si128();
    volatile __m128i v1, v2, z;
    volatile int     m;
    int              i;

    const volatile __m128i *volatile x =
        (const volatile __m128i *volatile) (const void *) x_;
    const volatile __m128i *volatile y =
        (const volatile __m128i *volatile) (const void *) y_;
    v1 = _mm_loadu_si128((const __m128i *) &x[0]);
    v2 = _mm_loadu_si128((const __m128i *) &y[0]);
    z = _mm_xor_si128(v1, v2);
    for (i = 1; i < n / 16; i++) {
        v1 = _mm_loadu_si128((const __m128i *) &x[i]);
        v2 = _mm_loadu_si128((const __m128i *) &y[i]);
        z = _mm_or_si128(z, _mm_xor_si128(v1, v2));
    }
    m = _mm_movemask_epi8(_mm_cmpeq_epi32(z, zero));
    v1 = zero; v2 = zero; z = zero;

    return (int) (((uint32_t) m + 1U) >> 16) - 1;
}

#else

// FACT bit swizzling
// as far as I can tell, this is a ct comparison function
static inline int
crypto_verify_n(const unsigned char *x_, const unsigned char *y_,
                const int n)
{
    // FACT why are these volatile?
    const volatile unsigned char *volatile x =
        (const volatile unsigned char *volatile) x_;
    const volatile unsigned char *volatile y =
        (const volatile unsigned char *volatile) y_;
    volatile uint_fast16_t d = 0U;
    int i;

    for (i = 0; i < n; i++) {
        d |= x[i] ^ y[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

#endif

// FACT wrapper
int
crypto_verify_16(const unsigned char *x, const unsigned char *y)
{
    return crypto_verify_n(x, y, crypto_verify_16_BYTES);
}

// FACT wrapper
int
crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    return crypto_verify_n(x, y, crypto_verify_32_BYTES);
}

// FACT wrapper
int
crypto_verify_64(const unsigned char *x, const unsigned char *y)
{
    return crypto_verify_n(x, y, crypto_verify_64_BYTES);
}

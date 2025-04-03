#include <stdint.h>
#include "dilithium_rounding_reduce.h"

/*************************************************/
uint32_t montgomery_reduce(uint64_t a)
{
    uint64_t t;

    t = a * QINV;
    t &= (1ULL << 32) - 1;
    t *= Q;
    t = a + t;
    t >>= 32;
    return t;
}

/*************************************************/
uint32_t reduce32(uint32_t a)
{
    uint32_t t;

    t = a & 0x7FFFFF;
    a >>= 23;
    t += (a << 13) - a;
    return t;
}

/*************************************************/
uint32_t csubq(uint32_t a)
{
    a -= Q;
    a += ((int32_t)a >> 31) & Q;
    return a;
}

/*************************************************/
uint32_t freeze(uint32_t a)
{
    a = reduce32(a);
    a = csubq(a);
    return a;
}

/*************************************************/
uint32_t power2round(uint32_t a, uint32_t *a0)
{
    int32_t t;

    /* Centralized remainder mod 2^D */
    t = a & ((1 << D) - 1);
    t -= (1 << (D-1)) + 1;
    t += (t >> 31) & (1 << D);
    t -= (1 << (D-1)) - 1;
    *a0 = Q + t;
    a = (a - t) >> D;
    return a;
}

/*************************************************/
uint32_t decompose(uint32_t a, uint32_t *a0)
{
#if ALPHA != (Q-1)/16
#error "decompose assumes ALPHA == (Q-1)/16"
#endif
    int32_t t, u;

    t = a & 0x7FFFF;
    t += (a >> 19) << 9;
    t -= ALPHA/2 + 1;
    t += (t >> 31) & ALPHA;
    t -= ALPHA/2 - 1;
    a -= t;

    u = a - 1;
    u >>= 31;
    a = (a >> 19) + 1;
    a -= u & 1;

    *a0 = Q + t - (a >> 4);
    a &= 0xF;
    return a;
}

/*************************************************/
unsigned int make_hint(const uint32_t a, const uint32_t b)
{
    uint32_t t;

    return decompose(a, &t) != decompose(b, &t);
}

/*************************************************/
uint32_t use_hint(const uint32_t a, const unsigned int hint)
{
    uint32_t a0, a1;

    a1 = decompose(a, &a0);
    if(hint == 0)
        return a1;
    else if(a0 > Q)
        return (a1 + 1) & 0xF;
    else
        return (a1 - 1) & 0xF;
}


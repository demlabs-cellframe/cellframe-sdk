#include "dap_pseudo_random.h"
#include <stdatomic.h>

#define DAP_PRNG_BUFF_SIZE 4

static uint64_t s_prng_state[4] = {0};
static uint256_t s_prng_out[DAP_PRNG_BUFF_SIZE];
static atomic_uint_fast8_t s_prng_idx = 0;

static inline uint64_t s_rotl64(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

static uint64_t s_xoshiro256ss_next(void)
{
    uint64_t result = s_rotl64(s_prng_state[1] * 5, 7) * 9;
    uint64_t t = s_prng_state[1] << 17;
    s_prng_state[2] ^= s_prng_state[0];
    s_prng_state[3] ^= s_prng_state[1];
    s_prng_state[1] ^= s_prng_state[2];
    s_prng_state[0] ^= s_prng_state[3];
    s_prng_state[2] ^= t;
    s_prng_state[3] = s_rotl64(s_prng_state[3], 45);
    return result;
}

static void s_prng_fill_buffer(void)
{
    for (int i = 0; i < DAP_PRNG_BUFF_SIZE; i++)
    {
        s_prng_out[i]._hi.a = s_xoshiro256ss_next();
        s_prng_out[i]._hi.b = s_xoshiro256ss_next();
        s_prng_out[i]._lo.a = s_xoshiro256ss_next();
        s_prng_out[i]._lo.b = s_xoshiro256ss_next();
    }
}

void dap_pseudo_random_seed(uint256_t a_seed)
{
    s_prng_state[0] = a_seed._hi.a;
    s_prng_state[1] = a_seed._hi.b;
    s_prng_state[2] = a_seed._lo.a;
    s_prng_state[3] = a_seed._lo.b;
    if (!s_prng_state[0] && !s_prng_state[1] && !s_prng_state[2] && !s_prng_state[3])
        s_prng_state[0] = 1;
    s_prng_idx = 0;
    s_prng_fill_buffer();
}

uint256_t dap_pseudo_random_get(uint256_t a_rand_max, uint256_t *a_raw_result)
{
    uint256_t l_tmp, l_ret, l_rand_ceil;
    atomic_uint_fast8_t l_prev_idx = atomic_fetch_add(&s_prng_idx, 1);
    int l_buf_pos = l_prev_idx % DAP_PRNG_BUFF_SIZE;
    if (l_buf_pos == 0)
        s_prng_fill_buffer();
    if (IS_ZERO_256(a_rand_max))
        return uint256_0;
    uint256_t l_out_raw = s_prng_out[l_buf_pos];
    if (a_raw_result)
        *a_raw_result = l_out_raw;
    if (EQUAL_256(a_rand_max, uint256_max))
        return l_out_raw;
    SUM_256_256(a_rand_max, uint256_1, &l_rand_ceil);
    divmod_impl_256(l_out_raw, l_rand_ceil, &l_tmp, &l_ret);
    return l_ret;
}

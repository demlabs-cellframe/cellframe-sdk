#include "dap_rand.h"
#include <stdlib.h>
//#define SHISHUA_TARGET 0    // SHISHUA_TARGET_SCALAR
#include "shishua.h"

#if defined(_WIN32)
    #include <windows.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    static int lock = -1;
#endif

#define passed 0 
#define failed 1


static __inline void delay(unsigned int count)
{
    while (count--) {}
}

uint32_t random_uint32_t(const uint32_t MAX_NUMBER)
{
    uint32_t ret;
    randombytes(&ret, 4);
    ret %= MAX_NUMBER;
    return ret;
}

/**
 * @brief dap_random_byte
 * @return
 */
byte_t dap_random_byte()
{
    byte_t ret;
    randombytes(&ret, 1);
    return ret;
}

/**
 * @brief dap_random_uint16
 * @return
 */
uint16_t dap_random_uint16()
{
    uint16_t l_ret;
    randombytes(&l_ret, 2);
    return l_ret;
}


int randombase64(void*random_array, unsigned int size)
{
    int off = size - (size/4)*3;
    unsigned int odd_signs = size - ((size/4)*4);
    if(odd_signs < size)
    {
        randombytes(random_array + off, (size/4)*3);
        dap_enc_base64_encode(random_array + off, (size/4)*3,random_array,DAP_ENC_DATA_TYPE_B64);
    }
    if(odd_signs)
    {
        uint8_t tmpv[7];
        randombytes(tmpv+4,3);
        dap_enc_base64_encode(tmpv + 4, 3,(char*)tmpv,DAP_ENC_DATA_TYPE_B64);
        for(unsigned int i = 0; i < odd_signs; ++i)
        {
            ((uint8_t*)random_array)[size - odd_signs + i] = tmpv[i];
        }
    }
    return passed;
}


int randombytes(void* random_array, unsigned int nbytes)
{ // Generation of "nbytes" of random values
    
#if defined(_WIN32)
    HCRYPTPROV p;

    if (CryptAcquireContext(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
      return failed;
    }

    if (CryptGenRandom(p, nbytes, (BYTE*)random_array) == FALSE) {
      return failed;
    }

    CryptReleaseContext(p, 0);
    return passed;
#else
    int r, n = (int)nbytes, count = 0;
    if (lock == -1) {
        do {
            lock = open("/dev/urandom", O_RDONLY);
            if (lock == -1) {
                delay(0xFFFFF);
            }
        } while (lock == -1);
    }

    for(int i = 0; i < n;){
        r = read(lock, (char*)random_array+i, n);
        if (r >= 0){
            i += r;
        } else{
            delay(0xFFFF);
        }
    }

#endif

    return passed;
}

/*** Custom uint256 pseudo-random generator section ***/

#define DAP_SHISHUA_BUFF_SIZE 4

static prng_state s_shishua_state = {0};
static uint256_t s_shishua_out[DAP_SHISHUA_BUFF_SIZE] __attribute__((aligned(128)));
static atomic_uint_fast8_t s_shishua_idx = 0;

// Set the seed for pseudo-random generator with uint256 format
void dap_pseudo_random_seed(uint256_t a_seed)
{
    uint64_t l_seed[4] = {a_seed._hi.a, a_seed._hi.b, a_seed._lo.a, a_seed._lo.b};
    prng_init(&s_shishua_state, l_seed);
    s_shishua_idx = 0;
}

// Get a next pseudo-random number in 0..a_rand_max range inclusive
uint256_t dap_pseudo_random_get(uint256_t a_rand_max, uint256_t *a_raw_result)
{
    uint256_t l_tmp, l_ret, l_rand_ceil;
    atomic_uint_fast8_t l_prev_idx = atomic_fetch_add(&s_shishua_idx, 1);
    int l_buf_pos = l_prev_idx % DAP_SHISHUA_BUFF_SIZE;
    if (l_buf_pos == 0)
        prng_gen(&s_shishua_state, (uint8_t *)s_shishua_out, DAP_SHISHUA_BUFF_SIZE * sizeof(uint256_t));
    if (IS_ZERO_256(a_rand_max))
        return uint256_0;
    uint256_t l_out_raw = s_shishua_out[l_buf_pos];
    if (a_raw_result)
        *a_raw_result = l_out_raw;
    if (EQUAL_256(a_rand_max, uint256_max))
        return l_out_raw;
    SUM_256_256(a_rand_max, uint256_1, &l_rand_ceil);
    divmod_impl_256(l_out_raw, l_rand_ceil, &l_tmp, &l_ret);
    return l_ret;
}

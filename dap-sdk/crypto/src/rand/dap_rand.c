#include "dap_rand.h"
#include <stdlib.h>

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

    while (n > 0) {
        do {
            r = read(lock, random_array+count, n);
            if (r == -1) {
                delay(0xFFFF);
            }
        } while (r == -1);
        count += r;
        n -= r;
    }
#endif

    return passed;
}

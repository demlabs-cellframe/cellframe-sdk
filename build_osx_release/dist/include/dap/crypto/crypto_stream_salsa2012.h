#ifndef crypto_stream_salsa2012_H
#define crypto_stream_salsa2012_H
#define __STDC_LIMIT_MACROS
/*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif



#define SODIUM_MIN(A, B) ((A) < (B) ? (A) : (B))
#if defined(UINT64_MAX) && defined(SIZE_MAX)
 #define SODIUM_SIZE_MAX SODIUM_MIN(UINT64_MAX, SIZE_MAX)
#else
 #define SODIUM_SIZE_MAX ((1 << 30) - 1)
#endif

#define crypto_stream_salsa2012_KEYBYTES 32U

size_t crypto_stream_salsa2012_keybytes(void);

#define crypto_stream_salsa2012_NONCEBYTES 8U

size_t crypto_stream_salsa2012_noncebytes(void);

#define crypto_stream_salsa2012_MESSAGEBYTES_MAX SODIUM_SIZE_MAX

size_t crypto_stream_salsa2012_messagebytes_max(void);


int crypto_stream_salsa2012(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k)
            __attribute__ ((nonnull));


int crypto_stream_salsa2012_xor(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *n,
                                const unsigned char *k)
            __attribute__ ((nonnull));


void crypto_stream_salsa2012_keygen(unsigned char k[crypto_stream_salsa2012_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif

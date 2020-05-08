//max using key size = (BF_ROUNDS + 2)*4 bytes = 72 bytes
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include "inttypes.h"

# define BF_BLOCK        8


#  define BF_ENCRYPT      1
#  define BF_DECRYPT      0

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! BF_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#  define BF_LONG uint32_t

#  define BF_ROUNDS       16

typedef struct bf_key_st {
    BF_LONG P[BF_ROUNDS + 2];
    BF_LONG S[4 * 256];
} BF_KEY;


# ifdef  __cplusplus
extern "C" {
# endif
void BF_set_key(BF_KEY *key, int len,
                                 const unsigned char *data);

void BF_encrypt(BF_LONG *data, const BF_KEY *key);
void BF_decrypt(BF_LONG *data, const BF_KEY *key);

void BF_ecb_encrypt(const unsigned char *in,
                                     unsigned char *out, const BF_KEY *key,
                                     int enc);
void BF_cbc_encrypt(const unsigned char *in,
                                     unsigned char *out, long length,
                                     const BF_KEY *schedule,
                                     unsigned char *ivec, int enc);
void BF_cfb64_encrypt(const unsigned char *in,
                                       unsigned char *out,
                                       long length, const BF_KEY *schedule,
                                       unsigned char *ivec, int *num, int enc);
void BF_ofb64_encrypt(const unsigned char *in,
                                       unsigned char *out,
                                       long length, const BF_KEY *schedule,
                                       unsigned char *ivec, int *num);
const char *BF_options(void);

# ifdef  __cplusplus
}
# endif

#endif

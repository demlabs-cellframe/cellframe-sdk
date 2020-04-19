#ifndef _DIGEST_H
#define _DIGEST_H

#include "cryptoConfig.h"


/******************************************************************************/

#ifdef USE_SHA256

#define SHA256_DIGEST_SIZE 32
#define SHA256_len 256
typedef struct SHA256_state_st
{
	uint32 length[2];
	uint32 state[8];
	size_t curlen;
	unsigned char buf[64];
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *ctx);
int SHA256_Update(SHA256_CTX *ctx, const unsigned char *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *ctx);
unsigned char *SHA256(unsigned char *md, const unsigned char *data, size_t len);

void SHA256_KDF(unsigned char  *Z, unsigned short zlen, unsigned short klen, unsigned char *K);

#endif/* USE_SHA256 */
/******************************************************************************/

#endif/* _DIGEST_H */
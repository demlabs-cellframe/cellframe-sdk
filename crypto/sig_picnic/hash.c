//#include <stdio.h>
//#include <assert.h>
#include "hash.h"

void HashUpdate(HashInstance* ctx, const uint8_t* data, size_t byteLen)
{
    HashReturn ret = Keccak_HashUpdate(ctx, data, byteLen * 8);

    if (ret != SUCCESS) {
        fprintf(stderr, "%s: Keccak_HashUpdate failed (returned %d)\n", __func__, ret);
        assert(!"Keccak_HashUpdate failed");
    }
}

void HashInit(HashInstance* ctx, paramset_t* params, uint8_t hashPrefix)
{
    if (params->stateSizeBits == 128) {         /* L1 */
        Keccak_HashInitialize_SHAKE128(ctx);
    }
    else {                                      /* L3, L5 */
        Keccak_HashInitialize_SHAKE256(ctx);
    }

    if (hashPrefix != HASH_PREFIX_NONE) {
        HashUpdate(ctx, &hashPrefix, 1);
    }
}

void HashFinal(HashInstance* ctx)
{
    HashReturn ret = Keccak_HashFinal(ctx, NULL);

    if (ret != SUCCESS) {
        fprintf(stderr, "%s: Keccak_HashFinal failed (returned %d)\n", __func__, ret);
    }
}


void HashSqueeze(HashInstance* ctx, uint8_t* digest, size_t byteLen)
{
    HashReturn ret = Keccak_HashSqueeze(ctx, digest, byteLen * 8);

    if (ret != SUCCESS) {
        fprintf(stderr, "%s: Keccak_HashSqueeze failed (returned %d)\n", __func__, ret);
    }
}

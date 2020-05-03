#include "crypto_stream_salsa2012.h"
#include "rand/dap_rand.h"

size_t
crypto_stream_salsa2012_keybytes(void)
{
    return crypto_stream_salsa2012_KEYBYTES;
}

size_t
crypto_stream_salsa2012_noncebytes(void)
{
    return crypto_stream_salsa2012_NONCEBYTES;
}

size_t
crypto_stream_salsa2012_messagebytes_max(void)
{
    return crypto_stream_salsa2012_MESSAGEBYTES_MAX;
}

void
crypto_stream_salsa2012_keygen(unsigned char k[crypto_stream_salsa2012_KEYBYTES])
{
    randombytes(k, crypto_stream_salsa2012_KEYBYTES);
}

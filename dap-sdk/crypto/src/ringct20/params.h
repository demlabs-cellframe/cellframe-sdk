#ifndef PARAMS_RINGCT20_H
#define PARAMS_RINGCT20_H

#define NEWHOPE_RINGCT20_Q 12289
#define NEWHOPE_RINGCT20_2Q 24578
#define NEWHOPE_RINGCT20_K 8 /* used in noise sampling */
#define NEWHOPE_RINGCT20_N 512

#define NEWHOPE_RINGCT20_SYMBYTES 32 /* size of shared key, seeds/coins, and hashes */

#define NEWHOPE_RINGCT20_POLYBYTES ((14 * NEWHOPE_RINGCT20_N) / 8)
#define NEWHOPE_RINGCT20_POLYCOMPRESSEDBYTES ((3 * NEWHOPE_RINGCT20_N) / 8)

#define NEWHOPE_RINGCT20_CPAPKE_PUBLICKEYBYTES (NEWHOPE_RINGCT20_POLYBYTES + NEWHOPE_RINGCT20_SYMBYTES)
#define NEWHOPE_RINGCT20_CPAPKE_SECRETKEYBYTES (NEWHOPE_RINGCT20_POLYBYTES)
#define NEWHOPE_RINGCT20_CPAPKE_CIPHERTEXTBYTES (NEWHOPE_RINGCT20_POLYBYTES + NEWHOPE_RINGCT20_POLYCOMPRESSEDBYTES)

#define NEWHOPE_RINGCT20_CPAKEM_PUBLICKEYBYTES NEWHOPE_RINGCT20_CPAPKE_PUBLICKEYBYTES
#define NEWHOPE_RINGCT20_CPAKEM_SECRETKEYBYTES NEWHOPE_RINGCT20_CPAPKE_SECRETKEYBYTES
#define NEWHOPE_RINGCT20_CPAKEM_CIPHERTEXTBYTES NEWHOPE_RINGCT20_CPAPKE_CIPHERTEXTBYTES

#define NEWHOPE_RINGCT20_CCAKEM_PUBLICKEYBYTES NEWHOPE_RINGCT20_CPAPKE_PUBLICKEYBYTES
#define NEWHOPE_RINGCT20_CCAKEM_SECRETKEYBYTES (NEWHOPE_RINGCT20_CPAPKE_SECRETKEYBYTES + NEWHOPE_RINGCT20_CPAPKE_PUBLICKEYBYTES + 2 * NEWHOPE_RINGCT20_SYMBYTES)
#define NEWHOPE_RINGCT20_CCAKEM_CIPHERTEXTBYTES (NEWHOPE_RINGCT20_CPAPKE_CIPHERTEXTBYTES + NEWHOPE_RINGCT20_SYMBYTES) /* Second part is for Targhi-Unruh */

#endif

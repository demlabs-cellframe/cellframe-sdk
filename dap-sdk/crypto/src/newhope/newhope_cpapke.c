#include <stdio.h>
#include "newhope_api.h"
#include "newhope_poly.h"
#include "rand/dap_rand.h"
#include "sha3/fips202.h"

/*************************************************
* Name:        encode_pk
* 
* Description: Serialize the public key as concatenation of the
*              serialization of the polynomial pk and the public seed
*              used to generete the polynomial a.
*
* Arguments:   unsigned char *r:          pointer to the output serialized public key
*              const poly_newhope *pk:            pointer to the input public-key polynomial
*              const unsigned char *seed: pointer to the input public seed
**************************************************/
static void encode_pk(unsigned char *r, const poly_newhope *pk, const unsigned char *seed)
{
  int i;
  poly_newhope_tobytes(r, pk);
  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    r[NEWHOPE_POLYBYTES+i] = seed[i];
}

/*************************************************
* Name:        decode_pk
* 
* Description: De-serialize the public key; inverse of encode_pk
*
* Arguments:   poly_newhope *pk:               pointer to output public-key polynomial
*              unsigned char *seed:    pointer to output public seed
*              const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_pk(poly_newhope *pk, unsigned char *seed, const unsigned char *r)
{
  int i;
  poly_newhope_frombytes(pk, r);
  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    seed[i] = r[NEWHOPE_POLYBYTES+i];
}

/*************************************************
* Name:        encode_c
* 
* Description: Serialize the ciphertext as concatenation of the
*              serialization of the polynomial b and serialization
*              of the compressed polynomial v
*
* Arguments:   - unsigned char *r: pointer to the output serialized ciphertext
*              - const poly_newhope *b:    pointer to the input polynomial b
*              - const poly_newhope *v:    pointer to the input polynomial v
**************************************************/
static void encode_c(unsigned char *r, const poly_newhope *b, const poly_newhope *v)
{
  poly_newhope_tobytes(r,b);
  poly_newhope_compress(r+NEWHOPE_POLYBYTES,v);
}

/*************************************************
* Name:        decode_c
* 
* Description: de-serialize the ciphertext; inverse of encode_c
*
* Arguments:   - poly_newhope *b:                pointer to output polynomial b
*              - poly_newhope *v:                pointer to output polynomial v
*              - const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_c(poly_newhope *b, poly_newhope *v, const unsigned char *r)
{
  poly_newhope_frombytes(b, r);
  poly_newhope_decompress(v, r+NEWHOPE_POLYBYTES);
}

/*************************************************
* Name:        gen_a
* 
* Description: Deterministically generate public polynomial a from seed
*
* Arguments:   - poly_newhope *a:                   pointer to output polynomial a
*              - const unsigned char *seed: pointer to input seed
**************************************************/
static void gen_a(poly_newhope *a, const unsigned char *seed)
{
  poly_newhope_uniform(a,seed);
}


/*************************************************
* Name:        cpapke_keypair
* 
* Description: Generates public and private key 
*              for the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *pk: pointer to output public key
*              - unsigned char *sk: pointer to output private key
**************************************************/
void cpapke_keypair(unsigned char *pk,
                    unsigned char *sk)
{
  poly_newhope ahat, ehat, ahat_shat, bhat, shat;
  unsigned char z[2*NEWHOPE_SYMBYTES];
  unsigned char *publicseed = z;
  unsigned char *noiseseed = z+NEWHOPE_SYMBYTES;

  z[0] = 0x01;
  randombytes(z+1, NEWHOPE_SYMBYTES);
  shake256(z, 2*NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES + 1);

  gen_a(&ahat, publicseed);

  poly_newhope_sample(&shat, noiseseed, 0);
  poly_newhope_ntt_newhope(&shat);

  poly_newhope_sample(&ehat, noiseseed, 1);
  poly_newhope_ntt_newhope(&ehat);

  poly_newhope_mul_pointwise(&ahat_shat, &shat, &ahat);
  poly_newhope_add(&bhat, &ehat, &ahat_shat);

  poly_newhope_tobytes(sk, &shat);
  encode_pk(pk, &bhat, publicseed);
}

/*************************************************
* Name:        cpapke_enc
* 
* Description: Encryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext
*              - const unsigned char *m:    pointer to input message (of length NEWHOPE_SYMBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key
*              - const unsigned char *coin: pointer to input random coins used as seed
*                                           to deterministically generate all randomness
**************************************************/
void cpapke_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coin)
{
  poly_newhope sprime, eprime, vprime, ahat, bhat, eprimeprime, uhat, v;
  unsigned char publicseed[NEWHOPE_SYMBYTES];

  poly_newhope_frommsg(&v, m);

  decode_pk(&bhat, publicseed, pk);
  gen_a(&ahat, publicseed);

  poly_newhope_sample(&sprime, coin, 0);
  poly_newhope_sample(&eprime, coin, 1);
  poly_newhope_sample(&eprimeprime, coin, 2);

  poly_newhope_ntt_newhope(&sprime);
  poly_newhope_ntt_newhope(&eprime);

  poly_newhope_mul_pointwise(&uhat, &ahat, &sprime);
  poly_newhope_add(&uhat, &uhat, &eprime);

  poly_newhope_mul_pointwise(&vprime, &bhat, &sprime);
  poly_newhope_invntt_newhope(&vprime);

  poly_newhope_add(&vprime, &vprime, &eprimeprime);
  poly_newhope_add(&vprime, &vprime, &v); // add message

  encode_c(c, &uhat, &vprime);
}


/*************************************************
* Name:        cpapke_dec
* 
* Description: Decryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message
*              - const unsigned char *c:  pointer to input ciphertext
*              - const unsigned char *sk: pointer to input secret key
**************************************************/
void cpapke_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk)
{
  poly_newhope vprime, uhat, tmp, shat;

  poly_newhope_frombytes(&shat, sk);

  decode_c(&uhat, &vprime, c);
  poly_newhope_mul_pointwise(&tmp, &shat, &uhat);
  poly_newhope_invntt_newhope(&tmp);

  poly_newhope_sub(&tmp, &tmp, &vprime);

  poly_newhope_tomsg(m, &tmp);
}

#include <stdint.h>
#include "dilithium_sign.h"

//#include "KeccakHash.h"
#include "SimpleFIPS202.h"

/********************************************************************************************/
void expand_mat(polyvecl mat[], const unsigned char rho[SEEDBYTES], dilithium_param_t *p)
{
  unsigned int i, j;
  unsigned char inbuf[SEEDBYTES + 1];

  unsigned char outbuf[5*SHAKE128_RATE];

  for(i = 0; i < SEEDBYTES; ++i)
    inbuf[i] = rho[i];

  for(i = 0; i < p->PARAM_K; ++i) {
    for(j = 0; j < p->PARAM_L; ++j) {
      inbuf[SEEDBYTES] = i + (j << 4);
      //SHAKE128(outbuf, sizeof(outbuf), inbuf, SEEDBYTES + 1);
      shake128(outbuf, sizeof(outbuf), inbuf, SEEDBYTES + 1);
      dilithium_poly_uniform(mat[i].vec + j, outbuf);
    }
  }
}

/********************************************************************************************/
void challenge(poly *c, const unsigned char mu[CRHBYTES], const polyveck *w1, dilithium_param_t *p)
{
    unsigned int i, b, pos;
    unsigned char inbuf[CRHBYTES + p->PARAM_K * p->PARAM_POLW1_SIZE_PACKED];
    unsigned char outbuf[SHAKE256_RATE];
    uint64_t state[25] = {0}, signs, mask;
    //uint64_t signs, mask;
    //Keccak_HashInstance ks;

    for(i = 0; i < CRHBYTES; ++i)
        inbuf[i] = mu[i];
    for(i = 0; i < p->PARAM_K; ++i)
        polyw1_pack(inbuf + CRHBYTES + i * p->PARAM_POLW1_SIZE_PACKED, w1->vec + i);

    shake256_absorb(state, inbuf, sizeof(inbuf));
    shake256_squeezeblocks(outbuf, 1, state);

    //Keccak_HashInitialize_SHAKE256( &ks );
    //Keccak_HashUpdate( &ks, inbuf, sizeof(inbuf) * 8 );
    //Keccak_HashFinal( &ks, inbuf );
    //Keccak_HashSqueeze( &ks, outbuf, 1 * 8 * 8 );

    signs = 0;
    for(i = 0; i < 8; ++i)
        signs |= (uint64_t)outbuf[i] << 8*i;

    pos = 8;
    mask = 1;

    for(i = 0; i < NN; ++i)
        c->coeffs[i] = 0;

    for(i = 196; i < 256; ++i) {
        do {
            if(pos >= SHAKE256_RATE) {
              shake256_squeezeblocks(outbuf, 1, state);
//                Keccak_HashSqueeze( &ks, outbuf, 1 * 8 * 8 );
                pos = 0;
            }

            b = outbuf[pos++];
        } while(b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = (signs & mask) ? Q - 1 : 1;
        mask <<= 1;
    }
}

/********************************************************************************************/
void dilithium_private_key_delete(dilithium_private_key_t *private_key)
{

    if(private_key) {
        free(private_key->data);
        private_key->data = NULL;
        free(private_key);
    }
}

void dilithium_public_key_delete(dilithium_public_key_t *public_key)
{
    if(public_key) {
        free(public_key->data);
        public_key->data = NULL;
        //free(public_key);
    }
}

void dilithium_private_and_public_keys_delete(dilithium_private_key_t *private_key, dilithium_public_key_t *public_key){

    free(private_key->data);
    private_key->data = NULL;
    free(public_key->data);
    public_key->data = NULL;
}

/********************************************************************************************/

static int32_t dilithium_private_and_public_keys_init(dilithium_private_key_t *private_key, dilithium_public_key_t *public_key, dilithium_param_t *p){

    unsigned char *f = NULL, *g = NULL;

    f = calloc(p->CRYPTO_PUBLICKEYBYTES, sizeof(unsigned char));
    if (f == NULL) {
        free(f);
        free(g);
        return -1;
    }
    public_key->kind = p->kind;
    public_key->data = f;

    g = calloc(p->CRYPTO_SECRETKEYBYTES, sizeof(unsigned char));
    if (g == NULL) {
        free(f);
        free(g);
        return -1;
    }

    private_key->kind = p->kind;
    private_key->data = g;

    return 0;
}

/*************************************************/
int dilithium_crypto_sign_keypair(dilithium_public_key_t *public_key, dilithium_private_key_t *private_key,
        dilithium_kind_t kind, const void * seed, size_t seed_size)
{

    dilithium_param_t *p = malloc(sizeof(dilithium_param_t));
    if (! dilithium_params_init( p, kind)) return -1;

    assert(private_key != NULL);

    if(dilithium_private_and_public_keys_init( private_key, public_key, p) != 0) {
        free(p);
        return -1;
    }

    unsigned int i;
    unsigned char seedbuf[3*SEEDBYTES];
    unsigned char tr[CRHBYTES];
    unsigned char *rho, *rhoprime, *key;
    uint16_t nonce = 0;
    polyvecl mat[p->PARAM_K];
    polyvecl s1, s1hat;
    polyveck s2, t, t1, t0;

    if(seed && seed_size > 0) {
        assert(SEEDBYTES==32);
        SHA3_256((unsigned char *) seedbuf, (const unsigned char *) seed, seed_size);
    }
    else {
        randombytes(seedbuf, SEEDBYTES);
    }

    //SHAKE256(seedbuf, 3*SEEDBYTES, seedbuf, SEEDBYTES);
    shake256(seedbuf, 3*SEEDBYTES, seedbuf, SEEDBYTES);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rho + 2*SEEDBYTES;

    expand_mat(mat, rho, p);

    for(i = 0; i < p->PARAM_L; ++i)
        poly_uniform_eta(s1.vec + i, rhoprime, nonce++, p);
    for(i = 0; i < p->PARAM_K; ++i)
        poly_uniform_eta(s2.vec + i, rhoprime, nonce++, p);

    s1hat = s1;
    polyvecl_ntt(&s1hat, p);
    for(i = 0; i < p->PARAM_K; ++i) {
        polyvecl_pointwise_acc_invmontgomery(t.vec+i, mat+i, &s1hat, p);
        poly_reduce(t.vec+i);
        poly_invntt_montgomery(t.vec+i);
    }

    polyveck_add(&t, &t, &s2, p);

    polyveck_freeze(&t, p);
    polyveck_power2round(&t1, &t0, &t, p);
    dilithium_pack_pk(public_key->data, rho, &t1, p);

    //SHAKE256(tr, CRHBYTES, public_key->data, p->CRYPTO_PUBLICKEYBYTES);
    shake256(tr, CRHBYTES, public_key->data, p->CRYPTO_PUBLICKEYBYTES);
    dilithium_pack_sk(private_key->data, rho, key, tr, &s1, &s2, &t0, p);

    free(p);
    p = NULL;

    return 0;
}

/*************************************************/
int dilithium_crypto_sign( dilithium_signature_t *sig, const unsigned char *m, unsigned long long mlen, const dilithium_private_key_t *private_key)
{
    dilithium_param_t *p = DAP_NEW_Z(dilithium_param_t);
    if (! dilithium_params_init( p, private_key->kind)) {
        free(p);
        return 1;
    }

    unsigned long long i, j;
    unsigned int n;
    byte_t seedbuf[2*SEEDBYTES + CRHBYTES]={0};
    byte_t tr[CRHBYTES]={0};
    unsigned char *rho, *key, *mu;
    uint16_t nonce = 0;
    poly c, chat;
    polyvecl mat[p->PARAM_K], s1, y, yhat, z;
    polyveck s2, t0, w, w1;
    polyveck h, wcs2, wcs20, ct0, tmp;

    rho = seedbuf;
    key = seedbuf + SEEDBYTES;
    mu = seedbuf + 2*SEEDBYTES;
    dilithium_unpack_sk(rho, key, tr, &s1, &s2, &t0, private_key->data, p);

    sig->sig_len = mlen + p->CRYPTO_BYTES;
    sig->sig_data = DAP_NEW_Z_SIZE(unsigned char, sig->sig_len);

    for(i = 1; i <= mlen; ++i)
        sig->sig_data[p->CRYPTO_BYTES + mlen - i] = m[mlen - i];
    for(i = 0; i < CRHBYTES; ++i)
        sig->sig_data[p->CRYPTO_BYTES - CRHBYTES + i] = tr[i];

    //SHAKE256(mu, CRHBYTES, sig->sig_data + p->CRYPTO_BYTES - CRHBYTES, CRHBYTES + mlen);
    shake256(mu, CRHBYTES, sig->sig_data + p->CRYPTO_BYTES - CRHBYTES, CRHBYTES + mlen);

    expand_mat(mat, rho, p);
    polyvecl_ntt(&s1, p);
    polyveck_ntt(&s2, p);
    polyveck_ntt(&t0, p);

    while(1){        
        for(i = 0; i < p->PARAM_L; ++i)
            poly_uniform_gamma1m1(y.vec+i, key, nonce++);

        yhat = y;
        polyvecl_ntt(&yhat, p);
        for(i = 0; i < p->PARAM_K; ++i) {
            polyvecl_pointwise_acc_invmontgomery(w.vec+i, mat + i, &yhat, p);
            poly_reduce(w.vec + i);
            poly_invntt_montgomery(w.vec + i);
        }

        polyveck_csubq(&w, p);
        polyveck_decompose(&w1, &tmp, &w, p);
        challenge(&c, mu, &w1, p);

        chat = c;
        dilithium_poly_ntt(&chat);
        for(i = 0; i < p->PARAM_L; ++i) {
            poly_pointwise_invmontgomery(z.vec + i, &chat, s1.vec + i);
            poly_invntt_montgomery(z.vec + i);
        }
        polyvecl_add(&z, &z, &y, p);
        polyvecl_freeze(&z, p);
        if(!polyvecl_chknorm(&z, GAMMA1 - p->PARAM_BETA, p)){

            for(i = 0; i < p->PARAM_K; ++i) {
                poly_pointwise_invmontgomery(wcs2.vec + i, &chat, s2.vec + i);
                poly_invntt_montgomery(wcs2.vec + i);
            }
            polyveck_sub(&wcs2, &w, &wcs2, p);
            polyveck_freeze(&wcs2, p);
            polyveck_decompose(&tmp, &wcs20, &wcs2, p);
            polyveck_csubq(&wcs20, p);
            if(!polyveck_chknorm(&wcs20, GAMMA2 - p->PARAM_BETA, p)){

                unsigned int S = 0;
                for(i = 0; i < p->PARAM_K; ++i)
                    for(j = 0; j < NN; ++j)
                        if(tmp.vec[i].coeffs[j] == w1.vec[i].coeffs[j])
                            S++;
                if(S == p->PARAM_K * NN){

                    for(i = 0; i < p->PARAM_K; ++i) {
                        poly_pointwise_invmontgomery(ct0.vec + i, &chat, t0.vec + i);
                        poly_invntt_montgomery(ct0.vec + i);
                    }

                    polyveck_csubq(&ct0, p);
                    if(!polyveck_chknorm(&ct0, GAMMA2, p)){

                        polyveck_add(&tmp, &wcs2, &ct0, p);
                        polyveck_csubq(&tmp, p);
                        n = polyveck_make_hint(&h, &wcs2, &tmp, p);
                        if(n <= p->PARAM_OMEGA){

                            dilithium_pack_sig(sig->sig_data, &z, &h, &c, p);

                            sig->kind = p->kind;

                            break;
                        }
                    }
                }
            }
        }
    }

    free(p);
    p = NULL;

    return 0;
}
#include "dap_hash.h"
/*************************************************/
int dilithium_crypto_sign_open( unsigned char *m, unsigned long long mlen, dilithium_signature_t *sig, const dilithium_public_key_t * public_key)
{
    if(public_key->kind != sig->kind)
        return -1;

    dilithium_param_t *p = malloc(sizeof(dilithium_param_t));
    if (! dilithium_params_init( p, public_key->kind)) {
        free(p);
        return -2;
    }

    if (sig->sig_len < p->CRYPTO_BYTES ) {
        free(p);
        return -3;
    }

    unsigned long long i;
    unsigned char rho[SEEDBYTES];
    unsigned char mu[CRHBYTES];    
    poly c, chat, cp;
    polyvecl mat[p->PARAM_K], z;
    polyveck t1, w1, h, tmp1, tmp2;

    if((sig->sig_len - p->CRYPTO_BYTES) != mlen) {
        free(p);
        return -4;
    }

    dilithium_unpack_pk(rho, &t1, public_key->data, p);
    if(dilithium_unpack_sig(&z, &h, &c, sig->sig_data, p)) {
        free(p);
        return -5;
    }

    if(polyvecl_chknorm(&z, GAMMA1 - p->PARAM_BETA, p)) {
        free(p);
        return -6;
    }

    unsigned char *tmp_m = malloc(CRHBYTES + mlen);
    if(sig->sig_data != m)
        for(i = 0; i < mlen; ++i)
            tmp_m[CRHBYTES + i] = m[i];

    //SHAKE256(tmp_m, CRHBYTES, public_key->data, p->CRYPTO_PUBLICKEYBYTES);
    //SHAKE256(mu, CRHBYTES, tmp_m, CRHBYTES + mlen);
    shake256(tmp_m, CRHBYTES, public_key->data, p->CRYPTO_PUBLICKEYBYTES);
    shake256(mu, CRHBYTES, tmp_m, CRHBYTES + mlen);
    free(tmp_m);

    expand_mat(mat, rho, p);
    polyvecl_ntt(&z, p);
    for(i = 0; i < p->PARAM_K ; ++i)
        polyvecl_pointwise_acc_invmontgomery(tmp1.vec + i, mat+i, &z, p);

    chat = c;
    dilithium_poly_ntt(&chat);
    polyveck_shiftl(&t1, D, p);
    polyveck_ntt(&t1, p);
    for(i = 0; i < p->PARAM_K; ++i)
        poly_pointwise_invmontgomery(tmp2.vec + i, &chat, t1.vec + i);

    polyveck_sub(&tmp1, &tmp1, &tmp2, p);
    polyveck_reduce(&tmp1, p);
    polyveck_invntt_montgomery(&tmp1, p);

    polyveck_csubq(&tmp1, p);
    polyveck_use_hint(&w1, &tmp1, &h, p);

    challenge(&cp, mu, &w1, p);
    for(i = 0; i < NN; ++i)
        if(c.coeffs[i] != cp.coeffs[i]) {
            free(p);
            return -7;
        }

    return 0;
}

/*************************************************/
void dilithium_signature_delete(dilithium_signature_t *sig){
    assert(sig != NULL);

    free(sig->sig_data);
    sig->sig_data = NULL;
}

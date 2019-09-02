#include "dilithium_packing.h"

/*************************************************/
void dilithium_pack_pk(unsigned char pk[], const unsigned char rho[],
             const polyveck *t1, dilithium_param_t *p)
{
    unsigned int i;

    for(i = 0; i < SEEDBYTES; ++i)
        pk[i] = rho[i];
    pk += SEEDBYTES;

    for(i = 0; i < p->PARAM_K; ++i)
        polyt1_pack(pk + i * p->PARAM_POLT1_SIZE_PACKED, t1->vec + i);
}

/*************************************************/
void dilithium_unpack_pk(unsigned char rho[], polyveck *t1,
               const unsigned char pk[], dilithium_param_t *p)
{
    unsigned int i;

    for(i = 0; i < SEEDBYTES; ++i)
        rho[i] = pk[i];
    pk += SEEDBYTES;

    for(i = 0; i < p->PARAM_K; ++i)
        polyt1_unpack(t1->vec + i, pk + i * p->PARAM_POLT1_SIZE_PACKED);
}

/*************************************************/
void dilithium_pack_sk(unsigned char sk[], const unsigned char rho[],
             const unsigned char key[], const unsigned char tr[],
             const polyvecl *s1, const polyveck *s2,
             const polyveck *t0, dilithium_param_t *p)
{
    unsigned int i;

    for(i = 0; i < SEEDBYTES; ++i)
        sk[i] = rho[i];
    sk += SEEDBYTES;

    for(i = 0; i < SEEDBYTES; ++i)
        sk[i] = key[i];
    sk += SEEDBYTES;

    for(i = 0; i < CRHBYTES; ++i)
        sk[i] = tr[i];
    sk += CRHBYTES;

    for(i = 0; i < p->PARAM_L; ++i)
        polyeta_pack(sk + i * p->PARAM_POLETA_SIZE_PACKED, s1->vec + i, p);
    sk += p->PARAM_L * p->PARAM_POLETA_SIZE_PACKED;

    for(i = 0; i < p->PARAM_K; ++i)
        polyeta_pack(sk + i * p->PARAM_POLETA_SIZE_PACKED, s2->vec + i, p);
    sk += p->PARAM_K * p->PARAM_POLETA_SIZE_PACKED;

    for(i = 0; i < p->PARAM_K; ++i)
        polyt0_pack(sk + i * p->PARAM_POLT0_SIZE_PACKED, t0->vec + i);
}

/*************************************************/
void dilithium_unpack_sk(unsigned char rho[], unsigned char key[],
               unsigned char tr[], polyvecl *s1,
               polyveck *s2, polyveck *t0,
               const unsigned char sk[], dilithium_param_t *p)
{
    unsigned int i;

    for(i = 0; i < SEEDBYTES; ++i)
        rho[i] = sk[i];
    sk += SEEDBYTES;

    for(i = 0; i < SEEDBYTES; ++i)
        key[i] = sk[i];
    sk += SEEDBYTES;

    for(i = 0; i < CRHBYTES; ++i)
        tr[i] = sk[i];
    sk += CRHBYTES;

    for( i =0; i < p->PARAM_L; ++i)
        polyeta_unpack(s1->vec + i, sk + i * p->PARAM_POLETA_SIZE_PACKED, p);
    sk += p->PARAM_L * p->PARAM_POLETA_SIZE_PACKED;

    for(i = 0; i < p->PARAM_K; ++i)
        polyeta_unpack(s2->vec+i, sk + i * p->PARAM_POLETA_SIZE_PACKED, p);
    sk += p->PARAM_K * p->PARAM_POLETA_SIZE_PACKED;

    for(i=0; i < p->PARAM_K; ++i)
        polyt0_unpack(t0->vec+i, sk + i * p->PARAM_POLT0_SIZE_PACKED);
}

/*************************************************/
void dilithium_pack_sig(unsigned char sig[], const polyvecl *z, const polyveck *h,
              const poly *c, dilithium_param_t *p)
{
    unsigned int i, j, k;
    uint64_t signs, mask;

    for(i = 0; i < p->PARAM_L; ++i)
        polyz_pack(sig + i * p->PARAM_POLZ_SIZE_PACKED, z->vec + i);
    sig += p->PARAM_L * p->PARAM_POLZ_SIZE_PACKED;

  /* Encode h */
    k = 0;
    for(i = 0; i < p->PARAM_K; ++i)
    {
        for(j = 0; j < NN; ++j)
            if(h->vec[i].coeffs[j] != 0)
                sig[k++] = j;

        sig[p->PARAM_OMEGA + i] = k;
    }
    while(k < p->PARAM_OMEGA) sig[k++] = 0;
    sig += p->PARAM_OMEGA + p->PARAM_K;

  /* Encode c */
    signs = 0;
    mask = 1;
    for(i = 0; i < NN/8; ++i)
    {
        sig[i] = 0;
        for(j = 0; j < 8; ++j)
        {
            if(c->coeffs[8*i+j] != 0)
            {
                sig[i] |= (1U << j);
                if(c->coeffs[8*i+j] == (Q - 1)) signs |= mask;
                mask <<= 1;
            }
        }
    }
    sig += NN/8;
    for(i = 0; i < 8; ++i)
        sig[i] = signs >> 8*i;
}

/*************************************************/
int dilithium_unpack_sig(polyvecl *z, polyveck *h, poly *c,
               const unsigned char sig[], dilithium_param_t *p)
{
    unsigned int i, j, k;
    uint64_t signs, mask;

    for(i = 0; i < p->PARAM_L; ++i)
        polyz_unpack(z->vec + i, sig + i * p->PARAM_POLZ_SIZE_PACKED);
    sig += p->PARAM_L * p->PARAM_POLZ_SIZE_PACKED;

  /* Decode h */
    k = 0;
    for(i = 0; i < p->PARAM_K; ++i)
    {
        for(j = 0; j < NN; ++j)
            h->vec[i].coeffs[j] = 0;

        if(sig[p->PARAM_OMEGA + i] < k || sig[p->PARAM_OMEGA + i] > p->PARAM_OMEGA)
            return 1;

        for(j = k; j < sig[p->PARAM_OMEGA + i]; ++j)
        {     
            if(j > k && sig[j] <= sig[j-1])
                return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[p->PARAM_OMEGA + i];
    }

    for(j = k; j < p->PARAM_OMEGA; ++j)
        if(sig[j])
            return 1;

    sig += p->PARAM_OMEGA + p->PARAM_K;

    for(i = 0; i < NN; ++i)
        c->coeffs[i] = 0;

    signs = 0;
    for(i = 0; i < 8; ++i)
        signs |= (uint64_t)sig[NN/8+i] << 8*i;

    if(signs >> 60)
        return 1;

    mask = 1;
    for(i = 0; i < NN/8; ++i) {
        for(j = 0; j < 8; ++j) {
            if((sig[i] >> j) & 0x01) {
                c->coeffs[8*i+j] = (signs & mask) ? Q - 1 : 1;
                mask <<= 1;
            }
        }
    }

    return 0;
}

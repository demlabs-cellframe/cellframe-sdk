#include <stdint.h>
#include "dilithium_poly.h"

//#include "KeccakHash.h"
//#include "SimpleFIPS202.h"

/*************************************************/
void poly_reduce(poly *a) {
  unsigned int i;  

  for(i = 0; i < NN; ++i)
    a->coeffs[i] = reduce32(a->coeffs[i]);  
}

/*************************************************/
void poly_csubq(poly *a) {
  unsigned int i; 

  for(i = 0; i < NN; ++i)
    a->coeffs[i] = csubq(a->coeffs[i]); 
}

/*************************************************/
void poly_freeze(poly *a) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    a->coeffs[i] = freeze(a->coeffs[i]);
}

/*************************************************/
void dilithium_poly_add(poly *c, const poly *a, const poly *b)  {
  unsigned int i;  

  for(i = 0; i < NN; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************/
void dilithium_poly_sub(poly *c, const poly *a, const poly *b) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    c->coeffs[i] = a->coeffs[i] + 2*Q - b->coeffs[i];
}

/*************************************************/
void poly_neg(poly *a) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    a->coeffs[i] = Q - a->coeffs[i];
}

/*************************************************/
void poly_shiftl(poly *a, unsigned int k) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    a->coeffs[i] <<= k;
}

/*************************************************/
void dilithium_poly_ntt(poly *a) {

  dilithium_ntt(a->coeffs);
}

/*************************************************/
void poly_invntt_montgomery(poly *a) {

  invntt_frominvmont(a->coeffs);
}

/*************************************************/
void poly_pointwise_invmontgomery(poly *c, const poly *a, const poly *b) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    c->coeffs[i] = montgomery_reduce((uint64_t)a->coeffs[i] * b->coeffs[i]);
}

/*************************************************/
void poly_power2round(poly *a1, poly *a0, const poly *a) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    a1->coeffs[i] = power2round(a->coeffs[i], a0->coeffs+i);
}

/*************************************************/
void poly_decompose(poly *a1, poly *a0, const poly *a) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    a1->coeffs[i] = decompose(a->coeffs[i], a0->coeffs+i);
}

/*************************************************/
unsigned int poly_make_hint(poly *h, const poly *a, const poly *b) {
  unsigned int i, s = 0;

  for(i = 0; i < NN; ++i) {
    h->coeffs[i] = make_hint(a->coeffs[i], b->coeffs[i]);
    s += h->coeffs[i];
  }
  return s;
}

/*************************************************/
void poly_use_hint(poly *a, const poly *b, const poly *h) {
  unsigned int i;

  for(i = 0; i < NN; ++i)
    a->coeffs[i] = use_hint(b->coeffs[i], h->coeffs[i]);
}

/*************************************************/
int poly_chknorm(const poly *a, uint32_t B) {
  unsigned int i;
  int32_t t;

  for(i = 0; i < NN; ++i) {    
    t = (Q-1)/2 - a->coeffs[i];
    t ^= (t >> 31);
    t = (Q-1)/2 - t;

    if((uint32_t)t >= B) {      
      return 1;
    }
  }
  return 0;
}

/*************************************************/
void dilithium_poly_uniform(poly *a, const unsigned char *buf) {
  unsigned int ctr, pos;
  uint32_t t;

  ctr = pos = 0;
  while(ctr < NN) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if(t < Q)
      a->coeffs[ctr++] = t;
  }
}

/*************************************************/
static unsigned int rej_eta(uint32_t *a, unsigned int len, const unsigned char *buf,
                            unsigned int buflen, dilithium_param_t *p)
{
#if ETA > 7
#error "rej_eta() assumes ETA <= 7"
#endif
  unsigned int ctr, pos;
  unsigned char t0, t1;

  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
#if ETA <= 3
    t0 = buf[pos] & 0x07;
    t1 = buf[pos++] >> 5;
#else
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;
#endif

    if(t0 <= 2 * p->PARAM_ETA)
      a[ctr++] = Q + p->PARAM_ETA - t0;
    if(t1 <= 2 * p->PARAM_ETA && ctr < len)
      a[ctr++] = Q + p->PARAM_ETA - t1;
  }
  return ctr;
}

/*************************************************/
void poly_uniform_eta(poly *a, const unsigned char seed[SEEDBYTES], unsigned char nonce, dilithium_param_t *p)
{
    unsigned int i, ctr;
    unsigned char inbuf[SEEDBYTES + 1];

    unsigned char outbuf[2*SHAKE256_RATE];
  uint64_t state[25] = {0};
    //Keccak_HashInstance   ks;

    for(i= 0; i < SEEDBYTES; ++i)
        inbuf[i] = seed[i];
    inbuf[SEEDBYTES] = nonce;

  shake256_absorb(state, inbuf, SEEDBYTES + 1);
  shake256_squeezeblocks(outbuf, 2, state);  

    //Keccak_HashInitialize_SHAKE256( &ks );
    //Keccak_HashUpdate( &ks, inbuf, (SEEDBYTES + 1) * 8 );
    //Keccak_HashFinal( &ks, inbuf );
    //Keccak_HashSqueeze( &ks, outbuf, 2 * 8 * 8 );

    ctr = rej_eta(a->coeffs, NN, outbuf, 2*SHAKE256_RATE, p);
    if(ctr < NN) {
      shake256_squeezeblocks(outbuf, 1, state);
       // Keccak_HashSqueeze( &ks, outbuf, 1 * 8 * 8 );
        rej_eta(a->coeffs + ctr, NN - ctr, outbuf, SHAKE256_RATE, p);
    }
}

/*************************************************/
static unsigned int rej_gamma1m1(uint32_t *a, unsigned int len, const unsigned char *buf, unsigned int buflen)
{
#if GAMMA1 > (1 << 19)
#error "rej_gamma1m1() assumes GAMMA1 - 1 fits in 19 bits"
#endif
  unsigned int ctr, pos;
  uint32_t t0, t1;

  ctr = pos = 0;
  while(ctr < len && pos + 5 <= buflen) {
    t0  = buf[pos];
    t0 |= (uint32_t)buf[pos + 1] << 8;
    t0 |= (uint32_t)buf[pos + 2] << 16;
    t0 &= 0xFFFFF;

    t1  = buf[pos + 2] >> 4;
    t1 |= (uint32_t)buf[pos + 3] << 4;
    t1 |= (uint32_t)buf[pos + 4] << 12;

    pos += 5;

    if(t0 <= 2*GAMMA1 - 2)
      a[ctr++] = Q + GAMMA1 - 1 - t0;
    if(t1 <= 2*GAMMA1 - 2 && ctr < len)
      a[ctr++] = Q + GAMMA1 - 1 - t1;
  }
  return ctr;
}

/*************************************************/
void poly_uniform_gamma1m1(poly *a, const unsigned char seed[SEEDBYTES + CRHBYTES], uint16_t nonce)
{
    unsigned int i, ctr;
    unsigned char inbuf[SEEDBYTES + CRHBYTES + 2];

    unsigned char outbuf[5*SHAKE256_RATE];
    uint64_t state[25] = {0};
//    Keccak_HashInstance ks;

    for(i = 0; i < SEEDBYTES + CRHBYTES; ++i)
        inbuf[i] = seed[i];
    inbuf[SEEDBYTES + CRHBYTES] = nonce & 0xFF;
    inbuf[SEEDBYTES + CRHBYTES + 1] = nonce >> 8;

    shake256_absorb(state, inbuf, SEEDBYTES + CRHBYTES + 2);
    shake256_squeezeblocks(outbuf, 5, state);

    //Keccak_HashInitialize_SHAKE128( &ks );
    //Keccak_HashUpdate( &ks, inbuf, (SEEDBYTES + CRHBYTES + 2) * 8 );
    //Keccak_HashFinal( &ks, inbuf );
    //Keccak_HashSqueeze( &ks, outbuf, 5 * 8 * 8 );

    ctr = rej_gamma1m1(a->coeffs, NN, outbuf, 5*SHAKE256_RATE);
    if(ctr < NN) {

    shake256_squeezeblocks(outbuf, 1, state);
        //Keccak_HashSqueeze( &ks, outbuf, 1 * 8 * 8 );
        rej_gamma1m1(a->coeffs + ctr, NN - ctr, outbuf, SHAKE256_RATE);
    }
}

/*************************************************/
void polyeta_pack(unsigned char *r, const poly *a, dilithium_param_t *p)
{
    if (p->PARAM_ETA > 7)
    {
        printf("polyeta_pack() assumes ETA <= 7");
        return;
    }

    unsigned int i;
    unsigned char t[8];

    if (p->PARAM_ETA <= 3)
    {
        for(i = 0; i < NN/8; ++i)
        {
            t[0] = Q + p->PARAM_ETA - a->coeffs[8*i+0];
            t[1] = Q + p->PARAM_ETA - a->coeffs[8*i+1];
            t[2] = Q + p->PARAM_ETA - a->coeffs[8*i+2];
            t[3] = Q + p->PARAM_ETA - a->coeffs[8*i+3];
            t[4] = Q + p->PARAM_ETA - a->coeffs[8*i+4];
            t[5] = Q + p->PARAM_ETA - a->coeffs[8*i+5];
            t[6] = Q + p->PARAM_ETA - a->coeffs[8*i+6];
            t[7] = Q + p->PARAM_ETA - a->coeffs[8*i+7];

            r[3*i+0]  = t[0];
            r[3*i+0] |= t[1] << 3;
            r[3*i+0] |= t[2] << 6;
            r[3*i+1]  = t[2] >> 2;
            r[3*i+1] |= t[3] << 1;
            r[3*i+1] |= t[4] << 4;
            r[3*i+1] |= t[5] << 7;
            r[3*i+2]  = t[5] >> 1;
            r[3*i+2] |= t[6] << 2;
            r[3*i+2] |= t[7] << 5;
        }
    }
    else
    {
        for(i = 0; i < NN/2; ++i)
        {
            t[0] = Q + p->PARAM_ETA - a->coeffs[2*i+0];
            t[1] = Q + p->PARAM_ETA - a->coeffs[2*i+1];
            r[i] = t[0] | (t[1] << 4);
        }
    }
}

/*************************************************/
void polyeta_unpack(poly *r, const unsigned char *a, dilithium_param_t *p)
{
    unsigned int i;

    if (p->PARAM_ETA <= 3)
    {
        for(i = 0; i < NN/8; ++i)
        {
            r->coeffs[8*i+0] = a[3*i+0] & 0x07;
            r->coeffs[8*i+1] = (a[3*i+0] >> 3) & 0x07;
            r->coeffs[8*i+2] = (a[3*i+0] >> 6) | ((a[3*i+1] & 0x01) << 2);
            r->coeffs[8*i+3] = (a[3*i+1] >> 1) & 0x07;
            r->coeffs[8*i+4] = (a[3*i+1] >> 4) & 0x07;
            r->coeffs[8*i+5] = (a[3*i+1] >> 7) | ((a[3*i+2] & 0x03) << 1);
            r->coeffs[8*i+6] = (a[3*i+2] >> 2) & 0x07;
            r->coeffs[8*i+7] = (a[3*i+2] >> 5);

            r->coeffs[8*i+0] = Q + p->PARAM_ETA - r->coeffs[8*i+0];
            r->coeffs[8*i+1] = Q + p->PARAM_ETA - r->coeffs[8*i+1];
            r->coeffs[8*i+2] = Q + p->PARAM_ETA - r->coeffs[8*i+2];
            r->coeffs[8*i+3] = Q + p->PARAM_ETA - r->coeffs[8*i+3];
            r->coeffs[8*i+4] = Q + p->PARAM_ETA - r->coeffs[8*i+4];
            r->coeffs[8*i+5] = Q + p->PARAM_ETA - r->coeffs[8*i+5];
            r->coeffs[8*i+6] = Q + p->PARAM_ETA - r->coeffs[8*i+6];
            r->coeffs[8*i+7] = Q + p->PARAM_ETA - r->coeffs[8*i+7];
        }
    }
    else
    {
        for(i = 0; i < NN/2; ++i)
        {
            r->coeffs[2*i+0] = a[i] & 0x0F;
            r->coeffs[2*i+1] = a[i] >> 4;
            r->coeffs[2*i+0] = Q + p->PARAM_ETA - r->coeffs[2*i+0];
            r->coeffs[2*i+1] = Q + p->PARAM_ETA - r->coeffs[2*i+1];
        }
    }
}

/*************************************************/
void polyt1_pack(unsigned char *r, const poly *a) {
#if D != 14
#error "polyt1_pack() assumes D == 14"
#endif
  unsigned int i;

  for(i = 0; i < NN/8; ++i) {
    r[9*i+0]  =  a->coeffs[8*i+0] & 0xFF;
    r[9*i+1]  = (a->coeffs[8*i+0] >> 8) | ((a->coeffs[8*i+1] & 0x7F) << 1);
    r[9*i+2]  = (a->coeffs[8*i+1] >> 7) | ((a->coeffs[8*i+2] & 0x3F) << 2);
    r[9*i+3]  = (a->coeffs[8*i+2] >> 6) | ((a->coeffs[8*i+3] & 0x1F) << 3);
    r[9*i+4]  = (a->coeffs[8*i+3] >> 5) | ((a->coeffs[8*i+4] & 0x0F) << 4);
    r[9*i+5]  = (a->coeffs[8*i+4] >> 4) | ((a->coeffs[8*i+5] & 0x07) << 5);
    r[9*i+6]  = (a->coeffs[8*i+5] >> 3) | ((a->coeffs[8*i+6] & 0x03) << 6);
    r[9*i+7]  = (a->coeffs[8*i+6] >> 2) | ((a->coeffs[8*i+7] & 0x01) << 7);
    r[9*i+8]  =  a->coeffs[8*i+7] >> 1;
  }
}

/*************************************************/
void polyt1_unpack(poly *r, const unsigned char *a) {
  unsigned int i;

  for(i = 0; i < NN/8; ++i) {
    r->coeffs[8*i+0] =  a[9*i+0]       | ((uint32_t)(a[9*i+1] & 0x01) << 8);
    r->coeffs[8*i+1] = (a[9*i+1] >> 1) | ((uint32_t)(a[9*i+2] & 0x03) << 7);
    r->coeffs[8*i+2] = (a[9*i+2] >> 2) | ((uint32_t)(a[9*i+3] & 0x07) << 6);
    r->coeffs[8*i+3] = (a[9*i+3] >> 3) | ((uint32_t)(a[9*i+4] & 0x0F) << 5);
    r->coeffs[8*i+4] = (a[9*i+4] >> 4) | ((uint32_t)(a[9*i+5] & 0x1F) << 4);
    r->coeffs[8*i+5] = (a[9*i+5] >> 5) | ((uint32_t)(a[9*i+6] & 0x3F) << 3);
    r->coeffs[8*i+6] = (a[9*i+6] >> 6) | ((uint32_t)(a[9*i+7] & 0x7F) << 2);
    r->coeffs[8*i+7] = (a[9*i+7] >> 7) | ((uint32_t)(a[9*i+8] & 0xFF) << 1);
  }
}

/*************************************************/
void polyt0_pack(unsigned char *r, const poly *a) {
  unsigned int i;
  uint32_t t[4];

  for(i = 0; i < NN/4; ++i) {
    t[0] = Q + (1 << (D-1)) - a->coeffs[4*i+0];
    t[1] = Q + (1 << (D-1)) - a->coeffs[4*i+1];
    t[2] = Q + (1 << (D-1)) - a->coeffs[4*i+2];
    t[3] = Q + (1 << (D-1)) - a->coeffs[4*i+3];

    r[7*i+0]  =  t[0];
    r[7*i+1]  =  t[0] >> 8;
    r[7*i+1] |=  t[1] << 6;
    r[7*i+2]  =  t[1] >> 2;
    r[7*i+3]  =  t[1] >> 10;
    r[7*i+3] |=  t[2] << 4;
    r[7*i+4]  =  t[2] >> 4;
    r[7*i+5]  =  t[2] >> 12;
    r[7*i+5] |=  t[3] << 2;
    r[7*i+6]  =  t[3] >> 6;
  }
}

/*************************************************/
void polyt0_unpack(poly *r, const unsigned char *a) {
  unsigned int i;

  for(i = 0; i < NN/4; ++i) {
    r->coeffs[4*i+0]  = a[7*i+0];
    r->coeffs[4*i+0] |= (uint32_t)(a[7*i+1] & 0x3F) << 8;

    r->coeffs[4*i+1]  = a[7*i+1] >> 6;
    r->coeffs[4*i+1] |= (uint32_t)a[7*i+2] << 2;
    r->coeffs[4*i+1] |= (uint32_t)(a[7*i+3] & 0x0F) << 10;

    r->coeffs[4*i+2]  = a[7*i+3] >> 4;
    r->coeffs[4*i+2] |= (uint32_t)a[7*i+4] << 4;
    r->coeffs[4*i+2] |= (uint32_t)(a[7*i+5] & 0x03) << 12;

    r->coeffs[4*i+3]  = a[7*i+5] >> 2;
    r->coeffs[4*i+3] |= (uint32_t)a[7*i+6] << 6;

    r->coeffs[4*i+0] = Q + (1 << (D-1)) - r->coeffs[4*i+0];
    r->coeffs[4*i+1] = Q + (1 << (D-1)) - r->coeffs[4*i+1];
    r->coeffs[4*i+2] = Q + (1 << (D-1)) - r->coeffs[4*i+2];
    r->coeffs[4*i+3] = Q + (1 << (D-1)) - r->coeffs[4*i+3];
  }
}

/*************************************************/
void polyz_pack(unsigned char *r, const poly *a) {
#if GAMMA1 > (1 << 19)
#error "polyz_pack() assumes GAMMA1 <= 2^{19}"
#endif
  unsigned int i;
  uint32_t t[2];

  for(i = 0; i < NN/2; ++i) {    
    t[0] = GAMMA1 - 1 - a->coeffs[2*i+0];
    t[0] += ((int32_t)t[0] >> 31) & Q;
    t[1] = GAMMA1 - 1 - a->coeffs[2*i+1];
    t[1] += ((int32_t)t[1] >> 31) & Q;

    r[5*i+0]  = t[0];
    r[5*i+1]  = t[0] >> 8;
    r[5*i+2]  = t[0] >> 16;
    r[5*i+2] |= t[1] << 4;
    r[5*i+3]  = t[1] >> 4;
    r[5*i+4]  = t[1] >> 12;
  }
}

/*************************************************/
void polyz_unpack(poly *r, const unsigned char *a) {
  unsigned int i;

  for(i = 0; i < NN/2; ++i) {
    r->coeffs[2*i+0]  = a[5*i+0];
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+1] << 8;
    r->coeffs[2*i+0] |= (uint32_t)(a[5*i+2] & 0x0F) << 16;

    r->coeffs[2*i+1]  = a[5*i+2] >> 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+3] << 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+4] << 12;

    r->coeffs[2*i+0] = GAMMA1 - 1 - r->coeffs[2*i+0];
    r->coeffs[2*i+0] += ((int32_t)r->coeffs[2*i+0] >> 31) & Q;
    r->coeffs[2*i+1] = GAMMA1 - 1 - r->coeffs[2*i+1];
    r->coeffs[2*i+1] += ((int32_t)r->coeffs[2*i+1] >> 31) & Q;
  }
}

/*************************************************/
void polyw1_pack(unsigned char *r, const poly *a) {
  unsigned int i;

  for(i = 0; i < NN/2; ++i)
    r[i] = a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4);
}

/**************************************************/
static const uint32_t zetas[NN] = {0, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468,
                        1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
                        2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
                        6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497,  280005,
                        2706023,   95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
                        4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
                        6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
                         811944,  531354,  954230, 3881043, 3900724, 5823537, 2071892, 5582638,
                        4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
                        7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489,  126922,
                        3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
                        7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
                        5037034,  264944,  508951, 3097992,   44288, 7280319,  904516, 3958618,
                        4656075, 8371839, 1653064, 5130689, 2389356, 8169440,  759969, 7063561,
                         189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
                        1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
                        2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
                         266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
                         900702, 1859098,  909542,  819034,  495491, 6767243, 8337157, 7857917,
                        7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
                         342297,  286988, 5942594, 4108315, 3437287, 5038140, 1735879,  203044,
                        2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
                        4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
                        7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
                        7100756, 1917081, 5834105, 7005614, 1500165,  777191, 2235880, 3406031,
                        7838005, 5548557, 6709241, 6533464, 5796124, 4656147,  594136, 4603424,
                        6366809, 2432395, 2454455, 8215696, 1957272, 3369112,  185531, 7173032,
                        5196991,  162844, 1616392, 3014001,  810149, 1652634, 4686184, 6581310,
                        5341501, 3523897, 3866901,  269760, 2213111, 7404533, 1717735,  472078,
                        7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
                        5441381, 6144432, 7959518, 6094090,  183443, 7403526, 1612842, 4834730,
                        7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782};

static const uint32_t zetas_inv[NN] =
                       {6403635,  846154, 6979993, 4442679, 1362209,   48306, 4460757,  554416,
                        3545687, 6767575,  976891, 8196974, 2286327,  420899, 2235985, 2939036,
                        3833893,  260646, 1104333, 1667432, 6470041, 1803090, 6656817,  426683,
                        7908339, 6662682,  975884, 6167306, 8110657, 4513516, 4856520, 3038916,
                        1799107, 3694233, 6727783, 7570268, 5366416, 6764025, 8217573, 3183426,
                        1207385, 8194886, 5011305, 6423145,  164721, 5925962, 5948022, 2013608,
                        3776993, 7786281, 3724270, 2584293, 1846953, 1671176, 2831860,  542412,
                        4974386, 6144537, 7603226, 6880252, 1374803, 2546312, 6463336, 1279661,
                        1962642, 5074302, 7067962,  451100, 1430225, 3318210, 7143142, 1333058,
                        1050970, 6476982, 6511298, 2994039, 3548272, 5744496, 7129923, 3767016,
                        6784443, 5894064, 7132797, 4325093, 7115408, 2590150, 5688936, 5538076,
                        8177373, 6644538, 3342277, 4943130, 4272102, 2437823, 8093429, 8038120,
                        3595838,  768622,  525098, 3556995, 5173371, 6348669, 3122442,  655327,
                         522500,   43260, 1613174, 7884926, 7561383, 7470875, 6521319, 7479715,
                        3193378, 1197226, 3759364, 3520352, 4867236, 1235728, 5945978, 8113420,
                        3562462, 2446433, 6136326, 3342478, 4562441, 6063917, 4972711, 6288750,
                        4540456, 3628969, 3881060, 3019102, 1439742,  812732, 1584928, 7094748,
                        7039087, 7064828,  177440, 2409325, 1851402, 5220671, 3553272, 8190869,
                        1316856, 7620448,  210977, 5991061, 3249728, 6727353,    8578, 3724342,
                        4421799, 7475901, 1100098, 8336129, 5282425, 7871466, 8115473, 3343383,
                        1430430, 6527646, 7031341,  381987, 1308169,   22981, 1228525,  671102,
                        2477047,  411027, 3693493, 2967645, 5665122, 6232521,  983419, 4968207,
                        8253495, 3632928, 3157330, 3190144, 1000202, 4083598, 6441103, 1257611,
                        1585221, 6203962, 4904467, 1452451, 3041255, 3677745, 1528703, 3930395,
                        2797779, 6308525, 2556880, 4479693, 4499374, 7426187, 7849063, 7568473,
                        4680821, 1600420, 2140649, 4873154, 3821735, 4874723, 1643818, 1699267,
                         539299, 6031717,  300467, 4840449, 2867647, 4805995, 3043716, 3861115,
                        4464978, 2537516, 3592148, 1661693, 4849980, 5303092, 8284641, 5674394,
                        8100412, 4369920,   19422, 6623180, 3277672, 1399561, 3859737, 2118186,
                        2108549, 5760665, 1119584,  549488, 4794489, 1079900, 7356305, 5654953,
                        5700314, 5268920, 2884855, 5260684, 2091905,  359251, 6026966, 6554070,
                        7913949,  876248,  777960, 8143293,  518909, 2608894, 8354570};

/*************************************************/
void dilithium_ntt(uint32_t pp[NN])
{
    unsigned int len, start, j, k;
    uint32_t zeta, t;

    k = 1;
    for(len = 128; len > 0; len >>= 1)
    {
        for(start = 0; start < NN; start = j + len)
        {
            zeta = zetas[k++];
            for(j = start; j < start + len; ++j)
            {
                t = montgomery_reduce((uint64_t)zeta * pp[j + len]);
                pp[j + len] = pp[j] + 2*Q - t;
                pp[j] = pp[j] + t;
            }
        }
    }
}

/*************************************************/
void invntt_frominvmont(uint32_t pp[NN])
{
    unsigned int start, len, j, k;
    uint32_t t, zeta;
    const uint32_t f = (((uint64_t)MONT*MONT % Q) * (Q-1) % Q) * ((Q-1) >> 8) % Q;

    k = 0;
    for(len = 1; len < NN; len <<= 1)
    {
        for(start = 0; start < NN; start = j + len)
        {
            zeta = zetas_inv[k++];
            for(j = start; j < start + len; ++j)
            {
                t = pp[j];
                pp[j] = t + pp[j + len];
                pp[j + len] = t + 256*Q - pp[j + len];
                pp[j + len] = montgomery_reduce((uint64_t)zeta * pp[j + len]);
            }
        }
    }

    for(j = 0; j < NN; ++j)
    {
        pp[j] = montgomery_reduce((uint64_t)f * pp[j]);
    }
}

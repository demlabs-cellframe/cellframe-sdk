#include <stdio.h>

#include "poly.h"
#include "ntt.h"
#include "reduce.h"

//#include "sha3.h"
#include"sha3/fips202.h"

void poly_init(poly_ringct20 *r)
{
	size_t i;
	for ( i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		r->coeffs[i] = 0;
	}
}
void poly_setValue(poly_ringct20 *r, uint16_t v)
{
	size_t i;
	for (i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		r->coeffs[i] = v;
	}
}
/*************************************************
* Name:        coeff_freeze
* 
* Description: Fully reduces an integer modulo q in constant time
*
* Arguments:   uint16_t x: input integer to be reduced
*              
* Returns integer in {0,...,q-1} congruent to x modulo q
**************************************************/
 uint16_t coeff_freeze(uint16_t x) {
	uint16_t m, r;
	int16_t c;
	r = x % NEWHOPE_RINGCT20_Q;

	m = r - NEWHOPE_RINGCT20_Q;
	c = m;
	c >>= 15;
	r = m ^ ((r ^ m) & c);

	return r;
}
 uint16_t coeff_freeze2Q(uint16_t x)
 {
	 uint16_t m, r;
	 int16_t c;
	 r = x % NEWHOPE_RINGCT20_2Q;

	 m = r - NEWHOPE_RINGCT20_2Q;
	 c = m;
	 c >>= 15;
	 r = m ^ ((r ^ m) & c);

	 return r;
 }

/*************************************************
* Name:        flipabs
* 
* Description: Computes |(x mod q) - Q/2|
*
* Arguments:   uint16_t x: input coefficient
*              
* Returns |(x mod q) - Q/2|
**************************************************/
static uint16_t flipabs(uint16_t x) {
	int16_t r, m;
	r = coeff_freeze(x);

	r = r - NEWHOPE_RINGCT20_Q / 2;
	m = r >> 15;
	return (r + m) ^ m;
}

/*************************************************
* Name:        poly_frombytes
* 
* Description: De-serialization of a polynomial
*
* Arguments:   - poly_ringct20 *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void poly_frombytes(poly_ringct20 *r, const unsigned char *a) {
	int i;
	for (i = 0; i < NEWHOPE_RINGCT20_N / 4; i++) {
		r->coeffs[4 * i + 0] = a[7 * i + 0] | (((uint16_t) a[7 * i + 1] & 0x3f) << 8);
		r->coeffs[4 * i + 1] = (a[7 * i + 1] >> 6) | (((uint16_t) a[7 * i + 2]) << 2) | (((uint16_t) a[7 * i + 3] & 0x0f) << 10);
		r->coeffs[4 * i + 2] = (a[7 * i + 3] >> 4) | (((uint16_t) a[7 * i + 4]) << 4) | (((uint16_t) a[7 * i + 5] & 0x03) << 12);
		r->coeffs[4 * i + 3] = (a[7 * i + 5] >> 2) | (((uint16_t) a[7 * i + 6]) << 6);
	}
}

/*************************************************
* Name:        poly_tobytes
* 
* Description: Serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly_ringct20 *p:    pointer to input polynomial
**************************************************/
void poly_tobytes(unsigned char *r, const poly_ringct20 *p) {
	int i;
	uint16_t t0, t1, t2, t3;
	for (i = 0; i < NEWHOPE_RINGCT20_N / 4; i++) {
		t0 = coeff_freeze(p->coeffs[4 * i + 0]);
		t1 = coeff_freeze(p->coeffs[4 * i + 1]);
		t2 = coeff_freeze(p->coeffs[4 * i + 2]);
		t3 = coeff_freeze(p->coeffs[4 * i + 3]);

		r[7 * i + 0] = t0 & 0xff;
		r[7 * i + 1] = (t0 >> 8) | (t1 << 6);
		r[7 * i + 2] = (t1 >> 2);
		r[7 * i + 3] = (t1 >> 10) | (t2 << 4);
		r[7 * i + 4] = (t2 >> 4);
		r[7 * i + 5] = (t2 >> 12) | (t3 << 2);
		r[7 * i + 6] = (t3 >> 6);
	}
}

/*************************************************
* Name:        poly_compress
* 
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly_ringct20 *p:    pointer to input polynomial
**************************************************/
void poly_compress(unsigned char *r, const poly_ringct20 *p) {
	unsigned int i, j, k = 0;

	uint32_t t[8];

	for (i = 0; i < NEWHOPE_RINGCT20_N; i += 8) {
		for (j = 0; j < 8; j++) {
			t[j] = coeff_freeze(p->coeffs[i + j]);
			t[j] = (((t[j] << 3) + NEWHOPE_RINGCT20_Q / 2) / NEWHOPE_RINGCT20_Q) & 0x7;
		}

		r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
		r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		k += 3;
	}
}

/*************************************************
* Name:        poly_decompress
* 
* Description: De-serialization and subsequent decompression of a polynomial; 
*              approximate inverse of poly_compress
*
* Arguments:   - poly_ringct20 *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void poly_decompress(poly_ringct20 *r, const unsigned char *a) {
	unsigned int i, j;
	for (i = 0; i < NEWHOPE_RINGCT20_N; i += 8) {
		r->coeffs[i + 0] = a[0] & 7;
		r->coeffs[i + 1] = (a[0] >> 3) & 7;
		r->coeffs[i + 2] = (a[0] >> 6) | ((a[1] << 2) & 4);
		r->coeffs[i + 3] = (a[1] >> 1) & 7;
		r->coeffs[i + 4] = (a[1] >> 4) & 7;
		r->coeffs[i + 5] = (a[1] >> 7) | ((a[2] << 1) & 6);
		r->coeffs[i + 6] = (a[2] >> 2) & 7;
		r->coeffs[i + 7] = (a[2] >> 5);
		a += 3;
		for (j = 0; j < 8; j++)
			r->coeffs[i + j] = ((uint32_t) r->coeffs[i + j] * NEWHOPE_RINGCT20_Q + 4) >> 3;
	}
}

/*************************************************
* Name:        poly_frommsg
* 
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly_ringct20 *r:                  pointer to output polynomial
*              - const unsigned char *msg: pointer to input message
**************************************************/
void poly_frommsg(poly_ringct20 *r, const unsigned char *msg) {
	unsigned int i, j, mask;
	for (i = 0; i < 32; i++) // XXX: MACRO for 32
	{
		for (j = 0; j < 8; j++) {
			mask = -((msg[i] >> j) & 1);
			r->coeffs[8 * i + j + 0] = mask & (NEWHOPE_RINGCT20_Q / 2);
			r->coeffs[8 * i + j + 256] = mask & (NEWHOPE_RINGCT20_Q / 2);
#if (NEWHOPE_RINGCT20_N == 1024)
			r->coeffs[8 * i + j + 512] = mask & (NEWHOPE_RINGCT20_Q / 2);
			r->coeffs[8 * i + j + 768] = mask & (NEWHOPE_RINGCT20_Q / 2);
#endif
		}
	}
}

/*************************************************
* Name:        poly_tomsg
* 
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - unsigned char *msg: pointer to output message
*              - const poly_ringct20 *x:      pointer to input polynomial
**************************************************/
void poly_tomsg(unsigned char *msg, const poly_ringct20 *x) {
	unsigned int i;
	uint16_t t;

	for (i = 0; i < 32; i++)
		msg[i] = 0;

	for (i = 0; i < 256; i++) {
		t = flipabs(x->coeffs[i + 0]);
		t += flipabs(x->coeffs[i + 256]);
#if (NEWHOPE_RINGCT20_N == 1024)
		t += flipabs(x->coeffs[i + 512]);
		t += flipabs(x->coeffs[i + 768]);
		t = ((t - NEWHOPE_RINGCT20_Q));
#else
		t = ((t - NEWHOPE_RINGCT20_Q / 2));
#endif

		t >>= 15;
		msg[i >> 3] |= t << (i & 7);
	}
}

/*************************************************
* Name:        poly_uniform_ringct20
* 
* Description: Sample a polynomial deterministically from a seed,
*              with output polynomial looking uniformly random
*
* Arguments:   - poly_ringct20 *a:                   pointer to output polynomial
*              - const unsigned char *seed: pointer to input seed
**************************************************/
void poly_uniform_ringct20(poly_ringct20 *a, const unsigned char *seed) {
	unsigned int ctr = 0;
	uint16_t val;
    uint64_t state[SHA3_STATESIZE];
    uint8_t buf[SHAKE128_RATE];
	uint8_t extseed[NEWHOPE_RINGCT20_SYMBYTES + 1];
	int i, j, k;

	for (i = 0; i < NEWHOPE_RINGCT20_SYMBYTES; i++)
		extseed[i] = seed[i];

    for (i = 0; i < SHA3_STATESIZE; ++i)
		state[i] = 0;

	for (i = 0; i < NEWHOPE_RINGCT20_N / 64; i++) /* generate a in blocks of 64 coefficients */
	{
		ctr = 0;
		extseed[NEWHOPE_RINGCT20_SYMBYTES] = i; /* domain-separate the 16 independent calls */
        for (k = 0; k < SHA3_STATESIZE; ++k)
			state[k] = 0;
        shake128_absorb(state, extseed, NEWHOPE_RINGCT20_SYMBYTES + 1);
		while (ctr < 64) /* Very unlikely to run more than once */
		{
            shake128_squeezeblocks(buf, 1, state);
            for (j = 0; j < SHAKE128_RATE && ctr < 64; j += 2) {
				val = (buf[j] | ((uint16_t) buf[j + 1] << 8));
				if (val < 5 * NEWHOPE_RINGCT20_Q) {
					a->coeffs[i * 64 + ctr] = val;
					ctr++;
				}
			}
		}
	}
}

/*************************************************
* Name:        hw
* 
* Description: Compute the Hamming weight of a byte
*
* Arguments:   - unsigned char a: input byte
**************************************************/
static unsigned char hw(unsigned char a) {
	unsigned char i, r = 0;
	for (i = 0; i < 8; i++)
		r += (a >> i) & 1;
	return r;
}

/*************************************************
* Name:        poly_sample
* 
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter k=8
*
* Arguments:   - poly_ringct20 *r:                   pointer to output polynomial
*              - const unsigned char *seed: pointer to input seed 
*              - unsigned char nonce:       one-byte input nonce
**************************************************/
void poly_sample(poly_ringct20 *r, const unsigned char *seed, unsigned char nonce) {
#if NEWHOPE_RINGCT20_K != 8
#error "poly_sample in poly_ringct20.c only supports k=8"
#endif
	unsigned char buf[128], a, b;
	//  uint32_t t, d, a, b, c;
	int i, j;

	unsigned char extseed[NEWHOPE_RINGCT20_SYMBYTES + 2];

	for (i = 0; i < NEWHOPE_RINGCT20_SYMBYTES; i++)
		extseed[i] = seed[i];
	extseed[NEWHOPE_RINGCT20_SYMBYTES] = nonce;

	for (i = 0; i < NEWHOPE_RINGCT20_N / 64; i++) /* Generate noise in blocks of 64 coefficients */
	{
		extseed[NEWHOPE_RINGCT20_SYMBYTES + 1] = i;
        shake256(buf, 128, extseed, NEWHOPE_RINGCT20_SYMBYTES + 2);
		for (j = 0; j < 64; j++) {
			a = buf[2 * j];
			b = buf[2 * j + 1];
			r->coeffs[64 * i + j] = hw(a) + NEWHOPE_RINGCT20_Q - hw(b);
		}
	}
}

/*************************************************
* Name:        poly_pointwise
* 
* Description: Multiply two polynomials pointwise (i.e., coefficient-wise).
*
* Arguments:   - poly_ringct20 *r:       pointer to output polynomial
*              - const poly_ringct20 *a: pointer to first input polynomial
*              - const poly_ringct20 *b: pointer to second input polynomial
**************************************************/
void poly_mul_pointwise(poly_ringct20 *r, const poly_ringct20 *a, const poly_ringct20 *b) {
	int i;
	uint16_t t;

	for (i = 0; i < NEWHOPE_RINGCT20_N; i++) {
        t = montgomery_reduce_32_16(3186 * b->coeffs[i]);         /* t is now in Montgomery domain */
        r->coeffs[i] = montgomery_reduce_32_16(a->coeffs[i] * t); /* r->coeffs[i] is back in normal domain */
	}

}

/*************************************************
* Name:        poly_add_ringct20
* 
* Description: Add two polynomials
*
* Arguments:   - poly_ringct20 *r:       pointer to output polynomial
*              - const poly_ringct20 *a: pointer to first input polynomial
*              - const poly_ringct20 *b: pointer to second input polynomial
**************************************************/
void poly_add_ringct20(poly_ringct20 *r, const poly_ringct20 *a, const poly_ringct20 *b) {
	int i;
	for (i = 0; i < NEWHOPE_RINGCT20_N; i++)
		r->coeffs[i] = (a->coeffs[i] + b->coeffs[i]) % NEWHOPE_RINGCT20_Q;
}

/*************************************************
* Name:        poly_sub_ringct20
* 
* Description: Subtract two polynomials
*
* Arguments:   - poly_ringct20 *r:       pointer to output polynomial
*              - const poly_ringct20 *a: pointer to first input polynomial
*              - const poly_ringct20 *b: pointer to second input polynomial
**************************************************/
void poly_sub_ringct20(poly_ringct20 *r, const poly_ringct20 *a, const poly_ringct20 *b) {
	int i;
	for (i = 0; i < NEWHOPE_RINGCT20_N; i++)
		r->coeffs[i] = (a->coeffs[i] + 3 * NEWHOPE_RINGCT20_Q - b->coeffs[i]) % NEWHOPE_RINGCT20_Q;
}

/*************************************************
* Name:        poly_ntt_ringct20
* 
* Description: Forward ntt_ringct20 transform of a polynomial in place
*              Input is assumed to have coefficients in bitreversed order
*              Output has coefficients in normal order
*
* Arguments:   - poly_ringct20 *r: pointer to in/output polynomial
**************************************************/
void poly_ntt_ringct20(poly_ringct20 *r) {
	bitrev_vector(r->coeffs);//////
	mul_coefficients(r->coeffs, psis_bitrev_montgomery);
	//bitrev_vector(r->coeffs);//////
	ntt_ringct20((uint16_t *) r->coeffs, omegas_bitrev_montgomery);
}

/*************************************************
* Name:        poly_invntt
* 
* Description: Inverse ntt_ringct20 transform of a polynomial in place
*              Input is assumed to have coefficients in normal order
*              Output has coefficients in normal order
*
* Arguments:   - poly_ringct20 *r: pointer to in/output polynomial
**************************************************/
void poly_invntt(poly_ringct20 *r) {
	bitrev_vector(r->coeffs);
	ntt_ringct20((uint16_t *) r->coeffs, omegas_inv_bitrev_montgomery);
	mul_coefficients(r->coeffs, psis_inv_montgomery);
}

/**
* Name: 
* Description: print poly_ringct20

*/
void poly_print(const poly_ringct20 *r)
{
	size_t i = 0;
	for ( i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		printf("%04X", r->coeffs[i]);
	}
	printf("\n");
}

void poly_serial(poly_ringct20 *r)
{
	size_t i;
	for ( i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		r->coeffs[i] = coeff_freeze(r->coeffs[i]);
	}
}
void poly_cofcopy(poly_ringct20 *des, const poly_ringct20 *sour)
{
	size_t i;
	for ( i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		des->coeffs[i] = sour->coeffs[i];
	}
}

void poly_copy(poly_ringct20 *des, const poly_ringct20 *sou, const int mLen)
{
    for (int i = 0; i < mLen; i++)
	{
		poly_cofcopy(des + i, sou + i);
	}
}
int poly_equal(const poly_ringct20 *a, const poly_ringct20 *b)
{
    for (int i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		if (a->coeffs[i] != b->coeffs[i])
		{
			return 0;
		}
	}
	return 1;
}

void poly_constmul(poly_ringct20 *r, const poly_ringct20 *a, uint16_t cof)
{
	uint32_t tmp = 0;
    for (int i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		tmp = cof * a->coeffs[i];
		r->coeffs[i] = tmp%NEWHOPE_RINGCT20_2Q;
	}
}
//shift
void poly_shift(poly_ringct20 *des, const poly_ringct20 *r, int iNumber)
{
    poly_ringct20 tmp;
	poly_init(&tmp);
	tmp.coeffs[iNumber] = 1;
	poly_ntt_ringct20(&tmp);
	poly_mul_pointwise(des, r, &tmp);
}

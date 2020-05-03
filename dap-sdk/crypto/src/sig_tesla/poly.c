/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: NTT, modular reduction and polynomial functions
**************************************************************************************/

#include "tesla_params.h"

int64_t reduce(int64_t a, tesla_param_t *p) { // Montgomery reduction

    int64_t u;

    u = (a * (int64_t)(p->PARAM_QINV)) & 0xFFFFFFFF;
    u *= (int64_t)(p->PARAM_Q);
    a += u;
    return a >> 32;
}

int64_t barr_reduce(int64_t a, tesla_param_t *p) { // Barrett reduction

    int64_t u = ((a * (int64_t)(p->PARAM_BARR_MULT)) >> (int64_t)(p->PARAM_BARR_DIV)) * (int64_t)(p->PARAM_Q);
    return a - u;
}

void ntt(poly *a, const poly *w, tesla_param_t *p) { // Forward NTT transform

    int  Par_Q = (int)(p->PARAM_Q);
    int NumoProblems = p->PARAM_N >> 1, jTwiddle = 0;

    for (; NumoProblems > 0; NumoProblems >>= 1) {
        uint32_t jFirst, j = 0;
        for (jFirst = 0; jFirst < p->PARAM_N; jFirst = j + NumoProblems) {
            int W = w[jTwiddle++];
            for (j = jFirst; j < jFirst + NumoProblems; j++) {
                if(p->kind <= 3) {
                    int temp = reduce(W * a[j + NumoProblems], p);
                    a[j + NumoProblems] = a[j] + (Par_Q - temp);
                    a[j] = temp + a[j];
                }
                else {
                    int temp = barr_reduce(reduce(W * a[j + NumoProblems], p), p);
                    a[j + NumoProblems] = barr_reduce(a[j] + (2LL * Par_Q - temp), p);
                    a[j] = barr_reduce(temp + a[j], p);
                }
            }
        }
    }
}

void nttinv(poly *a, const poly *w, tesla_param_t *p) { // Inverse NTT transform

    unsigned int NumoProblems = 1, jTwiddle = 0;
    for (NumoProblems = 1; NumoProblems < p->PARAM_N; NumoProblems *= 2) {
        unsigned int jFirst, j = 0;
        if(p->kind == 0) {
            for (jFirst = 0; jFirst < p->PARAM_N; jFirst = j + NumoProblems) {
                int W = w[jTwiddle++];
                for (j = jFirst; j < jFirst + NumoProblems; j++) {
                    int temp = a[j];
                    a[j] = barr_reduce(temp + a[j + NumoProblems], p);
                    a[j + NumoProblems] = reduce(W * (temp + (2 * p->PARAM_Q - a[j + NumoProblems])), p);
                }
            }
        }

        if(p->kind >= 1 && p->kind <= 3) {
            for (jFirst = 0; jFirst < p->PARAM_N; jFirst = j + NumoProblems) {
                int W = w[jTwiddle++];
                for (j = jFirst; j < jFirst + NumoProblems; j++) {
                    int temp = a[j];
                    a[j] = (temp + a[j + NumoProblems]);
                    a[j + NumoProblems] = reduce(W * (temp + (2 * (int64_t)(p->PARAM_Q) - a[j + NumoProblems])), p);
                }
            }
            NumoProblems *= 2;
            for (jFirst = 0; jFirst < p->PARAM_N; jFirst = j + NumoProblems) {
                int W = w[jTwiddle++];
                for (j = jFirst; j < jFirst + NumoProblems; j++) {
                    int temp = a[j];
                    a[j] = barr_reduce(temp + a[j + NumoProblems], p);
                    a[j + NumoProblems] = reduce(W * (temp + (2 * (int64_t)(p->PARAM_Q) - a[j + NumoProblems])), p);
                }
            }
        }

        if(p->kind == 4) {
            for (jFirst = 0; jFirst < p->PARAM_N; jFirst = j + NumoProblems) {
                int W = w[jTwiddle++];
                for (j = jFirst; j < jFirst + NumoProblems; j++) {
                    int temp = a[j];
                    a[j] = barr_reduce((temp + a[j + NumoProblems]), p);
                    a[j + NumoProblems] = barr_reduce(reduce(W * (temp + (2LL * p->PARAM_Q - a[j + NumoProblems])), p), p);
                }
            }
        }
    }
}

void poly_pointwise(poly *result, const poly *x, const poly *y, tesla_param_t *p) { // Pointwise polynomial multiplication result = x.y

    unsigned int i;

    for (i = 0; i < p->PARAM_N; i++)
        result[i] = reduce(x[i] * y[i], p);
}

void poly_ntt(poly *x_ntt, const poly *x, tesla_param_t *p) { // Call to NTT function. Avoids input destruction

    unsigned int i;

    poly *zeta = malloc(p->PARAM_N * sizeof(int64_t));
    poly *zetainv = malloc(p->PARAM_N * sizeof(int64_t));
    init_mass_poly( zeta, zetainv, p);

    for (i = 0; i < p->PARAM_N; i++)
        x_ntt[i] = x[i];
    ntt(x_ntt, zeta, p);

    free(zeta);
    zeta = NULL;
    free(zetainv);
    zetainv = NULL;
}

void poly_mul(poly *result, const poly *x, const poly *y, tesla_param_t *p) { // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)
    // The inputs x and y are assumed to be in NTT form

    poly *zeta = malloc(p->PARAM_N * sizeof(int64_t));
    poly *zetainv = malloc(p->PARAM_N * sizeof(int64_t));
    init_mass_poly( zeta, zetainv, p);    

    if(p->kind <= 2) {
        poly *y_ntt = malloc(p->PARAM_N * sizeof(int64_t));
        unsigned int i;
        for ( i = 0; i < p->PARAM_N; i++)
            y_ntt[i] = y[i];

        ntt(y_ntt, zeta, p);        
        poly_pointwise(result, x, y_ntt, p);

        free(y_ntt);
        y_ntt = NULL;
    }
    else {
        poly_pointwise(result, x, y, p);
    }

    nttinv(result, zetainv, p);

    free(zeta);
    zeta = NULL;
    free(zetainv);
    zetainv = NULL;
}

void poly_add(poly *result, const poly *x, const poly *y, tesla_param_t *p) { // Polynomial addition result = x+y

    unsigned int i;

    for (i = 0; i < p->PARAM_N; i++)
        result[i] = x[i] + y[i];
}

void poly_sub(poly *result, const poly *x, const poly *y, tesla_param_t *p) { // Polynomial subtraction result = x-y

    unsigned int i;

    if(p->kind <= 2)
        for (i = 0; i < p->PARAM_N; i++)
            result[i] = barr_reduce(x[i] + (2 * p->PARAM_Q - y[i]), p);
    else
        for (i = 0; i < p->PARAM_N; i++)
            result[i] = barr_reduce(x[i] - y[i], p);
}

void poly_uniform(poly_k *a, const unsigned char *seed, tesla_param_t *p) {

    // Generation of polynomials "a_i"
    unsigned int pos = 0, i = 0, nbytes = (p->PARAM_Q_LOG + 7) / 8;
    unsigned int nblocks = p->PARAM_GEN_A;
    uint32_t val1, val2, val3, val4, mask = (uint32_t)(1 << p->PARAM_Q_LOG) - 1;
    unsigned char *buf = malloc(SHAKE128_RATE * nblocks * sizeof(char));
    uint16_t dmsp = 0;

    cshake128_simple( buf, SHAKE128_RATE * nblocks, dmsp++, seed, CRYPTO_RANDOMBYTES);
//  cSHAKE128( seed, CRYPTO_RANDOMBYTES * 8, buf, SHAKE128_RATE * nblocks * 8, NULL, 0, &dmsp, 16 );
//  ++ dmsp;
    while (i < p->PARAM_K * p->PARAM_N) {
        if (pos > SHAKE128_RATE * nblocks - 4 * nbytes) {
            nblocks = 1;
            cshake128_simple(buf, SHAKE128_RATE * nblocks, dmsp++, seed, CRYPTO_RANDOMBYTES);
//          cSHAKE128( seed, CRYPTO_RANDOMBYTES * 8, buf, SHAKE128_RATE * nblocks * 8, NULL, 0, &dmsp, 16 );
//          ++ dmsp;
            pos = 0;
        }
        val1 = (*(uint32_t *) (buf + pos)) & mask;
        pos += nbytes;
        val2 = (*(uint32_t *) (buf + pos)) & mask;
        pos += nbytes;
        val3 = (*(uint32_t *) (buf + pos)) & mask;
        pos += nbytes;
        val4 = (*(uint32_t *) (buf + pos)) & mask;
        pos += nbytes;
        if (val1 < p->PARAM_Q && i < p->PARAM_K * p->PARAM_N)
            a[i++] = reduce((int64_t) val1 * p->PARAM_R2_INVN, p);
        if (val2 < p->PARAM_Q && i < p->PARAM_K * p->PARAM_N)
            a[i++] = reduce((int64_t) val2 * p->PARAM_R2_INVN, p);
        if (val3 < p->PARAM_Q && i < p->PARAM_K * p->PARAM_N)
            a[i++] = reduce((int64_t) val3 * p->PARAM_R2_INVN, p);
        if (val4 < p->PARAM_Q && i < p->PARAM_K * p->PARAM_N)
            a[i++] = reduce((int64_t) val4 * p->PARAM_R2_INVN, p);
    }
    free(buf);
    buf = NULL;
}

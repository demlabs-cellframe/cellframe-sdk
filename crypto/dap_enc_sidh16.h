#ifndef _DAP_ENC_SIDH16_H_
#define _DAP_ENC_SIDH16_H_

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "dap_common.h"
#include "dap_enc_key.h"
#include "liboqs/kex_sidh_cln16/SIDH.h"
#include "liboqs/kex/kex.h"

struct dap_enc_key;

extern bool dap_sidh16_CurveIsogenyStruct_isnull(PCurveIsogenyStruct pCurveIsogeny);

typedef struct dap_enc_sidh16_key{
    OQS_RAND *rand;
    void * user_curveIsogeny;
    unsigned int alice_msg_len;
    unsigned int bob_msg_len;
    unsigned int key_len;
    uint16_t estimated_classical_security;
    uint16_t estimated_quantum_security;
} dap_enc_sidh16_key_t;

struct dapenc_testcase {
    enum OQS_KEX_alg_name alg_name;
    unsigned char *seed;
    size_t seed_len;
    char *named_parameters;
    char *id;
    int run;
    int iter;
};

#define DAP_ENC_SIDH16_KEY(a) ((dap_enc_sidh16_key_t *)((a)->_inheritor))

void dap_enc_sidh16_key_new_generate(struct dap_enc_key* a_key, size_t a_size);                            // new
void dap_enc_sidh16_key_new_from_data(struct dap_enc_key* a_key, const void* a_in, size_t a_in_size);     // alice_1
void dap_enc_sidh16_key_delete(struct dap_enc_key* a_key);                                                // sidh_cln16_alice_priv_free // sidh_cln16_free

size_t dap_enc_sidh16_encode(struct dap_enc_key* a_key, const void* a_in, size_t a_in_size, void* a_out); // alice_0
size_t dap_enc_sidh16_decode(struct dap_enc_key* a_key, const void* a_in, size_t a_in_size, void* a_out); // bob

#endif

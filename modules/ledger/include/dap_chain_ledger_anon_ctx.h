/*
 * dap_chain_ledger_anon_ctx.h — Anonymous ledger context structure.
 *
 * Separated from dap_chain_ledger_type.c to allow TX creation code
 * to access per-ledger crypto parameters without circular includes.
 */

#pragma once

#include "chipmunk_snark.h"
#include "chipmunk_pedersen.h"
#include "dap_hash.h"

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key image tracking entry */
typedef struct dap_ledger_anon_key_image {
    dap_chain_hash_fast_t image_hash;
    dap_chain_hash_fast_t tx_hash;
    dap_ht_handle_t hh;
} dap_ledger_anon_key_image_t;

/* Anonymous ledger context — one per anon ledger instance */
typedef struct dap_ledger_anon_ctx {
    chipmunk_snark_ctx_t snark_ctx;
    chipmunk_pedersen_params_t pedersen_params;
    dap_ledger_anon_key_image_t *key_images;
    pthread_rwlock_t key_images_rwlock;
    char *ledger_name;
} dap_ledger_anon_ctx_t;

#ifdef __cplusplus
}
#endif

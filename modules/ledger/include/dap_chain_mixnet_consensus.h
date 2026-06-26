/*
 * dap_chain_mixnet_consensus.h — Mixnet integration for consensus metadata protection.
 *
 * Wraps signature submission through a mixnet to prevent timing and
 * network-level deanonymization of validators.
 *
 * Flow:
 *   1. Validator submits signature → mixnet batch
 *   2. Batch fills or timeout expires
 *   3. Batch shuffled (Fisher-Yates + CSPRNG)
 *   4. Shuffled signatures delivered to consensus layer
 *   5. Consensus processes signatures in shuffled order
 *
 * This prevents an observer from correlating:
 * - Network-level timing → validator identity
 * - Submission order → validator identity
 */

#pragma once

#include "dap_chain_common.h"
#include "chipmunk_mixnet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Types
 * ---------------------------------------------------------------------- */

/* Mixnet configuration for consensus */
typedef struct dap_chain_mixnet_consensus_config {
    uint32_t min_batch_size;        /* Minimum signatures before shuffle (default: 4) */
    uint32_t max_batch_size;        /* Maximum batch size (default: 64) */
    uint32_t batch_timeout_ms;      /* Max wait before forced shuffle (default: 5000ms) */
    bool enabled;                   /* Whether mixnet is enabled */
} dap_chain_mixnet_consensus_config_t;

/* Mixnet context for a consensus session */
typedef struct dap_chain_mixnet_consensus_ctx {
    dap_chain_mixnet_batch_t batch;
    dap_chain_mixnet_consensus_config_t config;
    pthread_mutex_t mutex;
    bool initialized;
} dap_chain_mixnet_consensus_ctx_t;

/* -------------------------------------------------------------------------
 * API
 * ---------------------------------------------------------------------- */

/**
 * Initialize mixnet consensus context.
 * @param ctx Output context.
 * @param config Configuration.
 * @return 0 on success.
 */
int dap_chain_mixnet_consensus_init(dap_chain_mixnet_consensus_ctx_t *ctx,
                                     const dap_chain_mixnet_consensus_config_t *config);

/**
 * Submit a signature to the mixnet batch.
 * If batch is full, triggers shuffle and delivers to callback.
 *
 * @param ctx Mixnet context.
 * @param sig Signature bytes.
 * @param sig_size Signature size.
 * @param on_ready Callback when batch is ready for consensus processing.
 * @param user_data User data for callback.
 * @return 0 if batched, 1 if batch was shuffled and delivered, negative on error.
 */
int dap_chain_mixnet_consensus_submit(dap_chain_mixnet_consensus_ctx_t *ctx,
                                       const uint8_t *sig, size_t sig_size,
                                       void (*on_ready)(const uint8_t **sigs,
                                                        const size_t *sizes,
                                                        uint32_t count,
                                                        void *user_data),
                                       void *user_data);

/**
 * Force shuffle and deliver current batch (e.g., on timeout).
 * @param ctx Mixnet context.
 * @param on_ready Callback when batch is ready.
 * @param user_data User data for callback.
 * @return 0 on success, negative on error.
 */
int dap_chain_mixnet_consensus_flush(dap_chain_mixnet_consensus_ctx_t *ctx,
                                      void (*on_ready)(const uint8_t **sigs,
                                                       const size_t *sizes,
                                                       uint32_t count,
                                                       void *user_data),
                                      void *user_data);

/**
 * Free mixnet context.
 */
void dap_chain_mixnet_consensus_free(dap_chain_mixnet_consensus_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

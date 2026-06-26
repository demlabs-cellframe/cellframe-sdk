/*
 * dap_chain_mixnet_consensus.c — Mixnet integration for consensus metadata protection.
 *
 * Wraps signature submission through a shuffled batch to prevent
 * timing/network-based deanonymization of validators.
 */

#include "dap_chain_mixnet_consensus.h"
#include "chipmunk_mixnet.h"
#include "dap_common.h"
#include "dap_rand.h"

#include <string.h>
#include <errno.h>
#include <pthread.h>

#define LOG_TAG "mixnet_consensus"

int dap_chain_mixnet_consensus_init(dap_chain_mixnet_consensus_ctx_t *ctx,
                                     const dap_chain_mixnet_consensus_config_t *config)
{
    if (!ctx || !config) return -EINVAL;
    if (config->max_batch_size > CHIPMUNK_MIXNET_MAX_PARTICIPANTS) return -EINVAL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->config = *config;

    int rc = chipmunk_mixnet_batch_init(&ctx->batch, config->max_batch_size);
    if (rc != 0) return rc;

    pthread_mutex_init(&ctx->mutex, NULL);
    ctx->initialized = true;

    log_it(L_INFO, "Mixnet consensus initialized: min=%u max=%u timeout=%ums",
           config->min_batch_size, config->max_batch_size, config->batch_timeout_ms);
    return 0;
}

int dap_chain_mixnet_consensus_submit(dap_chain_mixnet_consensus_ctx_t *ctx,
                                       const uint8_t *sig, size_t sig_size,
                                       void (*on_ready)(const uint8_t **sigs,
                                                        const size_t *sizes,
                                                        uint32_t count,
                                                        void *user_data),
                                       void *user_data)
{
    if (!ctx || !sig || !on_ready) return -EINVAL;
    if (!ctx->initialized) return -EINVAL;

    pthread_mutex_lock(&ctx->mutex);

    /* Add signature to batch */
    int rc = chipmunk_mixnet_batch_add(&ctx->batch, sig, sig_size);
    if (rc == -EAGAIN) {
        /* Batch full — shuffle and deliver */
        chipmunk_mixnet_batch_shuffle(&ctx->batch);
        on_ready((const uint8_t **)ctx->batch.signatures,
                 ctx->batch.sig_sizes,
                 ctx->batch.count,
                 user_data);
        /* Reset batch */
        chipmunk_mixnet_batch_free(&ctx->batch);
        chipmunk_mixnet_batch_init(&ctx->batch, ctx->config.max_batch_size);
        /* Add current signature to new batch */
        chipmunk_mixnet_batch_add(&ctx->batch, sig, sig_size);
        pthread_mutex_unlock(&ctx->mutex);
        return 1; /* Batch delivered */
    }

    /* Check if minimum batch size reached */
    if (ctx->batch.count >= ctx->config.min_batch_size) {
        /* Randomly decide to flush (probabilistic batching) */
        uint32_t l_rand;
        dap_random_bytes((uint8_t *)&l_rand, sizeof(l_rand));
        /* Probability of flush increases with batch size */
        uint32_t l_threshold = UINT32_MAX / (ctx->config.max_batch_size - ctx->config.min_batch_size + 1);
        if (ctx->batch.count >= ctx->config.min_batch_size &&
            l_rand < l_threshold * (ctx->batch.count - ctx->config.min_batch_size + 1)) {
            chipmunk_mixnet_batch_shuffle(&ctx->batch);
            on_ready((const uint8_t **)ctx->batch.signatures,
                     ctx->batch.sig_sizes,
                     ctx->batch.count,
                     user_data);
            chipmunk_mixnet_batch_free(&ctx->batch);
            chipmunk_mixnet_batch_init(&ctx->batch, ctx->config.max_batch_size);
            pthread_mutex_unlock(&ctx->mutex);
            return 1; /* Batch delivered */
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
    return 0; /* Batched */
}

int dap_chain_mixnet_consensus_flush(dap_chain_mixnet_consensus_ctx_t *ctx,
                                      void (*on_ready)(const uint8_t **sigs,
                                                       const size_t *sizes,
                                                       uint32_t count,
                                                       void *user_data),
                                      void *user_data)
{
    if (!ctx || !on_ready) return -EINVAL;
    if (!ctx->initialized) return -EINVAL;

    pthread_mutex_lock(&ctx->mutex);

    if (ctx->batch.count == 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return 0; /* Nothing to flush */
    }

    chipmunk_mixnet_batch_shuffle(&ctx->batch);
    on_ready((const uint8_t **)ctx->batch.signatures,
             ctx->batch.sig_sizes,
             ctx->batch.count,
             user_data);

    chipmunk_mixnet_batch_free(&ctx->batch);
    chipmunk_mixnet_batch_init(&ctx->batch, ctx->config.max_batch_size);

    pthread_mutex_unlock(&ctx->mutex);
    return 1; /* Batch delivered */
}

void dap_chain_mixnet_consensus_free(dap_chain_mixnet_consensus_ctx_t *ctx)
{
    if (!ctx || !ctx->initialized) return;
    chipmunk_mixnet_batch_free(&ctx->batch);
    pthread_mutex_destroy(&ctx->mutex);
    ctx->initialized = false;
}

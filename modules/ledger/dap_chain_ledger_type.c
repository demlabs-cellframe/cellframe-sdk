/*
 * dap_chain_ledger_type.c — Ledger type abstraction implementation.
 *
 * Registers built-in ledger types (open/anon) and provides dispatch
 * to type-specific TX verification and processing.
 *
 * Anonymous backend: SNARK ring membership proof + key image double-spend
 * prevention + Pedersen commitments for confidential amounts.
 */

#include "dap_chain_ledger_type.h"
#include "dap_chain_ledger_anon_ctx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_datum_tx_anon.h"
#include "dap_chain_datum_tx.h"
#include "chipmunk_snark.h"
#include "chipmunk_pedersen.h"
#include "chipmunk_range_proof.h"
#include "chipmunk.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_memwipe.h"

#include <string.h>
#include <errno.h>

#define LOG_TAG "ledger_type"

/* Registry */
#define DAP_LEDGER_TYPE_MAX_REGISTERED 16
static dap_ledger_type_desc_t s_type_registry[DAP_LEDGER_TYPE_MAX_REGISTERED];
static size_t s_type_count = 0;
static bool s_initialized = false;

/* -------------------------------------------------------------------------
 * Built-in: Open (UTXO) ledger
 * ---------------------------------------------------------------------- */

/* Open ledger uses the existing UTXO implementation directly.
 * These callbacks are thin wrappers that dispatch to the existing code. */

static int s_open_tx_check(dap_ledger_t *a_ledger,
                            dap_chain_datum_tx_t *a_tx,
                            size_t a_tx_size,
                            dap_hash_fast_t *a_tx_hash)
{
    (void)a_tx_size;
    return dap_ledger_tx_utxo_check(a_ledger, a_tx, a_tx_hash, true);
}

static int s_open_tx_add(dap_ledger_t *a_ledger,
                          dap_chain_datum_tx_t *a_tx,
                          dap_hash_fast_t *a_tx_hash)
{
    /* No type-specific add needed: UTXO state is updated in the shared dap_ledger_tx_add_impl() path */
    (void)a_ledger;
    (void)a_tx;
    (void)a_tx_hash;
    return 0;
}

static int s_open_tx_remove(dap_ledger_t *a_ledger,
                             dap_hash_fast_t *a_tx_hash)
{
    /* No type-specific cleanup needed: UTXO rollback is handled by the shared dap_ledger_tx_remove() */
    (void)a_ledger; (void)a_tx_hash;
    return 0;
}

static int s_open_calc_balance(dap_ledger_t *a_ledger,
                                const dap_chain_addr_t *a_addr,
                                const char *a_token_ticker,
                                uint256_t *a_balance)
{
    *a_balance = dap_ledger_calc_balance(a_ledger, a_addr, a_token_ticker);
    return 0;
}

static int s_open_emission_check(dap_ledger_t *a_ledger,
                                  dap_chain_datum_token_emission_t *a_emission,
                                  size_t a_emission_size)
{
    /* Delegate to existing emission check */
    return dap_ledger_token_emission_add_check(a_ledger, (byte_t *)a_emission, a_emission_size, NULL);
}

/* -------------------------------------------------------------------------
 * Built-in: Anonymous (SNARK) ledger
 * ---------------------------------------------------------------------- */

/* Key image and anon context types are in dap_chain_ledger_anon_ctx.h */

/* Initialize anonymous context */
static dap_ledger_anon_ctx_t *s_anon_ctx_new(const char *a_ledger_name)
{
    dap_ledger_anon_ctx_t *ctx = DAP_NEW_Z(dap_ledger_anon_ctx_t);
    if (!ctx) return NULL;

    if (a_ledger_name)
        ctx->ledger_name = dap_strdup(a_ledger_name);

    /* Initialize SNARK context */
    if (chipmunk_snark_init(&ctx->snark_ctx) != 0) {
        log_it(L_ERROR, "Failed to initialize SNARK context");
        DAP_DELETE(ctx);
        return NULL;
    }

    /* Initialize Pedersen parameters from fixed seed */
    uint8_t l_seed[32] = "chipchain-pedersen-params-v1";
    if (chipmunk_pedersen_init(&ctx->pedersen_params, l_seed) != 0) {
        log_it(L_ERROR, "Failed to initialize Pedersen parameters");
        chipmunk_snark_ctx_free(&ctx->snark_ctx);
        DAP_DELETE(ctx);
        return NULL;
    }

    pthread_rwlock_init(&ctx->key_images_rwlock, NULL);
    return ctx;
}

/* Free anonymous context */
static void s_anon_ctx_free(dap_ledger_anon_ctx_t *ctx)
{
    if (!ctx) return;
    /* Wipe SNARK context (contains secrets) */
    chipmunk_snark_ctx_free(&ctx->snark_ctx);
    /* Free key image hash table */
    dap_ledger_anon_key_image_t *l_item, *l_tmp;
    dap_ht_foreach(ctx->key_images, l_item, l_tmp) {
        dap_ht_del(ctx->key_images, l_item);
        DAP_DELETE(l_item);
    }
    pthread_rwlock_destroy(&ctx->key_images_rwlock);
    DAP_DELETE(ctx->ledger_name);
    DAP_DELETE(ctx);
}

static int s_key_image_gdb_persist(dap_ledger_t *a_ledger,
                                    const dap_chain_hash_fast_t *a_image_hash,
                                    const dap_chain_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !is_ledger_cached(PVT(a_ledger)))
        return 0;

    char *l_group = dap_ledger_get_gdb_group(a_ledger->name, DAP_LEDGER_KEY_IMAGES_STR);
    char l_key_str[DAP_HASH_SHA3_256_STR_SIZE];
    dap_hash_fast_to_str(a_image_hash, l_key_str, sizeof(l_key_str));
    int l_rc = dap_global_db_set(l_group, l_key_str, (byte_t *)a_tx_hash, sizeof(*a_tx_hash), false, NULL, NULL);
    DAP_DELETE(l_group);
    return l_rc ? -EIO : 0;
}

static void s_key_image_gdb_remove(dap_ledger_t *a_ledger,
                                    const dap_chain_hash_fast_t *a_image_hash)
{
    if (!a_ledger || !is_ledger_cached(PVT(a_ledger)))
        return;

    char *l_group = dap_ledger_get_gdb_group(a_ledger->name, DAP_LEDGER_KEY_IMAGES_STR);
    char l_key_str[DAP_HASH_SHA3_256_STR_SIZE];
    dap_hash_fast_to_str(a_image_hash, l_key_str, sizeof(l_key_str));
    dap_global_db_del(l_group, l_key_str, NULL, NULL);
    DAP_DELETE(l_group);
}

/* Add key image to tracking — atomic check-and-add under write lock
 * to prevent TOCTOU race between check and insertion. */
static int s_key_image_add(dap_ledger_anon_ctx_t *ctx,
                            const dap_chain_hash_fast_t *image_hash,
                            const dap_chain_hash_fast_t *tx_hash,
                            dap_ledger_t *a_ledger,
                            bool a_persist)
{
    dap_ledger_anon_key_image_t *l_item = DAP_NEW_Z(dap_ledger_anon_key_image_t);
    if (!l_item) return -ENOMEM;

    l_item->image_hash = *image_hash;
    l_item->tx_hash = *tx_hash;

    pthread_rwlock_wrlock(&ctx->key_images_rwlock);
    /* Check under write lock — atomic with insert */
    dap_ledger_anon_key_image_t *l_existing = NULL;
    dap_ht_find(ctx->key_images, image_hash, sizeof(dap_chain_hash_fast_t), l_existing);
    if (l_existing) {
        pthread_rwlock_unlock(&ctx->key_images_rwlock);
        DAP_DELETE(l_item);
        return -EEXIST; /* Double-spend attempt */
    }
    dap_ht_add(ctx->key_images, image_hash, l_item);
    pthread_rwlock_unlock(&ctx->key_images_rwlock);

    if (a_persist && a_ledger) {
        int l_gdb_rc = s_key_image_gdb_persist(a_ledger, image_hash, tx_hash);
        if (l_gdb_rc != 0) {
            pthread_rwlock_wrlock(&ctx->key_images_rwlock);
            dap_ht_del(ctx->key_images, l_item);
            pthread_rwlock_unlock(&ctx->key_images_rwlock);
            DAP_DELETE(l_item);
            return l_gdb_rc;
        }
    }

    return 0;
}

/* Remove key image from tracking (TX rollback) */
static void s_key_image_remove(dap_ledger_anon_ctx_t *ctx,
                                const dap_chain_hash_fast_t *image_hash,
                                dap_ledger_t *a_ledger,
                                bool a_persist)
{
    pthread_rwlock_wrlock(&ctx->key_images_rwlock);
    dap_ledger_anon_key_image_t *l_item = NULL;
    dap_ht_find(ctx->key_images, image_hash, sizeof(dap_chain_hash_fast_t), l_item);
    if (l_item) {
        dap_ht_del(ctx->key_images, l_item);
        DAP_DELETE(l_item);
        if (a_persist && a_ledger)
            s_key_image_gdb_remove(a_ledger, image_hash);
    }
    pthread_rwlock_unlock(&ctx->key_images_rwlock);
}

static int s_key_image_check_unused(dap_ledger_anon_ctx_t *ctx,
                                    const dap_chain_hash_fast_t *image_hash)
{
    dap_ledger_anon_key_image_t *l_existing = NULL;

    pthread_rwlock_rdlock(&ctx->key_images_rwlock);
    dap_ht_find(ctx->key_images, image_hash, sizeof(dap_chain_hash_fast_t), l_existing);
    pthread_rwlock_unlock(&ctx->key_images_rwlock);
    return l_existing ? -EEXIST : 0;
}

static int s_anon_tx_key_images_commit(dap_ledger_anon_ctx_t *a_anon,
                                       dap_chain_datum_tx_t *a_tx,
                                       const dap_hash_fast_t *a_tx_hash,
                                       dap_ledger_t *a_ledger)
{
    const dap_chain_tx_key_image_t **l_images = NULL;
    size_t l_image_count = 0;
    int l_rc = dap_chain_datum_tx_get_key_images(a_tx->tx_items, dap_chain_datum_tx_get_size(a_tx),
                                                 &l_images, &l_image_count);
    if (l_rc != 0) {
        DAP_DELETE(l_images);
        return l_rc;
    }

    /* Track committed images for rollback on partial failure */
    size_t l_committed = 0;
    dap_chain_hash_fast_t *l_committed_hashes = l_image_count > 0
        ? DAP_NEW_Z_COUNT(dap_chain_hash_fast_t, l_image_count)
        : NULL;

    for (size_t i = 0; i < l_image_count; ++i) {
        dap_chain_hash_fast_t l_image_hash;
        dap_hash_fast(l_images[i]->image, sizeof(l_images[i]->image), &l_image_hash);

        l_rc = s_key_image_add(a_anon, &l_image_hash, a_tx_hash, a_ledger, true);
        if (l_rc != 0) {
            log_it(L_WARNING, "Failed to commit key image %zu/%zu: %d, rolling back %zu committed",
                   i, l_image_count, l_rc, l_committed);
            /* Rollback: remove all previously committed KIs for this TX */
            for (size_t j = 0; j < l_committed; ++j)
                s_key_image_remove(a_anon, &l_committed_hashes[j], a_ledger, true);
            DAP_DEL_MULTY(l_committed_hashes, l_images);
            return l_rc;
        }
        if (l_committed_hashes)
            l_committed_hashes[l_committed++] = l_image_hash;
    }
    DAP_DEL_MULTY(l_committed_hashes, l_images);
    return 0;
}

/* -------------------------------------------------------------------------
 * Anonymous TX verification
 * ---------------------------------------------------------------------- */

bool dap_ledger_pedersen_commit_equal(const chipmunk_pedersen_commit_t *a_lhs,
                                       const chipmunk_pedersen_commit_t *a_rhs)
{
    if (!a_lhs || !a_rhs)
        return false;

    for (uint32_t i = 0; i < CHIPMUNK_PEDERSEN_K; ++i) {
        for (uint32_t k = 0; k < CHIPMUNK_N; ++k) {
            int32_t l_diff = a_lhs->C[i].coeffs[k] - a_rhs->C[i].coeffs[k];
            l_diff %= CHIPMUNK_Q;
            if (l_diff < 0)
                l_diff += CHIPMUNK_Q;
            if (l_diff != 0)
                return false;
        }
    }
    return true;
}

static int s_anon_pedersen_conservation_verify(dap_ledger_t *a_ledger,
                                             dap_ledger_anon_ctx_t *a_anon,
                                             dap_chain_datum_tx_t *a_tx)
{
    const dap_chain_tx_in_anon_t *l_in_anon = NULL;
    {
        const uint8_t *l_item;
        size_t l_item_size;
        TX_ITEM_ITER_TX(l_item, l_item_size, a_tx) {
            if (*l_item == TX_ITEM_TYPE_IN_ANON) {
                l_in_anon = (const dap_chain_tx_in_anon_t *)l_item;
                break;
            }
        }
    }
    if (!l_in_anon)
        return -EINVAL;

    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger,
        (const dap_hash_sha3_256_t *)&l_in_anon->prev_hash);
    if (!l_prev_tx)
        return -EINVAL;

    void *l_prev_out = dap_chain_datum_tx_item_get_nth(l_prev_tx, TX_ITEM_TYPE_OUT_ALL,
                                                       l_in_anon->prev_out_idx);
    if (!l_prev_out)
        return -EINVAL;

    chipmunk_pedersen_commit_t l_input_commit;
    memset(&l_input_commit, 0, sizeof(l_input_commit));

    switch (*(uint8_t *)l_prev_out) {
    case TX_ITEM_TYPE_OUT_STD: {
        const dap_chain_tx_out_std_t *l_out = (const dap_chain_tx_out_std_t *)l_prev_out;
        uint8_t l_seed[32], l_amount[CHIPMUNK_PEDERSEN_VALUE_BYTES];
        dap_chain_anon_input_commit_seed(l_seed, &l_in_anon->prev_hash, l_in_anon->prev_out_idx);
        memset(l_amount, 0, sizeof(l_amount));
        memcpy(l_amount, &l_out->value, sizeof(l_out->value));
        if (chipmunk_pedersen_commit(&l_input_commit, &a_anon->pedersen_params,
                                     l_amount, l_seed) != 0)
            return -EINVAL;
    } break;
    case TX_ITEM_TYPE_OUT_EXT: {
        const dap_chain_tx_out_ext_t *l_out = (const dap_chain_tx_out_ext_t *)l_prev_out;
        uint8_t l_seed[32], l_amount[CHIPMUNK_PEDERSEN_VALUE_BYTES];
        dap_chain_anon_input_commit_seed(l_seed, &l_in_anon->prev_hash, l_in_anon->prev_out_idx);
        memset(l_amount, 0, sizeof(l_amount));
        memcpy(l_amount, &l_out->header.value, sizeof(l_out->header.value));
        if (chipmunk_pedersen_commit(&l_input_commit, &a_anon->pedersen_params,
                                     l_amount, l_seed) != 0)
            return -EINVAL;
    } break;
    case TX_ITEM_TYPE_OUT_ANON: {
        const dap_chain_tx_out_anon_t *l_out = (const dap_chain_tx_out_anon_t *)l_prev_out;
        memcpy(&l_input_commit, &l_out->commitment, sizeof(l_input_commit));
    } break;
    default:
        log_it(L_WARNING, "Anonymous TX spends unsupported output type 0x%02x", *(uint8_t *)l_prev_out);
        return -EINVAL;
    }

    chipmunk_pedersen_commit_t l_outputs_sum;
    memset(&l_outputs_sum, 0, sizeof(l_outputs_sum));
    bool l_has_out_anon = false;

    {
        const uint8_t *l_item;
        size_t l_item_size;
        TX_ITEM_ITER_TX(l_item, l_item_size, a_tx) {
            if (*l_item == TX_ITEM_TYPE_OUT_ANON) {
                const dap_chain_tx_out_anon_t *l_out = (const dap_chain_tx_out_anon_t *)l_item;
                chipmunk_pedersen_commit_t l_out_commit;
                memcpy(&l_out_commit, &l_out->commitment, sizeof(l_out_commit));
                if (!l_has_out_anon) {
                    memcpy(&l_outputs_sum, &l_out_commit, sizeof(l_outputs_sum));
                    l_has_out_anon = true;
                } else {
                    chipmunk_pedersen_add(&l_outputs_sum, &l_outputs_sum, &l_out_commit);
                }
            }
        }
    }

    if (!l_has_out_anon || !dap_ledger_pedersen_commit_equal(&l_input_commit, &l_outputs_sum)) {
        log_it(L_WARNING, "Pedersen conservation check failed for anonymous TX");
        return -EINVAL;
    }
    return 0;
}

static int s_anon_tx_crypto_verify(dap_ledger_t *a_ledger,
                                    dap_chain_datum_tx_t *a_tx,
                                    dap_hash_fast_t *a_tx_hash,
                                    bool a_commit_key_images)
{
    if (!a_ledger || !a_tx || !a_tx_hash) return -EINVAL;

    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)l_pvt->anon_data;
    if (!l_anon) {
        log_it(L_ERROR, "Anonymous context not initialized");
        return -EINVAL;
    }

    int l_rc = 0;

    /* Verify SNARK ring membership proofs from IN_ANON items.
     * Proofs are embedded in IN_ANON items (not standalone ANON_PROOF items).
     * Ring public keys follow the IN_ANON struct as variable-length data.
     *
     * SECURITY: Ring membership is verified through the quotient relation:
     *   z(tp) == q(tp) * (tp - alpha) at 11 random test points.
     * The constraint polynomial z(X) encodes:
     *   C1: b*(b-1) = 0        (binary indicator)
     *   C2: sum(b_i) = 1       (exactly one signer)
     *   C3: sum(b_i*H(pk_i)) = H(pk_signer)  (ring membership)
     *   C4: sum(b_i*trace(pk_i)) = trace(pk_signer)  (lattice binding)
     * z(alpha)=0 at random alpha implies each Ci(alpha)=0 with high probability.
     * 11 quotient checks × ~12.6 bits each = ~138 bits soundness (≥128-bit target).
     *
     * FRI verification: the verifier re-derives the FRI folding chain from z
     * polynomial and checks all 7 layer commitments + final polynomial.
     * Combined soundness: FRI (~900 bits) + quotient (~138 bits) >> 128 bits.
     */
    const uint8_t *l_item_snark;
    size_t l_item_size_snark;
    bool l_found_anon_in = false;

    TX_ITEM_ITER_TX(l_item_snark, l_item_size_snark, a_tx) {
        uint8_t l_type_snark = *l_item_snark;
        if (l_type_snark == TX_ITEM_TYPE_IN_ANON) {
            const dap_chain_tx_in_anon_t *l_in_anon = (const dap_chain_tx_in_anon_t *)l_item_snark;
            l_found_anon_in = true;

            /* Build statement from IN_ANON metadata and embedded ring */
            chipmunk_snark_statement_t l_statement;
            memset(&l_statement, 0, sizeof(l_statement));
            l_statement.ring_size = l_in_anon->ring_size;

            /* Extract ring public keys from variable-length data after the struct */
            size_t l_ring_data_bytes = l_in_anon->hdr.size - sizeof(dap_chain_tx_in_anon_t);
            if (l_in_anon->ring_size > 0 && l_ring_data_bytes >= l_in_anon->ring_size) {
                l_statement.ring = (const chipmunk_lrs_public_key_t *)(l_item_snark + sizeof(dap_chain_tx_in_anon_t));
            }

            /* Reconstruct message: addr_to || commit_hash || ticker || ki_hash || rp_hash
             * Must match the prover's construction exactly. */
            const dap_chain_tx_out_anon_t *l_out_anon = NULL;
            {
                const uint8_t *l_scan_item;
                size_t l_scan_size;
                TX_ITEM_ITER_TX(l_scan_item, l_scan_size, a_tx) {
                    if (*l_scan_item == TX_ITEM_TYPE_OUT_ANON) {
                        l_out_anon = (const dap_chain_tx_out_anon_t *)l_scan_item;
                        break;
                    }
                }
            }
            if (!l_out_anon) {
                log_it(L_WARNING, "IN_ANON has no matching OUT_ANON");
                return -EINVAL;
            }

            dap_hash_sha3_256_t l_ver_ki_hash;
            dap_hash_sha3_256_raw(l_ver_ki_hash.raw, l_in_anon->key_image, sizeof(l_in_anon->key_image));

            chipmunk_range_proof_t l_ver_rp;
            memcpy(&l_ver_rp, &l_out_anon->range_proof, sizeof(l_ver_rp));
            dap_hash_sha3_256_t l_ver_rp_hash;
            dap_hash_sha3_256_raw(l_ver_rp_hash.raw, (const uint8_t *)&l_ver_rp, sizeof(l_ver_rp));

            chipmunk_pedersen_commit_t l_ver_commit;
            memcpy(&l_ver_commit, &l_out_anon->commitment, sizeof(l_ver_commit));
            dap_hash_sha3_256_t l_ver_commit_hash;
            dap_hash_sha3_256_raw(l_ver_commit_hash.raw, (const uint8_t *)&l_ver_commit, sizeof(l_ver_commit));

            uint8_t l_msg_buf[sizeof(dap_chain_addr_t) + 32 + DAP_CHAIN_TICKER_SIZE_MAX + 32 + 32];
            ssize_t l_msg_size = dap_chain_anon_snark_build_message(
                l_msg_buf, sizeof(l_msg_buf),
                &l_out_anon->addr, &l_ver_commit_hash,
                l_out_anon->token_ticker, &l_ver_ki_hash, &l_ver_rp_hash);
            if (l_msg_size < 0) {
                log_it(L_WARNING, "SNARK message build failed: %zd", l_msg_size);
                return -EINVAL;
            }
            l_statement.message = l_msg_buf;
            l_statement.message_size = (size_t)l_msg_size;

            /* Verify SNARK proof (copy from packed struct to avoid alignment issues) */
            chipmunk_snark_proof_t l_proof_copy;
            memcpy(&l_proof_copy, &l_in_anon->snark_proof, sizeof(l_proof_copy));
            l_rc = chipmunk_snark_verify(&l_proof_copy, &l_anon->snark_ctx, &l_statement);
            if (l_rc != 1) {
                log_it(L_WARNING, "SNARK proof verification failed for IN_ANON: %d", l_rc);
                return -EINVAL;
            }
        }
    }

    if (!l_found_anon_in) {
        log_it(L_WARNING, "Anonymous TX has no IN_ANON items with SNARK proofs");
        return -EINVAL;
    }

    /* 3. Check key images for double-spend prevention */
    const dap_chain_tx_key_image_t **l_images = NULL;
    size_t l_image_count = 0;
    l_rc = dap_chain_datum_tx_get_key_images(a_tx->tx_items, dap_chain_datum_tx_get_size(a_tx), &l_images, &l_image_count);
    if (l_rc != 0) {
        DAP_DELETE(l_images);
        return l_rc;
    }

    for (size_t i = 0; i < l_image_count; ++i) {
        dap_chain_hash_fast_t l_image_hash;
        dap_hash_fast(l_images[i]->image, sizeof(l_images[i]->image), &l_image_hash);

        int l_ki_rc;
        if (a_commit_key_images)
            l_ki_rc = s_key_image_add(l_anon, &l_image_hash, a_tx_hash, a_ledger, true);
        else
            l_ki_rc = s_key_image_check_unused(l_anon, &l_image_hash);

        if (l_ki_rc == -EEXIST) {
            log_it(L_WARNING, "Double-spend attempt detected: key image already used");
            DAP_DELETE(l_images);
            return -EINVAL;
        } else if (l_ki_rc != 0) {
            log_it(L_WARNING, "Key image check failed: %d", l_ki_rc);
            DAP_DELETE(l_images);
            return l_ki_rc;
        }
    }
    DAP_DELETE(l_images);

    /* 4. Verify Pedersen commitments and range proofs on outputs */
    {
        const uint8_t *l_item;
        size_t l_item_size;
        TX_ITEM_ITER_TX(l_item, l_item_size, a_tx) {
            if (*l_item == TX_ITEM_TYPE_OUT_ANON) {
                const dap_chain_tx_out_anon_t *l_out = (const dap_chain_tx_out_anon_t *)l_item;

                /* Verify range proof (copy from packed struct to avoid alignment issues) */
                chipmunk_range_proof_t l_rp_copy;
                chipmunk_pedersen_commit_t l_commit_copy;
                memcpy(&l_rp_copy, &l_out->range_proof, sizeof(l_rp_copy));
                memcpy(&l_commit_copy, &l_out->commitment, sizeof(l_commit_copy));
                l_rc = chipmunk_range_proof_verify(&l_rp_copy,
                                                    &l_anon->pedersen_params,
                                                    &l_commit_copy);
                if (l_rc != 1) {
                    log_it(L_WARNING, "Range proof verification failed for anonymous output");
                    return -EINVAL;
                }
            }
        }
    }

    l_rc = s_anon_pedersen_conservation_verify(a_ledger, l_anon, a_tx);
    if (l_rc != 0)
        return l_rc;

    return 0; /* Valid anonymous TX */
}

int dap_ledger_anon_tx_verify(dap_ledger_t *a_ledger,
                              dap_chain_datum_tx_t *a_tx,
                              dap_hash_fast_t *a_tx_hash)
{
    return s_anon_tx_crypto_verify(a_ledger, a_tx, a_tx_hash, false);
}

int dap_ledger_anon_tx_key_images_commit(dap_ledger_t *a_ledger,
                                         dap_chain_datum_tx_t *a_tx,
                                         dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx || !a_tx_hash)
        return -EINVAL;

    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)l_pvt->anon_data;
    if (!l_anon) {
        log_it(L_ERROR, "Anonymous context not initialized");
        return -EINVAL;
    }

    return s_anon_tx_key_images_commit(l_anon, a_tx, a_tx_hash, a_ledger);
}

/**
 * Anon ledger TX check orchestrator (WS-B4).
 * Plain TX  → full UTXO cache check (001 bootstrap canary).
 * Anon TX   → UTXO structural + SNARK/range/KI verify + Pedersen conservation.
 */
static int s_anon_tx_check(dap_ledger_t *a_ledger,
                            dap_chain_datum_tx_t *a_tx,
                            size_t a_tx_size,
                            dap_hash_fast_t *a_tx_hash)
{
    (void)a_tx_size;

    if (!a_ledger || !a_tx || !a_tx_hash)
        return DAP_LEDGER_CHECK_INVALID_ARGS;

    if (!PVT(a_ledger)->anon_data) {
        log_it(L_ERROR, "Anonymous ledger '%s' has no anon context", a_ledger->name);
        return DAP_LEDGER_CHECK_INVALID_ARGS;
    }

    int l_rc = dap_ledger_tx_utxo_check(a_ledger, a_tx, a_tx_hash, true);
    if (l_rc)
        return l_rc;

    if (dap_chain_datum_tx_is_anonymous((const uint8_t *)a_tx->tx_items, a_tx->header.tx_items_size))
        return dap_ledger_anon_tx_verify(a_ledger, a_tx, a_tx_hash);

    return DAP_LEDGER_CHECK_OK;
}

static int s_anon_tx_add(dap_ledger_t *a_ledger,
                          dap_chain_datum_tx_t *a_tx,
                          dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx || !a_tx_hash)
        return -EINVAL;

    if (!PVT(a_ledger)->anon_data) {
        log_it(L_ERROR, "Anonymous ledger '%s' has no anon context", a_ledger->name);
        return -EINVAL;
    }

    if (!dap_chain_datum_tx_is_anonymous((const uint8_t *)a_tx->tx_items, a_tx->header.tx_items_size))
        return 0;

    return dap_ledger_anon_tx_key_images_commit(a_ledger, a_tx, a_tx_hash);
}

int dap_ledger_type_tx_add_commit(dap_ledger_t *a_ledger,
                                  dap_chain_datum_tx_t *a_tx,
                                  dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx || !a_tx_hash)
        return -EINVAL;

    const dap_ledger_type_desc_t *l_desc =
        dap_ledger_type_get_by_enum((dap_ledger_type_t)PVT(a_ledger)->ledger_type);
    if (l_desc && l_desc->tx_add)
        return l_desc->tx_add(a_ledger, a_tx, a_tx_hash);
    return 0;
}

int dap_ledger_type_tx_remove_commit(dap_ledger_t *a_ledger,
                                      dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx_hash)
        return -EINVAL;

    const dap_ledger_type_desc_t *l_desc =
        dap_ledger_type_get_by_enum((dap_ledger_type_t)PVT(a_ledger)->ledger_type);
    if (l_desc && l_desc->tx_remove)
        return l_desc->tx_remove(a_ledger, a_tx_hash);
    return 0;
}

static int s_anon_tx_remove(dap_ledger_t *a_ledger,
                             dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx_hash) return -EINVAL;

    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)l_pvt->anon_data;

    /* Find and remove key images associated with this TX */
    if (l_anon) {
        /* We need to find which key images were in this TX.
         * Since we stored the tx_hash with each key image, we can search. */
        dap_ledger_anon_key_image_t *l_item, *l_tmp;
        pthread_rwlock_wrlock(&l_anon->key_images_rwlock);
        dap_ht_foreach(l_anon->key_images, l_item, l_tmp) {
            if (dap_hash_fast_compare(&l_item->tx_hash, a_tx_hash)) {
                if (a_ledger)
                    s_key_image_gdb_remove(a_ledger, &l_item->image_hash);
                dap_ht_del(l_anon->key_images, l_item);
                DAP_DELETE(l_item);
            }
        }
        pthread_rwlock_unlock(&l_anon->key_images_rwlock);
    }

    return 0;
}

static int s_anon_calc_balance(dap_ledger_t *a_ledger,
                                const dap_chain_addr_t *a_addr,
                                const char *a_token_ticker,
                                uint256_t *a_balance)
{
    /* Anonymous balance: the balance is committed via Pedersen commitments.
     * The actual value is hidden — only the commitment is stored.
     * To reveal the balance, use dap_chain_tx_anon_reveal_balance()
     * with the commitment randomness seed. */
    *a_balance = uint256_0;
    return 0;
}

static int s_anon_emission_check(dap_ledger_t *a_ledger,
                                  dap_chain_datum_token_emission_t *a_emission,
                                  size_t a_emission_size)
{
    /* Emissions are still transparent in anonymous mode.
     * The emission creates the initial Pedersen commitment. */
    return dap_ledger_token_emission_add_check(a_ledger, (byte_t *)a_emission, a_emission_size, NULL);
}

/* -------------------------------------------------------------------------
 * Registry
 * ---------------------------------------------------------------------- */

static const dap_ledger_type_desc_t s_builtin_types[] = {
    {
        .type = DAP_LEDGER_TYPE_OPEN,
        .name = "open",
        .anon_type = 0,
        .description = "Standard transparent UTXO ledger",
        .tx_check = s_open_tx_check,
        .tx_add = s_open_tx_add,
        .tx_remove = s_open_tx_remove,
        .calc_balance = s_open_calc_balance,
        .emission_check = s_open_emission_check,
    },
    {
        .type = DAP_LEDGER_TYPE_ANON,
        .name = "anon",
        .anon_type = DAP_LEDGER_ANON_CHIPMUNK_SNARK,
        .description = "Anonymous ledger with Chipmunk SNARK ring proofs",
        .tx_check = s_anon_tx_check,
        .tx_add = s_anon_tx_add,
        .tx_remove = s_anon_tx_remove,
        .calc_balance = s_anon_calc_balance,
        .emission_check = s_anon_emission_check,
    },
};

int dap_ledger_type_init(void)
{
    if (s_initialized) return 0;

    /* Register built-in types */
    for (size_t i = 0; i < sizeof(s_builtin_types) / sizeof(s_builtin_types[0]); ++i) {
        s_type_registry[s_type_count++] = s_builtin_types[i];
    }

    s_initialized = true;
    log_it(L_INFO, "Ledger type system initialized: %zu types registered", s_type_count);
    return 0;
}

void dap_ledger_type_deinit(void)
{
    s_type_count = 0;
    s_initialized = false;
}

int dap_ledger_type_register(const dap_ledger_type_desc_t *a_desc)
{
    if (!a_desc || !a_desc->name) return -EINVAL;
    if (s_type_count >= DAP_LEDGER_TYPE_MAX_REGISTERED) return -ENOMEM;

    /* Check for duplicate */
    for (size_t i = 0; i < s_type_count; ++i) {
        if (strcmp(s_type_registry[i].name, a_desc->name) == 0) {
            return -EEXIST;
        }
    }

    s_type_registry[s_type_count++] = *a_desc;
    log_it(L_INFO, "Registered ledger type: %s", a_desc->name);
    return 0;
}

const dap_ledger_type_desc_t *dap_ledger_type_get(const char *a_name)
{
    dap_ledger_type_init();
    if (!a_name) return NULL;
    for (size_t i = 0; i < s_type_count; ++i) {
        if (strcmp(s_type_registry[i].name, a_name) == 0) {
            return &s_type_registry[i];
        }
    }
    return NULL;
}

const dap_ledger_type_desc_t *dap_ledger_type_get_by_enum(dap_ledger_type_t a_type)
{
    dap_ledger_type_init();
    for (size_t i = 0; i < s_type_count; ++i) {
        if (s_type_registry[i].type == a_type) {
            return &s_type_registry[i];
        }
    }
    return NULL;
}

dap_ledger_type_t dap_ledger_type_from_config(dap_config_t *a_config,
                                               dap_ledger_anon_type_t *a_anon_type)
{
    if (!a_anon_type) return DAP_LEDGER_TYPE_OPEN;

    *a_anon_type = DAP_LEDGER_ANON_CHIPMUNK_SNARK;  /* default */

    if (!a_config) return DAP_LEDGER_TYPE_OPEN;

    const char *l_type_str = dap_config_get_item_str(a_config, "ledger", "type");
    if (!l_type_str) return DAP_LEDGER_TYPE_OPEN;

    if (strcmp(l_type_str, "anon") == 0) {
        /* Read anon_type */
        const char *l_anon_str = dap_config_get_item_str(a_config, "ledger", "anon_type");
        if (l_anon_str) {
            if (strcmp(l_anon_str, "chipmunk_snark") == 0) {
                *a_anon_type = DAP_LEDGER_ANON_CHIPMUNK_SNARK;
            } else {
                log_it(L_ERROR, "Unsupported anon_type '%s' in config. Only 'chipmunk_snark' is supported.", l_anon_str);
                return DAP_LEDGER_TYPE_OPEN;  /* Fail-safe: treat as open */
            }
        }
        return DAP_LEDGER_TYPE_ANON;
    }

    return DAP_LEDGER_TYPE_OPEN;
}

const char *dap_ledger_type_name(dap_ledger_type_t a_type)
{
    switch (a_type) {
    case DAP_LEDGER_TYPE_OPEN: return "open";
    case DAP_LEDGER_TYPE_ANON: return "anon";
    default: return "unknown";
    }
}

const char *dap_ledger_anon_type_name(dap_ledger_anon_type_t a_type)
{
    switch (a_type) {
    case DAP_LEDGER_ANON_CHIPMUNK_SNARK: return "chipmunk_snark";
    default:                             return "unknown";
    }
}

/* -------------------------------------------------------------------------
 * Public anon context API
 * ---------------------------------------------------------------------- */

void *dap_ledger_anon_ctx_create(const char *a_ledger_name)
{
    return (void *)s_anon_ctx_new(a_ledger_name);
}

void dap_ledger_anon_key_images_load(dap_ledger_t *a_ledger)
{
    if (!a_ledger || PVT(a_ledger)->ledger_type != DAP_LEDGER_TYPE_ANON || !PVT(a_ledger)->anon_data)
        return;
    if (!is_ledger_cached(PVT(a_ledger)))
        return;

    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)PVT(a_ledger)->anon_data;
    char *l_group = dap_ledger_get_gdb_group(a_ledger->name, DAP_LEDGER_KEY_IMAGES_STR);
    size_t l_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_group, &l_count);
    DAP_DELETE(l_group);
    if (!l_objs)
        return;

    for (size_t i = 0; i < l_count; ++i) {
        if (l_objs[i].value_len != sizeof(dap_chain_hash_fast_t))
            continue;
        dap_chain_hash_fast_t l_image_hash = {};
        dap_hash_fast_from_str(l_objs[i].key, &l_image_hash);
        dap_chain_hash_fast_t l_tx_hash = *(dap_chain_hash_fast_t *)l_objs[i].value;

        /* Integrity check: verify that the TX which spent this KI still exists in the ledger.
         * If not (crash, corruption, incomplete rollback), remove orphaned KI. */
        dap_ledger_tx_item_t *l_tx_item = NULL;
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        dap_ht_find(PVT(a_ledger)->ledger_items, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (!l_tx_item) {
            /* TX not found — KI is orphaned. Remove from GDB. */
            log_it(L_WARNING, "Orphaned KI %s references missing TX %s, removing",
                   l_objs[i].key, dap_hash_fast_to_str_static(&l_tx_hash));
            char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger->name, DAP_LEDGER_KEY_IMAGES_STR);
            dap_global_db_del_sync(l_gdb_group, l_objs[i].key);
            DAP_DELETE(l_gdb_group);
            continue;
        }

        s_key_image_add(l_anon, &l_image_hash, &l_tx_hash, a_ledger, false);
    }
    dap_global_db_objs_delete(l_objs, l_count);
}

void dap_ledger_anon_key_images_purge(dap_ledger_t *a_ledger)
{
    if (!a_ledger || !is_ledger_cached(PVT(a_ledger)))
        return;

    char *l_group = dap_ledger_get_gdb_group(a_ledger->name, DAP_LEDGER_KEY_IMAGES_STR);
    dap_global_db_erase_table(l_group, NULL, NULL);
    DAP_DELETE(l_group);

    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)PVT(a_ledger)->anon_data;
    if (!l_anon)
        return;

    dap_ledger_anon_key_image_t *l_item, *l_tmp;
    pthread_rwlock_wrlock(&l_anon->key_images_rwlock);
    dap_ht_foreach(l_anon->key_images, l_item, l_tmp) {
        dap_ht_del(l_anon->key_images, l_item);
        DAP_DELETE(l_item);
    }
    pthread_rwlock_unlock(&l_anon->key_images_rwlock);
}

void dap_ledger_anon_ctx_free(void *a_ctx)
{
    s_anon_ctx_free((dap_ledger_anon_ctx_t *)a_ctx);
}

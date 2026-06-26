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
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_datum_tx_anon.h"
#include "chipmunk_snark.h"
#include "chipmunk_pedersen.h"
#include "chipmunk_range_proof.h"
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
    /* Delegate to existing UTXO verification */
    return dap_ledger_tx_add_check(a_ledger, a_tx, a_tx_size, a_tx_hash);
}

static int s_open_tx_add(dap_ledger_t *a_ledger,
                          dap_chain_datum_tx_t *a_tx,
                          dap_hash_fast_t *a_tx_hash)
{
    /* Delegate to existing UTXO add */
    return dap_ledger_tx_add(a_ledger, a_tx, a_tx_hash, false, NULL);
}

static int s_open_tx_remove(dap_ledger_t *a_ledger,
                             dap_hash_fast_t *a_tx_hash)
{
    return dap_ledger_tx_remove(a_ledger, NULL, a_tx_hash);
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

/* Key image tracking: prevents double-spending in anonymous mode.
 * Key images are stored in a hash table indexed by image hash. */
typedef struct dap_ledger_anon_key_image {
    dap_chain_hash_fast_t image_hash;
    dap_chain_hash_fast_t tx_hash;
    dap_ht_handle_t hh;
} dap_ledger_anon_key_image_t;

/* Anonymous data stored in ledger's anon_data field */
typedef struct dap_ledger_anon_ctx {
    chipmunk_snark_ctx_t snark_ctx;
    chipmunk_pedersen_params_t pedersen_params;
    dap_ledger_anon_key_image_t *key_images;
    pthread_rwlock_t key_images_rwlock;
} dap_ledger_anon_ctx_t;

/* Initialize anonymous context */
static dap_ledger_anon_ctx_t *s_anon_ctx_new(void)
{
    dap_ledger_anon_ctx_t *ctx = DAP_NEW_Z(dap_ledger_anon_ctx_t);
    if (!ctx) return NULL;

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
    DAP_DELETE(ctx);
}

/* Check if key image already exists (double-spend detection) */
static bool s_key_image_exists(dap_ledger_anon_ctx_t *ctx,
                                const dap_chain_hash_fast_t *image_hash)
{
    dap_ledger_anon_key_image_t *l_item = NULL;
    pthread_rwlock_rdlock(&ctx->key_images_rwlock);
    dap_ht_find(ctx->key_images, image_hash, sizeof(dap_chain_hash_fast_t), l_item);
    pthread_rwlock_unlock(&ctx->key_images_rwlock);
    return l_item != NULL;
}

/* Add key image to tracking — atomic check-and-add under write lock
 * to prevent TOCTOU race between check and insertion. */
static int s_key_image_add(dap_ledger_anon_ctx_t *ctx,
                            const dap_chain_hash_fast_t *image_hash,
                            const dap_chain_hash_fast_t *tx_hash)
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

    return 0;
}

/* Remove key image from tracking (TX rollback) */
static void s_key_image_remove(dap_ledger_anon_ctx_t *ctx,
                                const dap_chain_hash_fast_t *image_hash)
{
    pthread_rwlock_wrlock(&ctx->key_images_rwlock);
    dap_ledger_anon_key_image_t *l_item = NULL;
    dap_ht_find(ctx->key_images, image_hash, sizeof(dap_chain_hash_fast_t), l_item);
    if (l_item) {
        dap_ht_del(ctx->key_images, l_item);
        DAP_DELETE(l_item);
    }
    pthread_rwlock_unlock(&ctx->key_images_rwlock);
}

/* -------------------------------------------------------------------------
 * Anonymous TX verification
 * ---------------------------------------------------------------------- */

static int s_anon_tx_check(dap_ledger_t *a_ledger,
                            dap_chain_datum_tx_t *a_tx,
                            size_t a_tx_size,
                            dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx || !a_tx_hash) return -EINVAL;

    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)l_pvt->anon_data;
    if (!l_anon) {
        log_it(L_ERROR, "Anonymous context not initialized");
        return -EINVAL;
    }

    /* 1. Check basic TX structure (same as open ledger) */
    int l_rc = dap_ledger_tx_add_check(a_ledger, a_tx, a_tx_size, a_tx_hash);
    if (l_rc != 0) return l_rc;

    /* 2. Verify SNARK ring membership proofs from IN_ANON items.
     * Proofs are embedded in IN_ANON items (not standalone ANON_PROOF items).
     * Ring public keys follow the IN_ANON struct as variable-length data. */
    const uint8_t *l_item_snark = a_tx->tx_items;
    size_t l_offset_snark = 0;
    size_t l_tx_size_snark = dap_chain_datum_tx_get_size(a_tx);
    bool l_found_anon_in = false;

    while (l_offset_snark < l_tx_size_snark) {
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

            /* Build message from TX hash for binding */
            uint8_t l_msg_buf[32];
            memcpy(l_msg_buf, a_tx_hash, 32);
            l_statement.message = l_msg_buf;
            l_statement.message_size = 32;

            /* Verify SNARK proof (copy from packed struct to avoid alignment issues) */
            chipmunk_snark_proof_t l_proof_copy;
            memcpy(&l_proof_copy, &l_in_anon->snark_proof, sizeof(l_proof_copy));
            l_rc = chipmunk_snark_verify(&l_proof_copy, &l_anon->snark_ctx, &l_statement);
            if (l_rc != 1) {
                log_it(L_WARNING, "SNARK proof verification failed for IN_ANON: %d", l_rc);
                return -EINVAL;
            }
        }
        uint32_t l_item_size_snark = *(const uint32_t *)(l_item_snark + 4);
        if (l_item_size_snark == 0) break;
        if (l_offset_snark + l_item_size_snark > l_tx_size_snark) break;
        l_item_snark += l_item_size_snark;
        l_offset_snark += l_item_size_snark;
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

        if (s_key_image_exists(l_anon, &l_image_hash)) {
            log_it(L_WARNING, "Double-spend attempt detected: key image already used");
            DAP_DELETE(l_images);
            return -EINVAL;
        }
    }
    DAP_DELETE(l_images);

    /* 4. Verify Pedersen commitments and range proofs on outputs */
    const uint8_t *l_item = a_tx->tx_items;
    size_t l_offset = 0;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);

    while (l_offset < l_tx_size) {
        uint8_t l_type = *l_item;
        if (l_type == TX_ITEM_TYPE_OUT_ANON) {
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
        uint32_t l_item_size = *(const uint32_t *)(l_item + 4);
        if (l_item_size == 0) break;
        if (l_offset + l_item_size > l_tx_size) break;
        l_item += l_item_size;
        l_offset += l_item_size;
    }

    return 0; /* Valid anonymous TX */
}

static int s_anon_tx_add(dap_ledger_t *a_ledger,
                          dap_chain_datum_tx_t *a_tx,
                          dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx || !a_tx_hash) return -EINVAL;

    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_ledger_anon_ctx_t *l_anon = (dap_ledger_anon_ctx_t *)l_pvt->anon_data;

    const dap_chain_tx_key_image_t **l_images = NULL;
    size_t l_image_count = 0;

    /* 1. Record key images BEFORE adding TX to ledger (TOCTOU fix) */
    if (l_anon) {
        int l_rc = dap_chain_datum_tx_get_key_images(a_tx->tx_items, dap_chain_datum_tx_get_size(a_tx), &l_images, &l_image_count);
        if (l_rc == 0 && l_images) {
            for (size_t i = 0; i < l_image_count; ++i) {
                dap_chain_hash_fast_t l_image_hash;
                dap_hash_fast(l_images[i]->image, sizeof(l_images[i]->image), &l_image_hash);
                int l_add_rc = s_key_image_add(l_anon, &l_image_hash, a_tx_hash);
                if (l_add_rc != 0) {
                    log_it(L_WARNING, "Key image already exists, double-spend rejected: %d", l_add_rc);
                    /* Roll back images already added */
                    for (size_t j = 0; j < i; ++j) {
                        dap_chain_hash_fast_t l_rollback_hash;
                        dap_hash_fast(l_images[j]->image, sizeof(l_images[j]->image), &l_rollback_hash);
                        s_key_image_remove(l_anon, &l_rollback_hash);
                    }
                    DAP_DELETE(l_images);
                    return l_add_rc;
                }
            }
            DAP_DELETE(l_images);
        }
    }

    /* 2. Add TX to ledger — key images already committed */
    int l_rc = dap_ledger_tx_add(a_ledger, a_tx, a_tx_hash, false, NULL);
    if (l_rc != 0) {
        /* TX add failed — roll back recorded key images */
        if (l_anon && l_image_count > 0) {
            const dap_chain_tx_key_image_t **l_rb_images = NULL;
            size_t l_rb_count = 0;
            if (dap_chain_datum_tx_get_key_images(a_tx->tx_items, dap_chain_datum_tx_get_size(a_tx), &l_rb_images, &l_rb_count) == 0 && l_rb_images) {
                for (size_t i = 0; i < l_rb_count; ++i) {
                    dap_chain_hash_fast_t l_rb_hash;
                    dap_hash_fast(l_rb_images[i]->image, sizeof(l_rb_images[i]->image), &l_rb_hash);
                    s_key_image_remove(l_anon, &l_rb_hash);
                }
                DAP_DELETE(l_rb_images);
            }
        }
        return l_rc;
    }

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
                dap_ht_del(l_anon->key_images, l_item);
                DAP_DELETE(l_item);
            }
        }
        pthread_rwlock_unlock(&l_anon->key_images_rwlock);
    }

    return dap_ledger_tx_remove(a_ledger, NULL, a_tx_hash);
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
            } else if (strcmp(l_anon_str, "mrng") == 0) {
                *a_anon_type = DAP_LEDGER_ANON_MRNG;
            } else if (strcmp(l_anon_str, "lrs") == 0) {
                *a_anon_type = DAP_LEDGER_ANON_LRS;
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
    case DAP_LEDGER_ANON_MRNG:           return "mrng";
    case DAP_LEDGER_ANON_LRS:            return "lrs";
    default: return "unknown";
    }
}

/* -------------------------------------------------------------------------
 * Public anon context API
 * ---------------------------------------------------------------------- */

void *dap_ledger_anon_ctx_create(void)
{
    return (void *)s_anon_ctx_new();
}

void dap_ledger_anon_ctx_free(void *a_ctx)
{
    s_anon_ctx_free((dap_ledger_anon_ctx_t *)a_ctx);
}

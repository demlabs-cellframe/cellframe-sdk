/*
 * dap_chain_ledger_type.h — Ledger type abstraction layer.
 *
 * Provides a pluggable ledger backend system allowing networks to choose
 * between open (transparent UTXO) and anonymous (SNARK-based) ledgers.
 *
 * Usage in network config (.cfg):
 *   [ledger]
 *   type = "open"        ; default, transparent UTXO
 *   ; type = "anon"      ; anonymous ledger with SNARK proofs
 *   ; anon_type = "chipmunk_snark"  ; SNARK backend (default for anon)
 */

#pragma once

#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Ledger type identifiers
 * ---------------------------------------------------------------------- */

typedef enum dap_ledger_type {
    DAP_LEDGER_TYPE_OPEN = 0,       /* Standard transparent UTXO ledger */
    DAP_LEDGER_TYPE_ANON,           /* Anonymous ledger with SNARK proofs */
    DAP_LEDGER_TYPE_MAX
} dap_ledger_type_t;

/* Anonymous ledger backend types */
typedef enum dap_ledger_anon_type {
    DAP_LEDGER_ANON_CHIPMUNK_SNARK = 0,  /* Chipmunk lattice-based SNARK (default) */
    DAP_LEDGER_ANON_MRNG,                 /* MRNG threshold ring (O(log N)) */
    DAP_LEDGER_ANON_LRS,                  /* LRS linkable ring (O(N)) */
    DAP_LEDGER_ANON_MAX
} dap_ledger_anon_type_t;

/* -------------------------------------------------------------------------
 * Ledger type callbacks
 * ---------------------------------------------------------------------- */

/**
 * TX verification callback.
 * @return 0 if valid, negative on error.
 */
typedef int (*dap_ledger_type_tx_check_cb_t)(
    dap_ledger_t *a_ledger,
    dap_chain_datum_tx_t *a_tx,
    size_t a_tx_size,
    dap_hash_fast_t *a_tx_hash);

/**
 * TX commit callback — type-specific side effects after UTXO checks pass
 * (e.g. anonymous key-image commit). Invoked from dap_ledger_tx_add_impl
 * immediately before the TX is inserted into the ledger cache.
 * @return 0 on success, negative on error.
 */
typedef int (*dap_ledger_type_tx_add_cb_t)(
    dap_ledger_t *a_ledger,
    dap_chain_datum_tx_t *a_tx,
    dap_hash_fast_t *a_tx_hash);

/**
 * TX removal callback.
 */
typedef int (*dap_ledger_type_tx_remove_cb_t)(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_tx_hash);

/**
 * Balance calculation callback.
 */
typedef int (*dap_ledger_type_calc_balance_cb_t)(
    dap_ledger_t *a_ledger,
    const dap_chain_addr_t *a_addr,
    const char *a_token_ticker,
    uint256_t *a_balance);

/**
 * Token emission verification callback.
 */
typedef int (*dap_ledger_type_emission_check_cb_t)(
    dap_ledger_t *a_ledger,
    dap_chain_datum_token_emission_t *a_emission,
    size_t a_emission_size);

/* -------------------------------------------------------------------------
 * Ledger type descriptor
 * ---------------------------------------------------------------------- */

typedef struct dap_ledger_type_desc {
    dap_ledger_type_t type;
    const char *name;                           /* "open" or "anon" */
    dap_ledger_anon_type_t anon_type;           /* Backend for anon type */
    const char *description;

    /* Pluggable callbacks */
    dap_ledger_type_tx_check_cb_t       tx_check;
    dap_ledger_type_tx_add_cb_t         tx_add;
    dap_ledger_type_tx_remove_cb_t      tx_remove;
    dap_ledger_type_calc_balance_cb_t   calc_balance;
    dap_ledger_type_emission_check_cb_t emission_check;
} dap_ledger_type_desc_t;

/* -------------------------------------------------------------------------
 * API
 * ---------------------------------------------------------------------- */

/**
 * Initialize ledger type system.
 * Registers built-in types: "open" (UTXO) and "anon" (SNARK-based).
 * @return 0 on success.
 */
int dap_ledger_type_init(void);

/**
 * Deinitialize ledger type system.
 */
void dap_ledger_type_deinit(void);

/**
 * Register a custom ledger type.
 * @param desc Type descriptor.
 * @return 0 on success, -EEXIST if name already registered.
 */
int dap_ledger_type_register(const dap_ledger_type_desc_t *desc);

/**
 * Get ledger type descriptor by name.
 * @param name Type name ("open" or "anon").
 * @return Descriptor or NULL if not found.
 */
const dap_ledger_type_desc_t *dap_ledger_type_get(const char *name);

/**
 * Get ledger type descriptor by enum.
 * @param type Type enum.
 * @return Descriptor or NULL if not found.
 */
const dap_ledger_type_desc_t *dap_ledger_type_get_by_enum(dap_ledger_type_t type);

/**
 * Get ledger type from network config.
 * Reads [ledger] type = "open"|"anon" from config.
 * @param a_config Network config.
 * @param a_anon_type Output: anonymous backend type (if anon).
 * @return Ledger type.
 */
dap_ledger_type_t dap_ledger_type_from_config(dap_config_t *a_config,
                                               dap_ledger_anon_type_t *a_anon_type);

/**
 * Check if ledger type is anonymous.
 */
static inline bool dap_ledger_type_is_anon(dap_ledger_type_t a_type)
{
    return a_type == DAP_LEDGER_TYPE_ANON;
}

/**
 * Get string name for ledger type.
 */
const char *dap_ledger_type_name(dap_ledger_type_t a_type);

/**
 * Get string name for anonymous backend type.
 */
const char *dap_ledger_anon_type_name(dap_ledger_anon_type_t a_type);

/**
 * Create anonymous ledger context (SNARK + Pedersen + key image tracking).
 * Called automatically by dap_ledger_create() when ledger_type == ANON.
 * @param a_ledger_name Ledger name for GDB persistence (required for anon ledgers).
 * @return Pointer to anon context, or NULL on error. Caller owns.
 */
void *dap_ledger_anon_ctx_create(const char *a_ledger_name);

/**
 * Free anonymous ledger context.
 */
void dap_ledger_anon_ctx_free(void *a_ctx);

/**
 * Load persisted key images from GDB into the anonymous context.
 * No-op if ledger cache is disabled or ledger is not anonymous.
 */
void dap_ledger_anon_key_images_load(dap_ledger_t *a_ledger);

/**
 * Erase persisted key images from GDB (ledger purge).
 */
void dap_ledger_anon_key_images_purge(dap_ledger_t *a_ledger);

/**
 * Verify anonymous TX cryptography (SNARK, range proofs, KI unused).
 * Does not commit key images — use dap_ledger_anon_tx_key_images_commit on ledger add.
 * @return 0 if valid, negative on error.
 */
int dap_ledger_anon_tx_verify(dap_ledger_t *a_ledger,
                              dap_chain_datum_tx_t *a_tx,
                              dap_hash_fast_t *a_tx_hash);

/**
 * Commit key images after a TX is accepted into the ledger.
 * @return 0 on success, -EEXIST if double-spend, negative on other errors.
 */
int dap_ledger_anon_tx_key_images_commit(dap_ledger_t *a_ledger,
                                         dap_chain_datum_tx_t *a_tx,
                                         dap_hash_fast_t *a_tx_hash);

/**
 * Dispatch type-specific TX commit hooks (tx_add callback).
 * Called from dap_ledger_tx_add_impl after balance/UTXO checks pass.
 */
int dap_ledger_type_tx_add_commit(dap_ledger_t *a_ledger,
                                  dap_chain_datum_tx_t *a_tx,
                                  dap_hash_fast_t *a_tx_hash);

#ifdef __cplusplus
}
#endif

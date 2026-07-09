/*
 * dap_chain_tx_anon_compose.c — Compose builder for anonymous transactions.
 *
 * Registers "anon_transfer" builder in the TX compose registry, allowing
 * anonymous TX creation through the unified dap_chain_tx_compose_create()
 * dispatcher (used by service-layer and programmatic callers).
 *
 * CLI callers use com_tx_create() with -anonymous flag directly
 * (see dap_chain_net_tx_cli.c).
 *
 * Authors:
 * Cellframe Team
 * Copyright (c) 2019-2026
 */

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_hash.h"

#include "dap_chain_net.h"
#include "dap_chain_wallet.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_tx_anon_create.h"

#define LOG_TAG "chain_tx_anon_compose"

/* Anonymous transfer compose parameters */
typedef struct {
    const char *wallet_name;
    const char *chain_name;
    const char *token_ticker;
    uint256_t value;
    dap_chain_addr_t addr_to;
    size_t anon_set;
    uint256_t fee;
    const char *hash_out_type;
} anon_transfer_compose_params_t;

/**
 * @brief Compose callback for anonymous transfer transactions.
 *
 * This is invoked via dap_chain_tx_compose_create("anon_transfer", ...).
 *
 * The callback opens the wallet, validates the key type, calls
 * dap_chain_tx_anon_transfer_auto_ring(), optionally adds a fee output,
 * and returns the constructed datum (caller adds to mempool).
 *
 * @param a_ledger        Ledger handle (used for network/chain resolution)
 * @param a_list_used_outs Unused for anonymous TX (we use our own UTXO search)
 * @param a_params        Pointer to anon_transfer_compose_params_t
 * @return dap_chain_datum_t* Constructed anonymous TX datum, or NULL on error
 */
static dap_chain_datum_t *s_anon_transfer_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params)
{
    (void)a_list_used_outs; /* Anonymous TX does its own UTXO search internally */

    anon_transfer_compose_params_t *l_params = (anon_transfer_compose_params_t *)a_params;
    if (!l_params || !l_params->wallet_name || !l_params->chain_name ||
        !l_params->token_ticker || IS_ZERO_256(l_params->value)) {
        log_it(L_ERROR, "Invalid anonymous transfer compose parameters");
        return NULL;
    }

    /* Resolve chain from ledger */
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_ledger->net_id);
    if (!l_net) {
        log_it(L_ERROR, "Network not found for net_id 0x%016" DAP_UINT64_FORMAT_X, a_ledger->net_id.uint64);
        return NULL;
    }

    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_params->chain_name);
    if (!l_chain) {
        log_it(L_ERROR, "Chain '%s' not found in network", l_params->chain_name);
        return NULL;
    }

    /* Open wallet */
    const char *l_wallets_path = dap_chain_wallet_get_path(g_config);
    if (!l_wallets_path) {
        log_it(L_ERROR, "Wallet path not configured");
        return NULL;
    }

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_params->wallet_name, l_wallets_path, NULL);
    if (!l_wallet) {
        log_it(L_ERROR, "Failed to open wallet '%s' for anonymous TX compose", l_params->wallet_name);
        return NULL;
    }

    /* Validate wallet key type */
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(l_wallet, 0);
    if (!l_key) {
        log_it(L_ERROR, "Failed to get key from wallet '%s'", l_params->wallet_name);
        dap_chain_wallet_close(l_wallet);
        return NULL;
    }

    if (l_key->type != DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_RING &&
        l_key->type != DAP_ENC_KEY_TYPE_SIG_CHIPMUNK_LRS) {
        log_it(L_ERROR, "Wallet '%s' key type 0x%04x is not suitable for anonymous TX "
               "(requires chipmunk_ring 0x010C or chipmunk_lrs 0x010A)",
               l_params->wallet_name, l_key->type);
        dap_enc_key_delete(l_key);
        dap_chain_wallet_close(l_wallet);
        return NULL;
    }
    dap_enc_key_delete(l_key);

    /* Create anonymous TX */
    size_t l_anon_set = l_params->anon_set > 0 ? l_params->anon_set : 10;
    dap_chain_datum_t *l_datum = dap_chain_tx_anon_transfer_auto_ring(
        l_wallet, l_chain, l_params->token_ticker,
        l_params->value, &l_params->addr_to, l_anon_set);

    dap_chain_wallet_close(l_wallet);

    if (!l_datum) {
        log_it(L_ERROR, "Failed to create anonymous TX via dap_chain_tx_anon_transfer_auto_ring");
        return NULL;
    }

    /* Add fee as OUT_STD item if specified */
    if (!IS_ZERO_256(l_params->fee)) {
        size_t l_tx_size = l_datum->header.data_size;
        dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, l_tx_size);
        if (l_tx) {
            memcpy(l_tx, l_datum->data, l_tx_size);

            dap_chain_addr_t l_fee_addr = {};
            dap_chain_tx_out_std_t *l_fee_out = DAP_NEW_Z(dap_chain_tx_out_std_t);
            if (l_fee_out) {
                l_fee_out->hdr.type = TX_ITEM_TYPE_OUT_STD;
                l_fee_out->hdr.version = 1;
                l_fee_out->hdr.size = sizeof(dap_chain_tx_out_std_t);
                l_fee_out->addr = l_fee_addr;
                l_fee_out->value = l_params->fee;
                dap_strncpy(l_fee_out->token_ticker, l_params->token_ticker, sizeof(l_fee_out->token_ticker));

                if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_fee_out) == 1) {
                    size_t l_new_size = dap_chain_datum_tx_get_size(l_tx);
                    dap_chain_datum_t *l_new_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_new_size);
                    DAP_DELETE(l_datum);
                    l_datum = l_new_datum;
                }
                DAP_DELETE(l_fee_out);
            }
            DAP_DELETE(l_tx);
        }
    }

    log_it(L_INFO, "Anonymous TX compose created: wallet=%s, chain=%s, ticker=%s, anon_set=%zu",
           l_params->wallet_name, l_params->chain_name, l_params->token_ticker, l_anon_set);

    return l_datum;
}

/**
 * @brief Register the anonymous transfer compose builder.
 *
 * Call this during ledger or wallet module initialization to make
 * "anon_transfer" available via dap_chain_tx_compose_create().
 *
 * @return 0 on success, -1 on error
 */
int dap_chain_tx_anon_compose_register(void)
{
    int l_ret = dap_chain_tx_compose_register("anon_transfer", s_anon_transfer_compose_cb, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register 'anon_transfer' compose builder");
        return l_ret;
    }
    log_it(L_INFO, "Registered 'anon_transfer' compose builder");
    return 0;
}

/**
 * @brief Unregister the anonymous transfer compose builder.
 */
void dap_chain_tx_anon_compose_unregister(void)
{
    dap_chain_tx_compose_unregister("anon_transfer");
    log_it(L_INFO, "Unregistered 'anon_transfer' compose builder");
}

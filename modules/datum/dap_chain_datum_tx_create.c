/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2026
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_chain_datum_tx_create.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_common.h"
#include "dap_math_ops.h"

#define LOG_TAG "dap_chain_datum_tx_create"

/**
 * @brief Add UTXO inputs to TX and return the total value of added inputs
 *
 * Iterates a_utxo_list (list of dap_chain_tx_used_out_item_t*) and
 * creates TX_ITEM_TYPE_IN for each, accumulating their value.
 */
static uint256_t s_add_inputs_from_utxo(dap_chain_datum_tx_t **a_tx, dap_list_t *a_utxo_list)
{
    return dap_chain_datum_tx_add_in_item_list(a_tx, a_utxo_list);
}

/**
 * @brief Common: add fee + change after outputs are set
 *
 * @return 0 on success, -1 on error
 */
static int s_finalize_fee_and_change(
    dap_chain_datum_tx_t **a_tx,
    uint256_t a_value_from_inputs,
    uint256_t a_total_outputs,
    uint256_t a_value_fee,
    const dap_chain_addr_t *a_addr_change,
    const char *a_token_ticker)
{
    uint256_t l_total_needed = {};
    SUM_256_256(a_total_outputs, a_value_fee, &l_total_needed);

    if (compare256(a_value_from_inputs, l_total_needed) < 0) {
        log_it(L_ERROR, "Insufficient UTXO value: have < need");
        return -1;
    }

    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(a_tx, a_value_fee) != 1)
            return -1;
    }

    uint256_t l_change = {};
    SUBTRACT_256_256(a_value_from_inputs, l_total_needed, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_ext_item(a_tx, a_addr_change, l_change, a_token_ticker) != 1)
            return -1;
    }
    return 0;
}

/* ──────────────── transfer ──────────────── */

dap_chain_datum_tx_t *dap_chain_datum_tx_create_transfer(
    dap_chain_net_id_t a_net_id,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee,
    dap_list_t *a_utxo_list)
{
    (void)a_net_id;
    dap_return_val_if_pass(!a_addr_from || !a_addr_to || !a_token_ticker || !a_utxo_list, NULL);
    dap_return_val_if_pass(IS_ZERO_256(a_value), NULL);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) return NULL;

    uint256_t l_value_in = s_add_inputs_from_utxo(&l_tx, a_utxo_list);

    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, a_value, a_token_ticker) != 1)
        goto fail;

    if (s_finalize_fee_and_change(&l_tx, l_value_in, a_value, a_value_fee,
                                  a_addr_from, a_token_ticker) != 0)
        goto fail;

    return l_tx;
fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

/* ──────────────── multi_transfer ──────────────── */

dap_chain_datum_tx_t *dap_chain_datum_tx_create_multi_transfer(
    dap_chain_net_id_t a_net_id,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t **a_addr_to,
    uint256_t *a_values,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value_fee,
    size_t a_outputs_count,
    dap_time_t *a_time_unlock,
    dap_list_t *a_utxo_list)
{
    (void)a_net_id;
    dap_return_val_if_pass(!a_addr_from || !a_addr_to || !a_values
                           || !a_token_ticker || !a_outputs_count || !a_utxo_list, NULL);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) return NULL;

    uint256_t l_value_in = s_add_inputs_from_utxo(&l_tx, a_utxo_list);

    uint256_t l_total_out = uint256_0;
    for (size_t i = 0; i < a_outputs_count; i++) {
        int l_rc;
        if (a_time_unlock && a_time_unlock[i])
            l_rc = dap_chain_datum_tx_add_out_std_item(&l_tx, a_addr_to[i],
                                                       a_values[i], a_token_ticker,
                                                       a_time_unlock[i]);
        else
            l_rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i],
                                                       a_values[i], a_token_ticker);
        if (l_rc != 1) goto fail;
        SUM_256_256(l_total_out, a_values[i], &l_total_out);
    }

    if (s_finalize_fee_and_change(&l_tx, l_value_in, l_total_out, a_value_fee,
                                  a_addr_from, a_token_ticker) != 0)
        goto fail;

    return l_tx;
fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

/* ──────────────── cond_output ──────────────── */

dap_chain_datum_tx_t *dap_chain_datum_tx_create_cond_output(
    dap_chain_net_id_t a_net_id,
    const dap_chain_addr_t *a_addr_from,
    dap_hash_sha3_256_t *a_pkey_cond_hash,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_per_unit_max,
    dap_chain_net_srv_price_unit_uid_t a_unit,
    dap_chain_srv_uid_t a_srv_uid,
    uint256_t a_value_fee,
    const void *a_cond,
    size_t a_cond_size,
    dap_list_t *a_utxo_list)
{
    (void)a_net_id;
    dap_return_val_if_pass(!a_addr_from || !a_pkey_cond_hash
                           || !a_token_ticker || !a_utxo_list, NULL);
    dap_return_val_if_pass(IS_ZERO_256(a_value), NULL);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) return NULL;

    uint256_t l_value_in = s_add_inputs_from_utxo(&l_tx, a_utxo_list);

    if (dap_chain_datum_tx_add_out_cond_item(&l_tx, a_pkey_cond_hash, a_srv_uid,
                                             a_value, a_value_per_unit_max, a_unit,
                                             a_cond, a_cond_size) != 1)
        goto fail;

    if (s_finalize_fee_and_change(&l_tx, l_value_in, a_value, a_value_fee,
                                  a_addr_from, a_token_ticker) != 0)
        goto fail;

    return l_tx;
fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

/* ──────────────── from_emission ──────────────── */

dap_chain_datum_tx_t *dap_chain_datum_tx_create_from_emission(
    dap_chain_net_id_t a_net_id,
    dap_hash_sha3_256_t *a_emission_hash,
    dap_chain_id_t a_emission_chain_id,
    uint256_t a_emission_value,
    const char *a_ticker,
    const dap_chain_addr_t *a_addr_to,
    uint256_t a_value_fee)
{
    (void)a_net_id;
    dap_return_val_if_pass(!a_emission_hash, NULL);

    if (a_addr_to && !IS_ZERO_256(a_value_fee)
        && compare256(a_emission_value, a_value_fee) <= 0) {
        log_it(L_ERROR, "Emission value must exceed fee");
        return NULL;
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) return NULL;

    const char *l_ticker = a_ticker ? a_ticker : "";
    dap_chain_tx_in_ems_t *l_in_ems =
        dap_chain_datum_tx_item_in_ems_create(a_emission_chain_id, a_emission_hash, l_ticker);
    if (!l_in_ems) goto fail;
    if (dap_chain_datum_tx_add_item(&l_tx, l_in_ems) != 1) {
        DAP_DELETE(l_in_ems);
        goto fail;
    }
    DAP_DELETE(l_in_ems);

    if (a_addr_to && !IS_ZERO_256(a_emission_value)) {
        uint256_t l_value_to_addr = a_emission_value;
        if (!IS_ZERO_256(a_value_fee)) {
            SUBTRACT_256_256(a_emission_value, a_value_fee, &l_value_to_addr);
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1)
                goto fail;
        }
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_value_to_addr, l_ticker) != 1)
            goto fail;
    }

    return l_tx;
fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

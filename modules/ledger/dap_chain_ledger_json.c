/**
 * @file dap_chain_ledger_json.c
 * @brief JSON-related functions for ledger
 * @details Includes datum_dump_json moved from datum module to avoid circular dependencies
 *
 * @date 2025-10-05
 */

#include "dap_chain_ledger.h"
#include "dap_chain_datum.h"
#include "dap_json_rpc_errors.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_json.h"
#include "dap_common.h"
#include "dap_rand.h"
#include "dap_enc_base58.h"

#define LOG_TAG "dap_chain_ledger_json"

/**
 * @brief Get list of transaction outputs from JSON array
 * @param a_outputs_array JSON array of outputs
 * @param a_outputs_count Number of outputs in array
 * @param a_value_need Required value
 * @param a_value_transfer[out] Actual transferred value
 * @param a_need_all_outputs Get all outputs or stop when value is reached
 * @return List of dap_chain_tx_used_out_item_t or NULL
 */
dap_list_t *dap_ledger_get_list_tx_outs_from_json(dap_json_t *a_outputs_array, int a_outputs_count,
                                                     uint256_t a_value_need, uint256_t *a_value_transfer,
                                                     bool a_need_all_outputs)
{
    if (!a_outputs_array || a_outputs_count <= 0) {
        return NULL;
    }

    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = {};

    for (int i = 0; i < a_outputs_count; i++) {
        dap_json_t *l_output = dap_json_array_get_idx(a_outputs_array, i);
        if (!l_output || !dap_json_is_object(l_output)) {
            continue;
        }

        dap_json_t *l_value_datosi_obj = NULL;
        dap_json_object_get_ex(l_output, "value_datosi", &l_value_datosi_obj);
        if (!l_value_datosi_obj) {
            continue;
        }
        const char *l_value_str = dap_json_get_string(l_value_datosi_obj);
        uint256_t l_value = dap_chain_balance_scan(l_value_str);

        if (IS_ZERO_256(l_value)) {
            continue;
        }

        dap_json_t *l_prev_hash_obj = NULL;
        dap_json_object_get_ex(l_output, "prev_hash", &l_prev_hash_obj);
        if (!l_prev_hash_obj) {
            continue;
        }
        const char *l_prev_hash_str = dap_json_get_string(l_prev_hash_obj);

        dap_json_t *l_out_prev_idx_obj = NULL;
        dap_json_object_get_ex(l_output, "out_prev_idx", &l_out_prev_idx_obj);
        if (!l_out_prev_idx_obj) {
            continue;
        }
        int l_out_idx = dap_json_object_get_int(l_out_prev_idx_obj, NULL);

        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        if (!l_item) {
            continue;
        }

        if (dap_hash_sha3_256_from_str(l_prev_hash_str, &l_item->tx_hash_fast)) {
            DAP_DELETE(l_item);
            continue;
        }

        l_item->num_idx_out = l_out_idx;
        l_item->value = l_value;

        l_list_used_out = dap_list_append(l_list_used_out, l_item);
        if (!l_list_used_out) {
            DAP_DELETE(l_item);
            return NULL;
        }

        SUM_256_256(l_value_transfer, l_value, &l_value_transfer);

        if (!a_need_all_outputs && compare256(l_value_transfer, a_value_need) >= 0) {
            break;
        }
    }

    if (compare256(l_value_transfer, a_value_need) >= 0 && l_list_used_out) {
        if (a_value_transfer) {
            *a_value_transfer = l_value_transfer;
        }
        return l_list_used_out;
    }

    // Not enough value, clean up
    dap_list_free_full(l_list_used_out, NULL);
    return NULL;
}

/**
 * @brief Dump datum to JSON format
 * @details Moved from datum module to ledger because it requires ledger access for TX ticker lookup
 * @param a_json_arr_reply JSON array for errors
 * @param a_obj_out JSON object for output
 * @param a_datum Datum to dump
 * @param a_hash_out_type Hash output type ("hex" or "base58")
 * @param a_net_id Network ID (to get ledger)
 * @param a_verbose Verbose output
 * @param a_version Output format version
 */
void dap_chain_datum_dump_json(dap_json_t *a_json_arr_reply, dap_json_t *a_obj_out,
                                 dap_chain_datum_t *a_datum, const char *a_hash_out_type,
                                 dap_chain_net_id_t a_net_id, bool a_verbose, int a_version)
{
    if (!a_datum) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "==Datum is NULL");
        return;
    }
    dap_json_t *json_obj_datum = dap_json_object_new();
    dap_hash_sha3_256_t l_datum_hash = {};
    dap_chain_datum_calc_hash(a_datum, &l_datum_hash);
    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(&l_datum_hash)
            : dap_hash_sha3_256_to_str_static(&l_datum_hash);
    if (a_version != 1)
        dap_json_object_add_object(json_obj_datum, "datum_type", dap_json_object_new_string(dap_datum_type_to_str(a_datum->header.type_id)));
    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN: {
            size_t l_token_size = a_datum->header.data_size;
            dap_chain_datum_token_t *l_token = dap_chain_datum_token_read(a_datum->data, &l_token_size);
            if (l_token_size < sizeof(dap_chain_datum_token_t)) {
                dap_json_rpc_error_add(a_json_arr_reply, -2, "==Datum has incorrect size. Only %zu, while at least %zu is expected\n",
                                       l_token_size, sizeof(dap_chain_datum_token_t));
                DAP_DEL_Z(l_token);
                return;
            }
            if (a_version == 1)
                dap_json_object_add_object(json_obj_datum, "=== Datum Token Declaration ===", dap_json_object_new_string(""));
            dap_json_object_add_object(json_obj_datum, a_version == 1 ? "hash" : "datum_hash", dap_json_object_new_string(l_hash_str));
            if (l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE || a_verbose) {
                dap_json_object_add_object(json_obj_datum, "ticker", dap_json_object_new_string(l_token->ticker));
            }
            dap_json_object_add_object(json_obj_datum, "size", dap_json_object_new_uint64(l_token_size));
            dap_json_object_add_int(json_obj_datum, "version", l_token->version);
            // Token-specific dump handled by token module
            dap_datum_token_dump_tsd_to_json(json_obj_datum, l_token, l_token_size, a_hash_out_type);
            DAP_DELETE(l_token);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            size_t l_emission_size = a_datum->header.data_size;
            dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_datum->data, &l_emission_size);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_emission->hdr.value, &l_coins_str);
            dap_json_object_add_object(json_obj_datum, a_version == 1 ? "emission hash" : "emission_hash", dap_json_object_new_string(l_hash_str));
            dap_json_object_add_object(json_obj_datum, "coins", dap_json_object_new_string(l_coins_str));
            dap_json_object_add_object(json_obj_datum, "value", dap_json_object_new_string(l_value_str));
            dap_json_object_add_object(json_obj_datum, "ticker", dap_json_object_new_string(l_emission->hdr.ticker));
            dap_json_object_add_object(json_obj_datum, "type", dap_json_object_new_string(dap_chain_datum_emission_type_str(l_emission->hdr.type)));
            dap_json_object_add_object(json_obj_datum, "version", dap_json_object_new_uint64(l_emission->hdr.version));
            dap_json_object_add_object(json_obj_datum, a_version == 1 ? "to addr" : "to_addr", dap_json_object_new_string(dap_chain_addr_to_str_static(&(l_emission->hdr.address))));

            switch (l_emission->hdr.type) {
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:
                    dap_json_object_add_object(json_obj_datum, "sig_count", dap_json_object_new_uint64(l_emission->data.type_auth.signs_count));
                    dap_json_object_add_object(json_obj_datum, "tsd_total_size", dap_json_object_new_uint64(l_emission->data.type_auth.tsd_total_size));

                    if (((void *)l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size) >
                        ((void *)l_emission + l_emission_size)) {
                        log_it(L_ERROR, "Illformed DATUM type %d, TSD section is out-of-buffer (%" DAP_UINT64_FORMAT_U " vs %zu)",
                               l_emission->hdr.type, l_emission->data.type_auth.tsd_total_size, l_emission_size);
                        dap_json_rpc_error_add(a_json_arr_reply, -3, "Skip incorrect or illformed DATUM");
                        break;
                    }
                    dap_chain_datum_token_certs_dump_to_json(json_obj_datum, l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                              l_emission->data.type_auth.tsd_n_signs_size - l_emission->data.type_auth.tsd_total_size, a_hash_out_type, a_version);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO:
                    dap_json_object_add_object(json_obj_datum, "codename", dap_json_object_new_string(l_emission->data.type_algo.codename));
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT: {
                    char l_time_str[32];
                    char l_flags[50] = {};
                    if (dap_time_to_str_rfc822(l_time_str, sizeof(l_time_str), l_emission->data.type_presale.lock_time) < 1)
                        l_time_str[0] = '\0';
                    snprintf(l_flags, 50, "0x%x", l_emission->data.type_presale.flags);
                    dap_json_object_add_object(json_obj_datum, "flags", dap_json_object_new_string(l_flags));
                    dap_json_object_add_object(json_obj_datum, "lock_time", dap_json_object_new_string(l_time_str));
                    dap_json_object_add_object(json_obj_datum, "addr", dap_json_object_new_string(dap_chain_addr_to_str_static(&l_emission->data.type_presale.addr)));
                }
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER:
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED:
                default:
                    break;
            }
            DAP_DELETE(l_emission);
        } break;
        case DAP_CHAIN_DATUM_TX: {
            // Get ledger to retrieve token ticker - THIS IS WHY this function is in ledger module!
            dap_ledger_t *l_ledger = dap_ledger_find_by_net_id(a_net_id);
            const char *l_tx_token_ticker = NULL;

            if (l_ledger) {
                l_tx_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_datum_hash);
            }

            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
            dap_chain_datum_dump_tx_json(a_json_arr_reply, l_tx, l_tx_token_ticker, json_obj_datum, a_hash_out_type, &l_datum_hash, a_net_id, a_version);
        } break;
        case DAP_CHAIN_DATUM_DECREE: {
            dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *)a_datum->data;
            size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
            if (a_version == 1)
                dap_json_object_add_object(json_obj_datum, "=== Datum decree ===", dap_json_object_new_string(""));
            dap_json_object_add_object(json_obj_datum, a_version == 1 ? "hash" : "datum_hash", dap_json_object_new_string(l_hash_str));
            dap_json_object_add_object(json_obj_datum, "size", dap_json_object_new_uint64(l_decree_size));
            // Decree dump is handled by chain module callback - use extern declaration to avoid circular dependency
            extern void dap_chain_datum_decree_dump_json(dap_json_t *, const void *, size_t, const char *, int);
            dap_chain_datum_decree_dump_json(json_obj_datum, l_decree, l_decree_size, a_hash_out_type, a_version);
        } break;
        case DAP_CHAIN_DATUM_ANCHOR: {
            dap_chain_datum_anchor_t *l_anchor = (dap_chain_datum_anchor_t *)a_datum->data;
            size_t l_anchor_size = sizeof(dap_chain_datum_anchor_t) + l_anchor->header.data_size + l_anchor->header.signs_size;
            if (a_version == 1)
                dap_json_object_add_object(json_obj_datum, "=== Datum anchor ===", dap_json_object_new_string(""));
            dap_json_object_add_object(json_obj_datum, a_version == 1 ? "hash" : "datum_hash", dap_json_object_new_string(l_hash_str));
            dap_json_object_add_object(json_obj_datum, "size", dap_json_object_new_uint64(l_anchor_size));
            // Anchor dump is handled by chain module callback - use extern declaration
            dap_hash_sha3_256_t l_decree_hash = {};
            dap_chain_datum_anchor_get_hash_from_data(l_anchor, &l_decree_hash);
            l_hash_str = dap_hash_sha3_256_to_str_static(&l_decree_hash);
            dap_json_object_add_object(json_obj_datum, a_version == 1 ? "decree hash" : "decree_hash", dap_json_object_new_string(l_hash_str));
            dap_chain_datum_anchor_certs_dump_json(json_obj_datum, l_anchor->data_n_sign + l_anchor->header.data_size, l_anchor->header.signs_size, a_hash_out_type, a_version);
        } break;
        case DAP_CHAIN_DATUM_CUSTOM: {
            dap_json_object_add_object(json_obj_datum, a_version == 1 ? "hash" : "datum_hash", dap_json_object_new_string(l_hash_str));
        } break;
    }
    dap_json_object_add_object(a_obj_out, a_version == 1 ? "Datum" : "datum", json_obj_datum);
}

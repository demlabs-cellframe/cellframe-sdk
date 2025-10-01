/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_cli_server.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_math_convert.h"
#include "dap_json_rpc_errors.h"
#include "dap_chain_srv.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"

#define LOG_TAG "chain_node_cli_cmd_tx"
/**
 * @brief
 * sign data (datum_token) by certificates (1 or more)
 * successful count of signes return in l_sign_counter
 * @param l_certs - array with certificates loaded from dcert file
 * @param l_datum_token - updated pointer for l_datum_token variable after realloc
 * @param l_certs_count - count of certificate
 * @param l_datum_data_offset - offset of datum
 * @param l_sign_counter - counter of successful data signing operation
 * @return dap_chain_datum_token_t*
 */
static dap_chain_datum_token_t * s_sign_cert_in_cycle(dap_cert_t ** l_certs, dap_chain_datum_token_t *l_datum_token, size_t l_certs_count,
            size_t *l_datum_signs_offset, uint16_t * l_sign_counter)
{
    dap_return_val_if_fail_err(l_datum_signs_offset, NULL, "Signs offset is NULL");

    size_t l_tsd_size = 0;
    switch (l_datum_token->subtype) {
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
        switch (l_datum_token->type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
            l_tsd_size = l_datum_token->header_native_decl.tsd_total_size;
            break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
            l_tsd_size = l_datum_token->header_native_update.tsd_total_size;
            break;
        default: break;
        }
    default: break;
    }
    uint16_t l_tmp_cert_sign_count = l_datum_token->signs_total;
    l_datum_token->signs_total = 0;

    for (size_t i = 0; i < l_certs_count; i++) {
        dap_sign_t * l_sign = dap_cert_sign(l_certs[i],  l_datum_token,
           sizeof(*l_datum_token) + l_tsd_size);
        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            dap_chain_datum_token_t *l_datum_token_new
                = DAP_REALLOC_RET_VAL_IF_FAIL(l_datum_token, sizeof(*l_datum_token) + (*l_datum_signs_offset) + l_sign_size, NULL, l_sign);
            l_datum_token = l_datum_token_new;
            memcpy(l_datum_token->tsd_n_signs + *l_datum_signs_offset, l_sign, l_sign_size);
            *l_datum_signs_offset += l_sign_size;
            DAP_DELETE(l_sign);
            log_it(L_DEBUG,"<-- Signed with '%s'", l_certs[i]->name);
            (*l_sign_counter)++;
        }
    }
    l_datum_token->signs_total = l_tmp_cert_sign_count;

    return l_datum_token;
}

/**
 * @brief com_token_decl_sign
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_token_decl_sign(int a_argc, char **a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    dap_json_t ** a_json_arr_reply = (json_object **) a_str_reply;
    int arg_index = 1;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_H_PARAM_ERR,
                                       "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    const char * l_datum_hash_str = NULL;
    // Chain name
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
    if(l_datum_hash_str) {
        char *l_datum_hash_hex_str = NULL, *l_datum_hash_base58_str = NULL;
        const char * l_certs_str = NULL;
        dap_cert_t ** l_certs = NULL;
        size_t l_certs_count = 0;
        dap_chain_t * l_chain = NULL;
        dap_chain_net_t * l_net = NULL;

        dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &arg_index, a_argc, a_argv,&l_chain, &l_net,
                                                      CHAIN_TYPE_TOKEN);
        if(!l_net)
            return -1;

        // Certificates thats will be used to sign currend datum token
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);

        // Load certs lists
        if (l_certs_str)
            dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);

        if(!l_certs_count) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NOT_VALID_CERT_ERR,
                                       "token_sign command requres at least one valid certificate to sign the basic transaction of emission");
            return -7;
        }

        char * l_gdb_group_mempool = dap_chain_mempool_group_new(l_chain);
        if(!l_gdb_group_mempool) {
            l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);
        }
        // datum hash may be in hex or base58 format
        if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
            l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
            l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
        } else {
            l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
            l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
        }
        const char *l_datum_hash_out_str = dap_strcmp(l_hash_out_type,"hex")
            ? l_datum_hash_base58_str
            : l_datum_hash_hex_str;

        log_it(L_DEBUG, "Requested to sign token declaration %s in gdb://%s with certs %s",
                l_gdb_group_mempool, l_datum_hash_hex_str, l_certs_str);

        dap_chain_datum_t * l_datum = NULL;
        size_t l_datum_size = 0;
        size_t l_tsd_size = 0;
        if((l_datum = (dap_chain_datum_t*) dap_global_db_get_sync(l_gdb_group_mempool,
                l_datum_hash_hex_str, &l_datum_size, NULL, NULL )) != NULL) {

            // Check if its token declaration
            if(l_datum->header.type_id == DAP_CHAIN_DATUM_TOKEN) {
                dap_chain_datum_token_t *l_datum_token = DAP_DUP_SIZE((dap_chain_datum_token_t*)l_datum->data, l_datum->header.data_size);
                DAP_DELETE(l_datum);
                if ((l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
                    ||  (l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE))
                    l_tsd_size = l_datum_token->header_native_decl.tsd_total_size;
                // Check for signatures, are they all in set and are good enought?
                size_t l_signs_size = 0, i = 1;
                uint16_t l_tmp_signs_total = l_datum_token->signs_total;
                l_datum_token->signs_total = 0;
                for (i = 1; i <= l_tmp_signs_total; i++){
                    dap_sign_t *l_sign = (dap_sign_t *)(l_datum_token->tsd_n_signs + l_tsd_size + l_signs_size);
                    if( dap_sign_verify(l_sign, l_datum_token, sizeof(*l_datum_token) + l_tsd_size) ) {
                        log_it(L_WARNING, "Wrong signature %zu for datum_token with key %s in mempool!", i, l_datum_hash_out_str);
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_DATUM_HAS_WRONG_SIGNATURE_ERR,
                                       "Datum %s with datum token has wrong signature %zu, break process and exit",
                                        l_datum_hash_out_str, i);
                        DAP_DELETE(l_datum_token);
                        DAP_DELETE(l_gdb_group_mempool);
                        return -6;
                    }else{
                        log_it(L_DEBUG,"Sign %zu passed", i);
                    }
                    l_signs_size += dap_sign_get_size(l_sign);
                }
                l_datum_token->signs_total = l_tmp_signs_total;
                log_it(L_DEBUG, "Datum %s with token declaration: %hu signatures are verified well (sign_size = %zu)",
                                 l_datum_hash_out_str, l_datum_token->signs_total, l_signs_size);

                // Sign header with all certificates in the list and add signs to the end of token update
                uint16_t l_sign_counter = 0;
                size_t l_data_size = l_tsd_size + l_signs_size;
                l_datum_token = s_sign_cert_in_cycle(l_certs, l_datum_token, l_certs_count, &l_data_size,
                                                            &l_sign_counter);
                log_it(L_DEBUG, "Apply %hu signs to datum %s", l_sign_counter, l_datum_hash_hex_str);
                if (!l_sign_counter) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_SERT_NOT_VALID_ERR,
                                       "Error! Used certs not valid");
                    DAP_DEL_MULTY(l_datum_token, l_datum_hash_hex_str, l_datum_hash_base58_str, l_gdb_group_mempool);
                    return -9;
                }
                l_datum_token->signs_total += l_sign_counter;
                size_t l_token_size = sizeof(*l_datum_token) + l_data_size;
                l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN,
                                                                     l_datum_token, l_token_size);
                DAP_DELETE(l_datum_token);
                // Calc datum's hash
                l_datum_size = dap_chain_datum_size(l_datum);
                dap_chain_hash_fast_t l_key_hash = { };
                dap_hash_fast(l_datum->data, l_token_size, &l_key_hash);
                const char  *l_key_str = dap_chain_hash_fast_to_str_static(&l_key_hash),
                            *l_key_str_base58 = dap_enc_base58_encode_hash_to_str_static(&l_key_hash),
                            *l_key_out_str = dap_strcmp(l_hash_out_type, "hex") ? l_key_str_base58 : l_key_str;

                int rc = 0;
                // Add datum to mempool with datum_token hash as a key
                if( dap_global_db_set_sync(l_gdb_group_mempool, l_key_str, l_datum, dap_chain_datum_size(l_datum), false) == 0) {
                    char* l_hash_str = l_datum_hash_hex_str;
                    // Remove old datum from pool
                    if( dap_global_db_del_sync(l_gdb_group_mempool, l_hash_str ) == 0) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_OK,
                                       "Datum was replaced in datum pool:\n\tOld: %s\n\tNew: %s",
                                l_datum_hash_out_str, l_key_out_str);
                    } else {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_REMOVE_OLD_DATUM_ERR,
                                       "Warning! Can't remove old datum %s ( new datum %s added normaly in datum pool)",
                                l_datum_hash_out_str, l_key_out_str);
                        rc = -DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_REMOVE_OLD_DATUM_ERR;
                    }
                } else {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_DATUM_CANT_BE_PL_MEMPOOL_ERR,
                                       "Error! datum %s produced from %s can't be placed in mempool",
                            l_key_out_str, l_datum_hash_out_str);
                    rc = -DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_DATUM_CANT_BE_PL_MEMPOOL_ERR;
                }
                DAP_DEL_MULTY(l_datum_hash_hex_str, l_datum_hash_base58_str, l_datum, l_gdb_group_mempool);
                return rc;
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_WRONG_DATUM_TYPE_ERR,
                                       "Error! Wrong datum type. token_decl_sign sign only token declarations datum");
                return -DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_WRONG_DATUM_TYPE_ERR;
            }
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_FIND_DATUM_ERR,
                                       "token_decl_sign can't find datum with %s hash in the mempool of %s:%s",l_datum_hash_out_str,l_net? l_net->pub.name: "<undefined>",
                                        l_chain?l_chain->name:"<undefined>");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_FIND_DATUM_ERR;
        }
        DAP_DEL_MULTY(l_datum_hash_hex_str, l_datum_hash_base58_str);
    } else {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NEED_DATUM_ARG_ERR,
                                       "token_decl_sign need -datum <datum hash> argument");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NEED_DATUM_ARG_ERR;
    }
    return 0;
}

typedef struct _dap_cli_token_additional_params {
    const char* flags;
    const char* delegated_token_from;
    const char* total_signs_valid;
    const char *total_supply_change;
    const char* datum_type_allowed;
    const char* datum_type_blocked;
    const char* tx_receiver_allowed;
    const char* tx_receiver_blocked;
    const char* tx_sender_allowed;
    const char* tx_sender_blocked;
    uint16_t    parsed_flags;
    size_t      tsd_total_size;
    byte_t      *parsed_tsd;
} dap_cli_token_additional_params;

typedef struct _dap_sdk_cli_params {
    const char *hash_out_type;
    const char *chain_str;
    const char *net_str;
    const char *ticker;
    const char *type_str;
    const char *certs_str;
    dap_chain_t *chain;
    dap_chain_net_t *net;
    uint16_t type;
    uint16_t subtype;
    uint16_t signs_total;
    uint16_t signs_emission;
    uint256_t total_supply;
    const char* decimals_str;
    dap_cli_token_additional_params ext;
} dap_sdk_cli_params, *pdap_sdk_cli_params;

static int s_parse_common_token_decl_arg(int a_argc, char ** a_argv, json_object* a_json_arr_reply, dap_sdk_cli_params* a_params, bool a_update_token)
{
    a_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-H", &a_params->hash_out_type);
    if(!a_params->hash_out_type)
        a_params->hash_out_type = "hex";
    if(dap_strcmp(a_params->hash_out_type,"hex") && dap_strcmp(a_params->hash_out_type,"base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_INTERNAL_COMMAND_PROCESSING,
                               "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_INTERNAL_COMMAND_PROCESSING;
    }

    int l_arg_index = 0;
    int l_res = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(a_json_arr_reply, &l_arg_index, a_argc, a_argv,
                                                              &a_params->chain, &a_params->net, CHAIN_TYPE_TOKEN);

    if(!a_params->net || !a_params->chain)
        return l_res;
    //net name
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &a_params->net_str);
    //chainname
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-chain", &a_params->chain_str);
    //token_ticker
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-token", &a_params->ticker);
    // Token type
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-type", &a_params->type_str);

    if (a_update_token)
    {
        dap_chain_datum_token_t* l_current_token = dap_ledger_token_ticker_check(a_params->net->pub.ledger, a_params->ticker);
        if (!l_current_token) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_LEDGER_TOKEN_TICKER,
                               "The updated token '%s' was not found in the '%s' network ledger.",
                a_params->ticker, a_params->net->pub.name);
            return -DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_LEDGER_TOKEN_TICKER;
        }
        a_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
        a_params->subtype = l_current_token->subtype;
    } else if (a_params->type_str) {
        if (strcmp(a_params->type_str, "private") == 0) {
            a_params->type = a_update_token ? DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE : DAP_CHAIN_DATUM_TOKEN_TYPE_DECL; // 256
            a_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE;
        } else if (strcmp(a_params->type_str, "CF20") == 0) {
            a_params->type = a_update_token ? DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE : DAP_CHAIN_DATUM_TOKEN_TYPE_DECL; // 256
            a_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
        } else if (strcmp(a_params->type_str, "public_simple") == 0 && !a_update_token) {
            a_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
            a_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC; // 256
        } else  {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_UNKNOWN_TOKEN_TYPE,
                        "Unknown token type %s was specified. Supported types:\n"
                        "   private\n"
                        "   CF20\n"
                        "Default token type is CF20.\n", a_params->type_str);
            return -1;
        }
    }


    // Certificates thats will be used to sign currend datum token
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-certs", &a_params->certs_str);
    // Signs number thats own emissioncan't find
    const char* l_signs_total_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-signs_total", &l_signs_total_str);
    // Signs total
    char* l_tmp = NULL;
    if(l_signs_total_str){
        if((a_params->signs_total = (uint16_t) strtol(l_signs_total_str, &l_tmp, 10)) == 0){
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_PARAMS_MUST_BE_UNSIGNED,
                               "'signs_total' parameter must be unsigned integer value that fits in 2 bytes");
            return -8;
        }
    }
    // Signs minimum number thats need to authorize the emission
    const char* l_signs_emission_str = NULL;
    l_tmp = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-signs_emission", &l_signs_emission_str);
    if (l_signs_emission_str){
        if((a_params->signs_emission = (uint16_t) strtol(l_signs_emission_str, &l_tmp, 10)) == 0){
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_PARAMS_MUST_BE_UNSIGNED,
                        "%s requires parameter 'signs_emission' to be unsigned integer value that fits in 2 bytes", a_update_token ? "token_update" : "token_decl");
            return -6;
        }
    }
    if (!a_update_token) {
        // Total supply value
        const char* l_total_supply_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-total_supply", &l_total_supply_str);
        if (l_total_supply_str){
            a_params->total_supply = dap_chain_balance_scan(l_total_supply_str);
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_PARAMS_MUST_BE_UNSIGNED,
                                "'-total_supply' must be unsigned integer value that fits in 32 bytes\n"
                                "You are update a token, be careful!\n"
                                "You can reset total_supply and make it infinite for native (CF20) tokens only, if set 0"
                                "for private tokens, you must specify the same or more total_supply.");
            return -4;
        }
    }
    // Total supply value
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-decimals", &a_params->decimals_str);

    return 0;
}

/**
 * @brief
 *
 * @param a_tx_address
 * @param l_tsd_list
 * @param l_tsd_total_size
 * @param flag
 * @return dap_list_t*
 */
dap_list_t* s_parse_wallet_addresses(const char *a_tx_address, dap_list_t *l_tsd_list, size_t *l_tsd_total_size, uint32_t flag)
{
    dap_return_val_if_fail(a_tx_address, l_tsd_list);

    char **l_str_wallet_addr = dap_strsplit(a_tx_address,",",0xffff);
    if (!l_str_wallet_addr)
       return log_it(L_ERROR, "Can't split \"%s\" by commas!", a_tx_address), l_tsd_list;

    for (char **l_cur = l_str_wallet_addr; l_cur && *l_cur; ++l_cur) {
        log_it(L_DEBUG, "Processing wallet address: %s", *l_cur);
        dap_chain_addr_t *addr_to = dap_chain_addr_from_str(*l_cur);
        if (addr_to){
            dap_tsd_t *l_tsd = dap_tsd_create(flag, addr_to, sizeof(dap_chain_addr_t));
            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            *l_tsd_total_size += dap_tsd_size(l_tsd);
            DAP_DELETE(addr_to);
        } else
            log_it(L_ERROR, "Can't convert it to address!");
    }
    dap_strfreev(l_str_wallet_addr);
    return l_tsd_list;
}

static int s_parse_additional_token_decl_arg(int a_argc, char ** a_argv, json_object* a_json_arr_reply, dap_sdk_cli_params* a_params, bool a_update_token)
{
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-flags", &a_params->ext.flags);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-total_signs_valid", &a_params->ext.total_signs_valid);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-total_supply_change", &a_params->ext.total_supply_change);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-delegated_token_from", &a_params->ext.delegated_token_from);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-datum_type_allowed", &a_params->ext.datum_type_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-datum_type_blocked", &a_params->ext.datum_type_blocked);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_receiver_allowed", &a_params->ext.tx_receiver_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_receiver_blocked", &a_params->ext.tx_receiver_blocked);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_sender_allowed", &a_params->ext.tx_sender_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_receiver_allowed", &a_params->ext.tx_receiver_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_sender_blocked", &a_params->ext.tx_sender_blocked);

    if (a_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE)
        return 0;

    dap_list_t *l_tsd_list = NULL;
    size_t l_tsd_total_size = 0;
    uint16_t l_flags = 0;
    char ** l_str_flags = NULL;

    if (!a_update_token) {
        if (a_params->ext.flags){   // Flags
            l_str_flags = dap_strsplit(a_params->ext.flags,",",0xffff );
            for (char **l_cur = l_str_flags; l_cur && *l_cur; ++l_cur) {
                uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_cur);
                if (l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_FLAG_UNDEF,
                               "Flag can't be \"%s\"",*l_str_flags);
                    return -20;
                }
                l_flags |= l_flag; // if we have multiple flags
            }
            dap_strfreev(l_str_flags);
        }
    } else {
        const char *l_set_flags = NULL;
        const char *l_unset_flags = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-flag_set", &l_set_flags);
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-flag_unset", &l_unset_flags);
        if (l_set_flags) {
            l_str_flags = dap_strsplit(l_set_flags,",",0xffff );
            while (l_str_flags && *l_str_flags){
                uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_str_flags);
                if (l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_FLAG_UNDEF,
                               "Flag can't be \"%s\"",*l_str_flags);
                    return -20;
                }
                l_flags |= l_flag; // if we have multiple flags
                l_str_flags++;
            }
            dap_tsd_t *l_flag_set_tsd = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS, l_flags);
            l_flags = 0;
            l_tsd_list = dap_list_append(l_tsd_list, l_flag_set_tsd);
            l_tsd_total_size += dap_tsd_size(l_flag_set_tsd);
        }
        if (l_unset_flags) {
            l_str_flags = dap_strsplit(l_unset_flags,",",0xffff );
            while (l_str_flags && *l_str_flags){
                uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_str_flags);
                if (l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_FLAG_UNDEF,
                               "Flag can't be \"%s\"",*l_str_flags);
                    return -20;
                }
                l_flags |= l_flag; // if we have multiple flags
                l_str_flags++;
            }
            dap_tsd_t *l_flag_unset_tsd = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS, l_flags);
            l_flags = 0;
            l_tsd_list = dap_list_append(l_tsd_list, l_flag_unset_tsd);
            l_tsd_total_size += dap_tsd_size(l_flag_unset_tsd);
        }
    }

    if (a_params->ext.total_signs_valid){ // Signs valid
        uint16_t l_param_value = (uint16_t)atoi(a_params->ext.total_signs_valid);
        dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID, l_param_value);
        l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
        l_tsd_total_size+= dap_tsd_size(l_tsd);
    }
    if (a_params->ext.datum_type_allowed){
        dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD, a_params->ext.datum_type_allowed);
        l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
        l_tsd_total_size+= dap_tsd_size(l_tsd);
    }
    if (a_params->ext.datum_type_blocked){
        dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD, a_params->ext.datum_type_blocked);
        l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
        l_tsd_total_size+= dap_tsd_size(l_tsd);
    }
    if (a_params->ext.tx_receiver_allowed)
        l_tsd_list = s_parse_wallet_addresses(a_params->ext.tx_receiver_allowed, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD);

    if (a_params->ext.tx_receiver_blocked)
        l_tsd_list = s_parse_wallet_addresses(a_params->ext.tx_receiver_blocked, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD);

    if (a_params->ext.tx_sender_allowed)
        l_tsd_list = s_parse_wallet_addresses(a_params->ext.tx_sender_allowed, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD);

    if (a_params->ext.tx_sender_blocked)
        l_tsd_list = s_parse_wallet_addresses(a_params->ext.tx_sender_blocked, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD);


    const char* l_new_certs_str = NULL;
    const char* l_remove_signs = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-add_certs", &l_new_certs_str);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-remove_certs", &l_remove_signs);
    const char *l_description  = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-description", &l_description);

    //Added remove signs
    if (l_remove_signs) {
        size_t l_added_tsd_size = 0;
        char *l_remove_signs_ptrs = NULL;
        char *l_remove_signs_dup = strdup(l_remove_signs);
        char *l_remove_signs_str = strtok_r(l_remove_signs_dup, ",", &l_remove_signs_ptrs);
        for (; l_remove_signs_str; l_remove_signs_str = strtok_r(NULL, ",", &l_remove_signs_ptrs)) {
            dap_hash_fast_t l_hf;
            if (dap_chain_hash_fast_from_str(l_remove_signs_str, &l_hf) == 0) {
                dap_tsd_t *l_hf_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE, &l_hf, sizeof(dap_hash_fast_t));
                size_t l_hf_tsd_size = dap_tsd_size(l_hf_tsd);
                l_tsd_list = dap_list_append(l_tsd_list, l_hf_tsd);
                l_added_tsd_size += l_hf_tsd_size;
            }
        }
        DAP_DELETE(l_remove_signs_dup);
        l_tsd_total_size += l_added_tsd_size;
    }
    //Added new certs
    dap_cert_t **l_new_certs = NULL;
    size_t l_new_certs_count = 0;
    if (l_new_certs_str) {
        dap_cert_parse_str_list(l_new_certs_str, &l_new_certs, &l_new_certs_count);
        for (size_t i = 0; i < l_new_certs_count; i++) {
            dap_pkey_t *l_pkey = dap_cert_to_pkey(l_new_certs[i]);
            if (!l_pkey) {
                log_it(L_ERROR, "Can't get pkey for cert: %s", l_new_certs[i]->name);
                continue;
            }
            size_t l_pkey_size = sizeof(dap_pkey_t) + l_pkey->header.size;
            dap_tsd_t *l_pkey_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD, l_pkey, l_pkey_size);
            size_t l_pkey_tsd_size = dap_tsd_size(l_pkey_tsd);
            l_tsd_list = dap_list_append(l_tsd_list, l_pkey_tsd);
            l_tsd_total_size += l_pkey_tsd_size;
            DAP_DELETE(l_pkey);
        }
        DAP_DEL_Z(l_new_certs);
    }
    if (l_description) {
        dap_tsd_t *l_desc_token = dap_tsd_create_string(DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION, l_description);
        l_tsd_list = dap_list_append(l_tsd_list, l_desc_token);
        l_tsd_total_size += dap_tsd_size(l_desc_token);
    }
    if (a_params->ext.total_supply_change) {
        uint256_t l_total_supply = uint256_0;
        if (dap_strcmp(a_params->ext.total_supply_change, "INF")) {
            l_total_supply = dap_chain_balance_scan(a_params->ext.total_supply_change);
            if (IS_ZERO_256(l_total_supply)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_FLAG_UNDEF,
                               "Unable to convert value '%s' to uint256_t, use INF, number, or integer.0e+degree to represent infinity",
                                                  a_params->ext.total_supply_change);
                return -2;
            }
        }
        dap_tsd_t *l_tsd_change_total_supply = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY, l_total_supply);
        l_tsd_list = dap_list_append(l_tsd_list, l_tsd_change_total_supply);
        l_tsd_total_size += dap_tsd_size(l_tsd_change_total_supply);
    }
    size_t l_tsd_offset = 0;
    a_params->ext.parsed_tsd = DAP_NEW_SIZE(byte_t, l_tsd_total_size);
    if(l_tsd_total_size && !a_params->ext.parsed_tsd) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    for (dap_list_t *l_iter = dap_list_first(l_tsd_list); l_iter; l_iter = l_iter->next) {
        dap_tsd_t * l_tsd = (dap_tsd_t *) l_iter->data;
        if (!l_tsd){
            log_it(L_ERROR, "NULL tsd in list!");
            continue;
        }
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        memcpy(a_params->ext.parsed_tsd + l_tsd_offset, l_tsd, l_tsd_size);
        l_tsd_offset += l_tsd_size;
    }
    a_params->ext.tsd_total_size = l_tsd_total_size;
    dap_list_free_full(l_tsd_list, NULL);
    return 0;
}

static int s_token_decl_check_params_json(int a_argc, char **a_argv, json_object* a_json_arr_reply, dap_sdk_cli_params *a_params, bool a_update_token)
{
    int l_parse_params = s_parse_common_token_decl_arg(a_argc,a_argv, a_json_arr_reply, a_params, a_update_token);
    if (l_parse_params)
        return l_parse_params;

    l_parse_params = s_parse_additional_token_decl_arg(a_argc,a_argv, a_json_arr_reply, a_params, a_update_token);
    if (l_parse_params)
        return l_parse_params;

    //DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL uses decimals parameter
    if (!a_update_token) {
        //// check l_decimals in CF20 token TODO: At the moment the checks are the same.
        if(!a_params->decimals_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_REQUIRES_PARAM,
                               "token_decl requires parameter '-decimals'");
            return -3;
        } else if (dap_strcmp(a_params->decimals_str, "18")) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_REQUIRES_PARAM,
                               "token_decl support '-decimals' to be 18 only");
            return -4;
        }
    }

    if (!a_params->signs_emission && !a_update_token) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_REQUIRES_PARAM,
                               "token_decl requires parameter '-signs_emission'");
        return -5;
    }

    if (!a_params->signs_total && !a_update_token){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_REQUIRES_PARAM,
                               "token_decl requires parameter '-signs_total'");
        return -7;
    }

    if(!a_params->ticker){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_REQUIRES_PARAM,
                               "%s requires parameter '-token'", a_update_token ? "token_update" : "token_decl");
        return -2;
    }

    // Check certs list
    if(!a_params->certs_str){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_REQUIRES_PARAM,
                               "%s requires parameter 'certs'", a_update_token ? "token_update" : "token_decl");
        return -9;
    }
    return 0;
}

/**
 * @brief com_token_decl
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 * @details token_decl -net <net name> -chain <chain name> -token <token ticker> -total_supply <total supply> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list>\n"
 *  \t Declare new simple token for <netname>:<chain name> with ticker <token ticker>, maximum emission <total supply> and <signs for emission> from <signs total> signatures on valid emission\n"
 *  \t   Extended private token declaration\n"
 *  \t token_decl -net <net name> -chain <chain name> -token <token ticker> -type private -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...  [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
 *  \t   Declare new token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>"
 *  \t   and custom parameters list <Param 1>, <Param 2>...<Param N>."
 *  \n"
 *  ==Flags=="
 *  \t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
 *  \t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
 *  \t ALL_FROZEN:\t All permissions are temprorary frozen\n"
 *  \t ALL_UNFROZEN:\t Unfrozen permissions\n"
 *  \t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
 *  \t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
 *  \t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
    "\n"
    "==Params==\n"
    "General:\n"
    "\t -flags <value>:\t Set list of flags from <value> to token declaration\n"
    "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
    "\t -signs_valid <value>:\t Set valid signatures count's minimum\n"
    "\t -signs <value>:\t Add signature's pkey fingerprint to the list of owners\n"
    "\nDatum type allowed/blocked:\n"
    "\t -datum_type_allowed <value>:\t Allowed datum type(s)\n"
    "\t -datum_type_blocked <value>:\t Blocked datum type(s)\n"
    "\nTx receiver addresses allowed/blocked:\n"
    "\t -tx_receiver_allowed <value>:\t Allowed tx receiver(s)\n"
    "\t -tx_receiver_blocked <value>:\t Blocked tx receiver(s)\n"
    "\n Tx sender addresses allowed/blocked:\n"
    "\t -tx_sender_allowed <value>:\t Allowed tx sender(s)\n"
    "\t -tx_sender_blocked <value>:\t Blocked tx sender(s)\n"
    "\n"
 */
int com_token_decl(int a_argc, char ** a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    dap_json_t ** a_json_arr_reply = (json_object **) a_str_reply;
    const char * l_ticker = NULL;
    uint256_t l_total_supply = {}; // 256
    uint16_t l_signs_emission = 0;
    uint16_t l_signs_total = 0;
    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;
    const char * l_hash_out_type = NULL;

    dap_sdk_cli_params l_params = { .type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL, .subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE };

    int l_parse_params = s_token_decl_check_params_json(a_argc,a_argv,*a_json_arr_reply, &l_params, false);
    if (l_parse_params)
        return l_parse_params;

    dap_chain_datum_token_t * l_datum_token = NULL;
    size_t l_datum_data_offset = 0;

    // Load certs lists
    dap_cert_parse_str_list(l_params.certs_str, &l_certs, &l_certs_count);
    if(!l_certs_count){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_NOT_VALID_CERT_ERR,
                                       "token_decl command requres at least one valid certificate to sign token");
        return -10;
    }

    l_signs_emission = l_params.signs_emission;
    l_signs_total = l_params.signs_total;
    l_total_supply = l_params.total_supply;
    l_chain = l_params.chain;
    l_net = l_params.net;
    l_ticker = l_params.ticker;
    l_hash_out_type = l_params.hash_out_type;

    switch(l_params.subtype)
    {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
        { // 256
            dap_list_t *l_tsd_list = NULL;
            size_t l_tsd_local_list_size = 0;

            if (l_params.ext.delegated_token_from){
                dap_chain_datum_token_t *l_delegated_token_from;
                if (NULL == (l_delegated_token_from = dap_ledger_token_ticker_check(l_net->pub.ledger, l_params.ext.delegated_token_from))) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_FIND_TICKER_ERR,
                                       "To create a delegated token %s, can't find token by ticket %s", l_ticker, l_params.ext.delegated_token_from);
                    return -91;
                }
                if (!dap_strcmp(l_ticker, l_params.ext.delegated_token_from)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_TOKEN_CANNOT_MATCH,
                                       "Delegated token ticker cannot match the original ticker");
                    return -92;
                }

                dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section;
                dap_strncpy((char*)l_tsd_section.ticker_token_from, l_params.ext.delegated_token_from, DAP_CHAIN_TICKER_SIZE_MAX);
//				l_tsd_section.token_from = dap_hash_fast();
                l_tsd_section.emission_rate = dap_chain_balance_coins_scan("0.001");//	TODO: 'm' 1:1000 tokens
                dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                        DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK, l_tsd_section);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                l_tsd_local_list_size += dap_tsd_size(l_tsd);
            }

            if (l_params.ext.total_signs_valid) {
                l_signs_total = (uint16_t)atoi(l_params.ext.total_signs_valid);
            }


            size_t l_tsd_total_size = l_tsd_local_list_size + l_params.ext.tsd_total_size;


            // if (l_params.ext.parsed_tsd)
                // l_tsd_total_size += l_params.ext.tsd_total_size;


            // Create new datum token
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t) + l_tsd_total_size);
            if (!l_datum_token) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_CANT_CREATE_DATUM,
                                       "Out of memory in com_token_decl");
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->type = l_params.type;
            l_datum_token->subtype = l_params.subtype;
            if (l_params.subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE) {
                log_it(L_DEBUG,"Prepared TSD sections for private token on %zd total size", l_tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->header_private_decl.flags = l_params.ext.parsed_flags;
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_private_decl.tsd_total_size = l_tsd_local_list_size + l_params.ext.tsd_total_size;
                l_datum_token->header_private_decl.decimals = atoi(l_params.decimals_str);
            } else { //DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL
                log_it(L_DEBUG,"Prepared TSD sections for CF20 token on %zd total size", l_tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->header_native_decl.flags = l_params.ext.parsed_flags;
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_native_decl.tsd_total_size = l_tsd_total_size;
                l_datum_token->header_native_decl.decimals = atoi(l_params.decimals_str);
            }
            // Add TSD sections in the end
            for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
                dap_tsd_t * l_tsd = (dap_tsd_t *) l_iter->data;
                if (l_tsd == NULL){
                    log_it(L_ERROR, "NULL tsd in list!");
                    continue;
                }
                switch (l_tsd->type){
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
                    uint16_t l_t = 0;
                        log_it(L_DEBUG,"== TOTAL_SIGNS_VALID: %u",
                                _dap_tsd_get_scalar(l_tsd, &l_t) );
                    break;
                }
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD:
                        log_it(L_DEBUG,"== DATUM_TYPE_ALLOWED_ADD: %s",
                               dap_tsd_get_string_const(l_tsd) );
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                        log_it(L_DEBUG,"== TX_SENDER_ALLOWED_ADD: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                        log_it(L_DEBUG,"== TYPE_TX_SENDER_BLOCKED: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                        log_it(L_DEBUG,"== TX_RECEIVER_ALLOWED_ADD: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                        log_it(L_DEBUG,"== TX_RECEIVER_BLOCKED_ADD: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD:
                        if(l_tsd->size >= sizeof(dap_pkey_t)){
                            char *l_hash_str;
                            dap_pkey_t *l_pkey = (dap_pkey_t*)l_tsd->data;
                            dap_hash_fast_t l_hf = {0};
                            if (!dap_pkey_get_hash(l_pkey, &l_hf)) {
                                log_it(L_DEBUG, "== TOTAL_PKEYS_ADD: <WRONG CALCULATION FINGERPRINT>");
                            } else {
                                log_it(L_DEBUG, "== TOTAL_PKEYS_ADD: %s",
                                    dap_chain_hash_fast_to_str_static(&l_hf));
                            }
                        } else
                            log_it(L_DEBUG,"== TOTAL_PKEYS_ADD: <WRONG SIZE %u>", l_tsd->size);
                        break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION:
                        log_it(L_DEBUG, "== DESCRIPTION: %s", l_tsd->data);
                        break;
                    default: log_it(L_DEBUG, "== 0x%04X: binary data %u size ",l_tsd->type, l_tsd->size );
                }
                size_t l_tsd_size = dap_tsd_size(l_tsd);
                memcpy(l_datum_token->tsd_n_signs + l_datum_data_offset, l_tsd, l_tsd_size);
                l_datum_data_offset += l_tsd_size;
            }
            if (l_params.ext.parsed_tsd) {
                memcpy(l_datum_token->tsd_n_signs + l_datum_data_offset,
                       l_params.ext.parsed_tsd,
                       l_params.ext.tsd_total_size);
                l_datum_data_offset += l_params.ext.tsd_total_size;
                DAP_DELETE(l_params.ext.parsed_tsd);
            }
            dap_list_free_full(l_tsd_list, NULL);
            log_it(L_DEBUG, "%s token declaration '%s' initialized", l_params.subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE ?
                            "Private" : "CF20", l_datum_token->ticker);
        }break;//end
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE: { // 256
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t));
            if (!l_datum_token) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_CANT_CREATE_DATUM,
                                       "Out of memory in com_token_decl");
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL; // 256
            l_datum_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE; // 256
            snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
            l_datum_token->total_supply = l_total_supply;
            l_datum_token->signs_valid = l_signs_emission;
            l_datum_token->header_simple.decimals = atoi(l_params.decimals_str);
        }break;
        default:
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_UNKNOWN_TOKEN_TYPE,
                                       "Unknown token type");
            return -8;
    }
    dap_uuid_generate_nonce(&l_datum_token->nonce, DAP_CHAIN_DATUM_NONCE_SIZE);
    // If we have more certs than we need signs - use only first part of the list
    if(l_certs_count > l_signs_total)
        l_certs_count = l_signs_total;
    // Sign header with all certificates in the list and add signs to the end of TSD cetions
    uint16_t l_sign_counter = 0;
    l_datum_token = s_sign_cert_in_cycle(l_certs, l_datum_token, l_certs_count, &l_datum_data_offset, &l_sign_counter);
    l_datum_token->signs_total = l_sign_counter;

    // We skip datum creation opeartion, if count of signed certificates in s_sign_cert_in_cycle is 0.
    // Usually it happen, when certificate in token_decl or token_update command doesn't contain private data or broken
    if (!l_datum_token || l_datum_token->signs_total == 0){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_FAILED,
                     "Token declaration failed. Successful count of certificate signing is 0");
            return -9;
    }

    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN,
                                                         l_datum_token,
                                                         sizeof(*l_datum_token) + l_datum_data_offset);
    DAP_DELETE(l_datum_token);
    size_t l_datum_size = dap_chain_datum_size(l_datum);

    // Calc datum's hash
    dap_chain_hash_fast_t l_key_hash;
    dap_chain_datum_calc_hash(l_datum, &l_key_hash);
    char *l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    const char *l_key_str_out = dap_strcmp(l_hash_out_type, "hex") ?
                           dap_enc_base58_encode_hash_to_str_static(&l_key_hash) : l_key_str;

    // Add datum to mempool with datum_token hash as a key
    char *l_gdb_group_mempool = l_chain
            ? dap_chain_mempool_group_new(l_chain)
            : dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);
    if (!l_gdb_group_mempool) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_NO_SUITABLE_CHAIN,
                     "No suitable chain for placing token datum found");
        DAP_DELETE(l_datum);
        return -10;
    }
    bool l_placed = dap_global_db_set_sync(l_gdb_group_mempool, l_key_str, l_datum, l_datum_size, false) == 0;
    DAP_DELETE(l_gdb_group_mempool);

    dap_json_t *json_obj_out = dap_json_object_new();
    char *l_str_reply_tmp = dap_strdup_printf("Datum %s with token %s is%s placed in datum pool", l_key_str_out, l_ticker, l_placed ? "" : " not");
    dap_json_object_add_string(json_obj_out, "result", l_str_reply_tmp);
    DAP_DELETE(l_str_reply_tmp);
    dap_json_array_add(*a_json_arr_reply, json_obj_out);
    DAP_DELETE(l_key_str);
    DAP_DELETE(l_datum);

    return l_placed ? 0 : -2;
}

/**
 * @brief com_token_decl_update
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 * @details token_update -net <net name> -chain <chain_name> -token <token ticker> [-type private] -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...  [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
 *  \t   Update token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>"
 *  \t   and custom parameters list <Param 1>, <Param 2>...<Param N>."
 *  \n"
 *  ==Flags=="
 *  \t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
 *  \t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
 *  \t ALL_FROZEN:\t All permissions are temprorary frozen\n"
 *  \t ALL_UNFROZEN:\t Unfrozen permissions\n"
 *  \t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
 *  \t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
 *  \t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
    "\n"
    "==Params==\n"
    "General:\n"
    "\t -flags_set <value>:\t Set list of flags from <value> to token declaration\n"
    "\t -flags_unset <value>:\t Unset list of flags from <value> from token declaration\n"
    "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
    "\t -total_signs_valid <value>:\t Set valid signatures count's minimum\n"
    "\t -total_signs_add <value>:\t Add signature's pkey fingerprint to the list of owners\n"
    "\t -total_signs_remove <value>:\t Remove signature's pkey fingerprint from the owners\n"
    "\nDatum type allowed/blocked updates:\n"
    "\t -datum_type_allowed_add <value>:\t Add allowed datum type(s)\n"
    "\t -datum_type_allowed_remove <value>:\t Remove datum type(s) from allowed\n"
    "\t -datum_type_blocked_add <value>:\t Add blocked datum type(s)\n"
    "\t -datum_type_blocked_remove <value>:\t Remove datum type(s) from blocked\n"
    "\nTx receiver addresses allowed/blocked updates:\n"
    "\t -tx_receiver_allowed_add <value>:\t Add allowed tx receiver(s)\n"
    "\t -tx_receiver_allowed_remove <value>:\t Remove tx receiver(s) from allowed\n"
    "\t -tx_receiver_blocked_add <value>:\t Add blocked tx receiver(s)\n"
    "\t -tx_receiver_blocked_remove <value>:\t Remove tx receiver(s) from blocked\n"
    "\n Tx sender addresses allowed/blocked updates:\n"
    "\t -tx_sender_allowed_add <value>:\t Add allowed tx sender(s)\n"
    "\t -tx_sender_allowed_remove <value>:\t Remove tx sender(s) from allowed\n"
    "\t -tx_sender_blocked_add <value>:\t Add allowed tx sender(s)\n"
    "\t -tx_sender_blocked_remove <value>:\t Remove tx sender(s) from blocked\n"
    "\n"
 */
int com_token_update(int a_argc, char ** a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    dap_json_t ** a_json_arr_reply = (json_object **) a_str_reply;
    const char * l_ticker = NULL;
    uint256_t l_total_supply = {}; // 256
    uint16_t l_signs_emission = 0;
    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;
    const char * l_hash_out_type = NULL;

    dap_sdk_cli_params l_params = { .type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE, .subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE };
    int l_parse_params = s_token_decl_check_params_json(a_argc,a_argv,*a_json_arr_reply, &l_params, true);
    if (l_parse_params)
        return l_parse_params;

    dap_chain_datum_token_t * l_datum_token = NULL;
    size_t l_datum_data_offset = 0;

    // Load certs lists
    dap_cert_parse_str_list(l_params.certs_str, &l_certs, &l_certs_count);
    if(!l_certs_count){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_NOT_VALID_CERT_ERR,
                                       "com_token_update command requres at least one valid certificate to sign token");
        return -10;
    }

    l_net = l_params.net;
    l_signs_emission = 0;
    l_total_supply = uint256_0;
    l_chain = l_params.chain;
    l_ticker = l_params.ticker;
    l_hash_out_type = l_params.hash_out_type;

    switch(l_params.subtype)
    {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
        { // 256
            // Create new datum token
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t) + l_params.ext.tsd_total_size);
            if (!l_datum_token) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
            l_datum_token->subtype = l_params.subtype;
            if (l_params.subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE) {
                log_it(L_DEBUG,"Prepared TSD sections for CF20 token on %zd total size", l_params.ext.tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_native_update.tsd_total_size = l_params.ext.tsd_total_size;
                l_datum_token->header_native_update.decimals = 0;
                l_datum_data_offset = l_params.ext.tsd_total_size;
            } else { // if (l_params.type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE) {
                log_it(L_DEBUG,"Prepared TSD sections for private token on %zd total size", l_params.ext.tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_private_update.tsd_total_size = l_params.ext.tsd_total_size;
                l_datum_token->header_private_update.decimals = 0;
                l_datum_data_offset = l_params.ext.tsd_total_size;
            }
            // Add TSD sections in the end
            if (l_params.ext.tsd_total_size) {
                memcpy(l_datum_token->tsd_n_signs, l_params.ext.parsed_tsd, l_params.ext.tsd_total_size);
                DAP_DELETE(l_params.ext.parsed_tsd);
            }
            log_it(L_DEBUG, "%s token declaration update '%s' initialized", (	l_params.subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)	?
                                                                     "Private" : "CF20", l_datum_token->ticker);
        }break;//end
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE: { // 256
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t));
            if (!l_datum_token) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->subtype = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
            l_datum_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE; // 256
            snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
            l_datum_token->total_supply = l_total_supply;
            l_datum_token->signs_valid = l_signs_emission;
            if (l_params.decimals_str)
                l_datum_token->header_simple.decimals = 0;
        }break;
        default:
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_UNKNOWN_TOKEN_TYPE,
                                       "Unknown token type");
            return -8;
    }
    dap_uuid_generate_nonce(&l_datum_token->nonce, DAP_CHAIN_DATUM_NONCE_SIZE);
    // Sign header with all certificates in the list and add signs to the end of TSD cetions
    uint16_t l_sign_counter = 0;
    l_datum_token = s_sign_cert_in_cycle(l_certs, l_datum_token, l_certs_count, &l_datum_data_offset, &l_sign_counter);
    l_datum_token->signs_total = l_sign_counter;

    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN,
                                                         l_datum_token,
                                                         sizeof(*l_datum_token) + l_datum_data_offset);
    DAP_DELETE(l_datum_token);
    size_t l_datum_size = dap_chain_datum_size(l_datum);

    // Calc datum's hash
    dap_chain_hash_fast_t l_key_hash;
    dap_chain_datum_calc_hash(l_datum, &l_key_hash);
    char *l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    const char *l_key_str_out = dap_strcmp(l_hash_out_type, "hex") ?
                           dap_enc_base58_encode_hash_to_str_static(&l_key_hash) : l_key_str;

    // Add datum to mempool with datum_token hash as a key
    char *l_gdb_group_mempool = l_chain
            ? dap_chain_mempool_group_new(l_chain)
            : dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);
    if (!l_gdb_group_mempool) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_NO_SUITABLE_CHAIN,
                                   "No suitable chain for placing token datum found");
        DAP_DELETE(l_datum);
        return -10;
    }
    bool l_placed = !dap_global_db_set_sync(l_gdb_group_mempool, l_key_str, (uint8_t *)l_datum, l_datum_size, false);
    DAP_DELETE(l_gdb_group_mempool);
    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_OK,
                           "Datum %s with token update for ticker %s is%s placed in datum pool",
                                                                 l_key_str_out, l_ticker, l_placed ? "" : " not");
    DAP_DELETE(l_key_str);
    DAP_DELETE(l_datum);
    return l_placed ? 0 : -2;
}

/**
 * @brief com_token_emit
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_token_emit(int a_argc, char **a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    dap_json_t ** a_json_arr_reply = (json_object **) a_str_reply;
    int arg_index = 1;
    const char *str_tmp = NULL;
    //const char *str_fee = NULL;
    char *l_str_reply_tmp = NULL;
    uint256_t l_emission_value = {};
    //uint256_t l_fee_value = {};
    const char * l_ticker = NULL;

    const char * l_addr_str = NULL;

    const char * l_emission_hash_str = NULL;
    const char * l_emission_hash_str_remove = NULL;
    dap_chain_hash_fast_t l_emission_hash;
    dap_chain_datum_token_emission_t *l_emission = NULL;
    size_t l_emission_size;

    const char * l_certs_str = NULL;

    dap_cert_t ** l_certs = NULL;
    size_t l_certs_size = 0;

    const char * l_chain_emission_str = NULL;
    dap_chain_t * l_chain_emission = NULL;

    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_H_PARAM_ERR,
                                   "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_H_PARAM_ERR;
    }

    dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &arg_index,a_argc,a_argv,NULL, &l_net, CHAIN_TYPE_INVALID);
    if( ! l_net) { // Can't find such network
        return -43;
    }
    // Token emission
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-emission", &l_emission_hash_str);

    // Emission certs
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);

    // Wallet address that recieves the emission
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);

    // Token ticker
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_ticker);

    if(!l_certs_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CERTS,
                                   "token_emit requires parameter '-certs'");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CERTS;
    }
    dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_size);

    if(!l_certs_size) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_NOT_VALID_CERT_ERRS,
                                   "token_emit command requres at least one valid certificate to sign the basic transaction of emission");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_NOT_VALID_CERT_ERRS;
    }
    const char *l_add_sign = NULL;
    dap_chain_addr_t *l_addr = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "sign", &l_add_sign);
    if (!l_add_sign) {      //Create the emission
        // Emission value
        if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-emission_value", &str_tmp)) {
            l_emission_value = dap_chain_balance_scan(str_tmp);
        }

        if (IS_ZERO_256(l_emission_value)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION_VAL,
                                   "token_emit requires parameter '-emission_value'");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION_VAL;
        }

        if(!l_addr_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_ADDR,
                                   "token_emit requires parameter '-addr'");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_ADDR;
        }

        if(!l_ticker) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN,
                                   "token_emit requires parameter '-token'");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN;
        }

        l_addr = dap_chain_addr_from_str(l_addr_str);

        if(!l_addr) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_ADDR_INVALID_ERR,
                                   "address \"%s\" is invalid", l_addr_str);
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_ADDR_INVALID_ERR;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain_emission", &l_chain_emission_str);
        if(l_chain_emission_str)
            l_chain_emission = dap_chain_net_get_chain_by_name(l_net, l_chain_emission_str);
        else
            l_chain_emission = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_EMISSION);

        if (l_chain_emission == NULL) { // Can't find such chain
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CHAIN_EMISSION,
                                   "token_emit requires parameter '-chain_emission' to be valid chain name in chain net %s"
                                   "or set default datum type in chain configuration file", l_net->pub.name);
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CHAIN_EMISSION;
        }
    } else {
        if (l_emission_hash_str) {
            DL_FOREACH(l_net->pub.chains, l_chain_emission) {
                l_emission = dap_chain_mempool_emission_get(l_chain_emission, l_emission_hash_str);
                if (l_emission){
                    l_emission_hash_str_remove = l_emission_hash_str;
                    break;
                }
            }
            if (!l_emission){
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_CANT_FIND_EMI_ERR,
                                   "Can't find emission with hash \"%s\" for token %s on network %s",
                                                  l_emission_hash_str, l_ticker, l_net->pub.name);
                return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_CANT_FIND_EMI_ERR;
            }
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION,
                                   "Subcommand 'sign' recuires parameter '-emission'");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION;
        }
    }

    if (!l_add_sign) {
        // Check, if network ID is same as ID in destination wallet address. If not - operation is cancelled.
        if (!dap_chain_addr_is_blank(l_addr) && l_addr->net_id.uint64 != l_net->pub.id.uint64) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION,
                                   "destination wallet network ID=0x%"DAP_UINT64_FORMAT_x
                                                           " and network ID=0x%"DAP_UINT64_FORMAT_x" is not equal."
                                                           " Please, change network name or wallet address",
                                                           l_addr->net_id.uint64, l_net->pub.id.uint64);
            DAP_DEL_Z(l_addr);
            DAP_DEL_Z(l_emission);
            return -3;
        }

        if(!l_ticker) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN,
                                   "token_emit requires parameter '-token'");
            DAP_DEL_Z(l_addr);
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN;
        }

        if (!l_chain_emission) {
            if ( (l_chain_emission = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_EMISSION)) == NULL ) {
                DAP_DEL_Z(l_addr);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CHAIN_EMISSION,
                    "token_create requires parameter '-chain_emission' to be valid chain name in chain net %s or set default datum type in chain configuration file",
                         l_net->pub.name);
                return -DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CHAIN_EMISSION;
            }
        }
        // Create emission datum
        l_emission = dap_chain_datum_emission_create(l_emission_value, l_ticker, l_addr);
    }
    // Then add signs
    for(size_t i = 0; i < l_certs_size; i++)
        l_emission = dap_chain_datum_emission_add_sign(l_certs[i]->enc_key, l_emission);
    // Calc emission's hash
    l_emission_size = dap_chain_datum_emission_get_size((uint8_t *)l_emission);
    dap_hash_fast(l_emission, l_emission_size, &l_emission_hash);
    // Produce datum
    dap_chain_datum_t *l_datum_emission = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_EMISSION,
            l_emission,
            l_emission_size);
    // Delete token emission
    DAP_DEL_Z(l_emission);
    l_emission_hash_str = dap_chain_mempool_datum_add(l_datum_emission, l_chain_emission, l_hash_out_type);
    if (l_emission_hash_str)
        l_str_reply_tmp = dap_strdup_printf("Datum %s with 256bit emission is placed in datum pool", l_emission_hash_str);
    else
        l_str_reply_tmp = dap_strdup("Can't place emission datum in mempool, examine log files");
    DAP_DEL_Z(l_emission_hash_str);
    DAP_DEL_Z(l_datum_emission);

    //remove previous emission datum from mempool if have new signed emission datum
    if (l_emission_hash_str_remove) {
        char *l_gdb_group_mempool_emission = dap_chain_mempool_group_new(l_chain_emission);
        dap_global_db_del_sync(l_gdb_group_mempool_emission, l_emission_hash_str_remove);
        DAP_DEL_Z(l_gdb_group_mempool_emission);
    }
    dap_json_t* json_obj_out = dap_json_object_new();
    dap_json_object_add_string(json_obj_out, "result", l_str_reply_tmp);
    dap_json_array_add(*a_json_arr_reply, json_obj_out);
    return DAP_DEL_MULTY(l_certs, l_str_reply_tmp, l_addr), 0;
}

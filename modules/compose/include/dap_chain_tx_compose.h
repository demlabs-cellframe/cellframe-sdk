/*
 * Authors:
 * Roman Padenkov <roman.padenkov@demlabs.net>
 * Olzhas Zharasbaev <oljas.jarasbaev@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2025-2026
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

 #pragma once
 #include "dap_chain_common.h"
 #include "dap_list.h"
 #include "dap_math_ops.h"
 #include "dap_chain_datum_tx.h"
 #include "dap_chain_wallet.h"
 #include "dap_chain_net_srv_xchange.h"

 #include <json-c/json.h>

#define NET_COUNT 6

typedef struct {
    char name[20];
    char native_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_net_id_t net_id;
    char url[128];
    uint16_t port;
} NetInfo;

typedef struct {
    const char *net_name;
    const char *url_str;
    const char *cert_path;
    uint16_t port;
    bool enc;
    json_object *response_handler;
} compose_config_t;

static NetInfo netinfo[NET_COUNT] = {
    {"riemann",  "tKEL",  {.uint64 = 0x000000000000dddd}, "45.76.140.191", 8081},
    {"raiden",   "tCELL", {.uint64 = 0x000000000000bbbb}, "http://rpc.cellframe.net", 8081},
    {"KelVPN",   "KEL",   {.uint64 = 0x1807202300000000}, "http://rpc.cellframe.net", 8081},
    {"Backbone", "CELL",  {.uint64 = 0x0404202200000000}, "http://rpc.cellframe.net", 8081},
    {"mileena",  "tMIL",  {.uint64 = 0x000000000000cccc}, "http://rpc.cellframe.net", 8081},
    {"subzero",  "tCELL", {.uint64 = 0x000000000000acca}, "http://rpc.cellframe.net", 8081}
};




#ifdef __cplusplus
extern "C" {
#endif

const char* dap_compose_get_net_url(const char* name);
uint16_t dap_compose_get_net_port(const char* name);
dap_chain_net_id_t dap_get_net_id(const char* name);

int dap_tx_json_tsd_add(json_object * json_tx, json_object * json_add);
json_object* dap_enc_request_command_to_rpc(const char *a_request, const char * a_url, uint16_t a_port, const char * a_cert_path);

json_object* dap_request_command_to_rpc(const char *request, compose_config_t *a_config);
json_object* dap_request_command_to_rpc_with_params(compose_config_t *a_config, const char *a_method, const char *msg, ...);

bool dap_get_remote_net_fee_and_address(uint256_t *a_net_fee, dap_chain_addr_t **l_addr_fee, compose_config_t *a_config);
bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker,
                                         json_object **l_outs, int *l_outputs_count, compose_config_t *a_config);
bool check_token_in_ledger(json_object *l_json_coins, const char *a_token);

dap_list_t *dap_ledger_get_list_tx_outs_from_json(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer);
dap_list_t *dap_ledger_get_list_tx_outs_from_json_all(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer);
dap_list_t *dap_ledger_get_list_tx_outs_from_jso_ex(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, 
                                                    uint256_t *a_value_transfer, bool a_need_all_outputs);
dap_chain_tx_out_cond_t *dap_find_last_xchange_tx(dap_hash_fast_t *a_order_hash,  dap_chain_addr_t *a_seller_addr,  compose_config_t * a_config, 
                                                  dap_time_t *a_ts_created, char **a_token_ticker, uint32_t *a_prev_cond_idx, dap_hash_fast_t *a_hash_out);

json_object* dap_tx_create_compose(const char *l_net_str, const char *l_token_ticker, const char *l_value_str, 
                                  const char *l_fee_str, const char *addr_base58_to, dap_chain_addr_t *l_addr_from, 
                                  const char *l_url_str, uint16_t l_port, const char *l_enc_cert);

json_object* dap_tx_create_xchange_compose(const char *l_net_str, const char *l_token_sell, const char *l_token_buy, 
                                          dap_chain_addr_t * l_wallet_addr, const char *l_value_str, const char *l_rate_str, const char *l_fee_str, 
                                          const char *l_url_str, uint16_t l_port, const char *l_enc_cert);

json_object* dap_tx_cond_create_compose(const char *a_net_name, const char *a_token_ticker, dap_chain_addr_t *a_wallet_addr, const char *a_cert_str, 
                                       const char *a_value_datoshi_str, const char *a_value_fee_str, const char *a_unit_str, const char *a_value_per_unit_max_str,
                                       const char *a_srv_uid_str, const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

json_object* dap_cli_hold_compose(const char *a_net_name, const char *a_chain_id_str, const char *a_ticker_str, 
                                 dap_chain_addr_t *a_wallet_addr, const char *a_coins_str, 
                                 const char *a_time_staking_str, const char *a_cert_str, const char *a_value_fee_str, 
                                 const char *a_reinvest_percent_str, const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

json_object* dap_cli_take_compose(const char *a_net_name, const char *a_chain_id_str, dap_chain_addr_t *a_wallet_addr, 
                                 const char *a_tx_str, const char *a_value_fee_str, const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

json_object* dap_cli_voting_compose(const char *a_net_name, const char *a_question_str, const char *a_options_list_str, 
                                   const char *a_voting_expire_str, const char *a_max_votes_count_str, const char *a_fee_str, 
                                   bool a_is_delegated_key, bool a_is_vote_changing_allowed, dap_chain_addr_t *a_wallet_addr, 
                                   const char *a_token_str, const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

json_object* dap_cli_vote_compose(const char *a_net_str, const char *a_hash_str, const char *a_cert_name, 
                                 const char *a_fee_str, dap_chain_addr_t *a_wallet_addr, const char *a_option_idx_str, 
                                 const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

dap_chain_datum_tx_t* dap_chain_net_vote_voting_compose(dap_cert_t *a_cert, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, 
                                                       dap_hash_fast_t a_hash, uint64_t a_option_idx, compose_config_t *a_config);

json_object* dap_cli_xchange_purchase_compose(const char *a_net_name, const char *a_order_hash, const char* a_value, 
                                             const char* a_fee, const char *a_wallet_name, const char *a_wallet_path, 
                                             const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

json_object* dap_cli_srv_stake_order_create_staker_compose(const char *l_net_str, const char *l_value_str, const char *l_fee_str, 
                                                          const char *l_tax_str, const char *l_addr_str, dap_chain_addr_t *a_wallet_addr, 
                                                          const char *l_url_str, uint16_t l_port, const char *l_enc_cert);

dap_chain_datum_tx_t* dap_chain_net_srv_order_remove_compose(dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                                              dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config);

json_object* dap_cli_xchange_order_remove_compose(const char *l_net_str, const char *l_order_hash_str, const char *l_fee_str, 
                                                   dap_chain_addr_t *a_wallet_addr, const char *l_url_str, uint16_t l_port, const char *l_enc_cert);

json_object* dap_cli_srv_stake_delegate_compose(const char* a_net_str, dap_chain_addr_t *a_wallet_addr, const char* a_cert_str, 
                                               const char* a_pkey_full_str, const char* a_sign_type_str, const char* a_value_str, 
                                               const char* a_node_addr_str, const char* a_order_hash_str, const char* a_url_str, 
                                               uint16_t a_port, const char* a_sovereign_addr_str, const char* a_fee_str, const char *a_enc_cert);

dap_chain_datum_tx_t* dap_xchange_tx_invalidate_compose( dap_chain_net_srv_xchange_price_t *a_price, dap_chain_tx_out_cond_t *a_cond_tx, 
                                                        dap_chain_addr_t *a_wallet_addr, dap_chain_addr_t *a_seller_addr, const char *a_tx_ticker, 
                                                        uint32_t a_prev_cond_idx, compose_config_t *a_config);

dap_chain_datum_tx_t* dap_stake_tx_invalidate_compose(dap_hash_fast_t *a_tx_hash, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, 
                                                     compose_config_t *a_config);

json_object* dap_cli_srv_stake_invalidate_compose(const char *a_net_str, const char *a_tx_hash_str, dap_chain_addr_t *a_wallet_addr, 
                                                 const char *a_cert_str, const char *a_fee_str, const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

dap_chain_datum_tx_t* dap_chain_datum_tx_create_compose(dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
                                                       const char* a_token_ticker, uint256_t *a_value, uint256_t a_value_fee, 
                                                       size_t a_tx_num, compose_config_t *a_config);

dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(const char *a_token_buy, const char *a_token_sell, 
                                                              uint256_t a_datoshi_sell, uint256_t a_rate, uint256_t a_fee, 
                                                              dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config);

dap_chain_datum_tx_t* dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, 
                                                           dap_chain_addr_t *a_seller_addr, const char *a_native_ticker, 
                                                           compose_config_t *a_config);

dap_chain_datum_tx_t* dap_chain_mempool_tx_create_cond_compose(dap_chain_addr_t *a_wallet_addr, dap_pkey_t *a_key_cond,
                                                              const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                                              uint256_t a_value, uint256_t a_value_per_unit_max,
                                                              dap_chain_net_srv_price_unit_uid_t a_unit, 
                                                              dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value_fee, 
                                                              const void *a_cond, size_t a_cond_size, compose_config_t *a_config);

dap_chain_datum_tx_t* dap_stake_lock_datum_create_compose(dap_chain_addr_t *a_wallet_addr, const char *a_main_ticker,
                                                         uint256_t a_value, uint256_t a_value_fee, dap_time_t a_time_staking, 
                                                         uint256_t a_reinvest_percent, const char *a_delegated_ticker_str, 
                                                         uint256_t a_delegated_value, const char *a_chain_id_str, 
                                                         compose_config_t *a_config);

dap_chain_datum_tx_t* dap_stake_unlock_datum_create_compose(dap_chain_addr_t *a_wallet_addr, dap_hash_fast_t *a_stake_tx_hash, 
                                                           uint32_t a_prev_cond_idx, const char *a_main_ticker, uint256_t a_value,
                                                           uint256_t a_value_fee, const char *a_delegated_ticker_str, 
                                                           uint256_t a_delegated_value, compose_config_t *a_config);

dap_chain_datum_tx_t* dap_chain_net_vote_create_compose(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                                                       uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                                                       bool a_vote_changing_allowed, dap_chain_addr_t *a_wallet_addr,
                                                       const char *a_token_ticker, compose_config_t *a_config);

dap_chain_datum_tx_t* dap_stake_tx_create_compose(dap_chain_addr_t *a_wallet_addr, uint256_t a_value, uint256_t a_fee,
                                                 dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr,
                                                 dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax,
                                                 dap_chain_datum_tx_t *a_prev_tx, dap_pkey_t *a_pkey, compose_config_t *a_config);

dap_chain_datum_tx_t* dap_chain_net_srv_xchange_purchase_compose(dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                                                uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, 
                                                                char **a_hash_out, compose_config_t *a_config);

json_object* dap_tx_create_xchange_purchase_compose(const char *a_net_name, const char *a_order_hash, const char* a_value, 
                                                   const char* a_fee, dap_chain_addr_t *a_wallet_addr, const char *a_url_str, uint16_t a_port, const char *a_enc_cert);

dap_chain_datum_tx_t* dap_xchange_tx_create_exchange_compose(dap_chain_net_srv_xchange_price_t *a_price, 
                                                            dap_chain_addr_t *a_buyer_addr, uint256_t a_datoshi_buy,
                                                            uint256_t a_datoshi_fee, dap_chain_tx_out_cond_t* a_cond_tx, 
                                                            uint32_t a_prev_cond_idx, compose_config_t *a_config);
#ifdef __cplusplus
}
#endif
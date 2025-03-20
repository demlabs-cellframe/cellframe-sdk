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




 // #define RPC_NODES_URL "http://rpc.cellframe.net"
#define RPC_NODES_URL "45.76.140.191:8081"

#define NET_COUNT 6

const char *c_wallets_path = NULL;

typedef struct {
    char name[20];
    char native_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_net_id_t net_id;
} NetInfo;

static NetInfo netinfo[NET_COUNT] = {
    {"riemann",  "tKEL",  {.uint64 = 0x000000000000dddd}},
    {"raiden",   "tCELL", {.uint64 = 0x000000000000bbbb}},
    {"KelVPN",   "KEL",   {.uint64 = 0x1807202300000000}},
    {"Backbone", "CELL",  {.uint64 = 0x0404202200000000}},
    {"mileena",  "tMIL",  {.uint64 = 0x000000000000cccc}},
    {"subzero",  "tCELL", {.uint64 = 0x000000000000acca}}
};

int dap_tx_create_compose(int argc, char ** argv);
int dap_tx_create_xchange_compose(int argc, char ** argv);
int dap_tx_cond_create_compose(int argc, char ** argv);
int dap_cli_hold_compose(int a_argc, char **a_argv);
int dap_cli_take_compose(int a_argc, char **a_argv);
int dap_cli_voting_compose(int a_argc, char **a_argv);
dap_list_t *dap_ledger_get_list_tx_outs_from_json(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer);
dap_chain_datum_tx_t *dap_chain_datum_tx_create_compose(const char * l_net_name, dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
                                                        const char* a_token_ticker, uint256_t *a_value, uint256_t a_value_fee, size_t a_tx_num);
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(const char *a_net_name, const char *a_token_buy,const char *a_token_sell, 
                                                        uint256_t a_datoshi_sell, uint256_t a_rate, uint256_t a_fee, dap_chain_wallet_t *a_wallet);
static dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet,
                                                                const char *a_native_ticker, const char *a_net_name);
dap_chain_datum_tx_t *dap_chain_mempool_tx_create_cond_compose(const char *a_net_name,
        dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, const char *a_hash_out_type);
bool dap_get_remote_net_fee_and_address(const char *l_net_name, uint256_t *a_net_fee, dap_chain_addr_t **l_addr_fee);
bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker, const char *l_net_name, json_object **l_outs, int *l_outputs_count);
dap_chain_datum_tx_t * dap_stake_lock_datum_create_compose(const char *a_net_name, dap_enc_key_t *a_key_from,
                                                    const char *a_main_ticker,
                                                    uint256_t a_value, uint256_t a_value_fee,
                                                    dap_time_t a_time_staking, uint256_t a_reinvest_percent,
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value, const char * l_chain_id_str);
bool check_token_in_ledger(json_object *l_json_coins, const char *a_token);
dap_chain_datum_tx_t *dap_stake_unlock_datum_create_compose(const char *a_net_name, dap_enc_key_t *a_key_from,
                                               dap_hash_fast_t *a_stake_tx_hash, uint32_t a_prev_cond_idx,
                                               const char *a_main_ticker, uint256_t a_value,
                                               uint256_t a_value_fee,
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value);
dap_chain_datum_tx_t* dap_chain_net_vote_create_compose(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                              uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                              bool a_vote_changing_allowed, dap_chain_wallet_t *a_wallet,
                              const char *a_net_str);

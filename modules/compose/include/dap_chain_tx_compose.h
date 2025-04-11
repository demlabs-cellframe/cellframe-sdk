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
    uint16_t port;
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

int dap_tx_create_compose(int argc, char ** argv);
int dap_tx_create_xchange_compose(int argc, char ** argv);
int dap_tx_cond_create_compose(int argc, char ** argv);
int dap_cli_hold_compose(int a_argc, char **a_argv);
int dap_cli_take_compose(int a_argc, char **a_argv);
int dap_cli_voting_compose(int a_argc, char **a_argv);
typedef enum {
    STAKE_ORDER_CREATE_STAKER_OK = 0,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_PARAMS = -1,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_VALUE = -2,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_FEE = -3,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_TAX = -4,
    STAKE_ORDER_CREATE_STAKER_ERR_WALLET_NOT_FOUND = -5,
    STAKE_ORDER_CREATE_STAKER_ERR_KEY_NOT_FOUND = -6,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_ADDR = -7,
    STAKE_ORDER_CREATE_STAKER_ERR_TX_CREATE_FAILED = -8,
    STAKE_ORDER_CREATE_STAKER_ERR_JSON_FAILED = -9
} dap_cli_srv_stake_order_create_staker_error_t;
json_object* dap_cli_srv_stake_order_create_staker_compose(const char *l_net_str, const char *l_value_str, const char *l_fee_str, const char *l_tax_str, const char *l_addr_str, const char *l_wallet_str, const char *l_wallet_path, const char *l_url_str, int l_port);

typedef enum {
    SRV_STAKE_ORDER_REMOVE_COMPOSE_OK = 0,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_WALLET_NOT_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_KEY_NOT_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ORDER_HASH,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_RPC_RESPONSE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ADDR,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TAX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_COND_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TOKEN_TICKER,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TS_CREATED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PRICE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_ENOUGH_FUNDS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_SIGN,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_ITEMS_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_COND_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_TOKEN_TICKER,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_TIMESTAMP,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_ALREADY_USED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_OWNER
} srv_stake_order_remove_compose_error_t;
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_remove_compose(dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                     dap_chain_wallet_t *a_wallet, compose_config_t *a_config);
json_object* dap_cli_srv_stake_order_remove_compose(const char *l_net_str, const char *l_order_hash_str, const char *l_fee_str, const char *l_wallet_str, const char *l_wallet_path, const char *l_url_str, int l_port);

typedef enum {
    STAKE_DELEGATE_COMPOSE_OK = 0,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE = -1,
    STAKE_DELEGATE_COMPOSE_ERR_WALLET_NOT_FOUND = -2,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_NOT_FOUND = -3,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_WRONG = -4,
    STAKE_DELEGATE_COMPOSE_ERR_WRONG_SIGN_TYPE = -5,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY = -6,
    STAKE_DELEGATE_COMPOSE_ERR_PKEY_UNDEFINED = -7,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR = -8,
    STAKE_DELEGATE_COMPOSE_ERR_ORDER_NOT_FOUND = -9,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER_SIZE = -10,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_REQUIRED = -11,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_REQUIRED = -12,
    STAKE_DELEGATE_COMPOSE_ERR_WRONG_TICKER = -13,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_FORMAT = -14,
    STAKE_DELEGATE_COMPOSE_ERR_RPC_RESPONSE = -15,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_VALUE = -16,
    STAKE_DELEGATE_COMPOSE_ERR_NO_ITEMS = -17,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_ADDR = -18,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_SIGNER_ADDR = -19,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_SOVEREIGN_ADDR = -20,
    STAKE_DELEGATE_COMPOSE_ERR_NO_TOKEN_TICKER = -21,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_LOW = -22,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_HIGH = -23,
    STAKE_DELEGATE_COMPOSE_ERR_UNSIGNED_ORDER = -24,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER = -25,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_TAX = -26,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_BELOW_MIN = -27,
    DAP_STAKE_TX_CREATE_COMPOSE_INVALID_PARAMS = -28,
    DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE = -29,
    DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE = -30,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR = -31,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_COND_OUT_ERROR = -32,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_OUT_ERROR = -33,
    DAP_STAKE_TX_CREATE_COMPOSE_NET_FEE_ERROR = -34,
    DAP_STAKE_TX_CREATE_COMPOSE_VALIDATOR_FEE_ERROR = -35,
    DAP_STAKE_TX_CREATE_COMPOSE_FEE_BACK_ERROR = -36
} stake_delegate_error_t;
json_object* dap_cli_srv_stake_delegate_compose(const char* a_net_str, const char* a_wallet_str, const char* a_cert_str, 
                                        const char* a_pkey_full_str, const char* a_sign_type_str, const char* a_value_str, const char* a_node_addr_str, 
                                        const char* a_order_hash_str, const char* a_url_str, uint16_t a_port, const char* a_sovereign_addr_str, const char* a_fee_str, const char* a_wallets_path);
typedef enum {
    DAP_CLI_STAKE_INVALIDATE_OK = 0,
    DAP_CLI_STAKE_INVALIDATE_CERT_NOT_FOUND = -1,
    DAP_CLI_STAKE_INVALIDATE_PRIVATE_KEY_MISSING = -2,
    DAP_CLI_STAKE_INVALIDATE_WRONG_CERT = -3,
    DAP_CLI_STAKE_INVALIDATE_LEDGER_ERROR = -4,
    DAP_CLI_STAKE_INVALIDATE_INVALID_TX_HASH = -5,
    DAP_CLI_STAKE_INVALIDATE_NOT_DELEGATED = -6,
    DAP_CLI_STAKE_INVALIDATE_NO_DELEGATE_OUT = -7,
    DAP_CLI_STAKE_INVALIDATE_PREV_TX_NOT_FOUND = -8,
    DAP_CLI_STAKE_INVALIDATE_TX_EXISTS = -9,
    DAP_CLI_STAKE_INVALIDATE_WALLET_NOT_FOUND = -10,
    DAP_CLI_STAKE_INVALIDATE_COMPOSE_ERROR = -11,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_LEDGER_ERROR = -12,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_ITEMS_NOT_FOUND = -13,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTPUTS_SPENT = -14,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_HASH_NOT_FOUND = -15,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_ERROR = -16,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_NOT_FOUND = -17,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_NOT_FOUND = -18,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_DECODE_ERROR = -19,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_WRONG_OWNER = -20,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TOKEN_NOT_FOUND = -21,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTS_NOT_FOUND = -22,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_NOT_ENOUGH_FUNDS = -23,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_IN_ERROR = -24,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_OUT_ERROR = -25,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_NET_FEE_ERROR = -26,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_ERROR = -27,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_BACK_ERROR = -28
} dap_cli_stake_invalidate_error_t;
dap_chain_datum_tx_t *dap_stake_tx_invalidate_compose(dap_hash_fast_t *a_tx_hash, uint256_t a_fee, dap_enc_key_t *a_key, compose_config_t *a_config);
json_object* dap_cli_srv_stake_invalidate_compose(const char *a_net_str, const char *a_tx_hash_str, const char *a_wallet_str, 
                        const char *a_wallet_path, const char *a_cert_str, uint256_t a_fee, const char *a_url_str, uint16_t a_port);

typedef enum {
    DAP_COMPOSE_ERROR_NONE = 0,
    DAP_COMPOSE_ERROR_RESPONSE_NULL = -1,
    DAP_COMPOSE_ERROR_RESULT_NOT_FOUND = -2,
    DAP_COMPOSE_ERROR_REQUEST_INIT_FAILED = -3,
    DAP_COMPOSE_ERROR_REQUEST_TIMEOUT = -4,
    DAP_COMPOSE_ERROR_REQUEST_FAILED = -5
} dap_compose_error_t;
json_object* dap_request_command_to_rpc(const char *request, compose_config_t *a_config);
int dap_tx_json_tsd_add(json_object * json_tx, json_object * json_add);

dap_list_t *dap_ledger_get_list_tx_outs_from_json(json_object * a_outputs_array, int a_outputs_count, uint256_t a_value_need, uint256_t *a_value_transfer);
dap_chain_datum_tx_t *dap_chain_datum_tx_create_compose(const char * l_net_name, dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
        const char* a_token_ticker, uint256_t *a_value, uint256_t a_value_fee, size_t a_tx_num, const char * a_url_str, uint16_t a_port);
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(const char *a_net_name, const char *a_token_buy, const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_wallet_t *a_wallet, const char * a_url_str, uint16_t a_port);
dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet,
                                                                const char *a_native_ticker, const char *a_net_name, const char * a_url_str, uint16_t a_port);
dap_chain_datum_tx_t *dap_chain_mempool_tx_create_cond_compose(const char *a_net_name,
        dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, const char *a_url_str, uint16_t a_port);
bool dap_get_remote_net_fee_and_address(uint256_t *a_net_fee, dap_chain_addr_t **l_addr_fee, compose_config_t *a_config);
bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from, const char *a_token_ticker, const char *l_net_name,
                                         json_object **l_outs, int *l_outputs_count, const char * a_url_str, uint16_t a_port);
dap_chain_datum_tx_t * dap_stake_lock_datum_create_compose(const char *a_net_name, dap_enc_key_t *a_key_from,
                                                    const char *a_main_ticker,
                                                    uint256_t a_value, uint256_t a_value_fee,
                                                    dap_time_t a_time_staking, uint256_t a_reinvest_percent,
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                                    const char * l_chain_id_str, const char *l_url_str, uint16_t l_port);
bool check_token_in_ledger(json_object *l_json_coins, const char *a_token);
dap_chain_datum_tx_t *dap_stake_unlock_datum_create_compose(const char *a_net_name, dap_enc_key_t *a_key_from,
                                               dap_hash_fast_t *a_stake_tx_hash, uint32_t a_prev_cond_idx,
                                               const char *a_main_ticker, uint256_t a_value,
                                               uint256_t a_value_fee,
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                               const char *l_url_str, uint16_t l_port);
dap_chain_datum_tx_t* dap_chain_net_vote_create_compose(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                              uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                              bool a_vote_changing_allowed, dap_chain_wallet_t *a_wallet,
                              const char *a_net_str, const char *a_token_ticker, const char *l_url_str, uint16_t l_port);
dap_chain_datum_tx_t *dap_stake_tx_create_compose(dap_enc_key_t *a_key,
                                               uint256_t a_value, uint256_t a_fee,
                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr,
                                               dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax,
                                               dap_chain_datum_tx_t *a_prev_tx, dap_pkey_t *a_pkey, compose_config_t *a_config);




#ifdef __cplusplus
}
#endif
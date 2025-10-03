/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
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

#include "dap_chain_net_srv.h"
#include "dap_chain_wallet.h"
#include "dap_chain_datum_tx_out_cond.h"

#define DAP_CHAIN_NET_SRV_XCHANGE_ID 0x2
#define GROUP_LOCAL_XCHANGE "local.xchange"

typedef struct dap_chain_net_srv_xchange_price {
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t datoshi_sell;
    dap_chain_net_t *net;
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t rate;
    uint256_t fee;
    dap_chain_hash_fast_t tx_hash;
    dap_chain_hash_fast_t order_hash;
    dap_chain_addr_t creator_addr;
    dap_time_t creation_date;
} dap_chain_net_srv_xchange_price_t;

typedef struct dap_srv_xchange_order_ext {
    uint64_t padding;
    uint256_t datoshi_buy;
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];
} DAP_ALIGN_PACKED dap_srv_xchange_order_ext_t;

typedef struct dap_chain_net_srv_xchange {
    dap_chain_net_srv_t *parent;
    bool enabled;
} dap_chain_net_srv_xchange_t;

extern const dap_chain_net_srv_uid_t c_dap_chain_net_srv_xchange_uid;

int dap_chain_net_srv_xchange_init();
void dap_chain_net_srv_xchange_deinit();

json_object *dap_chain_net_srv_xchange_print_fee_json(dap_chain_net_t *a_net);
void dap_chain_net_srv_xchange_print_fee(dap_chain_net_t *a_net, dap_string_t *a_string_ret);

typedef enum s_com_net_srv_xchange_err{
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_OK = 0,    

    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_REQ_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_REQ_PARAM_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_NET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_UNREC_STATUS_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CANT_FIND_TOKEN_TO_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CANT_FIND_TOKEN_FROM_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TOKEN_SELL_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TOKEN_BUY_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TICKR_NOTF_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_TOKEN_EQUAL_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_VALUE_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_RATE_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_FEE_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_W_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_WALLET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_REQ_PARAM_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_NET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_REQ_PARAM_ORDER_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_CAN_NOT_CONVERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_INCORRECT_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NOT_BELONG_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NO_HISTORY_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_NET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_W_ERR,    
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_WALLET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_ORDER_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_FEE_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_UNKNOWN_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_REQ_PARAM_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_NET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_NET_NOT_FOUN_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_REQ_PARAM_ORDER_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_ITS_NOT_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_GET_PRICE_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_GET_LAST_TX_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_LAST_TX_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_SUB_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_LIST_CAN_NOT_CONVERT_ERR,

    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_NET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_W_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_WALLET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_VALUE_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_FEE_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_UNKNOWN_ERR,

    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_UNREC_STATUS_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_REQ_PARAM_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_NET_NOT_FOUND_ERR,

    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_REQ_PARAM_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_NET_NOT_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_FROM_ARG_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_FROM_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_TO_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_TOKEN_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_TX_ERR,
    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_UNKNOWN_ERR,

    DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_UNKNOWN_COMMAND_ERR

} s_com_net_srv_xchange_err_t;

typedef enum dap_chain_net_srv_xchange_create_error_list{
    XCHANGE_CREATE_ERROR_OK = 0,
    XCHANGE_CREATE_ERROR_INVALID_ARGUMENT,
    XCHANGE_CREATE_ERROR_TOKEN_TICKER_SELL_IS_NOT_FOUND_LEDGER,
    XCHANGE_CREATE_ERROR_TOKEN_TICKER_BUY_IS_NOT_FOUND_LEDGER,
    XCHANGE_CREATE_ERROR_RATE_IS_ZERO,
    XCHANGE_CREATE_ERROR_FEE_IS_ZERO,
    XCHANGE_CREATE_ERROR_VALUE_SELL_IS_ZERO,
    XCHANGE_CREATE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE,
    XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET,
    XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET,
    XCHANGE_CREATE_ERROR_MEMORY_ALLOCATED,
    XCHANGE_CREATE_ERROR_CAN_NOT_COMPOSE_THE_CONDITIONAL_TRANSACTION,
    XCHANGE_CREATE_ERROR_CAN_NOT_PUT_TRANSACTION_TO_MEMPOOL
} dap_chain_net_srv_xchange_create_error_t;
dap_chain_net_srv_xchange_create_error_t dap_chain_net_srv_xchange_create(dap_chain_net_t *a_net, const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                     char **a_out_tx_hash);

typedef enum dap_chain_net_srv_xchange_remove_error_list{
    XCHANGE_REMOVE_ERROR_OK = 0,
    XCHANGE_REMOVE_ERROR_INVALID_ARGUMENT,
    XCHANGE_REMOVE_ERROR_FEE_IS_ZERO,
    XCHANGE_REMOVE_ERROR_CAN_NOT_FIND_TX,
    XCHANGE_REMOVE_ERROR_CAN_NOT_CREATE_PRICE,
    XCHANGE_REMOVE_ERROR_CAN_NOT_INVALIDATE_TX
} dap_chain_net_srv_xchange_remove_error_t;
dap_chain_net_srv_xchange_remove_error_t dap_chain_net_srv_xchange_remove(dap_chain_net_t *a_net, dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                     dap_chain_wallet_t *a_wallet, char **a_out_hash_tx);

dap_list_t *dap_chain_net_srv_xchange_get_tx_xchange(dap_chain_net_t *a_net);
dap_list_t *dap_chain_net_srv_xchange_get_prices(dap_chain_net_t *a_net);

typedef enum dap_chain_net_srv_xchange_purchase_error_list{
    XCHANGE_PURCHASE_ERROR_OK = 0,
    XCHANGE_PURCHASE_ERROR_INVALID_ARGUMENT,
    XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND,
    XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE,
    XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX,
    XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_JSON_OBJECT,
} dap_chain_net_srv_xchange_purchase_error_t;
dap_chain_net_srv_xchange_purchase_error_t dap_chain_net_srv_xchange_purchase(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                       uint256_t a_fee, dap_chain_wallet_t *a_wallet, char **a_hash_out);

uint64_t dap_chain_net_srv_xchange_get_order_completion_rate(dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash);

typedef enum dap_chain_net_srv_xchange_order_status{
    XCHANGE_ORDER_STATUS_OPENED = 0,
    XCHANGE_ORDER_STATUS_CLOSED,
    XCHANGE_ORDER_STATUS_UNKNOWN,
} dap_chain_net_srv_xchange_order_status_t;

typedef enum xchange_tx_type{
    TX_TYPE_UNDEFINED=0,
    TX_TYPE_ORDER,
    TX_TYPE_EXCHANGE,
    TX_TYPE_INVALIDATE
}   xchange_tx_type_t;

dap_chain_net_srv_xchange_order_status_t dap_chain_net_srv_xchange_get_order_status(dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash);
bool dap_chain_net_srv_xchange_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_fee, dap_chain_addr_t *a_addr, uint16_t *a_type);
xchange_tx_type_t dap_chain_net_srv_xchange_tx_get_type (dap_ledger_t * a_ledger, dap_chain_datum_tx_t * a_tx, dap_chain_tx_out_cond_t **a_out_cond_item, int *a_item_idx, 
                                                            dap_chain_tx_out_cond_t **a_out_prev_cond_item);

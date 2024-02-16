/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#include "dap_chain_net_srv_order.h"

#define DAP_CHAIN_NET_SRV_XCHANGE_ID 0x2
#define GROUP_LOCAL_XCHANGE "local.xchange"

typedef struct dap_chain_net_srv_xchange_price {
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t datoshi_sell;
    dap_chain_net_t *net;
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t datoshi_buy;
    uint256_t rate;
    uint256_t fee;
    dap_chain_hash_fast_t tx_hash;
    dap_chain_hash_fast_t order_hash;
    dap_enc_key_t *wallet_key;
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

enum dap_chain_net_srv_xchange_create_error_list{
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
    XCHANGE_CREATE_ERROR_CAN_NOT_PUT_TRANSACTION_TO_MEMPOOL,
};
int dap_chain_net_srv_xchange_create(dap_chain_net_t *a_net, const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                     char **a_out_tx_hash);

enum dap_chain_net_srv_xchange_remove_error_list{
    XCHANGE_REMOVE_ERROR_OK = 0,
    XCHANGE_REMOVE_ERROR_INVALID_ARGUMENT,
    XCHANGE_REMOVE_ERROR_FEE_IS_ZERO,
    XCHANGE_REMOVE_ERROR_CAN_NOT_FIND_TX,
    XCHANGE_REMOVE_ERROR_CAN_NOT_CREATE_PRICE,
    XCHANGE_REMOVE_ERROR_CAN_NOT_INVALIDATE_TX
};
int dap_chain_net_srv_xchange_remove(dap_chain_net_t *a_net, dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                     dap_chain_wallet_t *a_wallet, char **a_out_hash_tx);

dap_list_t *dap_chain_net_srv_xchange_get_tx_xchange(dap_chain_net_t *a_net);
dap_list_t *dap_chain_net_srv_xchange_get_prices(dap_chain_net_t *a_net);

enum dap_chain_net_srv_xchange_purchase_error_list{
    XCHANGE_PURCHASE_ERROR_OK = 0,
    XCHANGE_PURCHASE_ERROR_INVALID_ARGUMENT,
    XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND,
    XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE,
    XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX,
};
int dap_chain_net_srv_xchange_purchase(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                       uint256_t a_fee, dap_chain_wallet_t *a_wallet, char **a_hash_out);

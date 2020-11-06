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
    char *wallet_str;
    dap_chain_net_t *net_sell;
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t datoshi_sell;
    dap_chain_net_t *net_buy;
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];
    long double rate;
    dap_chain_hash_fast_t tx_hash;
    dap_chain_hash_fast_t order_hash;
    char *key_ptr;
    UT_hash_handle hh;
} dap_chain_net_srv_xchange_price_t;

typedef struct dap_chain_net_srv_xchange_db_item {
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];
    uint8_t padding[4];
    uint64_t net_sell_id;
    uint64_t net_buy_id;
    uint64_t datoshi_sell;
    long double rate;
    dap_chain_hash_fast_t tx_hash;
    dap_chain_hash_fast_t order_hash;
    char wallet_str[];
} DAP_ALIGN_PACKED dap_chain_net_srv_xchange_db_item_t;

typedef struct dap_srv_xchange_order_ext {
    uint64_t net_sell_id;
    uint64_t datoshi_sell;
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];
} dap_srv_xchange_order_ext_t;

typedef struct dap_chain_net_srv_xchange {
    dap_chain_net_srv_t *parent;
    dap_chain_net_srv_xchange_price_t *pricelist;
    bool enabled;
} dap_chain_net_srv_xchange_t;

int dap_chain_net_srv_xchange_init();
void dap_chain_net_srv_xchange_deinit();
bool dap_chain_net_srv_xchange_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx);

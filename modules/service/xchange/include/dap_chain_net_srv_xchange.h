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

typedef struct dap_chain_net_srv_xchange_price {
    dap_chain_wallet_t *wallet;
    dap_chain_net_t *net_sell;
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t datoshi_sell;
    dap_chain_net_t *net_buy;
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t datoshi_buy;
    dap_chain_net_srv_order_t *order;
    char *key_ptr;
    UT_hash_handle hh;
} dap_chain_net_srv_xchange_price_t;

typedef struct dap_chain_net_srv_xchange {
    dap_chain_net_srv_t *parent;
    dap_chain_net_srv_xchange_price_t *pricelist;
    bool enabled;
} dap_chain_net_srv_xchange_t;

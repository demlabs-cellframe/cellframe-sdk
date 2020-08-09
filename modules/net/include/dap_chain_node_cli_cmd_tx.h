/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "utlist.h"

typedef enum dap_chain_type_transaction_in_history{
    TYPE_TRANSACTION_EMIT,
    TYPE_TRANSACTION_TRANSLATION_IN_SEND,
    TYPE_TRANSACTION_TRANSLATION_IN_RECV,
    TYPE_TRANSACTION_TRANSLATION_SEND,
    TYPE_TRANSACTION_TRANSLATION_RECV,
}dap_chain_type_transaction_in_history_t;

typedef struct dap_chain_history{
    dap_chain_hash_fast_t *tx_hash;
    dap_chain_type_transaction_in_history_t type_transaction;
//    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    char *token_ticker;
    uint64_t amount;
    time_t time;
    dap_chain_addr_t *addr_src;
    dap_chain_addr_t *addr_dst;
    struct dap_chain_history *next;
}dap_chain_history_t;

/**
 *
 * return history string
 */
char* dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain, const char *a_hash_out_type);
char* dap_db_history_addr(dap_chain_addr_t * a_addr, dap_chain_t * a_chain, const char *a_hash_out_type);

dap_chain_history_t* dap_db_history_addr_struct(dap_chain_addr_t * a_addr, dap_chain_t * a_chain);
void dap_chain_history_add_data(dap_chain_history_t *a_history, const dap_chain_hash_fast_t *a_tx_hash,
                                const dap_chain_type_transaction_in_history_t a_type_transaction,
                                const char *a_token_ticker, const uint64_t a_amount, const time_t a_time,
                                const dap_chain_addr_t *a_addr_src, const dap_chain_addr_t *a_addr_dst);
void dap_chain_history_free(dap_chain_history_t *a_history);

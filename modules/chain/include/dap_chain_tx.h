/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
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
#include "dap_chain_datum_token.h"
#include "dap_hash.h"
#include "uthash.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_out_ext.h"
#include "dap_chain_datum_tx_out.h"

typedef struct dap_chain_tx
{
    enum {CHAIN_TX_STORE_TYPE_PACKED, CHAIN_TX_STORE_TYPE_UNPACKED} store_type;
    dap_chain_datum_tx_t * datum_tx;
    // Owner
    dap_chain_addr_t owner;
    const char * token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_hash_fast_t token_hash;
    dap_chain_datum_token_t *token;

    // Inputs
    byte_t * in;
    dap_chain_tx_in_cond_t * in_cond;
    // Outputs
    byte_t * out;
    dap_chain_tx_out_cond_t * out_cond;

    // Previous
    struct dap_chain_tx ** prev;
    size_t prev_count;
    dap_hash_fast_t * prev_hash;

    struct dap_chain_tx ** next;
    size_t next_count;
    dap_hash_fast_t * next_hash;

    // Hash and UT hash handle
    dap_hash_fast_t hash;
    UT_hash_handle hh;
} dap_chain_tx_t;

dap_chain_tx_t * dap_chain_tx_wrap_packed(dap_chain_datum_tx_t * a_tx_packed);
void dap_chain_tx_hh_add (dap_chain_tx_t ** a_tx_hh, dap_chain_tx_t * a_tx);

/**
 * @brief Find tx in hashtable by its datum_tx hash
 * @param a_tx_hh
 * @param a_tx_hash
 * @return
 */
static inline dap_chain_tx_t * dap_chain_tx_hh_find (dap_chain_tx_t * a_tx_hh, dap_hash_fast_t* a_tx_hash)
{
    dap_chain_tx_t * l_ret = NULL;
    HASH_FIND(hh, a_tx_hh, a_tx_hash, sizeof(*a_tx_hash), l_ret);
    return l_ret;
}

void dap_chain_tx_hh_free (dap_chain_tx_t * a_tx_hh);
dap_chain_tx_t* dap_chain_tx_dup(dap_chain_tx_t * a_tx);

void dap_chain_tx_delete(dap_chain_tx_t * a_tx);

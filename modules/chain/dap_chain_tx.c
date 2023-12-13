/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
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
#include "dap_chain_tx.h"
#include "dap_chain_datum_tx.h"
#include "dap_common.h"
#include "uthash.h"
#define LOG_TAG "dap_chain_tx"

/**
 * @brief Wrap without deep copy the datum tx into the deserialed tx
 * @param a_tx_packed
 * @return
 */
dap_chain_tx_t * dap_chain_tx_wrap_packed(dap_chain_datum_tx_t * a_tx_packed)
{
    dap_chain_tx_t * l_tx = DAP_NEW_Z(dap_chain_tx_t);
    if (!l_tx) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    dap_hash_fast(a_tx_packed, dap_chain_datum_tx_get_size(a_tx_packed), &l_tx->hash);
    l_tx->datum_tx = a_tx_packed;
    return l_tx;
}

/**
 * @brief Delete TX. IMPORTANT, doesn't delete wrapped packed tx if it has its store type
 * @param a_tx
 */
void dap_chain_tx_delete(dap_chain_tx_t * a_tx)
{
    if(a_tx->prev)
        DAP_DELETE(a_tx->prev);
    if( a_tx->prev_hash )
        DAP_DELETE(a_tx->prev_hash);

    DAP_DELETE(a_tx);
}

/**
 * @brief dap_chain_tx_dup
 * @param a_tx
 * @return
 */
dap_chain_tx_t* dap_chain_tx_dup(dap_chain_tx_t * a_tx)
{
    dap_chain_tx_t * l_ret = DAP_DUP(a_tx);
    if(a_tx->prev)
        l_ret->prev = DAP_DUP_SIZE(a_tx->prev, sizeof(*a_tx->prev)* a_tx->prev_count );
    if(a_tx->prev_hash)
        l_ret->prev_hash = DAP_DUP_SIZE(a_tx->prev_hash,sizeof(*a_tx->prev_hash)* a_tx->prev_count );
    return l_ret;
}

/**
 * @brief Add TX in hash table and updated prev/next links
 * @param a_tx_hh
 * @param a_tx
 */
void dap_chain_tx_hh_add (dap_chain_tx_t * a_tx_hh, dap_chain_tx_t * a_tx)
{
    HASH_ADD(hh,a_tx_hh,hash, sizeof(a_tx->hash),a_tx);
}

void dap_chain_tx_hh_free (dap_chain_tx_t * a_tx_hh)
{
    dap_chain_tx_t * l_tx = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_tx_hh, l_tx, l_tmp){
        HASH_DELETE(hh, a_tx_hh, l_tx);
        dap_chain_tx_delete(l_tx);
    }
}

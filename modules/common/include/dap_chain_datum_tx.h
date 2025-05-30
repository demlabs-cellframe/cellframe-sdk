/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
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

#include "dap_list.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_time.h"
#include "dap_pkey.h"


/**
  * @struct dap_chain_datum_tx
  * @brief Transaction section, consists from lot of tx_items
  */
typedef struct dap_chain_datum_tx {
    struct {
        dap_time_t ts_created;
        uint32_t tx_items_size; // total size of sequential tx_items
    } DAP_ALIGN_PACKED header;
    uint8_t tx_items[];
} DAP_ALIGN_PACKED dap_chain_datum_tx_t;

#define TX_ITEM_ITER(item, item_size, data, total_size)                                                             \
    for ( byte_t *l_pos = (byte_t*)(data), *l_end = l_pos + (total_size) > l_pos ? l_pos + (total_size) : l_pos;    \
          !!( item = l_pos < l_end                                                                                  \
          && (item_size = dap_chain_datum_item_tx_get_size(l_pos, l_end - l_pos))                                   \
            ? l_pos : NULL );                                                                                       \
        l_pos += item_size )

#define TX_ITEM_ITER_TX(item, item_size, tx) \
    TX_ITEM_ITER(item, item_size, tx->tx_items, tx->header.tx_items_size)

#define TX_ITEM_ITER_TX_TYPE(item, item_type, item_size, item_index, tx)                                            \
    for ( item_size = 0, item_index = 0, item = NULL;                                                               \
        !!( item = dap_chain_datum_tx_item_get(tx, &item_index, (byte_t*)item + item_size, item_type, &item_size) );\
        item_index = 0 )

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create empty transaction
 *
 * return transaction, 0 Error
 */
dap_chain_datum_tx_t* dap_chain_datum_tx_create(void);

/**
 * Delete transaction
 */
void dap_chain_datum_tx_delete(dap_chain_datum_tx_t *a_tx);

/**
 * Get size of transaction
 *
 * return size, 0 Error
 */
size_t dap_chain_datum_tx_get_size(dap_chain_datum_tx_t *a_tx);

/**
 * Insert item to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_item(dap_chain_datum_tx_t **a_tx, const void *a_item);

/**
 * Create 'in' items from list and insert to transaction
 *
 * return summary value from inserted items
 */
uint256_t dap_chain_datum_tx_add_in_item_list(dap_chain_datum_tx_t **a_tx, dap_list_t *a_list_used_out);


/**
 * Create 'in' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_in_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_tx_prev_hash,
        uint32_t a_tx_out_prev_idx);


/**
 * Create 'in_cond' item and insert to transaction
 *
 * return 0 Ok, -1 Error
 */
int dap_chain_datum_tx_add_in_cond_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_tx_prev_hash,
                                        uint32_t a_tx_out_prev_idx,
                                        uint32_t a_receipt_idx);

/**
 * Create 'in_cond' items from list  and insert to transaction
 *
 * return summary value from inserted items
 */
uint256_t dap_chain_datum_tx_add_in_cond_item_list(dap_chain_datum_tx_t **a_tx, dap_list_t *a_list_used_out_cound);

/**
 *  Create 'in_reward' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_in_reward_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_block_hash);

/**
 * Create 'out' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value);

/**
 * Create 'out_cond' item with fee value and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_fee_item(dap_chain_datum_tx_t **a_tx, uint256_t a_value);

/**
 * Create 'out_std' item with zero ts_unlock field and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_ext_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token);
/**
 * Create 'out_std' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_std_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token, dap_time_t a_ts_unlock);

/**
 * Create 'out_cond' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */

int dap_chain_datum_tx_add_out_cond_item(dap_chain_datum_tx_t **a_tx, dap_pkey_t *a_key, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value, uint256_t a_value_max_per_unit, dap_chain_net_srv_price_unit_uid_t a_unit, const void *a_cond, size_t a_cond_size);

/**
* Sign a transaction (Create sign item and insert to transaction)
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_sign_item(dap_chain_datum_tx_t **a_tx, dap_enc_key_t *a_key);

dap_sign_t *dap_chain_datum_tx_get_sign(dap_chain_datum_tx_t *a_tx, int a_sign_num);

/**
 * Verify all sign item in transaction
 *
 * return 1 Ok, 0 Invalid sign, -1 Not found sing or other Error
 */
int dap_chain_datum_tx_verify_sign(dap_chain_datum_tx_t *a_tx, int a_sign_num);


int dap_chain_datum_tx_get_fee_value (dap_chain_datum_tx_t *a_tx, uint256_t *a_value);

/**
 * @brief dap_chain_node_datum_tx_calc_hash
 * @param a_tx
 * @return
 */
DAP_STATIC_INLINE dap_hash_fast_t dap_chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *a_tx)
{
    dap_hash_fast_t l_res;
    return dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_res), l_res;
}

#ifdef __cplusplus
}
#endif

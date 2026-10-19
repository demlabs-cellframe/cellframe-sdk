/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.com>
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
#include <stdbool.h>
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"


typedef enum dap_chain_wallet_getting_type {
    DAP_CHAIN_WALLET_CACHE_GET_FIRST = 0,
    DAP_CHAIN_WALLET_CACHE_GET_LAST,
    DAP_CHAIN_WALLET_CACHE_GET_NEXT,
    DAP_CHAIN_WALLET_CACHE_GET_PREVIOUS,
} dap_chain_wallet_getting_type_t;
typedef struct dap_chain_wallet_cache_iter {
    dap_chain_datum_tx_t *cur_tx;
    dap_chain_hash_fast_t *cur_hash;
    dap_chain_hash_fast_t *cur_atom_hash;
    uint32_t action;
    dap_chain_net_srv_uid_t uid;
    int ret_code;
    char *token_ticker;
    void *cur_item;
    void *cur_addr_cache;
    // The iterator never holds pointers into the cache across calls: the cache
    // entries may be cleared/replaced while a history read is in progress. The
    // address locates the wallet entry again on every step, and the hashes and
    // ticker are returned from these copies.
    dap_chain_addr_t addr;
    dap_chain_hash_fast_t cur_item_hash;
    dap_chain_hash_fast_t cur_hash_copy;
    dap_chain_hash_fast_t cur_atom_hash_copy;
    char token_ticker_copy[DAP_CHAIN_TICKER_SIZE_MAX];
    bool has_cur_item;
} dap_chain_wallet_cache_iter_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Early cache init: reads [wallets] wallets_cache and initializes the
 *        cache lock. Must run BEFORE the network init - the ledger snapshot
 *        restore (inside the net init) populates the unspent index and needs
 *        the mode and the lock to be live. Idempotent.
 */
void dap_chain_wallet_cache_preinit(void);

int dap_chain_wallet_cache_init();
int dap_chain_wallet_cache_deinit();

/**
 * @brief Load wallet cache for all opened wallets in the specified network
 * This function should be called when network transitions to NET_STATE_ONLINE
 * to ensure wallet cache is populated even if wallets were opened during NET_STATE_LOADING
 * @param a_net Network to load wallet cache for
 * @return 0 on success, -1 on error
 */
int dap_chain_wallet_cache_load_for_net(dap_chain_net_t *a_net);

/**
 * @brief Forget that the single-pass bulk build for the network has completed:
 *        the next wallet cache load runs the full pass again (used when the
 *        network's chains are (re)loaded from scratch).
 */
void dap_chain_wallet_cache_bulk_reset(dap_chain_net_id_t a_net_id);

/**
 * @brief Add one unspent output to the wallet cache directly (snapshot restore).
 */
void dap_chain_wallet_cache_restore_unspent(dap_chain_net_id_t a_net_id, const dap_chain_addr_t *a_addr,
                                            dap_chain_hash_fast_t *a_tx_hash, uint16_t a_out_idx, uint8_t a_out_type,
                                            dap_time_t a_ts_unlock, const char *a_ticker, uint256_t a_value);

/**
 * @brief Mark the wallet cache bulk pass as completed for the network (e.g.
 *        the index was restored from the ledger snapshot and needs no pass).
 */
void dap_chain_wallet_cache_bulk_done_mark(dap_chain_net_id_t a_net_id);
void dap_chain_wallet_cache_invalidate_net(dap_chain_net_id_t a_net_id);

// Backlog of undelivered datum notifications above which the cache is
// considered to be still catching up with the chain.
#define DAP_WALLET_CACHE_PENDING_WARM_MAX 1024

bool dap_chain_wallet_cache_mode_all(void);
// True when the cache can answer address queries for the net from memory:
// not loading, no bulk build running, notification backlog drained. Fills
// a_reason (if given) when it returns false. Cheap: reads counters only.
bool dap_chain_wallet_cache_is_warm(dap_chain_net_id_t a_net_id, char *a_reason, size_t a_reason_size);

// True when the per-address index was restored from the ledger snapshot (its
// completion marker is set). During a load pass such an index already holds every
// output, so replaying one datum notification per transaction only fills the
// pending queue that used to keep the node in "warming up" for a long time.
bool dap_chain_wallet_cache_index_restored(dap_chain_net_id_t a_net_id);

// Records one transaction in the per-address history of a_addr (if it touches
// that address). Used by the address-history read path to fill wallet_txs on
// its first (cache-missing) walk, so repeats and the next snapshot start are
// served from the cache. Idempotent per tx hash.
void dap_chain_wallet_cache_history_fill(dap_chain_t *a_chain, const dap_chain_addr_t *a_addr,
                                         dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash,
                                         dap_hash_fast_t *a_atom_hash, int a_ret_code);
// [wallets] wallets_cache_cold_reply_unavailable (default true, ALL mode
// only): RPC address queries the cache can't answer yet must be refused with
// "index warming" instead of falling back to a full ledger scan.
bool dap_chain_wallet_cache_cold_reply_unavailable(void);

/**
 * @brief Find next transactions after l_tx_hash_curr for wallet addr and save pointer to datum into a_tx. If l_tx_hash_curr is NULL then function find first tx for addr.
 * @param a_addr wallet address
 * @param a_token token ticker for transactions filtering  by it
 * @param a_tx output parameter. Pointer for storaging pointer to current datum
 * @param a_tx_hash_curr current tx hash. Receive start tx hash. Return hash of next tx that contained in a_datum
 * @param a_ret_code ledger return code for returned tx
 * @return  0 - ok
 *         -100 - wrong arguments
 *         -101 - addr is not found in cache
 */
int dap_chain_wallet_cache_tx_find(dap_chain_addr_t *a_addr, char *a_token, dap_chain_datum_tx_t **a_tx, 
                                                            dap_hash_fast_t *a_tx_hash_curr, int* a_ret_code);

/**
 * @brief Find next transactions after l_tx_hash_curr for wallet addr and save pointer to transaction into a_tx. 
 *         If l_tx_hash_curr is NULL then function find first tx for addr.
 * @param a_addr  wallet address
 * @param a_token output parameter. Return tx msin token tiker
 * @param a_ret_code output parameter. Return ledger return code for returned tx.
 * @param a_action output parameter. Return action for returned tx.
 * @param a_uid output parameter. Return service uid for returned tx.
 * @param a_tx output parameter. Pointer for storaging pointer to returned tx
 * @param a_tx_hash_curr current tx hash. Return hash of next tx that contained in a_datum and get start tx hash
 * @return  0 - ok
 *         -100 - wrong arguments
 *         -101 - addr is not found in cache
 */
int dap_chain_wallet_cache_tx_find_in_history(dap_chain_addr_t *a_addr, char **a_token, int* a_ret_code, dap_chain_tx_tag_action_type_t *a_action,
                                    dap_chain_net_srv_uid_t *a_uid, dap_chain_datum_tx_t **a_tx, dap_hash_fast_t *a_tx_hash_curr);


/**
 * @brief Find unspent outputs for addr in wallet cache
 * @param a_net pointer to a net in which to find tx
 * @param a_token_ticker token ticker for transactions filtering  by it
 * @param a_addr wallet address
 * @param a_outs_list output parameter. Retrun list of outputs
 * @param a_value_needed needed value
 * @param a_value_transfer output parameter. Sum of outs values in list
 * @return  0 - ok
 *         -100 - wrong arguments
 *         -101 - addr is not found in cache
 */
int dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t a_value_needed, uint256_t *a_value_transfer, bool a_mempool_check,
                                                    bool a_skip_blocklist);
                                                    
int dap_chain_wallet_cache_tx_find_outs_mempool_check(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t *a_value_transfer, bool a_mempool_check,
                                                    bool a_skip_blocklist);

/**
 * @brief Standard UTXO selection with blocklist enforcement (for regular transactions)
 */
DAP_STATIC_INLINE int dap_chain_wallet_cache_tx_find_outs_with_val(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t a_value_needed, uint256_t *a_value_transfer)
{
    return dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(a_net, a_token_ticker, a_addr, a_outs_list, a_value_needed, a_value_transfer, true, false);
}

/**
 * @brief UTXO selection bypassing blocklist (for arbitrage transactions)
 */
DAP_STATIC_INLINE int dap_chain_wallet_cache_tx_find_outs_with_val_skip_blocklist(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t a_value_needed, uint256_t *a_value_transfer)
{
    return dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(a_net, a_token_ticker, a_addr, a_outs_list, a_value_needed, a_value_transfer, true, true);
}
                                                    
DAP_STATIC_INLINE int dap_chain_wallet_cache_tx_find_outs(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t *a_value_transfer)
{
    return dap_chain_wallet_cache_tx_find_outs_mempool_check(a_net, a_token_ticker, a_addr, a_outs_list, a_value_transfer, true, false);
}

dap_chain_wallet_cache_iter_t *dap_chain_wallet_cache_iter_create(dap_chain_addr_t a_addr);
void dap_chain_wallet_cache_iter_delete(dap_chain_wallet_cache_iter_t *a_iter);
dap_chain_datum_tx_t *dap_chain_wallet_cache_iter_get(dap_chain_wallet_cache_iter_t *a_iter, dap_chain_wallet_getting_type_t a_type);

#ifdef __cplusplus
}
#endif
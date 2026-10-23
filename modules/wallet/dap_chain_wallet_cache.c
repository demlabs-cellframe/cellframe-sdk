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

    MODIFICATION HISTORY:

    27-APR-2021 RRL Added password protected wallet support

*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>

#include "dap_chain_wallet_cache.h"
#include "dap_chain_wallet.h"
#include "dap_chain.h"
#include "dap_common.h"
#include "dap_time.h"
#include "dap_chain_mempool.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_utxo.h"
#include "dap_chain_ledger_snapshot.h"
#include "dap_string.h"



#define LOG_TAG "dap_chain_wallet_cache"

typedef enum dap_s_wallets_cache_type{
    DAP_WALLET_CACHE_TYPE_DISABLED = 0,
    DAP_WALLET_CACHE_TYPE_LOCAL,
    DAP_WALLET_CACHE_TYPE_ALL
} dap_s_wallets_cache_type_t;

typedef struct dap_wallet_tx_cache_input{
    dap_chain_hash_fast_t tx_prev_hash; 
    int tx_out_prev_idx;
    uint256_t value;
} dap_wallet_tx_cache_input_t;

typedef struct dap_wallet_tx_cache_output{
    int tx_out_idx;
} dap_wallet_tx_cache_output_t;

typedef struct dap_wallet_tx_cache {
    dap_hash_fast_t tx_hash;
    dap_hash_fast_t atom_hash;
    dap_chain_t *chain;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    bool multichannel;
    int ret_code;
    dap_chain_net_srv_uid_t srv_uid;
    dap_chain_tx_tag_action_type_t action;
    dap_list_t *tx_wallet_inputs;
    dap_list_t *tx_wallet_outputs;
    UT_hash_handle hh;
} dap_wallet_tx_cache_t;

typedef struct unspent_cache_hh_key {
    dap_hash_fast_t tx_hash;
    int out_idx;
} DAP_ALIGN_PACKED unspent_cache_hh_key;

typedef struct dap_wallet_cache_unspent_outs {
    unspent_cache_hh_key key;
    uint256_t value;
    dap_chain_tx_item_type_t out_type;
    dap_time_t ts_unlock;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];

    UT_hash_handle hh;
} dap_wallet_cache_unspent_outs_t;

typedef struct dap_s_wallets_cache {
    dap_chain_addr_t wallet_addr;
    dap_wallet_tx_cache_t *wallet_txs;
    dap_wallet_cache_unspent_outs_t *unspent_outputs;

    _Atomic bool is_loading;
    UT_hash_handle hh;
} dap_wallet_cache_t;

typedef struct dap_atom_notify_arg {
    dap_chain_t *chain;
    dap_chain_net_t *net;
} dap_atom_notify_arg_t;

// ALL by default: it indexes every address ever seen (a modest set on the
// shipped networks) and is what lets the ledger snapshot carry the unspent
// index, so "wallet outputs" answers instantly for any address with no ledger
// scan fallback. [wallets] wallets_cache=local|disable brings the old modes back.
static dap_s_wallets_cache_type_t s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_ALL;
static dap_wallet_cache_t *s_wallets_cache = NULL;
static pthread_rwlock_t s_wallet_cache_rwlock;
static bool s_debug_more = false;
static _Atomic int s_loading_threads_count = 0;
static dap_list_t *s_bulk_loading_nets = NULL;
// Datum index notifications queued for this cache but not yet applied. While
// it is non-zero (e.g. right after a chain load or a resync pushed tens of
// thousands of datums through the low-priority proc queues) the cache lags
// behind the ledger for an arbitrary set of addresses.
static _Atomic(uint64_t) s_notify_pending = 0;
// Default for [wallets] wallets_cache_cold_reply: in ALL mode a request the
// cache can't answer yet gets a fast 503 + Retry-After instead of a ledger
// fallback scan - a public RPC node must not turn every cold lookup into a
// full ledger walk, which is what pushed nodes into swap while the cache was
// (re)building.
static bool s_cold_reply_unavailable = true;

static bool s_bulk_loading_nets_has(uint64_t a_net_id)
{
    for (dap_list_t *l_it = s_bulk_loading_nets; l_it; l_it = l_it->next) {
        if (a_net_id == *(uint64_t*)l_it->data)
            return true;
    }
    return false;
}

static void s_bulk_loading_nets_add(uint64_t a_net_id)
{
    // No duplicates: the list keeps one entry per network and the remove
    // deletes the first match, so a duplicate would pin "bulk in progress"
    // (and the /health 503) until the process restarts.
    if (s_bulk_loading_nets_has(a_net_id))
        return;
    uint64_t *l_id = DAP_NEW(uint64_t);
    if (l_id)
        *l_id = a_net_id;
    s_bulk_loading_nets = dap_list_append(s_bulk_loading_nets, l_id);
}

// Nets whose single-pass bulk build has COMPLETED in this process. The
// datum-notify subscription keeps the cache incremental afterwards, so a new
// full pass on every ONLINE transition (a node cycling RESYNC<->ONLINE used
// to start a competing bulk each time - threads, CPU, RSS/swap) is pure
// waste: one completed pass per network load is enough. Reset on a new
// chain load (dap_chain_wallet_cache_bulk_reset).
static dap_list_t *s_bulk_done_nets = NULL;

static bool s_bulk_done_nets_has(uint64_t a_net_id)
{
    for (dap_list_t *l_it = s_bulk_done_nets; l_it; l_it = l_it->next) {
        if (a_net_id == *(uint64_t*)l_it->data)
            return true;
    }
    return false;
}

static void s_bulk_done_nets_add(uint64_t a_net_id)
{
    if (s_bulk_done_nets_has(a_net_id))
        return;
    uint64_t *l_id = DAP_NEW(uint64_t);
    if (l_id)
        *l_id = a_net_id;
    s_bulk_done_nets = dap_list_append(s_bulk_done_nets, l_id);
}

void dap_chain_wallet_cache_bulk_reset(dap_chain_net_id_t a_net_id)
{
    for (dap_list_t *l_it = s_bulk_done_nets; l_it;) {
        dap_list_t *l_next = l_it->next;
        if (a_net_id.uint64 == *(uint64_t*)l_it->data) {
            DAP_DELETE(l_it->data);
            s_bulk_done_nets = dap_list_remove_link(s_bulk_done_nets, l_it);
        }
        l_it = l_next;
    }
}

void dap_chain_wallet_cache_restore_unspent(dap_chain_net_id_t a_net_id, const dap_chain_addr_t *a_addr,
                                            dap_chain_hash_fast_t *a_tx_hash, uint16_t a_out_idx, uint8_t a_out_type,
                                            dap_time_t a_ts_unlock, const char *a_ticker, uint256_t a_value)
{
    if (s_wallets_cache_type != DAP_WALLET_CACHE_TYPE_ALL)
        return; // LOCAL mode does not keep a per-address unspent index
    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
    dap_wallet_cache_t *l_wallet_item = NULL;
    HASH_FIND(hh, s_wallets_cache, a_addr, sizeof(*a_addr), l_wallet_item);
    if (!l_wallet_item) {
        l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
        l_wallet_item->wallet_addr = *a_addr;
        HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(l_wallet_item->wallet_addr), l_wallet_item);
    }
    unspent_cache_hh_key l_key = { .tx_hash = *a_tx_hash, .out_idx = a_out_idx };
    dap_wallet_cache_unspent_outs_t *l_item = NULL;
    HASH_FIND(hh, l_wallet_item->unspent_outputs, &l_key, sizeof(l_key), l_item);
    if (!l_item) {
        l_item = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
        l_item->key = l_key;
        l_item->value = a_value;
        l_item->out_type = (dap_chain_tx_item_type_t)a_out_type;
        l_item->ts_unlock = a_ts_unlock;
        dap_strncpy(l_item->token_ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
        HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(l_item->key), l_item);
    }
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
}

size_t dap_chain_wallet_cache_foreach_unspent(dap_chain_net_id_t a_net_id,
        dap_chain_wallet_cache_unspent_cb_t a_cb, void *a_arg)
{
    if (s_wallets_cache_type != DAP_WALLET_CACHE_TYPE_ALL || !a_cb)
        return 0;
    size_t l_n = 0;
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    for (dap_wallet_cache_t *l_w = s_wallets_cache; l_w; l_w = l_w->hh.next) {
        if (l_w->wallet_addr.net_id.uint64 != a_net_id.uint64)
            continue;
        for (dap_wallet_cache_unspent_outs_t *l_u = l_w->unspent_outputs; l_u; l_u = l_u->hh.next) {
            a_cb(a_arg, &l_w->wallet_addr, &l_u->key.tx_hash, l_u->key.out_idx,
                 (uint8_t)l_u->out_type, l_u->ts_unlock, l_u->token_ticker, &l_u->value);
            ++l_n;
        }
    }
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    return l_n;
}

size_t dap_chain_wallet_cache_unspent_count(dap_chain_net_id_t a_net_id)
{
    if (s_wallets_cache_type != DAP_WALLET_CACHE_TYPE_ALL)
        return 0;
    size_t l_n = 0;
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    for (dap_wallet_cache_t *l_w = s_wallets_cache; l_w; l_w = l_w->hh.next) {
        if (l_w->wallet_addr.net_id.uint64 != a_net_id.uint64)
            continue;
        for (dap_wallet_cache_unspent_outs_t *l_u = l_w->unspent_outputs; l_u; l_u = l_u->hh.next)
            ++l_n;
    }
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    return l_n;
}

void dap_chain_wallet_cache_bulk_done_mark(dap_chain_net_id_t a_net_id)
{
    // The list is read under the cache lock elsewhere: mutate it under the same
    // lock (a snapshot restore calls this from the load thread while readers run).
    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
    s_bulk_done_nets_add(a_net_id.uint64);
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
}

static void s_bulk_loading_nets_remove(uint64_t a_net_id)
{
    for (dap_list_t *l_it = s_bulk_loading_nets; l_it; l_it = l_it->next) {
        if (a_net_id == *(uint64_t*)l_it->data) {
            DAP_DELETE(l_it->data);
            s_bulk_loading_nets = dap_list_remove_link(s_bulk_loading_nets, l_it);
            return;
        }
    }
}

static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx,
                                    dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                    dap_chain_net_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action, char a_cache_op);
static int s_save_cache_for_addr_in_net(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr);
static void s_callback_datum_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_hash_fast_t *a_atom_hash,
                                    const void *a_atom, size_t a_atom_size, void *a_datum, size_t a_datum_size, int a_ret_code,
                                    uint32_t a_action, dap_chain_net_srv_uid_t a_uid);
static void s_callback_datum_removed_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum);
static void s_wallet_opened_callback(dap_chain_wallet_t *a_wallet, void *a_arg);
static void s_wallet_cache_request_pass(dap_chain_net_t *a_net);
static void *s_wallet_load_all_for_net(void *a_arg);

static void s_wallet_cache_drop_unspent_by_tx_hash(dap_wallet_cache_t *a_wallet_item, const dap_hash_fast_t *a_tx_hash)
{
    if (!a_wallet_item || !a_tx_hash)
        return;

    dap_wallet_cache_unspent_outs_t *l_item = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_wallet_item->unspent_outputs, l_item, l_tmp) {
        if (!dap_hash_fast_compare(&l_item->key.tx_hash, a_tx_hash))
            continue;
        HASH_DEL(a_wallet_item->unspent_outputs, l_item);
        DAP_DELETE(l_item);
    }
}

static void s_wallet_cache_drop_unspent_global_by_key(const dap_hash_fast_t *a_tx_hash, int a_out_idx)
{
    if (!a_tx_hash)
        return;

    unspent_cache_hh_key l_key = { .tx_hash = *a_tx_hash, .out_idx = a_out_idx };
    dap_wallet_cache_t *l_wallet_item = NULL, *l_wallet_tmp = NULL;
    HASH_ITER(hh, s_wallets_cache, l_wallet_item, l_wallet_tmp) {
        dap_wallet_cache_unspent_outs_t *l_item = NULL;
        HASH_FIND(hh, l_wallet_item->unspent_outputs, &l_key, sizeof(unspent_cache_hh_key), l_item);
        if (!l_item)
            continue;
        HASH_DEL(l_wallet_item->unspent_outputs, l_item);
        DAP_DELETE(l_item);
    }
}

static void s_wallet_cache_clear_wallet_txs(dap_wallet_cache_t *a_wallet_item)
{
    if (!a_wallet_item)
        return;
    dap_wallet_tx_cache_t *l_tx = NULL, *l_tx_tmp = NULL;
    HASH_ITER(hh, a_wallet_item->wallet_txs, l_tx, l_tx_tmp) {
        HASH_DEL(a_wallet_item->wallet_txs, l_tx);
        dap_list_free_full(l_tx->tx_wallet_inputs, NULL);
        dap_list_free_full(l_tx->tx_wallet_outputs, NULL);
        DAP_DELETE(l_tx);
    }
}

static void s_wallet_cache_clear_unspent(dap_wallet_cache_t *a_wallet_item)
{
    if (!a_wallet_item)
        return;
    dap_wallet_cache_unspent_outs_t *l_item = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_wallet_item->unspent_outputs, l_item, l_tmp) {
        HASH_DEL(a_wallet_item->unspent_outputs, l_item);
        DAP_DELETE(l_item);
    }
}

// Decides what an address unknown to the cache means in ALL mode: it's only
// safe to report "genuinely empty wallet" (0) once the initial bulk load for
// this net has finished. While bulk loading is still running, an unseen
// address may simply not have been reached by the scan yet - reporting it as
// empty makes every caller (dap_chain_net_tx_create_by_json among them, see
// cellframe_node_rpc_overload_research_2026_09 sec. 10.1/9.3.2) skip the
// ledger fallback entirely and fail compose with "not enough funds" for a
// wallet that in fact has funds. -101 tells the caller "cache can't answer
// yet, go check the ledger" instead - the same contract already used for the
// is_loading and cache-not-populated cases right above each call site.
// Called with s_wallet_cache_rwlock released: s_bulk_loading_nets is unlinked
// and freed under the write lock when a net finishes its bulk load.
static int s_wallet_cache_unknown_addr_ret_code(const dap_chain_addr_t *a_addr)
{
    if (s_wallets_cache_type != DAP_WALLET_CACHE_TYPE_ALL)
        return -101; // LOCAL/unexpected: address was never meant to be cached, ledger fallback path
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    bool l_bulk_loading = s_bulk_loading_nets_has(a_addr->net_id.uint64);
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    if (l_bulk_loading) {
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_addr->net_id);
        debug_if(s_debug_more, L_DEBUG, "Wallet \"%s\" not yet seen, net %s is still bulk-loading",
                 dap_chain_addr_to_str_static(a_addr), l_net ? l_net->pub.name : "?");
        return -101;
    }
    log_it(L_INFO, "Wallet \"%s\" is empty", dap_chain_addr_to_str_static(a_addr));
    return 0;
}

static char * s_wallet_cache_type_to_str(dap_s_wallets_cache_type_t a_type)
{
    switch (a_type){
        case DAP_WALLET_CACHE_TYPE_DISABLED:
            return "DISABLED";
        case DAP_WALLET_CACHE_TYPE_LOCAL:
            return "LOCAL";
        case DAP_WALLET_CACHE_TYPE_ALL:
            return "ALL";
        default:
            return "UNKNOWN";
    }
}

// The [wallets] mode and the cache lock must be live before the ledger snapshot
// restore (it runs inside the net init, before dap_chain_wallet_cache_init), or
// the restored unspent index is silently dropped by the mode check.
void dap_chain_wallet_cache_preinit(void)
{
    static bool s_preinited = false;
    if (s_preinited)
        return;
    s_preinited = true;
    const char *l_walet_cache_type_str = dap_config_get_item_str(g_config, "wallets", "wallets_cache");
    if (l_walet_cache_type_str){
        if (!dap_strcmp(l_walet_cache_type_str, "disable")){
            s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_DISABLED;
        } else if (!dap_strcmp(l_walet_cache_type_str, "local")){
            s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_LOCAL;
        } else if (!dap_strcmp(l_walet_cache_type_str, "all")){
            s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_ALL;
        } else {
            log_it( L_WARNING, "Unknown cache type in config. Remain default: %s", s_wallet_cache_type_to_str(s_wallets_cache_type));
        }
    }
    pthread_rwlock_init(&s_wallet_cache_rwlock, NULL);
}

// Snapshot section "wallet_txs": per-address transaction history. Without it a
// restored node has the unspent index but an empty wallet_txs, and every
// 'tx_history -addr' falls back to a full chain datum walk.
#define DAP_WALLET_CACHE_SNAPSHOT_SECTION "wallet_txs"

typedef struct DAP_PACKED s_wallet_tx_snapshot_rec {
    dap_hash_fast_t tx_hash;
    dap_hash_fast_t atom_hash;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    int32_t ret_code;
    uint32_t action;
    uint64_t srv_uid;
    uint32_t n_inputs;
    uint32_t n_outputs;
    uint8_t multichannel;
    uint8_t pad[3];
} s_wallet_tx_snapshot_rec_t;

typedef struct DAP_PACKED s_wallet_tx_snapshot_in {
    dap_hash_fast_t tx_prev_hash;
    int32_t tx_out_prev_idx;
} s_wallet_tx_snapshot_in_t;

typedef struct DAP_PACKED s_wallet_tx_snapshot_out {
    int32_t tx_out_idx;
} s_wallet_tx_snapshot_out_t;

static bool s_snapshot_buf_append(dap_string_t *a_out, const void *a_data, size_t a_size)
{
    return dap_string_append_len(a_out, (const char *)a_data, a_size) != NULL;
}

static int s_snapshot_wallet_txs_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out)
{
    (void)a_ctx;
    uint64_t l_count = 0;
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    for (dap_wallet_cache_t *l_w = s_wallets_cache; l_w; l_w = l_w->hh.next)
        if (l_w->wallet_txs && l_w->wallet_addr.net_id.uint64 == a_net_id)
            ++l_count;
    if (!s_snapshot_buf_append(a_out, &l_count, sizeof(l_count))) {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return -1;
    }
    for (dap_wallet_cache_t *l_w = s_wallets_cache; l_w; l_w = l_w->hh.next) {
        if (!l_w->wallet_txs || l_w->wallet_addr.net_id.uint64 != a_net_id)
            continue;
        uint32_t l_n_tx = (uint32_t)HASH_COUNT(l_w->wallet_txs);
        if (!s_snapshot_buf_append(a_out, &l_w->wallet_addr, sizeof(l_w->wallet_addr))
                || !s_snapshot_buf_append(a_out, &l_n_tx, sizeof(l_n_tx))) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            return -1;
        }
        for (dap_wallet_tx_cache_t *l_t = l_w->wallet_txs; l_t; l_t = l_t->hh.next) {
            s_wallet_tx_snapshot_rec_t l_rec = {
                .tx_hash = l_t->tx_hash,
                .atom_hash = l_t->atom_hash,
                .ret_code = l_t->ret_code,
                .action = (uint32_t)l_t->action,
                .srv_uid = l_t->srv_uid.uint64,
                .n_inputs = (uint32_t)dap_list_length(l_t->tx_wallet_inputs),
                .n_outputs = (uint32_t)dap_list_length(l_t->tx_wallet_outputs),
                .multichannel = l_t->multichannel ? 1 : 0
            };
            dap_strncpy(l_rec.token_ticker, l_t->token_ticker, sizeof(l_rec.token_ticker));
            if (!s_snapshot_buf_append(a_out, &l_rec, sizeof(l_rec))) {
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                return -1;
            }
            for (dap_list_t *it = l_t->tx_wallet_inputs; it; it = it->next) {
                dap_wallet_tx_cache_input_t *l_in = it->data;
                s_wallet_tx_snapshot_in_t l_in_rec = {
                    .tx_prev_hash = l_in->tx_prev_hash,
                    .tx_out_prev_idx = l_in->tx_out_prev_idx
                };
                if (!s_snapshot_buf_append(a_out, &l_in_rec, sizeof(l_in_rec))) {
                    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                    return -1;
                }
            }
            for (dap_list_t *it = l_t->tx_wallet_outputs; it; it = it->next) {
                dap_wallet_tx_cache_output_t *l_out = it->data;
                s_wallet_tx_snapshot_out_t l_out_rec = { .tx_out_idx = l_out->tx_out_idx };
                if (!s_snapshot_buf_append(a_out, &l_out_rec, sizeof(l_out_rec))) {
                    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                    return -1;
                }
            }
        }
    }
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    return 0;
}

static int s_snapshot_wallet_txs_load(void *a_ctx, const uint8_t *a_data, size_t a_size)
{
    (void)a_ctx;
    if (!a_data || a_size < sizeof(uint64_t))
        return -1;
    const uint8_t *l_ptr = a_data, *l_end = a_data + a_size;
    uint64_t l_n_wallets = 0;
    memcpy(&l_n_wallets, l_ptr, sizeof(l_n_wallets));
    l_ptr += sizeof(l_n_wallets);
    for (uint64_t w = 0; w < l_n_wallets; ++w) {
        dap_chain_addr_t l_addr = {};
        uint32_t l_n_tx = 0;
        if (l_ptr + sizeof(l_addr) + sizeof(l_n_tx) > l_end)
            return -2;
        memcpy(&l_addr, l_ptr, sizeof(l_addr));
        l_ptr += sizeof(l_addr);
        memcpy(&l_n_tx, l_ptr, sizeof(l_n_tx));
        l_ptr += sizeof(l_n_tx);
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_addr.net_id);
        dap_chain_t *l_chain = l_net
                ? dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX) : NULL;
        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        dap_wallet_cache_t *l_wallet_item = NULL;
        HASH_FIND(hh, s_wallets_cache, &l_addr, sizeof(l_addr), l_wallet_item);
        if (!l_wallet_item) {
            l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
            if (!l_wallet_item) {
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                return -3;
            }
            l_wallet_item->wallet_addr = l_addr;
            l_wallet_item->is_loading = false;
            HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(l_wallet_item->wallet_addr), l_wallet_item);
        }
        for (uint32_t t = 0; t < l_n_tx; ++t) {
            s_wallet_tx_snapshot_rec_t l_rec = {};
            if (l_ptr + sizeof(l_rec) > l_end) {
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                return -4;
            }
            memcpy(&l_rec, l_ptr, sizeof(l_rec));
            l_ptr += sizeof(l_rec);
            if (l_rec.n_inputs > 1024 * 1024 || l_rec.n_outputs > 1024 * 1024) {
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                return -4;
            }
            size_t l_in_size = (size_t)l_rec.n_inputs * sizeof(s_wallet_tx_snapshot_in_t);
            size_t l_out_size = (size_t)l_rec.n_outputs * sizeof(s_wallet_tx_snapshot_out_t);
            if (l_ptr + l_in_size + l_out_size > l_end) {
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                return -5;
            }
            const s_wallet_tx_snapshot_in_t *l_ins = (const s_wallet_tx_snapshot_in_t *)l_ptr;
            l_ptr += l_in_size;
            const s_wallet_tx_snapshot_out_t *l_outs = (const s_wallet_tx_snapshot_out_t *)l_ptr;
            l_ptr += l_out_size;
            dap_wallet_tx_cache_t *l_found = NULL;
            HASH_FIND(hh, l_wallet_item->wallet_txs, &l_rec.tx_hash, sizeof(l_rec.tx_hash), l_found);
            if (l_found || !l_chain)
                continue; // already replayed from the blocks, or no chain to bind
            dap_wallet_tx_cache_t *l_new = DAP_NEW_Z(dap_wallet_tx_cache_t);
            if (!l_new) {
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                return -6;
            }
            l_new->tx_hash = l_rec.tx_hash;
            l_new->atom_hash = l_rec.atom_hash;
            l_new->chain = l_chain;
            l_new->ret_code = l_rec.ret_code;
            l_new->action = (dap_chain_tx_tag_action_type_t)l_rec.action;
            l_new->srv_uid.uint64 = l_rec.srv_uid;
            l_new->multichannel = l_rec.multichannel != 0;
            dap_strncpy(l_new->token_ticker, l_rec.token_ticker, sizeof(l_new->token_ticker));
            for (uint32_t i = 0; i < l_rec.n_inputs; ++i) {
                dap_wallet_tx_cache_input_t *l_in = DAP_NEW_Z(dap_wallet_tx_cache_input_t);
                if (!l_in)
                    continue;
                l_in->tx_prev_hash = l_ins[i].tx_prev_hash;
                l_in->tx_out_prev_idx = l_ins[i].tx_out_prev_idx;
                l_new->tx_wallet_inputs = dap_list_append(l_new->tx_wallet_inputs, l_in);
            }
            for (uint32_t i = 0; i < l_rec.n_outputs; ++i) {
                dap_wallet_tx_cache_output_t *l_out = DAP_NEW_Z(dap_wallet_tx_cache_output_t);
                if (!l_out)
                    continue;
                l_out->tx_out_idx = l_outs[i].tx_out_idx;
                l_new->tx_wallet_outputs = dap_list_append(l_new->tx_wallet_outputs, l_out);
            }
            HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(l_new->tx_hash), l_new);
        }
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    }
    log_it(L_NOTICE, "Wallet cache: transaction history restored from the snapshot (%" DAP_UINT64_FORMAT_U
           " addresses)", l_n_wallets);
    return 0;
}

int dap_chain_wallet_cache_init()
{
    dap_chain_wallet_cache_preinit();
    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL)
        dap_ledger_add_snapshot_section(DAP_WALLET_CACHE_SNAPSHOT_SECTION, 0,
                s_snapshot_wallet_txs_dump, s_snapshot_wallet_txs_load, NULL);

    s_debug_more = dap_config_get_item_bool_default(g_config,"wallet","debug_more", s_debug_more);
    s_cold_reply_unavailable = dap_config_get_item_bool_default(g_config, "wallets", "wallets_cache_cold_reply_unavailable",
                                                                s_cold_reply_unavailable);

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        debug_if(s_debug_more, L_DEBUG, "Wallet cache is disabled.");
        return 0;
    }

    log_it(L_INFO, "Wallet cache type: %s", s_wallet_cache_type_to_str(s_wallets_cache_type));

    {
        uint16_t l_addrs_count = 0;
        const char **l_addrs_str = dap_config_get_array_str(g_config, "wallet_cache", "addrs", &l_addrs_count);
        for (uint16_t i = 0; l_addrs_str && i < l_addrs_count; i++) {
            const char *l_addr_str = l_addrs_str[i];
            if (!l_addr_str || !*l_addr_str)
                continue;
            dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_str);
            if (!l_addr) {
                log_it(L_WARNING, "Can't parse address #%u from [wallet_cache].addrs: \"%s\"", i, l_addr_str);
                continue;
            }
            if (dap_chain_addr_is_blank(l_addr)) {
                DAP_DELETE(l_addr);
                continue;
            }
            if (!dap_chain_wallet_addr_cache_get_name(l_addr))
                dap_chain_wallet_addr_cache_add(l_addr, "config");
            debug_if(s_debug_more, L_DEBUG, "Wallet cache: registered extra address %s from config",
                     dap_chain_addr_to_str_static(l_addr));
            DAP_DELETE(l_addr);
        }
    }

    // Add notify callback for all chain with transactions in all nets
    for(dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net=dap_chain_net_iter_next(l_net)){
        // Find chain with transactions
        dap_chain_t *l_chain = l_net->pub.chains;
        while (l_chain){
            for(int i = 0; i < l_chain->datum_types_count; i++) {
                if(l_chain->datum_types[i] == CHAIN_TYPE_TX){
                    dap_atom_notify_arg_t *l_arg = DAP_NEW_Z(dap_atom_notify_arg_t);
                    l_arg->chain = l_chain;
                    l_arg->net = l_net;
                    dap_proc_thread_t *l_pt = dap_proc_thread_get_auto();
                    dap_chain_add_callback_datum_index_notify_ex(l_chain, s_callback_datum_notify, l_pt, l_arg, &s_notify_pending);
                    dap_chain_add_callback_datum_removed_from_index_notify_ex(l_chain, s_callback_datum_removed_notify, l_pt, l_arg,
                                                                              &s_notify_pending);
                }
            }
            l_chain=l_chain->next;
        }
        
    }

    dap_list_t *l_local_addr_list = dap_chain_wallet_get_local_addr();
    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
    for(dap_list_t *it = l_local_addr_list; it; it=it->next){
        dap_chain_addr_t *l_addr = (dap_chain_addr_t *)it->data;
        dap_wallet_cache_t *l_wallet_item = NULL;

        HASH_FIND(hh, s_wallets_cache, l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
        if (!l_wallet_item){
            l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
            memcpy (&l_wallet_item->wallet_addr, l_addr, sizeof(dap_chain_addr_t));
            HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            debug_if(s_debug_more, L_DEBUG, "Wallet %s saved.", dap_chain_addr_to_str_static(l_addr));
        }
    }
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    dap_list_free_full(l_local_addr_list, NULL);
    dap_chain_wallet_add_wallet_opened_notify(s_wallet_opened_callback, NULL);
    dap_chain_wallet_add_wallet_created_notify(s_wallet_opened_callback, NULL);

    return 0;
}

int dap_chain_wallet_cache_deinit()
{
    /* Wait for all background wallet-loading threads to finish before
     * the caller proceeds to deinit GlobalDB / MDBX. Without this wait,
     * a detached thread that is still writing to GlobalDB will crash
     * (SEGFAULT / SIGABRT) when the MDBX environment is destroyed. */
    const int l_timeout_ms = 5000;
    const int l_poll_us   = 5000;
    int l_waited_us = 0;
    while (atomic_load(&s_loading_threads_count) > 0 &&
           l_waited_us < l_timeout_ms * 1000) {
        dap_usleep(l_poll_us);
        l_waited_us += l_poll_us;
    }
    if (atomic_load(&s_loading_threads_count) > 0)
        log_it(L_WARNING, "dap_chain_wallet_cache_deinit: %d loading thread(s) still running after %d ms timeout",
               atomic_load(&s_loading_threads_count), l_timeout_ms);
    return 0;
}

int dap_chain_wallet_cache_load_for_net(dap_chain_net_t *a_net)
{
    dap_return_val_if_fail(a_net, -1);

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED) {
        debug_if(s_debug_more, L_DEBUG, "Wallet cache is disabled, skipping load for net %s", a_net->pub.name);
        return 0;
    }

#ifndef DAP_LEDGER_TEST
    if (dap_chain_net_get_load_mode(a_net)) {
        debug_if(s_debug_more, L_DEBUG, "Network %s is in LOADING mode, skipping wallet cache load", a_net->pub.name);
        return 0;
    }
#else
    if (dap_chain_net_get_load_mode(a_net))
        debug_if(s_debug_more, L_DEBUG, "Network %s is in LOADING mode, but DAP_LEDGER_TEST is defined - loading cache anyway", a_net->pub.name);
#endif

    dap_list_t *l_local_addr_list = dap_chain_wallet_get_local_addr();
    if (!l_local_addr_list && s_wallets_cache_type != DAP_WALLET_CACHE_TYPE_ALL) {
        debug_if(s_debug_more, L_DEBUG, "No local wallets found for net %s", a_net->pub.name);
        return 0;
    }

    int l_count = 0;
    // With a restored index (completion marker set, e.g. by a v2 snapshot) the
    // local addresses are already covered by the per-address unspent records:
    // do NOT mark them loading, or the catch-up below starts a full history
    // pass on every start - that walk is I/O-bound and takes hours on a full
    // Backbone chain (seen live on cf-mm-0).
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    bool l_index_restored = s_bulk_done_nets_has(a_net->pub.id.uint64);
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
    for (dap_list_t *it = l_local_addr_list; it; it = it->next) {
        dap_chain_addr_t *l_addr = (dap_chain_addr_t *)it->data;
        if (l_addr->net_id.uint64 != a_net->pub.id.uint64)
            continue;
        dap_wallet_cache_t *l_wallet_item = NULL;
        HASH_FIND(hh, s_wallets_cache, l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
        if (!l_wallet_item) {
            l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
            l_wallet_item->wallet_addr = *l_addr;
            l_wallet_item->is_loading = !l_index_restored;
            HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            if (!l_index_restored)
                l_count++;
        } else if (!l_index_restored && !l_wallet_item->is_loading && !l_wallet_item->wallet_txs) {
            l_wallet_item->is_loading = true;
            l_count++;
        }
    }
    // ALL mode indexes every address on the net, with or without local wallets.
    // Without this a node with zero local wallets never started the bulk pass,
    // so the cache answered "genuinely empty" (ret 0) for funded addresses and
    // neither the -101 cold path nor is_warm() could ever trigger.
    //
    // One full pass per network load: the datum-notify subscription keeps the
    // cache incremental, so ONLINE-transition re-runs of the whole-history
    // bulk are skipped (they only burned CPU/threads/swap on resync cycles).
    // The "bulk in progress" marker is set ONLY together with the actual
    // spawn - an early exit (pass already done, or already running) must not
    // leave it behind: is_warm() answered 503 "bulk build in progress" for
    // hours/days after a second load_for_net() on a completed pass.
    bool l_bulk_needed = (l_count || s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL)
            && !s_bulk_done_nets_has(a_net->pub.id.uint64)
            && !s_bulk_loading_nets_has(a_net->pub.id.uint64);
    if (l_bulk_needed)
        s_bulk_loading_nets_add(a_net->pub.id.uint64);
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    dap_list_free_full(l_local_addr_list, NULL);

    if (!l_count && s_wallets_cache_type != DAP_WALLET_CACHE_TYPE_ALL) {
        debug_if(s_debug_more, L_DEBUG, "No wallets needed cache loading for net %s", a_net->pub.name);
        return 0;
    }
    if (!l_bulk_needed) {
        debug_if(s_debug_more, L_DEBUG, "Wallet cache bulk pass for net %s is already completed or in progress, "
                 "skipping the repeat run (incremental notify keeps it fresh)", a_net->pub.name);
        // Addresses can be marked loading while no pass could start (a pass
        // completed earlier, e.g. marked done by a snapshot restore): give them
        // their coalesced catch-up, or reads answer -101 forever.
        pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
        bool l_any_loading = false;
        for (dap_wallet_cache_t *l_w = s_wallets_cache; l_w; l_w = l_w->hh.next) {
            if (l_w->wallet_addr.net_id.uint64 == a_net->pub.id.uint64 && l_w->is_loading) {
                l_any_loading = true;
                break;
            }
        }
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        if (l_any_loading)
            s_wallet_cache_request_pass(a_net);
        return 0;
    }

    pthread_t l_tid;
    pthread_attr_t l_attr;
    pthread_attr_init(&l_attr);
    pthread_attr_setdetachstate(&l_attr, PTHREAD_CREATE_DETACHED);
    atomic_fetch_add(&s_loading_threads_count, 1);
    if (pthread_create(&l_tid, &l_attr, s_wallet_load_all_for_net, a_net)) {
        // No thread will ever run the pass: the marker and the counter must go
        // back, or the "bulk in progress" state sticks until restart.
        atomic_fetch_sub(&s_loading_threads_count, 1);
        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        s_bulk_loading_nets_remove(a_net->pub.id.uint64);
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        log_it(L_CRITICAL, "Can't start the wallet cache pass for net %s (pthread_create failed)", a_net->pub.name);
        return -1;
    }
    pthread_attr_destroy(&l_attr);

    log_it(L_INFO, "Started single-pass wallet cache load for %d wallet(s) in net %s", l_count, a_net->pub.name);
    return 0;
}

bool dap_chain_wallet_cache_mode_all(void)
{
    return s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL;
}

bool dap_chain_wallet_cache_cold_reply_unavailable(void)
{
    return s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL && s_cold_reply_unavailable;
}

static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx,
                                    dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code,
                                    char *a_main_token_ticker, dap_chain_net_srv_uid_t a_srv_uid,
                                    dap_chain_tx_tag_action_type_t a_action, char a_cache_op);

bool dap_chain_wallet_cache_index_restored(dap_chain_net_id_t a_net_id)
{
    if (s_wallets_cache_type != DAP_WALLET_CACHE_TYPE_ALL)
        return false;
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    bool l_restored = s_bulk_done_nets_has(a_net_id.uint64);
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    return l_restored;
}

void dap_chain_wallet_cache_history_fill(dap_chain_t *a_chain, const dap_chain_addr_t *a_addr,
                                         dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash,
                                         dap_hash_fast_t *a_atom_hash, int a_ret_code)
{
    if (!a_chain || !a_addr || !a_tx || !a_tx_hash)
        return;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    s_save_tx_cache_for_addr(a_chain, (dap_chain_addr_t *)a_addr, a_tx, a_tx_hash, a_atom_hash,
                             a_ret_code,
                             l_net ? (char *)dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, a_tx_hash) : NULL,
                             (dap_chain_net_srv_uid_t){ .uint64 = 0 },
                             DAP_CHAIN_TX_TAG_ACTION_UNKNOWN, 'a');
}

bool dap_chain_wallet_cache_is_warm(dap_chain_net_id_t a_net_id, char *a_reason, size_t a_reason_size)
{
    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED)
        return true;
    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL) {
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
        // ALL mode is built from datum notifications: in LOADING they are not
        // delivered yet, so the cache can't answer for any address.
        if (!l_net || dap_chain_net_get_load_mode(l_net)) {
            if (a_reason && a_reason_size)
                snprintf(a_reason, a_reason_size, "wallet cache: net %s loading", l_net ? l_net->pub.name : "?");
            return false;
        }
    }
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    bool l_bulk = s_bulk_loading_nets_has(a_net_id.uint64);
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    if (l_bulk) {
        if (a_reason && a_reason_size)
            snprintf(a_reason, a_reason_size, "wallet cache: bulk build in progress");
        return false;
    }
    uint64_t l_pending = atomic_load(&s_notify_pending);
    // A handful of in-flight notifications is normal steady state (every new
    // block queues some); a backlog means the cache is still catching up.
    if (l_pending > DAP_WALLET_CACHE_PENDING_WARM_MAX) {
        if (a_reason && a_reason_size)
            snprintf(a_reason, a_reason_size, "wallet cache: %" DAP_UINT64_FORMAT_U " datum notifications pending", l_pending);
        return false;
    }
    return true;
}

void dap_chain_wallet_cache_invalidate_net(dap_chain_net_id_t a_net_id)
{
    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED)
        return;
    // The cache is about to be wiped: the "bulk pass completed" marker must go
    // with it, or the emptied cache would never be rebuilt (reads would answer
    // "empty" instead of scheduling a pass).
    dap_chain_wallet_cache_bulk_reset(a_net_id);

    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
    dap_wallet_cache_t *l_wallet_item = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_wallets_cache, l_wallet_item, l_tmp) {
        if (l_wallet_item->wallet_addr.net_id.uint64 != a_net_id.uint64)
            continue;
        s_wallet_cache_clear_unspent(l_wallet_item);
        s_wallet_cache_clear_wallet_txs(l_wallet_item);
        l_wallet_item->is_loading = false;
    }
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
}

int dap_chain_wallet_cache_tx_find(dap_chain_addr_t *a_addr, char *a_token, dap_chain_datum_tx_t **a_datum, dap_hash_fast_t *a_tx_hash_curr, int* a_ret_code)
{
    dap_wallet_cache_t *l_wallet_item = NULL;

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        debug_if(s_debug_more, L_DEBUG, "Wallet cache is disabled.");
        return -101;
    }

    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    HASH_FIND(hh, s_wallets_cache, a_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    if ( l_wallet_item ) {
        if ( l_wallet_item->is_loading ) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            log_it( L_WARNING, "Wallet address \"%s\" is pending...", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
        if (!l_wallet_item->wallet_txs) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            return -101;
        }
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return s_wallet_cache_unknown_addr_ret_code(a_addr);
    }

    dap_wallet_tx_cache_t *l_current_wallet_tx = NULL;
    if (!dap_hash_fast_is_blank(a_tx_hash_curr)) {
        // find start transaction
        HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash_curr, sizeof(dap_chain_hash_fast_t), l_current_wallet_tx);
        if (!l_current_wallet_tx){
            debug_if(s_debug_more, L_DEBUG, "Can't find tx %s for address %s", dap_hash_fast_to_str_static(a_tx_hash_curr), dap_chain_addr_to_str_static(a_addr));
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            return 0;
        }

        if (!l_current_wallet_tx->hh.next){
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            return 0;
        }
        // start searching from the next hash after a_tx_first_hash
        l_current_wallet_tx = l_current_wallet_tx->hh.next;
    } else {
        // find wallet
        l_current_wallet_tx = l_wallet_item->wallet_txs;
    }


    // Go iterate wallet txs
    dap_wallet_tx_cache_t *l_current_wallet_tx_iter = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_current_wallet_tx, l_current_wallet_tx_iter, l_tmp) {
        if (l_current_wallet_tx_iter->ret_code != DAP_LEDGER_CHECK_OK)
            continue;
        dap_chain_datum_tx_t *l_tx = NULL;
        bool skip = false;
        if (a_token){
            skip = true;
            if (*l_current_wallet_tx_iter->token_ticker &&
                !dap_strcmp(l_current_wallet_tx_iter->token_ticker, a_token))
            {
                skip = false;
            } else if (l_current_wallet_tx_iter->multichannel){
                dap_chain_datum_t *l_datum = l_current_wallet_tx_iter->chain
                    ? l_current_wallet_tx_iter->chain->callback_datum_find_by_hash(
                          l_current_wallet_tx_iter->chain, &l_current_wallet_tx_iter->tx_hash, NULL, NULL)
                    : NULL;
                l_tx = l_datum ? (dap_chain_datum_tx_t *)l_datum->data : NULL;
                if (!l_tx)
                    continue;
                for (dap_list_t *l_temp = l_current_wallet_tx_iter->tx_wallet_outputs; l_temp; l_temp=l_temp->next){
                    dap_wallet_tx_cache_output_t *l_cur_out_cache = (dap_wallet_tx_cache_output_t *)l_temp->data;
                    uint8_t *l_out_item = dap_chain_datum_tx_item_get_nth(l_tx, TX_ITEM_TYPE_OUT_ALL, l_cur_out_cache->tx_out_idx);
                    if (!l_out_item)
                        continue;
                    byte_t l_out_type = *l_out_item;
                    if (l_out_type == TX_ITEM_TYPE_OUT_EXT && !dap_strcmp(a_token, ((dap_chain_tx_out_ext_t *)l_out_item)->token)) {
                        skip = false;
                        break;
                    }
                    if (l_out_type == TX_ITEM_TYPE_OUT_STD && !dap_strcmp(a_token, ((dap_chain_tx_out_std_t *)l_out_item)->token)) {
                        skip = false;
                        break;
                    }
                }
            }
        }

        if (skip)
            continue;

        if (a_datum && !l_tx) {
            dap_chain_datum_t *l_datum = l_current_wallet_tx_iter->chain
                ? l_current_wallet_tx_iter->chain->callback_datum_find_by_hash(
                      l_current_wallet_tx_iter->chain, &l_current_wallet_tx_iter->tx_hash, NULL, NULL)
                : NULL;
            l_tx = l_datum ? (dap_chain_datum_tx_t *)l_datum->data : NULL;
            if (!l_tx)
                continue;
        }

        // Now work with it
        *a_tx_hash_curr = l_current_wallet_tx_iter->tx_hash;
        if (a_datum)
            *a_datum = l_tx;
        if(a_ret_code)
            *a_ret_code = l_current_wallet_tx_iter->ret_code;
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return 0;
    }
    
    if (a_tx_hash_curr)
        memset(a_tx_hash_curr, 0, sizeof(*a_tx_hash_curr));
    if (a_datum)
        *a_datum = NULL;
    if(a_ret_code)
        *a_ret_code = 0;

    pthread_rwlock_unlock(&s_wallet_cache_rwlock);    
    return 0;
}

int dap_chain_wallet_cache_tx_find_in_history(dap_chain_addr_t *a_addr, char **a_token, int* a_ret_code, dap_chain_tx_tag_action_type_t *a_action,
                                    dap_chain_net_srv_uid_t *a_uid, dap_chain_datum_tx_t **a_datum, dap_hash_fast_t *a_tx_hash_curr)
{
    dap_wallet_cache_t *l_wallet_item = NULL;

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        debug_if(s_debug_more, L_DEBUG, "Wallet cache is disabled.");
        return -101;
    }

    if (!a_tx_hash_curr)
        return -100;

    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    HASH_FIND(hh, s_wallets_cache, a_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    if ( l_wallet_item ) {
        if ( l_wallet_item->is_loading ) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            log_it( L_WARNING, "Wallet address \"%s\" is pending...", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
        if (!l_wallet_item->wallet_txs) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            return -101;
        }
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return s_wallet_cache_unknown_addr_ret_code(a_addr);
    }
    
    dap_wallet_tx_cache_t *l_current_wallet_tx = NULL;
    if (!dap_hash_fast_is_blank(a_tx_hash_curr)) {
        // find start transaction
        HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash_curr, sizeof(dap_chain_hash_fast_t), l_current_wallet_tx);
        if (l_current_wallet_tx && l_current_wallet_tx->hh.next){
            // start searching from the next hash after a_tx_first_hash
            l_current_wallet_tx = l_current_wallet_tx->hh.next;
        } else 
            l_current_wallet_tx = NULL;   
    } else {
        // find wallet
        l_current_wallet_tx = l_wallet_item->wallet_txs;
    }


    // Go iterate wallet txs
    if (l_current_wallet_tx){
        dap_chain_datum_t *l_datum = l_current_wallet_tx->chain
            ? l_current_wallet_tx->chain->callback_datum_find_by_hash(
                  l_current_wallet_tx->chain, &l_current_wallet_tx->tx_hash, NULL, NULL)
            : NULL;
        if (a_datum)
            *a_datum = l_datum ? (dap_chain_datum_tx_t *)l_datum->data : NULL;
        // Now work with it
        *a_tx_hash_curr = l_current_wallet_tx->tx_hash;
        if(a_ret_code)
            *a_ret_code = l_current_wallet_tx->ret_code;
        if(a_action)
            *a_action = l_current_wallet_tx->action;
        if(a_uid)
            *a_uid = l_current_wallet_tx->srv_uid;
        if (a_token)
            *a_token = l_current_wallet_tx->token_ticker;
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return 0;
    }
    
    
    if (a_tx_hash_curr)
        memset(a_tx_hash_curr, 0, sizeof(*a_tx_hash_curr));
    if (a_datum)
        *a_datum = NULL;
    if(a_ret_code)
        *a_ret_code = 0;
    if(a_action)
        *a_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    if (a_uid)
        memset(a_uid, 0, sizeof(*a_uid));
    if (a_token)
        *a_token = NULL;
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);    
    return 0;
}

int dap_chain_wallet_cache_tx_find_outs_mempool_check(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t *a_value_transfer, bool a_mempool_check,
                                                    bool a_skip_blocklist)
{

    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    uint256_t l_value_transfer = { };
    dap_chain_datum_tx_t *l_tx;

    if (!a_token_ticker){
        log_it(L_ERROR, "Token ticker is not specified.");
        return -100;
    } 
    
    if(!a_addr || dap_chain_addr_is_blank(a_addr)){
        log_it(L_ERROR, "Wallet addr is not specified.");
        return -100;
    }

    if (a_outs_list == NULL){
        log_it(L_ERROR, "a_outs_list is NULL");
        return -100;
    }

    dap_wallet_cache_t *l_wallet_item = NULL;
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    HASH_FIND(hh, s_wallets_cache, a_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    if ( l_wallet_item ) {
        if ( l_wallet_item->is_loading ) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            log_it( L_WARNING, "Wallet address \"%s\" is pending...", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return s_wallet_cache_unknown_addr_ret_code(a_addr);
    }

    dap_wallet_cache_unspent_outs_t *l_item_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_wallet_item->unspent_outputs, l_item_cur, l_tmp) {
        if (dap_strcmp(l_item_cur->token_ticker, a_token_ticker))
            continue;
        if (l_item_cur->out_type == TX_ITEM_TYPE_OUT_STD &&
            l_item_cur->ts_unlock > dap_ledger_get_blockchain_time(a_net->pub.ledger))
            continue;
        if (IS_ZERO_256(l_item_cur->value))
            continue;

        if (a_mempool_check && dap_chain_mempool_out_is_used(a_net, &l_item_cur->key.tx_hash, l_item_cur->key.out_idx))
            continue;

        // CRITICAL: Check if UTXO is blocked in token-specific blocklist
        // This check MUST be in wallet cache to prevent bypassing ledger blocking check
        // Applies to all output types (OUT, OUT_EXT, OUT_STD, OUT_COND)
        // Skip this check for arbitrage transactions (a_skip_blocklist = true)
        if (!a_skip_blocklist &&
            dap_ledger_utxo_is_blocked_by_ticker(a_net->pub.ledger, a_token_ticker,
                                                  &l_item_cur->key.tx_hash, l_item_cur->key.out_idx)) {
            debug_if(s_debug_more, L_DEBUG, "[WALLET_CACHE] UTXO %s:%u is blocked for token %s - skipping",
                    dap_hash_fast_to_str_static(&l_item_cur->key.tx_hash), l_item_cur->key.out_idx, a_token_ticker);
            continue;
        }

        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        *l_item = (dap_chain_tx_used_out_item_t) { l_item_cur->key.tx_hash, (uint32_t)l_item_cur->key.out_idx, l_item_cur->value};
        l_list_used_out = dap_list_append(l_list_used_out, l_item);
        SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
    }

    *a_outs_list = l_list_used_out;
    if (a_value_transfer)
        *a_value_transfer = l_value_transfer;

    // CRITICAL FIX: Check if cache was actually loaded
    // If wallet_txs is NULL, cache was never populated - trigger fallback to ledger
    // If wallet_txs exists but unspent_outputs is empty, wallet is genuinely empty - return success
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    if (!l_list_used_out && !l_wallet_item->wallet_txs) {
        // wallet_txs (the per-address history) is a separate index that the
        // snapshot does not carry yet. With a restored unspent index an empty
        // list IS the answer; falling back to a full ledger walk for every
        // empty address turned a 5 ms reply into a 30 s one.
        // (Checked after the unlock: the restored marker takes the same lock.)
        if (!dap_chain_wallet_cache_index_restored(a_net->pub.id)) {
            debug_if(s_debug_more, L_DEBUG, "[WALLET_CACHE] Cache not loaded for %s (wallet_txs=NULL), falling back to ledger",
                     dap_chain_addr_to_str_static(a_addr));
            return -101;  // Return error to trigger fallback to ledger
        }
    }
    return 0;
}

int dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t a_value_need, uint256_t *a_value_transfer, bool a_mempool_check,
                                                    bool a_skip_blocklist)
{

    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    uint256_t l_value_transfer = { };
    dap_chain_datum_tx_t *l_tx;

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        debug_if(s_debug_more, L_DEBUG, "Wallet cache is disabled.");
        return -101;
    }

    if (!a_token_ticker){
        log_it(L_ERROR, "Token ticker is not specified.");
        return -100;
    } 
    
    if(!a_addr || dap_chain_addr_is_blank(a_addr)){
        log_it(L_ERROR, "Wallet addr is not specified.");
        return -100;
    }

    if (IS_ZERO_256(a_value_need)){
        log_it(L_ERROR, "Needed value is zero.");
        return -100;
    }

    if (a_outs_list == NULL){
        log_it(L_ERROR, "a_outs_list is NULL");
        return -100;
    }

    dap_wallet_cache_t *l_wallet_item = NULL;
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    HASH_FIND(hh, s_wallets_cache, a_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    if ( l_wallet_item ) {
        if ( l_wallet_item->is_loading ) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            log_it( L_WARNING, "Wallet address \"%s\" is pending...", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return s_wallet_cache_unknown_addr_ret_code(a_addr);
    }

    dap_wallet_cache_unspent_outs_t *l_item_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_wallet_item->unspent_outputs, l_item_cur, l_tmp) {
        if (dap_strcmp(l_item_cur->token_ticker, a_token_ticker))
            continue;
        if (l_item_cur->out_type == TX_ITEM_TYPE_OUT_STD &&
            l_item_cur->ts_unlock > dap_ledger_get_blockchain_time(a_net->pub.ledger))
            continue;
        if (IS_ZERO_256(l_item_cur->value))
            continue;

        if (a_mempool_check && dap_chain_mempool_out_is_used(a_net, &l_item_cur->key.tx_hash, l_item_cur->key.out_idx))
            continue;

        // CRITICAL: Check if UTXO is blocked in token-specific blocklist
        // This check MUST be in wallet cache to prevent bypassing ledger blocking check
        // Applies to all output types (OUT, OUT_EXT, OUT_STD, OUT_COND)
        // Skip this check for arbitrage transactions (a_skip_blocklist = true)
        if (!a_skip_blocklist &&
            dap_ledger_utxo_is_blocked_by_ticker(a_net->pub.ledger, a_token_ticker,
                                                  &l_item_cur->key.tx_hash, l_item_cur->key.out_idx)) {
            debug_if(s_debug_more, L_DEBUG, "[WALLET_CACHE] UTXO %s:%u is blocked for token %s - skipping",
                    dap_hash_fast_to_str_static(&l_item_cur->key.tx_hash), l_item_cur->key.out_idx, a_token_ticker);
            continue;
        }

        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        *l_item = (dap_chain_tx_used_out_item_t) { l_item_cur->key.tx_hash, (uint32_t)l_item_cur->key.out_idx, l_item_cur->value};
        l_list_used_out = dap_list_append(l_list_used_out, l_item);
        SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
        if ( compare256(l_value_transfer, a_value_need) >= 0 ) {
            break;
        }
    }

    // CRITICAL FIX: Check if cache was actually loaded
    // If wallet_txs is NULL, cache was never populated - trigger fallback to ledger
    // If wallet_txs exists but unspent_outputs is empty, wallet is genuinely empty - return success
    if (!l_list_used_out && !l_wallet_item->wallet_txs) {
        debug_if(s_debug_more, L_DEBUG, "[WALLET_CACHE] Cache not loaded for %s (wallet_txs=NULL), falling back to ledger",
                 dap_chain_addr_to_str_static(a_addr));
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return -101;  // Return error to trigger fallback to ledger
    }

    pthread_rwlock_unlock(&s_wallet_cache_rwlock);

    if (compare256(l_value_transfer, a_value_need) >= 0 && l_list_used_out){
        *a_outs_list = l_list_used_out;
        if (a_value_transfer)
            *a_value_transfer = l_value_transfer;
    } else {
        *a_outs_list = NULL;
        dap_list_free_full(l_list_used_out, NULL);
        if (a_value_transfer)
            *a_value_transfer = uint256_0;
    }
   
    return 0;
}


static int s_save_cache_for_addr_in_net(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr)
{
    dap_chain_t *l_chain = a_net->pub.chains;
    while (l_chain){
        for(int i = 0; i < l_chain->datum_types_count; i++) {
            if(l_chain->datum_types[i] == CHAIN_TYPE_TX){
                dap_chain_datum_iter_t *l_iter = l_chain->callback_datum_iter_create(l_chain);

                uint64_t l_datums = 0;
                uint64_t l_ts_last = (uint64_t)time(NULL);
                for (dap_chain_datum_t *l_datum = l_chain->callback_datum_iter_get_first(l_iter);
                        l_datum;
                        l_datum = l_chain->callback_datum_iter_get_next(l_iter)){
                    // Progress trace: a full pass over the history is the one
                    // startup/online step without any other visible progress,
                    // and it is the first thing to look at when a node reports
                    // the wallet index building for hours.
                    ++l_datums;
                    if (!(l_datums & 0x1FFFF)) {
                        uint64_t l_now = (uint64_t)time(NULL);
                        log_it(L_NOTICE, "Wallet cache pass over chain %s: %"DAP_UINT64_FORMAT_U
                               " datums scanned (+%"DAP_UINT64_FORMAT_U" s)",
                               l_chain->name, l_datums, l_now - l_ts_last);
                        l_ts_last = l_now;
                    }

                    if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX)
                        s_save_tx_cache_for_addr(l_chain, a_addr, (dap_chain_datum_tx_t*)l_datum->data, l_iter->cur_hash,l_iter->cur_atom_hash,
                                                 l_iter->ret_code, l_iter->token_ticker, l_iter->uid, l_iter->action, 'a');
                }
                l_chain->callback_datum_iter_delete(l_iter);
                break;
            }
        }
        l_chain=l_chain->next;
    }

    return 0;
}

static void s_callback_datum_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_hash_fast_t *a_atom_hash,
                                    const void *a_atom, size_t a_atom_size, void *a_datum, size_t a_datum_size, int a_ret_code,
                                    uint32_t a_action, dap_chain_net_srv_uid_t a_uid)
{
    (void) a_atom;
    (void) a_atom_size;
    dap_atom_notify_arg_t *l_arg = (dap_atom_notify_arg_t*)a_arg;
    if (!l_arg || !l_arg->chain || !l_arg->chain->callback_datum_find_by_hash || !a_datum_hash)
        return;
    dap_chain_datum_t *l_datum = l_arg->chain->callback_datum_find_by_hash(l_arg->chain, a_datum_hash, NULL, NULL);
    if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return;

    s_save_tx_cache_for_addr(l_arg->chain, NULL, (dap_chain_datum_tx_t*)l_datum->data, a_datum_hash, a_atom_hash, a_ret_code,
                             (char*)dap_ledger_tx_get_token_ticker_by_hash(l_arg->net->pub.ledger, a_datum_hash),
                             a_uid, a_action, 'a');
}

static void s_callback_datum_removed_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum)
{
    if (!a_datum_hash || !a_datum || a_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return;

    dap_atom_notify_arg_t *l_arg = (dap_atom_notify_arg_t*)a_arg;
    s_save_tx_cache_for_addr(l_arg->chain, NULL, (dap_chain_datum_tx_t*)a_datum->data, a_datum_hash, NULL, 0,
                             NULL, (dap_chain_net_srv_uid_t){ }, DAP_CHAIN_TX_TAG_ACTION_UNKNOWN, 'd');
}

// Addresses already present in the cache before a bulk pass started. The
// single pass reads every datum and checks every output against the known
// address set, so for any address that was already known the pass is a
// complete answer: no transactions found means the wallet is empty, not
// "not loaded yet". Only wallets created while the pass was running (their
// address may have appeared mid-pass, after the datum that touches it was
// processed) still need their own re-check pass.
static bool s_addr_list_has(const dap_list_t *a_list, const dap_chain_addr_t *a_addr)
{
    for (const dap_list_t *it = a_list; it; it = it->next)
        if (dap_chain_addr_compare((const dap_chain_addr_t *)it->data, a_addr))
            return true;
    return false;
}

static void *s_wallet_load_all_for_net(void *a_arg)
{
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    time_t l_ts_start = time(NULL);
    log_it(L_INFO, "Single-pass wallet cache build started for net %s", l_net->pub.name);

    for (;;) {
        // Pre-pass snapshot of the addresses the single pass will fully cover.
        dap_list_t *l_pre_addrs = NULL;
        pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
        dap_wallet_cache_t *l_pre_item;
        for (l_pre_item = s_wallets_cache; l_pre_item; l_pre_item = l_pre_item->hh.next) {
            if (l_pre_item->wallet_addr.net_id.uint64 != l_net->pub.id.uint64)
                continue;
            dap_chain_addr_t *l_addr = DAP_NEW(dap_chain_addr_t);
            if (l_addr) {
                *l_addr = l_pre_item->wallet_addr;
                l_pre_addrs = dap_list_append(l_pre_addrs, l_addr);
            }
        }
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);

        s_save_cache_for_addr_in_net(l_net, NULL);

        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        dap_wallet_cache_t *l_item, *l_tmp;
        HASH_ITER(hh, s_wallets_cache, l_item, l_tmp) {
            if (l_item->wallet_addr.net_id.uint64 != l_net->pub.id.uint64)
                continue;
            // Addresses that appeared while this pass ran keep is_loading: the
            // follow-up round below covers them with one more full pass - far
            // cheaper than a per-address chain walk, and no thread per address.
            if (l_item->wallet_txs || s_addr_list_has(l_pre_addrs, &l_item->wallet_addr))
                l_item->is_loading = false;
        }
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        dap_list_free_full(l_pre_addrs, NULL);

        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        s_bulk_done_nets_add(l_net->pub.id.uint64);
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);

        // Wallets opened while this pass ran: one more pass services their
        // marked addresses (an address is marked loading exactly until a pass
        // covers it, so the loop terminates).
        // Release the "bulk in progress" marker only when the pass truly ends,
        // and take the last round check under the same write lock: an address
        // opened concurrently either lands in this check (one more round) or
        // creates its own pass right after the marker is gone - is_warm() must
        // never report ready while a pass is still running.
        bool l_again = false;
        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        for (dap_wallet_cache_t *l_w = s_wallets_cache; l_w; l_w = l_w->hh.next) {
            if (l_w->wallet_addr.net_id.uint64 == l_net->pub.id.uint64 && l_w->is_loading) {
                l_again = true;
                break;
            }
        }
        if (!l_again)
            s_bulk_loading_nets_remove(l_net->pub.id.uint64);
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        if (!l_again)
            break;
        log_it(L_NOTICE, "Wallet cache build for net %s: addresses appeared while the pass ran, running another pass",
               l_net->pub.name);
    }

    log_it(L_INFO, "Single-pass wallet cache build for net %s completed in %llu sec",
           l_net->pub.name, (unsigned long long)(time(NULL) - l_ts_start));
    atomic_fetch_sub(&s_loading_threads_count, 1);
    return NULL;
}

// Coalesced catch-up: the address is already marked loading; start ONE pass
// over the chain that services every marked address (or let the pass that is
// already running pick it up). A detached full-history walker per opened
// wallet used to explode a many-wallet node into hundreds of competing
// threads and stare at /health 503 "bulk build in progress" for hours.
static void s_wallet_cache_request_pass(dap_chain_net_t *a_net)
{
    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
    bool l_start = !s_bulk_loading_nets_has(a_net->pub.id.uint64);
    if (l_start)
        s_bulk_loading_nets_add(a_net->pub.id.uint64);
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    if (!l_start)
        return;
    pthread_t l_tid;
    pthread_attr_t l_attr;
    pthread_attr_init(&l_attr);
    pthread_attr_setdetachstate(&l_attr, PTHREAD_CREATE_DETACHED);
    atomic_fetch_add(&s_loading_threads_count, 1);
    if (pthread_create(&l_tid, &l_attr, s_wallet_load_all_for_net, a_net)) {
        atomic_fetch_sub(&s_loading_threads_count, 1);
        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        s_bulk_loading_nets_remove(a_net->pub.id.uint64);
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        log_it(L_CRITICAL, "Can't start the wallet cache catch-up pass for net %s (pthread_create failed)",
               a_net->pub.name);
        return;
    }
    pthread_attr_destroy(&l_attr);
    log_it(L_INFO, "Wallet cache catch-up pass started for net %s (a wallet was opened after the bulk pass)",
           a_net->pub.name);
}

static void s_wallet_opened_callback(dap_chain_wallet_t *a_wallet, void *a_arg)
{

    for(dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net=dap_chain_net_iter_next(l_net)){
        if (dap_chain_net_get_load_mode(l_net))
            continue;
        // get wallet addr in current net
        dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(a_wallet, l_net->pub.id);
        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        dap_wallet_cache_t *l_wallet_item = NULL;
        HASH_FIND(hh, s_wallets_cache, l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
        if (l_wallet_item){
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            DAP_DELETE(l_addr);
            continue;
        }
        if (s_bulk_loading_nets_has(l_net->pub.id.uint64)) {
            l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
            memcpy(&l_wallet_item->wallet_addr, l_addr, sizeof(dap_chain_addr_t));
            l_wallet_item->is_loading = true;
            HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            DAP_DELETE(l_addr);
            continue;
        }

        l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
        memcpy (&l_wallet_item->wallet_addr, l_addr, sizeof(dap_chain_addr_t));
        l_wallet_item->is_loading = true;
        HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        DAP_DELETE(l_addr);

        s_wallet_cache_request_pass(l_net);
    }
}

static int s_out_idx_cmp(dap_list_t *a_l1, dap_list_t *a_l2) {
    dap_wallet_tx_cache_output_t *o1 = a_l1->data,
                                 *o2 = a_l2->data;
    return o1->tx_out_idx != o2->tx_out_idx;
}

static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx, 
                                    dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                    dap_chain_net_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action, char a_cache_op)
{
    int l_ret_val = 0, l_items_cnt = 0, l_out_idx = -1;
    bool l_multichannel = false;
    dap_list_t *l_reset_wallets = NULL;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    dap_ret_val_if_any(-EINVAL, !l_net || !l_net->pub.ledger);
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    // Borrowed-body lookups for the previous transactions of inputs: the bulk
    // pass walks the entire chain, and the pinned variant of the lookup would
    // materialize every block body it touches into the chain's cache for the
    // rest of the process's life (a 20 GB chain, an 8 GB box: OOM).
    dap_chain_block_cache_transient_t *l_prev_handle = NULL;
#define m_check_addr(addr) (                                                                                    \
    !dap_chain_addr_is_blank(&addr) && (                                                                        \
        a_addr ? dap_chain_addr_compare(&addr, a_addr) :                                                        \
        ( (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_LOCAL && dap_chain_wallet_addr_cache_get_name(&addr))  \
            || s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL ) )                                            \
    && addr.net_id.uint64 == a_chain->net_id.uint64                                                             \
)
    uint8_t *l_tx_item; size_t l_size;
    TX_ITEM_ITER_TX(l_tx_item, l_size, a_tx) {
        dap_hash_fast_t l_prev_tx_hash;
        dap_chain_addr_t l_addr;
        uint256_t l_value;
        uint8_t *l_prev_item = NULL;
        int l_prev_idx = 0;
        dap_chain_tx_item_type_t l_prev_out_type = (dap_chain_tx_item_type_t)0;
        dap_time_t l_prev_ts_unlock = 0;
        char l_prev_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = {0};

        switch(*l_tx_item) {
        case TX_ITEM_TYPE_IN: {
            l_prev_tx_hash = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_prev_hash;
            if ( dap_hash_fast_is_blank(&l_prev_tx_hash) )
                continue;
            l_prev_idx = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_out_prev_idx;
            dap_chain_datum_t *l_prev_datum = a_chain->callback_datum_peek_by_hash
                    ? a_chain->callback_datum_peek_by_hash(a_chain, &l_prev_tx_hash, &l_prev_handle)
                    : a_chain->callback_datum_find_by_hash(a_chain, &l_prev_tx_hash, NULL, NULL);
            dap_chain_datum_tx_t *l_tx_prev = l_prev_datum ? (dap_chain_datum_tx_t *)(l_prev_datum->data) : NULL;
            if (!l_tx_prev) {
                // The initial bulk pass walks the whole historical chain, where
                // old inputs routinely reference datums that are not resolvable
                // by this callback; this is not actionable at ERROR level.
                debug_if(s_debug_more, L_DEBUG, "Can't find previous transaction by hash \"%s\"",
                         dap_hash_fast_to_str_static(&l_prev_tx_hash));
                if (!a_ret_code) {
                    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
                    s_wallet_cache_drop_unspent_global_by_key(&l_prev_tx_hash, l_prev_idx);
                    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                }
                continue;
            }
            l_prev_item = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_prev_idx);
            if (!l_prev_item) {
                debug_if(s_debug_more, L_DEBUG, "Can't find output %d in tx \"%s\"", l_prev_idx, dap_hash_fast_to_str_static(&l_prev_tx_hash));
                if (!a_ret_code) {
                    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
                    s_wallet_cache_drop_unspent_global_by_key(&l_prev_tx_hash, l_prev_idx);
                    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                }
                continue;
            }
            switch (*l_prev_item) {
            case TX_ITEM_TYPE_OUT_OLD:
                l_value = GET_256_FROM_64(((dap_chain_tx_out_old_t*)l_prev_item)->header.value);
                l_addr = ((dap_chain_tx_out_old_t*)l_prev_item)->addr;
                l_prev_out_type = TX_ITEM_TYPE_OUT_OLD;
                l_prev_ts_unlock = 0;
                dap_strncpy(l_prev_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX - 1);
                break;
            case TX_ITEM_TYPE_OUT:
            case TX_ITEM_TYPE_OUT_EXT:
                l_value = ((dap_chain_tx_out_ext_t*)l_prev_item)->header.value;
                l_addr = ((dap_chain_tx_out_ext_t*)l_prev_item)->addr;
                l_prev_out_type = (dap_chain_tx_item_type_t)*l_prev_item;
                l_prev_ts_unlock = 0;
                if (*l_prev_item == TX_ITEM_TYPE_OUT_EXT)
                    dap_strncpy(l_prev_ticker, ((dap_chain_tx_out_ext_t*)l_prev_item)->token, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                else
                    dap_strncpy(l_prev_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX - 1);
                break;
            case TX_ITEM_TYPE_OUT_STD:
                l_value = ((dap_chain_tx_out_std_t *)l_prev_item)->value;
                l_addr = ((dap_chain_tx_out_std_t *)l_prev_item)->addr;
                l_prev_out_type = TX_ITEM_TYPE_OUT_STD;
                l_prev_ts_unlock = ((dap_chain_tx_out_std_t *)l_prev_item)->ts_unlock;
                dap_strncpy(l_prev_ticker, ((dap_chain_tx_out_std_t *)l_prev_item)->token, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                break;
            case TX_ITEM_TYPE_OUT_COND: {
                dap_chain_tx_out_cond_t *l_prev_cond = (dap_chain_tx_out_cond_t*)l_prev_item;
                l_value = l_prev_cond->header.value;
                l_prev_out_type = TX_ITEM_TYPE_OUT_COND;
                l_prev_ts_unlock = 0;
                const char *l_cond_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_prev_tx_hash);
                dap_strncpy(l_prev_ticker, l_cond_ticker ? l_cond_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX - 1);
                switch (l_prev_cond->header.subtype) {
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX:
                    l_addr = l_prev_cond->subtype.srv_dex.seller_addr;
                    break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE:
                    l_addr = l_prev_cond->subtype.srv_xchange.seller_addr;
                    break;
                default:
                    continue;
                }
            } break;
            default:
                continue;
            }
        } break;
        case TX_ITEM_TYPE_OUT_OLD:
            l_addr = ((dap_chain_tx_out_old_t*)l_tx_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT:
            l_addr = ((dap_chain_tx_out_t*)l_tx_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_addr = ((dap_chain_tx_out_ext_t*)l_tx_item)->addr;
            l_multichannel = true;
            break;
        case TX_ITEM_TYPE_OUT_STD:
            l_addr = ((dap_chain_tx_out_std_t *)l_tx_item)->addr;
            l_multichannel = true;
            break;
        case TX_ITEM_TYPE_OUT_COND:
            l_value = ((dap_chain_tx_out_cond_t*)l_tx_item)->header.value;
            switch (((dap_chain_tx_out_cond_t*)l_tx_item)->header.subtype) {
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX:
                l_addr = ((dap_chain_tx_out_cond_t*)l_tx_item)->subtype.srv_dex.seller_addr;
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE:
                l_addr = ((dap_chain_tx_out_cond_t*)l_tx_item)->subtype.srv_xchange.seller_addr;
                break;
            default:
                break;
            }
            ++l_out_idx;
        default:
            continue;
        }
        l_out_idx += (int)(*l_tx_item != TX_ITEM_TYPE_IN);
        
        if ( !m_check_addr(l_addr) )
            continue;

        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        dap_wallet_cache_t *l_wallet_item = NULL;
        dap_wallet_tx_cache_t *l_wallet_tx_item = NULL;
        HASH_FIND(hh, s_wallets_cache, &l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
        switch (a_cache_op) {
        case 'a':
            if (!l_wallet_item) {
                l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
                l_wallet_item->wallet_addr = l_addr;
                HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            } else
                HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);

            if (!l_wallet_tx_item) {
                l_wallet_tx_item = DAP_NEW(dap_wallet_tx_cache_t);
                *l_wallet_tx_item = (dap_wallet_tx_cache_t){ .tx_hash = *a_tx_hash, .atom_hash = *a_atom_hash, .chain = a_chain,
                    .multichannel = l_multichannel, .ret_code = a_ret_code, .srv_uid = a_srv_uid, .action = a_action };
                dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            } else {
                bool l_need_reset = true;
                for (dap_list_t *l_tmp = l_reset_wallets; l_tmp; l_tmp = l_tmp->next) {
                    if (l_tmp->data == l_wallet_item) {
                        l_need_reset = false;
                        break;
                    }
                }
                if (l_need_reset) {
                    s_wallet_cache_drop_unspent_by_tx_hash(l_wallet_item, a_tx_hash);
                    dap_list_free_full(l_wallet_tx_item->tx_wallet_inputs, NULL);
                    l_wallet_tx_item->tx_wallet_inputs = NULL;
                    dap_list_free_full(l_wallet_tx_item->tx_wallet_outputs, NULL);
                    l_wallet_tx_item->tx_wallet_outputs = NULL;
                    l_reset_wallets = dap_list_append(l_reset_wallets, l_wallet_item);
                }
                l_wallet_tx_item->chain = a_chain;
                if (a_atom_hash)
                    l_wallet_tx_item->atom_hash = *a_atom_hash;
                l_wallet_tx_item->multichannel |= l_multichannel;
                l_wallet_tx_item->ret_code = a_ret_code;
                l_wallet_tx_item->srv_uid = a_srv_uid;
                l_wallet_tx_item->action = a_action;
                if (a_main_token_ticker && *a_main_token_ticker)
                    dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
            }
            break;
        case 'd': {
            if (!l_wallet_item) {
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
                continue;
            }
            s_wallet_cache_drop_unspent_by_tx_hash(l_wallet_item, a_tx_hash);
            HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            if (l_wallet_tx_item){
                HASH_DEL(l_wallet_item->wallet_txs, l_wallet_tx_item);
                dap_list_free_full(l_wallet_tx_item->tx_wallet_inputs, NULL);
                dap_list_free_full(l_wallet_tx_item->tx_wallet_outputs, NULL);
                DAP_DELETE(l_wallet_tx_item);
            }
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            continue;
        }
        default:
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            continue;
        }

        switch (*l_tx_item) {
        case TX_ITEM_TYPE_IN:
            switch (a_cache_op) {
            case 'a': {
                dap_wallet_tx_cache_input_t *l_tx_in = DAP_NEW(dap_wallet_tx_cache_input_t);
                *l_tx_in = (dap_wallet_tx_cache_input_t) { .tx_prev_hash = l_prev_tx_hash, .tx_out_prev_idx = l_prev_idx, .value = l_value };
                l_wallet_tx_item->tx_wallet_inputs = dap_list_append(l_wallet_tx_item->tx_wallet_inputs, l_tx_in);
                unspent_cache_hh_key l_key = { .tx_hash = l_prev_tx_hash, .out_idx = l_prev_idx };
                if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_prev_tx_hash, l_prev_idx, NULL)) {
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    HASH_FIND(hh, l_wallet_item->unspent_outputs, &l_key, sizeof(unspent_cache_hh_key), l_item);
                    if (l_item) {
                        HASH_DEL(l_wallet_item->unspent_outputs, l_item);
                        DAP_DELETE(l_item);
                    }
                } else if (l_prev_out_type) {
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    HASH_FIND(hh, l_wallet_item->unspent_outputs, &l_key, sizeof(unspent_cache_hh_key), l_item);
                    if (!l_item) {
                        l_item = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
                        l_item->key = l_key;
                        l_item->value = l_value;
                        l_item->out_type = l_prev_out_type;
                        l_item->ts_unlock = l_prev_ts_unlock;
                        dap_strncpy(l_item->token_ticker, l_prev_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                        HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_item);
                    }
                }
            } break;
            default:
                break;
            }
            break;
        default:
            switch (a_cache_op) {
            case 'a': {
                dap_wallet_tx_cache_output_t l_sought_out = { .tx_out_idx = l_out_idx };
                dap_list_t *l_out_item = dap_list_find(l_wallet_tx_item->tx_wallet_outputs, &l_sought_out, s_out_idx_cmp);
                if ( !l_out_item ) {
                    dap_wallet_tx_cache_output_t *l_out = DAP_NEW(dap_wallet_tx_cache_output_t);
                    *l_out = (dap_wallet_tx_cache_output_t){ .tx_out_idx = l_out_idx };
                    l_wallet_tx_item->tx_wallet_outputs = dap_list_append(l_wallet_tx_item->tx_wallet_outputs, l_out);
                }
                // ALREADY_CACHED is a restored-from-the-ledger-cache transaction: it IS in
                // the ledger, so for a wallet that was not cached before (new address, or the
                // persistent cache was lost) its unspent output must be collected here -
                // otherwise the bulk pass silently skips every transaction the chain scan
                // restored from the cache and the address balance comes up short.
                if ((!a_ret_code || a_ret_code == DAP_LEDGER_CHECK_ALREADY_CACHED)
                        && !dap_ledger_tx_hash_is_used_out_item(l_ledger, a_tx_hash, l_out_idx, NULL)) {
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    unspent_cache_hh_key l_key = { .tx_hash = *a_tx_hash, .out_idx = l_out_idx };
                    HASH_FIND(hh, l_wallet_item->unspent_outputs, &l_key, sizeof(unspent_cache_hh_key), l_item);
                    if ( !l_item ) {
                        uint256_t l_out_value = { };
                        dap_time_t l_out_ts_unlock = 0;
                        const char *l_out_ticker = NULL;
                        switch (*l_tx_item) {
                        case TX_ITEM_TYPE_OUT_OLD:
                            l_out_value = GET_256_FROM_64(((dap_chain_tx_out_old_t*)l_tx_item)->header.value);
                            l_out_ticker = a_main_token_ticker;
                            break;
                        case TX_ITEM_TYPE_OUT:
                            l_out_value = ((dap_chain_tx_out_t*)l_tx_item)->header.value;
                            l_out_ticker = a_main_token_ticker;
                            break;
                        case TX_ITEM_TYPE_OUT_EXT:
                            l_out_value = ((dap_chain_tx_out_ext_t*)l_tx_item)->header.value;
                            l_out_ticker = ((dap_chain_tx_out_ext_t*)l_tx_item)->token;
                            break;
                        case TX_ITEM_TYPE_OUT_STD:
                            l_out_value = ((dap_chain_tx_out_std_t*)l_tx_item)->value;
                            l_out_ts_unlock = ((dap_chain_tx_out_std_t*)l_tx_item)->ts_unlock;
                            l_out_ticker = ((dap_chain_tx_out_std_t*)l_tx_item)->token;
                            break;
                        default:
                            break;
                        }
                        if (l_out_ticker) {
                            l_item = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
                            l_item->key = l_key;
                            l_item->value = l_out_value;
                            l_item->out_type = (dap_chain_tx_item_type_t)*l_tx_item;
                            l_item->ts_unlock = l_out_ts_unlock;
                            dap_strncpy(l_item->token_ticker, l_out_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                            HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_item);
                        }
                    }
                }
            } break;
            case 'd': {           
                unspent_cache_hh_key key = { .tx_hash = *a_tx_hash, .out_idx = l_out_idx };
                dap_wallet_cache_unspent_outs_t *l_item = NULL;
                HASH_FIND(hh, l_wallet_item->unspent_outputs, &key, sizeof(unspent_cache_hh_key), l_item);
                if (l_item) {
                    HASH_DEL(l_wallet_item->unspent_outputs, l_item);
                    DAP_DELETE(l_item);
                }
                if ( !l_wallet_item->wallet_txs ) {
                    HASH_DEL(s_wallets_cache, l_wallet_item);
                    DAP_DELETE(l_wallet_item);
                } 
            } break;
            default:
                break;
            }
            break;
        }
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    }
    dap_list_free(l_reset_wallets);
    // Release the last borrowed body (see the peek handle above).
    if (l_prev_handle && a_chain->callback_datum_peek_free)
        a_chain->callback_datum_peek_free(a_chain, &l_prev_handle);
    return l_ret_val;
}

static void s_wallet_cache_iter_fill(dap_chain_wallet_cache_iter_t *a_cache_iter, dap_wallet_tx_cache_t *a_cache_index)
{
    a_cache_iter->cur_item = (void*)a_cache_index;
    if (a_cache_index) {
        dap_chain_datum_t *l_datum = a_cache_index->chain
            ? a_cache_index->chain->callback_datum_find_by_hash(
                  a_cache_index->chain, &a_cache_index->tx_hash, NULL, NULL)
            : NULL;
        a_cache_iter->cur_tx = l_datum ? (dap_chain_datum_tx_t *)l_datum->data : NULL;
        // Copies, not pointers into the cache: the entry may be cleared while
        // the caller still reads the values from the iterator.
        a_cache_iter->cur_item_hash = a_cache_index->tx_hash;
        a_cache_iter->cur_hash_copy = a_cache_index->tx_hash;
        a_cache_iter->cur_atom_hash_copy = a_cache_index->atom_hash;
        a_cache_iter->cur_hash = &a_cache_iter->cur_hash_copy;
        a_cache_iter->cur_atom_hash = &a_cache_iter->cur_atom_hash_copy;
        dap_strncpy(a_cache_iter->token_ticker_copy, a_cache_index->token_ticker,
                    sizeof(a_cache_iter->token_ticker_copy));
        a_cache_iter->token_ticker = dap_strcmp(a_cache_iter->token_ticker_copy, "0")
                ? a_cache_iter->token_ticker_copy : NULL;
        a_cache_iter->ret_code = a_cache_index->ret_code;
        a_cache_iter->action = a_cache_index->action;
        a_cache_iter->uid = a_cache_index->srv_uid;
        a_cache_iter->has_cur_item = true;
    } else {
        a_cache_iter->cur_tx = NULL;
        a_cache_iter->cur_hash = NULL;
        a_cache_iter->cur_atom_hash = NULL;
        a_cache_iter->ret_code = 0;
        a_cache_iter->token_ticker = NULL;
        a_cache_iter->action = 0;
        a_cache_iter->uid.uint64 = 0;
        a_cache_iter->has_cur_item = false;
    }
}

// The wallet entry is looked up again on every step (under the cache lock): an
// iterator must never dereference a pointer that may have been cleared since the
// previous call.
static dap_wallet_cache_t *s_wallet_cache_iter_wallet_locked(const dap_chain_wallet_cache_iter_t *a_iter)
{
    dap_wallet_cache_t *l_item = NULL;
    HASH_FIND(hh, s_wallets_cache, &a_iter->addr, sizeof(a_iter->addr), l_item);
    return l_item;
}


dap_chain_wallet_cache_iter_t *dap_chain_wallet_cache_iter_create(dap_chain_addr_t a_addr)
{
    dap_chain_wallet_cache_iter_t *l_iter = NULL;

    // Read-only lookup (HASH_FIND, no mutation of s_wallets_cache/wallet_txs) - a plain
    // rdlock is enough here (P.14); the previous wrlock needlessly serialized every
    // concurrent iterator creation/history read against every other reader.
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    dap_wallet_cache_t *l_wallet_item = NULL, *l_tmp;
    HASH_FIND(hh, s_wallets_cache, &a_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    if (!l_wallet_item || !l_wallet_item->wallet_txs){
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return l_iter;
    }

    l_iter = DAP_NEW_Z(dap_chain_wallet_cache_iter_t);
    if(!l_iter){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return NULL;
    }
    l_iter->addr = a_addr;
    l_iter->cur_item = l_wallet_item->wallet_txs;
    l_iter->cur_addr_cache = l_wallet_item;
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    return l_iter;
}

void dap_chain_wallet_cache_iter_delete(dap_chain_wallet_cache_iter_t *a_iter)
{
    DAP_DELETE(a_iter);
}

dap_chain_datum_tx_t *dap_chain_wallet_cache_iter_get(dap_chain_wallet_cache_iter_t *a_iter, dap_chain_wallet_getting_type_t a_type)
{
    if (!a_iter)
        return NULL;
        
    // All four cases below only read cur_addr_cache/wallet_txs (HASH lookup or hh.next/prev
    // traversal) into the iterator - no mutation of s_wallets_cache/wallet_txs happens here,
    // so a rdlock is sufficient (P.14: was wrlock, serializing every concurrent history read
    // against every other reader for no reason).
    switch (a_type){
        case DAP_CHAIN_WALLET_CACHE_GET_FIRST:{
            pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_cache = s_wallet_cache_iter_wallet_locked(a_iter);
            s_wallet_cache_iter_fill(a_iter, l_wallet_cache ? l_wallet_cache->wallet_txs : NULL);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        case DAP_CHAIN_WALLET_CACHE_GET_LAST:{
            pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_cache = s_wallet_cache_iter_wallet_locked(a_iter);
            dap_wallet_tx_cache_t *l_tx_cache = NULL;
            if (l_wallet_cache)
                l_tx_cache = HASH_LAST(l_wallet_cache->wallet_txs);
            s_wallet_cache_iter_fill(a_iter, l_tx_cache);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        case DAP_CHAIN_WALLET_CACHE_GET_NEXT:{
            pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_cache = s_wallet_cache_iter_wallet_locked(a_iter);
            dap_wallet_tx_cache_t *l_tx_cache = NULL, *l_cur = NULL;
            if (l_wallet_cache && a_iter->has_cur_item) {
                HASH_FIND(hh, l_wallet_cache->wallet_txs, &a_iter->cur_item_hash,
                          sizeof(a_iter->cur_item_hash), l_cur);
                l_tx_cache = l_cur ? l_cur->hh.next : NULL;
            } else if (l_wallet_cache) {
                l_tx_cache = l_wallet_cache->wallet_txs;
            }
            s_wallet_cache_iter_fill(a_iter, l_tx_cache);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        case DAP_CHAIN_WALLET_CACHE_GET_PREVIOUS:{
            pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_cache = s_wallet_cache_iter_wallet_locked(a_iter);
            dap_wallet_tx_cache_t *l_tx_cache = NULL, *l_cur = NULL;
            if (l_wallet_cache && a_iter->has_cur_item) {
                HASH_FIND(hh, l_wallet_cache->wallet_txs, &a_iter->cur_item_hash,
                          sizeof(a_iter->cur_item_hash), l_cur);
                l_tx_cache = l_cur ? l_cur->hh.prev : NULL;
            }
            s_wallet_cache_iter_fill(a_iter, l_tx_cache);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        default:
            break;
    }

    return a_iter->cur_tx;
}

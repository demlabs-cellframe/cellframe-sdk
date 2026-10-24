/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
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

#include <dirent.h>
#include <stdbool.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <glob.h>
#endif

#include "uthash.h"
#include "utlist.h"

#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_events.h"
#include "dap_math_ops.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_enc_base58.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_cert.h"
#include "dap_timerfd.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_in_ems.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_datum_token.h"
#include "dap_global_db.h"
#include "dap_global_db_driver.h"

// Storage-capacity latch passthrough: while GlobalDB is over its hard limit
// (MDBX_MAP_FULL) the cache writes can't succeed - skip the serialization work
// entirely instead of feeding a doomed write path on every chain event.
static inline bool s_ledger_cache_storage_full(void)
{
    return dap_global_db_driver_storage_full();
}

#include "dap_chain_ledger.h"
#include "dap_rpc_cache.h"
#include "dap_chain_ledger_snapshot.h"
#include "dap_chain_state_cache.h"
#include "dap_crc64.h"
#include "dap_chain.h"
#include "dap_chain_cs_blocks.h"
#include "json.h"
#include "json_object.h"
#include "dap_notify_srv.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_policy.h"
#include "dap_chain_wallet_shared.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_datum_tx_event.h"
#include "dap_chain_mempool.h"
#include "dap_chain_datum_tx.h"
#include "dap_common.h"
#include "dap_cli_server.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_common.h"
#include "dap_math_convert.h"
#include "dap_chain_arbitrage.h"
#include "dap_chain_ledger_utxo.h"

#define LOG_TAG "dap_ledger"

typedef struct dap_ledger_verificator {
    int subtype;    // hash key
    dap_ledger_verificator_callback_t callback;
    dap_ledger_updater_callback_t callback_added;
    dap_ledger_delete_callback_t callback_deleted;
    UT_hash_handle hh;
} dap_ledger_verificator_t;

typedef struct dap_chain_ledger_votings_callbacks {
    dap_chain_ledger_voting_callback_t voting_callback;
    dap_chain_ledger_voting_delete_callback_t voting_delete_callback;
} dap_chain_ledger_votings_callbacks_t;

typedef struct dap_ledger_service_info {
    dap_chain_net_srv_uid_t service_uid;    // hash key
    char tag_str[32];   // tag string name
    dap_ledger_tag_check_callback_t callback; //callback for check if a tx for particular service
    dap_ledger_srv_tx_to_json_callback_t tx_to_json; // service-specific TX-to-JSON formatter
    UT_hash_handle hh;
} dap_ledger_service_info_t;

static dap_ledger_verificator_t *s_verificators;
static dap_ledger_service_info_t *s_services;

static  pthread_rwlock_t s_verificators_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static  pthread_rwlock_t s_services_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static dap_chain_ledger_votings_callbacks_t s_voting_callbacks;

// Structures now defined in dap_chain_ledger_item.h

// Local structures for internal implementation only
typedef struct dap_ledger_event {
    dap_chain_net_srv_uid_t srv_uid;
    dap_time_t timestamp;
    dap_hash_fast_t tx_hash;
    dap_hash_fast_t pkey_hash;
    char *group_name;
    uint16_t event_type;
    void *event_data;
    size_t event_data_size;
    UT_hash_handle hh;
} dap_ledger_event_t;

typedef struct dap_ledger_event_notifier {
    dap_ledger_event_notify_t callback;
    void *arg;
} dap_ledger_event_notifier_t;

// ============================================================================
// UTXO BLOCKLIST INTERNAL API DECLARATIONS
// ============================================================================
// UTXO blocklist functions moved to dap_chain_ledger_utxo.c module

typedef struct dap_ledger_event_pkey_item {
    dap_hash_fast_t pkey_hash;
    UT_hash_handle hh;
} dap_ledger_event_pkey_item_t;

struct srv_callback_decree_item_t {
    uint64_t srv_uid;
    dap_ledger_srv_callback_decree_t callback;
    UT_hash_handle hh;
};

struct srv_callback_event_verify_item_t {
    uint64_t srv_uid;
    dap_ledger_srv_callback_event_verify_t callback;
    UT_hash_handle hh;
};
// dap_ledger_t private section
typedef struct dap_ledger_private {
    // separate access to transactions
    pthread_rwlock_t ledger_rwlock;
    dap_ledger_tx_item_t *ledger_items;
    // separate access to tokens
    pthread_rwlock_t tokens_rwlock;
    dap_ledger_token_item_t *tokens;
    // separate acces to stake items
    pthread_rwlock_t stake_lock_rwlock;
    dap_ledger_stake_lock_item_t *emissions_for_stake_lock;
    // separate access to rewards
    pthread_rwlock_t rewards_rwlock;
    dap_ledger_reward_item_t *rewards;
    // separate access to balances
    pthread_rwlock_t balance_accounts_rwlock;
    dap_ledger_wallet_balance_t *balance_accounts;
    // separate access to events
    pthread_rwlock_t events_rwlock;
    dap_ledger_event_t *events;
    // separate access to threshold
    dap_ledger_tx_item_t *threshold_txs;
    pthread_rwlock_t threshold_txs_rwlock;
    dap_interval_timer_t threshold_txs_free_timer;
    // Timed-locked outs support
    dap_ledger_locked_out_t *locked_outs;
    dap_ledger_locked_out_t *reverse_list;
    dap_time_t blockchain_time;
    dap_time_t cutoff_time;
    pthread_rwlock_t locked_outs_rwlock;
    // Save/load operations condition. load_end is the GlobalDB cache-stage
    // completion flag (see dap_ledger_load_cache); load_end_done marks that the
    // net-load finalization (dap_ledger_load_end) already ran for this ledger.
    // They are different events: the GDB stage chain completes before the chains
    // are walked, so sharing one flag would make the finalization a no-op.
    pthread_mutex_t load_mutex;
    pthread_cond_t load_cond;
    bool load_end;
    bool load_end_done;
    // Ledger flags
    bool check_ds, check_cells_ds, check_token_emission, cached, mapped, threshold_enabled;
    dap_chain_cell_id_t local_cell_id;
    //notifiers
    dap_list_t *bridged_tx_notifiers;
    dap_list_t *tx_add_notifiers;
    dap_list_t *event_notifiers;
    dap_ledger_cache_tx_check_callback_t cache_tx_check_callback;
    // White- and blacklist
    dap_ledger_hal_item_t *hal_items, *hrl_items;
    // Event allowed public keys
    pthread_rwlock_t event_pkeys_rwlock;
    dap_ledger_event_pkey_item_t *event_pkeys_allowed;
    // Service callbacks
    pthread_rwlock_t srv_callbacks_rwlock;
    struct srv_callback_decree_item_t *srv_callbacks_decree;
    struct srv_callback_event_verify_item_t *srv_callbacks_event_verify;
    // Snapshot cache ([ledger] snapshot_cache): periodic flat-file dumps of the
    // ledger state replace the GlobalDB txs/balances cache groups entirely
    bool snapshot_mode;
    dap_interval_timer_t snapshot_save_timer;
    uint32_t snapshot_interval_sec;
    // Chain-scan skip: a restored snapshot anchored at block N makes blocks
    // 1..N free for the ledger (their transactions are in the snapshot)
    bool snapshot_skip_active;
    uint64_t snapshot_skip_num;
    dap_chain_hash_fast_t snapshot_skip_hash;
    // Full ledger snapshot (header flag bit2): the file carries the "ledger_state"
    // section with tokens/emissions/stake locks/rewards/events/locked-outs.
    // snapshot_full is set only after that section restored successfully; with
    // snapshot_full_apply ([ledger] snapshot_full_apply) the service replay of
    // restored transactions is suppressed because those sections are authoritative.
    bool snapshot_full;
    bool snapshot_full_apply;
} dap_ledger_private_t;

#define PVT(a) ( (dap_ledger_private_t *) a->_internal )

static void s_threshold_emissions_proc( dap_ledger_t * a_ledger);
static void s_threshold_txs_proc( dap_ledger_t * a_ledger);
static void s_threshold_txs_free(dap_ledger_t *a_ledger);
static int s_sort_ledger_tx_item(dap_ledger_tx_item_t* a, dap_ledger_tx_item_t* b);
// Defined next to the ledger cache maintenance code; the snapshot section
// restore (further down) rebuilds the same ordered list.
static int s_compare_locked_outs(dap_ledger_locked_out_t *a_out1, dap_ledger_locked_out_t *a_out2);
// Ledger-state snapshot section (v3): dump/load are registered in dap_ledger_init().
static int s_snapshot_ledger_state_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out);
static int s_snapshot_ledger_state_load(void *a_ctx, const uint8_t *a_data, size_t a_size);
// Service GlobalDB groups carried by the snapshot (services register providers).
static int s_snapshot_service_groups_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out);
static int s_snapshot_service_groups_load(void *a_ctx, const uint8_t *a_data, size_t a_size);
// Node-local service state (dap_local_state): not replicated, no GDB limits.
static int s_snapshot_local_state_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out);
static int s_snapshot_local_state_load(void *a_ctx, const uint8_t *a_data, size_t a_size);
// Atom links for non-TX datums (emissions): completes the chain datum index
// without a scan.
static int s_snapshot_decrees_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out);
static int s_snapshot_decrees_load(void *a_ctx, const uint8_t *a_data, size_t a_size);
static int s_snapshot_datum_links_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out);
static int s_snapshot_datum_links_load(void *a_ctx, const uint8_t *a_data, size_t a_size);
static bool s_snapshot_append(dap_string_t *a_out, const void *a_data, size_t a_size);
// Cache writers used when a restored record was missing from GlobalDB.
static void s_ledger_emission_cache_update(dap_ledger_t *a_ledger, dap_ledger_token_emission_item_t *a_emission_item);
void s_ledger_stake_lock_cache_update(dap_ledger_t *a_ledger, dap_ledger_stake_lock_item_t *a_stake_lock_item);

// Arbitrage transaction helpers are now in dap_chain_arbitrage.c module

static size_t s_threshold_emissions_max = 1000;
static size_t s_threshold_txs_max = 10000;
static bool s_debug_more = true;

// Short-TTL cache for dap_ledger_count_from_to(): 'net get stats' polls the
// same (from,to) windows over and over, and every miss was a full
// (hundreds of thousands of items) ledger walk under ledger_rwlock rdlock.
// Direct-mapped, 5 second TTL - a stats counter being up to 5s stale is fine,
// holding the ledger read lock for a full scan per poll was not.
#define DAP_LEDGER_STATS_CACHE_SLOTS 16
#define DAP_LEDGER_STATS_CACHE_TTL_NS (5ull * 1000ull * 1000ull * 1000ull)
typedef struct {
    const void *ledger;
    dap_nanotime_t ts_from, ts_to, ts_cached;
    uint64_t count;
} s_stats_cache_entry_t;
static s_stats_cache_entry_t s_stats_cache[DAP_LEDGER_STATS_CACHE_SLOTS];
static pthread_mutex_t s_stats_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static size_t s_threshold_free_timer_tick = 900000; // 900000 ms = 15 minutes.

struct json_object *wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t* a_bal);
int dap_ledger_pvt_balance_update_for_addr(dap_ledger_t *a_ledger, dap_chain_addr_t *a_addr, const char *a_token_ticker, uint256_t a_value, bool a_reverse);

static int s_ledger_event_verify_add(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, dap_chain_datum_tx_t *a_tx, bool a_apply, bool a_check_for_apply);
static int s_ledger_event_remove(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash);

//add a service declaration for tx tagging and more
static bool s_tag_check_block_reward(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    //reward tag
    if (a_items_grp->items_in_reward)
    {
        if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR;
        return true;
    }
    return false;
}

static bool s_tag_check_event(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    //event tag
    if (!a_items_grp->items_event)
        return false;

    if (a_action)
        *a_action = DAP_CHAIN_TX_TAG_ACTION_EVENT;
    return true;
}
dap_chain_tx_out_cond_t* dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(dap_ledger_t *a_ledger, dap_chain_tx_in_cond_t *a_in_cond)
{
        dap_hash_fast_t *l_tx_prev_hash = &a_in_cond->header.tx_prev_hash;    
        uint32_t l_tx_prev_out_idx = a_in_cond->header.tx_out_prev_idx;
        dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash (a_ledger,l_tx_prev_hash);
        
        if (!l_tx_prev) return NULL;
        byte_t* l_item_res = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
        if (!l_item_res) {
            log_it(L_WARNING, "IN_COND references missing OUT idx %u in tx %s",
                   l_tx_prev_out_idx, dap_chain_hash_fast_to_str_static(l_tx_prev_hash));
            return NULL;
        }
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_item_res;
        
        if (l_type != TX_ITEM_TYPE_OUT_COND) return NULL;

        
        return (dap_chain_tx_out_cond_t*)l_item_res;
}

static dap_chain_addr_t s_get_out_addr(byte_t *out_item)
{
    dap_chain_tx_item_type_t l_type = *(uint8_t *)out_item;
    
    switch (l_type) {
        case TX_ITEM_TYPE_OUT: { 
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)out_item;
            return l_tx_out->addr;
        } break;
        case TX_ITEM_TYPE_OUT_EXT: { // 256
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)out_item;
            return l_tx_out->addr;
        } break;
        case TX_ITEM_TYPE_OUT_STD: { // 256
            dap_chain_tx_out_std_t *l_tx_out = (dap_chain_tx_out_std_t *)out_item;
            return l_tx_out->addr;
        } break;
    }

    dap_chain_addr_t l_tx_out_to={0};
    return l_tx_out_to;
}

static bool s_tag_check_transfer(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    //crosschain transfer
    //regular transfer
    //comission transfer

    // fee transfer: in_cond item linked to out_cond_fee
    if (a_items_grp->items_in_cond) 
    {
       for (dap_list_t *it = a_items_grp->items_in_cond; it; it = it->next) {
            dap_chain_tx_in_cond_t *l_tx_in = it->data;
            dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(a_ledger, l_tx_in);

            if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_TRANSFER_COMISSION;
                return true;
            }   
        }
    }

    //crosschain transfer: outs destination net-id differs from current net-id
    // to differ with wrong stakes -> no ems in required

    if (!a_items_grp->items_in_ems)
    {
        for (dap_list_t *it =  a_items_grp->items_out_all; it; it = it->next) {
            
            dap_chain_addr_t l_tx_out_to = s_get_out_addr(it->data);
        
            //tag cross-chain _outputs_ transactions (recepient-tx is emission-based)
            if (l_tx_out_to.net_id.uint64 != a_ledger->net->pub.id.uint64 && !dap_chain_addr_is_blank(&l_tx_out_to)) {
                if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_TRANSFER_CROSSCHAIN;
                return true;
            }
        }   
    }

    //regular transfers 
    //have no other ins except regular in
    //have no OUT_COND except fee
    //have no vote
    //no TSD!

    //have any of those -> not regular transfer
    if (a_items_grp->items_in_cond ||
        a_items_grp->items_in_ems ||
        a_items_grp->items_in_reward ) {
        return false;   
    }
    
    //have any of those -> not regular transfer
    if ( 
        a_items_grp->items_out_cond_srv_pay ||
        a_items_grp->items_out_cond_srv_stake_lock ||
        a_items_grp->items_out_cond_srv_stake_pos_delegate ||
        a_items_grp->items_out_cond_srv_xchange) 
    {
        return false;
    }
    
    //not voting or vote...
    if (a_items_grp->items_vote || a_items_grp->items_voting || dap_list_length(a_items_grp->items_tsd) > 1 || 
        (a_items_grp->items_tsd && !dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT)))
        return false;

    //not tsd sects (staking!) or only batching tsd
    if(a_action) {
        *a_action = DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR;
    }
    return true;
}
int dap_ledger_service_add(dap_chain_net_srv_uid_t a_uid, char *tag_str, dap_ledger_tag_check_callback_t a_callback)
{
    
    dap_ledger_service_info_t *l_new_sinfo = NULL;
    
    int l_tmp = a_uid.raw_ui64;

    pthread_rwlock_rdlock(&s_services_rwlock);
    HASH_FIND_INT(s_services, &l_tmp, l_new_sinfo);
    pthread_rwlock_unlock(&s_services_rwlock);
    if (l_new_sinfo) {
        l_new_sinfo->callback = a_callback;
        return 1;
    }

    l_new_sinfo = DAP_NEW_Z(dap_ledger_service_info_t);
    if (!l_new_sinfo) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    l_new_sinfo->service_uid = a_uid;
    l_new_sinfo->callback = a_callback;
    strncpy(l_new_sinfo->tag_str, tag_str, sizeof(l_new_sinfo->tag_str) - 1);
    
    pthread_rwlock_wrlock(&s_services_rwlock);
    HASH_ADD_INT(s_services, service_uid.raw_ui64, l_new_sinfo);
    pthread_rwlock_unlock(&s_services_rwlock);

    log_it(L_NOTICE, "Successfully registered service tag %s with uid %02" DAP_UINT64_FORMAT_X, tag_str, a_uid.raw_ui64);

    return 0;
}

int dap_ledger_service_tx_to_json_set(dap_chain_net_srv_uid_t a_uid, dap_ledger_srv_tx_to_json_callback_t a_callback)
{
    int l_tmp = a_uid.raw_ui64;
    dap_ledger_service_info_t *l_sinfo = NULL;
    pthread_rwlock_rdlock(&s_services_rwlock);
    HASH_FIND_INT(s_services, &l_tmp, l_sinfo);
    pthread_rwlock_unlock(&s_services_rwlock);
    if (!l_sinfo)
        return -1;
    l_sinfo->tx_to_json = a_callback;
    return 0;
}

struct json_object *dap_ledger_service_tx_to_json(dap_chain_net_srv_uid_t a_uid, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                                   dap_hash_fast_t *a_tx_hash, const dap_chain_addr_t *a_addr, const char *a_hash_out_type)
{
    int l_tmp = a_uid.raw_ui64;
    dap_ledger_service_info_t *l_sinfo = NULL;
    pthread_rwlock_rdlock(&s_services_rwlock);
    HASH_FIND_INT(s_services, &l_tmp, l_sinfo);
    dap_ledger_srv_tx_to_json_callback_t l_cb = l_sinfo ? l_sinfo->tx_to_json : NULL;
    pthread_rwlock_unlock(&s_services_rwlock);
    return l_cb ? l_cb(a_ledger, a_tx, a_tx_hash, a_addr, a_hash_out_type) : NULL;
}

/**
 * @brief dap_ledger_init
 * current function version set s_debug_more parameter, if it define in config, and returns 0
 * @return
 */
int dap_ledger_init()
{
    s_debug_more = dap_config_get_item_bool_default(g_config,"ledger","debug_more",false);
    
    //register native ledger services
    dap_chain_net_srv_uid_t l_uid_transfer = { .uint64 = DAP_CHAIN_NET_SRV_TRANSFER_ID };
    dap_ledger_service_add(l_uid_transfer, "transfer", s_tag_check_transfer);

    dap_chain_net_srv_uid_t l_uid_breward = { .uint64 = DAP_CHAIN_NET_SRV_BLOCK_REWARD_ID };
    dap_ledger_service_add(l_uid_breward, "block_reward", s_tag_check_block_reward);

    dap_chain_net_srv_uid_t l_uid_event = { .uint64 = DAP_CHAIN_NET_SRV_EVENT_ID };
    dap_ledger_service_add(l_uid_event, "event", s_tag_check_event);

    // The ledger's own snapshot section: everything the restored transaction
    // cache and balances do not carry (tokens/emissions/stake locks/rewards/
    // events/locked-outs). Idempotent by name, so a second init is harmless.
    dap_ledger_add_snapshot_section(DAP_LEDGER_SNAPSHOT_LEDGER_STATE_SECTION,
            DAP_LEDGER_SNAPSHOT_SECTION_FLAG_FULL,
            s_snapshot_ledger_state_dump, s_snapshot_ledger_state_load, NULL);
    // Service registries: the snapshot is their durable source, not the GDB.
    dap_ledger_add_snapshot_section("service_groups", 0,
            s_snapshot_service_groups_dump, s_snapshot_service_groups_load, NULL);
    // Node-local service state (order books, journals, shared-wallet state).
    dap_ledger_add_snapshot_section("local_state", 0,
            s_snapshot_local_state_dump, s_snapshot_local_state_load, NULL);
    // Atom links for non-TX datums: the TX part comes from the tx records.
    dap_ledger_add_snapshot_section("datum_links", 0,
            s_snapshot_datum_links_dump, s_snapshot_datum_links_load, NULL);
    // Approval-state registries of the decree system (active grants, explicit
    // deactivations, last approved number, operator exceptions): a decree replay
    // produces them only as its final step, so the state itself is persisted.
    dap_ledger_add_snapshot_section("decrees", 0,
            s_snapshot_decrees_dump, s_snapshot_decrees_load, NULL);

    return 0;
}

/**
 * @brief dap_ledger_deinit
 * nothing do
 */
void dap_ledger_deinit()
{
}

/**
 * @brief dap_ledger_handle_new
 * Create empty dap_ledger_t structure
 * @return dap_ledger_t*
 */
static dap_ledger_t *dap_ledger_handle_new(void)
{
    dap_ledger_t *l_ledger = DAP_NEW_Z(dap_ledger_t);
    if ( !l_ledger ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    dap_ledger_private_t * l_ledger_pvt;
    l_ledger->_internal = l_ledger_pvt = DAP_NEW_Z(dap_ledger_private_t);
    if ( !l_ledger_pvt ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_ledger);
        return NULL;
    }
    // Initialize Read/Write Lock Attribute
    // B4 (reverted): switching this lock to PTHREAD_RWLOCK_PREFER_WRITER_
    // NONRECURSIVE_NP caused a full node hang during chain sync (observed:
    // stuck for 1.5h+ at a fixed backbone load percentage on a fresh node).
    // Root cause: several read paths recursively take ledger_rwlock rdlock
    // from the same thread while already holding it - e.g.
    // dap_ledger_get_list_tx_outs_unspent_by_addr() holds rdlock over its
    // HASH_ITER and, for OUT/OUT_OLD items, called
    // dap_ledger_tx_get_token_ticker_by_hash() (a second, independent
    // rdlock), and for OUT_COND items resolves the chain root via
    // dap_ledger_get_first_chain_tx_hash()/dap_ledger_tx_find_by_hash()
    // (another rdlock). Under the default reader-preferring glibc policy a
    // recursive rdlock from the same thread is harmless (readers never
    // block behind a pending writer). Under PREFER_WRITER_NONRECURSIVE,
    // once a concurrent writer (e.g. dap_ledger_tx_add() adding a new tx
    // from sync) is queued waiting for the lock, ALL subsequent rdlock
    // attempts block behind it - including that same thread's own nested
    // rdlock call several frames deeper. The scanning thread can then never
    // release the outer rdlock the writer is waiting on: permanent
    // self-deadlock between one thread's own nested lock acquisition and a
    // concurrent writer. This is not a narrow, easily-audited set of call
    // sites (multiple functions across this file take the lock and call
    // other lock-taking helpers), so revert to the default (reader-
    // preferring) policy rather than try to eliminate every recursive
    // rdlock site under time pressure. The cache_data-mutation locking fix
    // from B4 (broadened wrlock further down in dap_ledger_tx_add()) is
    // independent of the lock's fairness policy and is kept as-is.
    pthread_rwlock_init(&l_ledger_pvt->ledger_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->tokens_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->threshold_txs_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->balance_accounts_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->stake_lock_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->rewards_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->events_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->locked_outs_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->event_pkeys_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->srv_callbacks_rwlock, NULL);
    pthread_mutex_init(&l_ledger_pvt->load_mutex, NULL);
    pthread_cond_init(&l_ledger_pvt->load_cond, NULL);
    return l_ledger;
}

/**
 * @brief dap_ledger_handle_free
 * Remove dap_ledger_t structure
 * @param a_ledger
 */
void dap_ledger_handle_free(dap_ledger_t *a_ledger)
{
    if(!a_ledger)
        return;
    log_it(L_INFO,"Ledger for network %s destroyed", a_ledger->net->pub.name);

    // Stop the interval timers BEFORE the memory they tick over is freed:
    // a timer firing after net delete / ledger free would touch the freed
    // pvt (use-after-free in the timer callback)
    if (PVT(a_ledger)->snapshot_save_timer) {
        dap_interval_timer_delete(PVT(a_ledger)->snapshot_save_timer);
        PVT(a_ledger)->snapshot_save_timer = NULL;
    }
    if (PVT(a_ledger)->threshold_txs_free_timer) {
        dap_interval_timer_delete(PVT(a_ledger)->threshold_txs_free_timer);
        PVT(a_ledger)->threshold_txs_free_timer = NULL;
    }
    // Cleanup arbitrage rate limiting
    // Destroy Read/Write Lock
    pthread_rwlock_destroy(&PVT(a_ledger)->ledger_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->tokens_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->threshold_txs_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->balance_accounts_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->stake_lock_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->rewards_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->events_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->locked_outs_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->event_pkeys_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->srv_callbacks_rwlock);
    pthread_mutex_destroy(&PVT(a_ledger)->load_mutex);
    pthread_cond_destroy(&PVT(a_ledger)->load_cond);
    DAP_DELETE(PVT(a_ledger));
    DAP_DELETE(a_ledger);

}

struct json_object *wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_bal) {
    char *pos = strrchr(a_bal->key, ' ');
    if (pos) {
        size_t l_addr_len = pos - a_bal->key;
        char *l_addr_str = DAP_NEW_STACK_SIZE(char, l_addr_len + 1);
        dap_strncpy(l_addr_str, a_bal->key, l_addr_len);
        dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_str);
        const char *l_wallet_name = dap_chain_wallet_addr_cache_get_name(l_addr);
        DAP_DELETE(l_addr);
        if (l_wallet_name) {
            struct json_object *l_json = json_object_new_object();
            json_object_object_add(l_json, "class", json_object_new_string("WalletInfo"));
            struct json_object *l_jobj_wallet = json_object_new_object();
            json_object_object_add(l_jobj_wallet, l_wallet_name, dap_chain_wallet_info_to_json(l_wallet_name,
                                                                                               dap_chain_wallet_get_path(g_config)));
            json_object_object_add(l_json, "wallet", l_jobj_wallet);
            return l_json;
        }
    }
    return NULL;
}

inline static dap_ledger_hal_item_t *s_check_hal(dap_ledger_t *a_ledger, dap_hash_fast_t *a_hal_hash)
{
    dap_ledger_hal_item_t *ret = NULL;
    HASH_FIND(hh, PVT(a_ledger)->hal_items, a_hal_hash, sizeof(dap_hash_fast_t), ret);
    if (ret)
        // A HAL hit bypasses signature/value checks for this exact hash: operators
        // must see every use of that loaded gun in the log, not only in debug mode
        log_it(L_WARNING, "Datum %s accepted via hard_accept_list bypass", dap_hash_fast_to_str_static(a_hal_hash));
    else
        debug_if(s_debug_more, L_MSG, "Datum %s is not in the whitelist", dap_hash_fast_to_str_static(a_hal_hash));
    return ret;
}

bool dap_ledger_datum_is_blacklisted(dap_ledger_t *a_ledger, dap_hash_fast_t a_hash) {
    dap_ledger_hal_item_t *ret = NULL;
    HASH_FIND(hh, PVT(a_ledger)->hrl_items, &a_hash, sizeof(dap_hash_fast_t), ret);
    debug_if(s_debug_more && ret, L_MSG, "Datum %s is blacklisted", dap_hash_fast_to_str_static(&a_hash));
    return !!ret;
}

inline static dap_ledger_token_item_t *s_ledger_find_token(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_return_val_if_fail(a_ledger && a_token_ticker, NULL);
    dap_ledger_token_item_t *l_token_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token_ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_token_item;
}

/**
 * @brief s_token_tsd_parse
 *
 * @param a_item_apply_to Token item to apply changes to
 * @param a_current_datum Current token datum
 * @param a_ledger Ledger instance
 * @param a_tsd TSD data
 * @param a_tsd_total_size Total TSD size
 * @param a_apply Whether to apply changes
 * @param a_token_update_hash Hash of token_update datum (for history tracking)
 * @return int Status code
 */
static int s_token_tsd_parse(dap_ledger_token_item_t *a_item_apply_to, dap_chain_datum_token_t *a_current_datum,
                             dap_ledger_t *a_ledger, byte_t *a_tsd, size_t a_tsd_total_size, bool a_apply,
                             dap_hash_fast_t *a_token_update_hash)
{
    if (!a_tsd_total_size) {
        debug_if(a_item_apply_to, L_NOTICE, "No TSD sections in datum token");
        return DAP_LEDGER_CHECK_OK;
    }
    dap_return_val_if_pass(a_apply && !a_item_apply_to, DAP_LEDGER_CHECK_INVALID_ARGS);
    size_t l_new_signs_valid = a_item_apply_to ? a_item_apply_to->auth_signs_valid : 0;
    size_t l_new_signs_total = a_item_apply_to ? a_item_apply_to->auth_signs_total : 0;
    dap_pkey_t **l_new_pkeys = NULL;
    dap_hash_fast_t *l_new_pkey_hashes = NULL;
    bool l_was_pkeys_copied = false;
    size_t l_new_tx_recv_allow_size = a_item_apply_to ? a_item_apply_to->tx_recv_allow_size : 0;
    size_t l_new_tx_recv_block_size = a_item_apply_to ? a_item_apply_to->tx_recv_block_size : 0;
    size_t l_new_tx_send_allow_size = a_item_apply_to ? a_item_apply_to->tx_send_allow_size : 0;
    size_t l_new_tx_send_block_size = a_item_apply_to ? a_item_apply_to->tx_send_block_size : 0;
    struct spec_address *l_new_tx_recv_allow = NULL, *l_new_tx_recv_block = NULL,
                        *l_new_tx_send_allow = NULL, *l_new_tx_send_block = NULL;
    bool l_was_tx_recv_allow_copied = false, l_was_tx_recv_block_copied = false,
         l_was_tx_send_allow_copied = false, l_was_tx_send_block_copied = false;

#define m_ret_cleanup(ret_code) ({                          \
    DAP_DEL_ARRAY(l_new_pkeys, l_new_signs_total);          \
    DAP_DEL_MULTY(l_new_tx_recv_allow, l_new_tx_recv_block, \
                  l_new_tx_send_allow, l_new_tx_send_block, \
                  l_new_pkeys, l_new_pkey_hashes);          \
    ret_code; })
    uint64_t l_tsd_size = 0;
    dap_tsd_t *l_tsd = (dap_tsd_t *)a_tsd;
    for (uint64_t l_offset = 0; l_offset < a_tsd_total_size; l_offset += l_tsd_size) {
        if (l_offset + sizeof(dap_tsd_t) > a_tsd_total_size || l_offset + sizeof(dap_tsd_t) < l_offset) {
            log_it(L_WARNING, "Incorrect TSD section size, less than header");
            return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
        }
        l_tsd = (dap_tsd_t *)((byte_t *)l_tsd + l_tsd_size);
        l_tsd_size = dap_tsd_size(l_tsd);
        if (l_offset + l_tsd_size > a_tsd_total_size || l_offset + l_tsd_size < l_offset) {
            log_it(L_WARNING, "Wrong TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
            return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
        }
        switch (l_tsd->type) {
        // set flags
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS: {
            if (l_tsd->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Wrong SET_FLAGS TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_apply)
                break;
            a_item_apply_to->flags |= dap_tsd_get_scalar(l_tsd, uint16_t);
        } break;

        // unset flags
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS: {
            if (l_tsd->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Wrong UNSET_FLAGS TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_apply)
                break;
            a_item_apply_to->flags &= ~dap_tsd_get_scalar(l_tsd, uint16_t);
        } break;

        // set total supply
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: { // 256
            if (l_tsd->size != sizeof(uint256_t)) {
                log_it(L_WARNING, "Wrong TOTAL_SUPPLY TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_item_apply_to) {
                log_it(L_WARNING, "Unexpected TOTAL_SUPPLY TSD section in datum token declaration");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }
            uint256_t l_new_supply = dap_tsd_get_scalar(l_tsd, uint256_t);
            if (IS_ZERO_256(a_item_apply_to->total_supply)){
                log_it(L_WARNING, "Cannot update total_supply for token %s because the current value is set to infinity.", a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_SUPPLY);
            }
            if (!IS_ZERO_256(l_new_supply) && compare256(a_item_apply_to->total_supply, l_new_supply) > -1) {
                log_it(L_WARNING, "Can't update token with ticker '%s' because the new 'total_supply' can't be smaller than the old one", a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_SUPPLY);
            }
            if (!a_apply)
                break;
            uint256_t l_supply_delta = {};
            SUBTRACT_256_256(l_new_supply, a_item_apply_to->total_supply, &l_supply_delta);
            a_item_apply_to->total_supply = l_new_supply;
            SUM_256_256(a_item_apply_to->current_supply, l_supply_delta, &a_item_apply_to->current_supply);
        } break;

        // Allowed tx receiver addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_ALLOWED_ADD TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_ALLOWED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_allow && l_new_tx_recv_allow_size && !l_was_tx_recv_allow_copied) {
                assert(a_item_apply_to->tx_recv_allow);
                // Deep copy addrs to sandbox
                l_new_tx_recv_allow = DAP_DUP_SIZE(a_item_apply_to->tx_recv_allow, l_new_tx_recv_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_allow_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_recv_allow_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_allow[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_RECEIVER_ALLOWED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            struct spec_address *l_tmp = DAP_REALLOC_COUNT(l_new_tx_recv_allow, l_new_tx_recv_allow_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_recv_allow = l_tmp;
            l_new_tx_recv_allow[l_new_tx_recv_allow_size++].addr = *l_add_addr;
            l_new_tx_recv_allow[l_new_tx_recv_allow_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_ALLOWED_REMOVE TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_ALLOWED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_allow && l_new_tx_recv_allow_size && !l_was_tx_recv_allow_copied) {
                assert(a_item_apply_to->tx_recv_allow);
                // Deep copy addrs to sandbox
                l_new_tx_recv_allow = DAP_DUP_SIZE(a_item_apply_to->tx_recv_allow, l_new_tx_recv_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_allow_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_recv_allow_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_allow[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_recv_allow_size) {
                log_it(L_WARNING, "TSD param TX_RECEIVER_ALLOWED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            {
                size_t l_last_idx = l_new_tx_recv_allow_size - 1;
                if (i < l_last_idx)
                    l_new_tx_recv_allow[i] = l_new_tx_recv_allow[l_last_idx];
                l_new_tx_recv_allow_size = l_last_idx;
            }
            // Memory clearing
            if (l_new_tx_recv_allow_size)
                l_new_tx_recv_allow = DAP_REALLOC_COUNT(l_new_tx_recv_allow, l_new_tx_recv_allow_size);
            else
                DAP_DEL_Z(l_new_tx_recv_allow);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_ALLOWED_CLEAR TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_recv_allow);
            l_new_tx_recv_allow_size = 0;
            l_was_tx_recv_allow_copied = true;
        } break;

        // Blocked tx receiver addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_BLOCKED_ADD TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_BLOCKED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_block && l_new_tx_recv_block_size && !l_was_tx_recv_block_copied) {
                assert(a_item_apply_to->tx_recv_block);
                // Deep copy addrs to sandbox
                l_new_tx_recv_block = DAP_DUP_SIZE(a_item_apply_to->tx_recv_block, l_new_tx_recv_block_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_block_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_recv_block_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_block[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_RECEIVER_BLOCKED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            struct spec_address *l_tmp = DAP_REALLOC_COUNT(l_new_tx_recv_block, l_new_tx_recv_block_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_recv_block = l_tmp;
            l_new_tx_recv_block[l_new_tx_recv_block_size++].addr = *l_add_addr;
            l_new_tx_recv_block[l_new_tx_recv_block_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_BLOCKED_REMOVE TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_RECEIVER_BLOCKED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_recv_block && l_new_tx_recv_block_size && !l_was_tx_recv_block_copied) {
                assert(a_item_apply_to->tx_recv_block);
                // Deep copy addrs to sandbox
                l_new_tx_recv_block = DAP_DUP_SIZE(a_item_apply_to->tx_recv_block, l_new_tx_recv_block_size * sizeof(struct spec_address));
                if (!l_new_tx_recv_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_block_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_recv_block_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_recv_block[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_recv_block_size) {
                log_it(L_WARNING, "TSD param TX_RECEIVER_BLOCKED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            {
                size_t l_last_idx = l_new_tx_recv_block_size - 1;
                if (i < l_last_idx)
                    l_new_tx_recv_block[i] = l_new_tx_recv_block[l_last_idx];
                l_new_tx_recv_block_size = l_last_idx;
            }
            // Memory clearing
            if (l_new_tx_recv_block_size)
                l_new_tx_recv_block = DAP_REALLOC_COUNT(l_new_tx_recv_block, l_new_tx_recv_block_size);
            else
                DAP_DEL_Z(l_new_tx_recv_block);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_RECEIVER_BLOCKED_CLEAR TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_recv_block);
            l_new_tx_recv_block_size = 0;
            l_was_tx_recv_block_copied = true;
        } break;

        // Blocked tx sender addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_ALLOWED_ADD TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_ALLOWED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_send_allow && l_new_tx_send_allow_size && !l_was_tx_send_allow_copied) {
                assert(a_item_apply_to->tx_send_allow);
                // Deep copy addrs to sandbox
                l_new_tx_send_allow = DAP_DUP_SIZE(a_item_apply_to->tx_send_allow, l_new_tx_send_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_send_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_allow_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_send_allow_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_allow[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_SENDER_ALLOWED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            struct spec_address *l_tmp = DAP_REALLOC_COUNT(l_new_tx_send_allow, l_new_tx_send_allow_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_send_allow = l_tmp;
            l_new_tx_send_allow[l_new_tx_send_allow_size++].addr = *l_add_addr;
            l_new_tx_send_allow[l_new_tx_send_allow_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_ALLOWED_REMOVE TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_ALLOWED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);

            }
            if (!l_new_tx_send_allow && l_new_tx_send_allow_size && !l_was_tx_send_allow_copied) {
                assert(a_item_apply_to->tx_send_allow);
                // Deep copy addrs to sandbox
                l_new_tx_send_allow = DAP_DUP_SIZE(a_item_apply_to->tx_send_allow, l_new_tx_send_allow_size * sizeof(struct spec_address));
                if (!l_new_tx_send_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_allow_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_send_allow_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_allow[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_send_allow_size) {
                log_it(L_WARNING, "TSD param TX_SENDER_ALLOWED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            {
                size_t l_last_idx = l_new_tx_send_allow_size - 1;
                if (i < l_last_idx)
                    l_new_tx_send_allow[i] = l_new_tx_send_allow[l_last_idx];
                l_new_tx_send_allow_size = l_last_idx;
            }
            // Memory clearing
            if (l_new_tx_send_allow_size)
                l_new_tx_send_allow = DAP_REALLOC_COUNT(l_new_tx_send_allow, l_new_tx_send_allow_size);
            else
                DAP_DEL_Z(l_new_tx_send_allow);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_SENDER_ALLOWED_CLEAR TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_send_allow);
            l_new_tx_send_allow_size = 0;
            l_was_tx_send_allow_copied = true;
        } break;

        // Blocked tx sender addres list add, remove or clear
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_BLOCKED_ADD TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_BLOCKED_ADD");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_send_block && l_new_tx_send_block_size && !l_was_tx_send_block_copied) {
                assert(a_item_apply_to->tx_send_block);
                // Deep copy addrs to sandbox
                l_new_tx_send_block = DAP_DUP_SIZE(a_item_apply_to->tx_send_block, l_new_tx_send_block_size * sizeof(struct spec_address));
                if (!l_new_tx_send_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_block_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_send_block_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_block[i].addr, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_SENDER_BLOCKED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            if (!a_apply)
                break;
            struct spec_address *l_tmp = DAP_REALLOC_COUNT(l_new_tx_send_block, l_new_tx_send_block_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_send_block = l_tmp;
            l_new_tx_send_block[l_new_tx_send_block_size++].addr = *l_add_addr;
            l_new_tx_send_block[l_new_tx_send_block_size - 1].becomes_effective = dap_time_now();
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE: {
            if (l_tsd->size != sizeof(dap_chain_addr_t)) {
                log_it(L_WARNING, "Wrong TX_SENDER_BLOCKED_REMOVE TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            // Check if its correct
            dap_chain_addr_t *l_add_addr = dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            if (dap_chain_addr_check_sum(l_add_addr)) {
                log_it(L_WARNING, "Wrong address checksum in TSD param TX_SENDER_BLOCKED_REMOVE");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR);
            }
            if (!l_new_tx_send_block && l_new_tx_send_block_size && !l_was_tx_send_block_copied) {
                assert(a_item_apply_to->tx_send_block);
                // Deep copy addrs to sandbox
                l_new_tx_send_block = DAP_DUP_SIZE(a_item_apply_to->tx_send_block, l_new_tx_send_block_size * sizeof(struct spec_address));
                if (!l_new_tx_send_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_block_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_send_block_size; i++) // Check for all the list
                if (dap_chain_addr_compare(&l_new_tx_send_block[i].addr, l_add_addr))
                    break;
            if (i == l_new_tx_send_block_size) {
                log_it(L_WARNING, "TSD param TX_SENDER_BLOCKED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing: swap with last
            {
                size_t l_last_idx = l_new_tx_send_block_size - 1;
                if (i < l_last_idx)
                    l_new_tx_send_block[i] = l_new_tx_send_block[l_last_idx];
                l_new_tx_send_block_size = l_last_idx;
            }
            // Memory clearing
            if (l_new_tx_send_block_size)
                l_new_tx_send_block = DAP_REALLOC_COUNT(l_new_tx_send_block, l_new_tx_send_block_size);
            else
                DAP_DEL_Z(l_new_tx_send_block);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong TX_SENDER_BLOCKED_CLEAR TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            DAP_DEL_Z(l_new_tx_send_block);
            l_new_tx_send_block_size = 0;
            l_was_tx_send_block_copied = true;
        } break;

        // ============================================================================
        // UTXO FLAGS TSD SECTION (stores all UTXO-related flags in uint32_t)
        // ============================================================================
        
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS: {
            // UTXO flags are stored separately in TSD to avoid uint16_t overflow
            // (flags like BIT(16-20) don't fit in header_native_decl.flags which is uint16_t)
            if (l_tsd->size != sizeof(uint32_t)) {
                log_it(L_WARNING, "Wrong UTXO_FLAGS TSD size %"DAP_UINT64_FORMAT_U", expected %zu", 
                       l_tsd_size, sizeof(uint32_t));
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_apply)
                break;
            
            uint32_t l_utxo_flags = dap_tsd_get_scalar(l_tsd, uint32_t);
            
            // Merge UTXO flags into token item's flags
            // Note: UTXO flags use BIT(0-4) in TSD, but are conceptually separate from header flags
            // We store them in the same token_item->flags field for simplicity
            a_item_apply_to->flags |= l_utxo_flags;
            
            log_it(L_INFO, "Applied UTXO flags 0x%08X to token %s (total flags: 0x%08X)", 
                   l_utxo_flags, a_item_apply_to->ticker, a_item_apply_to->flags);
        } break;

        // ============================================================================
        // UTXO BLOCKLIST TSD SECTIONS
        // ============================================================================

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD: {
            // Two formats supported:
            // Basic:    [tx_hash: 32B][out_idx: 4B] = 36 bytes (immediate activation)
            // Extended: [tx_hash: 32B][out_idx: 4B][timestamp: 8B] = 44 bytes (delayed activation)
            size_t l_expected_size_basic = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
            size_t l_expected_size_extended = l_expected_size_basic + sizeof(dap_time_t);
            
            if (l_tsd->size != l_expected_size_basic && l_tsd->size != l_expected_size_extended) {
                log_it(L_WARNING, "Wrong UTXO_BLOCKED_ADD TSD size %"DAP_UINT64_FORMAT_U", expected %zu or %zu, exiting TSD parse", 
                       l_tsd_size, l_expected_size_basic, l_expected_size_extended);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }

            // Check if UTXO blocking is disabled for this token
            if (a_item_apply_to->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) {
                log_it(L_WARNING, "UTXO blocking is disabled for token %s, cannot add UTXO to blocklist", 
                       a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }

            // Check if blocklist is static
            if (a_item_apply_to->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST) {
                log_it(L_WARNING, "UTXO blocklist is static for token %s, cannot modify", 
                       a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }

            // Parse UTXO data (tx_hash + out_idx)
            dap_chain_hash_fast_t *l_tx_hash = (dap_chain_hash_fast_t *)l_tsd->data;
            uint32_t l_out_idx = *(uint32_t *)(l_tsd->data + sizeof(dap_chain_hash_fast_t));
            
            // Parse activation time (optional)
            dap_time_t l_becomes_effective;
            if (l_tsd->size == l_expected_size_extended) {
                // Extended format with explicit timestamp
                memcpy(&l_becomes_effective, l_tsd->data + sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t), sizeof(l_becomes_effective));
                log_it(L_DEBUG, "UTXO blocking with delayed activation at %"DAP_UINT64_FORMAT_U, l_becomes_effective);
            } else {
                // Basic format - immediate activation (use blockchain time, not wall clock!)
                l_becomes_effective = dap_ledger_get_blockchain_time(a_ledger);
            }

            // Validate UTXO exists (optional validation with warning)
            // Note: UTXO may not exist yet at token_update time, but will exist later
            // This is a sanity check, not a blocking error
            if (a_apply) {
                dap_ledger_tx_item_t *l_tx_item = NULL;
                dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_datum_by_hash(a_ledger, l_tx_hash, &l_tx_item, false);
                if (l_tx) {
                    // Check if output index exists
                    void *l_tx_out = dap_chain_datum_tx_item_get_nth(l_tx, TX_ITEM_TYPE_OUT_ALL, l_out_idx);
                    if (!l_tx_out) {
                        char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                        dap_chain_hash_fast_to_str(l_tx_hash, l_hash_str, sizeof(l_hash_str));
                        log_it(L_WARNING, "UTXO validation: output index %u not found in tx %s (may not exist yet)", 
                               l_out_idx, l_hash_str);
                    } else {
                        // Check if already spent
                        if (l_tx_item && l_tx_item->cache_data.n_outs_used > l_out_idx &&
                            !dap_hash_fast_is_blank(&l_tx_item->cache_data.tx_hash_spent_fast[l_out_idx])) {
                            char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                            dap_chain_hash_fast_to_str(l_tx_hash, l_hash_str, sizeof(l_hash_str));
                            log_it(L_WARNING, "UTXO validation: output %s:%u is already spent", l_hash_str, l_out_idx);
                        }
                    }
                } else {
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(l_tx_hash, l_hash_str, sizeof(l_hash_str));
                    log_it(L_DEBUG, "UTXO validation: transaction %s not found in ledger (may not exist yet)", l_hash_str);
                }
            }

            if (!a_apply)
                break;

            // Add UTXO to blocklist with specified activation time
            if (dap_ledger_utxo_block_add(a_item_apply_to, l_tx_hash, l_out_idx, l_becomes_effective, 
                                         a_token_update_hash, a_ledger) != 0) {
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(l_tx_hash, l_hash_str, sizeof(l_hash_str));
                log_it(L_ERROR, "Failed to add UTXO to blocklist: tx=%s, out_idx=%u", l_hash_str, l_out_idx);
                return m_ret_cleanup(DAP_LEDGER_CHECK_APPLY_ERROR);
            }
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE: {
            // Two formats supported:
            // 1. Basic (36 bytes): [tx_hash: 32B][out_idx: 4B] → immediate removal
            // 2. Extended (44 bytes): [tx_hash: 32B][out_idx: 4B][timestamp: 8B] → delayed unblocking
            size_t l_basic_size = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
            size_t l_extended_size = l_basic_size + sizeof(uint64_t);
            
            if (l_tsd->size != l_basic_size && l_tsd->size != l_extended_size) {
                log_it(L_WARNING, "Wrong UTXO_BLOCKED_REMOVE TSD size %"DAP_UINT64_FORMAT_U", expected %zu (basic) or %zu (extended)", 
                       l_tsd_size, l_basic_size, l_extended_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }

            // Check if UTXO blocking is disabled for this token
            if (a_item_apply_to->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) {
                log_it(L_WARNING, "UTXO blocking is disabled for token %s, cannot remove UTXO from blocklist", 
                       a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }

            // Check if blocklist is static
            if (a_item_apply_to->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST) {
                log_it(L_WARNING, "UTXO blocklist is static for token %s, cannot modify", 
                       a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }

            // Parse UTXO data
            dap_chain_hash_fast_t *l_tx_hash = (dap_chain_hash_fast_t *)l_tsd->data;
            uint32_t l_out_idx = *(uint32_t *)(l_tsd->data + sizeof(dap_chain_hash_fast_t));
            
            // Parse optional timestamp for delayed unblocking
            dap_time_t l_becomes_unblocked = 0;  // 0 = immediate removal
            if (l_tsd->size == l_extended_size) {
                uint64_t l_timestamp; memcpy(&l_timestamp, l_tsd->data + sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t), sizeof(l_timestamp));
                l_becomes_unblocked = (dap_time_t)l_timestamp;
            }

            if (!a_apply)
                break;

            // Remove UTXO from blocklist (or schedule delayed unblocking)
            if (dap_ledger_utxo_block_remove(a_item_apply_to, l_tx_hash, l_out_idx, l_becomes_unblocked,
                                             a_token_update_hash, a_ledger) != 0) {
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(l_tx_hash, l_hash_str, sizeof(l_hash_str));
                if (l_becomes_unblocked == 0) {
                    log_it(L_WARNING, "Failed to remove UTXO from blocklist (may not exist): tx=%s, out_idx=%u", 
                           l_hash_str, l_out_idx);
                } else {
                    log_it(L_WARNING, "Failed to schedule UTXO unblocking (may not exist): tx=%s, out_idx=%u, unblock_time=%"DAP_UINT64_FORMAT_U, 
                           l_hash_str, l_out_idx, (uint64_t)l_becomes_unblocked);
                }
                // Don't fail if UTXO wasn't in blocklist
            }
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR: {
            if (l_tsd->size != 0) {
                log_it(L_WARNING, "Wrong UTXO_BLOCKED_CLEAR TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", 
                       l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }

            // Check if UTXO blocking is disabled for this token
            if (a_item_apply_to->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) {
                log_it(L_WARNING, "UTXO blocking is disabled for token %s, cannot clear blocklist", 
                       a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }

            // Check if blocklist is static
            if (a_item_apply_to->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST) {
                log_it(L_WARNING, "UTXO blocklist is static for token %s, cannot clear", 
                       a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }

            if (!a_apply)
                break;

            // Clear entire UTXO blocklist with history tracking
            if (dap_ledger_utxo_block_clear(a_item_apply_to, a_token_update_hash, a_ledger) != 0) {
                log_it(L_ERROR, "Failed to clear UTXO blocklist for token %s", a_item_apply_to->ticker);
                return m_ret_cleanup(DAP_LEDGER_CHECK_APPLY_ERROR);
            }
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION: {
            if (l_tsd->size == 0 || l_tsd->data[l_tsd->size - 1] != 0) {
                log_it(L_ERROR, "Wrong TOKEN_DESCRIPTION TSD format or size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!a_apply)
                break;
            DAP_DEL_Z(a_item_apply_to->description);
            a_item_apply_to->description = strdup((char *)l_tsd->data);
        } break;

        // Set signs count value need to emission be valid
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
            if (l_tsd->size != sizeof(uint16_t)) {
                log_it(L_WARNING, "Wrong SIGNS_VALID TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            l_new_signs_valid = dap_tsd_get_scalar(l_tsd, uint16_t);
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD: {
            if (l_tsd->size < sizeof(dap_pkey_t) || l_tsd->size != dap_pkey_get_size((dap_pkey_t *)l_tsd->data)) {
                log_it(L_WARNING, "Wrong TOTAL_PKEYS_ADD TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!l_new_pkeys && l_new_signs_total && !l_was_pkeys_copied) {
                assert(a_item_apply_to->auth_pkeys);
                assert(a_item_apply_to->auth_pkey_hashes);
                // Deep copy pkeys & its hashes to sandbox
                l_new_pkeys = DAP_NEW_SIZE(dap_pkey_t *, l_new_signs_total * sizeof(dap_pkey_t *));
                if (!l_new_pkeys) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
                for (size_t i = 0; i < l_new_signs_total; i++) {
                    l_new_pkeys[i] = DAP_DUP_SIZE(a_item_apply_to->auth_pkeys[i], dap_pkey_get_size(a_item_apply_to->auth_pkeys[i]));
                    if (!l_new_pkeys[i]) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                    }
                }
                assert(!l_new_pkey_hashes);
                l_new_pkey_hashes = DAP_DUP_SIZE(a_item_apply_to->auth_pkey_hashes, l_new_signs_total * sizeof(dap_hash_t));
                if (!l_new_pkey_hashes) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_pkeys_copied = true;
            dap_pkey_t *l_new_auth_pkey = dap_tsd_get_object(l_tsd, dap_pkey_t);
            dap_pkey_type_t l_pkey_type_correction = { .type = DAP_PKEY_TYPE_NULL };
            if (dap_pkey_type_to_enc_key_type(l_new_auth_pkey->header.type) == DAP_ENC_KEY_TYPE_INVALID) {
                dap_sign_type_t l_sign_type = { .type = l_new_auth_pkey->header.type.type }; // Legacy cratch
                l_pkey_type_correction = dap_pkey_type_from_sign_type(l_sign_type);
                if (l_pkey_type_correction.type == DAP_PKEY_TYPE_NULL) {
                    log_it(L_WARNING, "Unknonw public key type %hu", l_new_auth_pkey->header.type.type);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_PARSE_ERROR);
                }
            }
            // Check if its already present in new list OR in existing token keys OR in current datum signatures
            dap_hash_t l_new_auth_pkey_hash;
            dap_pkey_get_hash(l_new_auth_pkey, &l_new_auth_pkey_hash);
            bool l_key_already_present = false;
            
            // First check in new keys list (if already copied)
            if (l_new_pkeys) {
                for (size_t i = 0; i < l_new_signs_total; i++) {
                    if (dap_pkey_compare(l_new_auth_pkey, l_new_pkeys[i])) {
                        log_it(L_WARNING, "TSD param TOTAL_PKEYS_ADD has pkey %s thats already present in new list, skipping duplicate",
                                                                        dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                        l_key_already_present = true;
                        break;
                    }
                }
            }
            
            // Also check in existing token keys (if not yet copied to new list)
            if (!l_key_already_present && a_item_apply_to && a_item_apply_to->auth_pkeys) {
                for (size_t i = 0; i < a_item_apply_to->auth_signs_total; i++) {
                    if (dap_pkey_compare(l_new_auth_pkey, a_item_apply_to->auth_pkeys[i])) {
                        log_it(L_WARNING, "TSD param TOTAL_PKEYS_ADD has pkey %s thats already present in existing token keys, skipping duplicate",
                                                                        dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                        l_key_already_present = true;
                        break;
                    }
                }
            }
            
            // CRITICAL: Also check if this key is already present in current datum signatures
            // This prevents duplicates when keys from signatures are also added via TSD TOTAL_PKEYS_ADD
            // This happens when token_decl uses -certs (adds keys via signatures) and -pub_certs (adds same keys via TSD)
            // OR when token_decl_sign copies TSD from old datum that already has keys from signatures
            if (!l_key_already_present && a_current_datum && a_current_datum->signs_total > 0) {
                // Get TSD size from datum header to find where signatures start
                size_t l_current_tsd_size = 0;
                switch (a_current_datum->subtype) {
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
                    l_current_tsd_size = a_current_datum->header_private_decl.tsd_total_size;
                    break;
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
                    l_current_tsd_size = a_current_datum->header_native_decl.tsd_total_size;
                    break;
                default:
                    break;
                }
                
                // Check signatures in current datum (they come after TSD)
                // Signatures contain public keys that are automatically added to auth_pkeys
                if (l_current_tsd_size > 0 && l_current_tsd_size <= a_tsd_total_size) {
                    byte_t *l_signs_ptr = a_current_datum->tsd_n_signs + l_current_tsd_size;
                    // Estimate max signs size: signs_total * reasonable max signature size
                    size_t l_estimated_signs_size = a_current_datum->signs_total * 1024;  // Conservative estimate
                    size_t l_signs_unique = a_current_datum->signs_total;
                    
                    dap_sign_t **l_signs = dap_sign_get_unique_signs(l_signs_ptr, l_estimated_signs_size, &l_signs_unique);
                    if (l_signs && l_signs_unique > 0) {
                        for (size_t i = 0; i < l_signs_unique; i++) {
                            dap_pkey_t *l_sign_pkey = dap_pkey_get_from_sign(l_signs[i]);
                            if (l_sign_pkey) {
                                if (dap_pkey_compare(l_new_auth_pkey, l_sign_pkey)) {
                                    log_it(L_WARNING, "TSD param TOTAL_PKEYS_ADD has pkey %s thats already present in current datum signatures (will be added via signature), skipping duplicate",
                                                                           dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                                    l_key_already_present = true;
                                    DAP_DELETE(l_sign_pkey);
                                    break;
                                }
                                DAP_DELETE(l_sign_pkey);
                            }
                        }
                        DAP_DELETE(l_signs);
                    }
                }
            }
            
            // Skip adding duplicate key - it's already in the list
            if (l_key_already_present) {
                continue; // Continue to next TSD entry
            }
            dap_pkey_t **l_tmp = DAP_REALLOC_COUNT(l_new_pkeys, l_new_signs_total + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_pkeys = l_tmp;
            // Pkey adding
            l_new_pkeys[l_new_signs_total] = DAP_DUP_SIZE(l_new_auth_pkey, dap_pkey_get_size(l_new_auth_pkey));
            if (!l_new_pkeys[l_new_signs_total]) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            if (l_pkey_type_correction.type != DAP_PKEY_TYPE_NULL)
                l_new_pkeys[l_new_signs_total]->header.type = l_pkey_type_correction;

            dap_hash_fast_t *l_tmp_hashes = DAP_REALLOC_COUNT(l_new_pkey_hashes, l_new_signs_total + 1);
            if (!l_tmp_hashes) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_pkey_hashes = l_tmp_hashes;
            l_new_pkey_hashes[l_new_signs_total++] = l_new_auth_pkey_hash;
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE: {
            if (l_tsd->size != sizeof(dap_hash_t)) {
                log_it(L_WARNING, "Wrong TOTAL_PKEYS_REMOVE TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            if (!l_new_pkeys && l_new_signs_total && !l_was_pkeys_copied) {
                assert(a_item_apply_to->auth_pkeys);
                assert(a_item_apply_to->auth_pkey_hashes);
                // Deep copy pkeys & its hashes to sandbox
                l_new_pkeys = DAP_NEW_SIZE(dap_pkey_t *, l_new_signs_total * sizeof(dap_pkey_t *));
                if (!l_new_pkeys) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
                for (size_t i = 0; i < l_new_signs_total; i++) {
                    l_new_pkeys[i] = DAP_DUP_SIZE(a_item_apply_to->auth_pkeys[i], dap_pkey_get_size(a_item_apply_to->auth_pkeys[i]));
                    if (!l_new_pkeys[i]) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                    }
                }
                assert(!l_new_pkey_hashes);
                l_new_pkey_hashes = DAP_DUP_SIZE(a_item_apply_to->auth_pkey_hashes, l_new_signs_total * sizeof(dap_hash_t));
                if (!l_new_pkey_hashes) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_pkeys_copied = true;
            dap_hash_t l_new_auth_pkey_hash = dap_tsd_get_scalar(l_tsd, dap_hash_t);
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_signs_total; i++) // Check for all the list
                if (dap_hash_fast_compare(l_new_pkey_hashes + i, &l_new_auth_pkey_hash))
                    break;
            if (i == l_new_signs_total) {
                log_it(L_WARNING, "TSD param TOTAL_PKEYS_REMOVE has public key hash %s thats not present in list, skipping removal",
                                                    dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                continue; // Skip removal of non-existent key - continue to next TSD entry
            }
            // Pkey removing: swap with last to avoid O(n) shifts
            {
                size_t l_last_idx = l_new_signs_total - 1;
                DAP_DEL_Z(l_new_pkeys[i]);
                if (i < l_last_idx) {
                    l_new_pkeys[i] = l_new_pkeys[l_last_idx];
                    l_new_pkey_hashes[i] = l_new_pkey_hashes[l_last_idx];
                }
                l_new_signs_total = l_last_idx;
            }
            // Memory clearing
            if (l_new_signs_total) {
                l_new_pkeys = DAP_REALLOC_COUNT(l_new_pkeys, l_new_signs_total);
                l_new_pkey_hashes = DAP_REALLOC_COUNT(l_new_pkey_hashes, l_new_signs_total);
            } else {
                DAP_DEL_Z(l_new_pkeys);
                DAP_DEL_Z(l_new_pkey_hashes);
            }
        } break;

        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK: {
            if (a_current_datum->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE) {
                log_it(L_WARNING, "TSD section DELEGATE_EMISSION_FROM_STAKE_LOCK allowed for NATIVE subtype only");
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN);
            }
            if (l_tsd->size != sizeof(dap_chain_datum_token_tsd_delegate_from_stake_lock_t) &&
                    l_tsd->size != sizeof(dap_chain_datum_token_tsd_delegate_from_stake_lock_t) + 256 /* Legacy size */) {
                log_it(L_WARNING, "Wrong DELEGATE_EMISSION_FROM_STAKE_LOCK TSD size %"DAP_UINT64_FORMAT_U", exiting TSD parse", l_tsd_size);
                return m_ret_cleanup(DAP_LEDGER_CHECK_INVALID_SIZE);
            }
            dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_delegate = dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
            const char *l_basic_token_ticker = (const char *)l_delegate->ticker_token_from;
            char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_basic_token_ticker);
            if (dap_strcmp(l_delegated_ticker, a_current_datum->ticker)) {
                log_it(L_WARNING, "Unexpected delegated token ticker %s (expected %s)", a_current_datum->ticker, l_delegated_ticker);
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_OTHER_TICKER_EXPECTED);
            }
            dap_ledger_token_item_t *l_basic_token = NULL;
            HASH_FIND_STR(PVT(a_ledger)->tokens, l_basic_token_ticker, l_basic_token);
            if (!l_basic_token) {
                log_it(L_WARNING, "Basic token ticker %s for delegated token isn't found", l_basic_token_ticker);
                return m_ret_cleanup(DAP_LEDGER_CHECK_TICKER_NOT_FOUND);
            }
            if (IS_ZERO_256(l_delegate->emission_rate)) {
                log_it(L_WARNING, "Emission rate for delegated toke should not be a zero");
                return m_ret_cleanup(DAP_LEDGER_CHECK_ZERO_VALUE);
            }
            if (!a_apply)
                break;
            assert(a_item_apply_to);
            a_item_apply_to->is_delegated = true;
            dap_strncpy(a_item_apply_to->delegated_from, l_basic_token->ticker, sizeof(a_item_apply_to->delegated_from) - 1);
            a_item_apply_to->emission_rate = l_delegate->emission_rate;
        } break;

        default:
            log_it(L_ERROR, "Unexpected TSD type %hu", l_tsd->type);
            return m_ret_cleanup(DAP_LEDGER_CHECK_PARSE_ERROR);
        }
    }
    if (l_new_signs_total < l_new_signs_valid)
        return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS);

    if (!a_apply)
        return m_ret_cleanup(DAP_LEDGER_CHECK_OK);
#undef m_ret_cleanup

    if (l_was_tx_recv_allow_copied) {
        a_item_apply_to->tx_recv_allow_size = l_new_tx_recv_allow_size;
        DAP_DEL_Z(a_item_apply_to->tx_recv_allow);
        a_item_apply_to->tx_recv_allow = l_new_tx_recv_allow;
    }
    if (l_was_tx_recv_block_copied) {
        a_item_apply_to->tx_recv_block_size = l_new_tx_recv_block_size;
        DAP_DEL_Z(a_item_apply_to->tx_recv_block);
        a_item_apply_to->tx_recv_block = l_new_tx_recv_block;
    }
    if (l_was_tx_send_allow_copied) {
        a_item_apply_to->tx_send_allow_size = l_new_tx_send_allow_size;
        DAP_DEL_Z(a_item_apply_to->tx_send_allow);
        a_item_apply_to->tx_send_allow = l_new_tx_send_allow;
    }
    if (l_was_tx_send_block_copied) {
        a_item_apply_to->tx_send_block_size = l_new_tx_send_block_size;
        DAP_DEL_Z(a_item_apply_to->tx_send_block);
        a_item_apply_to->tx_send_block = l_new_tx_send_block;
    }
    a_item_apply_to->auth_signs_valid = l_new_signs_valid;
    if (l_was_pkeys_copied) {
        for (size_t i = 0; i < a_item_apply_to->auth_signs_total; i++)
            DAP_DELETE(a_item_apply_to->auth_pkeys[i]);
        DAP_DEL_Z(a_item_apply_to->auth_pkeys);
        DAP_DEL_Z(a_item_apply_to->auth_pkey_hashes);
        a_item_apply_to->auth_signs_total = l_new_signs_total;
        a_item_apply_to->auth_pkeys = l_new_pkeys;
        a_item_apply_to->auth_pkey_hashes = l_new_pkey_hashes;
    }
    return DAP_LEDGER_CHECK_OK;
}

/**
 * @brief dap_ledger_token_check
 * @param a_ledger
 * @param a_token
 * @param a_token_size
 * @return
 */
int s_token_add_check(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size,
                      dap_ledger_token_item_t **a_token_item, dap_chain_datum_token_t **a_token_out,
                      size_t *a_tsd_total_size, size_t *a_signs_size,
                      dap_hash_fast_t *a_token_update_hash)
{
    size_t l_token_size = a_token_size;
    dap_chain_datum_token_t *l_token = dap_chain_datum_token_read(a_token, &l_token_size);
    if (!l_token)
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    bool l_legacy_type = a_token_size != l_token_size;
    if (l_legacy_type && !a_token_item) { // It's mempool check
        log_it(L_WARNING, "Legacy token type %hu isn't supported for a new declaration", l_token->type);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_LEGACY_FORBIDDEN;
    }
    if (l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE && l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_DECL) {
        log_it(L_WARNING, "Unknown token type %hu", l_token->type);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_PARSE_ERROR;
    }
    if (!l_token->ticker[0] || l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1]) {
        log_it(L_WARNING, "Unreadable token ticker");
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_PARSE_ERROR;
    }
    char *ptr = l_token->ticker;
    while (*ptr) {
        if (!dap_ascii_isalnum(*ptr++)) {
            log_it(L_WARNING, "Token ticker is not alpha-numeric");
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_PARSE_ERROR;
        }
    }
    if (!l_token->signs_total) {
        log_it(L_WARNING, "No auth signs in token '%s' datum!", l_token->ticker);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
    }
    bool l_update_token = l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, l_token->ticker);
    dap_hash_fast_t l_token_update_hash = {};
    if (l_token_item) {
        if (!l_update_token) {
            log_it(L_WARNING, "Duplicate token declaration for ticker '%s'", l_token->ticker);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
        }
        if (l_token->signs_total < l_token_item->auth_signs_valid) {
            log_it(L_WARNING, "Datum token for ticker '%s' has only %hu signatures out of %zu",
                                            l_token->ticker, l_token->signs_total, l_token_item->auth_signs_valid);
            DAP_DELETE(l_token);
            return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
        }
        
        // Check irreversible flags FIRST - they can only be SET, never UNSET
        // This check must happen BEFORE duplicate check to ensure violations are caught
        // even if the update was already applied (security critical)
        // This applies to: UTXO_BLOCKING_DISABLED, ARBITRAGE_TX_DISABLED, etc.
        uint32_t l_old_irreversible = l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_IRREVERSIBLE_MASK;
        uint32_t l_new_flags = 0;
        
        // Get new flags from token datum (different header structure for PRIVATE vs NATIVE)
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_new_flags = l_token->header_private_decl.flags;
            break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_new_flags = l_token->header_native_decl.flags;
            break;
        default:
            l_new_flags = 0;
        }
        
        // Extract UTXO flags from TSD if present in token_update
        // If UTXO_FLAGS TSD is NOT present, inherit old UTXO flags (they don't change)
        size_t l_tsd_total = 0;
        bool l_utxo_flags_in_tsd = false;
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_tsd_total = l_token->header_private_decl.tsd_total_size;
            break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_tsd_total = l_token->header_native_decl.tsd_total_size;
            break;
        }
        
        if (l_tsd_total > 0) {
            dap_tsd_t *l_tsd = (dap_tsd_t *)l_token->tsd_n_signs;
            for (size_t l_offset = 0; l_offset < l_tsd_total; ) {
                if (l_offset + sizeof(dap_tsd_t) > l_tsd_total)
                    break;
                dap_tsd_t *l_tsd_item = (dap_tsd_t *)((byte_t *)l_tsd + l_offset);
                size_t l_tsd_size = dap_tsd_size(l_tsd_item);
                if (l_offset + l_tsd_size > l_tsd_total)
                    break;
                
                if (l_tsd_item->type == DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS && 
                    l_tsd_item->size == sizeof(uint32_t)) {
                    uint32_t l_utxo_flags_from_tsd = dap_tsd_get_scalar(l_tsd_item, uint32_t);
                    l_new_flags |= l_utxo_flags_from_tsd;
                    l_utxo_flags_in_tsd = true;
                    break;
                }
                l_offset += l_tsd_size;
            }
        }
        
        // If UTXO_FLAGS TSD is not present in token_update, inherit old UTXO flags
        // (token_update that doesn't change UTXO flags shouldn't include UTXO_FLAGS TSD)
        if (!l_utxo_flags_in_tsd) {
            uint32_t l_old_utxo_flags = l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_IRREVERSIBLE_MASK;
            l_new_flags |= l_old_utxo_flags;
        }
        
        uint32_t l_new_irreversible = l_new_flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_IRREVERSIBLE_MASK;
        
        // Validate: new irreversible flags must be >= old irreversible flags
        // This means: once a bit is set, it stays set forever
        // CRITICAL: Use bitwise check - all old bits must be present in new flags
        // This prevents unsetting individual bits while keeping others
        if ((l_new_irreversible & l_old_irreversible) != l_old_irreversible) {
            log_it(L_WARNING, "Attempt to unset irreversible flags for token '%s': old=0x%08X new=0x%08X (bitwise check failed: 0x%08X & 0x%08X = 0x%08X != 0x%08X)",
                   l_token->ticker, l_old_irreversible, l_new_irreversible,
                   l_new_irreversible, l_old_irreversible, (l_new_irreversible & l_old_irreversible), l_old_irreversible);
            DAP_DELETE(l_token);
            return DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION;
        }
        
        // Check for duplicate update AFTER irreversible flags check
        // (security: violations must be caught even if update was already applied)
        dap_hash_fast(l_token, l_token_size, &l_token_update_hash);
        dap_ledger_token_update_item_t *l_token_update_item = NULL;
        pthread_rwlock_rdlock(&l_token_item->token_ts_updated_rwlock);
        HASH_FIND(hh, l_token_item->token_ts_updated, &l_token_update_hash, sizeof(dap_hash_fast_t), l_token_update_item);
        pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
        if (l_token_update_item) {
            log_it(L_WARNING, "This update for token '%s' was already applied", l_token->ticker);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
        }
        if (a_token_update_hash)
            *a_token_update_hash = l_token_update_hash;
        
    } else if (l_update_token) {
        log_it(L_WARNING, "Can't update token that doesn't exist for ticker '%s'", l_token->ticker);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
    } else if (l_token->signs_total < l_token->signs_valid) {
        log_it(L_WARNING, "Datum token for ticker '%s' has only %hu signatures out of %hu",
                                            l_token->ticker, l_token->signs_total, l_token->signs_valid);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
    }
    // Check TSD
    size_t l_size_tsd_section = 0;
    if (l_update_token) {
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_size_tsd_section = l_token->header_private_decl.tsd_total_size; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_size_tsd_section = l_token->header_native_decl.tsd_total_size; break;
        default:
            /* Bogdanoff, unknown token subtype update. What shall we TODO? */
            log_it(L_WARNING, "Unsupported token subtype '0x%0hX' update! "
                              "Ticker: %s, total_supply: %s, signs_valid: %hu, signs_total: %hu",
                              l_token->type, l_token->ticker, dap_uint256_to_char(l_token->total_supply, NULL),
                              l_token->signs_valid, l_token->signs_total);
            /* Dump it right now */
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_PARSE_ERROR;
        }
    } else {
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_size_tsd_section = l_token->header_private_update.tsd_total_size; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_size_tsd_section = l_token->header_native_update.tsd_total_size; break;
        default:
            /* Bogdanoff, unknown token subtype declaration. What shall we TODO? */
            log_it(L_WARNING, "Unsupported token subtype '0x%0hX' declaration! "
                              "Ticker: %s, total_supply: %s, signs_valid: %hu, signs_total: %hu",
                              l_token->type, l_token->ticker, dap_uint256_to_char(l_token->total_supply, NULL),
                              l_token->signs_valid, l_token->signs_total);
            /* Dump it right now */
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_PARSE_ERROR;
        }
    }
    if (sizeof(dap_chain_datum_token_t) + l_size_tsd_section > l_token_size ||
            sizeof(dap_chain_datum_token_t) + l_size_tsd_section < l_size_tsd_section) {
        log_it(L_WARNING, "Incorrect size %zu of datum token, expected at least %zu", l_token_size,
                                                sizeof(dap_chain_datum_token_t) + l_size_tsd_section);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    }
    // Check signs
    byte_t *l_signs_ptr = l_token->tsd_n_signs + l_size_tsd_section;
    uint64_t l_signs_size = 0, l_signs_offset = sizeof(dap_chain_datum_token_t) + l_size_tsd_section;
    for (uint16_t l_signs_passed = 0; l_signs_passed < l_token->signs_total; l_signs_passed++) {
        dap_sign_t *l_sign = (dap_sign_t *)(l_signs_ptr + l_signs_size);
        if (l_signs_offset + l_signs_size + sizeof(dap_sign_t) > l_token_size ||
                l_signs_offset + l_signs_size + sizeof(dap_sign_t) < l_signs_offset) {
            log_it(L_WARNING, "Incorrect size %zu of datum token, expected at least %"DAP_UINT64_FORMAT_U, l_token_size,
                                                    l_signs_offset + l_signs_size + sizeof(dap_sign_t));
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_INVALID_SIZE;
        }
        uint64_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size || l_sign_size + l_signs_size < l_signs_size) {
            log_it(L_WARNING, "Incorrect size %"DAP_UINT64_FORMAT_U" of datum token sign", l_sign_size);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_INVALID_SIZE;
        }
        l_signs_size += l_sign_size;
    }
    if (l_token_size != l_signs_offset + l_signs_size) {
        log_it(L_WARNING, "Incorrect size %zu of datum token, expected %"DAP_UINT64_FORMAT_U, l_token_size, l_signs_offset + l_signs_size);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    }
    size_t l_signs_unique = l_token->signs_total;
    dap_sign_t **l_signs = dap_sign_get_unique_signs(l_signs_ptr, l_signs_size, &l_signs_unique);
    if (l_signs_unique != l_token->signs_total) {
        DAP_DEL_Z(l_signs);
        log_it(L_WARNING, "The number of unique token signs %zu is less than total token signs set to %hu",
               l_signs_unique, l_token->signs_total);
        DAP_DELETE(l_token);
        return DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS;
    }
    size_t l_signs_approve = 0;
    size_t l_verify_size = 0;
    uint16_t l_tmp_auth_signs = 0;
    if (l_legacy_type)
        l_verify_size = sizeof(dap_chain_datum_token_old_t) - sizeof(uint16_t);
    else {
        l_verify_size = l_signs_offset;
        l_tmp_auth_signs = l_token->signs_total;
        l_token->signs_total = 0;
    }
    for (size_t i = 0; i < l_signs_unique; i++) {
        if (!dap_sign_verify(l_signs[i], l_legacy_type ? a_token : (void *)l_token, l_verify_size)) {
            if (l_update_token) {
                for (size_t j = 0; j < l_token_item->auth_signs_total; j++) {
                    if (dap_pkey_compare_with_sign(l_token_item->auth_pkeys[j], l_signs[i])) {
                        l_signs_approve++;
                        break;
                    }
                }
            } else
                l_signs_approve++;
        }
    }
    DAP_DELETE(l_signs);
    if (!l_legacy_type)
        l_token->signs_total = l_tmp_auth_signs;
    size_t l_signs_need = l_update_token ? l_token_item->auth_signs_valid : l_token->signs_total;
    if (l_signs_approve < l_signs_need) {
        log_it(L_WARNING, "Datum token for ticker '%s' has only %zu valid signatures out of %zu",
                                                l_token->ticker, l_signs_approve, l_signs_need);
        DAP_DELETE(l_token);
        return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
    }
    // Check content & size of enclosed TSD sections
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    int ret = s_token_tsd_parse(l_token_item, l_token, a_ledger, l_token->tsd_n_signs, l_size_tsd_section, false, NULL);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    dap_ledger_hal_item_t *l_hash_found = NULL;
    if (ret != DAP_LEDGER_CHECK_OK) {
        if (PVT(a_ledger)->hal_items) {
            dap_hash_fast_t l_token_hash;
            if (!dap_hash_fast_is_blank(&l_token_update_hash))
                l_token_hash = l_token_update_hash;
            else
                dap_hash_fast(a_token, a_token_size, &l_token_hash);
            l_hash_found = s_check_hal(a_ledger, &l_token_hash);
        }
        if (!l_hash_found) {
            DAP_DELETE(l_token);
            return ret;
        }
    }
    if (a_token_item)
        *a_token_item = l_token_item;
    if (a_token_out)
        *a_token_out = l_token;
    else
        DAP_DELETE(l_token);
    if (a_tsd_total_size)
        *a_tsd_total_size = l_size_tsd_section;
    if (a_signs_size)
        *a_signs_size = l_signs_size;
    return l_hash_found ? DAP_LEDGER_CHECK_WHITELISTED : DAP_LEDGER_CHECK_OK;
}

int dap_ledger_token_add_check(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size)
{
    dap_return_val_if_fail(a_ledger && a_token && a_token_size, DAP_LEDGER_CHECK_INVALID_ARGS);
    int ret = s_token_add_check(a_ledger, a_token, a_token_size, NULL, NULL, NULL, NULL, NULL);
    if (ret == DAP_LEDGER_CHECK_WHITELISTED)
        ret = DAP_LEDGER_CHECK_OK;
    return ret;
}

/**
 * @brief dap_ledger_token_ticker_check
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
dap_chain_datum_token_t *dap_ledger_token_ticker_check(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_return_val_if_fail(a_ledger && a_token_ticker, NULL);
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    return l_token_item ? l_token_item->datum_token : NULL;
}

/**
 * @brief Check if UTXO is blocked by token ticker (public wrapper for wallet cache)
 * @param a_ledger Ledger instance
 * @param a_token_ticker Token ticker string
 * @param a_tx_hash Transaction hash
 * @param a_out_idx Output index
 * @return true if UTXO is blocked, false otherwise
 */
bool dap_ledger_utxo_is_blocked_by_ticker(dap_ledger_t *a_ledger, const char *a_token_ticker,
                                          const dap_chain_hash_fast_t *a_tx_hash, int a_out_idx)
{
    if (!a_ledger || !a_token_ticker || !a_tx_hash)
        return false;
    
    // Find token item using internal function (has PVT() access)
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return false;
    
    // Check if UTXO blocking is disabled for this token
    if (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED)
        return false;
    
    // Use the standard blocking check from dap_chain_ledger_utxo.c
    return dap_ledger_utxo_is_blocked(l_token_item, (dap_chain_hash_fast_t *)a_tx_hash, a_out_idx, a_ledger);
}

/**
 * @brief update current_supply in token cache
 *
 * @param a_ledger ledger object
 * @param l_token_item token item object
 */
void s_ledger_token_cache_update(dap_ledger_t *a_ledger, dap_ledger_token_item_t *l_token_item)
{
    if (s_ledger_cache_storage_full())
        return; // storage full - cache writes are dropped until restart
    if (!PVT(a_ledger)->cached)
        return;
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TOKENS_STR);
    size_t l_cache_size = l_token_item->datum_token_size + sizeof(uint256_t);
    // Heap, not alloca: datum_token_size is unbounded (a large token datum
    // would blow the stack of the loading thread), and the (copying) async set
    // below is the only consumer.
    uint8_t *l_cache = DAP_NEW_Z_SIZE(uint8_t, l_cache_size);
    if ( !l_cache ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return;
    }
    memcpy(l_cache, &l_token_item->current_supply, sizeof(uint256_t));
    memcpy(l_cache + sizeof(uint256_t), l_token_item->datum_token, l_token_item->datum_token_size);
    if (dap_global_db_set(l_gdb_group, l_token_item->ticker, l_cache, l_cache_size, false, NULL, NULL)) {
        char *l_supply = dap_chain_balance_print(l_token_item->current_supply);
        log_it(L_WARNING, "Ledger cache mismatch, can't add token [%s] with supply %s", l_token_item->ticker, l_supply);
        DAP_DELETE(l_supply);
    }
    DAP_DELETE(l_cache);
    DAP_DELETE(l_gdb_group);
}

static bool s_ledger_token_supply_check(dap_ledger_token_item_t *a_token_item, uint256_t a_value)
{
    if ((IS_ZERO_256(a_token_item->total_supply) || IS_ZERO_256(a_value)))
        return true;
    if (compare256(a_token_item->current_supply, a_value) >= 0)
        return true;
    char *l_supply_str = dap_chain_balance_print(a_token_item->current_supply);
    char *l_value_str = dap_chain_balance_print(a_value);
    log_it(L_WARNING, "Token current supply %s < emission value %s", l_supply_str, l_value_str);
    DAP_DEL_MULTY(l_supply_str, l_value_str);
    return false;
}

static bool s_ledger_token_supply_check_update(dap_ledger_t *a_ledger, dap_ledger_token_item_t *a_token_item, uint256_t a_value, bool a_for_removing)
{
    assert(a_token_item);
    if ((IS_ZERO_256(a_token_item->total_supply) || IS_ZERO_256(a_value)))
        return true;
    if (!s_ledger_token_supply_check(a_token_item, a_value) && !a_for_removing)
        return false;
    int l_overflow = a_for_removing
        ? SUM_256_256(a_token_item->current_supply, a_value, &a_token_item->current_supply)
        : SUBTRACT_256_256(a_token_item->current_supply, a_value, &a_token_item->current_supply);
    assert(!l_overflow);
    const char *l_balance; dap_uint256_to_char(a_token_item->current_supply, &l_balance);
    log_it(L_NOTICE, "New current supply %s for token %s", l_balance, a_token_item->ticker);
    s_ledger_token_cache_update(a_ledger, a_token_item);
    return true;
}

/**
 * @brief dap_ledger_token_add
 * @param a_token
 * @param a_token_size
 * @return
 */
int dap_ledger_token_add(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size, dap_time_t a_creation_time)
{
    dap_return_val_if_fail(a_ledger && a_token && a_token_size, DAP_LEDGER_CHECK_INVALID_ARGS);
    dap_ledger_token_item_t *l_token_item = NULL;
    dap_chain_datum_token_t *l_token = NULL;
    size_t l_tsd_total_size = 0, l_signs_size = 0;
    dap_hash_fast_t l_token_update_hash;
    int ret = s_token_add_check(a_ledger, a_token, a_token_size, &l_token_item, &l_token,
                                &l_tsd_total_size, &l_signs_size, &l_token_update_hash);
    if (ret != DAP_LEDGER_CHECK_OK && ret != DAP_LEDGER_CHECK_WHITELISTED)
        return ret;

    if (!l_token_item) {
        assert(l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL);
        l_token_item = DAP_NEW_Z(dap_ledger_token_item_t);
        if ( !l_token_item ) {
            DAP_DELETE(l_token);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        *l_token_item = (dap_ledger_token_item_t) {
                .subtype            = l_token->subtype,
                .total_supply       = l_token->total_supply,
                .current_supply     = l_token->total_supply,
                .auth_signs_total   = l_token->signs_total,
                .auth_signs_valid   = l_token->signs_valid,
                .token_emissions_rwlock     = PTHREAD_RWLOCK_INITIALIZER,
                .token_ts_updated_rwlock    = PTHREAD_RWLOCK_INITIALIZER,
                .auth_pkeys         = DAP_NEW_Z_SIZE(dap_pkey_t*, sizeof(dap_pkey_t*) * l_token->signs_total),
                .auth_pkey_hashes   = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, sizeof(dap_chain_hash_fast_t) * l_token->signs_total),
                .flags = 0,
                .utxo_blocklist_rwlock      = PTHREAD_RWLOCK_INITIALIZER,
                .utxo_blocklist             = NULL,
                .utxo_blocklist_count       = 0
        };
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_token_item->flags = l_token->header_private_decl.flags; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_token_item->flags = l_token->header_native_decl.flags; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC:
            l_token_item->flags = l_token->header_public.flags; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:
        default:;
        }
        if ( !l_token_item->auth_pkeys ) {
            DAP_DEL_MULTY(l_token, l_token_item);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        };
        if ( !l_token_item->auth_pkey_hashes ) {
            DAP_DEL_MULTY(l_token, l_token_item->auth_pkeys, l_token_item);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        size_t l_auth_signs_total = l_token->signs_total;
        dap_sign_t **l_signs = dap_sign_get_unique_signs(l_token->tsd_n_signs + l_tsd_total_size,
                                                         l_signs_size,
                                                         &l_auth_signs_total);
#define CLEAN_UP DAP_DEL_MULTY(l_token, l_token_item->auth_pkeys, l_token_item->auth_pkey_hashes, l_token_item)
        if (!l_signs) {
            CLEAN_UP;
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        dap_stpcpy((char *)l_token_item->ticker, l_token->ticker);
        for (uint16_t k = 0; k < l_token_item->auth_signs_total; k++) {
            l_token_item->auth_pkeys[k] = dap_pkey_get_from_sign(l_signs[k]);
            if (!l_token_item->auth_pkeys[k]) {
                CLEAN_UP;
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
            }
            dap_pkey_get_hash(l_token_item->auth_pkeys[k], &l_token_item->auth_pkey_hashes[k]);
        }
#undef CLEAN_UP
        DAP_DELETE(l_signs);
        l_token_item->datum_token_size = sizeof(dap_chain_datum_token_t) + l_tsd_total_size + l_signs_size;
        l_token_item->datum_token = l_token;
        pthread_rwlock_wrlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_ADD_STR(PVT(a_ledger)->tokens, ticker, l_token_item);
    } else {
        // A DECL for a token the ledger already knows: on a snapshot-based start
        // the item can have been created from a section/GDB record without its
        // declaration bytes, and the ledger_state dump then wrote token_size = 0
        // for it - the next start could not recreate the token at all (measured
        // on cf-mm-0: the section shrank from 1.07 GB to 393 MB across restarts
        // and `token info -name QEVM` stopped finding a token the ledger had held
        // since 17 Oct). Adopt the declaration here so the state stays complete.
        if (l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL && !l_token_item->datum_token) {
            l_token_item->datum_token_size = sizeof(dap_chain_datum_token_t) + l_tsd_total_size + l_signs_size;
            l_token_item->datum_token = l_token;
            s_ledger_token_cache_update(a_ledger, l_token_item);
            return DAP_LEDGER_CHECK_OK;
        }
        assert(l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE);
        pthread_rwlock_wrlock(&PVT(a_ledger)->tokens_rwlock);
        dap_ledger_token_update_item_t *l_token_update_item = NULL;
        pthread_rwlock_wrlock(&l_token_item->token_ts_updated_rwlock);
        HASH_FIND(hh, l_token_item->token_ts_updated, &l_token_update_hash, sizeof(dap_hash_fast_t), l_token_update_item);
        if (l_token_update_item) {
            pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
            pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
            log_it(L_ERROR, "Token update with hash %s already exist in token %s hash-table",
                            dap_hash_fast_to_str_static(&l_token_update_hash), l_token->ticker);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_APPLY_ERROR;
        }
        l_token_update_item = DAP_NEW(dap_ledger_token_update_item_t);
        if (!l_token_update_item) {
            pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
            pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_token);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
        }
        *l_token_update_item = (dap_ledger_token_update_item_t) {
                .update_token_hash			= l_token_update_hash,
                .datum_token_update			= l_token,
                .datum_token_update_size	= sizeof(dap_chain_datum_token_t) + l_tsd_total_size + l_signs_size,
                .updated_time               = dap_time_now()
        };
        HASH_ADD(hh, l_token_item->token_ts_updated, update_token_hash, sizeof(dap_chain_hash_fast_t), l_token_update_item);
        pthread_rwlock_unlock(&l_token_item->token_ts_updated_rwlock);
        l_token_item->last_update_token_time = l_token_update_item->updated_time;
    }
    if (ret != DAP_LEDGER_CHECK_WHITELISTED) {
        ret = s_token_tsd_parse(l_token_item, l_token, a_ledger, l_token->tsd_n_signs, l_tsd_total_size, true, &l_token_update_hash);
        assert(ret == DAP_LEDGER_CHECK_OK);
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    const char *l_balance_dbg = NULL, *l_declare_update_str = NULL, *l_type_str = NULL;
    if (s_debug_more)
        dap_uint256_to_char(l_token->total_supply, &l_balance_dbg);
    switch (l_token->type) {
    case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:       l_declare_update_str = "declared"; break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:     l_declare_update_str = "updated"; break;
    default: assert(false); break;
    }
    switch (l_token->subtype) {
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:  l_type_str = "Simple"; break;
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE: l_type_str = "Private"; break;
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:  l_type_str = "CF20"; break;
    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC:  l_type_str = "Public"; break;
    default: assert(false); break;
    }
    debug_if(s_debug_more, L_INFO, "%s token %s has been %s, total_supply: %s, signs_valid: %zu, signs_total: %zu",
                                l_type_str, l_token_item->ticker, l_declare_update_str,
                                l_balance_dbg, l_token_item->auth_signs_valid, l_token_item->auth_signs_total);
    s_ledger_token_cache_update(a_ledger, l_token_item);
    return ret;
}

int dap_ledger_token_load(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size, dap_time_t a_creation_time)
{
    if (dap_chain_net_get_load_mode(a_ledger->net)) {
        const char *l_ticker = NULL;
        switch (*(uint16_t *)a_token) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
            l_ticker = ((dap_chain_datum_token_t *)a_token)->ticker;
            break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL:
            l_ticker = ((dap_chain_datum_token_old_t *)a_token)->ticker;
            break;
        }
        if (l_ticker && s_ledger_find_token(a_ledger, l_ticker))
            return DAP_LEDGER_CHECK_OK;
    }
    return dap_ledger_token_add(a_ledger, a_token, a_token_size, a_creation_time);
}

static bool s_pack_ledger_threshold_info_json (json_object *a_json_arr_out, dap_ledger_tx_item_t *a_tx_item, int a_version)
{
    json_object *json_obj_tx = json_object_new_object();
    if (!json_obj_tx) 
        return 1;
    char l_tx_prev_hash_str[DAP_HASH_FAST_STR_SIZE]={0};
    char l_time[DAP_TIME_STR_SIZE] = {0};
    dap_chain_hash_fast_to_str(&a_tx_item->tx_hash_fast,l_tx_prev_hash_str,sizeof(l_tx_prev_hash_str));
    dap_time_to_str_rfc822(l_time, sizeof(l_time), a_tx_item->cache_data.ts_created);
    json_object_object_add(json_obj_tx, a_version == 1 ? "Ledger thresholded tx_hash_fast" : "tx_hash", json_object_new_string(l_tx_prev_hash_str));
    json_object_object_add(json_obj_tx, "time_created", json_object_new_string(l_time));
    json_object_object_add(json_obj_tx, "tx_item_size", json_object_new_int(a_tx_item->tx->header.tx_items_size));
    json_object_array_add(a_json_arr_out, json_obj_tx);
    return 0;
}
static bool s_pack_ledger_balance_info_json (json_object *a_json_arr_out, dap_ledger_wallet_balance_t *a_balance_item, int a_version)
{
    json_object* json_obj_tx = json_object_new_object();
        
        json_object_object_add(json_obj_tx, a_version == 1 ? "Ledger balance key" : "balance_key", json_object_new_string(a_balance_item->key));
        json_object_object_add(json_obj_tx, "token_ticker", json_object_new_string(a_balance_item->token_ticker));
        json_object_object_add(json_obj_tx, "balance", json_object_new_string(dap_uint256_to_char(a_balance_item->balance, NULL)));
        json_object_array_add(a_json_arr_out, json_obj_tx);
    return 0;
}

// D5: flat value-only snapshots of the fields s_pack_ledger_threshold_info_json/
// s_pack_ledger_balance_info_json actually read, so dap_ledger_threshold_info()/
// dap_ledger_balance_info() can collect the requested page under a short rdlock and
// build all json_object's afterwards, instead of holding threshold_txs_rwlock/
// balance_accounts_rwlock for the whole JSON serialization pass (same lock-held-
// during-serialize class of issue already fixed for DEX in stage C1).
typedef struct ledger_threshold_snapshot {
    dap_hash_fast_t tx_hash_fast;
    dap_time_t ts_created;
    uint32_t tx_items_size;
} ledger_threshold_snapshot_t;

typedef struct ledger_balance_snapshot {
    char *key;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t balance;
} ledger_balance_snapshot_t;

static bool s_pack_ledger_threshold_snapshot_json(json_object *a_json_arr_out, const ledger_threshold_snapshot_t *a_snap, int a_version)
{
    json_object *json_obj_tx = json_object_new_object();
    if (!json_obj_tx)
        return 1;
    char l_tx_prev_hash_str[DAP_HASH_FAST_STR_SIZE] = {0};
    char l_time[DAP_TIME_STR_SIZE] = {0};
    dap_chain_hash_fast_to_str(&a_snap->tx_hash_fast, l_tx_prev_hash_str, sizeof(l_tx_prev_hash_str));
    dap_time_to_str_rfc822(l_time, sizeof(l_time), a_snap->ts_created);
    json_object_object_add(json_obj_tx, a_version == 1 ? "Ledger thresholded tx_hash_fast" : "tx_hash", json_object_new_string(l_tx_prev_hash_str));
    json_object_object_add(json_obj_tx, "time_created", json_object_new_string(l_time));
    json_object_object_add(json_obj_tx, "tx_item_size", json_object_new_int(a_snap->tx_items_size));
    json_object_array_add(a_json_arr_out, json_obj_tx);
    return 0;
}

static void s_pack_ledger_balance_snapshot_json(json_object *a_json_arr_out, const ledger_balance_snapshot_t *a_snap, int a_version)
{
    json_object *json_obj_tx = json_object_new_object();
    json_object_object_add(json_obj_tx, a_version == 1 ? "Ledger balance key" : "balance_key", json_object_new_string(a_snap->key));
    json_object_object_add(json_obj_tx, "token_ticker", json_object_new_string(a_snap->token_ticker));
    json_object_object_add(json_obj_tx, "balance", json_object_new_string(dap_uint256_to_char(a_snap->balance, NULL)));
    json_object_array_add(a_json_arr_out, json_obj_tx);
}
json_object *dap_ledger_threshold_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, dap_chain_hash_fast_t *a_threshold_hash, bool a_head, int a_version)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_tx_item = NULL, *l_tx_tmp;
    json_object *json_arr_out = json_object_new_array();
    if (!json_arr_out)
        return NULL;
    size_t l_arr_start = 0;
    size_t l_arr_end = 0;
    dap_chain_set_offset_limit_json(json_arr_out, &l_arr_start, &l_arr_end, a_limit, a_offset, HASH_COUNT(l_ledger_pvt->threshold_txs),false);

    if (a_threshold_hash) {
        // Single lookup, no page to build - a short rdlock around the HASH_FIND is enough,
        // the JSON built here is tiny and value-only (found/not-found), no need for a snapshot.
        pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
        HASH_FIND(hh, l_ledger_pvt->threshold_txs, a_threshold_hash, sizeof(dap_hash_t), l_tx_item);
        bool l_found = l_tx_item != NULL;
        pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
        json_object *json_obj_tx = json_object_new_object();
        if (!json_obj_tx) {
            json_object_put(json_arr_out);
            return NULL;
        }
        if (l_found)
            json_object_object_add(json_obj_tx, a_version == 1 ? "Hash was found in ledger tx threshold" : "tx_hash", json_object_new_string(dap_hash_fast_to_str_static(a_threshold_hash)));
        else
            json_object_object_add(json_obj_tx, a_version == 1 ? "Hash wasn't found in ledger" : "tx_hash", json_object_new_string("empty"));
        json_object_array_add(json_arr_out, json_obj_tx);
    } else {
        // D5: collect the requested page as flat POD snapshots under rdlock, release the
        // lock, then build all json_object's - avoids holding threshold_txs_rwlock for the
        // whole serialization pass (lock-held-during-serialize, same class as DEX C1).
        // Snapshot capacity is l_arr_end - l_arr_start (dap_chain_set_offset_limit_json
        // clamps l_arr_end to the table size when a_limit==0/"unlimited"), not a_limit itself.
        size_t l_snap_cap = l_arr_end > l_arr_start ? l_arr_end - l_arr_start : 0;
        ledger_threshold_snapshot_t *l_snap = l_snap_cap ? DAP_NEW_Z_COUNT(ledger_threshold_snapshot_t, l_snap_cap) : NULL;
        size_t l_snap_count = 0;
        size_t i_tmp = 0;
        pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
        if (a_head)
            HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp) {
                if (i_tmp < l_arr_start || i_tmp >= l_arr_end) {
                    i_tmp++;
                    continue;
                }
                i_tmp++;
                if (l_snap && l_snap_count < l_snap_cap) {
                    l_snap[l_snap_count++] = (ledger_threshold_snapshot_t){
                        .tx_hash_fast = l_tx_item->tx_hash_fast,
                        .ts_created = l_tx_item->cache_data.ts_created,
                        .tx_items_size = l_tx_item->tx->header.tx_items_size
                    };
                }
            }
        else {
            l_tx_item = HASH_LAST(l_ledger_pvt->threshold_txs);
            for(; l_tx_item; l_tx_item = l_tx_item->hh.prev, i_tmp++){
                if (i_tmp < l_arr_start || i_tmp >= l_arr_end)
                    continue;
                if (l_snap && l_snap_count < l_snap_cap) {
                    l_snap[l_snap_count++] = (ledger_threshold_snapshot_t){
                        .tx_hash_fast = l_tx_item->tx_hash_fast,
                        .ts_created = l_tx_item->cache_data.ts_created,
                        .tx_items_size = l_tx_item->tx->header.tx_items_size
                    };
                }
            }
        }
        pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);

        uint32_t l_counter = 0;
        for (size_t i = 0; i < l_snap_count; i++) {
            if (s_pack_ledger_threshold_snapshot_json(json_arr_out, &l_snap[i], a_version)) {
                DAP_DELETE(l_snap);
                json_object_put(json_arr_out);
                return NULL;
            }
            l_counter++;
        }
        DAP_DELETE(l_snap);
        if (!l_counter) {
            json_object* json_obj_tx = json_object_new_object();
            json_object_object_add(json_obj_tx, "status", json_object_new_string("0 items in ledger tx threshold"));
            json_object_array_add(json_arr_out, json_obj_tx);
        }
    }

    return json_arr_out;
}

json_object *dap_ledger_balance_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, bool a_head, int a_version)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    json_object * json_arr_out = json_object_new_array();
    dap_ledger_wallet_balance_t *l_balance_item, *l_balance_tmp;
    size_t l_arr_start = 0;
    size_t l_arr_end = 0;
    dap_chain_set_offset_limit_json(json_arr_out, &l_arr_start, &l_arr_end, a_limit, a_offset, HASH_COUNT(l_ledger_pvt->balance_accounts),false);

    // D5: same snapshot-then-serialize pattern as dap_ledger_threshold_info() above -
    // collect the requested page as flat POD snapshots (key is duplicated, since the
    // original dap_ledger_wallet_balance_t.key string lives only as long as the item)
    // under rdlock, then build json_object's after unlock.
    size_t l_snap_cap = l_arr_end > l_arr_start ? l_arr_end - l_arr_start : 0;
    ledger_balance_snapshot_t *l_snap = l_snap_cap ? DAP_NEW_Z_COUNT(ledger_balance_snapshot_t, l_snap_cap) : NULL;
    size_t l_snap_count = 0;
    size_t i_tmp = 0;
    pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
    if (a_head)
        HASH_ITER(hh, l_ledger_pvt->balance_accounts, l_balance_item, l_balance_tmp) {
            if (i_tmp < l_arr_start || i_tmp >= l_arr_end) {
                i_tmp++;
                continue;
            }
            i_tmp++;
            if (l_snap && l_snap_count < l_snap_cap) {
                l_snap[l_snap_count].key = dap_strdup(l_balance_item->key);
                dap_strncpy(l_snap[l_snap_count].token_ticker, l_balance_item->token_ticker, sizeof(l_snap[l_snap_count].token_ticker) - 1);
                l_snap[l_snap_count].balance = l_balance_item->balance;
                l_snap_count++;
            }
        }
    else {
        l_balance_item = HASH_LAST(l_ledger_pvt->balance_accounts);
            for(; l_balance_item; l_balance_item = l_balance_item->hh.prev, i_tmp++){
                if (i_tmp < l_arr_start || i_tmp >= l_arr_end)
                    continue;
                if (l_snap && l_snap_count < l_snap_cap) {
                    l_snap[l_snap_count].key = dap_strdup(l_balance_item->key);
                    dap_strncpy(l_snap[l_snap_count].token_ticker, l_balance_item->token_ticker, sizeof(l_snap[l_snap_count].token_ticker) - 1);
                    l_snap[l_snap_count].balance = l_balance_item->balance;
                    l_snap_count++;
                }
            }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);

    uint32_t l_counter = 0;
    for (size_t i = 0; i < l_snap_count; i++) {
        s_pack_ledger_balance_snapshot_json(json_arr_out, &l_snap[i], a_version);
        DAP_DELETE(l_snap[i].key);
        l_counter++;
    }
    DAP_DELETE(l_snap);
    if (!l_counter){
        json_object* json_obj_tx = json_object_new_object();
        json_object_object_add(json_obj_tx, a_version == 1 ? "No items in ledger balance_accounts" : "info_status", json_object_new_string("empty"));
        json_object_array_add(json_arr_out, json_obj_tx);
    } 
    return json_arr_out;
}

/**
 * @breif dap_ledger_token_get_auth_signs_valid
 * @param a_ledger
 * @param a_token_ticker
 * @return 0 if no ticker found
 */
size_t dap_ledger_token_get_auth_signs_valid(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return 0;
    return l_token_item->auth_signs_valid;
}

/**
 * @breif dap_ledger_token_get_auth_signs_total
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
size_t dap_ledger_token_get_auth_signs_total(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return 0;
    return l_token_item->auth_signs_total;
}

/**
 * @breif dap_ledger_token_auth_signs_hashes
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
dap_list_t *dap_ledger_token_get_auth_pkeys_hashes(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_list_t *l_ret = NULL;
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return l_ret;
    debug_if(s_debug_more, L_INFO, " ! Token %s : total %zu auth signs", a_token_ticker, l_token_item->auth_signs_total);
    for (size_t i = 0; i < l_token_item->auth_signs_total; i++)
        l_ret = dap_list_append(l_ret, l_token_item->auth_pkey_hashes + i);
    return l_ret;
}

uint256_t dap_ledger_token_get_emission_rate(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    if (!l_token_item || !l_token_item->is_delegated)
        return uint256_0;
    return l_token_item->emission_rate;
}

json_object *s_token_item_to_json(dap_ledger_token_item_t *a_token_item, int a_version, int a_history_limit)
{
    json_object *json_obj_datum = json_object_new_object();
    const char *l_type_str = NULL;
    switch (a_token_item->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:
            l_type_str = "SIMPLE"; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            l_type_str = "PRIVATE"; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            l_type_str = "CF20"; break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC:
            l_type_str = "PUBLIC"; break;
        default: l_type_str = "UNKNOWN"; break;
    }
    json_object_object_add(json_obj_datum, a_version == 1 ? "-->Token name" : "token_name", json_object_new_string(a_token_item->ticker));
    json_object_object_add(json_obj_datum, a_version == 1 ? "type" : "subtype", json_object_new_string(l_type_str));
    if (a_token_item->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE && a_token_item->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC) {
        dap_chain_datum_token_flags_dump_to_json(json_obj_datum, "flags", a_token_item->flags);
        json_object_object_add(json_obj_datum, "description", a_token_item->description ?
                               json_object_new_string(a_token_item->description) :
                               json_object_new_string("The token description is not set"));
    }
    json_object_object_add(json_obj_datum, a_version == 1 ? "Supply current" : "supply_current", json_object_new_string(dap_uint256_to_char(a_token_item->current_supply, NULL)));
    json_object_object_add(json_obj_datum, a_version == 1 ? "Supply total" : "supply_total", json_object_new_string(dap_uint256_to_char(a_token_item->total_supply, NULL)));
    json_object_object_add(json_obj_datum, a_version == 1 ? "Decimals" : "decimals", json_object_new_string("18"));
    json_object_object_add(json_obj_datum, a_version == 1 ? "Auth signs valid" : "auth_sig_valid", json_object_new_int(a_token_item->auth_signs_valid));
    json_object_object_add(json_obj_datum, a_version == 1 ? "Auth signs total" : "auth_sig_total", json_object_new_int(a_token_item->auth_signs_total));
    json_object *l_json_arr_pkeys = json_object_new_array();
    for (uint16_t i = 0; i < a_token_item->auth_signs_total; i++) {
        json_object *l_json_obj_out = json_object_new_object();
        json_object_object_add(l_json_obj_out, "line", json_object_new_int(i));
        json_object_object_add(l_json_obj_out, a_version == 1 ? "hash" : "pkey_hash", json_object_new_string(dap_hash_fast_to_str_static(a_token_item->auth_pkey_hashes + i)));
        json_object_object_add(l_json_obj_out, "pkey_type", json_object_new_string(dap_pkey_type_to_str(a_token_item->auth_pkeys[i]->header.type)));
        json_object_object_add(l_json_obj_out, a_version == 1 ? "bytes" : "pkey_size", json_object_new_int(a_token_item->auth_pkeys[i]->header.size));
        json_object_array_add(l_json_arr_pkeys, l_json_obj_out);
    }
    json_object *l_json_arr_tx_recv_allow = json_object_new_array();
    for (size_t i = 0; i < a_token_item->tx_recv_allow_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_recv_allow[i].addr;
        json_object_array_add(l_json_arr_tx_recv_allow, json_object_new_string(dap_chain_addr_to_str_static(&l_addr)));
    }
    json_object *l_json_arr_tx_recv_block = json_object_new_array();
    for (size_t i = 0; i < a_token_item->tx_recv_block_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_recv_block[i].addr;
        json_object_array_add(l_json_arr_tx_recv_block, json_object_new_string(dap_chain_addr_to_str_static(&l_addr)));
    }
    json_object *l_json_arr_tx_send_allow = json_object_new_array();
    for (size_t i = 0; i < a_token_item->tx_send_allow_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_send_allow[i].addr;
        json_object_array_add(l_json_arr_tx_send_allow, json_object_new_string(dap_chain_addr_to_str_static(&l_addr)));
    }
    json_object *l_json_arr_tx_send_block = json_object_new_array();
    for (size_t i = 0; i < a_token_item->tx_send_block_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_send_block[i].addr;
        json_object_array_add(l_json_arr_tx_send_block, json_object_new_string(dap_chain_addr_to_str_static(&l_addr)));
    }
    json_object_object_add(json_obj_datum, a_version == 1 ? "Signatures public keys" : "sig_pkeys", l_json_arr_pkeys);
    a_token_item->tx_recv_allow_size ? json_object_object_add(json_obj_datum, "tx_recv_allow", l_json_arr_tx_recv_allow) :
        json_object_put(l_json_arr_tx_recv_allow);
    a_token_item->tx_recv_block_size ? json_object_object_add(json_obj_datum, "tx_recv_block", l_json_arr_tx_recv_block) :
        json_object_put(l_json_arr_tx_recv_block);
    a_token_item->tx_send_allow_size ? json_object_object_add(json_obj_datum, "tx_send_allow", l_json_arr_tx_send_allow) :
        json_object_put(l_json_arr_tx_send_allow);
    a_token_item->tx_send_block_size ? json_object_object_add(json_obj_datum, "tx_send_block", l_json_arr_tx_send_block) :
        json_object_put(l_json_arr_tx_send_block);
    
    // UTXO blocklist information
    // Read all data under single rwlock protection to avoid race conditions
    pthread_rwlock_rdlock(&a_token_item->utxo_blocklist_rwlock);
    size_t l_utxo_count = atomic_load_explicit(&a_token_item->utxo_blocklist_count, memory_order_relaxed);
    json_object_object_add(json_obj_datum, "utxo_blocklist_count", json_object_new_int64((int64_t)l_utxo_count));
    
    if (l_utxo_count > 0) {
        json_object *l_json_arr_utxo_blocklist = json_object_new_array();
        
        dap_ledger_utxo_block_item_t *l_utxo_item, *l_tmp;
        
        HASH_ITER(hh, a_token_item->utxo_blocklist, l_utxo_item, l_tmp) {
            json_object *l_json_utxo = json_object_new_object();
            char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_utxo_item->key.tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
            
            json_object_object_add(l_json_utxo, "tx_hash", json_object_new_string(l_tx_hash_str));
            json_object_object_add(l_json_utxo, "out_idx", json_object_new_int(l_utxo_item->key.out_idx));
            json_object_object_add(l_json_utxo, "blocked_time", json_object_new_uint64((uint64_t)l_utxo_item->blocked_time));
            json_object_object_add(l_json_utxo, "becomes_effective", json_object_new_uint64((uint64_t)l_utxo_item->becomes_effective));
            if (l_utxo_item->becomes_unblocked != 0) {
                json_object_object_add(l_json_utxo, "becomes_unblocked", json_object_new_uint64((uint64_t)l_utxo_item->becomes_unblocked));
            }
            
            // Add history for this UTXO
            pthread_rwlock_rdlock(&l_utxo_item->history_rwlock);
            if (l_utxo_item->history_head) {
                json_object *l_json_arr_history = json_object_new_array();
                int l_history_count = 0;
                
                // Iterate from tail (newest) to head (oldest)
                // Use limit from parameter (0 = unlimited)
                dap_ledger_utxo_block_history_item_t *l_hist = l_utxo_item->history_tail;
                while (l_hist && (a_history_limit == 0 || l_history_count < a_history_limit)) {
                    json_object *l_json_hist = json_object_new_object();
                    
                    const char *l_action_str = "";
                    switch (l_hist->action) {
                        case BLOCK_ACTION_ADD: l_action_str = "ADD"; break;
                        case BLOCK_ACTION_REMOVE: l_action_str = "REMOVE"; break;
                        case BLOCK_ACTION_CLEAR: l_action_str = "CLEAR"; break;
                        default: l_action_str = "UNKNOWN";
                    }
                    
                    char l_update_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(&l_hist->token_update_hash, l_update_hash_str, sizeof(l_update_hash_str));
                    
                    json_object_object_add(l_json_hist, "action", json_object_new_string(l_action_str));
                    json_object_object_add(l_json_hist, "bc_time", json_object_new_uint64((uint64_t)l_hist->bc_time));
                    json_object_object_add(l_json_hist, "token_update_hash", json_object_new_string(l_update_hash_str));
                    
                    json_object_array_add(l_json_arr_history, l_json_hist);
                    l_history_count++;
                    l_hist = l_hist->prev;  // Go backwards (newest to oldest)
                }
                
                json_object_object_add(l_json_utxo, "history_recent", l_json_arr_history);
                
                // Count total history items
                int l_total_history = 0;
                l_hist = l_utxo_item->history_head;
                while (l_hist) {
                    l_total_history++;
                    l_hist = l_hist->next;
                }
                json_object_object_add(l_json_utxo, "history_total_count", json_object_new_int(l_total_history));
            }
            pthread_rwlock_unlock(&l_utxo_item->history_rwlock);
            
            json_object_array_add(l_json_arr_utxo_blocklist, l_json_utxo);
        }
        
        json_object_object_add(json_obj_datum, "utxo_blocklist", l_json_arr_utxo_blocklist);
    }
    
    pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
    
    json_object_object_add(json_obj_datum, a_version == 1 ? "Total emissions" : "total_emissions", json_object_new_int(HASH_COUNT(a_token_item->token_emissions)));
    return json_obj_datum;
}

/**
 * @brief Compose string list of all tokens with information
 * @param a_ledger
 * @return
 */
json_object *dap_ledger_token_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, int a_version, int a_history_limit)
{
    json_object * json_obj_datum;
    json_object * json_arr_out = json_object_new_array();
    dap_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    size_t l_arr_start = 0;
    if (a_offset > 0) {
        l_arr_start = a_offset;
        json_object* json_obj_tx = json_object_new_object();
        json_object_object_add(json_obj_tx, "offset", json_object_new_int(l_arr_start));
        json_object_array_add(json_arr_out, json_obj_tx);        
    }
    size_t l_arr_end = HASH_COUNT(PVT(a_ledger)->tokens);
    if (a_limit) {
        json_object* json_obj_tx = json_object_new_object();
        json_object_object_add(json_obj_tx, "limit", json_object_new_int(a_limit));
        json_object_array_add(json_arr_out, json_obj_tx);
        l_arr_end = l_arr_start + a_limit;
        if (l_arr_end > HASH_COUNT(PVT(a_ledger)->tokens)) {
            l_arr_end = HASH_COUNT(PVT(a_ledger)->tokens);
        }
    }
    size_t i = 0;
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (i < l_arr_start || i >= l_arr_end) {
            i++;
            continue;
        }
        json_obj_datum = s_token_item_to_json(l_token_item, a_version, a_history_limit);
        json_object_array_add(json_arr_out, json_obj_datum);
        i++;
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return json_arr_out;
}

/**
 * @breif Forms a JSON object with a token description for the specified ticker.
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
json_object *dap_ledger_token_info_by_name(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version, int a_history_limit)
{
    // s_ledger_find_token() takes tokens_rwlock around the HASH_FIND: that table is
    // mutated under wrlock elsewhere in this file (token add/update), so a bare
    // unlocked HASH_FIND_STR here (as this used to be) races against it, same class
    // of bug already fixed for blocks/dag hash tables and srv_stake's itemlist.
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    if (l_token_item)
        return s_token_item_to_json(l_token_item, a_version, a_history_limit);
    return json_object_new_null();
}

/**
 * @brief Get all token declatations
 * @param a_ledger
 * @return
 */
dap_list_t* dap_ledger_token_decl_all(dap_ledger_t *a_ledger)
{
    dap_list_t * l_ret = NULL;
    dap_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);

    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        dap_chain_datum_token_t *l_token = l_token_item->datum_token;
        l_ret = dap_list_append(l_ret, l_token);
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_ret;
}


/**
 * @brief s_threshold_txs_proc
 * @param a_ledger
 */
static void s_threshold_txs_proc( dap_ledger_t *a_ledger)
{
    bool l_success;
    dap_ledger_private_t * l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->threshold_txs_rwlock);
    do {
        l_success = false;
        dap_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
        HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp) {
            int l_res = dap_ledger_tx_add(a_ledger, l_tx_item->tx, &l_tx_item->tx_hash_fast, true, NULL);
            if (l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION &&
                    l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS) {
                HASH_DEL(l_ledger_pvt->threshold_txs, l_tx_item);
                if (l_tx_item->tx_owned)
                    DAP_DELETE(l_tx_item->tx);
                DAP_DELETE(l_tx_item);
                l_success = true;
            } else if (l_res == 0) {
                a_ledger->net->pub.chains->callback_count_tx_increase(a_ledger->net->pub.chains);
            }
        }
    } while (l_success);
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
}

/**
 * @breif s_treshold_txs_free
 * @param a_ledger
 */
static void s_threshold_txs_free(dap_ledger_t *a_ledger)
{
    log_it(L_DEBUG, "Start free threshold txs");
    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_current = NULL, *l_tmp = NULL;
    dap_nanotime_t l_time_cut_off = dap_nanotime_now() - dap_nanotime_from_sec(7200); //7200 sec = 2 hours.
    pthread_rwlock_wrlock(&l_pvt->threshold_txs_rwlock);
    HASH_ITER(hh, l_pvt->threshold_txs, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            HASH_DEL(l_pvt->threshold_txs, l_current);
            char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_current->tx_hash_fast, l_tx_hash_str, sizeof(l_tx_hash_str));
            if (l_current->tx_owned)
                DAP_DELETE(l_current->tx);
            DAP_DELETE(l_current);
            log_it(L_NOTICE, "Removed transaction %s form threshold ledger", l_tx_hash_str);
        }
    }
    pthread_rwlock_unlock(&l_pvt->threshold_txs_rwlock);
}

static void s_load_cache_finish(dap_ledger_t *a_ledger);
static bool s_load_cache_gdb_loaded_txs_callback(dap_global_db_instance_t *a_dbi, int a_rc,
        const char *a_group, const size_t a_values_total, const size_t a_values_count,
        dap_global_db_obj_t *a_values, void *a_arg);
static bool s_load_cache_gdb_loaded_stake_lock_callback(dap_global_db_instance_t *a_dbi, int a_rc,
        const char *a_group, const size_t a_values_total, const size_t a_values_count,
        dap_global_db_obj_t *a_values, void *a_arg);

/* Hands the load over to the next cache group. The loader thread waits for the chain to reach
 * its last stage, so a request that cannot even be queued must end the load here instead of
 * leaving that thread waiting forever. */
static void s_load_cache_next_stage(dap_ledger_t *a_ledger, const char *a_suffix,
                                    dap_global_db_callback_results_t a_callback)
{
    // Snapshot mode: the tx and balances groups are served by the snapshot
    // file, not by GlobalDB - skip straight past them
    if (PVT(a_ledger)->snapshot_mode
            && (!strcmp(a_suffix, DAP_LEDGER_TXS_STR) || !strcmp(a_suffix, DAP_LEDGER_BALANCES_STR))) {
        debug_if(s_debug_more, L_INFO, "Ledger cache: %s group is served by the snapshot, skipping", a_suffix);
        if (!strcmp(a_suffix, DAP_LEDGER_BALANCES_STR))
            s_load_cache_finish(a_ledger); // nothing left to read from GlobalDB
        else
            s_load_cache_next_stage(a_ledger, DAP_LEDGER_BALANCES_STR, a_callback);
        return;
    }
    // A COMPLETE snapshot carries tokens, emissions and stake-lock marks in its own
    // ledger_state section, which is applied at load end - after this GDB stage chain
    // has finished. Reading those groups here would run BEFORE the tokens exist (the
    // tokens themselves come from the same section), so every emission record was
    // dropped with "Not found token with ticker" on a node whose GDB had been reset
    // (535k of them on 0-rpc). The section is authoritative for the covered height;
    // the tail above it re-applies its datums through the live path anyway.
    if (PVT(a_ledger)->snapshot_mode && PVT(a_ledger)->snapshot_full) {
        if (!strcmp(a_suffix, DAP_LEDGER_EMISSIONS_STR)) {
            log_it(L_NOTICE, "Ledger cache: %s group is carried by the complete snapshot, skipping", a_suffix);
            s_load_cache_next_stage(a_ledger, DAP_LEDGER_STAKE_LOCK_STR,
                                    s_load_cache_gdb_loaded_stake_lock_callback);
            return;
        }
        if (!strcmp(a_suffix, DAP_LEDGER_STAKE_LOCK_STR)) {
            log_it(L_NOTICE, "Ledger cache: %s group is carried by the complete snapshot, skipping", a_suffix);
            s_load_cache_next_stage(a_ledger, DAP_LEDGER_TXS_STR, s_load_cache_gdb_loaded_txs_callback);
            return;
        }
    }
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, a_suffix);
    log_it(L_NOTICE, "Ledger cache: reading group %s", l_gdb_group);
    if (dap_global_db_get_all(l_gdb_group, 0, a_callback, a_ledger) != 0) {
        log_it(L_WARNING, "Ledger cache: can't start reading group %s, finishing the load early", l_gdb_group);
        s_load_cache_finish(a_ledger);
    }
    DAP_DELETE(l_gdb_group);
}

/**
 * @brief s_load_cache_gdb_loaded_balances_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static bool s_load_cache_gdb_loaded_balances_callback(dap_global_db_instance_t *a_dbi,
                                                      int a_rc, const char *a_group,
                                                      const size_t a_values_total, const size_t a_values_count,
                                                      dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t * l_ledger = (dap_ledger_t*) a_arg;
    dap_ledger_private_t * l_ledger_pvt = PVT(l_ledger);
    for (size_t i = 0; i < a_values_count; i++) {
        dap_ledger_wallet_balance_t *l_balance_item = DAP_NEW_Z(dap_ledger_wallet_balance_t);
        if (!l_balance_item) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return false;
        }
        l_balance_item->key = dap_strdup(a_values[i].key);
        if (!l_balance_item->key) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DEL_Z(l_balance_item);
            return false;
        }
        char *l_ptr = strchr(l_balance_item->key, ' ');
        if (l_ptr++) {
            dap_strncpy(l_balance_item->token_ticker, l_ptr, sizeof(l_balance_item->token_ticker) - 1);
        }
        l_balance_item->balance = *(uint256_t *)a_values[i].value;
        HASH_ADD_KEYPTR(hh, l_ledger_pvt->balance_accounts, l_balance_item->key,
                        strlen(l_balance_item->key), l_balance_item);
        /* Notify the world */
        /*struct json_object *l_json = wallet_info_json_collect(a_ledger, l_balance_item);
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);*/ // TODO: unstable and spammy
    }
    pthread_mutex_lock( &l_ledger_pvt->load_mutex );
    l_ledger_pvt->load_end = true;
    pthread_cond_broadcast( &l_ledger_pvt->load_cond );
    pthread_mutex_unlock( &l_ledger_pvt->load_mutex );
    return true;
}

/**
 * @brief s_load_cache_gdb_loaded_txs_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static bool s_load_cache_gdb_loaded_txs_callback(dap_global_db_instance_t *a_dbi,
                                                 int a_rc, const char *a_group,
                                                 const size_t a_values_total, const size_t a_values_count,
                                                 dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t * l_ledger = (dap_ledger_t*) a_arg;
    dap_ledger_private_t * l_ledger_pvt = PVT(l_ledger);
    if (a_rc) {
        log_it(L_WARNING, "Ledger cache: txs group read failed (rc %d), continuing without cached txs", a_rc);
        // Skip straight to the balances stage so the loader gets completed.
        s_load_cache_next_stage(l_ledger, DAP_LEDGER_BALANCES_STR, s_load_cache_gdb_loaded_balances_callback);
        return false;
    }
    // A malformed record must not abort the whole load: the loader thread waits for the chain
    // to reach its last stage, so whatever is skipped here is skipped, nothing hangs.
    for (size_t i = 0; i < a_values_count; i++) {
        dap_ledger_cache_gdb_record_t *l_current_record = (dap_ledger_cache_gdb_record_t*)a_values[i].value;
        if (a_values[i].value_len != l_current_record->cache_size + l_current_record->datum_size + sizeof(dap_ledger_cache_gdb_record_t)) {
            log_it(L_ERROR, "Worng ledger_cache_gdb_record size");
            break;
        }
        dap_ledger_tx_item_t *l_tx_item = DAP_NEW_Z_SIZE(dap_ledger_tx_item_t, sizeof(dap_ledger_tx_item_t) - sizeof(l_tx_item->cache_data) + l_current_record->cache_size);
        if ( !l_tx_item ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            break;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_tx_item->tx_hash_fast);
        l_tx_item->tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, l_current_record->datum_size);
        l_tx_item->tx_owned = 1;
        if ( !l_tx_item->tx ) {
            DAP_DELETE(l_tx_item);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            break;
        }
        memcpy(&l_tx_item->cache_data, l_current_record->data, l_current_record->cache_size);
        memcpy(l_tx_item->tx, l_current_record->data + l_current_record->cache_size, l_current_record->datum_size);
        l_tx_item->ts_added = dap_nanotime_now();
        // This callback runs on a GDB proc thread while the loader thread adds
        // txs concurrently: same lock as dap_ledger_tx_add() around both the
        // tail read and the insert (the read used to be unguarded, and the
        // write never took the lock at all).
        pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
        dap_ledger_tx_item_t *l_tail_item = HASH_LAST(l_ledger_pvt->ledger_items);
        if (!l_tail_item || l_tail_item->cache_data.ts_created <= l_tx_item->cache_data.ts_created)
            HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
        else
            HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item, s_sort_ledger_tx_item);
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    }
    // The balances stage is the one that ends the load (sets load_end); without this the
    // loader thread waits on load_cond forever (the chain used to stop right here).
    s_load_cache_next_stage(l_ledger, DAP_LEDGER_BALANCES_STR, s_load_cache_gdb_loaded_balances_callback);
    return true;
}

static bool s_load_cache_gdb_loaded_stake_lock_callback(dap_global_db_instance_t *a_dbi,
                                                        int a_rc, const char *a_group,
                                                        const size_t a_values_total, const size_t a_values_count,
                                                        dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t *l_ledger = (dap_ledger_t *) a_arg;
    dap_ledger_private_t *l_ledger_pvt = PVT(l_ledger);

    for (size_t i = 0; i < a_values_count; i++) {
        if (a_values[i].value_len != sizeof(dap_hash_fast_t))
            continue;
        dap_ledger_stake_lock_item_t *l_new_stake_lock_emission = DAP_NEW(dap_ledger_stake_lock_item_t);
        if (!l_new_stake_lock_emission) {
            debug_if(s_debug_more, L_ERROR, "Error: memory allocation when try adding item 'dap_ledger_stake_lock_item_t' to hash-table");
            continue;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_new_stake_lock_emission->tx_for_stake_lock_hash);
        l_new_stake_lock_emission->tx_used_out = *(dap_hash_fast_t *)(a_values[i].value);
        HASH_ADD(hh, l_ledger_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
    }

    s_load_cache_next_stage(l_ledger, DAP_LEDGER_TXS_STR, s_load_cache_gdb_loaded_txs_callback);
    return true;
}
/**
 * @brief GDB callback for loaded emissions from cache
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 * @return Always true thats means to clear up a_values
 */
static bool s_load_cache_gdb_loaded_emissions_callback(dap_global_db_instance_t *a_dbi,
                                                       int a_rc, const char *a_group,
                                                       const size_t a_values_total, const size_t a_values_count,
                                                       dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t * l_ledger = (dap_ledger_t*) a_arg;
    dap_ledger_private_t * l_ledger_pvt = PVT(l_ledger);

    for (size_t i = 0; i < a_values_count; i++) {
        if (a_values[i].value_len <= sizeof(dap_hash_fast_t))
            continue;
        const char *c_token_ticker = ((dap_chain_datum_token_emission_t *)
                                      (a_values[i].value + sizeof(dap_hash_fast_t)))->hdr.ticker;
        dap_ledger_token_item_t *l_token_item = NULL;
        HASH_FIND_STR(l_ledger_pvt->tokens, c_token_ticker, l_token_item);
        if (!l_token_item) {
            log_it(L_WARNING, "Not found token with ticker [%s], need to 'ledger reload' to update cache", c_token_ticker);
            continue;
        }
        dap_ledger_token_emission_item_t *l_emission_item = DAP_NEW_Z(dap_ledger_token_emission_item_t);
        if ( !l_emission_item ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return false;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_emission_item->datum_token_emission_hash);
        l_emission_item->tx_used_out = *(dap_hash_fast_t*)a_values[i].value;
        l_emission_item->datum_token_emission = DAP_DUP_SIZE(a_values[i].value + sizeof(dap_hash_fast_t),
                                                             a_values[i].value_len - sizeof(dap_hash_fast_t));
        l_emission_item->datum_token_emission_size = a_values[i].value_len - sizeof(dap_hash_fast_t);
        HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash,
                 sizeof(dap_chain_hash_fast_t), l_emission_item);
    }

    s_load_cache_next_stage(l_ledger, DAP_LEDGER_STAKE_LOCK_STR, s_load_cache_gdb_loaded_stake_lock_callback);
    return true;
}


/**
 * @brief s_load_cache_gdb_loaded_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static bool s_load_cache_gdb_loaded_tokens_callback(dap_global_db_instance_t *a_dbi,
                                                    int a_rc, const char *a_group,
                                                    const size_t a_values_total, const size_t a_values_count,
                                                    dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t *l_ledger = (dap_ledger_t *) a_arg;
    dap_ledger_private_t *l_ledger_pvt = PVT(l_ledger);
    if (a_rc) {
        log_it(L_NOTICE, "No ledger cache found (rc %d)", a_rc);
        s_load_cache_finish(l_ledger);
        return false;
    }
    for (size_t i = 0; i < a_values_count; i++) {
        if (a_values[i].value_len <= sizeof(uint256_t))
            continue;
        dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t *)(a_values[i].value + sizeof(uint256_t));
        size_t l_token_size = a_values[i].value_len - sizeof(uint256_t);
        if (strcmp(l_token->ticker, a_values[i].key)) {
            log_it(L_WARNING, "Corrupted token with ticker [%s], need to 'ledger reload' to update cache", a_values[i].key);
            continue;
        }
        dap_ledger_token_add(l_ledger, (byte_t *)l_token, l_token_size, dap_time_now());
        dap_ledger_token_item_t *l_token_item = s_ledger_find_token(l_ledger, l_token->ticker);
        if (l_token_item)
            l_token_item->current_supply = *(uint256_t*)a_values[i].value;
    }

    s_load_cache_next_stage(l_ledger, DAP_LEDGER_EMISSIONS_STR, s_load_cache_gdb_loaded_emissions_callback);
    return true;
}

/**
 * @brief Load ledger from cache (stored in GDB)
 * @param a_ledger
 */
/* *** Ledger snapshot cache ([ledger] snapshot_cache) ***
 *
 * A flat binary file next to the chain cell files that captures the in-memory
 * ledger state - every transaction cache record (spent-outs bookkeeping) and
 * every account balance - together with the save timestamp and item counts.
 * The snapshot deliberately stores no transaction datums: the chain scan that
 * always follows a restart completes every restored item with the datum it
 * reads from the chain (dap_ledger_tx_load), so the file stays compact.
 *
 * Unlike the GlobalDB ledger cache this does not go through the GlobalDB
 * layer at all - no groups, no replication, no per-record signing - so a full
 * chain replay cannot push the node's GlobalDB over its size limit through
 * ledger cache writes anymore. In snapshot mode the GlobalDB txs/balances
 * groups are neither written nor read; the small groups (tokens, emissions,
 * stake locks, delegated keys) keep using GlobalDB as before.
 */

#define DAP_LEDGER_SNAPSHOT_MAGIC "CFLEDGSN"
#define DAP_LEDGER_SNAPSHOT_VERSION 4
#define DAP_LEDGER_SNAPSHOT_FILENAME "ledger-snapshot.bin"

typedef struct DAP_ALIGN_PACKED dap_ledger_snapshot_header {
    uint8_t  magic[8];        // "CFLEDGSN"
    uint32_t version;
    uint32_t header_size;     // for forward extensions: payload starts here
    uint64_t net_id;
    uint64_t ts_saved;        // unix time of the save
    uint64_t n_tx_items;
    uint64_t n_balances;
    uint64_t payload_size;    // bytes after the header
    uint64_t crc64;           // over the payload
    uint64_t block_num;       // last block of the block chain at save time (0 = unknown);
                              // the scan skips transaction processing up to this position
    uint8_t  block_hash[sizeof(dap_chain_hash_fast_t)]; // that block's hash: continuity check
    uint32_t flags;           // bit0: wallet section, bit1: extension sections present
    uint32_t n_sections;      // extension section descriptors that follow the wallet section
    uint64_t n_wallet_outs;   // unspent-output records in the wallet section
} dap_ledger_snapshot_header_t;

typedef struct DAP_ALIGN_PACKED dap_ledger_snapshot_tx_record {
    uint8_t  tx_hash[sizeof(dap_chain_hash_fast_t)];
    uint32_t cache_size;      // followed by exactly cache_size bytes of cache_data
} dap_ledger_snapshot_tx_record_t;

// v4: adds the atom link, so a restored item can attach its datum lazily from
// the chain-state index instead of waiting for a chain scan.
typedef struct DAP_ALIGN_PACKED dap_ledger_snapshot_tx_record_v4 {
    uint8_t  tx_hash[sizeof(dap_chain_hash_fast_t)];
    uint8_t  atom_hash[sizeof(dap_chain_hash_fast_t)];
    uint32_t datum_index;
    uint32_t atom_link_valid;
    uint32_t cache_size;      // followed by exactly cache_size bytes of cache_data
} dap_ledger_snapshot_tx_record_v4_t;

typedef struct DAP_ALIGN_PACKED dap_ledger_snapshot_wallet_record {
    uint16_t addr_size;       // followed by: addr[addr_size], out_idx, out_type,
    uint16_t out_idx;         // ticker[ticker_len], value[32], tx_hash[32]
    uint8_t  out_type;
    uint16_t ticker_len;
    uint64_t ts_unlock;
} dap_ledger_snapshot_wallet_record_t;

#define DAP_LEDGER_SNAPSHOT_MAX_SECTIONS 16

typedef struct DAP_ALIGN_PACKED dap_ledger_snapshot_section_desc {
    char name[DAP_LEDGER_SNAPSHOT_SECTION_NAME_MAX];
    uint32_t flags;
    uint32_t reserved;
    uint64_t size;
    uint64_t crc64;
} dap_ledger_snapshot_section_desc_t;

typedef struct s_ledger_snapshot_section {
    char name[DAP_LEDGER_SNAPSHOT_SECTION_NAME_MAX];
    uint32_t flags;
    dap_ledger_snapshot_dump_cb_t dump;
    dap_ledger_snapshot_load_cb_t load;
    void *ctx;
    struct s_ledger_snapshot_section *next;
} s_ledger_snapshot_section_t;

static s_ledger_snapshot_section_t *s_snapshot_sections = NULL;
static pthread_mutex_t s_snapshot_sections_lock = PTHREAD_MUTEX_INITIALIZER;

int dap_ledger_add_snapshot_section(const char *a_name, uint32_t a_flags,
        dap_ledger_snapshot_dump_cb_t a_dump, dap_ledger_snapshot_load_cb_t a_load, void *a_ctx)
{
    if (!a_name || !*a_name || (!a_dump && !a_load))
        return -1;
    pthread_mutex_lock(&s_snapshot_sections_lock);
    for (s_ledger_snapshot_section_t *l_it = s_snapshot_sections; l_it; l_it = l_it->next) {
        if (!dap_strcmp(l_it->name, a_name)) {
            pthread_mutex_unlock(&s_snapshot_sections_lock);
            return 0; // idempotent by name
        }
    }
    s_ledger_snapshot_section_t *l_new = DAP_NEW_Z(s_ledger_snapshot_section_t);
    if (!l_new) {
        pthread_mutex_unlock(&s_snapshot_sections_lock);
        return -2;
    }
    dap_strncpy(l_new->name, a_name, sizeof(l_new->name) - 1);
    l_new->flags = a_flags;
    l_new->dump = a_dump;
    l_new->load = a_load;
    l_new->ctx = a_ctx;
    l_new->next = s_snapshot_sections;
    s_snapshot_sections = l_new;
    pthread_mutex_unlock(&s_snapshot_sections_lock);
    log_it(L_INFO, "Ledger snapshot: section '%s' registered", a_name);
    return 0;
}

/* *** Service GlobalDB groups in the snapshot ***
 *
 * Services keep their registries in per-network GlobalDB groups, and a start
 * without a chain scan cannot rebuild them from datums. They register a group
 * getter here; the "service_groups" section dumps the groups per network and
 * restores every record synchronously at load. The snapshot is the durable
 * source, the GDB is just the runtime store.
 */
typedef struct s_snapshot_group_provider {
    char name[DAP_LEDGER_SNAPSHOT_SECTION_NAME_MAX];
    dap_ledger_snapshot_group_getter_t getter;
    void *ctx;
    struct s_snapshot_group_provider *next;
} s_snapshot_group_provider_t;

static s_snapshot_group_provider_t *s_group_providers = NULL;
static pthread_mutex_t s_group_providers_lock = PTHREAD_MUTEX_INITIALIZER;

int dap_ledger_add_snapshot_gdb_group(const char *a_name, dap_ledger_snapshot_group_getter_t a_getter, void *a_ctx)
{
    if (!a_name || !*a_name || !a_getter)
        return -1;
    pthread_mutex_lock(&s_group_providers_lock);
    for (s_snapshot_group_provider_t *l_it = s_group_providers; l_it; l_it = l_it->next) {
        if (!dap_strcmp(l_it->name, a_name)) {
            pthread_mutex_unlock(&s_group_providers_lock);
            return 0; // idempotent by name
        }
    }
    s_snapshot_group_provider_t *l_new = DAP_NEW_Z(s_snapshot_group_provider_t);
    if (!l_new) {
        pthread_mutex_unlock(&s_group_providers_lock);
        return -2;
    }
    dap_strncpy(l_new->name, a_name, sizeof(l_new->name) - 1);
    l_new->getter = a_getter;
    l_new->ctx = a_ctx;
    l_new->next = s_group_providers;
    s_group_providers = l_new;
    pthread_mutex_unlock(&s_group_providers_lock);
    return 0;
}

static int s_snapshot_service_groups_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out)
{
    (void)a_ctx;
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = a_net_id });
    if (!l_net)
        return 0;
    dap_string_t *l_body = dap_string_new("");
    if (!l_body)
        return -2;
    uint32_t l_n_groups = 0;
    bool l_ok = true;
    pthread_mutex_lock(&s_group_providers_lock);
    for (s_snapshot_group_provider_t *l_p = s_group_providers; l_ok && l_p; l_p = l_p->next) {
        char *l_group = l_p->getter(l_net, l_p->ctx);
        if (!l_group)
            continue;
        size_t l_cnt = 0;
        dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_group, &l_cnt);
        size_t l_glen = strlen(l_group);
        if (l_objs && l_cnt && l_glen < UINT16_MAX) {
            uint16_t l_gl16 = (uint16_t)(l_glen + 1);   // namespace including NUL
            uint32_t l_cnt32 = (uint32_t)l_cnt;
            l_ok = s_snapshot_append(l_body, &l_gl16, sizeof(l_gl16))
                    && s_snapshot_append(l_body, l_group, l_glen + 1)
                    && s_snapshot_append(l_body, &l_cnt32, sizeof(l_cnt32));
            for (size_t i = 0; l_ok && i < l_cnt; ++i) {
                uint32_t l_klen = (uint32_t)(strlen(l_objs[i].key) + 1);
                uint32_t l_vlen = (uint32_t)l_objs[i].value_len;
                l_ok = s_snapshot_append(l_body, &l_klen, sizeof(l_klen))
                        && s_snapshot_append(l_body, &l_vlen, sizeof(l_vlen))
                        && s_snapshot_append(l_body, l_objs[i].key, l_klen)
                        && (!l_vlen || s_snapshot_append(l_body, l_objs[i].value, l_vlen));
            }
            if (l_ok)
                ++l_n_groups;
        }
        if (l_objs)
            dap_global_db_objs_delete(l_objs, l_cnt);
        DAP_DELETE(l_group);
    }
    pthread_mutex_unlock(&s_group_providers_lock);
    if (l_ok && l_n_groups)
        l_ok = s_snapshot_append(a_out, &l_n_groups, sizeof(l_n_groups))
                && s_snapshot_append(a_out, l_body->str, l_body->len);
    dap_string_free(l_body, true);
    return l_ok ? 0 : -2;   // zero groups -> empty section, skipped by the save
}

static int s_snapshot_service_groups_load(void *a_ctx, const uint8_t *a_data, size_t a_size)
{
    (void)a_ctx;
    if (!a_data || a_size < sizeof(uint32_t))
        return -1;
    uint32_t l_n_groups = 0;
    memcpy(&l_n_groups, a_data, sizeof(l_n_groups));
    const uint8_t *l_ptr = a_data + sizeof(l_n_groups), *l_end = a_data + a_size;
    for (uint32_t g = 0; g < l_n_groups; ++g) {
        uint16_t l_glen = 0;
        uint32_t l_cnt = 0;
        if ((size_t)(l_end - l_ptr) < sizeof(l_glen) || (size_t)(l_end - l_ptr) < sizeof(l_glen) + sizeof(l_cnt))
            return -2;
        memcpy(&l_glen, l_ptr, sizeof(l_glen));
        l_ptr += sizeof(l_glen);
        if (!l_glen || (size_t)(l_end - l_ptr) < l_glen || l_ptr[l_glen - 1])
            return -3;
        const char *l_group = (const char *)l_ptr;
        l_ptr += l_glen;
        memcpy(&l_cnt, l_ptr, sizeof(l_cnt));
        l_ptr += sizeof(l_cnt);
        for (uint32_t i = 0; i < l_cnt; ++i) {
            uint32_t l_klen = 0, l_vlen = 0;
            if ((size_t)(l_end - l_ptr) < 2 * sizeof(uint32_t))
                return -4;
            memcpy(&l_klen, l_ptr, sizeof(l_klen));
            l_ptr += sizeof(l_klen);
            memcpy(&l_vlen, l_ptr, sizeof(l_vlen));
            l_ptr += sizeof(l_vlen);
            if (!l_klen || (size_t)(l_end - l_ptr) < (size_t)l_klen + l_vlen
                    || l_ptr[l_klen - 1])
                return -5;
            const char *l_key = (const char *)l_ptr;
            l_ptr += l_klen;
            const void *l_value = l_ptr;
            l_ptr += l_vlen;
            dap_global_db_set_sync(l_group, l_key, l_value, l_vlen, false);
        }
    }
    log_it(L_NOTICE, "Ledger snapshot: service groups restored (%u group(s))", l_n_groups);
    return l_ptr == l_end ? 0 : -6;
}

static int s_snapshot_local_state_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out)
{
    (void)a_ctx;
    (void)a_net_id;
    return dap_chain_state_cache_dump_all(a_out);
}

static int s_snapshot_local_state_load(void *a_ctx, const uint8_t *a_data, size_t a_size)
{
    (void)a_ctx;
    return dap_chain_state_cache_load_all(a_data, a_size);
}

// Decree-system approval states (see dap_chain_policy_state_dump): persisted as
// the resulting state, not as the decrees that produced it.
static int s_snapshot_decrees_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out)
{
    (void)a_ctx;
    uint8_t *l_state = NULL;
    size_t l_size = dap_chain_policy_state_dump((dap_chain_net_id_t){ .uint64 = a_net_id }, &l_state);
    if (!l_size || !l_state)
        return 0;   // no registry for this net: nothing to carry
    bool l_ok = s_snapshot_append(a_out, l_state, l_size);
    DAP_DELETE(l_state);
    return l_ok ? 0 : -2;
}

static int s_snapshot_decrees_load(void *a_ctx, const uint8_t *a_data, size_t a_size)
{
    (void)a_ctx;
    if (!a_data || a_size < sizeof(uint64_t))
        return -1;
    uint64_t l_net_id = 0;
    memcpy(&l_net_id, a_data, sizeof(l_net_id));
    return dap_chain_policy_state_load((dap_chain_net_id_t){ .uint64 = l_net_id }, a_data, a_size);
}

// Datum links (non-TX: emissions) read from the snapshot section. They are held
// here until load end so that the datum index receives TX and non-TX entries in
// one block-ordered pass: the wallet bulk pass and the tx/event iterators read
// the index in insertion order and must see block order after a restore.
typedef struct s_pending_datum_link {
    dap_hash_fast_t datum_hash, atom_hash;
    uint32_t datum_idx;
} s_pending_datum_link_t;
static s_pending_datum_link_t *s_pending_datum_links;
static size_t s_pending_datum_links_n;
// Geometric growth: the Realloc-per-record version memcpy'd the whole array on
// every one of the ~1M links a full Backbone snapshot carries (and left a
// transient double-sized copy for the allocator) - measurable in both time and
// peak RSS on the restore path.
static size_t s_pending_datum_links_cap;

typedef struct DAP_ALIGN_PACKED s_snapshot_datum_link_rec {
    uint8_t datum_hash[sizeof(dap_chain_hash_fast_t)];
    uint8_t atom_hash[sizeof(dap_chain_hash_fast_t)];
    uint32_t datum_idx;
} s_snapshot_datum_link_rec_t;

static dap_chain_t *s_snapshot_link_chain(dap_ledger_t *a_ledger)
{
    for (dap_chain_t *l_c = a_ledger && a_ledger->net ? a_ledger->net->pub.chains : NULL; l_c; l_c = l_c->next) {
        const char *l_cs_type = dap_chain_get_cs_type(l_c);
        if (l_cs_type && !dap_strcmp(l_cs_type, "esbocs"))
            return l_c;
    }
    return NULL;
}

// Non-TX datums are not in the ledger tx records; their atom links let a no-scan
// start rebuild the datum index for them too. Emissions carry their datum hash,
// so this covers the bulk of the index (tokens/decrees keep their own stores).
static int s_snapshot_datum_links_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out)
{
    (void)a_ctx;
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = a_net_id });
    dap_ledger_t *l_ledger = l_net ? l_net->pub.ledger : NULL;
    dap_chain_t *l_chain = s_snapshot_link_chain(l_ledger);
    if (!l_chain)
        return 0;
    dap_ledger_private_t *l_pvt = PVT(l_ledger);
    // Snapshot the emission hashes under the token locks and resolve the atom
    // links after releasing them: the location lookup takes the blocks lock, and
    // the live path takes blocks -> ledger, so holding tokens while calling into
    // the blocks layer would invert that order (ABBA with a block being added).
    dap_chain_hash_fast_t *l_hashes = NULL;
    size_t l_n = 0, l_cap = 0;
    bool l_oom = false;
    pthread_rwlock_rdlock(&l_pvt->tokens_rwlock);
    for (dap_ledger_token_item_t *l_tok = l_pvt->tokens; l_tok && !l_oom; l_tok = l_tok->hh.next) {
        pthread_rwlock_rdlock(&l_tok->token_emissions_rwlock);
        for (dap_ledger_token_emission_item_t *l_em = l_tok->token_emissions; l_em; l_em = l_em->hh.next) {
            if (l_n == l_cap) {
                size_t l_new_cap = l_cap ? l_cap * 2 : 4096;
                dap_chain_hash_fast_t *l_new = DAP_REALLOC(l_hashes, sizeof(*l_hashes) * l_new_cap);
                if (!l_new) {
                    l_oom = true;
                    break;
                }
                l_hashes = l_new;
                l_cap = l_new_cap;
            }
            l_hashes[l_n++] = l_em->datum_token_emission_hash;
        }
        pthread_rwlock_unlock(&l_tok->token_emissions_rwlock);
    }
    pthread_rwlock_unlock(&l_pvt->tokens_rwlock);
    if (l_oom) {
        DAP_DEL_Z(l_hashes);
        return -2;
    }
    dap_string_t *l_body = dap_string_new("");
    if (!l_body) {
        DAP_DEL_Z(l_hashes);
        return -2;
    }
    uint64_t l_recs = 0;
    bool l_ok = true;
    for (size_t i = 0; l_ok && i < l_n; ++i) {
        dap_chain_hash_fast_t l_atom = {};
        uint32_t l_idx = 0;
        if (dap_chain_cs_blocks_datum_location(l_chain, &l_hashes[i], &l_atom, &l_idx))
            continue;
        s_snapshot_datum_link_rec_t l_rec = { .datum_idx = l_idx };
        memcpy(l_rec.datum_hash, &l_hashes[i], sizeof(l_rec.datum_hash));
        memcpy(l_rec.atom_hash, &l_atom, sizeof(l_rec.atom_hash));
        if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec)))
            l_ok = false;
        else
            ++l_recs;
    }
    DAP_DEL_Z(l_hashes);
    if (l_ok && l_recs) {
        uint64_t l_hdr[2] = { a_net_id, l_recs };
        l_ok = s_snapshot_append(a_out, l_hdr, sizeof(l_hdr))
                && s_snapshot_append(a_out, l_body->str, l_body->len);
    }
    dap_string_free(l_body, true);
    return l_ok ? 0 : -2;
}

static int s_snapshot_datum_links_load(void *a_ctx, const uint8_t *a_data, size_t a_size)
{
    (void)a_ctx;
    if (!a_data || a_size < 2 * sizeof(uint64_t))
        return -1;
    uint64_t l_hdr[2];
    memcpy(l_hdr, a_data, sizeof(l_hdr));
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = l_hdr[0] });
    dap_ledger_t *l_ledger = l_net ? l_net->pub.ledger : NULL;
    dap_chain_t *l_chain = s_snapshot_link_chain(l_ledger);
    if (!l_chain)
        return 0;
    const uint8_t *l_ptr = a_data + sizeof(l_hdr), *l_end = a_data + a_size;
    size_t l_restored = 0, l_missing = 0;
    for (uint64_t i = 0; i < l_hdr[1]; ++i) {
        if ((size_t)(l_end - l_ptr) < sizeof(s_snapshot_datum_link_rec_t))
            return -3;
        s_snapshot_datum_link_rec_t l_rec;
        memcpy(&l_rec, l_ptr, sizeof(l_rec));
        l_ptr += sizeof(l_rec);
        dap_chain_hash_fast_t l_datum = {}, l_atom = {};
        memcpy(&l_datum, l_rec.datum_hash, sizeof(l_datum));
        memcpy(&l_atom, l_rec.atom_hash, sizeof(l_atom));
        if (dap_chain_cs_blocks_index_was_restored(l_chain)) {
            // Defer: merged with the TX links in block order at load end.
            if (s_pending_datum_links_n == s_pending_datum_links_cap) {
                size_t l_cap = s_pending_datum_links_cap ? s_pending_datum_links_cap * 2 : 4096;
                s_pending_datum_link_t *l_new = DAP_REALLOC(s_pending_datum_links,
                        sizeof(*l_new) * l_cap);
                if (!l_new)
                    return -4;
                s_pending_datum_links = l_new;
                s_pending_datum_links_cap = l_cap;
            }
            s_pending_datum_links[s_pending_datum_links_n++] = (s_pending_datum_link_t){
                    .datum_hash = l_datum, .atom_hash = l_atom, .datum_idx = l_rec.datum_idx };
            ++l_restored;
            continue;
        }
        if (!dap_chain_cs_blocks_index_restored_datum(l_chain, &l_datum, &l_atom, l_rec.datum_idx))
            ++l_restored;
        else
            ++l_missing;
    }
    log_it(L_NOTICE, "Ledger snapshot: datum links restored (%zu emission(s), %zu missing)",
           l_restored, l_missing);
    return 0;
}

static bool s_snapshot_section_find_flags(const char *a_name, dap_ledger_snapshot_load_cb_t *a_load,
                                          void **a_ctx, uint32_t *a_flags);

// Copies the callbacks out so a load callback runs without the registry lock.
static bool s_snapshot_section_find(const char *a_name, dap_ledger_snapshot_load_cb_t *a_load, void **a_ctx)
{
    return s_snapshot_section_find_flags(a_name, a_load, a_ctx, NULL);
}

static bool s_snapshot_section_find_flags(const char *a_name, dap_ledger_snapshot_load_cb_t *a_load,
                                          void **a_ctx, uint32_t *a_flags)
{
    bool l_found = false;
    pthread_mutex_lock(&s_snapshot_sections_lock);
    for (s_ledger_snapshot_section_t *l_it = s_snapshot_sections; l_it; l_it = l_it->next) {
        if (!dap_strcmp(l_it->name, a_name)) {
            if (a_load) *a_load = l_it->load;
            if (a_ctx) *a_ctx = l_it->ctx;
            if (a_flags) *a_flags = l_it->flags;
            l_found = true;
            break;
        }
    }
    pthread_mutex_unlock(&s_snapshot_sections_lock);
    return l_found;
}

// Sections may need chain data (transaction datums are attached to the ledger
// items only while the scan runs), so their load callbacks are deferred to
// dap_ledger_load_end() instead of running in the middle of the restore.
// The snapshot payload stays mapped for as long as any of its sections is still
// pending: the sections point INTO the mapping, no copy is made (a copy of the
// wallet_txs section alone is hundreds of megabytes, and a 1.9 GB payload per
// network read into the heap was the OOM killer's main course on an 8 GB node).
// One mapping per snapshot file - two networks load one after another, each
// snapshot's mapping lives until that network's load end applies its sections.
typedef struct s_snapshot_mapping {
    void *base;
    size_t size;
    int refs;                   // pending sections pointing into the mapping
} s_snapshot_mapping_t;

static s_snapshot_mapping_t *s_snapshot_mapping_hold(void *a_base, size_t a_size)
{
    s_snapshot_mapping_t *l_map = DAP_NEW_Z(s_snapshot_mapping_t);
    if (!l_map)
        return NULL;
    l_map->base = a_base;
    l_map->size = a_size;
    l_map->refs = 1;            // held by the loader until it finishes the file
    return l_map;
}

static void s_snapshot_mapping_release(s_snapshot_mapping_t *a_map)
{
    if (!a_map || --a_map->refs > 0)
        return;
#ifndef _WIN32
    if (a_map->base)
        munmap(a_map->base, a_map->size);
#endif
    DAP_DELETE(a_map);
}

typedef struct s_pending_snapshot_section {
    char name[DAP_LEDGER_SNAPSHOT_SECTION_NAME_MAX];
    uint64_t net_id;            // sections are applied only by that net's load end
    uint8_t *data;              // borrowed from the mapped snapshot payload
    size_t size;
    s_snapshot_mapping_t *map;  // keeps the payload mapped while this section lives
    struct s_pending_snapshot_section *next;
} s_pending_snapshot_section_t;

static s_pending_snapshot_section_t *s_pending_sections = NULL;
static pthread_mutex_t s_pending_sections_lock = PTHREAD_MUTEX_INITIALIZER;

static void s_pending_section_add(s_snapshot_mapping_t *a_map, uint64_t a_net_id, const char *a_name,
                                  const uint8_t *a_data, size_t a_size)
{
    s_pending_snapshot_section_t *l_new = DAP_NEW_Z(s_pending_snapshot_section_t);
    if (!l_new)
        return;
    if (a_size && a_map) {
        // Borrowed pointer into the mapped payload - zero copy. The mapping
        // stays alive through the section's reference.
        l_new->data = (uint8_t *)a_data;
        ++a_map->refs;
        l_new->map = a_map;
    } else if (a_size) {
        // Heap payload (Windows, or a failed mmap): the buffer is freed at the
        // end of the load, while sections run later at load end - they must own
        // their bytes. (The borrowed-pointer version crashed exactly here.)
        l_new->data = DAP_DUP_SIZE((uint8_t *)a_data, a_size);
        if (!l_new->data) {
            DAP_DELETE(l_new);
            return;
        }
    }
    dap_strncpy(l_new->name, a_name, sizeof(l_new->name) - 1);
    l_new->net_id = a_net_id;
    l_new->size = a_size;
    pthread_mutex_lock(&s_pending_sections_lock);
    l_new->next = s_pending_sections;
    s_pending_sections = l_new;
    pthread_mutex_unlock(&s_pending_sections_lock);
}

static void s_pending_sections_clear(uint64_t a_net_id)
{
    // A section either owns its bytes (heap payload) or holds a reference into
    // the snapshot mapping. Take the owners and the mapping references out under
    // the lock, then release both outside it.
    dap_list_t *l_drop = NULL, *l_owned = NULL;
    pthread_mutex_lock(&s_pending_sections_lock);
    s_pending_snapshot_section_t *l_keep = NULL;
    s_pending_snapshot_section_t *l_it = s_pending_sections;
    while (l_it) {
        s_pending_snapshot_section_t *l_next = l_it->next;
        if (l_it->net_id == a_net_id) {
            if (l_it->data && l_it->map)
                l_drop = dap_list_append(l_drop, l_it->map);
            else if (l_it->data)
                l_owned = dap_list_append(l_owned, l_it->data);
            DAP_DELETE(l_it);
        } else {
            l_it->next = l_keep;
            l_keep = l_it;
        }
        l_it = l_next;
    }
    s_pending_sections = l_keep;
    pthread_mutex_unlock(&s_pending_sections_lock);
    for (dap_list_t *l_d = l_drop; l_d; l_d = l_d->next)
        s_snapshot_mapping_release((s_snapshot_mapping_t *)l_d->data);
    dap_list_free(l_drop);
    for (dap_list_t *l_o = l_owned; l_o; l_o = l_o->next)
        DAP_DELETE(l_o->data);
    dap_list_free(l_owned);
}

static void s_pending_sections_apply(dap_ledger_t *a_ledger)
{
    uint64_t a_net_id = a_ledger->net->pub.id.uint64;
    pthread_mutex_lock(&s_pending_sections_lock);
    // Take only this net's sections; another net's load end handles the rest.
    s_pending_snapshot_section_t *l_take = NULL, *l_rest = NULL;
    s_pending_snapshot_section_t *l_it = s_pending_sections;
    while (l_it) {
        s_pending_snapshot_section_t *l_next = l_it->next;
        if (l_it->net_id == a_net_id) {
            l_it->next = l_take;
            l_take = l_it;
        } else {
            l_it->next = l_rest;
            l_rest = l_it;
        }
        l_it = l_next;
    }
    s_pending_sections = l_rest;
    pthread_mutex_unlock(&s_pending_sections_lock);
    l_it = l_take;
    while (l_it) {
        s_pending_snapshot_section_t *l_next = l_it->next;
        dap_ledger_snapshot_load_cb_t l_load = NULL;
        void *l_ctx = NULL;
        if (s_snapshot_section_find(l_it->name, &l_load, &l_ctx) && l_load) {
            dap_nanotime_t l_t0 = dap_nanotime_now();
            int l_rc = l_load(l_ctx, l_it->data, l_it->size);
            log_it(l_rc ? L_WARNING : L_NOTICE, "Ledger snapshot: section '%s' %s (%zu bytes, %"
                   DAP_UINT64_FORMAT_U " ms)", l_it->name, l_rc ? "load failed" : "restored",
                   l_it->size, (uint64_t)(dap_nanotime_now() - l_t0) / 1000000);
            // The complete-state flag is valid only when that section actually
            // restored: a truncated/failed ledger_state leaves the remaining
            // state to the regular replay, which must keep running.
            if (!dap_strcmp(l_it->name, DAP_LEDGER_SNAPSHOT_LEDGER_STATE_SECTION)) {
                if (!l_rc) {
                    PVT(a_ledger)->snapshot_full = true;
                } else {
                    // If the service replay was suppressed ([ledger] snapshot_full_apply),
                    // this is not recoverable by replaying now - report loudly. With the
                    // default (apply off) the scan replayed everything, so the failed
                    // section only means the next snapshot is written from the replay.
                    bool l_suppressed = PVT(a_ledger)->snapshot_full_apply;
                    PVT(a_ledger)->snapshot_full = false;
                    log_it(l_suppressed ? L_CRITICAL : L_WARNING,
                           "Ledger snapshot: complete ledger state failed to restore (%d); %s",
                           l_rc, l_suppressed
                                ? "the chain scan suppressed the service replay, so polls/events/"
                                  "rewards may be incomplete - rescan the network"
                                : "the regular datum replay produced the service state");
                }
            }
        } else {
            log_it(L_INFO, "Ledger snapshot: section '%s' skipped (not registered)", l_it->name);
        }
        // The section either borrowed its bytes from the snapshot mapping (then
        // the reference goes back, and the mapping itself goes away with the
        // last pending section of that snapshot) or owns a heap copy.
        if (l_it->data && l_it->map)
            s_snapshot_mapping_release(l_it->map);
        else
            DAP_DEL_Z(l_it->data);
        DAP_DELETE(l_it);
        l_it = l_next;
    }
}

// Wallet section is persisted only when the node indexes every address
// ([wallets] wallets_cache=all): in that mode the restored unspent index
// matches what the wallet bulk pass would rebuild anyway. Ask the cache for
// its effective mode - the config string alone misses the built-in default.
static bool s_snapshot_wallet_section_enabled(void)
{
    return dap_chain_wallet_cache_mode_all();
}

// Defined together with the save code: whether a wallet section of the given size
// can describe the ledger's whole unspent set.
static bool s_snapshot_wallet_section_plausible(dap_ledger_t *a_ledger, uint64_t a_section_records);

/* *** Snapshot section "ledger_state" (v3, full ledger snapshot) ***
 *
 * The transaction cache and the balances are restored by the core snapshot
 * payload. This section carries the state that the scan does NOT rebuild for
 * transactions already present in the restored ledger (dap_ledger_tx_load returns
 * ALREADY_CACHED before the balance/service part of tx_add):
 *   - stake-lock used marks (legacy IN_EMS_VIRTUAL);
 *   - block-reward spends (IN_REWARD) - without them a reward already spent in
 *     the restored history would pass the "already used" check again;
 *   - service events and the event public-key allowlist;
 *   - timed-locked outputs (OUT_STD ts_unlock) with the blockchain time they
 *     were locked against.
 * Tokens, token updates and emissions are NOT here: they arrive as non-TX
 * datums, and the scan still feeds those into the ledger in every mode (the
 * section would otherwise carry ~1 GB of one-emission-per-block-reward data).
 * Loading is idempotent: every record is looked up before insertion, so a
 * section restored on top of the regular replay adds only what is missing.
 *
 * The header flag bit2 ("complete ledger state") is set when this section is
 * present. With [ledger] snapshot_full_apply the ledger then stops replaying the
 * service side of restored transactions (dap_ledger_tx_load -> see
 * s_ledger_tx_service_notify_added): polls/votes, events and rewards come from
 * this snapshot instead of being rebuilt by the scan.
 */

typedef struct DAP_ALIGN_PACKED s_snapshot_ledger_state_hdr {
    uint64_t net_id;
    uint64_t blockchain_time;
    uint64_t cutoff_time;
    uint64_t n_tokens;          // {current_supply[32], token_size} + datum
    uint64_t n_token_updates;   // {updated_time, datum_size} + datum, time-ordered
    uint64_t n_emissions;       // {hash, used_out, ts_added, datum_size} + datum
    uint64_t n_stake_locks;     // {tx_for_stake_lock_hash, tx_used_out}
    uint64_t n_rewards;         // {block_hash, sign_pkey_hash, spender_tx}
    uint64_t n_events;          // {srv_uid, timestamp, tx_hash, pkey_hash, type, sizes} + blobs
    uint64_t n_event_pkeys;     // {pkey_hash}
    uint64_t n_locked_outs;     // {addr, value, unlock_time, ticker_len} + ticker
} s_snapshot_ledger_state_hdr_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_token_rec {
    uint8_t current_supply[sizeof(uint256_t)];
    uint64_t token_size;
} s_snapshot_token_rec_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_token_update_rec {
    int64_t updated_time;
    uint64_t datum_size;
} s_snapshot_token_update_rec_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_emission_rec {
    uint8_t emission_hash[sizeof(dap_chain_hash_fast_t)];
    uint8_t tx_used_out[sizeof(dap_chain_hash_fast_t)];
    uint64_t ts_added;
    uint64_t datum_size;
} s_snapshot_emission_rec_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_stake_lock_rec {
    uint8_t tx_for_stake_lock_hash[sizeof(dap_chain_hash_fast_t)];
    uint8_t tx_used_out[sizeof(dap_chain_hash_fast_t)];
} s_snapshot_stake_lock_rec_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_reward_rec {
    uint8_t block_hash[sizeof(dap_chain_hash_fast_t)];
    uint8_t sign_pkey_hash[sizeof(dap_chain_hash_fast_t)];
    uint8_t spender_tx[sizeof(dap_chain_hash_fast_t)];
} s_snapshot_reward_rec_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_event_rec {
    uint64_t srv_uid;
    int64_t timestamp;
    uint8_t tx_hash[sizeof(dap_chain_hash_fast_t)];
    uint8_t pkey_hash[sizeof(dap_chain_hash_fast_t)];
    uint16_t event_type;
    uint16_t group_len;     // group_name bytes, no terminating NUL
    uint32_t data_size;     // then group_name[group_len], event_data[data_size]
} s_snapshot_event_rec_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_event_pkey_rec {
    uint8_t pkey_hash[sizeof(dap_chain_hash_fast_t)];
} s_snapshot_event_pkey_rec_t;

typedef struct DAP_ALIGN_PACKED s_snapshot_locked_out_rec {
    uint8_t addr[sizeof(dap_chain_addr_t)];
    uint8_t value[sizeof(uint256_t)];
    int64_t unlock_time;
    uint16_t ticker_len;
} s_snapshot_locked_out_rec_t;

static bool s_snapshot_append(dap_string_t *a_out, const void *a_data, size_t a_size)
{
    return dap_string_append_len(a_out, (const char *)a_data, (ssize_t)a_size) != NULL;
}

typedef struct s_snapshot_update_ref {
    int64_t ts;
    dap_ledger_token_update_item_t *item;
} s_snapshot_update_ref_t;

static int s_snapshot_update_ref_cmp(const void *a, const void *b)
{
    int64_t l_a = ((const s_snapshot_update_ref_t *)a)->ts;
    int64_t l_b = ((const s_snapshot_update_ref_t *)b)->ts;
    return l_a < l_b ? -1 : l_a > l_b ? 1 : 0;
}

static int s_snapshot_ledger_state_dump(void *a_ctx, uint64_t a_net_id, dap_string_t *a_out)
{
    (void)a_ctx;
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = a_net_id });
    dap_ledger_t *l_ledger = l_net ? l_net->pub.ledger : NULL;
    if (!l_ledger)
        return -1;
    dap_ledger_private_t *l_pvt = PVT(l_ledger);
    s_snapshot_ledger_state_hdr_t l_hdr = { .net_id = a_net_id,
            .blockchain_time = (uint64_t)l_pvt->blockchain_time,
            .cutoff_time = (uint64_t)l_pvt->cutoff_time };
    dap_string_t *l_body = dap_string_new("");
    if (!l_body)
        return -2;
    int l_ret = 0;

    // Token declarations with their current supply and the update datums in
    // chronological order. Emissions stay out of this section for now (they
    // return as two-tier compact records in the no-scan stage); until then the
    // chain replay still feeds them, and the token supply restored here is the
    // authoritative value for the snapshot height.
    pthread_rwlock_rdlock(&l_pvt->tokens_rwlock);
    for (dap_ledger_token_item_t *l_tok = l_pvt->tokens; l_tok && !l_ret; l_tok = l_tok->hh.next) {
        uint64_t l_size = l_tok->datum_token ? l_tok->datum_token_size : 0;
        s_snapshot_token_rec_t l_rec = { .token_size = l_size };
        memcpy(l_rec.current_supply, &l_tok->current_supply, sizeof(uint256_t));
        if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec))
                || (l_size && !s_snapshot_append(l_body, l_tok->datum_token, l_size))) {
            l_ret = -2;
            break;
        }
        ++l_hdr.n_tokens;
    }
    if (!l_ret) {
        size_t l_count = 0, l_cap = 0;
        s_snapshot_update_ref_t *l_refs = NULL;
        for (dap_ledger_token_item_t *l_tok = l_pvt->tokens; l_tok; l_tok = l_tok->hh.next) {
            pthread_rwlock_rdlock(&l_tok->token_ts_updated_rwlock);
            for (dap_ledger_token_update_item_t *l_up = l_tok->token_ts_updated; l_up; l_up = l_up->hh.next) {
                if (l_count == l_cap) {
                    size_t l_new_cap = l_cap ? l_cap * 2 : 64;
                    s_snapshot_update_ref_t *l_new = DAP_REALLOC(l_refs, sizeof(*l_refs) * l_new_cap);
                    if (!l_new) {
                        l_ret = -2;
                        break;
                    }
                    l_refs = l_new;
                    l_cap = l_new_cap;
                }
                l_refs[l_count++] = (s_snapshot_update_ref_t){ .ts = l_up->updated_time, .item = l_up };
            }
            pthread_rwlock_unlock(&l_tok->token_ts_updated_rwlock);
            if (l_ret)
                break;
        }
        if (!l_ret && l_count)
            qsort(l_refs, l_count, sizeof(*l_refs), s_snapshot_update_ref_cmp);
        for (size_t i = 0; i < l_count && !l_ret; ++i) {
            s_snapshot_token_update_rec_t l_rec = {
                .updated_time = l_refs[i].ts,
                .datum_size = l_refs[i].item->datum_token_update_size
            };
            if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec))
                    || !s_snapshot_append(l_body, l_refs[i].item->datum_token_update, l_rec.datum_size))
                l_ret = -2;
            else
                ++l_hdr.n_token_updates;
        }
        DAP_DEL_Z(l_refs);
    }
    // Emissions with their used-out marks. The full datum is stored (the item
    // exposes it to stake-lock/bridge/mempool consumers); supply is NOT
    // recomputed on load - the token record above carries it. A compact
    // two-tier encoding is a size optimisation for a later pass.
    for (dap_ledger_token_item_t *l_tok = l_pvt->tokens; l_tok && !l_ret; l_tok = l_tok->hh.next) {
        pthread_rwlock_rdlock(&l_tok->token_emissions_rwlock);
        for (dap_ledger_token_emission_item_t *l_em = l_tok->token_emissions; l_em; l_em = l_em->hh.next) {
            s_snapshot_emission_rec_t l_rec = { .ts_added = l_em->ts_added,
                    .datum_size = l_em->datum_token_emission_size };
            memcpy(l_rec.emission_hash, &l_em->datum_token_emission_hash, sizeof(dap_chain_hash_fast_t));
            memcpy(l_rec.tx_used_out, &l_em->tx_used_out, sizeof(dap_chain_hash_fast_t));
            if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec))
                    || (l_rec.datum_size && !s_snapshot_append(l_body, l_em->datum_token_emission, l_rec.datum_size))) {
                l_ret = -2;
                break;
            }
            ++l_hdr.n_emissions;
        }
        pthread_rwlock_unlock(&l_tok->token_emissions_rwlock);
    }
    pthread_rwlock_unlock(&l_pvt->tokens_rwlock);

    if (!l_ret) {
        pthread_rwlock_rdlock(&l_pvt->stake_lock_rwlock);
        for (dap_ledger_stake_lock_item_t *l_sl = l_pvt->emissions_for_stake_lock; l_sl && !l_ret; l_sl = l_sl->hh.next) {
            s_snapshot_stake_lock_rec_t l_rec;
            memcpy(l_rec.tx_for_stake_lock_hash, &l_sl->tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t));
            memcpy(l_rec.tx_used_out, &l_sl->tx_used_out, sizeof(dap_chain_hash_fast_t));
            if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec)))
                l_ret = -2;
            else
                ++l_hdr.n_stake_locks;
        }
        pthread_rwlock_unlock(&l_pvt->stake_lock_rwlock);
    }
    if (!l_ret) {
        pthread_rwlock_rdlock(&l_pvt->rewards_rwlock);
        for (dap_ledger_reward_item_t *l_rw = l_pvt->rewards; l_rw && !l_ret; l_rw = l_rw->hh.next) {
            s_snapshot_reward_rec_t l_rec;
            memcpy(l_rec.block_hash, &l_rw->key.block_hash, sizeof(dap_chain_hash_fast_t));
            memcpy(l_rec.sign_pkey_hash, &l_rw->key.sign_pkey_hash, sizeof(dap_chain_hash_fast_t));
            memcpy(l_rec.spender_tx, &l_rw->spender_tx, sizeof(dap_chain_hash_fast_t));
            if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec)))
                l_ret = -2;
            else
                ++l_hdr.n_rewards;
        }
        pthread_rwlock_unlock(&l_pvt->rewards_rwlock);
    }
    if (!l_ret) {
        pthread_rwlock_rdlock(&l_pvt->events_rwlock);
        for (dap_ledger_event_t *l_ev = l_pvt->events; l_ev && !l_ret; l_ev = l_ev->hh.next) {
            size_t l_group_len = l_ev->group_name ? strlen(l_ev->group_name) : 0;
            if (l_group_len > UINT16_MAX || l_ev->event_data_size > UINT32_MAX) {
                l_ret = -3;
                break;
            }
            s_snapshot_event_rec_t l_rec = {
                .srv_uid = l_ev->srv_uid.uint64,
                .timestamp = l_ev->timestamp,
                .event_type = l_ev->event_type,
                .group_len = (uint16_t)l_group_len,
                .data_size = (uint32_t)l_ev->event_data_size
            };
            memcpy(l_rec.tx_hash, &l_ev->tx_hash, sizeof(dap_chain_hash_fast_t));
            memcpy(l_rec.pkey_hash, &l_ev->pkey_hash, sizeof(dap_chain_hash_fast_t));
            if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec))
                    || (l_group_len && !s_snapshot_append(l_body, l_ev->group_name, l_group_len))
                    || (l_ev->event_data_size && !s_snapshot_append(l_body, l_ev->event_data, l_ev->event_data_size))) {
                l_ret = -2;
                break;
            }
            ++l_hdr.n_events;
        }
        pthread_rwlock_unlock(&l_pvt->events_rwlock);
    }
    if (!l_ret) {
        pthread_rwlock_rdlock(&l_pvt->event_pkeys_rwlock);
        for (dap_ledger_event_pkey_item_t *l_pk = l_pvt->event_pkeys_allowed; l_pk && !l_ret; l_pk = l_pk->hh.next) {
            s_snapshot_event_pkey_rec_t l_rec;
            memcpy(l_rec.pkey_hash, &l_pk->pkey_hash, sizeof(dap_chain_hash_fast_t));
            if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec)))
                l_ret = -2;
            else
                ++l_hdr.n_event_pkeys;
        }
        pthread_rwlock_unlock(&l_pvt->event_pkeys_rwlock);
    }
    if (!l_ret) {
        pthread_rwlock_rdlock(&l_pvt->locked_outs_rwlock);
        for (dap_ledger_locked_out_t *l_lo = l_pvt->locked_outs; l_lo && !l_ret; l_lo = l_lo->next) {
            size_t l_ticker_len = strnlen(l_lo->ticker, sizeof(l_lo->ticker));
            s_snapshot_locked_out_rec_t l_rec = {
                .unlock_time = l_lo->unlock_time,
                .ticker_len = (uint16_t)l_ticker_len
            };
            memcpy(l_rec.addr, &l_lo->addr, sizeof(dap_chain_addr_t));
            memcpy(l_rec.value, &l_lo->value, sizeof(uint256_t));
            if (!s_snapshot_append(l_body, &l_rec, sizeof(l_rec))
                    || (l_ticker_len && !s_snapshot_append(l_body, l_lo->ticker, l_ticker_len))) {
                l_ret = -2;
                break;
            }
            ++l_hdr.n_locked_outs;
        }
        pthread_rwlock_unlock(&l_pvt->locked_outs_rwlock);
    }

    if (!l_ret && (!s_snapshot_append(a_out, &l_hdr, sizeof(l_hdr))
            || (l_body->len && !s_snapshot_append(a_out, l_body->str, l_body->len))))
        l_ret = -2;
    dap_string_free(l_body, true);
    return l_ret;
}

static int s_snapshot_ledger_state_load(void *a_ctx, const uint8_t *a_data, size_t a_size)
{
    (void)a_ctx;
    if (!a_data || a_size < sizeof(s_snapshot_ledger_state_hdr_t))
        return -1;
    s_snapshot_ledger_state_hdr_t l_hdr;
    memcpy(&l_hdr, a_data, sizeof(l_hdr));
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){ .uint64 = l_hdr.net_id });
    dap_ledger_t *l_ledger = l_net ? l_net->pub.ledger : NULL;
    if (!l_ledger)
        return -2;
    dap_ledger_private_t *l_pvt = PVT(l_ledger);
    const uint8_t *l_ptr = a_data + sizeof(l_hdr), *l_end = a_data + a_size;
    int l_ret = 0;

#define SNAP_TAKE(rec_type, rec_var) \
    if ((size_t)(l_end - l_ptr) < sizeof(rec_type)) { l_ret = -3; goto state_done; } \
    rec_type rec_var; memcpy(&rec_var, l_ptr, sizeof(rec_var)); l_ptr += sizeof(rec_var)

    // Blockchain time the locked-outs were compared against. The scan that ran
    // before this call may have advanced it; never move it backwards.
    if ((dap_time_t)l_hdr.blockchain_time > l_pvt->blockchain_time)
        l_pvt->blockchain_time = (dap_time_t)l_hdr.blockchain_time;
    if ((dap_time_t)l_hdr.cutoff_time > l_pvt->cutoff_time)
        l_pvt->cutoff_time = (dap_time_t)l_hdr.cutoff_time;

    // Token declarations. Created only when the GlobalDB token group did not
    // provide them; an existing token keeps its (at least as new) supply.
    for (uint64_t i = 0; i < l_hdr.n_tokens; ++i) {
        SNAP_TAKE(s_snapshot_token_rec_t, l_rec);
        if (l_rec.token_size < sizeof(dap_chain_datum_token_t) || l_rec.token_size > (uint64_t)(l_end - l_ptr)) {
            l_ret = -4;
            goto state_done;
        }
        const dap_chain_datum_token_t *l_datum = (const dap_chain_datum_token_t *)l_ptr;
        char l_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = {0};
        dap_strncpy(l_ticker, l_datum->ticker, sizeof(l_ticker) - 1);
        dap_ledger_token_item_t *l_item = NULL;
        pthread_rwlock_rdlock(&l_pvt->tokens_rwlock);
        HASH_FIND_STR(l_pvt->tokens, l_ticker, l_item);
        pthread_rwlock_unlock(&l_pvt->tokens_rwlock);
        if (!l_item) {
            dap_ledger_token_add(l_ledger, (byte_t *)l_ptr, (size_t)l_rec.token_size, dap_time_now());
            pthread_rwlock_rdlock(&l_pvt->tokens_rwlock);
            HASH_FIND_STR(l_pvt->tokens, l_ticker, l_item);
            pthread_rwlock_unlock(&l_pvt->tokens_rwlock);
            if (l_item)
                memcpy(&l_item->current_supply, l_rec.current_supply, sizeof(uint256_t));
        }
        l_ptr += l_rec.token_size;
    }
    // Token updates, in their original order. The update item is idempotent by
    // datum hash; add only what the scan did not already apply.
    for (uint64_t i = 0; i < l_hdr.n_token_updates; ++i) {
        SNAP_TAKE(s_snapshot_token_update_rec_t, l_rec);
        if (l_rec.datum_size < sizeof(dap_chain_datum_token_t) || l_rec.datum_size > (uint64_t)(l_end - l_ptr)) {
            l_ret = -5;
            goto state_done;
        }
        const dap_chain_datum_token_t *l_datum = (const dap_chain_datum_token_t *)l_ptr;
        dap_ledger_token_item_t *l_item = NULL;
        pthread_rwlock_rdlock(&l_pvt->tokens_rwlock);
        HASH_FIND_STR(l_pvt->tokens, l_datum->ticker, l_item);
        pthread_rwlock_unlock(&l_pvt->tokens_rwlock);
        if (l_item) {
            dap_hash_fast_t l_update_hash = {};
            dap_hash_fast((void *)l_ptr, (size_t)l_rec.datum_size, &l_update_hash);
            dap_ledger_token_update_item_t *l_up = NULL;
            pthread_rwlock_rdlock(&l_item->token_ts_updated_rwlock);
            HASH_FIND(hh, l_item->token_ts_updated, &l_update_hash, sizeof(l_update_hash), l_up);
            pthread_rwlock_unlock(&l_item->token_ts_updated_rwlock);
            if (!l_up)
                dap_ledger_token_add(l_ledger, (byte_t *)l_ptr, (size_t)l_rec.datum_size,
                                     (dap_time_t)l_rec.updated_time);
        }
        l_ptr += l_rec.datum_size;
    }
    // Emissions: insert the item directly, like the GlobalDB emissions stage -
    // the supply is already in the token record, re-applying it would double-count.
    for (uint64_t i = 0; i < l_hdr.n_emissions; ++i) {
        SNAP_TAKE(s_snapshot_emission_rec_t, l_rec);
        if (l_rec.datum_size < sizeof(dap_chain_datum_token_emission_t)
                || l_rec.datum_size > (uint64_t)(l_end - l_ptr)) {
            l_ret = -6;
            goto state_done;
        }
        const dap_chain_datum_token_emission_t *l_em_datum = (const dap_chain_datum_token_emission_t *)l_ptr;
        dap_ledger_token_item_t *l_item = NULL;
        pthread_rwlock_rdlock(&l_pvt->tokens_rwlock);
        HASH_FIND_STR(l_pvt->tokens, l_em_datum->hdr.ticker, l_item);
        pthread_rwlock_unlock(&l_pvt->tokens_rwlock);
        if (l_item) {
            dap_hash_fast_t l_em_hash = {};
            memcpy(&l_em_hash, l_rec.emission_hash, sizeof(l_em_hash));
            dap_ledger_token_emission_item_t *l_exists = NULL;
            pthread_rwlock_rdlock(&l_item->token_emissions_rwlock);
            HASH_FIND(hh, l_item->token_emissions, &l_em_hash, sizeof(l_em_hash), l_exists);
            pthread_rwlock_unlock(&l_item->token_emissions_rwlock);
            if (!l_exists) {
                dap_ledger_token_emission_item_t *l_new = DAP_NEW_Z(dap_ledger_token_emission_item_t);
                if (!l_new) {
                    l_ret = -7;
                    goto state_done;
                }
                l_new->datum_token_emission_hash = l_em_hash;
                memcpy(&l_new->tx_used_out, l_rec.tx_used_out, sizeof(dap_hash_fast_t));
                l_new->datum_token_emission = DAP_DUP_SIZE((dap_chain_datum_token_emission_t *)l_ptr, l_rec.datum_size);
                if (!l_new->datum_token_emission) {
                    DAP_DELETE(l_new);
                    l_ret = -7;
                    goto state_done;
                }
                l_new->datum_token_emission_size = (size_t)l_rec.datum_size;
                l_new->ts_added = (dap_nanotime_t)l_rec.ts_added;
                pthread_rwlock_wrlock(&l_item->token_emissions_rwlock);
                HASH_ADD(hh, l_item->token_emissions, datum_token_emission_hash,
                         sizeof(l_em_hash), l_new);
                pthread_rwlock_unlock(&l_item->token_emissions_rwlock);
                // GlobalDB held no such record (otherwise it would exist here):
                // write it back so a start without this snapshot still sees it.
                s_ledger_emission_cache_update(l_ledger, l_new);
            }
        }
        l_ptr += l_rec.datum_size;
    }
    for (uint64_t i = 0; i < l_hdr.n_stake_locks; ++i) {
        SNAP_TAKE(s_snapshot_stake_lock_rec_t, l_rec);
        dap_hash_fast_t l_hash = {};
        memcpy(&l_hash, l_rec.tx_for_stake_lock_hash, sizeof(l_hash));
        dap_ledger_stake_lock_item_t *l_exists = NULL;
        pthread_rwlock_rdlock(&l_pvt->stake_lock_rwlock);
        HASH_FIND(hh, l_pvt->emissions_for_stake_lock, &l_hash, sizeof(l_hash), l_exists);
        pthread_rwlock_unlock(&l_pvt->stake_lock_rwlock);
        if (!l_exists) {
            dap_ledger_stake_lock_item_t *l_new = DAP_NEW_Z(dap_ledger_stake_lock_item_t);
            if (!l_new) {
                l_ret = -8;
                goto state_done;
            }
            l_new->tx_for_stake_lock_hash = l_hash;
            memcpy(&l_new->tx_used_out, l_rec.tx_used_out, sizeof(dap_chain_hash_fast_t));
            pthread_rwlock_wrlock(&l_pvt->stake_lock_rwlock);
            HASH_ADD(hh, l_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(l_hash), l_new);
            pthread_rwlock_unlock(&l_pvt->stake_lock_rwlock);
            s_ledger_stake_lock_cache_update(l_ledger, l_new);
        }
    }
    for (uint64_t i = 0; i < l_hdr.n_rewards; ++i) {
        SNAP_TAKE(s_snapshot_reward_rec_t, l_rec);
        dap_ledger_reward_key_t l_key = {};
        memcpy(&l_key.block_hash, l_rec.block_hash, sizeof(dap_chain_hash_fast_t));
        memcpy(&l_key.sign_pkey_hash, l_rec.sign_pkey_hash, sizeof(dap_chain_hash_fast_t));
        dap_ledger_reward_item_t *l_exists = NULL;
        pthread_rwlock_rdlock(&l_pvt->rewards_rwlock);
        HASH_FIND(hh, l_pvt->rewards, &l_key, sizeof(l_key), l_exists);
        pthread_rwlock_unlock(&l_pvt->rewards_rwlock);
        if (!l_exists) {
            dap_ledger_reward_item_t *l_new = DAP_NEW_Z(dap_ledger_reward_item_t);
            if (!l_new) {
                l_ret = -9;
                goto state_done;
            }
            l_new->key = l_key;
            memcpy(&l_new->spender_tx, l_rec.spender_tx, sizeof(dap_chain_hash_fast_t));
            pthread_rwlock_wrlock(&l_pvt->rewards_rwlock);
            HASH_ADD(hh, l_pvt->rewards, key, sizeof(l_key), l_new);
            pthread_rwlock_unlock(&l_pvt->rewards_rwlock);
        }
    }
    for (uint64_t i = 0; i < l_hdr.n_events; ++i) {
        SNAP_TAKE(s_snapshot_event_rec_t, l_rec);
        if ((size_t)(l_end - l_ptr) < (size_t)l_rec.group_len + l_rec.data_size) {
            l_ret = -10;
            goto state_done;
        }
        dap_hash_fast_t l_tx_hash = {};
        memcpy(&l_tx_hash, l_rec.tx_hash, sizeof(l_tx_hash));
        dap_ledger_event_t *l_exists = NULL;
        pthread_rwlock_rdlock(&l_pvt->events_rwlock);
        HASH_FIND(hh, l_pvt->events, &l_tx_hash, sizeof(l_tx_hash), l_exists);
        pthread_rwlock_unlock(&l_pvt->events_rwlock);
        if (!l_exists) {
            dap_ledger_event_t *l_new = DAP_NEW_Z(dap_ledger_event_t);
            if (!l_new) {
                l_ret = -11;
                goto state_done;
            }
            l_new->srv_uid.uint64 = l_rec.srv_uid;
            l_new->timestamp = (dap_time_t)l_rec.timestamp;
            l_new->tx_hash = l_tx_hash;
            memcpy(&l_new->pkey_hash, l_rec.pkey_hash, sizeof(dap_chain_hash_fast_t));
            l_new->event_type = l_rec.event_type;
            if (l_rec.group_len) {
                l_new->group_name = DAP_NEW_Z_SIZE(char, (size_t)l_rec.group_len + 1);
                if (!l_new->group_name) {
                    DAP_DELETE(l_new);
                    l_ret = -11;
                    goto state_done;
                }
                memcpy(l_new->group_name, l_ptr, l_rec.group_len);
            }
            l_ptr += l_rec.group_len;
            if (l_rec.data_size) {
                l_new->event_data = DAP_DUP_SIZE((void *)l_ptr, l_rec.data_size);
                if (!l_new->event_data) {
                    DAP_DEL_Z(l_new->group_name);
                    DAP_DELETE(l_new);
                    l_ret = -11;
                    goto state_done;
                }
                l_new->event_data_size = l_rec.data_size;
            }
            l_ptr += l_rec.data_size;
            pthread_rwlock_wrlock(&l_pvt->events_rwlock);
            HASH_ADD(hh, l_pvt->events, tx_hash, sizeof(l_tx_hash), l_new);
            pthread_rwlock_unlock(&l_pvt->events_rwlock);
        } else {
            l_ptr += (size_t)l_rec.group_len + l_rec.data_size;
        }
    }
    for (uint64_t i = 0; i < l_hdr.n_event_pkeys; ++i) {
        SNAP_TAKE(s_snapshot_event_pkey_rec_t, l_rec);
        dap_hash_fast_t l_hash = {};
        memcpy(&l_hash, l_rec.pkey_hash, sizeof(l_hash));
        dap_ledger_event_pkey_item_t *l_exists = NULL;
        pthread_rwlock_rdlock(&l_pvt->event_pkeys_rwlock);
        HASH_FIND(hh, l_pvt->event_pkeys_allowed, &l_hash, sizeof(l_hash), l_exists);
        pthread_rwlock_unlock(&l_pvt->event_pkeys_rwlock);
        if (!l_exists) {
            dap_ledger_event_pkey_item_t *l_new = DAP_NEW_Z(dap_ledger_event_pkey_item_t);
            if (!l_new) {
                l_ret = -12;
                goto state_done;
            }
            l_new->pkey_hash = l_hash;
            pthread_rwlock_wrlock(&l_pvt->event_pkeys_rwlock);
            HASH_ADD(hh, l_pvt->event_pkeys_allowed, pkey_hash, sizeof(l_hash), l_new);
            pthread_rwlock_unlock(&l_pvt->event_pkeys_rwlock);
        }
    }
    // Timed-locked outputs are NEVER recreated by the datum replay of a
    // snapshot-restored ledger: tx_add() returns ALREADY_CACHED before its
    // output loop, so this section is the only source for them.
    for (uint64_t i = 0; i < l_hdr.n_locked_outs; ++i) {
        SNAP_TAKE(s_snapshot_locked_out_rec_t, l_rec);
        if (l_rec.ticker_len >= DAP_CHAIN_TICKER_SIZE_MAX || (size_t)(l_end - l_ptr) < l_rec.ticker_len) {
            l_ret = -13;
            goto state_done;
        }
        dap_ledger_locked_out_t *l_new = DAP_NEW_Z(dap_ledger_locked_out_t);
        if (!l_new) {
            l_ret = -13;
            goto state_done;
        }
        memcpy(&l_new->addr, l_rec.addr, sizeof(dap_chain_addr_t));
        memcpy(&l_new->value, l_rec.value, sizeof(uint256_t));
        memcpy(l_new->ticker, l_ptr, l_rec.ticker_len);
        l_new->unlock_time = (dap_time_t)l_rec.unlock_time;
        l_ptr += l_rec.ticker_len;
        pthread_rwlock_wrlock(&l_pvt->locked_outs_rwlock);
        LL_INSERT_INORDER(l_pvt->locked_outs, l_new, s_compare_locked_outs);
        pthread_rwlock_unlock(&l_pvt->locked_outs_rwlock);
    }
    if (l_ptr != l_end)
        log_it(L_WARNING, "Ledger snapshot: ledger_state section has %zu trailing bytes ignored",
               (size_t)(l_end - l_ptr));

state_done:
#undef SNAP_TAKE
    return l_ret;
}

typedef struct DAP_ALIGN_PACKED dap_ledger_snapshot_balance_record {
    uint16_t key_len;         // followed by key, ticker and the 32-byte uint256 balance
    uint16_t ticker_len;
    // key[key_len], ticker[ticker_len], balance[sizeof(uint256_t)]
} dap_ledger_snapshot_balance_record_t;

typedef struct { uint8_t *data; size_t size; size_t cap; } s_snapshot_buf_t;

static int s_snapshot_buf_put(s_snapshot_buf_t *a_buf, const void *a_data, size_t a_size)
{
    if (a_buf->size + a_size > a_buf->cap) {
        size_t l_new_cap = a_buf->cap ? a_buf->cap : (64u * 1024u);
        while (l_new_cap < a_buf->size + a_size)
            l_new_cap *= 2;
        uint8_t *l_data = DAP_REALLOC(a_buf->data, l_new_cap);
        if (!l_data)
            return -1;
        a_buf->data = l_data;
        a_buf->cap = l_new_cap;
    }
    memcpy(a_buf->data + a_buf->size, a_data, a_size);
    a_buf->size += a_size;
    return 0;
}

static char *s_snapshot_file_path(dap_ledger_t *a_ledger)
{
    // The snapshot lives next to the chain cell files: take the first block
    // chain's storage directory and use its parent (the network data dir)
    for (dap_chain_t *l_chain = a_ledger->net->pub.chains; l_chain; l_chain = l_chain->next) {
        const char *l_cs_type = dap_chain_get_cs_type(l_chain);
        if (!l_cs_type || dap_strcmp(l_cs_type, "esbocs"))
            continue;
        char *l_chain_dir = DAP_CHAIN_PVT(l_chain)->file_storage_dir;
        if (!l_chain_dir || !*l_chain_dir)
            continue;
        const char *l_slash = strrchr(l_chain_dir, '/');
        size_t l_dir_len = l_slash ? (size_t)(l_slash - l_chain_dir) : 0;
        if (!l_dir_len)
            l_dir_len = strlen(l_chain_dir);
        return dap_strdup_printf("%.*s/%s", (int)l_dir_len, l_chain_dir, DAP_LEDGER_SNAPSHOT_FILENAME);
    }
    return NULL;
}

bool dap_ledger_snapshot_mode(dap_ledger_t *a_ledger)
{
    return a_ledger && PVT(a_ledger)->snapshot_mode;
}

bool dap_ledger_snapshot_is_full(dap_ledger_t *a_ledger)
{
    return a_ledger && PVT(a_ledger)->snapshot_full;
}

bool dap_ledger_snapshot_full_apply_enabled(dap_ledger_t *a_ledger)
{
    return a_ledger && PVT(a_ledger)->snapshot_full && PVT(a_ledger)->snapshot_full_apply;
}

typedef struct s_snapshot_wallet_ctx {
    s_snapshot_buf_t *buf;
    uint64_t *count;
    bool failed;
} s_snapshot_wallet_ctx_t;

// One unspent output of a ledger transaction.
typedef void (*s_ledger_out_cb_t)(void *a_arg, dap_ledger_tx_item_t *a_item,
        const dap_chain_addr_t *a_addr, const uint256_t *a_value, const char *a_ticker,
        uint16_t a_out_idx, uint8_t a_out_type, dap_time_t a_ts_unlock);

// Walks the unspent outputs of one transaction. The tx is passed separately: the
// spend marks live in the item's flexible array, and the datum may come from a
// temporary buffer (the repair walk) rather than from the item.
static void s_ledger_tx_walk_unspent(dap_chain_datum_tx_t *a_tx, dap_ledger_tx_item_t *a_item,
                                     s_ledger_out_cb_t a_cb, void *a_arg)
{
    if (!a_tx || !a_item || !a_cb)
        return;
    uint8_t *l_it = NULL; size_t l_it_size = 0;
    uint16_t l_out_idx = 0;
    TX_ITEM_ITER_TX(l_it, l_it_size, a_tx) {
        dap_chain_addr_t *l_out_addr = NULL;
        uint256_t l_out_value = uint256_0;
        const char *l_out_ticker = NULL;
        dap_time_t l_out_ts_unlock = 0;
        uint8_t l_out_type = *l_it;
        switch (l_out_type) {
        case TX_ITEM_TYPE_OUT: {
            dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_it;
            l_out_addr = &l_out->addr; l_out_value = l_out->header.value;
            l_out_ticker = a_item->cache_data.token_ticker;
            break;
        }
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t *)l_it;
            l_out_addr = &l_out->addr; l_out_value = GET_256_FROM_64(l_out->header.value);
            l_out_ticker = a_item->cache_data.token_ticker;
            break;
        }
        case TX_ITEM_TYPE_OUT_EXT: {
            dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t *)l_it;
            l_out_addr = &l_out->addr; l_out_value = l_out->header.value;
            l_out_ticker = l_out->token;
            break;
        }
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_out = (dap_chain_tx_out_std_t *)l_it;
            l_out_addr = &l_out->addr; l_out_value = l_out->value;
            l_out_ts_unlock = l_out->ts_unlock; l_out_ticker = l_out->token;
            break;
        }
        case TX_ITEM_TYPE_OUT_COND:
            // OUT_COND belongs to the ledger's OUT_ALL index domain (n_outs and
            // the spent marks are indexed over it) but is not a wallet-cache output.
            ++l_out_idx;
            continue;
        default:
            continue; // not an output
        }
        ++l_out_idx;
        if (l_out_idx > a_item->cache_data.n_outs)
            break;
        if (!dap_hash_fast_is_blank(&a_item->cache_data.tx_hash_spent_fast[l_out_idx - 1]))
            continue; // spent output
        a_cb(a_arg, a_item, l_out_addr, &l_out_value, l_out_ticker, (uint16_t)(l_out_idx - 1),
             l_out_type, l_out_ts_unlock);
    }
}

// Wallet section record produced from a ledger transaction (dump path).
static void s_snapshot_wallet_out_put(void *a_arg, dap_ledger_tx_item_t *a_item,
        const dap_chain_addr_t *a_addr, const uint256_t *a_value, const char *a_ticker,
        uint16_t a_out_idx, uint8_t a_out_type, dap_time_t a_ts_unlock)
{
    s_snapshot_wallet_ctx_t *l_ctx = (s_snapshot_wallet_ctx_t *)a_arg;
    if (l_ctx->failed)
        return;
    size_t l_ticker_len = a_ticker ? strnlen(a_ticker, DAP_CHAIN_TICKER_SIZE_MAX) : 0;
    dap_ledger_snapshot_wallet_record_t l_rec = {
        .addr_size = (uint16_t)sizeof(dap_chain_addr_t),
        .out_idx = a_out_idx,
        .out_type = a_out_type,
        .ticker_len = (uint16_t)l_ticker_len,
        .ts_unlock = (uint64_t)a_ts_unlock,
    };
    if (s_snapshot_buf_put(l_ctx->buf, &l_rec, sizeof(l_rec))
            || s_snapshot_buf_put(l_ctx->buf, a_addr, sizeof(*a_addr))
            || s_snapshot_buf_put(l_ctx->buf, a_ticker, l_ticker_len)
            || s_snapshot_buf_put(l_ctx->buf, a_value, sizeof(*a_value))
            || s_snapshot_buf_put(l_ctx->buf, &a_item->tx_hash_fast, sizeof(a_item->tx_hash_fast))) {
        l_ctx->failed = true;
        return;
    }
    ++*l_ctx->count;
}

// Wallet section record from the wallet cache (no-scan snapshot save).
static void s_snapshot_wallet_record_put(void *a_arg, const dap_chain_addr_t *a_addr,
        const dap_chain_hash_fast_t *a_tx_hash, uint16_t a_out_idx, uint8_t a_out_type,
        dap_time_t a_ts_unlock, const char *a_ticker, const uint256_t *a_value)
{
    s_snapshot_wallet_ctx_t *l_ctx = (s_snapshot_wallet_ctx_t *)a_arg;
    if (l_ctx->failed)
        return;
    size_t l_ticker_len = a_ticker ? strnlen(a_ticker, DAP_CHAIN_TICKER_SIZE_MAX) : 0;
    dap_ledger_snapshot_wallet_record_t l_rec = {
        .addr_size = (uint16_t)sizeof(dap_chain_addr_t),
        .out_idx = a_out_idx,
        .out_type = a_out_type,
        .ticker_len = (uint16_t)l_ticker_len,
        .ts_unlock = (uint64_t)a_ts_unlock,
    };
    if (s_snapshot_buf_put(l_ctx->buf, &l_rec, sizeof(l_rec))
            || s_snapshot_buf_put(l_ctx->buf, a_addr, sizeof(*a_addr))
            || s_snapshot_buf_put(l_ctx->buf, a_ticker, l_ticker_len)
            || s_snapshot_buf_put(l_ctx->buf, a_value, sizeof(*a_value))
            || s_snapshot_buf_put(l_ctx->buf, a_tx_hash, sizeof(*a_tx_hash))) {
        l_ctx->failed = true;
        return;
    }
    ++*l_ctx->count;
}

int dap_ledger_snapshot_save(dap_ledger_t *a_ledger, bool a_shutdown)
{
    dap_return_val_if_fail(a_ledger && PVT(a_ledger)->snapshot_mode, -1);
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    // Never save while the chains are loading: the scan attaches datums as it
    // walks, and a snapshot written before it finishes carries a partial wallet
    // section (unspent outs only for the transactions seen so far) that the
    // next start would trust as complete and skip the rebuilding pass for.
    if (a_ledger->net && dap_chain_net_get_load_mode(a_ledger->net)) {
        debug_if(s_debug_more, L_DEBUG, "Ledger snapshot: save skipped while net %s is loading",
                 a_ledger->net->pub.name);
        return 0;
    }

    // Never persist a position above the local cell files: an item without its datum is an
    // effect of a block that lives only in this process (accepted from the network while the
    // chain scan was still running, or restored from an earlier snapshot that did the same).
    // Saving such a position bakes phantom items into the next restart - their datums can
    // never be completed because the blocks are not in the cell files, and services that
    // need the transactions (voting reads the poll transaction from the ledger) then see a
    // ledger ahead of the chain. Keep the previous snapshot; once the catch-up writes those
    // blocks into the cell files, the next scan completes the datums and this check passes.
    bool l_phantom = false;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    dap_ledger_tx_item_t *l_phantom_item = NULL, *l_phantom_tmp = NULL;
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_phantom_item, l_phantom_tmp) {
        if (!l_phantom_item->tx) {
            // A complete snapshot restores items without their datum on purpose:
            // the datum is attached lazily from the atom link. Only an item with
            // no datum AND no atom link is a phantom - it came from a block that
            // is not in the local cell files. Refusing to save in the restored
            // case kept the snapshot (and its anchor) frozen forever after a
            // no-scan start.
            if (l_ledger_pvt->snapshot_full && l_phantom_item->atom_link_valid)
                continue;
            l_phantom = true;
            break;
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    if (l_phantom) {
        log_it(L_WARNING, "Ledger snapshot: ledger has items without datums (their blocks are "
                          "not in the local cell files yet) - keeping the previous snapshot");
        return 0;
    }

    // Same rule for tokens: the ledger_state section writes each declaration's
    // bytes, and a token without them is written with token_size = 0 - the next
    // start cannot recreate that token at all. That is exactly how the section
    // shrank from 1.07 GB to 393 MB across restarts on cf-mm-0 and tokens the
    // ledger had held for a week (QEVM) disappeared from `token info`. Keep the
    // previous snapshot until every token carries its declaration.
    {
        bool l_token_without_decl = false;
        const char *l_bad_ticker = NULL;
        pthread_rwlock_rdlock(&l_ledger_pvt->tokens_rwlock);
        for (dap_ledger_token_item_t *l_tok = l_ledger_pvt->tokens; l_tok; l_tok = l_tok->hh.next) {
            if (!l_tok->datum_token || !l_tok->datum_token_size) {
                l_token_without_decl = true;
                l_bad_ticker = l_tok->ticker;
                break;
            }
        }
        pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
        if (l_token_without_decl) {
            log_it(L_WARNING, "Ledger snapshot: token '%s' carries no declaration in this ledger "
                              "(a restored item without its datum) - keeping the previous snapshot "
                              "instead of writing a section that would lose it",
                   l_bad_ticker ? l_bad_ticker : "?");
            return 0;
        }
    }

    char *l_path = s_snapshot_file_path(a_ledger);
    if (!l_path) {
        log_it(L_WARNING, "Ledger snapshot: can't find a block chain storage dir, save skipped");
        return -1;
    }
    // Remove tmp files of saves interrupted by a shutdown/kill. Only stale ones:
    // a concurrent save may be writing its own unique tmp right now.
#ifndef DAP_OS_WINDOWS
    {
        char *l_glob = dap_strdup_printf("%s.tmp.*", l_path);
        glob_t l_matches = {0};
        if (l_glob && glob(l_glob, 0, NULL, &l_matches) == 0) {
            time_t l_now = time(NULL);
            for (size_t i = 0; i < l_matches.gl_pathc; ++i) {
                struct stat l_st = {0};
                if (stat(l_matches.gl_pathv[i], &l_st) == 0
                        && l_now > l_st.st_mtime && l_now - l_st.st_mtime > 600)
                    unlink(l_matches.gl_pathv[i]);
            }
            globfree(&l_matches);
        }
        DAP_DELETE(l_glob);
    }
#endif
    // Unique per save: the periodic timer and a shutdown save can overlap, and a
    // shared "<path>.tmp" let one of them rename/remove the other's file
    // (live: "io ok, rename -1" at shutdown).
    char *l_tmp_path = dap_strdup_printf("%s.tmp.%d.%" DAP_UINT64_FORMAT_U, l_path,
            (int)getpid(), (uint64_t)dap_nanotime_now());

    s_snapshot_buf_t l_buf = {};
    uint64_t l_n_tx = 0, l_n_balances = 0;
    int l_ret = 0;
    uint64_t l_n_wallet_outs = 0;

    // Atom links come from the chain-state index (no block reads): the snapshot
    // stores where each restored transaction's datum lives.
    dap_chain_t *l_link_chain = NULL;
    for (dap_chain_t *l_c = a_ledger->net->pub.chains; l_c; l_c = l_c->next) {
        const char *l_cs_type = dap_chain_get_cs_type(l_c);
        if (l_cs_type && !dap_strcmp(l_cs_type, "esbocs")) {
            l_link_chain = l_c;
            break;
        }
    }
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    dap_ledger_tx_item_t *l_item = NULL, *l_item_tmp = NULL;
    HASH_ITER (hh, l_ledger_pvt->ledger_items, l_item, l_item_tmp) {
        uint32_t l_cache_size = (uint32_t)(sizeof(l_item->cache_data)
                                           + l_item->cache_data.n_outs * sizeof(dap_chain_hash_fast_t));
        dap_ledger_snapshot_tx_record_v4_t l_rec = { .cache_size = l_cache_size };
        memcpy(l_rec.tx_hash, &l_item->tx_hash_fast, sizeof(l_rec.tx_hash));
        dap_chain_hash_fast_t l_atom_hash = {};
        uint32_t l_datum_idx = 0;
        if (l_link_chain && !dap_chain_cs_blocks_datum_location(l_link_chain, &l_item->tx_hash_fast,
                                                            &l_atom_hash, &l_datum_idx)) {
            memcpy(l_rec.atom_hash, &l_atom_hash, sizeof(l_rec.atom_hash));
            l_rec.datum_index = l_datum_idx;
            l_rec.atom_link_valid = 1;
        }
        if (s_snapshot_buf_put(&l_buf, &l_rec, sizeof(l_rec)) || s_snapshot_buf_put(&l_buf, &l_item->cache_data, l_cache_size)) {
            l_ret = -2;
            break;
        }
        l_n_tx++;
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);

    if (!l_ret) {
        pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
        dap_ledger_wallet_balance_t *l_balance = NULL, *l_balance_tmp = NULL;
        HASH_ITER (hh, l_ledger_pvt->balance_accounts, l_balance, l_balance_tmp) {
            size_t l_key_len = strlen(l_balance->key);
            size_t l_ticker_len = strnlen(l_balance->token_ticker, sizeof(l_balance->token_ticker));
            if (l_key_len > UINT16_MAX - 1 || l_ticker_len > UINT16_MAX - 1) {
                // Impossible for the current key/ticker formats, skip the outlier
                log_it(L_WARNING, "Ledger snapshot: balance key/ticker too long, skipped");
                continue;
            }
            dap_ledger_snapshot_balance_record_t l_rec = {
                .key_len = (uint16_t)l_key_len, .ticker_len = (uint16_t)l_ticker_len
            };
            bool l_fail = s_snapshot_buf_put(&l_buf, &l_rec, sizeof(l_rec))
                    || s_snapshot_buf_put(&l_buf, l_balance->key, l_key_len)
                    || s_snapshot_buf_put(&l_buf, l_balance->token_ticker, l_ticker_len)
                    || s_snapshot_buf_put(&l_buf, &l_balance->balance, sizeof(l_balance->balance));
            if (l_fail) {
                l_ret = -2;
                break;
            }
            ++l_n_balances;
        }
        pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    }

    // Wallet section: every unspent output with its owner address, so the
    // wallet cache is warm right after a snapshot restore without re-walking
    // the whole chain. Saved only in wallets_cache=all mode (the only mode
    // that keeps a per-address unspent index).
    if (!l_ret && l_ledger_pvt->snapshot_mode && s_snapshot_wallet_section_enabled()
            && dap_chain_wallet_cache_index_restored(a_ledger->net->pub.id)) {
        // No-scan start: the ledger items carry no datums (they are attached
        // lazily), so their outputs cannot be walked. The restored wallet index
        // holds exactly that unspent set - dump it directly.
        s_snapshot_wallet_ctx_t l_wctx = { .buf = &l_buf, .count = &l_n_wallet_outs };
        dap_chain_wallet_cache_foreach_unspent(a_ledger->net->pub.id,
                                               s_snapshot_wallet_record_put, &l_wctx);
        if (l_wctx.failed)
            l_ret = -2;
    } else if (!l_ret && l_ledger_pvt->snapshot_mode && s_snapshot_wallet_section_enabled()) {
        pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
        s_snapshot_wallet_ctx_t l_wctx = { .buf = &l_buf, .count = &l_n_wallet_outs };
        dap_ledger_tx_item_t *l_witem = NULL, *l_wtmp = NULL;
        HASH_ITER (hh, l_ledger_pvt->ledger_items, l_witem, l_wtmp) {
            if (!l_witem->tx) // datum-less restored item: datums are absent until the scan
                continue;
            s_ledger_tx_walk_unspent(l_witem->tx, l_witem, s_snapshot_wallet_out_put, &l_wctx);
            if (l_wctx.failed) {
                l_ret = -2;
                break;
            }
        }
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    }

    // Extension sections (v3): registered services dump their data after the
    // wallet section; the ledger core does not interpret it.
    uint32_t l_n_sections = 0;
    bool l_full_state = false;
    if (!l_ret) {
        dap_ledger_snapshot_section_desc_t l_descs[DAP_LEDGER_SNAPSHOT_MAX_SECTIONS] = {};
        s_snapshot_buf_t l_sections_buf = {};
        pthread_mutex_lock(&s_snapshot_sections_lock);
        for (s_ledger_snapshot_section_t *l_sec = s_snapshot_sections;
                l_sec && l_n_sections < DAP_LEDGER_SNAPSHOT_MAX_SECTIONS; l_sec = l_sec->next) {
            if (!l_sec->dump)
                continue;
            dap_string_t *l_data = dap_string_new("");
            if (!l_data || l_sec->dump(l_sec->ctx, a_ledger->net->pub.id.uint64, l_data) || !l_data->len) {
                if (l_data)
                    dap_string_free(l_data, true);
                continue;
            }
            dap_ledger_snapshot_section_desc_t *l_desc = &l_descs[l_n_sections];
            dap_strncpy(l_desc->name, l_sec->name, sizeof(l_desc->name) - 1);
            l_desc->flags = l_sec->flags;
            l_desc->size = l_data->len;
            l_desc->crc64 = crc64((const uint8_t *)l_data->str, l_data->len);
            if (s_snapshot_buf_put(&l_sections_buf, l_data->str, l_data->len))
                l_ret = -2;
            dap_string_free(l_data, true);
            if (l_ret)
                break;
            // Header bit2: this file carries the complete ledger state, not only
            // the transaction cache and balances.
            if (l_sec->flags & DAP_LEDGER_SNAPSHOT_SECTION_FLAG_FULL)
                l_full_state = true;
            ++l_n_sections;
        }
        pthread_mutex_unlock(&s_snapshot_sections_lock);
        if (!l_ret && l_n_sections) {
            if (s_snapshot_buf_put(&l_buf, l_descs, sizeof(l_descs[0]) * l_n_sections)
                    || s_snapshot_buf_put(&l_buf, l_sections_buf.data, l_sections_buf.size))
                l_ret = -2;
        }
        DAP_DEL_Z(l_sections_buf.data);
    }

    if (l_ret) {
        log_it(L_ERROR, "Ledger snapshot: allocation error, save aborted");
        DAP_DEL_Z(l_buf.data);
        DAP_DELETE(l_path);
        DAP_DELETE(l_tmp_path);
        return l_ret;
    }

    dap_ledger_snapshot_header_t l_header = {};
    memcpy(l_header.magic, DAP_LEDGER_SNAPSHOT_MAGIC, sizeof(l_header.magic));
    l_header.version = DAP_LEDGER_SNAPSHOT_VERSION;
    l_header.header_size = (uint32_t)sizeof(l_header);
    l_header.net_id = a_ledger->net->pub.id.uint64;
    l_header.ts_saved = (uint64_t)time(NULL);
    l_header.n_tx_items = l_n_tx;
    l_header.n_balances = l_n_balances;
    l_header.payload_size = l_buf.size;
    l_header.crc64 = crc64(l_buf.data, l_buf.size);
    l_header.flags = (l_n_wallet_outs ? 0x1u : 0u) | (l_n_sections ? 0x2u : 0u)
            | (l_full_state ? 0x4u : 0u);
    l_header.n_wallet_outs = l_n_wallet_outs;
    l_header.n_sections = l_n_sections;
    // Anchor the snapshot to the block chain position it was taken at: on the
    // next start the scan skips transaction processing up to this block and
    // validates continuity against the hash before switching to live processing
    for (dap_chain_t *l_chain = a_ledger->net->pub.chains; l_chain; l_chain = l_chain->next) {
        const char *l_cs_type = dap_chain_get_cs_type(l_chain);
        if (!l_cs_type || dap_strcmp(l_cs_type, "esbocs"))
            continue;
        dap_chain_hash_fast_t l_tip_hash = {};
        uint64_t l_tip_num = 0;
        if (dap_chain_cs_blocks_get_tip(l_chain, &l_tip_num, &l_tip_hash)) {
            l_header.block_num = l_tip_num;
            memcpy(l_header.block_hash, &l_tip_hash, sizeof(l_header.block_hash));
        }
        break;
    }

    FILE *l_file = fopen(l_tmp_path, "wb");
    if (!l_file) {
        log_it(L_ERROR, "Ledger snapshot: can't open %s for writing", l_tmp_path);
        DAP_DEL_Z(l_buf.data);
        DAP_DELETE(l_path);
        DAP_DELETE(l_tmp_path);
        return -3;
    }
    bool l_ok = fwrite(&l_header, sizeof(l_header), 1, l_file) == 1
            && (!l_buf.size || fwrite(l_buf.data, l_buf.size, 1, l_file) == 1);
    if (l_ok) {
        // A shutdown save runs inside the SIGTERM handler: fflush/fsync can be
        // interrupted (EINTR) and must be retried instead of reporting a failure
        // for a snapshot that was actually written.
        l_ok = false;
        for (int l_try = 0; l_try < 3; l_try++) {
            errno = 0;
            if (fflush(l_file) == 0 && fsync(fileno(l_file)) == 0) {
                l_ok = true;
                break;
            }
            if (errno != EINTR)
                break;
        }
    }
    fclose(l_file);
    int l_rename_rc;
    do {
        errno = 0;
        l_rename_rc = rename(l_tmp_path, l_path);
    } while (l_rename_rc && errno == EINTR);
    if (!l_ok || l_rename_rc) {
        log_it(L_ERROR, "Ledger snapshot: save to %s failed%s (io %s, rename %d: %s)",
               l_path, a_shutdown ? " (shutdown)" : "", l_ok ? "ok" : "error", l_rename_rc,
               l_rename_rc ? dap_strerror(errno) : "-");
        remove(l_tmp_path);
        l_ret = -4;
    } else {
        log_it(l_n_tx ? L_INFO : L_NOTICE, "Ledger snapshot%s saved: %s (%"DAP_UINT64_FORMAT_U" tx items, %"
               DAP_UINT64_FORMAT_U" balances, %"DAP_UINT64_FORMAT_U" bytes)",
               a_shutdown ? " (shutdown)" : "", l_path, l_n_tx, l_n_balances,
               (uint64_t)(l_buf.size + sizeof(l_header)));
    }
    DAP_DEL_Z(l_buf.data);
    DAP_DELETE(l_path);
    DAP_DELETE(l_tmp_path);
    return l_ret;
}

bool dap_ledger_snapshot_skip_get(dap_ledger_t *a_ledger, uint64_t *a_block_num, dap_chain_hash_fast_t *a_block_hash)
{
    if (!a_ledger || !PVT(a_ledger)->snapshot_skip_active)
        return false;
    *a_block_num = PVT(a_ledger)->snapshot_skip_num;
    *a_block_hash = PVT(a_ledger)->snapshot_skip_hash;
    return true;
}

void dap_ledger_snapshot_skip_set(dap_ledger_t *a_ledger, uint64_t a_block_num,
                                  const dap_chain_hash_fast_t *a_block_hash)
{
    if (!a_ledger || !a_block_hash || !a_block_num || PVT(a_ledger)->snapshot_skip_active)
        return;
    PVT(a_ledger)->snapshot_skip_active = true;
    PVT(a_ledger)->snapshot_skip_num = a_block_num;
    PVT(a_ledger)->snapshot_skip_hash = *a_block_hash;
}

void dap_ledger_snapshot_skip_consume(dap_ledger_t *a_ledger)
{
    if (!a_ledger)
        return;
    PVT(a_ledger)->snapshot_skip_active = false;
    PVT(a_ledger)->snapshot_skip_num = 0;
    memset(&PVT(a_ledger)->snapshot_skip_hash, 0, sizeof(PVT(a_ledger)->snapshot_skip_hash));
}

// Structural validation of a snapshot payload BEFORE anything is applied. The
// header (counts, sizes, flags) is not covered by the CRC, so a corrupted or
// crafted header could point the section readers anywhere; and a partially
// applied snapshot (items without their balances, truncated sections) would
// leave the scan believing the restored parts are already accounted for, which
// double-counts balances. Returns 0 only when the payload walks exactly to its
// end with all declared records structurally valid.
static int s_snapshot_validate_payload(const dap_ledger_snapshot_header_t *a_hdr, const uint8_t *a_payload, size_t a_size)
{
    const uint8_t *l_ptr = a_payload, *l_end = a_payload + a_size;
    const bool l_v4 = a_hdr->version >= 4;
    const size_t l_tx_rec_size = l_v4 ? sizeof(dap_ledger_snapshot_tx_record_v4_t)
                                      : sizeof(dap_ledger_snapshot_tx_record_t);
    for (uint64_t i = 0; i < a_hdr->n_tx_items; ++i) {
        if ((size_t)(l_end - l_ptr) < l_tx_rec_size)
            return -1;
        uint32_t l_cache_size = l_v4 ? ((const dap_ledger_snapshot_tx_record_v4_t *)l_ptr)->cache_size
                                     : ((const dap_ledger_snapshot_tx_record_t *)l_ptr)->cache_size;
        if (l_cache_size < sizeof(dap_ledger_tx_cache_t))
            return -1;
        const dap_ledger_tx_cache_t *l_cache = (const dap_ledger_tx_cache_t *)(l_ptr + l_tx_rec_size);
        // The cache record is exactly the fixed part plus one spent-mark hash
        // per output; n_outs_used cannot exceed n_outs.
        if ((uint64_t)l_cache_size != sizeof(dap_ledger_tx_cache_t)
                + (uint64_t)l_cache->n_outs * sizeof(dap_chain_hash_fast_t))
            return -1;
        if (l_cache->n_outs_used > l_cache->n_outs)
            return -1;
        l_ptr += l_tx_rec_size + l_cache_size;
        if (l_ptr > l_end)
            return -1;
    }
    for (uint64_t i = 0; i < a_hdr->n_balances; ++i) {
        if (l_ptr + sizeof(dap_ledger_snapshot_balance_record_t) > l_end)
            return -1;
        const dap_ledger_snapshot_balance_record_t *l_rec = (const dap_ledger_snapshot_balance_record_t *)l_ptr;
        l_ptr += sizeof(*l_rec);
        if (l_rec->ticker_len >= DAP_CHAIN_TICKER_SIZE_MAX)
            return -1;
        if (l_ptr + (size_t)l_rec->key_len + l_rec->ticker_len + sizeof(uint256_t) > l_end)
            return -1;
        l_ptr += (size_t)l_rec->key_len + l_rec->ticker_len + sizeof(uint256_t);
    }
    if ((a_hdr->flags & 0x1u) && a_hdr->n_wallet_outs) {
        for (uint64_t i = 0; i < a_hdr->n_wallet_outs; ++i) {
            if (l_ptr + sizeof(dap_ledger_snapshot_wallet_record_t) > l_end)
                return -1;
            const dap_ledger_snapshot_wallet_record_t *l_rec = (const dap_ledger_snapshot_wallet_record_t *)l_ptr;
            l_ptr += sizeof(*l_rec);
            if (l_rec->addr_size != sizeof(dap_chain_addr_t) || l_rec->ticker_len >= DAP_CHAIN_TICKER_SIZE_MAX)
                return -1;
            if (l_ptr + l_rec->addr_size + l_rec->ticker_len + sizeof(uint256_t) + sizeof(dap_chain_hash_fast_t) > l_end)
                return -1;
            l_ptr += l_rec->addr_size + l_rec->ticker_len + sizeof(uint256_t) + sizeof(dap_chain_hash_fast_t);
        }
    }
    if ((a_hdr->flags & 0x2u) && a_hdr->n_sections) {
        if (!a_payload || a_hdr->n_sections > DAP_LEDGER_SNAPSHOT_MAX_SECTIONS)
            return -1;
        size_t l_desc_size = sizeof(dap_ledger_snapshot_section_desc_t) * a_hdr->n_sections;
        if (l_ptr + l_desc_size > l_end)
            return -1;
        const dap_ledger_snapshot_section_desc_t *l_desc =
                (const dap_ledger_snapshot_section_desc_t *)l_ptr;
        l_ptr += l_desc_size;
        for (uint32_t i = 0; i < a_hdr->n_sections; ++i) {
            if (!memchr(l_desc[i].name, 0, sizeof(l_desc[i].name))
                    || l_desc[i].size > (uint64_t)(l_end - l_ptr))
                return -1;
            if (crc64(l_ptr, l_desc[i].size) != l_desc[i].crc64)
                return -1;
            l_ptr += l_desc[i].size;
        }
    }
    // No trailing bytes: a tail means the counts and the payload disagree.
    return l_ptr == l_end ? 0 : -1;
}

int dap_ledger_snapshot_load(dap_ledger_t *a_ledger)
{    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    char *l_path = s_snapshot_file_path(a_ledger);
    if (!l_path)
        return 0;
    FILE *l_file = fopen(l_path, "rb");
    if (!l_file) {
        log_it(L_NOTICE, "Ledger snapshot: no snapshot file %s, loading the ledger from the chains", l_path);
        DAP_DELETE(l_path);
        return 0;
    }
    dap_ledger_snapshot_header_t l_header = {};
    int l_ret = 0;
    uint64_t l_loaded_tx = 0, l_loaded_balances = 0;
    const dap_nanotime_t l_t_start = dap_nanotime_now();
    uint8_t *l_payload = NULL;
    // Mapping of this snapshot's payload, when serviced by mmap: extension
    // sections borrow their bytes from it instead of copying them.
    s_snapshot_mapping_t *l_snapshot_map = NULL;
    do {
        // The first 16 bytes (magic/version/header_size) are common to every
        // version: read them first so a v1 file (64- or 104-byte header) does
        // not over-read into the payload, then take whatever follows up to the
        // declared header size.
        if (fread(&l_header, 1, 16, l_file) != 16
                || memcmp(l_header.magic, DAP_LEDGER_SNAPSHOT_MAGIC, sizeof(l_header.magic))) {
            log_it(L_WARNING, "Ledger snapshot: %s is not a ledger snapshot file (magic/version), ignoring", l_path);
            l_ret = 0;
            break;
        }
        if (l_header.header_size < 16 || l_header.header_size > 0x10000) {
            log_it(L_WARNING, "Ledger snapshot: %s declares no usable header (%u), ignoring", l_path, l_header.header_size);
            l_ret = 0;
            break;
        }
        size_t l_header_read = l_header.header_size < sizeof(l_header) ? l_header.header_size : sizeof(l_header);
        if (l_header_read > 16
                && fread((uint8_t *)&l_header + 16, 1, l_header_read - 16, l_file) != l_header_read - 16) {
            log_it(L_WARNING, "Ledger snapshot: %s has a truncated header, ignoring", l_path);
            l_ret = 0;
            break;
        }
        if (l_header.version < 1 || l_header.version > DAP_LEDGER_SNAPSHOT_VERSION
                || l_header.header_size < sizeof(dap_ledger_snapshot_header_t) - 16 // the fixed fields v1 always had
                || l_header.net_id != a_ledger->net->pub.id.uint64
                || l_header.payload_size > ((uint64_t)4) << 30) {
            log_it(L_WARNING, "Ledger snapshot: %s is not a usable snapshot for this network (version %u), ignoring",
                   l_path, l_header.version);
            l_ret = 0;
            break;
        }
        log_it(L_NOTICE, "Ledger snapshot: header v%u, header_size %u, net_id 0x%016"DAP_UINT64_FORMAT_x
               ", block_num %"DAP_UINT64_FORMAT_U", payload %"DAP_UINT64_FORMAT_U" bytes",
               l_header.version, l_header.header_size, l_header.net_id, l_header.block_num, l_header.payload_size);
        if (l_header.header_size > sizeof(l_header))
            fseek(l_file, (long)(l_header.header_size - sizeof(l_header)), SEEK_CUR);
        if (l_header.payload_size) {
            // Map the payload instead of reading it into the heap: on the 8 GB
            // 0-rpc box two 1.7-1.9 GB payloads in malloc'd memory (plus a copy
            // of every extension section out of them) was what drove the node
            // into the OOM killer. Mapped pages are file-backed and reclaimable.
            // The payload starts right after the header, at an offset that is
            // not page-aligned: map from the page boundary below and offset into
            // the mapping, or mmap answers EINVAL.
#ifndef _WIN32
            off_t l_payload_off = ftello(l_file);
            long l_page = sysconf(_SC_PAGESIZE);
            if (l_payload_off >= 0 && l_page > 0) {
                off_t l_map_off = l_payload_off - (l_payload_off % l_page);
                size_t l_map_len = (size_t)(l_payload_off - l_map_off) + l_header.payload_size;
                void *l_map = mmap(NULL, l_map_len, PROT_READ, MAP_PRIVATE, fileno(l_file), l_map_off);
                if (l_map != MAP_FAILED) {
                    l_snapshot_map = s_snapshot_mapping_hold(l_map, l_map_len);
                    if (l_snapshot_map)
                        l_payload = (uint8_t *)l_map + (l_payload_off - l_map_off);
                    else
                        munmap(l_map, l_map_len);   // no tracker: fall through to the heap
                }
            }
#endif
            if (!l_payload) {
                l_payload = DAP_NEW_Z_SIZE(uint8_t, l_header.payload_size);
                if (!l_payload || fread(l_payload, l_header.payload_size, 1, l_file) != 1) {
                    log_it(L_WARNING, "Ledger snapshot: %s is truncated, ignoring", l_path);
                    l_ret = 0;
                    break;
                }
            } else {
                log_it(L_INFO, "Ledger snapshot: payload of %" DAP_UINT64_FORMAT_U
                       " bytes is mapped, not copied", l_header.payload_size);
            }
            if (crc64(l_payload, l_header.payload_size) != l_header.crc64) {
                log_it(L_WARNING, "Ledger snapshot: %s is corrupt, ignoring", l_path);
                l_ret = 0;
                break;
            }
        }
        // Structure first, apply second: the header is not covered by the CRC,
        // and a half-applied snapshot would leave the scan double-counting the
        // restored aggregates.
        if (s_snapshot_validate_payload(&l_header, l_payload, l_header.payload_size)) {
            log_it(L_WARNING, "Ledger snapshot: %s has an invalid payload structure, ignoring", l_path);
            l_ret = 0;
            break;
        }
        // Header flag bit2: the file carries the complete ledger state. This must
        // be known BEFORE the chain scan starts (that is where the service replay
        // of the restored transactions is suppressed); the section itself is
        // applied later, at load end, and clears the flag if the restore fails.
        l_ledger_pvt->snapshot_full = (l_header.flags & 0x4u) != 0;
        if (l_ledger_pvt->snapshot_full && l_ledger_pvt->snapshot_full_apply)
            log_it(L_NOTICE, "Ledger snapshot: %s is a complete ledger state, service replay of "
                   "the restored transactions is suppressed", l_path);
        // An empty tx section with non-empty balances is not a coherent state:
        // the balances are aggregates over the history those items describe,
        // and the scan would re-apply every delta on top of them. (This is the
        // "0 tx items" file a broken skip-era build left behind.)
        if (!l_header.n_tx_items) {
            log_it(L_WARNING, "Ledger snapshot: %s carries no tx items, ignoring "
                   "(restored balances alone would double-count on the replay)", l_path);
            l_ret = 0;
            break;
        }
        // Restore the transaction cache items (datum-less: completed by the chain scan)
        uint8_t *l_ptr = l_payload, *l_end = l_payload + l_header.payload_size;
        const bool l_v4 = l_header.version >= 4;
        const size_t l_tx_rec_size = l_v4 ? sizeof(dap_ledger_snapshot_tx_record_v4_t)
                                          : sizeof(dap_ledger_snapshot_tx_record_t);
        pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
        for (uint64_t i = 0; i < l_header.n_tx_items; ++i) {
            if ((size_t)(l_end - l_ptr) < l_tx_rec_size) {
                log_it(L_WARNING, "Ledger snapshot: truncated tx section at item %"DAP_UINT64_FORMAT_U, i);
                break;
            }
            uint8_t *l_tx_hash = l_ptr;
            uint8_t *l_atom_hash = l_v4 ? l_ptr + sizeof(dap_chain_hash_fast_t) : NULL;
            uint32_t l_datum_index = l_v4 ? ((dap_ledger_snapshot_tx_record_v4_t *)l_ptr)->datum_index : 0;
            uint32_t l_atom_link_valid = l_v4 ? ((dap_ledger_snapshot_tx_record_v4_t *)l_ptr)->atom_link_valid : 0;
            uint32_t l_cache_size = l_v4 ? ((dap_ledger_snapshot_tx_record_v4_t *)l_ptr)->cache_size
                                         : ((dap_ledger_snapshot_tx_record_t *)l_ptr)->cache_size;
            l_ptr += l_tx_rec_size;
            if ((size_t)(l_end - l_ptr) < l_cache_size) {
                log_it(L_WARNING, "Ledger snapshot: truncated tx record payload at item %"DAP_UINT64_FORMAT_U, i);
                break;
            }
            dap_ledger_tx_item_t *l_item = DAP_NEW_Z_SIZE(dap_ledger_tx_item_t,
                                                sizeof(dap_ledger_tx_item_t) - sizeof(l_item->cache_data) + l_cache_size);
            if (!l_item) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                break;
            }
            memcpy(&l_item->tx_hash_fast, l_tx_hash, sizeof(l_item->tx_hash_fast));
            if (l_atom_hash) {
                memcpy(&l_item->atom_hash, l_atom_hash, sizeof(l_item->atom_hash));
                l_item->datum_index = l_datum_index;
                l_item->atom_link_valid = l_atom_link_valid;
            }
            memcpy(&l_item->cache_data, l_ptr, l_cache_size);
            l_ptr += l_cache_size;
            HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(l_item->tx_hash_fast), l_item);
            ++l_loaded_tx;
        }
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
        dap_nanotime_t l_t_tx = dap_nanotime_now();
        // Restore the balances exactly like the GlobalDB balances stage does
        pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
        for (uint64_t i = 0; i < l_header.n_balances; ++i) {
            if (l_ptr + sizeof(dap_ledger_snapshot_balance_record_t) > l_end) {
                log_it(L_WARNING, "Ledger snapshot: truncated balances section at record %"DAP_UINT64_FORMAT_U, i);
                break;
            }
            dap_ledger_snapshot_balance_record_t *l_rec = (dap_ledger_snapshot_balance_record_t *)l_ptr;
            l_ptr += sizeof(*l_rec);
            if (l_ptr + (size_t)l_rec->key_len + l_rec->ticker_len + sizeof(uint256_t) > l_end) {
                log_it(L_WARNING, "Ledger snapshot: truncated balance record payload at record %"DAP_UINT64_FORMAT_U, i);
                break;
            }
            dap_ledger_wallet_balance_t *l_balance = DAP_NEW_Z(dap_ledger_wallet_balance_t);
            if (!l_balance) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                break;
            }
            l_balance->key = DAP_NEW_Z_SIZE(char, l_rec->key_len + 1);
            if (!l_balance->key) {
                DAP_DEL_Z(l_balance);
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                break;
            }
            memcpy(l_balance->key, l_ptr, l_rec->key_len);
            l_ptr += l_rec->key_len;
            memcpy(l_balance->token_ticker, l_ptr, l_rec->ticker_len);
            l_ptr += l_rec->ticker_len;
            memcpy(&l_balance->balance, l_ptr, sizeof(l_balance->balance));
            l_ptr += sizeof(l_balance->balance);
            HASH_ADD_KEYPTR(hh, l_ledger_pvt->balance_accounts, l_balance->key, strlen(l_balance->key), l_balance);
            ++l_loaded_balances;
        }
        pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
        dap_nanotime_t l_t_bal = dap_nanotime_now();
        // Restore the wallet cache unspent index (v2 header, flag bit0)
        if ((l_header.flags & 0x1u) && l_header.n_wallet_outs) {
            uint64_t l_restored_wallet = 0;
            for (uint64_t i = 0; i < l_header.n_wallet_outs; ++i) {
                if (l_ptr + sizeof(dap_ledger_snapshot_wallet_record_t) > l_end) {
                    log_it(L_WARNING, "Ledger snapshot: truncated wallet section at record %"DAP_UINT64_FORMAT_U, i);
                    break;
                }
                dap_ledger_snapshot_wallet_record_t *l_rec = (dap_ledger_snapshot_wallet_record_t *)l_ptr;
                l_ptr += sizeof(*l_rec);
                if (l_ptr + l_rec->addr_size + l_rec->ticker_len + sizeof(uint256_t) + sizeof(dap_chain_hash_fast_t) > l_end) {
                    log_it(L_WARNING, "Ledger snapshot: truncated wallet record payload at record %"DAP_UINT64_FORMAT_U, i);
                    break;
                }
                dap_chain_addr_t l_addr = {};
                memcpy(&l_addr, l_ptr, l_rec->addr_size);
                l_ptr += l_rec->addr_size;
                char l_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = {0};
                memcpy(l_ticker, l_ptr, l_rec->ticker_len);
                l_ptr += l_rec->ticker_len;
                uint256_t l_value = {};
                memcpy(&l_value, l_ptr, sizeof(l_value));
                l_ptr += sizeof(l_value);
                dap_chain_hash_fast_t l_tx_hash = {};
                memcpy(&l_tx_hash, l_ptr, sizeof(l_tx_hash));
                l_ptr += sizeof(l_tx_hash);
                dap_chain_wallet_cache_restore_unspent(a_ledger->net->pub.id, &l_addr, &l_tx_hash,
                                                       l_rec->out_idx, l_rec->out_type,
                                                       (dap_time_t)l_rec->ts_unlock, l_ticker, l_value);
                ++l_restored_wallet;
            }
            if (l_restored_wallet == l_header.n_wallet_outs
                    && s_snapshot_wallet_section_plausible(a_ledger, l_header.n_wallet_outs)) {
                dap_chain_wallet_cache_bulk_done_mark(a_ledger->net->pub.id);
                log_it(L_NOTICE, "Ledger snapshot: wallet cache restored (%"DAP_UINT64_FORMAT_U
                       " unspent outputs, %" DAP_UINT64_FORMAT_U " ms), bulk pass is not needed",
                       l_restored_wallet, (uint64_t)(dap_nanotime_now() - l_t_bal) / 1000000);
            } else if (l_restored_wallet == l_header.n_wallet_outs) {
                // The section was written by a build that dumped it from datum-less
                // ledger items: it says "complete" but covers almost nothing. Leave
                // the marker unset so the regular wallet bulk pass rebuilds the
                // index from the datums.
                log_it(L_WARNING, "Ledger snapshot: wallet section carries only %"DAP_UINT64_FORMAT_U
                       " record(s) for this ledger - the wallet bulk pass will rebuild the index",
                       l_header.n_wallet_outs);
            } else
                log_it(L_WARNING, "Ledger snapshot: wallet section restored %"DAP_UINT64_FORMAT_U
                       " of %"DAP_UINT64_FORMAT_U" records - the wallet bulk pass will re-run", l_restored_wallet, l_header.n_wallet_outs);
        }
        // Extension sections (v3).
        if ((l_header.flags & 0x2u) && l_header.n_sections) {
            size_t l_desc_size = sizeof(dap_ledger_snapshot_section_desc_t) * l_header.n_sections;
            if (l_ptr + l_desc_size > l_end) {
                log_it(L_WARNING, "Ledger snapshot: truncated section table");
            } else {
                const dap_ledger_snapshot_section_desc_t *l_desc =
                        (const dap_ledger_snapshot_section_desc_t *)l_ptr;
                l_ptr += l_desc_size;
                for (uint32_t i = 0; i < l_header.n_sections; ++i) {
                    if (l_desc[i].size > (uint64_t)(l_end - l_ptr)) {
                        log_it(L_WARNING, "Ledger snapshot: truncated section '%s'", l_desc[i].name);
                        break;
                    }
                    dap_ledger_snapshot_load_cb_t l_early_load = NULL;
                    void *l_early_ctx = NULL;
                    uint32_t l_early_flags = 0;
                    if (s_snapshot_section_find_flags(l_desc[i].name, &l_early_load, &l_early_ctx, &l_early_flags)
                            && (l_early_flags & DAP_LEDGER_SNAPSHOT_SECTION_FLAG_EARLY) && l_early_load) {
                        // Needed by the loader itself before it walks the chains.
                        dap_nanotime_t l_t0 = dap_nanotime_now();
                        int l_rc = l_early_load(l_early_ctx, l_ptr, l_desc[i].size);
                        log_it(l_rc ? L_WARNING : L_INFO, "Ledger snapshot: early section '%s' %s "
                               "(%" DAP_UINT64_FORMAT_U " bytes, %" DAP_UINT64_FORMAT_U " ms)",
                               l_desc[i].name, l_rc ? "load failed" : "applied", l_desc[i].size,
                               (uint64_t)(dap_nanotime_now() - l_t0) / 1000000);
                    } else {
                        s_pending_section_add(l_snapshot_map, l_header.net_id, l_desc[i].name, l_ptr, l_desc[i].size);
                    }
                    l_ptr += l_desc[i].size;
                }
            }
        }
        // Chain-scan skip (EXPERIMENTAL, disabled in release builds): with the
        // skip active the cell loader stops feeding blocks into the block cache
        // past the anchor position (reproduced on a full Backbone replica:
        // 13577 of 587744 blocks cached, the loader then finishes "successfully"
        // and the node re-syncs the range from the network; an intermediate
        // 5.7-63 build left a production node stuck exactly like this). Root
        // cause is in the load path - revive under a dedicated debugging
        // session. Enable together with the cs-blocks helper by defining
        // DAP_LEDGER_SNAPSHOT_SKIP_EXPERIMENTAL in that module as well.
#ifdef DAP_LEDGER_SNAPSHOT_SKIP_EXPERIMENTAL
        if (l_header.block_num && !dap_hash_fast_is_blank((dap_chain_hash_fast_t *)l_header.block_hash)) {
            l_ledger_pvt->snapshot_skip_active = true;
            l_ledger_pvt->snapshot_skip_num = l_header.block_num;
            memcpy(&l_ledger_pvt->snapshot_skip_hash, l_header.block_hash, sizeof(l_ledger_pvt->snapshot_skip_hash));
            log_it(L_NOTICE, "Ledger snapshot: chain-scan skip armed up to block %"DAP_UINT64_FORMAT_U, l_header.block_num);
        }
#endif
        log_it(L_NOTICE, "Ledger snapshot: restored %"DAP_UINT64_FORMAT_U" tx items and %"DAP_UINT64_FORMAT_U
               " balances from %s (saved %"DAP_UINT64_FORMAT_U" s ago; tx %" DAP_UINT64_FORMAT_U
               " ms, balances %" DAP_UINT64_FORMAT_U " ms, total %" DAP_UINT64_FORMAT_U
               " ms); the chain scan will re-fill the transaction datums",
               l_loaded_tx, l_loaded_balances, l_path, (uint64_t)time(NULL) - l_header.ts_saved,
               (uint64_t)(l_t_tx - l_t_start) / 1000000,
               (uint64_t)(l_t_bal - l_t_tx) / 1000000,
               (uint64_t)(dap_nanotime_now() - l_t_start) / 1000000);
        if (l_loaded_tx != l_header.n_tx_items || l_loaded_balances != l_header.n_balances)
            log_it(L_WARNING, "Ledger snapshot: %s carries %"DAP_UINT64_FORMAT_U" tx items and %"DAP_UINT64_FORMAT_U
                   " balances, restored less - the chain scan will rebuild the difference", l_path,
                   l_header.n_tx_items, l_header.n_balances);
        l_ret = (l_loaded_tx || l_loaded_balances) ? 1 : 0;
    } while (0);
    // The mapped payload is released through its reference: pending sections
    // hold their own references and keep it alive until their load end.
    if (l_snapshot_map)
        s_snapshot_mapping_release(l_snapshot_map);
    else
        DAP_DEL_Z(l_payload);
    fclose(l_file);
    DAP_DELETE(l_path);
    return l_ret;
}

static void s_snapshot_save_timer_tick(void *a_arg)
{
    dap_ledger_t *l_ledger = (dap_ledger_t *)a_arg;
    // Nothing to protect before the load finishes: the restore itself has just
    // read this very file, and a full replay would not be shortened by it.
    if (dap_chain_net_get_load_mode(l_ledger->net))
        return;
    dap_ledger_snapshot_save(l_ledger, false);
}

/* *** End of the ledger snapshot cache *** */

// Completes the cached-ledger load: wakes dap_ledger_load_cache() no matter
// whether the callback chain reached the last stage or broke earlier (a
// failed get_all for any group used to leave the loader waiting forever).
static void s_load_cache_finish(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_mutex_lock(&l_ledger_pvt->load_mutex);
    l_ledger_pvt->load_end = true;
    pthread_cond_broadcast(&l_ledger_pvt->load_cond);
    pthread_mutex_unlock(&l_ledger_pvt->load_mutex);
}

void dap_ledger_load_cache(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    // Snapshot mode: the transaction cache items and the balances come from the
    // snapshot file (see s_load_cache_next_stage for the skipped GlobalDB
    // stages); only the small groups keep being served by GlobalDB.
    if (l_ledger_pvt->snapshot_mode)
        dap_ledger_snapshot_load(a_ledger);
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TOKENS_STR);

    pthread_mutex_lock(& l_ledger_pvt->load_mutex);
    // The loader waits for the callback chain to reach its last stage, so the very first
    // request must either be queued or end the load here - never leave that wait dangling.
    if (dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_tokens_callback, a_ledger) != 0) {
        log_it(L_ERROR, "Ledger cache: can't start reading group %s, loading without cache",
               l_gdb_group ? l_gdb_group : "(no group name)");
        l_ledger_pvt->load_end = true;
    }
    while (!l_ledger_pvt->load_end)
        pthread_cond_wait(& l_ledger_pvt->load_cond, &l_ledger_pvt->load_mutex);
    pthread_mutex_unlock(& l_ledger_pvt->load_mutex);

    DAP_DELETE(l_gdb_group);
}

/**
 * @brief Drops every cached ledger group of a network.
 *
 * The GDB ledger cache is a rebuildable index of the chain data, so clearing it is always safe:
 * whatever is dropped is read back from the chains and written again while the ledger is fed -
 * either right away, if a network reload follows (what the CLI command does by default), or on
 * the next chain load. Nothing in the in-memory ledger is touched.
 */
int dap_ledger_cache_reset(dap_ledger_t *a_ledger)
{
    dap_return_val_if_fail(a_ledger && a_ledger->net, -1);
    // Everything the ledger caches itself, plus the delegated stake service's key cache: the
    // stake service writes it under the same local.ledger-cache.<net>.* family.
    static const char *l_suffixes[] = {
        DAP_LEDGER_TOKENS_STR, DAP_LEDGER_EMISSIONS_STR, DAP_LEDGER_STAKE_LOCK_STR,
        DAP_LEDGER_TXS_STR, DAP_LEDGER_BALANCES_STR, "delegate_keys"
    };
    int l_dropped = 0;
    for (size_t i = 0; i < sizeof(l_suffixes) / sizeof(l_suffixes[0]); ++i) {
        char *l_group = dap_ledger_get_gdb_group(a_ledger, l_suffixes[i]);
        if (!l_group)
            continue;
        if (dap_global_db_erase_table_sync(l_group) == 0) {
            ++l_dropped;
            log_it(L_NOTICE, "Ledger cache: group %s cleared", l_group);
        } else {
            debug_if(s_debug_more, L_INFO, "Ledger cache: group %s was not present", l_group);
        }
        DAP_DELETE(l_group);
    }
    // The snapshot file holds the same state the GDB groups did: drop it too,
    // or the next restart resurrects everything this reset just removed.
    {
        char *l_snapshot_path = s_snapshot_file_path(a_ledger);
        if (l_snapshot_path) {
            if (remove(l_snapshot_path) == 0)
                log_it(L_NOTICE, "Ledger snapshot file %s removed", l_snapshot_path);
            DAP_DELETE(l_snapshot_path);
        }
    }
    log_it(L_NOTICE, "Ledger cache for network %s has been reset: %d group(s) cleared",
           a_ledger->net->pub.name, l_dropped);
    return 0;
}

static void s_blockchain_timer_callback(dap_chain_t *a_chain, dap_time_t a_blockchain_time, void UNUSED_ARG *a_arg, bool a_reverse)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    assert(l_net);
    dap_ledger_private_t *l_ledger_pvt = PVT(l_net->pub.ledger);
    l_ledger_pvt->blockchain_time = a_blockchain_time;
    pthread_rwlock_wrlock(&l_ledger_pvt->locked_outs_rwlock);
    if (a_reverse) {
        dap_ledger_locked_out_t *it, *tmp;
        LL_FOREACH_SAFE(l_ledger_pvt->reverse_list, it, tmp) {
            if (it->unlock_time <= a_blockchain_time)
                break;
            dap_ledger_pvt_balance_update_for_addr(l_net->pub.ledger, &it->addr, it->ticker, it->value, true);
            LL_DELETE(l_ledger_pvt->reverse_list, it);
            LL_APPEND(l_ledger_pvt->locked_outs, it);
        }
        pthread_rwlock_unlock(&l_ledger_pvt->locked_outs_rwlock);
        return;
    }
    dap_ledger_locked_out_t *it, *tmp;
    LL_FOREACH_SAFE(l_ledger_pvt->locked_outs, it, tmp) {
        if (it->unlock_time > a_blockchain_time)
            break;
        dap_ledger_pvt_balance_update_for_addr(l_net->pub.ledger, &it->addr, it->ticker, it->value, false);
        LL_DELETE(l_ledger_pvt->locked_outs, it);
        if (!dap_chain_net_get_load_mode(l_net))
            LL_PREPEND(l_ledger_pvt->reverse_list, it);
        else
            DAP_DELETE(it);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->locked_outs_rwlock);
    LL_FOREACH_SAFE(l_ledger_pvt->reverse_list, it, tmp) {
        if (it->unlock_time < l_ledger_pvt->cutoff_time) {
            LL_DELETE(l_ledger_pvt->reverse_list, it);
            DAP_DELETE(it);
        }
    }
}

static void s_blockchain_cutoff_callback(void *a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, dap_chain_hash_fast_t *a_atom_hash, void *a_atom, size_t a_atom_size, dap_time_t a_atom_time)
{
    if (a_id.uint64)
        return;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    assert(l_net);
    dap_ledger_private_t *l_ledger_pvt = PVT(l_net->pub.ledger);
    l_ledger_pvt->cutoff_time = a_atom_time;
}

dap_time_t dap_ledger_get_blockchain_time(dap_ledger_t *a_ledger)
{
#ifndef DAP_LEDGER_TEST
    return PVT(a_ledger)->blockchain_time;
#else
    return dap_time_now();
#endif
}

dap_ledger_locked_out_t *dap_ledger_get_locked_values(dap_ledger_t *a_ledger, dap_chain_addr_t *a_addr)
{
    dap_ledger_locked_out_t *ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->locked_outs_rwlock);
    for (dap_ledger_locked_out_t *it = l_ledger_pvt->locked_outs; it; it = it->next) {
        if (!dap_chain_addr_compare(&it->addr, a_addr))
            continue;
        dap_ledger_locked_out_t *l_out_new = DAP_DUP(it);
        if (!l_out_new) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            break;
        }
        LL_APPEND(ret, l_out_new); // includes nullification of 'next' field
    }
    pthread_rwlock_unlock(&l_ledger_pvt->locked_outs_rwlock);
    return ret;
}

/**
 * @brief
 * create ledger for specific net
 * load ledger cache
 * @param a_check_flags checking flags
 *          DAP_LEDGER_CHECK_TOKEN_EMISSION
 *          DAP_LEDGER_CHECK_CELLS_DS
 *          DAP_LEDGER_CHECK_CELLS_DS
 * @param a_net_name char * network name, for example "kelvin-testnet"
 * @return dap_ledger_t*
 */
dap_ledger_t *dap_ledger_create(dap_chain_net_t *a_net, uint16_t a_flags)
{
    dap_ledger_t *l_ledger = dap_ledger_handle_new();
    if (!l_ledger) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_ledger->net = a_net;
    dap_ledger_private_t *l_ledger_pvt = PVT(l_ledger);
    l_ledger_pvt->check_ds = a_flags & DAP_LEDGER_CHECK_LOCAL_DS;
    l_ledger_pvt->check_cells_ds = a_flags & DAP_LEDGER_CHECK_CELLS_DS;
    l_ledger_pvt->check_token_emission = a_flags & DAP_LEDGER_CHECK_TOKEN_EMISSION;
    l_ledger_pvt->cached = a_flags & DAP_LEDGER_CACHE_ENABLED;
    l_ledger_pvt->mapped = a_flags & DAP_LEDGER_MAPPED;
    l_ledger_pvt->threshold_enabled = a_flags & DAP_LEDGER_THRESHOLD_ENABLED;
    // Snapshot cache: on by default for cached ledgers, replaces the GlobalDB
    // txs/balances cache groups with periodic flat-file snapshots
    if (l_ledger_pvt->cached
            && dap_config_get_item_bool_default(g_config, "ledger", "snapshot_cache", true)) {
        l_ledger_pvt->snapshot_mode = true;
        l_ledger_pvt->snapshot_interval_sec =
                (uint32_t)dap_config_get_item_int32_default(g_config, "ledger", "snapshot_interval_sec", 600);
        if (!l_ledger_pvt->snapshot_interval_sec)
            l_ledger_pvt->snapshot_interval_sec = 600;
        l_ledger_pvt->snapshot_save_timer = dap_interval_timer_create(
                l_ledger_pvt->snapshot_interval_sec * 1000u,
                (dap_timer_callback_t)s_snapshot_save_timer_tick, l_ledger);
        // Full snapshot: the "ledger_state" section is always written, but its
        // authoritative use (no service replay of restored transactions) is opt-in
        // until the equivalence runner has compared a scan-only replica with a
        // snapshot-restored one.
        l_ledger_pvt->snapshot_full_apply =
                dap_config_get_item_bool_default(g_config, "ledger", "snapshot_full_apply", true);
        log_it(L_NOTICE, "Ledger snapshot cache enabled (save interval %u s, full apply %s)",
               l_ledger_pvt->snapshot_interval_sec, l_ledger_pvt->snapshot_full_apply ? "on" : "off");
    }
    if (l_ledger_pvt->threshold_enabled)
        l_ledger_pvt->threshold_txs_free_timer = dap_interval_timer_create(s_threshold_free_timer_tick,
                                                                      (dap_timer_callback_t)s_threshold_txs_free, l_ledger);
    pthread_cond_init(&l_ledger_pvt->load_cond, NULL);
    pthread_mutex_init(&l_ledger_pvt->load_mutex, NULL);

    // Load the cached ledger state (txs, tokens, emissions, stake locks, balances) before
    // anything else touches the ledger. Gated by the runtime flag only: the build-time
    // DAP_LEDGER_TEST define used to hide this from every test build, which made the cache
    // resume path untestable; test ledgers simply do not set DAP_LEDGER_CACHE_ENABLED.
    if ( l_ledger_pvt->cached )
        dap_ledger_load_cache(l_ledger);

#ifndef DAP_LEDGER_TEST
    for ( dap_chain_t *l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next ) {
        uint16_t l_whitelist_size, l_blacklist_size, i;
        const char **l_whitelist = dap_config_get_array_str(l_chain->config, "ledger", "hard_accept_list", &l_whitelist_size),
                   **l_blacklist = dap_config_get_array_str(l_chain->config, "ledger", "hard_reject_list", &l_blacklist_size);
        for (i = 0; i < l_blacklist_size; ++i) {
            dap_ledger_hal_item_t *l_item = DAP_NEW_Z(dap_ledger_hal_item_t);
            dap_chain_hash_fast_from_str(l_blacklist[i], &l_item->hash);
            HASH_ADD(hh, l_ledger_pvt->hrl_items, hash, sizeof(dap_hash_fast_t), l_item);
        }
        for (i = 0; i < l_whitelist_size; ++i) {
            dap_ledger_hal_item_t *l_item = DAP_NEW_Z(dap_ledger_hal_item_t);
            dap_chain_hash_fast_from_str(l_whitelist[i], &l_item->hash);
            HASH_ADD(hh, l_ledger_pvt->hal_items, hash, sizeof(dap_hash_fast_t), l_item);
        }
        log_it(L_DEBUG, "Chain %s.%s has %d datums in HAL and %d datums in HRL", a_net->pub.name, l_chain->name, l_whitelist_size, l_blacklist_size);

    }
#else
    l_ledger_pvt->blockchain_time = dap_time_now();
#endif

    dap_chain_t *l_default_tx_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (l_default_tx_chain) {
        dap_chain_add_callback_timer(l_default_tx_chain, s_blockchain_timer_callback, NULL);
        dap_chain_atom_confirmed_notify_add(l_default_tx_chain, s_blockchain_cutoff_callback, NULL, 0);
    } else
        log_it(L_WARNING, "Can't get deafult chain for transactions, timelocks for it will be disabled");

    return l_ledger;
}

enum ledger_permissions {
    LEDGER_PERMISSION_RECEIVER_ALLOWED,
    LEDGER_PERMISSION_RECEIVER_BLOCKED,
    LEDGER_PERMISSION_SENDER_ALLOWED,
    LEDGER_PERMISSION_SENDER_BLOCKED
};

/**
 * @brief dap_ledger_permissions_check
 * @param a_token_item
 * @param a_permission_id
 * @param a_data
 * @param a_data_size
 * @return
 */
static bool s_ledger_permissions_check(dap_ledger_t *a_ledger, dap_ledger_token_item_t *a_token_item, enum ledger_permissions a_permission_id, dap_chain_addr_t *a_addr)
{
    struct spec_address *l_addrs = NULL;
    size_t l_addrs_count = 0;
    switch (a_permission_id) {
    case LEDGER_PERMISSION_RECEIVER_ALLOWED:
        l_addrs = a_token_item->tx_recv_allow;
        l_addrs_count = a_token_item->tx_recv_allow_size;
    break;
    case LEDGER_PERMISSION_RECEIVER_BLOCKED:
        l_addrs = a_token_item->tx_recv_block;
        l_addrs_count = a_token_item->tx_recv_block_size;
    break;
    case LEDGER_PERMISSION_SENDER_ALLOWED:
        l_addrs = a_token_item->tx_send_allow;
        l_addrs_count = a_token_item->tx_send_allow_size;
    break;
    case LEDGER_PERMISSION_SENDER_BLOCKED:
        l_addrs = a_token_item->tx_send_block;
        l_addrs_count = a_token_item->tx_send_block_size;
    break;
    }
    for (size_t n = 0; n < l_addrs_count; n++)
        if (dap_chain_addr_compare(&l_addrs[n].addr, a_addr) &&
                l_addrs[n].becomes_effective <= dap_ledger_get_blockchain_time(a_ledger))
            return true;
    return false;
}

dap_ledger_check_error_t s_ledger_addr_check(dap_ledger_t *a_ledger, dap_ledger_token_item_t *a_token_item, dap_chain_addr_t *a_addr, bool a_receive)
{
    dap_return_val_if_fail(a_token_item && a_addr, DAP_LEDGER_CHECK_INVALID_ARGS);
    if (dap_chain_addr_is_blank(a_addr))
        return DAP_LEDGER_CHECK_OK;
    
    // Check if address-based blocking is disabled for this token
    if (a_receive) {
        // Skip all receiver address checks if DISABLE_ADDRESS_RECEIVER_BLOCKING is set
        if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_RECEIVER_BLOCKING) {
            return DAP_LEDGER_CHECK_OK;
        }
    } else {
        // Skip all sender address checks if DISABLE_ADDRESS_SENDER_BLOCKING is set
        if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_SENDER_BLOCKING) {
            return DAP_LEDGER_CHECK_OK;
        }
    }
    
    if (a_receive) {
        if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN)) {
            // Check we are in white list
            if (!s_ledger_permissions_check(a_ledger, a_token_item, LEDGER_PERMISSION_RECEIVER_ALLOWED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        } else if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN)) {
            // Check we are in black list
            if (s_ledger_permissions_check(a_ledger,a_token_item, LEDGER_PERMISSION_RECEIVER_BLOCKED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        }
    } else {
        if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN)) {
            // Check we are in white list
            if (!s_ledger_permissions_check(a_ledger, a_token_item, LEDGER_PERMISSION_SENDER_ALLOWED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        } else if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN)) {
            // Check we are in black list
            if (s_ledger_permissions_check(a_ledger, a_token_item, LEDGER_PERMISSION_SENDER_BLOCKED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        }
    }
    return DAP_LEDGER_CHECK_OK;
}

int s_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_chain_hash_fast_t *a_emission_hash,
                         dap_chain_datum_token_emission_t **a_emission, dap_ledger_token_item_t **a_token_item)
{
    dap_return_val_if_fail(a_token_emission && a_token_emission_size, DAP_LEDGER_CHECK_INVALID_ARGS);
    size_t l_emission_size = a_token_emission_size;
    dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_token_emission, &l_emission_size);
    if (!l_emission)
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    if (l_emission->hdr.version < 3 && !a_token_item) { // It's mempool check
        log_it(L_WARNING, "Legacy emission version %hhu isn't supported for a new emissions", l_emission->hdr.version);
        DAP_DELETE(l_emission);
        return DAP_LEDGER_EMISSION_CHECK_LEGACY_FORBIDDEN;
    }
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, l_emission->hdr.ticker);
    if (!l_token_item) {
        log_it(L_ERROR, "Check emission: token %s was not found", l_emission->hdr.ticker);
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
    }
    dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
    // check if such emission is already present in table
    pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    if (l_token_emission_item) {
        debug_if(s_debug_more, L_WARNING, "Can't add token emission datum of %s %s ( %s ): already present in cache",
                                    dap_uint256_to_char(l_emission->hdr.value, NULL), l_emission->hdr.ticker,
                                    dap_chain_hash_fast_to_str_static(a_emission_hash));
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_ALREADY_CACHED;
    }

    if (!PVT(a_ledger)->check_token_emission)
        goto ret_success;

    // Check emission correctness
    if (IS_ZERO_256((l_emission->hdr.value))) {
        log_it(L_ERROR, "Emission check: zero %s emission value", l_token_item->ticker);
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_ZERO_VALUE;
    }

    if (!s_ledger_token_supply_check(l_token_item, l_emission->hdr.value)) {
        DAP_DELETE(l_emission);
        return DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY;
    }

    //additional check for private tokens
    if((l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
        ||  (l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)) {
        dap_ledger_check_error_t ret = s_ledger_addr_check(a_ledger, l_token_item, &l_emission->hdr.address, true);
        if (ret == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
            log_it(L_WARNING, "Address %s is not in allowed to receive for emission of token %s",
                            dap_chain_addr_to_str_static(&l_emission->hdr.address), l_token_item->ticker);
            DAP_DELETE(l_emission);
            return ret;
        }
    }
    switch (l_emission->hdr.type) {

    case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH: {
        size_t l_sign_data_check_size = sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_total_size >= sizeof(dap_chain_datum_token_emission_t)
                                                ? sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_total_size : 0;
        if (l_sign_data_check_size > l_emission_size) {
            if (!s_check_hal(a_ledger, a_emission_hash)) {
                log_it(L_WARNING, "Incorrect size %zu of datum emission, expected at least %zu", l_emission_size, l_sign_data_check_size);
                DAP_DELETE(l_emission);
                return DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            goto ret_success;
        }
        size_t l_emission_check_size = sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_n_signs_size >= sizeof(dap_chain_datum_token_emission_t)
                                                ? sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_n_signs_size : 0;
        if (l_emission_check_size != l_emission_size) {
            log_it(L_WARNING, "Incorrect size %zu of datum emission, must be %zu", l_emission_size, l_emission_check_size);
            DAP_DELETE(l_emission);
            return DAP_LEDGER_CHECK_INVALID_SIZE;
        }
        size_t l_signs_unique = l_emission->data.type_auth.signs_count;
        dap_sign_t **l_signs = dap_sign_get_unique_signs(l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size,
                                                         l_emission->data.type_auth.tsd_n_signs_size, &l_signs_unique);
        if (l_signs_unique < l_token_item->auth_signs_valid) {
            
            DAP_DELETE(l_signs);

            if (!s_check_hal(a_ledger, a_emission_hash)) {
                
                log_it(L_WARNING, "The number of unique token signs %zu is less than total token signs set to %zu",
                       l_signs_unique, l_token_item->auth_signs_total);
                DAP_DELETE(l_emission);
                return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
            }
            
            goto ret_success;
        }
        size_t l_sign_auth_count = l_emission->data.type_auth.signs_count;
        size_t l_sign_auth_size = l_emission->data.type_auth.tsd_n_signs_size;
        if (l_emission->hdr.version < 3) {
            l_sign_data_check_size = sizeof(l_emission->hdr);
        } else {
            l_emission->data.type_auth.signs_count = 0;
            l_emission->data.type_auth.tsd_n_signs_size = 0;
        }
        size_t l_aproves = 0;
        debug_if(s_debug_more, L_DEBUG, "=== Emission signature validation for %s: %zu unique signs, need to match with %zu token auth_pkeys ===", 
                 l_emission->hdr.ticker, l_signs_unique, l_token_item->auth_signs_total);
        for (uint16_t i = 0; i < l_signs_unique; i++) {
            dap_hash_fast_t l_sign_pkey_hash = {0};
            dap_sign_get_pkey_hash(l_signs[i], &l_sign_pkey_hash);
            debug_if(s_debug_more, L_DEBUG, "  Sign[%u] pkey hash: %s", i, dap_hash_fast_to_str_static(&l_sign_pkey_hash));
            
            bool l_matched = false;
            for (uint16_t k = 0; k < l_token_item->auth_signs_total; k++) {
                size_t l_sign_pkey_size = 0;
                const uint8_t *l_sign_pkey = dap_sign_get_pkey(l_signs[i], &l_sign_pkey_size);
                dap_pkey_t *l_token_pkey = l_token_item->auth_pkeys[k];
                
                debug_if(s_debug_more, L_DEBUG, "    Comparing with token auth_pkey[%u]: type=%u, size=%u, data_start=0x%02X%02X%02X%02X", 
                         k, l_token_pkey->header.type.type, l_token_pkey->header.size,
                         l_token_pkey->pkey[0], l_token_pkey->pkey[1], l_token_pkey->pkey[2], l_token_pkey->pkey[3]);
                debug_if(s_debug_more, L_DEBUG, "    Sign pkey: type=%u, size=%u, data_start=0x%02X%02X%02X%02X",
                         dap_sign_type_to_key_type(l_signs[i]->header.type), (uint32_t)l_sign_pkey_size,
                         l_sign_pkey[0], l_sign_pkey[1], l_sign_pkey[2], l_sign_pkey[3]);
                
                if (dap_pkey_compare_with_sign(l_token_pkey, l_signs[i])) {
                    debug_if(s_debug_more, L_DEBUG, "    ✓ MATCH! Verifying signature...");
                    // Verify if token emission is signed
                    if (!dap_sign_verify(l_signs[i], l_emission, l_sign_data_check_size)) {
                        l_aproves++;
                        debug_if(s_debug_more, L_DEBUG, "    ✓ Signature VALID (l_aproves=%zu)", l_aproves);
                    } else {
                        debug_if(s_debug_more, L_DEBUG, "    ✗ Signature INVALID");
                    }
                    l_matched = true;
                    break;
                } else {
                    debug_if(s_debug_more, L_DEBUG, "    ✗ NO MATCH (types=%d vs %d, sizes=%u vs %u, memcmp=%d)",
                             dap_pkey_type_to_enc_key_type(l_token_pkey->header.type), dap_sign_type_to_key_type(l_signs[i]->header.type),
                             l_token_pkey->header.size, (uint32_t)l_sign_pkey_size,
                             (l_token_pkey->header.size == l_sign_pkey_size) ? memcmp(l_token_pkey->pkey, l_sign_pkey, l_token_pkey->header.size) : -999);
                }
            }
            if (!l_matched) {
                debug_if(s_debug_more, L_DEBUG, "  ✗ Sign[%u] did NOT match any token auth_pkey", i);
            }
        }
        debug_if(s_debug_more, L_DEBUG, "=== Emission validation result: %zu aproves out of %zu required ===", l_aproves, l_token_item->auth_signs_valid);
        if (l_emission->hdr.version >= 3) {
            l_emission->data.type_auth.signs_count = l_sign_auth_count;
            l_emission->data.type_auth.tsd_n_signs_size = l_sign_auth_size;
        }
        DAP_DELETE(l_signs);
        if (l_aproves < l_token_item->auth_signs_valid &&
                !s_check_hal(a_ledger, a_emission_hash)) {
            log_it(L_WARNING, "Emission of %s datoshi of %s:%s is wrong: only %zu valid aproves when %zu need",
                        dap_uint256_to_char(l_emission->hdr.value, NULL), a_ledger->net->pub.name, l_emission->hdr.ticker,
                        l_aproves, l_token_item->auth_signs_valid);
            debug_if(s_debug_more, L_ATT, "!!! Datum hash for HAL: %s", dap_chain_hash_fast_to_str_static(a_emission_hash));
            DAP_DELETE(l_emission);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
        }
    } break;

    default:
        log_it(L_ERROR, "Checking emission of type %s not implemented", dap_chain_datum_emission_type_str(l_emission->hdr.type));
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_PARSE_ERROR;
    }

ret_success:
    if (a_token_item)
        *a_token_item = l_token_item;
    if (a_emission)
        *a_emission = l_emission;
    else
        DAP_DELETE(l_emission);

    return DAP_LEDGER_CHECK_OK;
}

int dap_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_chain_hash_fast_t *a_emission_hash)
{
    return s_emission_add_check(a_ledger, a_token_emission, a_token_emission_size, a_emission_hash, NULL, NULL);
}
static void s_ledger_emission_cache_update(dap_ledger_t *a_ledger, dap_ledger_token_emission_item_t *a_emission_item)
{
    if (s_ledger_cache_storage_full())
        return; // storage full - cache writes dropped
    if (!PVT(a_ledger)->cached)
        return;
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_EMISSIONS_STR);
    size_t l_cache_size = a_emission_item->datum_token_emission_size + sizeof(dap_hash_fast_t);
    // Heap, not alloca: datum_token_emission_size is unbounded (see the token
    // cache above); the async set copies the value before returning.
    uint8_t *l_cache = DAP_NEW_Z_SIZE(uint8_t, l_cache_size);
    memcpy(l_cache, &a_emission_item->tx_used_out, sizeof(dap_hash_fast_t));
    memcpy(l_cache + sizeof(dap_hash_fast_t), a_emission_item->datum_token_emission, a_emission_item->datum_token_emission_size);
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_emission_item->datum_token_emission_hash, l_hash_str, sizeof(l_hash_str));
    if (dap_global_db_set(l_gdb_group, l_hash_str, l_cache, l_cache_size, false, NULL, NULL)) {
        log_it(L_WARNING, "Ledger cache mismatch");
    }
    DAP_DELETE(l_cache);
    DAP_DELETE(l_gdb_group);
}

/**
 * @brief dap_ledger_token_emission_add
 * @param a_token_emission
 * @param a_token_emision_size
 * @return
 */

int dap_ledger_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_hash_fast_t *a_emission_hash)
{
    dap_ledger_token_item_t *l_token_item = NULL;
    dap_chain_datum_token_emission_t *l_emission = NULL;
    int l_ret = s_emission_add_check(a_ledger, a_token_emission, a_token_emission_size, a_emission_hash, &l_emission, &l_token_item);
    if (l_ret != DAP_LEDGER_CHECK_OK)
        return l_ret;
    dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
    // check if such emission is already present in table
    pthread_rwlock_wrlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    if (l_token_emission_item) {
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        log_it(L_ERROR, "Duplicate token emission datum of %s %s ( %s )",
                dap_uint256_to_char(l_emission->hdr.value, NULL), l_emission->hdr.ticker, dap_hash_fast_to_str_static(a_emission_hash));
        DAP_DELETE(l_emission);
        return DAP_LEDGER_CHECK_APPLY_ERROR;
    }
    l_token_emission_item = DAP_NEW_Z(dap_ledger_token_emission_item_t);
    if (!l_token_emission_item) {
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
    }
    l_token_emission_item->datum_token_emission = l_emission;
    l_token_emission_item->datum_token_emission_hash = *a_emission_hash;
    // Not a cosmetic field: the GlobalDB emissions cache record and the ledger
    // snapshot section are built from it. Without it every live-added emission
    // was cached as a bare hash and the snapshot could not restore it.
    l_token_emission_item->datum_token_emission_size = a_token_emission_size;
    HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    //Update value in ledger memory object
    if (!s_ledger_token_supply_check_update(a_ledger, l_token_item, l_emission->hdr.value, false)) {
        HASH_DEL(l_token_item->token_emissions, l_token_emission_item);
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        DAP_DELETE(l_emission);
        DAP_DELETE(l_token_emission_item);
        return DAP_LEDGER_CHECK_APPLY_ERROR;
    }
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    // Add it to cache
    s_ledger_emission_cache_update(a_ledger, l_token_emission_item);
    if (s_debug_more) {
        const char *l_balance; dap_uint256_to_char(l_token_emission_item->datum_token_emission->hdr.value, &l_balance);
        log_it(L_NOTICE, "Added token emission datum to emissions cache: type=%s value=%s token=%s to_addr=%s",
                       dap_chain_datum_emission_type_str(l_emission->hdr.type),
                       l_balance, l_emission->hdr.ticker,
                       dap_chain_addr_to_str_static(&(l_emission->hdr.address)));
    }
    if (PVT(a_ledger)->threshold_enabled)
        s_threshold_txs_proc(a_ledger);
    return DAP_LEDGER_CHECK_OK;
}

void s_ledger_stake_lock_cache_update(dap_ledger_t *a_ledger, dap_ledger_stake_lock_item_t *a_stake_lock_item)
{
    if (!PVT(a_ledger)->cached)
        return;
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_stake_lock_item->tx_for_stake_lock_hash, l_hash_str, sizeof(l_hash_str));
    char *l_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_STAKE_LOCK_STR);
    if (dap_global_db_set(l_group, l_hash_str, &a_stake_lock_item->tx_used_out, sizeof(dap_hash_fast_t), false, NULL, NULL))
        log_it(L_WARNING, "Ledger cache mismatch");
    DAP_DEL_Z(l_group);
}

int dap_ledger_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_stake_lock_item_t *l_new_stake_lock_emission = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_pvt->emissions_for_stake_lock, a_tx_hash, sizeof(dap_hash_fast_t),
              l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);
    if (l_new_stake_lock_emission) {
        return -1;
    }
    l_new_stake_lock_emission = DAP_NEW_Z(dap_ledger_stake_lock_item_t);
    if (!l_new_stake_lock_emission) {
        if (s_debug_more) {
            log_it(L_ERROR, "Error: memory allocation when try adding item 'dap_ledger_stake_lock_item_t' to hash-table");
        }
        return -13;
    }
    l_new_stake_lock_emission->tx_for_stake_lock_hash = *a_tx_hash;
    pthread_rwlock_wrlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_ADD(hh, l_ledger_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);

    s_ledger_stake_lock_cache_update(a_ledger, l_new_stake_lock_emission);

    return 0;

}

dap_ledger_stake_lock_item_t *s_emissions_for_stake_lock_item_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_stake_lock_item_t *l_new_stake_lock_emission = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_pvt->emissions_for_stake_lock, a_token_emission_hash, sizeof(dap_chain_hash_fast_t),
              l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);
    return l_new_stake_lock_emission;
}

// The strict girdled-mint rules (EMIT flag mandatory, no mint-plus-base-TX combination,
// mandatory burn on unstake) are enforced from the policy's ts_start onwards, so blocks
// mined before activation replay exactly as before. The boundary comes from a policy
// decree, the same mechanism the xchange/voting cutoffs use, so every node derives it
// from the chain itself rather than from local config.
bool dap_ledger_stake_strict_mint_in_force(dap_ledger_t *a_ledger)
{
    dap_time_t l_strict_since = 0;
    if (!dap_chain_policy_get_ts_start(a_ledger->net->pub.id, DAP_CHAIN_POLICY_STAKE_LOCK_STRICT_MINT_CUTOFF,
                                       &l_strict_since) || !l_strict_since)
        return false;   // no policy decree applied yet: lenient semantics
    return l_strict_since <= dap_ledger_get_blockchain_time(a_ledger);
}


int dap_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission,
                                         size_t a_token_emission_size, dap_hash_fast_t *a_token_emission_hash)
{
    if (dap_chain_net_get_load_mode(a_ledger->net)) {
        dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
        dap_ledger_token_item_t *l_token_item, *l_item_tmp;
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_item_tmp) {
            pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
            HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash),
                    l_token_emission_item);
            pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
            if (l_token_emission_item) {
                pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
                return 0;
            }
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    }
    return dap_ledger_token_emission_add(a_ledger, a_token_emission, a_token_emission_size, a_token_emission_hash);
}

dap_ledger_token_emission_item_t *s_emission_item_find(dap_ledger_t *a_ledger,
                const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash, dap_ledger_token_item_t **a_token_item)
{
    dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, a_token_ticker);
    if (!l_token_item)
        return NULL;
    else if (a_token_item)
        *a_token_item = l_token_item;
    dap_ledger_token_emission_item_t *l_token_emission_item = NULL;
    pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash), l_token_emission_item);
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    return l_token_emission_item;
}

/**
 * @brief dap_ledger_token_emission_find
 * @param a_token_ticker
 * @param a_token_emission_hash
 * @return
 */
dap_chain_datum_token_emission_t *dap_ledger_token_emission_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_token_emission_item_t *l_emission_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    for (dap_ledger_token_item_t *l_item = PVT(a_ledger)->tokens; l_item; l_item = l_item->hh.next) {
        // Search the item directly: s_emission_item_find() would re-take tokens_rwlock on this thread
        pthread_rwlock_rdlock(&l_item->token_emissions_rwlock);
        HASH_FIND(hh, l_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash), l_emission_item);
        pthread_rwlock_unlock(&l_item->token_emissions_rwlock);
        if (l_emission_item)
            break;
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_emission_item ? l_emission_item->datum_token_emission : NULL;
}

/**
 * @brief Get first emission hash for token
 * @param a_ledger Ledger instance
 * @param a_token_ticker Token ticker
 * @param a_emission_hash Output parameter for emission hash
 * @return true if emission found, false otherwise
 */
bool dap_ledger_token_get_first_emission_hash(dap_ledger_t *a_ledger, const char *a_token_ticker, dap_chain_hash_fast_t *a_emission_hash)
{
    if (!a_ledger || !a_token_ticker || !a_emission_hash) {
        return false;
    }
    
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    dap_ledger_token_item_t *l_token_item = NULL;
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token_ticker, l_token_item);
    
    if (!l_token_item) {
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        return false;
    }
    
    pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
    dap_ledger_token_emission_item_t *l_emission = l_token_item->token_emissions;
    
    if (l_emission) {
        *a_emission_hash = l_emission->datum_token_emission_hash;
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        return true;
    }
    
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return false;
}

/**
 * @brief dap_ledger_set_local_cell_id
 * @param a_local_cell_id
 */
void dap_ledger_set_local_cell_id(dap_ledger_t *a_ledger, dap_chain_cell_id_t a_local_cell_id)
{
    PVT(a_ledger)->local_cell_id.uint64 = a_local_cell_id.uint64;
}

/**
 * @brief dap_ledger_tx_get_token_ticker_by_hash
 * @param a_ledger
 * @param a_tx_hash
 * @return
 */
const char* dap_ledger_tx_get_token_ticker_by_hash(dap_ledger_t *a_ledger,dap_chain_hash_fast_t *a_tx_hash)
{
    if(!a_ledger || !a_tx_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    if ( dap_hash_fast_is_blank(a_tx_hash) )
        return NULL;

    dap_ledger_tx_item_t *l_item = NULL;
    unsigned l_hash_value;
    HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    const char *l_ticker = l_item ? l_item->cache_data.token_ticker : NULL;
    return l_ticker;
}

const char *dap_ledger_tx_get_token_ticker(dap_ledger_t *a_ledger, dap_ledger_datum_iter_t *a_iter) {
    return a_iter ? ((dap_ledger_tx_item_t*)(a_iter->cur_ledger_tx_item))->cache_data.token_ticker : NULL;
}

/**
 * @brief Get list of all tickets for ledger and address. If address is NULL returns all the tockens present in system
 * @param a_ledger
 * @param a_addr
 * @param a_tickers
 * @param a_tickers_size
 */
void dap_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size)
{
    if (a_addr == NULL){ // Get all tockens
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        size_t l_count = HASH_COUNT(PVT(a_ledger)->tokens);
        if (l_count && a_tickers){
            dap_ledger_token_item_t * l_token_item, *l_tmp;
            char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            if (!l_tickers) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                // Bug fix: this branch holds tokens_rwlock (locked above), not
                // balance_accounts_rwlock (never taken here) - unlocking the wrong/
                // never-locked mutex is undefined behavior and leaks tokens_rwlock held.
                pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
                return;
            }
            l_count = 0;
            HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp) {
                l_tickers[l_count] = dap_strdup(l_token_item->ticker);
                l_count++;
            }
            *a_tickers = l_tickers;
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        if(a_tickers_size)
            *a_tickers_size = l_count;
    }else{ // Calc only tokens from address balance
        dap_ledger_wallet_balance_t *wallet_balance, *tmp;
        // Bug fix: balance_accounts_rwlock must guard the HASH_COUNT read too (the
        // table is mutated under wrlock elsewhere), and must be held before any
        // early-return unlock of it - previously HASH_COUNT ran unlocked and the
        // alloc-failure path unlocked a mutex that wasn't locked yet (UB).
        pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
        size_t l_count = HASH_COUNT(PVT(a_ledger)->balance_accounts);
        if(l_count && a_tickers){
            char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            if (!l_tickers) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
                return;
            }
            l_count = 0;
            // Balance keys are "<addr_str> <ticker>"; match by fixed-length
            // prefix instead of dap_strsplit per account (two heap alloc/free
            // rounds per account, over every account in the net, per call).
            // dap_chain_addr_to_str_static() returns the address string by
            // value (a fixed-size union); copy it into a local buffer so
            // nothing aliases the return slot.
            dap_chain_addr_str_t l_addr_str_val = dap_chain_addr_to_str_static_(a_addr);
            char l_addr_str[DAP_ENC_BASE58_ENCODE_SIZE(sizeof(dap_chain_addr_t))];
            memcpy(l_addr_str, l_addr_str_val.s, sizeof(l_addr_str));
            size_t l_addr_len = strnlen(l_addr_str, sizeof(l_addr_str));
            HASH_ITER(hh, PVT(a_ledger)->balance_accounts, wallet_balance, tmp) {
                if (!strncmp(wallet_balance->key, l_addr_str, l_addr_len) && wallet_balance->key[l_addr_len] == ' ') {
                    l_tickers[l_count] = dap_strdup(wallet_balance->token_ticker);
                    ++l_count;
                }
            }
            *a_tickers = l_tickers;
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
        if(a_tickers_size)
            *a_tickers_size = l_count;
    }
}

const char *dap_ledger_get_description_by_ticker(dap_ledger_t *a_ledger, const char *a_token_ticker){
    if (!a_ledger || !a_token_ticker)
        return NULL;
    // The ticker may legitimately be unknown to this ledger (a foreign-network
    // token in a bridged listing): the NULL deref here crashed nodes at startup.
    dap_ledger_token_item_t *l_token = s_ledger_find_token(a_ledger, a_token_ticker);
    return l_token ? l_token->description : NULL;
}

/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
dap_chain_datum_tx_t* dap_ledger_tx_find_datum_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash,
                                                     dap_ledger_tx_item_t **a_item_out, bool a_unspent_only)
{
    if ( !a_tx_hash || dap_hash_fast_is_blank(a_tx_hash) )
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_datum_tx_t *l_tx_ret = NULL;
    dap_ledger_tx_item_t *l_tx_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    if(l_tx_item) {
        // Snapshot-restored item without its datum: attach it lazily from the
        // atom link (chain-state index), without a chain scan. Only for a complete
        // snapshot: otherwise the scan's attach also replays the service side of
        // the transaction, and attaching here first would suppress that replay.
        if (!l_tx_item->tx && l_tx_item->atom_link_valid && l_ledger_pvt->snapshot_full) {
            dap_chain_t *l_chain = NULL;
            for (dap_chain_t *l_c = a_ledger->net ? a_ledger->net->pub.chains : NULL; l_c; l_c = l_c->next) {
                const char *l_cs_type = dap_chain_get_cs_type(l_c);
                if (l_cs_type && !dap_strcmp(l_cs_type, "esbocs")) {
                    l_chain = l_c;
                    break;
                }
            }
            dap_chain_datum_t *l_datum = NULL;
            size_t l_datum_size = 0;
            if (l_chain && !dap_chain_cs_blocks_datum_at(l_chain, &l_tx_item->atom_hash,
                                    l_tx_item->datum_index, &l_datum, &l_datum_size)
                    && l_datum && l_datum_size > sizeof(dap_chain_datum_t)) {
                dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
                pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
                if (!l_tx_item->tx) { // another thread may have attached it meanwhile
                    // Always own a copy: the datum comes from a thin entry's heap
                    // body, which the block cache frees on purge/reorg - unlike the
                    // scan-time attach, it is not part of the mmap'ed cell.
                    l_tx_item->tx = DAP_DUP_SIZE(l_tx, dap_chain_datum_tx_get_size(l_tx));
                    l_tx_item->tx_owned = 1;
                }
                pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
            }
        }
        if (!a_unspent_only || !l_tx_item->cache_data.ts_spent) {
            l_tx_ret = l_tx_item->tx;
            if(a_item_out)
                *a_item_out = l_tx_item;
        }
    }
    return l_tx_ret;
}

bool dap_ledger_tx_is_known(dap_ledger_t *a_ledger, const dap_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx_hash)
        return false;
    dap_ledger_tx_item_t *l_item = NULL;
    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_pvt->ledger_rwlock);
    HASH_FIND(hh, l_pvt->ledger_items, a_tx_hash, sizeof(*a_tx_hash), l_item);
    pthread_rwlock_unlock(&l_pvt->ledger_rwlock);
    return l_item != NULL;
}

// For callers that already hold ledger_rwlock: a nested rdlock on the same thread deadlocks as soon
// as a writer is queued on writer-preferring rwlocks (macOS default).
static dap_chain_datum_tx_t *s_tx_find_by_hash_locked(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash)
{
    if (dap_hash_fast_is_blank(a_tx_hash))
        return NULL;
    dap_ledger_tx_item_t *l_tx_item = NULL;
    HASH_FIND(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    return l_tx_item ? l_tx_item->tx : NULL;
}

static dap_chain_datum_tx_t *s_tx_find_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash, bool a_ledger_locked)
{
    return a_ledger_locked ? s_tx_find_by_hash_locked(a_ledger, a_tx_hash) : dap_ledger_tx_find_by_hash(a_ledger, a_tx_hash);
}

/*
 * Get first chain tx hash and optional OUT_COND pointer.
 */
static dap_hash_fast_t s_first_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                             dap_chain_tx_out_cond_subtype_t a_cond_type,
                                             dap_chain_tx_out_cond_t **a_out_cond, bool a_ledger_locked)
{
    dap_hash_fast_t l_hash = { }, l_hash_prev;
    dap_return_val_if_fail(a_ledger && a_tx, l_hash);
    if (a_out_cond)
        *a_out_cond = NULL;
    dap_chain_datum_tx_t *l_prev_tx = a_tx;
    byte_t *l_iter = a_tx->tx_items;
    // SRV_DEX special-case: root is recorded in order_root_hash field
    // - non-blank order_root_hash => root is directly available (persisted chain)
    // - blank order_root_hash     => this tx is the head of its own chain (root = this tx hash at call site)
    if (a_cond_type == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
        dap_chain_tx_out_cond_t *l_oc = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
        // Blank root for SRV_DEX:
        //  - ORDER: fresh order (root will be set to tx hash by caller)
        //  - Buyer-leftover: fresh order starting new chain from this EXCHANGE
        // In both cases head-of-chain semantics are handled by callers using the tx hash,
        // so we return blank here as a sentinel without traversing IN_COND backwards.
        if (l_oc) {
            if (a_out_cond)
                *a_out_cond = l_oc;
            return dap_hash_fast_is_blank(&l_oc->subtype.srv_dex.order_root_hash) ? l_hash : l_oc->subtype.srv_dex.order_root_hash;
        }
        // No OUT_COND: derive root from IN_COND, allow multi-IN only if signer owns all roots
        dap_hash_fast_t l_root = {}, l_sign_hash = {};
        bool l_owner_match = true;
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_sign = l_tx_sig ? dap_chain_datum_tx_item_sign_get_sig(l_tx_sig) : NULL;
        bool l_have_sign = l_sign && dap_sign_get_pkey_hash(l_sign, &l_sign_hash);
        byte_t *l_iter_in = a_tx->tx_items;
        int l_in_cnt = 0;
        while ((l_iter_in = dap_chain_datum_tx_item_get(a_tx, NULL, l_iter_in, TX_ITEM_TYPE_IN_COND, NULL))) {
            dap_chain_tx_in_cond_t *l_in = (dap_chain_tx_in_cond_t *)l_iter_in;
            l_hash_prev = l_in->header.tx_prev_hash;
            if (dap_hash_fast_is_blank(&l_hash_prev))
                return l_hash_prev;
            l_prev_tx = s_tx_find_by_hash(a_ledger, &l_hash_prev, a_ledger_locked);
            if (!l_prev_tx)
                return l_hash;
            int l_prev_idx = (int)l_in->header.tx_out_prev_idx;
            dap_chain_tx_out_cond_t *l_prev =
                dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_idx);
            if (!l_prev)
                return l_hash;
            dap_hash_fast_t l_root_i = dap_hash_fast_is_blank(&l_prev->subtype.srv_dex.order_root_hash)
                                           ? l_hash_prev
                                           : l_prev->subtype.srv_dex.order_root_hash;
            if (dap_hash_fast_is_blank(&l_root))
                l_root = l_root_i;
            l_in_cnt++;
            dap_chain_datum_tx_t *l_owner_tx =
                dap_hash_fast_compare(&l_root_i, &l_hash_prev) ? l_prev_tx : s_tx_find_by_hash(a_ledger, &l_root_i, a_ledger_locked);
            dap_chain_tx_sig_t *l_owner_sig =
                l_owner_tx ? (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL) : NULL;
            dap_sign_t *l_owner_sign = l_owner_sig ? dap_chain_datum_tx_item_sign_get_sig(l_owner_sig) : NULL;
            dap_hash_fast_t l_owner_hash = {};
            if (!l_have_sign || !l_owner_sign || !dap_sign_get_pkey_hash(l_owner_sign, &l_owner_hash) ||
                !dap_hash_fast_compare(&l_owner_hash, &l_sign_hash))
                l_owner_match = false;
            if (l_in_cnt > 1 && !l_owner_match)
                return l_hash;
        }
        return (dap_hash_fast_is_blank(&l_root) || (l_in_cnt > 1 && !l_owner_match)) ? l_hash : l_root;
    }
    while (( l_iter = dap_chain_datum_tx_item_get(l_prev_tx, NULL, l_iter, TX_ITEM_TYPE_IN_COND, NULL) )) {
        l_hash_prev =  ((dap_chain_tx_in_cond_t *)l_iter)->header.tx_prev_hash;
        if ( dap_hash_fast_is_blank(&l_hash_prev) )
            return l_hash_prev;
        if (( l_prev_tx = s_tx_find_by_hash(a_ledger, &l_hash_prev, a_ledger_locked) ) &&
                ( dap_chain_datum_tx_out_cond_get(l_prev_tx, a_cond_type, NULL) )) {
            l_hash = l_hash_prev;
        }
    }
    return l_hash;
}

dap_hash_fast_t dap_ledger_get_first_chain_tx_hash_ex(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                                      dap_chain_tx_out_cond_subtype_t a_cond_type,
                                                      dap_chain_tx_out_cond_t **a_out_cond)
{
    return s_first_chain_tx_hash(a_ledger, a_tx, a_cond_type, a_out_cond, false);
}

dap_hash_fast_t dap_ledger_get_first_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                                   dap_chain_tx_out_cond_subtype_t a_cond_type)
{
    return s_first_chain_tx_hash(a_ledger, a_tx, a_cond_type, NULL, false);
}

dap_hash_fast_t dap_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only)
{
    dap_chain_hash_fast_t l_hash = { };
    dap_return_val_if_fail(a_ledger && a_tx_hash && !dap_hash_fast_is_blank(a_tx_hash), l_hash);
    l_hash = *a_tx_hash;
    dap_chain_datum_tx_t *l_tx = NULL;
    dap_ledger_tx_item_t *l_item = NULL;
    // Special handling for SRV_DEX to avoid jumping to buyer-leftover EXCHANGE chain
    if (a_cond_type == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
        l_tx = dap_ledger_tx_find_datum_by_hash(a_ledger, &l_hash, &l_item, false);
        if (!l_tx)
            return (dap_hash_fast_t){};
        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_oc = dap_chain_datum_tx_out_cond_get(l_tx, a_cond_type, &l_out_idx);
        if (!l_oc)
            return a_unspent_only ? (dap_hash_fast_t){} : l_hash;
        // Determine chain root: blank => this tx is the root
        dap_hash_fast_t l_root = dap_hash_fast_is_blank(&l_oc->subtype.srv_dex.order_root_hash) ? l_hash : l_oc->subtype.srv_dex.order_root_hash;
        // Traverse while the current chain out is spent and the spender continues the same root (UPDATE or seller residual)
        // If a_unspent_only is set and the chain ends due to root divergence, return blank (no unspent tail for this root)
        while(l_item) {
            dap_hash_fast_t l_spender = l_item->cache_data.tx_hash_spent_fast[l_out_idx];
            if (dap_hash_fast_is_blank(&l_spender))
                break; // current out is unspent => current hash is the tail
            // Load spender tx
            l_tx = dap_ledger_tx_find_datum_by_hash(a_ledger, &l_spender, &l_item, false);
            if (!l_tx)
                // Spender not found in cache, return current known hash
                break;
            // Find SRV_DEX OUT_COND that continues the same root (UPDATE or seller residual) and its output index
            int l_idx = -1, l_found_idx = -1;
            byte_t *it; size_t sz = 0;
            TX_ITEM_ITER_TX(it, sz, l_tx) {
                switch (*it) {
                case TX_ITEM_TYPE_OUT_STD:
                case TX_ITEM_TYPE_OUT_EXT:
                    l_idx++; break;
                case TX_ITEM_TYPE_OUT_COND: {
                    dap_chain_tx_out_cond_t *oc = (dap_chain_tx_out_cond_t*)it; l_idx++;
                    if (oc->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
                        bool l_is_blank = dap_hash_fast_is_blank(&oc->subtype.srv_dex.order_root_hash);
                        bool l_cmp_result = dap_hash_fast_compare(&oc->subtype.srv_dex.order_root_hash, &l_root);
                        // Match root: order_root_hash should point to the same root we're tracking
                        // dap_hash_fast_compare returns true if hashes ARE equal
                        if (l_cmp_result && !l_is_blank) {
                            l_found_idx = l_idx;
                        }
                    }
                } break;
                default: break;
                }
            }
            if (l_found_idx < 0) {
                // No continuation (UPDATE or seller residual) for this root in spender tx => chain ended at previous hash
                if (a_unspent_only)
                    return (dap_hash_fast_t){};
                break;
            }
            // Continue traversal from spender OUT_COND (UPDATE or seller residual)
            l_hash = l_spender;
            l_out_idx = l_found_idx;
            // loop continues
        }
        return l_hash;
    }
    // Default behavior for other condition types
    while (( l_tx = dap_ledger_tx_find_datum_by_hash(a_ledger, &l_hash, &l_item, false) )) {
        int l_out_num = 0;
        if (!dap_chain_datum_tx_out_cond_get(l_tx, a_cond_type, &l_out_num))
            return a_unspent_only ? (dap_hash_fast_t){} : l_hash;
        else if ( dap_hash_fast_is_blank(&(l_item->cache_data.tx_hash_spent_fast[l_out_num])) )
            break;
        l_hash = l_item->cache_data.tx_hash_spent_fast[l_out_num];
    }
    return l_hash;
}

/**
 * Check whether used 'out' items (local function)
 */
static bool s_ledger_tx_hash_is_used_out_item(dap_ledger_tx_item_t *a_item, int a_idx_out, dap_hash_fast_t *a_out_spender_hash)
{
    if (!a_item || !a_item->cache_data.n_outs) {
        //log_it(L_DEBUG, "list_cached_item is NULL");
        return true;
    }
    // a_idx_out comes from the network tx header (tx_out_prev_idx) and is
    // validated by the callers only AFTER this call: bound it here, the
    // tx_hash_spent_fast[] flexible array holds exactly n_outs entries
    if (a_idx_out < 0 || (uint32_t)a_idx_out >= a_item->cache_data.n_outs) {
        debug_if(s_debug_more, L_WARNING, "Out index %d is out of range (%u outs), treat as used", a_idx_out, a_item->cache_data.n_outs);
        return true;
    }
    // if there are used 'out' items
    if ((a_item->cache_data.n_outs_used > 0) && !dap_hash_fast_is_blank(&(a_item->cache_data.tx_hash_spent_fast[a_idx_out]))) {
        if (a_out_spender_hash)
            *a_out_spender_hash = a_item->cache_data.tx_hash_spent_fast[a_idx_out];
        return true;
    }
    return false;
}

static dap_ledger_reward_item_t *s_find_reward(dap_ledger_t *a_ledger, dap_ledger_reward_key_t *a_search_key)
{
    dap_ledger_reward_item_t *l_reward_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->rewards_rwlock);
    HASH_FIND(hh, PVT(a_ledger)->rewards, a_search_key, sizeof(*a_search_key), l_reward_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->rewards_rwlock);
    return l_reward_item;
}

bool dap_ledger_is_used_reward(dap_ledger_t *a_ledger, dap_hash_fast_t *a_block_hash, dap_hash_fast_t *a_sign_pkey_hash)
{
    dap_ledger_reward_key_t l_search_key = { .block_hash = *a_block_hash, .sign_pkey_hash = *a_sign_pkey_hash };
    return s_find_reward(a_ledger, &l_search_key);
}

static int s_callback_sign_compare(dap_list_t *a_list_elem, dap_list_t *a_sign_elem)
{
    dap_pkey_t *l_key = (dap_pkey_t *)a_list_elem->data;
    dap_sign_t *l_sign = (dap_sign_t *)a_sign_elem->data;
    if (!l_key || !l_sign) {
        log_it(L_CRITICAL, "Invalid argument");
        return -1;
    }
    return !dap_pkey_compare_with_sign(l_key, l_sign);
}

inline static bool s_ledger_check_token_ticker(const char *a_ticker)
{
    if (!a_ticker)
        return false;
    size_t l_len = strlen(a_ticker);
    if (l_len < 3 || l_len > 10)
        return false;
    for (size_t i = 0; i < l_len; i++)
        if (!isalnum(a_ticker[i]))
            return false;
    return true;
}


bool dap_ledger_tx_poa_signed(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx)
{
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
    return dap_list_find(a_ledger->net->pub.keys, l_sign, s_callback_sign_compare);
}

const char *dap_ledger_tx_action_str(dap_chain_tx_tag_action_type_t a_tag)
{

    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_UNKNOWN) return "unknown";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR) return "regular";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_TRANSFER_COMISSION) return "comission";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_TRANSFER_CROSSCHAIN) return "crosschain";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REWARD) return "reward";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_OPEN) return "open";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_USE) return "use";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EXTEND) return "extend";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_CLOSE) return "close";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_CHANGE) return "change";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_VOTING) return "voting";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_VOTE) return "vote";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_HOLD) return "hold";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_TAKE) return "take";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_REFILL) return "refill";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EVENT) return "event";

    return "WTFSUBTAG";

}

dap_chain_tx_tag_action_type_t dap_ledger_tx_action_str_to_action_t(const char *a_str)
{
    if (!a_str)
        return DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    
    if (strcmp("unknown", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    if (strcmp("regular", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR;
    if (strcmp("comission", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_TRANSFER_COMISSION;
    if (strcmp("crosschain", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_TRANSFER_CROSSCHAIN;
    if (strcmp("reward", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REWARD;
    if (strcmp("open", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_OPEN;
    if (strcmp("use", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_USE;
    if (strcmp("extend", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EXTEND;
    if (strcmp("close", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_CLOSE;
    if (strcmp("change", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_CHANGE;
    if (strcmp("hold", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_HOLD;
    if (strcmp("take", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_TAKE;
    if (strcmp("refill", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_REFILL;
    if (strcmp("event", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EVENT;
    return DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
}

bool dap_ledger_tx_service_info(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, 
                                dap_chain_net_srv_uid_t *a_uid, char **a_service_name,  dap_chain_tx_tag_action_type_t *a_action)
{
    //find tx
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_tx_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    
    
    if(l_tx_item) {
        dap_ledger_service_info_t *l_sinfo = NULL;
        pthread_rwlock_rdlock(&s_services_rwlock);
        HASH_FIND_INT(s_services, &l_tx_item->cache_data.tag, l_sinfo);
        pthread_rwlock_unlock(&s_services_rwlock);
        if (l_sinfo)
        { 
            if(a_uid) *a_uid = l_sinfo->service_uid;
            if (a_service_name) *a_service_name = l_sinfo->tag_str;
            if (a_action) *a_action = l_tx_item->cache_data.action;
            return true; 
        } 
    }

    if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    return false;
}
bool dap_ledger_deduct_tx_tag(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, char **a_service_name, dap_chain_net_srv_uid_t *a_tag, dap_chain_tx_tag_action_type_t *a_action)
{
    dap_ledger_service_info_t *l_sinfo_current, *l_sinfo_tmp;

    
    dap_chain_datum_tx_item_groups_t l_items_groups = {0};
    dap_chain_datum_tx_group_items(a_tx, &l_items_groups);

    bool l_res = false;
    int l_deductions_ok = 0;

    pthread_rwlock_rdlock(&s_services_rwlock);
    HASH_ITER(hh, s_services , l_sinfo_current, l_sinfo_tmp) {
        dap_chain_tx_tag_action_type_t action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
        if (l_sinfo_current->callback && l_sinfo_current->callback(a_ledger, a_tx, &l_items_groups, &action)){
            if (a_tag) *a_tag =  l_sinfo_current->service_uid;
            if (a_action) *a_action =  action;
            if (a_service_name) *a_service_name = l_sinfo_current->tag_str;
            l_res = true;
            l_deductions_ok ++;
        }
    } 
    pthread_rwlock_unlock(&s_services_rwlock);
    
    dap_chain_datum_tx_group_items_free(&l_items_groups);

    return l_res;
}


const char *dap_ledger_tx_tag_str_by_uid(dap_chain_net_srv_uid_t a_service_uid)
{
    dap_ledger_service_info_t *l_new_sinfo = NULL;
    
    int l_tmp = a_service_uid.raw_ui64;

    pthread_rwlock_rdlock(&s_services_rwlock);
    HASH_FIND_INT(s_services, &l_tmp, l_new_sinfo);
    pthread_rwlock_unlock(&s_services_rwlock);
    
    return l_new_sinfo ? l_new_sinfo->tag_str : "unknown";
}

/**
 * Checking a new transaction before adding to the cache
 *
 * return 0 OK, otherwise error
 */
// Checking a new transaction before adding to the cache
static int s_tx_cache_check(dap_ledger_t *a_ledger,
                            dap_chain_datum_tx_t *a_tx,
                            dap_hash_fast_t *a_tx_hash,
                            bool a_from_threshold,
                            dap_list_t **a_list_bound_items,
                            dap_list_t **a_list_tx_out,
                            char *a_main_ticker,
                            dap_chain_net_srv_uid_t *a_tag,
                            dap_chain_tx_tag_action_type_t *a_action,
                            bool a_check_for_removing,
                            bool a_check_for_apply)
{
    dap_return_val_if_fail(a_ledger && a_tx && a_tx_hash, DAP_LEDGER_CHECK_INVALID_ARGS);
    
    // ARBITRAGE TRANSACTION CHECK
    // Arbitrage TX (marked with TSD) bypass PER-TOKEN blocking checks:
    // - UTXO blocking (for the arbitrage token only)
    // - Address ban-lists sender/receiver (for the arbitrage token only)
    // This allows token owners to claim blocked outputs of THEIR token in emergency situations.
    bool l_is_arbitrage = dap_chain_arbitrage_tx_is_arbitrage(a_tx);
    bool l_arbitrage_auth_valid = false;  // Track if arbitrage authorization passed
    const char *l_arbitrage_token_ticker = NULL;  // Token the arbitrage is authorized for (per-token bypass)
    
    // SECURITY CRITICAL: For arbitrage TX, validate authorization BEFORE processing inputs
    // We must determine the arbitrage token from OUTPUTS (not inputs) to prevent:
    // 1. Order-dependent vulnerabilities (if fee token comes first in inputs)
    // 2. Token confusion attacks (multiple non-native tokens in inputs)
    // 3. Missing validation (if all inputs are fee token)
    if (l_is_arbitrage) {
        debug_if(s_debug_more, L_INFO, "Arbitrage TX detected: %s", 
                 dap_chain_hash_fast_to_str_static(a_tx_hash));
        
        // Determine arbitrage token from outputs (SECURITY CRITICAL)
        l_arbitrage_token_ticker = dap_chain_arbitrage_tx_get_token_ticker(a_ledger, a_tx);
        if (!l_arbitrage_token_ticker) {
            log_it(L_WARNING, "Arbitrage TX %s: can't determine arbitrage token from outputs - rejecting",
                   dap_chain_hash_fast_to_str_static(a_tx_hash));
            return DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED;
        }
        
        // Get token item for authorization check
        dap_ledger_token_item_t *l_arbitrage_token_item = s_ledger_find_token(a_ledger, l_arbitrage_token_ticker);
        if (!l_arbitrage_token_item) {
            log_it(L_WARNING, "Arbitrage TX %s references unknown token '%s' - rejecting",
                   dap_chain_hash_fast_to_str_static(a_tx_hash), l_arbitrage_token_ticker);
            return DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED;
        }
        
        // Validate arbitrage authorization (signatures + outputs to fee address)
        int l_arb_check = dap_chain_arbitrage_tx_check_auth(a_ledger, a_tx, l_arbitrage_token_item);
        if (l_arb_check == DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS) {
            // Not enough signatures yet - keep in mempool for additional signatures
            debug_if(s_debug_more, L_INFO, "Arbitrage TX %s needs more owner signatures for token '%s' - keeping in mempool",
                     dap_chain_hash_fast_to_str_static(a_tx_hash), l_arbitrage_token_ticker);
            return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
        } else if (l_arb_check != 0) {
            log_it(L_WARNING, "Arbitrage TX %s not authorized for token '%s' or outputs not to fee address",
                   dap_chain_hash_fast_to_str_static(a_tx_hash), l_arbitrage_token_ticker);
            return DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED;
        }
        
        // Authorization passed - mark as valid
        l_arbitrage_auth_valid = true;
        debug_if(s_debug_more, L_INFO, "Arbitrage TX %s authorized for token '%s' - bypassing blocking checks for that token only",
                 dap_chain_hash_fast_to_str_static(a_tx_hash), l_arbitrage_token_ticker);
    }
    
    if (!a_from_threshold) {
        dap_ledger_tx_item_t *l_ledger_item = NULL;
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_ledger_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (l_ledger_item && !a_check_for_removing ) {     // transaction already present in the cache list
            if (s_debug_more) {
                log_it(L_WARNING, "Transaction %s already present in the cache", dap_chain_hash_fast_to_str_static(a_tx_hash));
                if (a_tag) *a_tag = l_ledger_item->cache_data.tag;
                if (a_action) *a_action = l_ledger_item->cache_data.action;
            }
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
        } else if (!l_ledger_item && a_check_for_removing) {     // transaction already present in the cache list
            debug_if(s_debug_more, L_WARNING, "Transaction %s not present in the cache. Can not delete it. Skip.", dap_chain_hash_fast_to_str_static(a_tx_hash));
            return DAP_LEDGER_TX_CHECK_FOR_REMOVING_CANT_FIND_TX;
        }
    }
/*
 * Steps of checking for current transaction tx2 and every previous transaction tx1:
 * 1. valid(tx2.dap_chain_datum_tx_sig.pkey)
 * &&
 * 2. tx2.input != tx2.inputs.used
 * &&
 * 3. !is_used_out(tx1.dap_chain_datum_tx_out)
 * &&
 * 4. tx1.dap_chain_datum_tx_out.addr.data.key == tx2.dap_chain_datum_tx_sig.pkey for unconditional output
 * \\
 * 5. tx1.dap_chain_datum_tx_out.condition == verify_svc_type(tx2) for conditional output
 * &&
 * 6. sum(  find (tx2.input.tx_prev_hash).output[tx2.input_tx_prev_idx].value )  ==  sum (tx2.outputs.value) per token
 * &&
 * 7. valid(fee)
*/
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;

    // sum of values in 'out' items from the previous transactions
    dap_ledger_tokenizer_t *l_values_from_prev_tx = NULL, *l_values_from_cur_tx = NULL,
                                 *l_value_cur = NULL, *l_tmp = NULL, *l_res = NULL;
    const char *l_token = NULL, *l_main_ticker = NULL;

    int l_err_num = DAP_LEDGER_CHECK_OK, l_verificator_error = -1;
    int l_prev_tx_count = 0;

    // 1. Verify signature in current transaction
    if (!a_from_threshold && dap_chain_datum_tx_verify_sign(a_tx, 0) && !s_check_hal(a_ledger, a_tx_hash))
        return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;

    // ----------------------------------------------------------------
    // find all 'in' && 'in_cond' && 'in_ems' && 'in_reward'  items in current transaction
    dap_list_t *l_list_in = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN_ALL, &l_prev_tx_count);
    if (!l_list_in) {
        log_it(L_WARNING, "Tx check: no valid inputs found");
        return DAP_LEDGER_TX_CHECK_TX_NO_VALID_INPUTS;
    }
    dap_chain_hash_fast_t l_tx_first_sign_pkey_hash = {};
    dap_pkey_t *l_tx_first_sign_pkey = NULL;
    bool l_girdled_ems_used = false;
    uint256_t l_taxed_value = {};
    
    if(a_tag) dap_ledger_deduct_tx_tag(a_ledger, a_tx, NULL, a_tag, a_action);
    bool l_tax_check = false;
    // find all previous transactions
    for (dap_list_t *it = l_list_in; it; it = it->next) {
         dap_ledger_tx_bound_t *l_bound_item = DAP_NEW_Z(dap_ledger_tx_bound_t);
        if (!l_bound_item) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
            break;
        }
        l_list_bound_items = dap_list_append(l_list_bound_items, l_bound_item);

        uint8_t l_cond_type = *(uint8_t *)it->data;
        l_bound_item->type = l_cond_type;
        uint256_t l_value = uint256_0;
        void *l_tx_prev_out = NULL;
        dap_chain_datum_tx_t *l_tx_prev = NULL;
        dap_ledger_token_emission_item_t *l_emission_item = NULL;
        dap_ledger_stake_lock_item_t *l_stake_lock_emission = NULL;
        bool l_girdled_ems = false;

        switch (l_cond_type) {
        case TX_ITEM_TYPE_IN_EMS: {   // It's the emission (base) TX
            dap_chain_tx_in_ems_t *l_tx_in_ems = it->data;
            l_token = l_tx_in_ems->header.ticker;
            if (!s_ledger_check_token_ticker(l_token)) {
                l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                break;
            }
            dap_hash_fast_t *l_emission_hash = &l_tx_in_ems->header.token_emission_hash;
            // 2. Check current transaction for doubles in input items list
            for (dap_list_t *l_iter = it->next; l_iter; l_iter = l_iter->next) {
                dap_chain_tx_in_ems_t *l_in_ems_check = l_iter->data;
                if (l_in_ems_check->header.type == TX_ITEM_TYPE_IN_EMS &&
                    dap_hash_fast_compare(&l_in_ems_check->header.token_emission_hash, l_emission_hash) && !a_check_for_removing)
                {
                    debug_if(s_debug_more, L_ERROR, "Emission output already used in current tx");
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                    break;
                }
            }
            if (l_err_num)
                break;
            if ((l_girdled_ems = dap_hash_fast_is_blank(l_emission_hash)) ||
                    (l_stake_lock_emission = s_emissions_for_stake_lock_item_find(a_ledger, l_emission_hash))) {
                if (l_stake_lock_emission && !a_check_for_apply) { // It's mempool process, so we don't accept f*cking legacy!
                    log_it(L_WARNING, "Legacy stakes are not accepted from mempool anymore! Dismiss stake emission tx %s", dap_get_data_hash_str(a_tx, dap_chain_datum_tx_get_size(a_tx)).s);
                    l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_LEGACY_FORBIDDEN;
                    break;
                }
                dap_chain_datum_tx_t *l_tx_stake_lock = a_tx;
                // 3. Check emission for STAKE_LOCK
                if (!dap_hash_fast_is_blank(l_emission_hash)) {
                    dap_hash_fast_t cur_tx_hash;
                    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &cur_tx_hash);
                    if (!dap_hash_fast_is_blank(&l_stake_lock_emission->tx_used_out) && !a_check_for_removing) {
                        if (!dap_hash_fast_compare(&cur_tx_hash, &l_stake_lock_emission->tx_used_out))
                            debug_if(s_debug_more, L_WARNING, "stake_lock_emission already present in cache for IN_EMS [%s]", l_token);
                        else
                            debug_if(s_debug_more, L_WARNING, "stake_lock_emission is used out for IN_EMS [%s]", l_token);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_IN_EMS_ALREADY_USED;
                        break;
                    }
                    l_tx_stake_lock = dap_ledger_tx_find_by_hash(a_ledger, l_emission_hash);
                } else {
                    // 2. The only allowed item with girdled emission
                    if (l_girdled_ems_used && !a_check_for_removing) {
                        debug_if(s_debug_more, L_WARNING, "stake_lock_emission is used out for IN_EMS [%s]", l_token);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_IN_EMS_ALREADY_USED;
                        break;
                    } else
                        l_girdled_ems_used = true;
                }
                if (!l_tx_stake_lock) {
                    debug_if(s_debug_more, L_WARNING, "Not found stake_lock transaction");
                    l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
                    break;
                }
                // A base TX that minted m-tokens in its own transaction (contains IN_EMS) must
                // not serve as a second mint source for somebody else: its own mint already
                // credited value*rate, and its registry entry keeps tx_used_out blank.
                if (!l_girdled_ems && !a_check_for_removing &&
                        dap_ledger_stake_strict_mint_in_force(a_ledger) &&
                        dap_chain_datum_tx_item_get(l_tx_stake_lock, NULL, NULL, TX_ITEM_TYPE_IN_EMS, NULL)) {
                    log_it(L_WARNING, "Stake-lock base TX already minted m-tokens in its own transaction - rejecting the second mint");
                    l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_GIRDLED_BASE_TX_CONFLICT;
                    break;
                }

                dap_ledger_token_item_t *l_delegated_item = s_ledger_find_token(a_ledger, l_token);
                if (!l_delegated_item) {
                    debug_if(s_debug_more, L_WARNING, "Token [%s] not found", l_token);
                    l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                    break;
                }
                if (!l_delegated_item->is_delegated) {
                    debug_if(s_debug_more, L_WARNING, "Token [%s] not valid for stake_lock transaction", l_token);
                    l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_INVALID_TOKEN;
                    break;
                }
                if (!dap_ledger_token_ticker_check(a_ledger, l_delegated_item->delegated_from)) {
                    debug_if(s_debug_more, L_WARNING, "Token [%s] not found", l_delegated_item->delegated_from);
                    l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                    break;
                }

                if (l_girdled_ems)
                    l_main_ticker = l_delegated_item->delegated_from;

                // Universal service detection for girdled emissions
                // Support multiple services that can use delegated m-tokens
                static const uint16_t l_supported_service_subtypes[] = {
                    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK,
                    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_EXT_LOCK
                };
                static const size_t l_subtypes_count = sizeof(l_supported_service_subtypes) / sizeof(l_supported_service_subtypes[0]);
                
                dap_chain_tx_out_cond_t *l_tx_service_out_cond = NULL;
                uint16_t l_detected_subtype = 0;
                
                // Find any supported service OUT_COND in the transaction
                for (size_t i = 0; i < l_subtypes_count; i++) {
                    uint16_t l_subtype = l_supported_service_subtypes[i];
                    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(l_tx_stake_lock, l_subtype, NULL);
                    if (l_cond) {
                        l_tx_service_out_cond = l_cond;
                        l_detected_subtype = l_subtype;
                        break;
                    }
                }
                
                if (!l_tx_service_out_cond) {
                    debug_if(s_debug_more, L_WARNING, "No supported service OUT_COND found for IN_EMS [%s] (checked: stake_lock, stake_ext lock)", l_tx_in_ems->header.ticker);
                    l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS;
                    break;
                }
                
                debug_if(s_debug_more, L_NOTICE, "Found service OUT_COND subtype 0x%04X for IN_EMS [%s]", l_detected_subtype, l_tx_in_ems->header.ticker);

                if (l_detected_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
                    uint32_t l_stake_lock_flags = l_tx_service_out_cond->subtype.srv_stake_lock.flags;
                    bool l_strict_mint_rules = dap_ledger_stake_strict_mint_in_force(a_ledger);
                    // Girdled (self-minting) stake-lock emission: the ledger credits value*rate
                    // to the very transaction that carries the lock, so the lock condition must
                    // carry the EMIT flag. Otherwise a lock with flags=0 mints normally and then
                    // unstakes with every burn check skipped (the verificator keys its burn
                    // block off those same flags), leaving the minted m-tokens unbacked.
                    if (l_girdled_ems && l_strict_mint_rules &&
                            !(l_stake_lock_flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_EMIT)) {
                        log_it(L_WARNING, "Girdled stake-lock mint with EMIT flag not set on the lock condition (flags=0x%08X)", l_stake_lock_flags);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_EMIT_FLAG_REQUIRED;
                        break;
                    }
                    // A lock that mints in its own transaction must not double as a base TX for
                    // a later mint: the self-mint leaves the registry entry's tx_used_out blank,
                    // so a second IN_EMS referencing this very tx would mint value*rate again.
                    if (l_girdled_ems && l_strict_mint_rules &&
                            (l_stake_lock_flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX)) {
                        log_it(L_WARNING, "Girdled stake-lock mint combined with CREATE_BASE_TX (flags=0x%08X) would allow minting twice", l_stake_lock_flags);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_GIRDLED_BASE_TX_CONFLICT;
                        break;
                    }
                }

                uint256_t l_value_expected ={};
                if (MULT_256_COIN(l_tx_service_out_cond->header.value, l_delegated_item->emission_rate, &l_value_expected)) {
                    if (s_debug_more) {
                        char *l_emission_rate_str = dap_chain_balance_to_coins(l_delegated_item->emission_rate);
                        const char *l_locked_value_str; dap_uint256_to_char(l_tx_service_out_cond->header.value, &l_locked_value_str);
                        log_it( L_WARNING, "Multiplication overflow for %s emission: locked value %s emission rate %s",
                                                                l_tx_in_ems->header.ticker, l_locked_value_str, l_emission_rate_str);
                        DAP_DEL_Z(l_emission_rate_str);
                    }
                    l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
                    break;
                }
                uint256_t l_stake_lock_ems_value;
                byte_t *l_tx_out = NULL;
                for (int l_item_idx = 0; ; l_item_idx++) {
                    if (!(l_tx_out = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, NULL, TX_ITEM_TYPE_OUT_ALL, NULL)))
                        break;
                    if (*l_tx_out == TX_ITEM_TYPE_OUT_EXT) {
                        dap_chain_tx_out_ext_t *l_tx_out_ext = (dap_chain_tx_out_ext_t *)l_tx_out;
                        if (!strcmp(l_tx_out_ext->token, l_token)) {
                            l_stake_lock_ems_value = l_tx_out_ext->header.value;
                            break;
                        }
                    } else if (*l_tx_out == TX_ITEM_TYPE_OUT_STD) {
                        dap_chain_tx_out_std_t *l_tx_out_std = (dap_chain_tx_out_std_t *)l_tx_out;
                        if (l_tx_out_std->ts_unlock) {
                            debug_if(s_debug_more, L_WARNING, "Time lock is forbidden for stake lock txs");
                            l_err_num = DAP_LEDGER_TX_CHECK_TIMELOCK_ILLEGAL;
                            break;
                        }
                        if (!strcmp(l_tx_out_std->token, l_token)) {
                            l_stake_lock_ems_value = l_tx_out_std->value;
                            break;
                        }
                    } else if (*l_tx_out == TX_ITEM_TYPE_OUT) {
                        dap_chain_tx_out_t *l_tx_out_nontickered = (dap_chain_tx_out_t *)l_tx_out;
                        if (!l_girdled_ems) {
                            l_stake_lock_ems_value = l_tx_out_nontickered->header.value;
                            break;
                        }
                    }
                }
                if (l_err_num)
                    break;
                if (!l_tx_out) {
                    const char *l_err_str = l_girdled_ems ? "No OUT_EXT for girdled IN_EMS"
                                                          : "Can't find OUT nor OUT_EXT item for base TX with IN_EMS";
                    debug_if(s_debug_more, L_WARNING, "%s [%s]", l_err_str, l_tx_in_ems->header.ticker);
                    l_err_num = l_girdled_ems ? DAP_LEDGER_TX_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS : DAP_LEDGER_TX_CHECK_NO_OUT_ITEMS_FOR_BASE_TX;
                    break;
                }

                if (!s_ledger_token_supply_check(l_delegated_item, l_stake_lock_ems_value)) {
                    l_err_num = DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY;
                    break;
                }
                if (!EQUAL_256(l_value_expected, l_stake_lock_ems_value)) {
                    // !!! A terrible legacy crutch, TODO !!!
                    SUM_256_256(l_value_expected, GET_256_FROM_64(10), &l_value_expected);
                    if (!EQUAL_256(l_value_expected, l_stake_lock_ems_value)) {
                            char *l_value_expected_str = dap_chain_balance_print(l_value_expected);
                            char *l_locked_value_str = dap_chain_balance_print(l_stake_lock_ems_value);

                            debug_if(s_debug_more, L_WARNING, "Value %s != %s expected for [%s]",l_locked_value_str, l_value_expected_str,
                                     l_tx_in_ems->header.ticker);

                            DAP_DEL_Z(l_value_expected_str);
                            DAP_DEL_Z(l_locked_value_str);
                            l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_UNEXPECTED_VALUE;
                            break;
                    }
                }
                if (!l_girdled_ems) {
                    // check tiker
                    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, l_emission_hash);
                    if (!l_tx_ticker) {
                        debug_if(s_debug_more, L_WARNING, "No ticker found for stake_lock tx [expected '%s']", l_tx_in_ems->header.ticker);
                        l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                        break;
                    }
                    if (strcmp(l_tx_ticker, l_delegated_item->delegated_from)) {
                        debug_if(s_debug_more, L_WARNING, "Ticker '%s' != expected '%s'", l_tx_ticker, l_tx_in_ems->header.ticker);
                        l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_OTHER_TICKER_EXPECTED;
                        break;
                    }
                }
                debug_if(s_debug_more, L_NOTICE, "Check emission passed for IN_EMS [%s]", l_tx_in_ems->header.ticker);
                if (l_stake_lock_emission)
                    l_bound_item->stake_lock_item = l_stake_lock_emission;
                l_value = l_stake_lock_ems_value;
                l_bound_item->token_item = l_delegated_item;
                l_bound_item->type = TX_ITEM_TYPE_IN_EMS_VIRTUAL;
            } else if ( (l_emission_item = s_emission_item_find(a_ledger, l_token, l_emission_hash, &l_bound_item->token_item)) ) {
                // 3. Check AUTH token emission
                if (!dap_hash_fast_is_blank(&l_emission_item->tx_used_out)  && !a_check_for_removing) {
                    debug_if(s_debug_more, L_WARNING, "Emission for IN_EMS [%s] is already used", l_tx_in_ems->header.ticker);
                    l_err_num = DAP_LEDGER_TX_CHECK_IN_EMS_ALREADY_USED;
                    break;
                }
                l_value = l_emission_item->datum_token_emission->hdr.value;
                l_bound_item->emission_item = l_emission_item;
            } else {
                l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
                break;
            }
        } break;

        case TX_ITEM_TYPE_IN_REWARD: {
            dap_chain_tx_in_reward_t *l_tx_in_reward = it->data;
            dap_hash_fast_t *l_block_hash = &l_tx_in_reward->block_hash;
            // 2. Check current transaction for doubles in input items list
            for (dap_list_t *l_iter = l_list_in; l_iter; l_iter = l_iter->next) {
                dap_chain_tx_in_reward_t *l_in_reward_check = l_iter->data;
                if (l_tx_in_reward != l_in_reward_check &&
                        l_in_reward_check->type == TX_ITEM_TYPE_IN_REWARD &&
                        dap_hash_fast_compare(&l_in_reward_check->block_hash, l_block_hash) && !a_check_for_removing) {
                    debug_if(s_debug_more, L_ERROR, "Reward for this block sign already used in current tx");
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                    break;
                }
            }
            if (l_err_num)
                break;
            if (!l_tx_first_sign_pkey) {
                // Get sign item
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(a_tx, NULL, NULL,
                        TX_ITEM_TYPE_SIG, NULL);
                assert(l_tx_sig);
                // Get sign from sign item
                dap_sign_t *l_tx_first_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
                assert(l_tx_first_sign);
                // calculate hash from sign public key
                dap_sign_get_pkey_hash(l_tx_first_sign, &l_tx_first_sign_pkey_hash);
                l_tx_first_sign_pkey = dap_pkey_get_from_sign(l_tx_first_sign);
            }
            // 3. Check if already spent reward
            dap_ledger_reward_key_t l_search_key = { .block_hash = *l_block_hash, .sign_pkey_hash = l_tx_first_sign_pkey_hash };
            dap_ledger_reward_item_t *l_reward_item = s_find_reward(a_ledger, &l_search_key);
            if (l_reward_item && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_TX_CHECK_REWARD_ITEM_ALREADY_USED;
                char l_block_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE],
                     l_sign_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE],
                     l_spender_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(l_block_hash, l_block_hash_str, sizeof(l_block_hash_str));
                dap_chain_hash_fast_to_str(&l_tx_first_sign_pkey_hash, l_sign_hash_str, sizeof(l_sign_hash_str));
                dap_chain_hash_fast_to_str(&l_reward_item->spender_tx, l_spender_hash_str, sizeof(l_spender_hash_str));
                debug_if(s_debug_more, L_WARNING, "Reward for block %s sign %s already spent by %s", l_block_hash_str, l_sign_hash_str, l_spender_hash_str);
                break;
            }
            // Check reward legitimacy & amount
            dap_chain_t *l_chain;
            DL_FOREACH(a_ledger->net->pub.chains, l_chain) {
                if (l_chain->callback_calc_reward) {
                    l_value = l_chain->callback_calc_reward(l_chain, l_block_hash, l_tx_first_sign_pkey);
                    break;
                }
            }
            if (IS_ZERO_256(l_value)) {
                l_err_num = DAP_LEDGER_TX_CHECK_REWARD_ITEM_ILLEGAL;
                char l_block_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE],
                     l_sign_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(l_block_hash, l_block_hash_str, sizeof(l_block_hash_str));
                dap_chain_hash_fast_to_str(&l_tx_first_sign_pkey_hash, l_sign_hash_str, sizeof(l_sign_hash_str));
                debug_if(s_debug_more, L_DEBUG, "Can't find block %s with sign %s", l_block_hash_str, l_sign_hash_str);
                break;
            }
            // Reward nominated in net native ticker only
            l_token = l_main_ticker = a_ledger->net->pub.native_ticker;
            dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, l_token);
            if (!l_token_item) {
                debug_if(s_debug_more, L_ERROR, "Native token ticker not found");
                l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                break;
            }
            if (!s_ledger_token_supply_check(l_token_item, l_value) && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY;
                break;
            }
            l_bound_item->token_item = l_token_item;
            l_bound_item->reward_key = l_search_key;
            // Overflow checked later with overall values sum
            SUM_256_256(l_taxed_value, l_value, &l_taxed_value);
        } break;
        case TX_ITEM_TYPE_IN:
        case TX_ITEM_TYPE_IN_COND: { // Not emission types
            uint32_t l_tx_prev_out_idx = (uint32_t)-1;
            dap_hash_fast_t *l_tx_prev_hash;
            if (l_cond_type == TX_ITEM_TYPE_IN) {
                dap_chain_tx_in_t *l_tx_in = it->data;
                l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                if (dap_hash_fast_is_blank(l_tx_prev_hash)) {
                    DAP_DELETE(l_bound_item);
                    l_list_bound_items = dap_list_delete_link(l_list_bound_items, dap_list_last(l_list_bound_items));
                    continue; // old base tx compliance
                }
                l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
                // 2. Check current transaction for doubles in input items list
                for (dap_list_t *l_iter = l_list_in; l_iter; l_iter = l_iter->next) {
                    dap_chain_tx_in_t *l_in_check = l_iter->data;
                    if (l_tx_in != l_in_check &&
                            l_in_check->header.type == TX_ITEM_TYPE_IN &&
                            l_in_check->header.tx_out_prev_idx == l_tx_prev_out_idx &&
                            dap_hash_fast_compare(&l_in_check->header.tx_prev_hash, l_tx_prev_hash) && !a_check_for_removing) {
                        debug_if(s_debug_more, L_ERROR, "This previous tx output already used in current tx");
                        l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                        break;
                    }
                }
                if (l_err_num)
                    break;
            } else {
                dap_chain_tx_in_cond_t *l_tx_in_cond = it->data;
                l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
                // 2. Check current transaction for doubles in input items list
                for (dap_list_t *l_iter = l_list_in; l_iter; l_iter = l_iter->next) {
                    dap_chain_tx_in_cond_t *l_in_cond_check = l_iter->data;
                    if (l_tx_in_cond != l_in_cond_check &&
                            l_in_cond_check->header.type == TX_ITEM_TYPE_IN_COND &&
                            l_in_cond_check->header.tx_out_prev_idx == l_tx_prev_out_idx &&
                            dap_hash_fast_compare(&l_in_cond_check->header.tx_prev_hash, l_tx_prev_hash) && !a_check_for_removing) {
                        debug_if(s_debug_more, L_ERROR, "This previous tx output already used in current tx");
                        l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                        break;
                    }
                }
                if (l_err_num)
                    break;
            }
            // Get previous transaction in the cache by hash
            dap_ledger_tx_item_t *l_item_out = NULL;
            l_tx_prev = dap_ledger_tx_find_datum_by_hash(a_ledger, l_tx_prev_hash, &l_item_out, false);
            char l_tx_prev_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(l_tx_prev_hash, l_tx_prev_hash_str, DAP_HASH_FAST_STR_SIZE);
            if (!l_tx_prev) { // Unchained transaction or previous TX was already spent and removed from ledger
                debug_if(s_debug_more && !a_from_threshold, L_DEBUG, "No previous transaction was found for hash %s", l_tx_prev_hash_str);
                l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
                break;
            } else if (l_item_out->cache_data.ts_spent && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED;
                debug_if(s_debug_more, L_WARNING, "All 'out' items of previous tx %s were already spent", l_tx_prev_hash_str);
                break;
            }
            l_bound_item->prev_item = l_item_out;
            l_bound_item->prev_out_idx = l_tx_prev_out_idx;
            l_token = l_item_out->cache_data.token_ticker;
            debug_if(s_debug_more && !a_from_threshold, L_INFO, "Previous transaction was found for hash %s",l_tx_prev_hash_str);

            // 2. Check if out in previous transaction has spent
            dap_hash_fast_t l_spender = {};
            if (s_ledger_tx_hash_is_used_out_item(l_item_out, l_tx_prev_out_idx, &l_spender) && !a_check_for_removing) {
                l_err_num = DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED;
                char l_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(&l_spender, l_hash, sizeof(l_hash));
                debug_if(s_debug_more, L_INFO, "'Out' item %u of previous tx %s already spent by %s", l_tx_prev_out_idx, l_tx_prev_hash_str, l_hash);
                break;
            }

            // 3. Check if UTXO is blocked in token-specific blocklist (UTXO blocking mechanism)
            // This check is skipped if:
            // - UTXO_BLOCKING_DISABLED flag is set for this token
            // - Transaction is an authorized arbitrage TX and this input's token matches the arbitrage token
            dap_ledger_token_item_t *l_token_item_for_utxo_check = s_ledger_find_token(a_ledger, l_token);
            bool l_arb_bypass_for_this_input = l_arbitrage_auth_valid &&
                l_arbitrage_token_ticker && !dap_strcmp(l_token, l_arbitrage_token_ticker);
            if (!l_arb_bypass_for_this_input &&
                l_token_item_for_utxo_check && 
                !(l_token_item_for_utxo_check->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) &&
                !a_check_for_removing) {
                // UTXO blocking is enabled (default behavior) - check if this UTXO is in blocklist
                if (dap_ledger_utxo_is_blocked(l_token_item_for_utxo_check, l_tx_prev_hash, l_tx_prev_out_idx, a_ledger)) {
                    l_err_num = DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED;
                    debug_if(s_debug_more, L_WARNING, "UTXO %s:%u is blocked for token '%s'", 
                             l_tx_prev_hash_str, l_tx_prev_out_idx, l_token);
                    break;
                }
            }
            // Note: Arbitrage authorization is checked ONCE at the beginning of the function
            // (before processing inputs) to prevent order-dependent vulnerabilities and token confusion attacks.
            // The bypass is per-token: only inputs whose token matches l_arbitrage_token_ticker are exempted.

            // Get one 'out' item in previous transaction bound with current 'in' item
            l_tx_prev_out = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
            if(!l_tx_prev_out) {
                l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_NOT_FOUND;
                break;
            }
            if (dap_hash_fast_is_blank(&l_tx_first_sign_pkey_hash)) {
                // Get sign item
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(a_tx, NULL, NULL,
                        TX_ITEM_TYPE_SIG, NULL);
                assert(l_tx_sig);
                // Get sign from sign item
                dap_sign_t *l_tx_first_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
                assert(l_tx_first_sign);
                // calculate hash from sign public key
                dap_sign_get_pkey_hash(l_tx_first_sign, &l_tx_first_sign_pkey_hash);
            }
            if (l_cond_type == TX_ITEM_TYPE_IN) {
                dap_chain_addr_t *l_addr_from = NULL;
                dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_prev_out;
                switch (l_type) {
                case TX_ITEM_TYPE_OUT_OLD: // Deprecated
                    l_addr_from = &((dap_chain_tx_out_old_t *)l_tx_prev_out)->addr;
                    l_value = dap_chain_uint256_from(((dap_chain_tx_out_old_t *)l_tx_prev_out)->header.value);
                    break;
                case TX_ITEM_TYPE_OUT:
                    l_addr_from = &((dap_chain_tx_out_t *)l_tx_prev_out)->addr;
                    l_value = ((dap_chain_tx_out_t *)l_tx_prev_out)->header.value;
                    break;
                case TX_ITEM_TYPE_OUT_EXT:
                    l_addr_from = &((dap_chain_tx_out_ext_t *)l_tx_prev_out)->addr;
                    l_value = ((dap_chain_tx_out_ext_t *)l_tx_prev_out)->header.value;
                    l_token = ((dap_chain_tx_out_ext_t *)l_tx_prev_out)->token;
                    break;       
                case TX_ITEM_TYPE_OUT_STD:
                    if (((dap_chain_tx_out_std_t *)l_tx_prev_out)->ts_unlock > PVT(a_ledger)->blockchain_time) {
                        l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_LOCKED;
                        break;
                    }
                    l_addr_from = &((dap_chain_tx_out_std_t *)l_tx_prev_out)->addr;
                    l_value = ((dap_chain_tx_out_std_t *)l_tx_prev_out)->value;
                    l_token = ((dap_chain_tx_out_std_t *)l_tx_prev_out)->token;
                    break;
                default:
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_MISSTYPED;
                    break;
                }
                if (l_err_num)
                    break;
                l_bound_item->in.addr_from = *l_addr_from;
                dap_strncpy(l_bound_item->in.token_ticker, l_token, DAP_CHAIN_TICKER_SIZE_MAX);
                // 4. compare public key hashes in the signature of the current transaction and in the 'out' item of the previous transaction
                // Arbitrage lifts the blocking mechanisms, not the UTXO-ownership rule:
                // the input must still belong to the first signer's key.
                if (l_addr_from->net_id.uint64 != a_ledger->net->pub.id.uint64 ||
                        !dap_hash_fast_compare(&l_tx_first_sign_pkey_hash, &l_addr_from->data.hash_fast)) {
                    l_err_num = DAP_LEDGER_TX_CHECK_PKEY_HASHES_DONT_MATCH;
                    break;
                }

                if ( !l_token || !*l_token ) {
                    log_it(L_WARNING, "No token ticker found in previous transaction");
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                    break;
                }
                // Get permissions
                dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, l_token);
                if (!l_token_item) {
                    debug_if(s_debug_more, L_WARNING, "Token with ticker %s not found", l_token);
                    l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
                    break;
                }
                // Check permissions
                if (!l_arb_bypass_for_this_input &&
                    s_ledger_addr_check(a_ledger, l_token_item, l_addr_from, false) == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
                    debug_if(s_debug_more, L_WARNING, "No permission to send for addr %s", dap_chain_addr_to_str_static(l_addr_from));
                    l_err_num = DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
                    break;
                }
            } else { // l_cond_type == TX_ITEM_TYPE_IN_COND
                if(*(uint8_t *)l_tx_prev_out != TX_ITEM_TYPE_OUT_COND) {
                    l_err_num = DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_MISSTYPED;
                    break;
                }
                dap_chain_tx_out_cond_t *l_tx_prev_out_cond = NULL;
                l_tx_prev_out_cond = (dap_chain_tx_out_cond_t *)l_tx_prev_out;

                // 5a. Check for condition owner
                // Get owner tx
                dap_hash_fast_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, l_tx_prev, l_tx_prev_out_cond->header.subtype);
                dap_chain_datum_tx_t *l_owner_tx = dap_hash_fast_is_blank(&l_owner_tx_hash)
                    ? l_tx_prev
                    : dap_ledger_tx_find_by_hash(a_ledger, &l_owner_tx_hash);
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
                dap_chain_tx_sig_t *l_owner_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                dap_sign_t *l_owner_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_owner_tx_sig);

                bool l_owner = false;
                l_owner = dap_sign_compare_pkeys(l_owner_sign, l_sign);

                // 5b. Call verificator for conditional output
                dap_ledger_verificator_t *l_verificator = NULL;
                int l_sub_tmp = l_tx_prev_out_cond->header.subtype;

                pthread_rwlock_rdlock(&s_verificators_rwlock);
                HASH_FIND_INT(s_verificators, &l_sub_tmp, l_verificator);
                pthread_rwlock_unlock(&s_verificators_rwlock);
                if (!l_verificator || !l_verificator->callback) {
                    debug_if(s_debug_more, L_ERROR, "No verificator set for conditional output subtype %d", l_sub_tmp);
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
                    break;
                }

                l_verificator_error = l_verificator->callback(a_ledger, l_tx_prev_out_cond, a_tx, l_owner, a_check_for_apply);
                if ( !s_check_hal(a_ledger, a_tx_hash) && l_verificator_error != DAP_LEDGER_CHECK_OK ) { // TODO add string representation for verificator return codes
                    debug_if(s_debug_more, L_WARNING, "Verificator check error %d for conditional output %s",
                                                                    l_verificator_error, dap_chain_tx_out_cond_subtype_to_str(l_sub_tmp));
                    // Retranslate NO_SIGNS code to upper level
                    l_err_num = l_verificator_error == DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS ? l_verificator_error : DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                    break;
                }
                l_bound_item->cond = l_tx_prev_out_cond;
                l_value = l_tx_prev_out_cond->header.value;
                if (l_tx_prev_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                    l_tax_check = true;
                    l_token = a_ledger->net->pub.native_ticker;
                    // Overflow checked later with overall values sum
                    SUM_256_256(l_taxed_value, l_value, &l_taxed_value);
                }
                l_main_ticker = l_token;
            }
        } break;

        default:
            break;
        }
        if (l_err_num)
            break;

        l_bound_item->value = l_value;

        if (l_cond_type != TX_ITEM_TYPE_IN) {
            // If not checked earlier
            if (!l_token || !*l_token) {
                log_it(L_WARNING, "No token ticker found in previous transaction");
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
        }
        HASH_FIND_STR(l_values_from_prev_tx, l_token, l_value_cur);
        if (!l_value_cur) {
            l_value_cur = DAP_NEW_Z(dap_ledger_tokenizer_t);
            if ( !l_value_cur ) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
                break;
            }
            dap_strncpy(l_value_cur->token_ticker, l_token, DAP_CHAIN_TICKER_SIZE_MAX - 1);
            HASH_ADD_STR(l_values_from_prev_tx, token_ticker, l_value_cur);
        }
        // calculate  from previous transactions per each token
        if (SUM_256_256(l_value_cur->sum, l_value, &l_value_cur->sum)) {
            debug_if(s_debug_more, L_WARNING, "Sum result overflow for tx_add_check with ticker %s",
                                    l_value_cur->token_ticker);
            l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
            break;
        }
    }

    dap_list_free(l_list_in);
    DAP_DELETE(l_tx_first_sign_pkey);
    if (l_err_num) {
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, NULL);
        HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
            HASH_DEL(l_values_from_prev_tx, l_value_cur);
            DAP_DELETE(l_value_cur);
        }
    return l_err_num;
    }

    // 6. Compare sum of values in 'out' items

    switch ( HASH_COUNT(l_values_from_prev_tx) ) {
    case 1:
        if (!l_main_ticker)
            l_main_ticker = l_value_cur->token_ticker;
        break;
    case 2:
        if (l_main_ticker)
            break;
        HASH_FIND_STR(l_values_from_prev_tx, a_ledger->net->pub.native_ticker, l_value_cur);
        if (l_value_cur) {
            l_value_cur = l_value_cur->hh.next ? l_value_cur->hh.next : l_value_cur->hh.prev;
            l_main_ticker = l_value_cur->token_ticker;
        }
        break;
    default:
        if (!l_main_ticker) {
            dap_list_free_full(l_list_bound_items, NULL);
            HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
                HASH_DEL(l_values_from_prev_tx, l_value_cur);
                DAP_DELETE(l_value_cur);
            }
            return DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
        }
    }

    dap_chain_net_srv_stake_item_t *l_key_item = NULL;
    if (l_tax_check) {
        l_key_item = dap_chain_net_srv_stake_check_pkey_hash(a_ledger->net->pub.id, &l_tx_first_sign_pkey_hash);
        l_tax_check = l_key_item && !dap_chain_addr_is_blank(&l_key_item->sovereign_addr) && !IS_ZERO_256(l_key_item->sovereign_tax);
    }
    

    // find 'out' items
    bool l_cross_network = false;
    uint256_t l_out_value = {}, l_fee_sum = {}, l_tax_sum = {};
    bool l_fee_check = !IS_ZERO_256(a_ledger->net->pub.fee_value) && !dap_chain_addr_is_blank(&a_ledger->net->pub.fee_addr);
    int l_item_idx = 0;
    byte_t *it; size_t l_size;
    TX_ITEM_ITER_TX(it, l_size, a_tx) {
        dap_chain_addr_t l_tx_out_to = { };
        switch ( *it ) {
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_tx_out = (dap_chain_tx_out_old_t*)it;
            l_token = l_main_ticker;
            if (!l_token) {
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_out_value = dap_chain_uint256_from(l_tx_out->header.value);
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)it;
            l_token = l_main_ticker;
            if (!l_token) {
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_out_value = l_tx_out->header.value;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_EXT: { // 256
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)it;
            l_out_value = l_tx_out->header.value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_tx_out = (dap_chain_tx_out_std_t *)it;
            l_out_value = l_tx_out->value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t *)it;
            if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                l_token = a_ledger->net->pub.native_ticker;
            } else if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
                // Classify SRV_DEX: main_ticker = sell token (from inputs)
                const char *l_native = a_ledger->net->pub.native_ticker, *l_buy_tok = l_tx_out->subtype.srv_dex.buy_token;
                l_token = NULL;
                dap_ledger_tokenizer_t *l_tok_prev, *l_tok_tmp;
                // First pass: find non-native, non-buy token
                HASH_ITER(hh, l_values_from_prev_tx, l_tok_prev, l_tok_tmp) {
                    if ( !dap_strcmp(l_tok_prev->token_ticker, l_native) )
                        continue;
                    if ( dap_strcmp(l_tok_prev->token_ticker, l_buy_tok) ) {
                        l_token = l_tok_prev->token_ticker;
                        break;
                    }
                }
                if ( !l_token ) {
                    // Second pass: check if native token is the sell token
                    // (happens when native is QUOTE in BID or BASE in ASK)
                    HASH_FIND_STR(l_values_from_prev_tx, l_native, l_tok_prev);
                    l_token = l_tok_prev && dap_strcmp(l_native, l_buy_tok) ? l_native : l_buy_tok;
                    // Native token present in inputs AND native != buy_token → native is sell token
                }
                if ( !l_token ) {
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                    break;
                }
                log_it(L_DEBUG, "SRV_DEX token extraction: buy = %s, main = %s, unqualified main was %s",
                       l_buy_tok ? l_buy_tok : "NULL", l_token, l_main_ticker);
                l_main_ticker = l_token;
            } else
                l_token = l_main_ticker;
            if (!l_token) {
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_out_value = l_tx_out->header.value;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
            // Call verificator for new OUT_COND (ORDER creation validation)
            // Pass a_tx_out_cond=NULL to indicate this is a NEW conditional output
            if (l_verificator_error == -1 && (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX ||
                                              l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE)) {
                dap_ledger_verificator_t *l_verificator = NULL;
                int l_sub_tmp = l_tx_out->header.subtype;
                pthread_rwlock_rdlock(&s_verificators_rwlock);
                HASH_FIND_INT(s_verificators, &l_sub_tmp, l_verificator);
                pthread_rwlock_unlock(&s_verificators_rwlock);
                if (l_verificator && l_verificator->callback) {
                    int l_verif_err = l_verificator->callback(a_ledger, NULL, a_tx, false, a_check_for_apply);
                    if (!s_check_hal(a_ledger, a_tx_hash) && l_verif_err) {
                        debug_if(s_debug_more, L_WARNING, "Verificator rejected new OUT_COND subtype %d: error %d",
                                 l_sub_tmp, l_verif_err);
                        l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                        break;
                    }
                }
            }
            if (l_tax_check && l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE &&
                    SUBTRACT_256_256(l_taxed_value, l_out_value, &l_taxed_value)) {
                log_it(L_WARNING, "[%s] Fee is greater than sum of inputs", dap_chain_hash_fast_to_str_static(a_tx_hash));
                l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
                break;
            }
        } break;
        default:
            continue;
        }
        if (!dap_chain_addr_is_blank(&l_tx_out_to)) {
            if (l_tx_out_to.addr_type != DAP_CHAIN_ADDR_TYPE_REGULAR) {
                log_it(L_WARNING, "[%s] Standard output targets non-regular address (addr_type=0x%02x)",
                       dap_chain_hash_fast_to_str_static(a_tx_hash), l_tx_out_to.addr_type);
                l_err_num = DAP_LEDGER_TX_CHECK_INVALID_ADDR_TYPE;
                break;
            }
            if (l_tx_out_to.net_id.uint64 != a_ledger->net->pub.id.uint64) {
                if (!l_cross_network) {
                    l_cross_network = true;
                } else {
                    log_it(L_WARNING, "[%s] The transaction was rejected because it contains multiple outputs to other network.", dap_chain_hash_fast_to_str_static(a_tx_hash));
                    l_err_num = DAP_LEDGER_TX_CHECK_MULTIPLE_OUTS_TO_OTHER_NET;
                    break;
                }
            }
        }

        if (l_err_num)
            break;
        HASH_FIND_STR(l_values_from_cur_tx, l_token, l_value_cur);
        if (!l_value_cur) {
            l_value_cur = DAP_NEW_Z(dap_ledger_tokenizer_t);
            if ( !l_value_cur ) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_err_num = DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
                break;
            }
            dap_strncpy(l_value_cur->token_ticker, l_token, DAP_CHAIN_TICKER_SIZE_MAX - 1);
            HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
        }
        if (SUM_256_256(l_value_cur->sum, l_out_value, &l_value_cur->sum)) {
            debug_if(s_debug_more, L_WARNING, "Sum result overflow for tx_add_check with ticker %s",
                                    l_value_cur->token_ticker);
            l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
            break;
        }

        // Find token item
        dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, l_token);
        if (!l_token_item) {
            debug_if(s_debug_more, L_WARNING, "[%s] Token with ticker %s not found", dap_chain_hash_fast_to_str_static(a_tx_hash), l_token);
            l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
            break;
        }
        // Check permissions
        bool l_arb_bypass_for_output = l_arbitrage_auth_valid &&
            l_arbitrage_token_ticker && !dap_strcmp(l_token, l_arbitrage_token_ticker);
        if (!l_arb_bypass_for_output &&
            s_ledger_addr_check(a_ledger, l_token_item, &l_tx_out_to, true) == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
            debug_if(s_debug_more, L_WARNING, "[%s] No permission to receive for addr %s", dap_chain_hash_fast_to_str_static(a_tx_hash), dap_chain_addr_to_str_static(&l_tx_out_to));
            l_err_num = DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
            break;
        }
        if (l_fee_check && dap_chain_addr_compare(&l_tx_out_to, &a_ledger->net->pub.fee_addr) &&
                !dap_strcmp(l_value_cur->token_ticker, a_ledger->net->pub.native_ticker))
            SUM_256_256(l_fee_sum, l_out_value, &l_fee_sum);

        if (l_tax_check && dap_chain_addr_compare(&l_tx_out_to, &l_key_item->sovereign_addr) &&
                !dap_strcmp(l_value_cur->token_ticker, a_ledger->net->pub.native_ticker))
            SUM_256_256(l_tax_sum, l_out_value, &l_tax_sum);
    }

    // Check for transaction consistency (sum(ins) == sum(outs))
    if ( !l_err_num && !s_check_hal(a_ledger, a_tx_hash) ) {
        if ( HASH_COUNT(l_values_from_prev_tx) != HASH_COUNT(l_values_from_cur_tx) ) {
            log_it(L_ERROR, "[%s] Token tickers IN and OUT mismatch: %u != %u",
                            dap_chain_hash_fast_to_str_static(a_tx_hash),
                            HASH_COUNT(l_values_from_prev_tx), HASH_COUNT(l_values_from_cur_tx));
            l_err_num = DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS;
        } else {
            HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
                HASH_FIND_STR(l_values_from_cur_tx, l_value_cur->token_ticker, l_res);
                if (!l_res || !EQUAL_256(l_res->sum, l_value_cur->sum) ) {
                    if (s_debug_more) {
                        char *l_balance = dap_chain_balance_to_coins(l_res ? l_res->sum : uint256_0);
                        char *l_balance_cur = dap_chain_balance_to_coins(l_value_cur->sum);
                        log_it(L_ERROR, "[%s] Sum of values of out items from current tx (%s) is not equal outs from previous txs (%s) for token %s",
                                dap_chain_hash_fast_to_str_static(a_tx_hash),
                                l_balance, l_balance_cur, l_value_cur->token_ticker);
                        DAP_DELETE(l_balance);
                        DAP_DELETE(l_balance_cur);
                    }
                    l_err_num = DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS;
                    break;
                }
            }
        }
    }

    // 7. Check the network fee
    if (!l_err_num && l_fee_check) {
        // Check for PoA-cert-signed "service" no-tax tx
        if (compare256(l_fee_sum, a_ledger->net->pub.fee_value) == -1 &&
                !dap_ledger_tx_poa_signed(a_ledger, a_tx)) {
            char *l_current_fee = dap_chain_balance_to_coins(l_fee_sum);
            char *l_expected_fee = dap_chain_balance_to_coins(a_ledger->net->pub.fee_value);
            log_it(L_WARNING, "[%s] Fee value is invalid, expected %s pointed %s", dap_chain_hash_fast_to_str_static(a_tx_hash), l_expected_fee, l_current_fee);
            l_err_num = DAP_LEDGER_TX_CHECK_NOT_ENOUGH_FEE;
            DAP_DEL_Z(l_current_fee);
            DAP_DEL_Z(l_expected_fee);
        }
        if (l_tax_check && SUBTRACT_256_256(l_taxed_value, l_fee_sum, &l_taxed_value)) {
            log_it(L_WARNING, "[%s] Fee is greater than sum of inputs", dap_chain_hash_fast_to_str_static(a_tx_hash));
            l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
        }
    }

    // 8. Check sovereign tax
    if (l_tax_check && !l_err_num) {
        uint256_t l_expected_tax = {};
        MULT_256_COIN(l_taxed_value, l_key_item->sovereign_tax, &l_expected_tax);
        if (compare256(l_tax_sum, l_expected_tax) == -1) {
            char *l_current_tax_str = dap_chain_balance_to_coins(l_tax_sum);
            char *l_expected_tax_str = dap_chain_balance_to_coins(l_expected_tax);
            log_it(L_WARNING, "[%s] Tax value is invalid, expected %s pointed %s", dap_chain_hash_fast_to_str_static(a_tx_hash), l_expected_tax_str, l_current_tax_str);
            l_err_num = DAP_LEDGER_TX_CHECK_NOT_ENOUGH_TAX;
            DAP_DEL_Z(l_current_tax_str);
            DAP_DEL_Z(l_expected_tax_str);
        }
    }
    if (!l_err_num) {

        byte_t *it; size_t l_size;
        TX_ITEM_ITER_TX(it, l_size, a_tx) {
            switch (*it) {
            case TX_ITEM_TYPE_VOTING:
                if (s_voting_callbacks.voting_callback) {
                    if ((l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx, a_tx_hash, false))) {
                        debug_if(s_debug_more, L_WARNING, "Verificator check error %d for voting", l_err_num);
                        l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                        break;
                    }
                } else {
                    debug_if(s_debug_more, L_WARNING, "Verificator check error for voting item");
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
                    break;
                }
                break;
            case TX_ITEM_TYPE_VOTE:
                if (s_voting_callbacks.voting_callback) {
                    if (!s_check_hal(a_ledger, a_tx_hash) &&
                    (l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx, a_tx_hash, false))) {
                        debug_if(s_debug_more, L_WARNING, "Verificator check error %d for vote", l_err_num);
                        l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                        break;
                    }
                } else {
                    debug_if(s_debug_more, L_WARNING, "Verificator check error for vote item");
                    l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
                    break;
                }
                break;
            case TX_ITEM_TYPE_EVENT:
                if (s_ledger_event_verify_add(a_ledger, a_tx_hash, a_tx, false, a_check_for_apply)) {
                    l_err_num = DAP_LEDGER_TX_CHECK_EVENT_VERIFY_FAILURE;
                    break;
                }
                break;
            default:
                break;
            }
            if (l_err_num)
                break;
        }
    }

    if (a_main_ticker && !l_err_num)
        dap_strncpy(a_main_ticker, l_main_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);

    HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
        HASH_DEL(l_values_from_prev_tx, l_value_cur);
        DAP_DELETE(l_value_cur);
    }
    HASH_ITER(hh, l_values_from_cur_tx, l_value_cur, l_tmp) {
        HASH_DEL(l_values_from_cur_tx, l_value_cur);
        DAP_DELETE(l_value_cur);
    }
    if (!a_list_bound_items || l_err_num) {
        dap_list_free_full(l_list_bound_items, NULL);
    } else {
        *a_list_bound_items = l_list_bound_items;
    }

    if (!a_list_tx_out || l_err_num) {
        dap_list_free(l_list_tx_out);
    } else {
        *a_list_tx_out = l_list_tx_out;
    }

    return l_err_num;
}

/**
 * @brief dap_ledger_tx_check
 * @param a_ledger
 * @param a_tx
 * @return
 */
int dap_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, size_t a_datum_size, dap_hash_fast_t *a_datum_hash)
{
    dap_return_val_if_fail(a_tx && a_ledger, DAP_LEDGER_CHECK_INVALID_ARGS);

    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    if (l_tx_size != a_datum_size) {
        log_it (L_WARNING, "Inconsistent datum TX: datum size %zu != tx size %zu", a_datum_size, l_tx_size);
        return DAP_LEDGER_CHECK_INVALID_SIZE;
    }
    int l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_datum_hash, false, NULL, NULL, NULL, NULL, NULL, false, false);
    if(s_debug_more) {
        if (l_ret_check)
            log_it(L_NOTICE, "Ledger TX adding check not passed for TX %s: error %s",
                   dap_chain_hash_fast_to_str_static(a_datum_hash), dap_ledger_check_error_str(l_ret_check));
        else
            log_it(L_INFO, "Ledger TX adding check passed for TX %s", dap_chain_hash_fast_to_str_static(a_datum_hash));
    }

    return l_ret_check;
}

/**
 * @brief s_balance_cache_update
 * @param a_ledger
 * @param a_balance
 * @return
 */
static int s_balance_cache_update(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_balance)
{
    if (PVT(a_ledger)->cached && !PVT(a_ledger)->snapshot_mode) {
        char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_BALANCES_STR);
        if (dap_global_db_set(l_gdb_group, a_balance->key, &a_balance->balance, sizeof(uint256_t), false, NULL, NULL)) {
            debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch");
            return -1;
        }
        DAP_DELETE(l_gdb_group);
    }
    /* Notify the world*/
    if ( !dap_chain_net_get_load_mode(a_ledger->net) ) {
        struct json_object *l_json = wallet_info_json_collect(a_ledger, a_balance);
        if (l_json) {
            dap_notify_server_send_mt(json_object_get_string(l_json));
            json_object_put(l_json);
        }
    }
    return 0;
}

static int s_sort_ledger_tx_item(dap_ledger_tx_item_t *a, dap_ledger_tx_item_t *b)
{
    if (a->cache_data.ts_created < b->cache_data.ts_created)
        return -1;
    if (a->cache_data.ts_created == b->cache_data.ts_created)
        return 0;
    return 1;
}

static int s_compare_locked_outs(dap_ledger_locked_out_t *a_out1, dap_ledger_locked_out_t *a_out2)
{
    return a_out1->unlock_time < a_out2->unlock_time ? -1
           : a_out1->unlock_time > a_out2->unlock_time ?
           1 : 0;
}

int dap_ledger_pvt_balance_update_for_addr(dap_ledger_t *a_ledger, dap_chain_addr_t *a_addr, const char *a_token_ticker, uint256_t a_value, bool a_reverse)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_wallet_balance_t *l_wallet_balance = NULL;
    char *l_wallet_balance_key = dap_strjoin(" ", dap_chain_addr_to_str_static(a_addr), a_token_ticker, (char*)NULL);
    debug_if(s_debug_more, L_DEBUG, "%s %s to addr: %s", a_reverse ? "UNDO" : "GOT", dap_uint256_to_char(a_value, NULL), l_wallet_balance_key);
    pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
    HASH_FIND_STR(l_ledger_pvt->balance_accounts, l_wallet_balance_key, l_wallet_balance);
    if (l_wallet_balance) {
        if (a_reverse) {
            int of = SUBTRACT_256_256(l_wallet_balance->balance, a_value, &l_wallet_balance->balance);
            assert(!of);
        } else
            SUM_256_256(l_wallet_balance->balance, a_value, &l_wallet_balance->balance);
        DAP_DELETE(l_wallet_balance_key);
    } else {
        if (a_reverse) {
            log_it(L_ERROR, "Trying to substract value from nonexistent balance %s", l_wallet_balance_key);
            DAP_DELETE(l_wallet_balance_key);
            pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
            return -2;
        }
        l_wallet_balance = DAP_NEW_Z(dap_ledger_wallet_balance_t);
        if (!l_wallet_balance) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
            return -1;
        }
        l_wallet_balance->key = l_wallet_balance_key;
        dap_strncpy(l_wallet_balance->token_ticker, a_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
        SUM_256_256(l_wallet_balance->balance, a_value, &l_wallet_balance->balance);
        debug_if(s_debug_more, L_DEBUG, "Create new balance item: %s %s", dap_chain_addr_to_str_static(a_addr), a_token_ticker);
        HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, l_wallet_balance->key,
                        strlen(l_wallet_balance_key), l_wallet_balance);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    // Update the cache
    s_balance_cache_update(a_ledger, l_wallet_balance);
    return 0;
}

// RPC reply cache maintenance: a transaction changes the UTXO set of every address
// it pays to and of every address it spends from. Invalidate exactly those entries
// (both cached classes keep the base58 address first in their keys) instead of
// dropping whole classes on every accepted block - a class-wide drop makes the cache
// useless on a chain that keeps producing blocks.
static void s_ledger_rpc_cache_invalidate_addr(const char *a_addr_str,
                                               dap_rpc_cache_class_t *a_wallet_outputs,
                                               dap_rpc_cache_class_t *a_tx_history)
{
    char l_prefix[DAP_ENC_BASE58_ENCODE_SIZE(sizeof(dap_chain_addr_t)) + 2];
    if (snprintf(l_prefix, sizeof(l_prefix), "%s|", a_addr_str) <= 0)
        return;
    if (a_wallet_outputs)
        dap_rpc_cache_invalidate_prefix(a_wallet_outputs, l_prefix);
    if (a_tx_history)
        dap_rpc_cache_invalidate_prefix(a_tx_history, l_prefix);
}

static void s_ledger_rpc_cache_notify_tx(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                         dap_list_t *a_bound_items)
{
    if (!dap_rpc_cache_is_enabled())
        return;
    dap_rpc_cache_class_t *l_wallet_outputs = dap_rpc_cache_class_find("wallet_outputs");
    dap_rpc_cache_class_t *l_tx_history = dap_rpc_cache_class_find("tx_history");
    if ((!l_wallet_outputs || !dap_rpc_cache_class_has_entries(l_wallet_outputs))
            && (!l_tx_history || !dap_rpc_cache_class_has_entries(l_tx_history)))
        return;
    // Inputs: the spent address is already known from the bound items built by
    // s_tx_cache_check() - re-resolving every previous transaction by hash here
    // doubled the ledger hot path for nothing.
    for (dap_list_t *it = a_bound_items; it; it = it->next) {
        dap_ledger_tx_bound_t *l_bound = it->data;
        if (l_bound->type == TX_ITEM_TYPE_IN)
            s_ledger_rpc_cache_invalidate_addr(dap_chain_addr_to_str_static(&l_bound->in.addr_from),
                                               l_wallet_outputs, l_tx_history);
    }
    byte_t *l_item = NULL;
    size_t l_item_size = 0;
    TX_ITEM_ITER_TX(l_item, l_item_size, a_tx) {
        dap_chain_addr_t *l_addr = NULL;
        switch ((dap_chain_tx_item_type_t)*l_item) {
        case TX_ITEM_TYPE_OUT:
            l_addr = &((dap_chain_tx_out_t *)l_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_addr = &((dap_chain_tx_out_ext_t *)l_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT_STD:
            l_addr = &((dap_chain_tx_out_std_t *)l_item)->addr;
            break;
        case TX_ITEM_TYPE_IN_COND: {
            // Conditional outs have no common address field; resolve the spent
            // output only for these (rare) items.
            dap_chain_tx_in_cond_t *l_in_cond = (dap_chain_tx_in_cond_t *)l_item;
            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_in_cond->header.tx_prev_hash);
            if (!l_prev_tx)
                break;
            byte_t *l_prev_item = dap_chain_datum_tx_out_get_by_out_idx(l_prev_tx, l_in_cond->header.tx_out_prev_idx);
            if (!l_prev_item)
                break;
            switch ((dap_chain_tx_item_type_t)*l_prev_item) {
            case TX_ITEM_TYPE_OUT:
                l_addr = &((dap_chain_tx_out_t *)l_prev_item)->addr;
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                l_addr = &((dap_chain_tx_out_ext_t *)l_prev_item)->addr;
                break;
            case TX_ITEM_TYPE_OUT_STD:
                l_addr = &((dap_chain_tx_out_std_t *)l_prev_item)->addr;
                break;
            default:
                break;
            }
        } break;
        default:
            break;
        }
        if (l_addr)
            s_ledger_rpc_cache_invalidate_addr(dap_chain_addr_to_str_static(l_addr),
                                               l_wallet_outputs, l_tx_history);
    }
}

/**
 * @brief Add new transaction to the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
 * @return return 1 OK, -1 error
 */
int dap_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold, dap_ledger_datum_iter_data_t *a_datum_index_data)
{
    if(!a_tx) {
        debug_if(s_debug_more, L_ERROR, "NULL tx detected");
        return -1;
    }
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;
    dap_ledger_tx_item_t *l_item_tmp = NULL;
    char l_main_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = { '\0' };

    bool l_from_threshold = a_from_threshold;
    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    int l_ret_check;
    dap_chain_net_srv_uid_t l_tag =  { .uint64 = 0 }; 
    dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;

    if( (l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_tx_hash, a_from_threshold,
                                                       &l_list_bound_items, &l_list_tx_out,
                                                       l_main_token_ticker, &l_tag, &l_action, false, true))) {                                                        
        if ((l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS ||
                l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION) &&
                l_ledger_pvt->threshold_enabled && !dap_chain_net_get_load_mode(a_ledger->net)) {
            if (!l_from_threshold) {
                unsigned l_hash_value = 0;
                HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
                pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
                HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->threshold_txs, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item_tmp);
                unsigned long long l_threshold_txs_count = HASH_COUNT(l_ledger_pvt->threshold_txs);
                if (!l_item_tmp) {
                    if (l_threshold_txs_count >= s_threshold_txs_max) {
                        if(s_debug_more)
                            log_it(L_WARNING, "Threshold for transactions is overfulled (%zu max), dropping down tx %s, added nothing",
                                       s_threshold_txs_max, l_tx_hash_str);
                    } else {
                        l_item_tmp = DAP_NEW_Z(dap_ledger_tx_item_t);
                        if ( !l_item_tmp ) {
                            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                            return -1;
                        }
                        l_item_tmp->tx_hash_fast = *a_tx_hash;
                        l_item_tmp->tx = l_ledger_pvt->mapped ? a_tx : DAP_DUP_SIZE(a_tx, dap_chain_datum_tx_get_size(a_tx));
                        l_item_tmp->tx_owned = !l_ledger_pvt->mapped;
                        if ( !l_item_tmp->tx ) {
                            DAP_DELETE(l_item_tmp);
                            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                            return -1;
                        }
                        l_item_tmp->ts_added = dap_nanotime_now();
                        l_item_tmp->cache_data.ts_created = a_tx->header.ts_created;
                        HASH_ADD_BYHASHVALUE(hh, l_ledger_pvt->threshold_txs, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_tmp);
                        if(s_debug_more)
                            log_it (L_DEBUG, "Tx %s added to threshold", l_tx_hash_str);
                    }
                }
                pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            }
        } else {
            debug_if(s_debug_more, L_WARNING, "dap_ledger_tx_add() tx %s not passed the check: %s ", l_tx_hash_str,
                        dap_ledger_check_error_str(l_ret_check));
        }
        
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, NULL);
        
        return l_ret_check;
    }
    // add info for wallet shared
    if (
        !dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF) &&
        !dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_WALLET_SHARED_TSD_REFILL)
        )
    {
        dap_chain_wallet_shared_hold_tx_add(a_tx, a_ledger->net->pub.name);
    }
    debug_if(s_debug_more, L_DEBUG, "dap_ledger_tx_add() check passed for tx %s", l_tx_hash_str);
    if ( a_datum_index_data != NULL){
        dap_strncpy(a_datum_index_data->token_ticker, l_main_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
        a_datum_index_data->action = l_action;
        a_datum_index_data->uid = l_tag;
    }
    // Mark 'out' items in cache if they were used & delete previous transactions from cache if it need
    // find all bound pairs 'in' and 'out'
    size_t l_outs_used = dap_list_length(l_list_bound_items);

    dap_store_obj_t *l_cache_used_outs = NULL;
    char *l_ledger_cache_group = NULL;
    if (PVT(a_ledger)->cached && !PVT(a_ledger)->snapshot_mode) {
        l_cache_used_outs = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * (l_outs_used + 1));
        if ( !l_cache_used_outs ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            l_ret = -1;
            goto FIN;
        }
        l_ledger_cache_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
    }
    const char *l_cur_token_ticker = NULL;

    // Update balance: deducts
    int l_spent_idx = 0;
    for (dap_list_t *it = l_list_bound_items; it; it = it->next) {
        dap_ledger_tx_bound_t *l_bound_item = it->data;
        dap_chain_tx_item_type_t l_type = l_bound_item->type;
        if (l_type == TX_ITEM_TYPE_IN || l_type == TX_ITEM_TYPE_IN_COND) {
            if (l_bound_item->prev_item->cache_data.n_outs <= l_bound_item->prev_item->cache_data.n_outs_used) {
                log_it(L_ERROR, "[!] Irrelevant prev tx: out items mismatch %d <= %d",
                       l_bound_item->prev_item->cache_data.n_outs, l_bound_item->prev_item->cache_data.n_outs_used);
                l_outs_used--;
                continue;
            }
            l_spent_idx++;
        }

        if ((l_type == TX_ITEM_TYPE_IN_EMS_VIRTUAL || l_type == TX_ITEM_TYPE_IN_REWARD) &&
                !s_ledger_token_supply_check_update(a_ledger, l_bound_item->token_item, l_bound_item->value, false))
            log_it(L_ERROR, "Insufficient supply for token %s", l_bound_item->token_item->ticker);

        switch (l_type) {
        case TX_ITEM_TYPE_IN_EMS:
            // Mark it as used with current tx hash
            l_bound_item->emission_item->tx_used_out = *a_tx_hash;
            s_ledger_emission_cache_update(a_ledger, l_bound_item->emission_item);
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_EMS_VIRTUAL:
            if (l_bound_item->stake_lock_item) { // Legacy stake lock emission
                // Mark it as used with current tx hash
                l_bound_item->stake_lock_item->tx_used_out = *a_tx_hash;
                s_ledger_stake_lock_cache_update(a_ledger, l_bound_item->stake_lock_item);
            }
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_REWARD: {
            dap_ledger_reward_item_t *l_item = DAP_NEW_Z(dap_ledger_reward_item_t);
            if (!l_item) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_ret = -1;
                goto FIN;
            }
            l_item->key = l_bound_item->reward_key;
            l_item->spender_tx = *a_tx_hash;
            pthread_rwlock_wrlock(&l_ledger_pvt->rewards_rwlock);
            HASH_ADD(hh, l_ledger_pvt->rewards, key, sizeof(l_item->key), l_item);
            pthread_rwlock_unlock(&l_ledger_pvt->rewards_rwlock);
        }
        l_outs_used--; // Do not calc this output with tx used items
        continue;

        case TX_ITEM_TYPE_IN: {
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            l_cur_token_ticker = l_bound_item->in.token_ticker;
            char *l_wallet_balance_key = dap_strjoin(" ", dap_chain_addr_to_str_static(&l_bound_item->in.addr_from), l_cur_token_ticker, (char*)NULL);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            if (wallet_balance) {
                debug_if(s_debug_more, L_DEBUG, "SPEND %s from addr: %s",
                    dap_uint256_to_char(l_bound_item->value, NULL), l_wallet_balance_key);
                SUBTRACT_256_256(wallet_balance->balance, l_bound_item->value, &wallet_balance->balance);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                if(s_debug_more)
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", dap_chain_addr_to_str_static(&l_bound_item->in.addr_from), l_cur_token_ticker);
            }
            
            DAP_DELETE(l_wallet_balance_key);
        } break;

        case TX_ITEM_TYPE_IN_COND: { // all balance deducts performed with previous conditional transaction
            // Update service items if any
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_bound_item->cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_added)
                l_verificator->callback_added(a_ledger, a_tx, a_tx_hash, l_bound_item->cond);
        } break;

        default:
            log_it(L_ERROR, "Unknown item type %d in ledger TX bound for IN part", l_type);
            break;
        }

        // add a used output
        dap_ledger_tx_item_t *l_prev_item_out = l_bound_item->prev_item;
        if (!l_prev_item_out)
            continue;

        // cache_data of an already added tx item is read by other threads under ledger_rwlock
        // rdlock, so its mutation needs the wrlock. Keep the section limited to this mutation:
        // the balance/wallet notifications and service callbacks above take other locks
        // (wallet cache, service caches) that are held while calling back into the ledger.
        pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
        l_prev_item_out->cache_data.tx_hash_spent_fast[l_bound_item->prev_out_idx] = *a_tx_hash;
        l_prev_item_out->cache_data.n_outs_used++;
        if (PVT(a_ledger)->cached && !PVT(a_ledger)->snapshot_mode) {
            // mirror it in the cache
            size_t l_cache_size = sizeof(l_prev_item_out->cache_data) + l_prev_item_out->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
            // Heap, not alloca: a datum can be hundreds of KB (SIGSEGV in the
            // loading thread reproduced with a 210 KB datum at chain load).
            dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_Z_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
            l_tx_cache->cache_size = l_cache_size;
            l_tx_cache->datum_size = l_tx_size;
            memcpy(l_tx_cache->data, &l_prev_item_out->cache_data, l_cache_size);
            memcpy(l_tx_cache->data + l_cache_size, l_prev_item_out->tx, l_tx_size);
            char *l_tx_i_hash = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast);
            l_cache_used_outs[l_spent_idx] = (dap_store_obj_t) {
                    .key        = l_tx_i_hash,
                    .value      = (byte_t*)l_tx_cache,
                    .value_len  = l_tx_cache_sz,
                    .group      = l_ledger_cache_group,
            };
            l_cache_used_outs[l_spent_idx].timestamp = dap_nanotime_now();
        }
        // mark previous transactions as used with the extra timestamp
        if (l_prev_item_out->cache_data.n_outs_used == l_prev_item_out->cache_data.n_outs)
            l_prev_item_out->cache_data.ts_spent = a_tx->header.ts_created;
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    }


    //Update balance : raise
    bool l_multichannel = false;
    bool l_cross_network = false;
    uint32_t l_outs_count = 0;
    for (dap_list_t *l_tx_out = l_list_tx_out; l_tx_out; l_tx_out = l_tx_out->next, l_outs_count++) {
        if (!l_tx_out->data) {
            log_it(L_ERROR, "Can't detect tx ticker or matching output, can't append balances cache");
            continue;
        }
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_out->data;
        if (l_type == TX_ITEM_TYPE_OUT_COND) {
            // Update service items if any
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_tx_out->data;
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_added)
                l_verificator->callback_added(a_ledger, a_tx, a_tx_hash, NULL);
            continue;   // balance raise will be with next conditional transaction
        }

        dap_chain_addr_t *l_addr = NULL;
        uint256_t l_value = {};
        switch (l_type) {
        case TX_ITEM_TYPE_OUT: {
            dap_chain_tx_out_t *l_out_item_256 = (dap_chain_tx_out_t *)l_tx_out->data;
            l_addr = &l_out_item_256->addr;
            l_value = l_out_item_256->header.value;
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_out_item = (dap_chain_tx_out_old_t *)l_tx_out->data;
            l_addr = &l_out_item->addr;
            l_value = GET_256_FROM_64(l_out_item->header.value);
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            dap_chain_tx_out_ext_t *l_out_item_ext_256 = (dap_chain_tx_out_ext_t *)l_tx_out->data;
            l_addr = &l_out_item_ext_256->addr;
            l_value = l_out_item_ext_256->header.value;
            l_cur_token_ticker = l_out_item_ext_256->token;
            if (dap_strcmp(l_cur_token_ticker, l_main_token_ticker))
                l_multichannel = true;
        } break;
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_out_item_std = (dap_chain_tx_out_std_t *)l_tx_out->data;
            l_addr = &l_out_item_std->addr;
            l_value = l_out_item_std->value;
            l_cur_token_ticker = l_out_item_std->token;
            if (dap_strcmp(l_cur_token_ticker, l_main_token_ticker))
                l_multichannel = true;
            if (l_out_item_std->ts_unlock > l_ledger_pvt->blockchain_time) {
                dap_ledger_locked_out_t *l_new_locked_out = DAP_NEW_Z(dap_ledger_locked_out_t);
                if (!l_new_locked_out) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    goto FIN;
                }
                l_new_locked_out->addr = *l_addr;
                l_new_locked_out->value = l_value;
                dap_strncpy(l_new_locked_out->ticker, l_cur_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                l_new_locked_out->unlock_time = l_out_item_std->ts_unlock;
                LL_INSERT_INORDER(l_ledger_pvt->locked_outs, l_new_locked_out, s_compare_locked_outs);
                continue;
            }
        } break;
        default:
            log_it(L_ERROR, "Unknown item type %d", l_type);
            break;
        }
        if (!l_addr)
            continue;
        else if (l_addr->net_id.uint64 != a_ledger->net->pub.id.uint64 &&
                 !dap_chain_addr_is_blank(l_addr))
            l_cross_network = true;

        dap_ledger_pvt_balance_update_for_addr(a_ledger, l_addr, l_cur_token_ticker, l_value, false);

    }
    // Process special tx items
    int l_err_num = 0, l_counter = 0;
    byte_t *it; size_t l_size;
    TX_ITEM_ITER_TX(it, l_size, a_tx) {
        switch (*it) {
        case TX_ITEM_TYPE_VOTING:
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx, a_tx_hash, true);
            if (l_err_num)
                log_it(L_MSG, "[!] Voting cb ret %d for item %d in tx %s", l_err_num, l_counter, dap_hash_fast_to_str_static(a_tx_hash));
            break;
        case TX_ITEM_TYPE_VOTE:
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx, a_tx_hash, true);
            if (l_err_num)
                log_it(L_MSG, "[!] Vote cb ret %d for item %d in tx %s", l_err_num, l_counter, dap_hash_fast_to_str_static(a_tx_hash));
            break;
        case TX_ITEM_TYPE_EVENT:
            l_err_num = s_ledger_event_verify_add(a_ledger, a_tx_hash, a_tx, true, false);
            if (l_err_num)
                log_it(L_MSG, "[!] Event cb ret %d for item %d in tx %s", l_err_num, l_counter, dap_hash_fast_to_str_static(a_tx_hash));
            break;
        default:
            break;
        }
    }
    if (!s_check_hal(a_ledger, a_tx_hash))
        assert(!l_err_num);
    (void)l_err_num;

    // add transaction to the cache list
    dap_ledger_tx_item_t *l_tx_item = DAP_NEW_Z_SIZE(dap_ledger_tx_item_t, sizeof(dap_ledger_tx_item_t) + l_outs_count * sizeof(dap_chain_hash_fast_t));
    if ( !l_tx_item ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        l_ret = -1;
        goto FIN;
    }
    l_tx_item->tx_hash_fast = *a_tx_hash;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    l_tx_item->tx = l_ledger_pvt->mapped ? a_tx : DAP_DUP_SIZE(a_tx, l_tx_size);
    l_tx_item->tx_owned = !l_ledger_pvt->mapped;
    l_tx_item->cache_data.n_outs = l_outs_count;
    l_tx_item->cache_data.tag = l_tag;
    l_tx_item->cache_data.action = l_action;
    dap_stpcpy(l_tx_item->cache_data.token_ticker, l_main_token_ticker);

    l_tx_item->cache_data.multichannel = l_multichannel;
    l_tx_item->cache_data.ts_created = a_tx->header.ts_created;   // was never set before: the INORDER comparator below compared all-zero keys
    l_tx_item->ts_added = dap_nanotime_now();
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    // In load/sync mode the chain is historical, plain append; HASH_SORT at
    // load end fixes the order up. In live mode keep the items sorted by
    // ts_created: a live tx is almost always newer than the tail, so the
    // guarded append is O(1) - the previous HASH_ADD_INORDER walked the whole
    // (hundreds of thousands of items) list under this wrlock on every
    // accepted tx.
    if (dap_chain_net_get_load_mode(a_ledger->net) || dap_chain_net_get_state(a_ledger->net) == NET_STATE_SYNC_CHAINS)
        HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
    else {
        dap_ledger_tx_item_t *l_tail_item = HASH_LAST(l_ledger_pvt->ledger_items);
        // The header timestamp is not authenticated relative to acceptance:
        // a tx claiming ts_created = 0 must not be able to force the O(N)
        // INORDER walk on every insert (which would hold this wrlock for the
        // whole scan). Only a timestamp inside a bounded reordering window
        // takes the positional insert; anything older is appended (worst case
        // it appears late in the time-ordered iteration, same as during load).
        const dap_time_t DAP_LEDGER_TS_REORDER_WINDOW = 3600; // 1 hour
        if (!l_tail_item || l_tail_item->cache_data.ts_created <= l_tx_item->cache_data.ts_created)
            HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
        else if (l_tx_item->cache_data.ts_created + DAP_LEDGER_TS_REORDER_WINDOW >= l_tail_item->cache_data.ts_created)
            HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t),
                             l_tx_item, s_sort_ledger_tx_item); // tx_hash_fast: name of key field
        else
            HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    // Callable callback
    dap_list_t *l_notifier;
    DL_FOREACH(PVT(a_ledger)->tx_add_notifiers, l_notifier) {
        dap_ledger_tx_notifier_t *l_notify = (dap_ledger_tx_notifier_t *)l_notifier->data;
        l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx, a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_ADDED,
                           a_datum_index_data ? &a_datum_index_data->atom_hash : NULL);
    }
    if (l_cross_network) {
        dap_list_t *l_notifier;
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notifiers, l_notifier) {
            dap_ledger_bridged_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
        }
    }
    if (PVT(a_ledger)->cached && !PVT(a_ledger)->snapshot_mode && !s_ledger_cache_storage_full()) {
        // Add it to cache (skipped in snapshot mode and while GlobalDB storage is over its limit)
        size_t l_cache_size = sizeof(l_tx_item->cache_data) + l_tx_item->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
        size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
        // Heap, not alloca (see the spent-slot buffer above).
        dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_Z_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
        l_tx_cache->cache_size = l_cache_size;
        l_tx_cache->datum_size = l_tx_size;
        memcpy(l_tx_cache->data, &l_tx_item->cache_data, l_cache_size);
        memcpy(l_tx_cache->data + l_cache_size, a_tx, l_tx_size);
        l_cache_used_outs[0] = (dap_store_obj_t) {
                .key        = l_tx_hash_str,
                .value      = (byte_t*)l_tx_cache,
                .value_len  = l_tx_cache_sz,
                .group      = l_ledger_cache_group,
                .timestamp  = dap_nanotime_now()
        };
        // Apply it with single DB transaction
        // Records are kept unsigned here (signing every cache record on the tx_add hot path
        // would cost more than the cache saves); the GDB worker signs them with the node key
        // before applying, which is what the cluster role check requires.
        int l_sr_rc = dap_global_db_set_raw_signed(l_cache_used_outs, l_outs_used + 1, NULL, NULL);
        if (l_sr_rc)
            debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch (txs set_raw rc %d)", l_sr_rc);
    }
    if (!a_from_threshold && l_ledger_pvt->threshold_enabled)
        s_threshold_txs_proc(a_ledger);
FIN:
    if (!l_ret)
        s_ledger_rpc_cache_notify_tx(a_ledger, a_tx, l_list_bound_items);
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    if (PVT(a_ledger)->cached) {
        if (l_cache_used_outs) {
            // Both key and value of the spent slots are heap allocations
            // (dap_chain_hash_fast_to_str_new / DAP_NEW_Z_SIZE). Slot 0 holds
            // the tx's own record: its value is heap too, but its key points at
            // the stack array l_tx_hash_str and must not be freed.
            for (size_t i = 1; i <= l_outs_used; i++) {
                DAP_DEL_Z(l_cache_used_outs[i].key);
                DAP_DEL_Z(l_cache_used_outs[i].value);
            }
            DAP_DEL_Z(l_cache_used_outs[0].value);
        }
        DAP_DEL_Z(l_cache_used_outs);
        DAP_DEL_Z(l_ledger_cache_group);
    }
    return l_ret;
}

// Whether the wallet section of a snapshot describes (about) the whole unspent
// set the ledger holds. Only the ledger's own aggregates are consulted: no chain
// is walked here, a full scan is the job of the scan path.
static bool s_snapshot_wallet_section_plausible(dap_ledger_t *a_ledger, uint64_t a_section_records)
{
    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    size_t l_ledger_unspent = 0;
    pthread_rwlock_rdlock(&l_pvt->ledger_rwlock);
    dap_ledger_tx_item_t *l_it = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_pvt->ledger_items, l_it, l_tmp) {
        for (size_t i = 0; i < l_it->cache_data.n_outs; ++i)
            if (dap_hash_fast_is_blank(&l_it->cache_data.tx_hash_spent_fast[i]))
                ++l_ledger_unspent;
    }
    pthread_rwlock_unlock(&l_pvt->ledger_rwlock);
    // Allow for outputs above the snapshot anchor and for in-flight spends.
    return !l_ledger_unspent || a_section_records + a_section_records / 2 >= l_ledger_unspent;
}

static void s_ledger_tx_service_notify_cond_added(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                                  dap_hash_fast_t *a_tx_hash,
                                                  dap_chain_tx_out_cond_subtype_t a_only_subtype);

static int s_ledger_link_block_cmp(const void *a_a, const void *a_b)
{
    const struct { dap_hash_fast_t tx_hash, atom_hash; uint64_t block_num; uint32_t idx; } *a = a_a, *b = a_b;
    if (a->block_num != b->block_num)
        return a->block_num < b->block_num ? -1 : 1;
    if (a->idx != b->idx)
        return a->idx < b->idx ? -1 : 1;
    return memcmp(&a->tx_hash, &b->tx_hash, sizeof(a->tx_hash));
}

void dap_ledger_load_end(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    // Idempotent: besides the net load path this is also called from the sync's
    // deferred heavy-ops step. The second run must not repeat the destructive part:
    // by then the snapshot-scan skip is consumed, so the phantom clean below would
    // drop every datum-less restored item (472k of them on Backbone, 2026-10-21).
    if (l_ledger_pvt->load_end_done)
        return;
    l_ledger_pvt->load_end_done = true;
    // Deferred snapshot sections: the chain data they may consult is attached now.
    s_pending_sections_apply(a_ledger);
    // No-scan startup: the chain-state datum index is empty because the cell walk
    // did not happen. Rebuild its TX part from the snapshot atom links (the block
    // cache was restored from the index before this call). Collected under the
    // ledger lock, inserted without it: live block processing takes the blocks
    // lock and then the ledger lock, never the other way around.
    if (l_ledger_pvt->snapshot_full) {
        dap_chain_t *l_chain = NULL;
        for (dap_chain_t *l_c = a_ledger->net ? a_ledger->net->pub.chains : NULL; l_c; l_c = l_c->next) {
            const char *l_cs_type = dap_chain_get_cs_type(l_c);
            if (l_cs_type && !dap_strcmp(l_cs_type, "esbocs")) {
                l_chain = l_c;
                break;
            }
        }
        if (l_chain && dap_chain_cs_blocks_index_was_restored(l_chain)) {
            typedef struct { dap_hash_fast_t tx_hash, atom_hash; uint64_t block_num; uint32_t idx; } s_link_t;
            pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
            size_t l_cap = HASH_COUNT(l_ledger_pvt->ledger_items), l_n = 0;
            s_link_t *l_links = l_cap ? DAP_NEW_Z_COUNT(s_link_t, l_cap) : NULL;
            if (l_links) {
                dap_ledger_tx_item_t *l_it = NULL, *l_tmp = NULL;
                HASH_ITER(hh, l_ledger_pvt->ledger_items, l_it, l_tmp) {
                    if (!l_it->atom_link_valid || l_n == l_cap)
                        continue;
                    l_links[l_n].tx_hash = l_it->tx_hash_fast;
                    l_links[l_n].atom_hash = l_it->atom_hash;
                    l_links[l_n].idx = l_it->datum_index;
                    l_links[l_n].block_num = dap_chain_cs_blocks_number_by_hash(l_chain, &l_it->atom_hash);
                    ++l_n;
                }
            }
            pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
            // The non-TX links (emissions) collected by the datum_links section are
            // merged in here: one array, one block-ordered pass, so the index has TX
            // and non-TX entries interleaved exactly as the chain produced them.
            size_t l_n_all = l_n + s_pending_datum_links_n;
            size_t l_n_links = s_pending_datum_links_n;
            // Both runs go into one array sorted by block position: the index must
            // read in block order for every consumer (wallet bulk pass, tx/event lists).
            if (l_links)
                qsort(l_links, l_n, sizeof(*l_links), s_ledger_link_block_cmp);
            s_link_t *l_all = l_n_all ? DAP_NEW_Z_COUNT(s_link_t, l_n_all) : NULL;
            if (l_all) {
                for (size_t i = 0; i < l_n; ++i)
                    l_all[i] = l_links[i];
                for (size_t i = 0; i < s_pending_datum_links_n; ++i) {
                    l_all[l_n + i].tx_hash = s_pending_datum_links[i].datum_hash;
                    l_all[l_n + i].atom_hash = s_pending_datum_links[i].atom_hash;
                    l_all[l_n + i].idx = s_pending_datum_links[i].datum_idx;
                }
            }
            DAP_DEL_Z(s_pending_datum_links);
            s_pending_datum_links_n = 0;
            s_pending_datum_links_cap = 0;
            // Block order is the service-replay order: the delegated-stake registry
            // and every other conditional-service registry are rebuilt from the
            // same pass below, and applying their updates out of block order
            // leaves them in a wrong final state.
            if (l_all)
                qsort(l_all, l_n_all, sizeof(*l_all), s_ledger_link_block_cmp);
            for (size_t i = 0; l_all && i < l_n_all; ++i)
                dap_chain_cs_blocks_index_restored_datum(l_chain, &l_all[i].tx_hash,
                                                         &l_all[i].atom_hash, l_all[i].idx);
            log_it(L_NOTICE, "Ledger snapshot: datum index rebuilt from %zu tx atom links "
                   "and %zu non-TX link(s), in block order", l_n, l_n_links);
            (void)l_all;
            // Index bookkeeping only - nothing is re-applied to the ledger. Items
            // restored from a snapshot must be locatable by hash. Used to be
            // replayed instead, which was wrong: a restored ledger IS the state.
            size_t l_filled = 0;
            pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
            dap_ledger_tx_item_t *l_fit = NULL, *l_ftmp = NULL;
            HASH_ITER(hh, l_ledger_pvt->ledger_items, l_fit, l_ftmp) {
                if (l_fit->tx || l_fit->atom_link_valid)
                    continue;
                dap_chain_hash_fast_t l_atom_hash = {};
                uint32_t l_idx = 0;
                if (!dap_chain_cs_blocks_datum_location(l_chain, &l_fit->tx_hash_fast,
                                                        &l_atom_hash, &l_idx)) {
                    l_fit->atom_hash = l_atom_hash;
                    l_fit->datum_index = l_idx;
                    l_fit->atom_link_valid = 1;
                    ++l_filled;
                }
            }
            pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
            if (l_filled)
                log_it(L_NOTICE, "Ledger snapshot: datum links resolved for %zu restored "
                       "transaction(s) (index bookkeeping)", l_filled);
            // The chain TX counter (all TX datums, not only ledger items) is
            // restored from the chain-state header by the index restore.
            DAP_DEL_Z(l_links);
        }
    }
    // The cell-scan window is over: disarm the snapshot chain-scan skip. It
    // must not survive into the network phase - the zone accepts blocks
    // without verification, and if the scan ended below the snapshot anchor
    // (local files shorter than the snapshot) that would cover blocks arriving
    // from peers.
    //
    // A still-armed anchor means exactly that case: the scan ended BELOW the
    // snapshot position, i.e. the local cell files are shorter than the
    // snapshot - blocks accepted from the network but not yet written to the
    // file (the node accepted them, the write happens outside load mode).
    // Restored items covered by those blocks legitimately carry no datum yet,
    // and the phantom clean must not run: it used to drop the whole range
    // (each following block then failed with "No previous transaction found"
    // and the tip froze - seen live on cf-mm-0). The datums arrive with the
    // network catch-up.
    bool l_scan_below_anchor = l_ledger_pvt->snapshot_skip_active;
    dap_ledger_snapshot_skip_consume(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    HASH_SORT(l_ledger_pvt->ledger_items, s_sort_ledger_tx_item);
    // Security: an item whose datum was never attached did not appear in ANY
    // chain of this network - it can only come from a restored cache/snapshot
    // taken on a different (forked or longer) branch. Such a phantom carries
    // spendable-looking outputs the network would reject; drop it here, after
    // the full scan, while real transactions all carry their datum. Balances
    // are aggregate and stay as restored - the log tells the operator if a
    // 'ledger reload' is due.
    dap_ledger_tx_item_t *l_item = NULL, *l_tmp = NULL;
    size_t l_phantoms = 0;
    if (l_scan_below_anchor) {
        log_it(L_WARNING, "Ledger: the chain scan ended below the ledger snapshot position - "
               "keeping cache-restored items without datums (their blocks are not in the local "
               "cell files yet); the network catch-up attaches them");
    } else {
        HASH_ITER (hh, l_ledger_pvt->ledger_items, l_item, l_tmp) {
            if (!l_item->tx) {
                HASH_DEL(l_ledger_pvt->ledger_items, l_item);
                DAP_DELETE(l_item);
                ++l_phantoms;
            }
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    // Flush the chain-state index tails now that the scan window is over: the
    // records are stdio-buffered, and the ledger snapshot is about to anchor at
    // the tip. Without this the last few indexed blocks stayed in the buffer and
    // the next start saw an index ending BELOW the snapshot anchor (refused with
    // -12 and a full rescan, repeating after every scan).
    for (dap_chain_t *l_c = a_ledger->net ? a_ledger->net->pub.chains : NULL; l_c; l_c = l_c->next)
        dap_chain_cs_blocks_state_flush(l_c);
    dap_chain_net_tx_replay_summary();
    if (l_phantoms)
        log_it(L_CRITICAL, "Ledger: dropped %zu cache-restored transaction(s) not found in any "
               "chain of this network (snapshot from a different branch?); consider "
               "'net -net %s ledger reload' to recompute the balances",
               l_phantoms, a_ledger->net->pub.name);
}

/**
 * @brief Remove transaction from the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @return return 1 OK, -1 error
 */
int dap_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash)
{
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;
    dap_chain_net_srv_uid_t l_tag =  { .uint64 = 0 };
    dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    char l_main_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX] = { '\0' };

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    // Get boundary items list into l_list_bound_items
    // Get tx outs list into l_list_tx_out
    int l_ret_check;
    if( (l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_tx_hash, false,
                                                       &l_list_bound_items, &l_list_tx_out,
                                                       l_main_token_ticker, &l_tag, &l_action, true, true))) {
        debug_if(s_debug_more, L_WARNING, "dap_ledger_tx_remove() tx %s not passed the check: %s ", l_tx_hash_str,
                    dap_ledger_check_error_str(l_ret_check));
        return l_ret_check;
    }

    dap_ledger_tx_item_t *l_ledger_item = NULL;
    pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
    HASH_FIND(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_ledger_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    if (l_ledger_item && l_ledger_item->cache_data.n_outs_used != 0) {     // transaction already present in the cache list
        return DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED;
    }
    
    // find all bound pairs 'in' and 'out'
    size_t l_outs_used = dap_list_length(l_list_bound_items);

    dap_store_obj_t *l_cache_used_outs = NULL;
    char *l_ledger_cache_group = NULL;
    if (PVT(a_ledger)->cached) {
        l_cache_used_outs = DAP_NEW_Z_COUNT(dap_store_obj_t, l_outs_used);
        if ( !l_cache_used_outs ) {
            log_it(L_CRITICAL, "Memory allocation error");
            l_ret = -1;
            goto FIN;
        }
        l_ledger_cache_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
    }
    
    const char *l_cur_token_ticker = NULL;

    // Update balance : raise all bound items to balances
    int l_spent_idx = 0;
    for (dap_list_t *it = l_list_bound_items; it; it = it->next) {
        dap_ledger_tx_bound_t *l_bound_item = it->data;
        dap_chain_tx_item_type_t l_type = l_bound_item->type;
        if ((l_type == TX_ITEM_TYPE_IN_EMS_VIRTUAL || l_type == TX_ITEM_TYPE_IN_REWARD) &&
                !s_ledger_token_supply_check_update(a_ledger, l_bound_item->token_item, l_bound_item->value, true))
            log_it(L_ERROR, "Insufficient supply for token %s", l_bound_item->token_item->ticker);

        switch (l_type) {
        case TX_ITEM_TYPE_IN_EMS:
            // Mark it as unused
            memset(&(l_bound_item->emission_item->tx_used_out), 0, sizeof(dap_hash_fast_t));
            s_ledger_emission_cache_update(a_ledger, l_bound_item->emission_item);
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_EMS_VIRTUAL:
            if (l_bound_item->stake_lock_item) { // Legacy stake lock emission
                // Mark it as used with current tx hash
                memset(&(l_bound_item->stake_lock_item->tx_used_out), 0, sizeof(dap_hash_fast_t));
                s_ledger_stake_lock_cache_update(a_ledger, l_bound_item->stake_lock_item);
            }
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_REWARD: {
            dap_ledger_reward_item_t *l_item = NULL;
            pthread_rwlock_wrlock(&l_ledger_pvt->rewards_rwlock);
            HASH_FIND(hh, l_ledger_pvt->rewards, &l_bound_item->reward_key, sizeof(l_bound_item->reward_key), l_item);
            if(l_item){
                HASH_DEL(l_ledger_pvt->rewards, l_item);
                DAP_DEL_Z(l_item);
            } 
            pthread_rwlock_unlock(&l_ledger_pvt->rewards_rwlock);
        }
        l_outs_used--; // Do not calc this output with tx used items
        continue;

        case TX_ITEM_TYPE_IN: {
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            l_cur_token_ticker = l_bound_item->in.token_ticker;
            char *l_wallet_balance_key = dap_strjoin(" ", dap_chain_addr_to_str_static(&l_bound_item->in.addr_from), l_cur_token_ticker, (char*)NULL);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            if (wallet_balance) {
                if(s_debug_more) {
                    char *l_balance = dap_chain_balance_print(l_bound_item->value);
                    log_it(L_DEBUG,"REFUND %s from addr: %s because tx was removed.", l_balance, l_wallet_balance_key);
                    DAP_DELETE(l_balance);
                }
                SUM_256_256(wallet_balance->balance, l_bound_item->value, &wallet_balance->balance);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                if(s_debug_more)
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", dap_chain_addr_to_str_static(&l_bound_item->in.addr_from), l_cur_token_ticker);
            }
            DAP_DELETE(l_wallet_balance_key);
        } break;

        case TX_ITEM_TYPE_IN_COND: { // all balance deducts performed with previous conditional transaction
            // Update service items if any
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_bound_item->cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_deleted)
                l_verificator->callback_deleted(a_ledger, a_tx, l_bound_item->cond);
        } break;

        default:
            log_it(L_ERROR, "Unknown item type %d in ledger TX bound for IN part", l_type);
            break;
        }

        // add a used output 
        dap_ledger_tx_item_t *l_prev_item_out = l_bound_item->prev_item;
        pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
        l_prev_item_out->cache_data.tx_hash_spent_fast[l_bound_item->prev_out_idx] = (dap_hash_fast_t){ };
        l_prev_item_out->cache_data.n_outs_used--;
        if (PVT(a_ledger)->cached) {
            // mirror it in the cache
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_cache_size = sizeof(l_prev_item_out->cache_data) + l_prev_item_out->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
            size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
            dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_Z_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
            l_tx_cache->cache_size = l_cache_size;
            l_tx_cache->datum_size = l_tx_size;
            memcpy(l_tx_cache->data, &l_prev_item_out->cache_data, l_cache_size);
            memcpy(l_tx_cache->data + l_cache_size, l_prev_item_out->tx, l_tx_size);
            l_cache_used_outs[l_spent_idx] = (dap_store_obj_t) {
                    .key        = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast),
                    .value      = (byte_t*)l_tx_cache,
                    .value_len  = l_tx_cache_sz,
                    .group      = l_ledger_cache_group,
                    .timestamp  = 0
            };
        }
        // mark previous transactions as used with the extra timestamp
        if(l_prev_item_out->cache_data.n_outs_used != l_prev_item_out->cache_data.n_outs)
            l_prev_item_out->cache_data.ts_spent = 0;
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);

        if (l_type == TX_ITEM_TYPE_IN || l_type == TX_ITEM_TYPE_IN_COND) {
            l_spent_idx++;
        }
    }

    // Update balance: deducts all outs from balances
    bool l_cross_network = false;
    for (dap_list_t *l_tx_out = l_list_tx_out; l_tx_out; l_tx_out = dap_list_next(l_tx_out)) {
        if (!l_tx_out->data) {
            debug_if(s_debug_more, L_WARNING, "Can't detect tx ticker or matching output, can't append balances cache");
            continue;
        }
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_out->data;
        if (l_type == TX_ITEM_TYPE_OUT_COND) {
            // Update service items if any
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_tx_out->data;
            dap_ledger_verificator_t *l_verificator = NULL;
            int l_tmp = l_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_deleted)
                l_verificator->callback_deleted(a_ledger, a_tx, NULL);
            continue;   // balance raise will be with next conditional transaction
        }

        dap_chain_addr_t *l_addr = NULL;
        uint256_t l_value = {};
        switch (l_type) {
        case TX_ITEM_TYPE_OUT: {
            dap_chain_tx_out_t *l_out_item_256 = (dap_chain_tx_out_t *)l_tx_out->data;
            l_addr = &l_out_item_256->addr;
            l_value = l_out_item_256->header.value;
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_out_item = (dap_chain_tx_out_old_t *)l_tx_out->data;
            l_addr = &l_out_item->addr;
            l_value = GET_256_FROM_64(l_out_item->header.value);
            l_cur_token_ticker = l_main_token_ticker;
        } break;
        case TX_ITEM_TYPE_OUT_EXT: {
            dap_chain_tx_out_ext_t *l_out_item_ext_256 = (dap_chain_tx_out_ext_t *)l_tx_out->data;
            l_addr = &l_out_item_ext_256->addr;
            l_value = l_out_item_ext_256->header.value;
            l_cur_token_ticker = l_out_item_ext_256->token;
        } break;
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_out_item_std = (dap_chain_tx_out_std_t *)l_tx_out->data;
            l_addr = l_out_item_std->ts_unlock < PVT(a_ledger)->blockchain_time ? &l_out_item_std->addr : NULL;
            l_value = l_out_item_std->value;
            l_cur_token_ticker = l_out_item_std->token;
        } break;
        default:
            log_it(L_DEBUG, "Unknown item type %d", l_type);
            break;
        }
        if (!l_addr)
            continue;
        else if (l_addr->net_id.uint64 != a_ledger->net->pub.id.uint64 &&
                 !dap_chain_addr_is_blank(l_addr))
            l_cross_network = true;

        dap_ledger_pvt_balance_update_for_addr(a_ledger, l_addr, l_cur_token_ticker, l_value, true);
    }

    // Handle special tx items that need to be processed when tx is removed
    byte_t *it; size_t l_size;
    TX_ITEM_ITER_TX(it, l_size, a_tx) {
        switch (*it) {
        case TX_ITEM_TYPE_VOTING:
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx);
            break;
        case TX_ITEM_TYPE_VOTE:
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx);
            break;
        case TX_ITEM_TYPE_EVENT:
            s_ledger_event_remove(a_ledger, a_tx_hash);
            break;
        default:
            break;
        }
    }

    // remove transaction from ledger 
    dap_ledger_tx_item_t *l_tx_item = NULL;
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    if (l_tx_item)
        HASH_DEL(l_ledger_pvt->ledger_items, l_tx_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);

    // Callable callback
    dap_list_t *l_notifier;
    if (l_tx_item) {
        DL_FOREACH(PVT(a_ledger)->tx_add_notifiers, l_notifier) {
            dap_ledger_tx_notifier_t *l_notify = (dap_ledger_tx_notifier_t*)l_notifier->data;
            l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx, a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_DELETED, NULL);
        }
    }
    if (l_tx_item && l_tx_item->tx_owned)
        DAP_DELETE(l_tx_item->tx);
    DAP_DELETE(l_tx_item);
    if (l_cross_network) {
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notifiers, l_notifier) {
            dap_ledger_bridged_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
        }
    }

    if (PVT(a_ledger)->cached && !PVT(a_ledger)->snapshot_mode && !s_ledger_cache_storage_full()) {
        // Add it to cache (skipped in snapshot mode and while GlobalDB storage is over its limit)
        dap_global_db_del_sync(l_ledger_cache_group, l_tx_hash_str);
        // Apply it with single DB transaction
        if (dap_global_db_set_raw_signed(l_cache_used_outs, l_outs_used, NULL, NULL))
            debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch");
    }
FIN:
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    if (PVT(a_ledger)->cached) {
        if (l_cache_used_outs) {
            // The buffer holds exactly l_outs_used slots and every one of them
            // was heap-filled here (keys via dap_chain_hash_fast_to_str_new,
            // values via DAP_NEW_Z_SIZE) - clean the range [0, l_outs_used).
            // The old loop ran 1..l_outs_used inclusive: it leaked slot 0 and
            // freed garbage past the end of the buffer - the SIGSEGV inside
            // __libc_free() in dap_ledger_tx_remove() seen on rollback cores.
            for (size_t i = 0; i < l_outs_used; i++) {
                DAP_DEL_Z(l_cache_used_outs[i].key);
                DAP_DEL_Z(l_cache_used_outs[i].value);
            }
        }
        DAP_DEL_Z(l_cache_used_outs);
        DAP_DEL_Z(l_ledger_cache_group);
    }
    return l_ret;
}

// Voting state is chain-wide: polls are created by VOTING items and votes are counted by
// VOTE items. A transaction whose UTXO inputs are already spent in the restored snapshot
// cannot be re-applied through dap_ledger_tx_add(), so its voting items would never be
// replayed and the votes of later blocks would reference polls that do not exist. Replay
// the voting part for such transactions as well.
static void s_ledger_tx_voting_notify(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash)
{
    byte_t *l_tx_item = NULL;
    size_t l_tx_item_size = 0;
    TX_ITEM_ITER_TX(l_tx_item, l_tx_item_size, a_tx) {
        if (*l_tx_item == TX_ITEM_TYPE_VOTING || *l_tx_item == TX_ITEM_TYPE_VOTE) {
            if (s_voting_callbacks.voting_callback)
                s_voting_callbacks.voting_callback(a_ledger, (dap_chain_tx_item_type_t)*l_tx_item,
                                                   a_tx, a_tx_hash, true);
        }
    }
}

// A snapshot-restored item completed by the chain scan goes through neither
// dap_ledger_tx_add() nor its service notifications: the early return in dap_ledger_tx_load()
// is what makes a restart cheap, but the OUT_COND/bound callbacks of the add path are exactly
// how the service registries (the stake delegate registry above all - esbocs checks it for
// every block's signs) learn about the transaction. Replay those notifications once the item
// gets its datum back, otherwise every restart through the snapshot silently drops the
// affected delegations and the node rejects the next block signed by those validators.
// The conditional-service (verificator) part of the add-path notifications. When
// a_only_subtype is non-zero, only that service's callback is invoked - the ordered
// replay pass uses it to touch exactly the registry it is rebuilding.
static void s_ledger_tx_service_notify_cond_added(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                                  dap_hash_fast_t *a_tx_hash,
                                                  dap_chain_tx_out_cond_subtype_t a_only_subtype)
{
    int l_items_count = 0;
    // Same notification as the bound-items loop of dap_ledger_tx_add(): for every IN_COND
    // item the verifying service gets callback_added() with the conditional output of the
    // previous transaction that the item consumes.
    dap_list_t *l_list_in_cond = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN_COND, &l_items_count);
    for (dap_list_t *l_it = l_list_in_cond; l_it; l_it = l_it->next) {
        dap_chain_tx_out_cond_t *l_cond = dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(
                a_ledger, (dap_chain_tx_in_cond_t *)l_it->data);
        if (!l_cond)
            continue;
        int l_subtype = l_cond->header.subtype;
        if (a_only_subtype && l_subtype != (int)a_only_subtype)
            continue;
        dap_ledger_verificator_t *l_verificator = NULL;
        pthread_rwlock_rdlock(&s_verificators_rwlock);
        HASH_FIND_INT(s_verificators, &l_subtype, l_verificator);
        pthread_rwlock_unlock(&s_verificators_rwlock);
        if (l_verificator && l_verificator->callback_added)
            l_verificator->callback_added(a_ledger, a_tx, a_tx_hash, l_cond);
    }
    if (l_list_in_cond)
        dap_list_free(l_list_in_cond);
    // And the transaction's own OUT_COND items, same as the outs loop of dap_ledger_tx_add().
    l_items_count = 0;
    dap_list_t *l_list_out_cond = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_COND, &l_items_count);
    for (dap_list_t *l_it = l_list_out_cond; l_it; l_it = l_it->next) {
        dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_it->data;
        int l_subtype = l_cond->header.subtype;
        if (a_only_subtype && l_subtype != (int)a_only_subtype)
            continue;
        dap_ledger_verificator_t *l_verificator = NULL;
        pthread_rwlock_rdlock(&s_verificators_rwlock);
        HASH_FIND_INT(s_verificators, &l_subtype, l_verificator);
        pthread_rwlock_unlock(&s_verificators_rwlock);
        if (l_verificator && l_verificator->callback_added)
            l_verificator->callback_added(a_ledger, a_tx, a_tx_hash, NULL);
    }
    if (l_list_out_cond)
        dap_list_free(l_list_out_cond);
}

static void s_ledger_tx_service_notify_added(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash)
{
    s_ledger_tx_service_notify_cond_added(a_ledger, a_tx, a_tx_hash, 0);
    int l_items_count = 0;
    // And the "special tx items" pass of dap_ledger_tx_add(), which a restored tx never
    // reaches either: voting/event services apply their item state there, and the rewards
    // map (checked by dap_ledger_is_used_reward()) is filled from the IN_REWARD items -
    // without it a reward already spent in the restored history would pass the "already
    // used" check and could be spent a second time.
    s_ledger_tx_voting_notify(a_ledger, a_tx, a_tx_hash);
    byte_t *l_tx_item = NULL;
    size_t l_tx_item_size = 0;
    TX_ITEM_ITER_TX(l_tx_item, l_tx_item_size, a_tx) {
        switch (*l_tx_item) {
        case TX_ITEM_TYPE_EVENT:
            s_ledger_event_verify_add(a_ledger, a_tx_hash, a_tx, true, false);
            break;
        case TX_ITEM_TYPE_IN_REWARD: {
            dap_chain_tx_in_reward_t *l_tx_in_reward = (dap_chain_tx_in_reward_t *)l_tx_item;
            dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL,
                                                                                              TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_tx_first_sign = l_tx_sig ? dap_chain_datum_tx_item_sign_get_sig(l_tx_sig) : NULL;
            if (!l_tx_first_sign)
                break;
            dap_ledger_reward_item_t *l_reward_item = DAP_NEW_Z(dap_ledger_reward_item_t);
            if (!l_reward_item) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                break;
            }
            dap_sign_get_pkey_hash(l_tx_first_sign, &l_reward_item->key.sign_pkey_hash);
            l_reward_item->key.block_hash = l_tx_in_reward->block_hash;
            l_reward_item->spender_tx = *a_tx_hash;
            pthread_rwlock_wrlock(&PVT(a_ledger)->rewards_rwlock);
            // The same reward may be recorded by another transaction of the restored
            // history already; uthash must not get a second entry for one key.
            dap_ledger_reward_item_t *l_dup = NULL;
            HASH_FIND(hh, PVT(a_ledger)->rewards, &l_reward_item->key, sizeof(l_reward_item->key), l_dup);
            if (l_dup) {
                DAP_DELETE(l_reward_item);
            } else {
                HASH_ADD(hh, PVT(a_ledger)->rewards, key, sizeof(l_reward_item->key), l_reward_item);
            }
            pthread_rwlock_unlock(&PVT(a_ledger)->rewards_rwlock);
        } break;
        default:
            break;
        }
    }
}

int dap_ledger_tx_load(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash, dap_ledger_datum_iter_data_t *a_datum_index_data)
{
    // A restored item may be waiting for its datum in any mode: not only the chain scan of a
    // restart completes it, the network catch-up does too when the block was not in the local
    // cell files at snapshot time. Complete it exactly once (fill the datum + replay the
    // add-path service notifications) and never re-apply the balances - they are already in
    // the restored ledger. Otherwise the item stays a phantom forever, blocks snapshot saves
    // and services that need the transaction (voting polls) break.
    dap_ledger_tx_item_t *l_tx_item = NULL;
    bool l_restored_completed = false;
    unsigned l_hash_value;
    HASH_VALUE(a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value);
    pthread_rwlock_wrlock(&PVT(a_ledger)->ledger_rwlock);
    HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_item);
    if (l_tx_item && !l_tx_item->tx) {
        // Snapshot-restored item: the snapshot deliberately stores no
        // transaction datums, the chain scan re-fills them as it walks the
        // blocks, so a later spend of this transaction's outputs sees the
        // full item. For a mapped ledger the datum pointer goes straight
        // into the block file's mmap (same as the regular add path; every
        // delete site frees it only when !mapped) - no per-transaction
        // heap copies for the whole restored history.
        l_tx_item->tx = PVT(a_ledger)->mapped
                ? a_tx
                : DAP_DUP_SIZE(a_tx, dap_chain_datum_tx_get_size(a_tx));
        l_tx_item->tx_owned = !PVT(a_ledger)->mapped;
        l_restored_completed = true;
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    if (l_tx_item) {
        // The cache-invalidation replay belongs to the GlobalDB ledger-cache flow: there a
        // restored tx is never re-applied, and the stake service compensates the missing
        // events by invalidating the keys of the recorded updates on load. In snapshot mode
        // the service events themselves are replayed instead (see
        // s_ledger_tx_service_notify_added() below), so the invalidation replay would strip
        // exactly the entries the snapshot is supposed to restore: a delegation update would
        // invalidate the key and then find no entry to update, leaving the validator out of
        // the registry after every restart.
        if (dap_chain_net_get_load_mode(a_ledger->net)
                && PVT(a_ledger)->cache_tx_check_callback && !PVT(a_ledger)->snapshot_mode)
            PVT(a_ledger)->cache_tx_check_callback(a_ledger, a_tx_hash);
        // The restored item holds its datum again: replay the service notifications the
        // regular add path would have made (see s_ledger_tx_service_notify_added above).
        // Outside ledger_rwlock on purpose: the callbacks take the service locks and may
        // re-enter the ledger through its read paths.
        //
        // A COMPLETE snapshot ([ledger] snapshot_full_apply, ledger_state section
        // restored) already carries that service state - polls/votes, events,
        // rewards, conditional-service records - so replaying the covered
        // transactions would apply it twice (a restored vote is not idempotent by
        // itself). Only the blocks above the snapshot anchor are new to the
        // ledger and take the regular dap_ledger_tx_add() path.
        if (l_restored_completed
                && !(PVT(a_ledger)->snapshot_full && PVT(a_ledger)->snapshot_full_apply))
            s_ledger_tx_service_notify_added(a_ledger, a_tx, a_tx_hash);
        return DAP_LEDGER_CHECK_ALREADY_CACHED;
    }
    return dap_ledger_tx_add(a_ledger, a_tx, a_tx_hash, false, a_datum_index_data);
}

/**
 * Delete all transactions from the cache
 */
void dap_ledger_purge(dap_ledger_t *a_ledger, bool a_preserve_db)
{
    // The stats cache is keyed by ledger pointer: after a purge/reload a new
    // ledger can reuse the same address, so drop the cached counts with it.
    pthread_mutex_lock(&s_stats_cache_lock);
    memset(s_stats_cache, 0, sizeof(s_stats_cache));
    pthread_mutex_unlock(&s_stats_cache_lock);
    dap_return_if_fail(a_ledger);
    // A purge invalidates the ledger state the snapshot stands for: disarm the
    // chain-scan anchor and drop the file, or a reload/restart within the save
    // interval would resurrect the state the operator just threw away.
    dap_ledger_snapshot_skip_consume(a_ledger);
    {
        char *l_snapshot_path = s_snapshot_file_path(a_ledger);
        if (l_snapshot_path) {
            remove(l_snapshot_path);
            DAP_DELETE(l_snapshot_path);
        }
    }
    // Sections whose load was deferred from that snapshot must not be applied
    // later to a ledger that no longer represents the snapshot state.
    s_pending_sections_clear(a_ledger->net->pub.id.uint64);
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->tokens_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->threshold_txs_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->stake_lock_rwlock);

    /* Delete regular transactions */
    dap_ledger_tx_item_t *l_item_current, *l_item_tmp;
    char *l_gdb_group;
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_pvt->ledger_items, l_item_current);
        if (l_item_current->tx_owned)
            DAP_DELETE(l_item_current->tx);
        DAP_DEL_Z(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    if (!a_preserve_db) {
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_SPENT_TXS_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete balances */
    dap_ledger_wallet_balance_t *l_balance_current, *l_balance_tmp;
    HASH_ITER(hh, l_ledger_pvt->balance_accounts, l_balance_current, l_balance_tmp) {
        HASH_DEL(l_ledger_pvt->balance_accounts, l_balance_current);
        DAP_DELETE(l_balance_current->key);
        DAP_DELETE(l_balance_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_BALANCES_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete tokens and their emissions */
    dap_ledger_token_item_t *l_token_current, *l_token_tmp;
    dap_ledger_token_emission_item_t *l_emission_current, *l_emission_tmp;
    HASH_ITER(hh, l_ledger_pvt->tokens, l_token_current, l_token_tmp) {
        HASH_DEL(l_ledger_pvt->tokens, l_token_current);
        pthread_rwlock_wrlock(&l_token_current->token_emissions_rwlock);
        HASH_ITER(hh, l_token_current->token_emissions, l_emission_current, l_emission_tmp) {
            HASH_DEL(l_token_current->token_emissions, l_emission_current);
            DAP_DELETE(l_emission_current->datum_token_emission);
            DAP_DEL_Z(l_emission_current);
        }
        pthread_rwlock_unlock(&l_token_current->token_emissions_rwlock);
        DAP_DELETE(l_token_current->datum_token);
        DAP_DELETE(l_token_current->auth_pkeys);
        DAP_DELETE(l_token_current->auth_pkey_hashes);
        DAP_DEL_Z(l_token_current->tx_recv_allow);
        DAP_DEL_Z(l_token_current->tx_recv_block);
        DAP_DEL_Z(l_token_current->tx_send_allow);
        DAP_DEL_Z(l_token_current->tx_send_block);
        pthread_rwlock_destroy(&l_token_current->token_emissions_rwlock);
        // Clear UTXO blocklist and destroy rwlock
        // Note: s_ledger_utxo_block_clear requires token_update_hash, but during purge we don't have it
        // Instead, we rely on the fact that purge completely removes all ledger data
        // UTXO blocklist will be cleaned up with token item deletion
        pthread_rwlock_destroy(&l_token_current->utxo_blocklist_rwlock);
        DAP_DELETE(l_token_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TOKENS_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_EMISSIONS_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete stake-lock items */
    dap_ledger_stake_lock_item_t *l_stake_item_current, *l_stake_item_tmp;
    HASH_ITER(hh, l_ledger_pvt->emissions_for_stake_lock, l_stake_item_current, l_stake_item_tmp) {
        HASH_DEL(l_ledger_pvt->emissions_for_stake_lock, l_stake_item_current);
        DAP_DELETE(l_stake_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_STAKE_LOCK_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete threshold transactions */
    HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_pvt->threshold_txs, l_item_current);
        if (l_item_current->tx_owned)
            DAP_DELETE(l_item_current->tx);
        DAP_DEL_Z(l_item_current);
    }

    l_ledger_pvt->ledger_items         = NULL;
    l_ledger_pvt->balance_accounts     = NULL;
    l_ledger_pvt->tokens               = NULL;
    l_ledger_pvt->threshold_txs        = NULL;

    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);

    // Service-side state that the snapshot's ledger_state section restores:
    // a purge/reload must drop it as well, or the reloaded ledger keeps events,
    // reward spends and timed locks of the state that was just discarded.
    pthread_rwlock_wrlock(&l_ledger_pvt->rewards_rwlock);
    dap_ledger_reward_item_t *l_reward_current, *l_reward_tmp;
    HASH_ITER(hh, l_ledger_pvt->rewards, l_reward_current, l_reward_tmp) {
        HASH_DEL(l_ledger_pvt->rewards, l_reward_current);
        DAP_DELETE(l_reward_current);
    }
    l_ledger_pvt->rewards = NULL;
    pthread_rwlock_unlock(&l_ledger_pvt->rewards_rwlock);

    pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event_current, *l_event_tmp;
    HASH_ITER(hh, l_ledger_pvt->events, l_event_current, l_event_tmp) {
        HASH_DEL(l_ledger_pvt->events, l_event_current);
        DAP_DEL_Z(l_event_current->group_name);
        DAP_DEL_Z(l_event_current->event_data);
        DAP_DELETE(l_event_current);
    }
    l_ledger_pvt->events = NULL;
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);

    pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);
    dap_ledger_event_pkey_item_t *l_pkey_current, *l_pkey_tmp;
    HASH_ITER(hh, l_ledger_pvt->event_pkeys_allowed, l_pkey_current, l_pkey_tmp) {
        HASH_DEL(l_ledger_pvt->event_pkeys_allowed, l_pkey_current);
        DAP_DELETE(l_pkey_current);
    }
    l_ledger_pvt->event_pkeys_allowed = NULL;
    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);

    pthread_rwlock_wrlock(&l_ledger_pvt->locked_outs_rwlock);
    dap_ledger_locked_out_t *l_lo_current, *l_lo_tmp;
    LL_FOREACH_SAFE(l_ledger_pvt->locked_outs, l_lo_current, l_lo_tmp) {
        LL_DELETE(l_ledger_pvt->locked_outs, l_lo_current);
        DAP_DELETE(l_lo_current);
    }
    LL_FOREACH_SAFE(l_ledger_pvt->reverse_list, l_lo_current, l_lo_tmp) {
        LL_DELETE(l_ledger_pvt->reverse_list, l_lo_current);
        DAP_DELETE(l_lo_current);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->locked_outs_rwlock);

    l_ledger_pvt->snapshot_full = false;
    l_ledger_pvt->load_end = false;
    // A new load cycle may follow the purge: re-arm the finalization guard too.
    l_ledger_pvt->load_end_done = false;
}

/**
 * Return number transactions from the cache
 * According to UT_hash_handle size of return value is sizeof(unsigned int)
 */
unsigned dap_ledger_count(dap_ledger_t *a_ledger)
{
    pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
    unsigned long ret = HASH_COUNT(PVT(a_ledger)->ledger_items);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    return ret;
}

/**
 * @brief dap_ledger_count_from_to
 * @param a_ledger
 * @param a_ts_from
 * @param a_ts_to
 * @return
 */
static inline size_t s_stats_cache_slot(const void *a_ledger, dap_nanotime_t a_from, dap_nanotime_t a_to) {
    uint64_t h = 1469598103934665603ull;
    const uint64_t l_parts[3] = { (uint64_t)(uintptr_t)a_ledger, (uint64_t)a_from, (uint64_t)a_to };
    for (size_t i = 0; i < 3; ++i) {
        uint64_t v = l_parts[i];
        for (int b = 0; b < 8; ++b) { h ^= (v >> (b * 8)) & 0xFF; h *= 1099511628211ull; }
    }
    return (size_t)(h % DAP_LEDGER_STATS_CACHE_SLOTS);
}

uint64_t dap_ledger_count_from_to(dap_ledger_t * a_ledger, dap_nanotime_t a_ts_from, dap_nanotime_t a_ts_to)
{
    uint64_t l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    size_t l_slot = s_stats_cache_slot(a_ledger, a_ts_from, a_ts_to);
    dap_nanotime_t l_now = dap_nanotime_now();
    pthread_mutex_lock(&s_stats_cache_lock);
    if (s_stats_cache[l_slot].ledger == (const void *)a_ledger &&
        s_stats_cache[l_slot].ts_from == a_ts_from && s_stats_cache[l_slot].ts_to == a_ts_to &&
        l_now - s_stats_cache[l_slot].ts_cached < DAP_LEDGER_STATS_CACHE_TTL_NS) {
        l_ret = s_stats_cache[l_slot].count;
        pthread_mutex_unlock(&s_stats_cache_lock);
        return l_ret;
    }
    pthread_mutex_unlock(&s_stats_cache_lock);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    if ( a_ts_from && a_ts_to) {
        HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->ts_added >= a_ts_from && l_iter_current->ts_added <= a_ts_to )
                l_ret++;
        }
    } else if ( a_ts_to ){
        HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->ts_added <= a_ts_to )
                l_ret++;
        }
    } else if ( a_ts_from ){
        HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->ts_added >= a_ts_from )
                l_ret++;
        }
    } else {
        l_ret = HASH_COUNT(l_ledger_pvt->ledger_items);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    pthread_mutex_lock(&s_stats_cache_lock);
    s_stats_cache[l_slot] = (s_stats_cache_entry_t){ .ledger = a_ledger, .ts_from = a_ts_from,
                                                     .ts_to = a_ts_to, .ts_cached = dap_nanotime_now(), .count = l_ret };
    pthread_mutex_unlock(&s_stats_cache_lock);
    return l_ret;
}


/**
 * Check whether used 'out' items
 */
bool dap_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out, dap_hash_fast_t *a_out_spender)
{
    dap_ledger_tx_item_t *l_item_out = NULL;
    /*dap_chain_datum_tx_t *l_tx =*/ dap_ledger_tx_find_datum_by_hash(a_ledger, a_tx_hash, &l_item_out, false);
    return l_item_out ? s_ledger_tx_hash_is_used_out_item(l_item_out, a_idx_out, a_out_spender) : true;
}

bool dap_ledger_tx_is_used_out_item(dap_ledger_t *a_ledger, dap_ledger_datum_iter_t *a_iter, int a_idx_out, dap_hash_fast_t *a_out_spender) {
    return a_iter ? s_ledger_tx_hash_is_used_out_item((dap_ledger_tx_item_t*)(a_iter->cur_ledger_tx_item), a_idx_out, a_out_spender) : true;
}

/**
 * Calculate balance of addr
 *
 */
uint256_t dap_ledger_calc_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                        const char *a_token_ticker)
{
    uint256_t l_ret = uint256_0;

    dap_ledger_wallet_balance_t *l_balance_item = NULL;// ,* l_balance_item_tmp = NULL;
    char *l_wallet_balance_key = dap_strjoin(" ", dap_chain_addr_to_str_static(a_addr), a_token_ticker, (char*)NULL);
    pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, l_balance_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
    if (l_balance_item) {
        debug_if(s_debug_more, L_INFO, "Found address in cache with balance %s",
            dap_uint256_to_char(l_balance_item->balance, NULL));
        l_ret = l_balance_item->balance;
    } else {
        debug_if(s_debug_more, L_WARNING, "Balance item %s not found", l_wallet_balance_key);
    }
    DAP_DELETE(l_wallet_balance_key);
    return l_ret;
}

uint256_t dap_ledger_calc_balance_full(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                             const char *a_token_ticker)
{
    uint256_t balance = uint256_0;

    if(!a_addr || dap_chain_addr_check_sum(a_addr))
        return balance;

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_cur_tx = l_iter_current->tx;
        // Get 'out' items from transaction
        int l_out_idx = 0;
        byte_t *it; size_t l_size;
        TX_ITEM_ITER_TX(it, l_size, l_cur_tx) {
            uint256_t l_add = { };
            dap_chain_addr_t l_out_addr = { };
            switch (*it) {
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_tx_out = (dap_chain_tx_out_old_t*)it;
                l_add = dap_chain_uint256_from(l_tx_out->header.value);
                l_out_addr = l_tx_out->addr;
            } break;
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*)it;
                l_add = l_tx_out->header.value;
                l_out_addr = l_tx_out->addr;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t*)it;
                l_add = l_tx_out->header.value;
                l_out_addr = l_tx_out->addr;
            } break;
            case TX_ITEM_TYPE_OUT_STD: {
                dap_chain_tx_out_std_t *l_tx_out = (dap_chain_tx_out_std_t *)it;
                l_add = l_tx_out->value;
                l_out_addr = l_tx_out->addr;
                if (l_tx_out->ts_unlock > PVT(a_ledger)->blockchain_time) {
                    ++l_out_idx;
                    continue;
                }
            } break;
            case TX_ITEM_TYPE_OUT_COND:
                ++l_out_idx;
            default:
                continue;
            }
            ++l_out_idx;
            if (    !dap_strcmp( a_token_ticker, l_iter_current->cache_data.token_ticker )  // Tokens match
                &&  !dap_chain_addr_compare( a_addr, &l_out_addr )                          // Addresses match
                &&  !s_ledger_tx_hash_is_used_out_item( l_iter_current, l_out_idx, NULL )   // Output is unused
                )
            {
                SUM_256_256(balance, l_add, &balance);
            }
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return balance;
}

/**
 * Get the transaction in the cache by the addr in out item
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 * a_tx_first_hash [in/out] hash of the initial transaction/ found transaction, if 0 start from the beginning
 */
dap_chain_datum_tx_t *dap_ledger_tx_find_by_addr(dap_ledger_t *a_ledger, const char *a_token,
                                                 const dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash,
                                                 bool a_unspent_only)
{
    if(!a_addr || !a_tx_first_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    bool is_tx_found = false;
    dap_ledger_tx_item_t *l_iter_start = NULL, *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    if (!dap_hash_fast_is_blank(a_tx_first_hash)) {
        HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_first_hash, sizeof(dap_hash_t), l_iter_start);
        if (!l_iter_start || !l_iter_start->hh.next){
            pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
            return NULL;
        }
        // start searching from the next hash after a_tx_first_hash
        l_iter_start = l_iter_start->hh.next;
    } else
        l_iter_start = l_ledger_pvt->ledger_items;
    HASH_ITER(hh, l_iter_start, l_iter_current, l_item_tmp) {
        // If a_token is setup we check if its not our token - miss it
        if (a_token && *l_iter_current->cache_data.token_ticker &&
                dap_strcmp(l_iter_current->cache_data.token_ticker, a_token) &&
                !l_iter_current->cache_data.multichannel)
            continue;
        // Now work with it
        dap_chain_datum_tx_t *l_tx = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash = &l_iter_current->tx_hash_fast;
        // Get 'out' items from transaction
        int num = -1;
        byte_t *it; size_t l_size;
        TX_ITEM_ITER_TX(it, l_size, l_tx) {
            dap_chain_addr_t l_addr = { };
            switch (*it) {
            case TX_ITEM_TYPE_OUT:
                num++;
                l_addr = ((dap_chain_tx_out_t*)it)->addr;
                break;
            case TX_ITEM_TYPE_OUT_OLD:
                num++;
                l_addr = ((dap_chain_tx_out_old_t*)it)->addr;
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                num++;
                if ( a_token && dap_strcmp(a_token, ((dap_chain_tx_out_ext_t*)it)->token) )
                    continue;
                l_addr = ((dap_chain_tx_out_ext_t*)it)->addr;
                break;
            case TX_ITEM_TYPE_OUT_STD:
                num++;
                if (a_token && dap_strcmp(a_token, ((dap_chain_tx_out_std_t *)it)->token))
                    continue;
                l_addr = ((dap_chain_tx_out_std_t *)it)->addr;
                break;
            case TX_ITEM_TYPE_OUT_COND:
                num++;
            default:
                continue;
            }
            if ( dap_chain_addr_compare(a_addr, &l_addr) ) {
                if (a_unspent_only && s_ledger_tx_hash_is_used_out_item(l_iter_current, num, NULL))
                    continue;
                *a_tx_first_hash = *l_tx_hash;
                is_tx_found = true;
                break;
            }
        }
        if (is_tx_found)
            break;
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return is_tx_found ? l_iter_current->tx : NULL;
}

 bool dap_ledger_tx_check_recipient(dap_ledger_t* a_ledger, dap_chain_hash_fast_t* a_tx_prev_hash, dap_chain_addr_t *a_addr)
 {
     dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_tx_prev_hash);
     if ( !l_tx )
        return false;
    dap_chain_addr_t l_dst_addr = { };
    byte_t *it; size_t l_size;
    TX_ITEM_ITER_TX(it, l_size, l_tx) {
        switch (*it) {
        case TX_ITEM_TYPE_OUT:
            l_dst_addr = ((dap_chain_tx_out_t*)it)->addr;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_dst_addr = ((dap_chain_tx_out_ext_t*)it)->addr;
            break;
        case TX_ITEM_TYPE_OUT_OLD:
            l_dst_addr = ((dap_chain_tx_out_old_t*)it)->addr;
            break;
        default:
            continue;
        }
        if ( dap_chain_addr_compare(a_addr, &l_dst_addr) )
            return true;
    }
    return false;
 }

/**
 * @brief Get all transactions from the cache with the out_cond item
 * @param a_ledger
 * @param a_srv_uid
 * @return
 */
dap_list_t* dap_ledger_tx_cache_find_out_cond_all(dap_ledger_t *a_ledger, dap_chain_net_srv_uid_t a_srv_uid)
{
    dap_list_t * l_ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_iter_current = NULL, *l_item_tmp = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_iter_current, l_item_tmp) {
        dap_chain_datum_tx_t *l_tx = l_iter_current->tx;
        byte_t *item; size_t l_size;
        TX_ITEM_ITER_TX(item, l_size, l_tx) {
            if (*item == TX_ITEM_TYPE_OUT_COND && ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64 == a_srv_uid.uint64)
                l_ret = dap_list_append(l_ret, l_tx);
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return l_ret;
}

dap_list_t *dap_ledger_get_list_tx_outs_unspent_by_addr(dap_ledger_t *a_ledger, const char *a_token,
        const dap_chain_addr_t *a_addr, const uint256_t *a_limit, uint256_t *a_out_value,
        bool a_cond_only, dap_chain_tx_out_cond_subtype_t a_cond_subtype, bool a_mempool_check,
        bool a_skip_blocklist)
{
    if ( !a_ledger || ( a_limit && IS_ZERO_256(*a_limit) ) ) return NULL;
    if ( a_cond_only && ( a_cond_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED || !a_addr) ) return NULL;
    
    // Debug: log search parameters
    if (s_debug_more && a_addr && a_token) {
        const char *l_limit_str = a_limit ? dap_uint256_to_char(*a_limit, NULL) : "NULL";
        log_it(L_DEBUG, "UTXO SEARCH: addr=%s token=%s limit=%s", 
               dap_chain_addr_to_str_static(a_addr), a_token, l_limit_str);
    }
    
    dap_list_t *l_ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_cur, *l_tmp;
    uint256_t l_out_value = { };
    if ( a_out_value )
        *a_out_value = (uint256_t){ };
    else if ( a_limit )
        a_out_value = &l_out_value;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    // Cooperative cancellation: this is the full ledger_items scan behind
    // tx_create_json (see cellframe_node_rpc_overload_research_2026_09, sec.
    // 2) — on mainnet-sized ledgers it can run well past the point where the
    // requesting CLI client has already disconnected. Checked every 4096
    // items (mutex-guarded, so not on every single one) so an abandoned
    // request lets go of ledger_rwlock quickly instead of finishing a scan
    // for a reply nobody will read.
    uint64_t l_item_idx = 0;
    const char *l_bl_token_cached = NULL;
    dap_ledger_token_item_t *l_bl_token_item = NULL;
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_cur, l_tmp) {
        if (!(++l_item_idx & 0xFFF) && !dap_cli_server_client_is_alive())
            break;
        if ( l_cur->cache_data.ts_spent )
            continue;
        // Phantom item: its transaction datum is not in the local cell files yet
        // (restored from the ledger snapshot, block still to be caught up). There
        // is nothing to iterate over - dereferencing tx here crashed the UTXO
        // scan behind wallet outputs / tx_create_json.
        if ( !l_cur->tx )
            continue;
        if ( a_token && dap_strcmp(l_cur->cache_data.token_ticker, a_token) && !l_cur->cache_data.multichannel )
            continue;
        byte_t *l_item; size_t l_size; int l_out_idx = -1;
        TX_ITEM_ITER_TX(l_item, l_size, l_cur->tx) {
            dap_chain_addr_t l_addr = { };
            uint256_t l_value;
            const char *l_token;
            switch (*l_item) {
            case TX_ITEM_TYPE_OUT:
                ++l_out_idx;
                if ( a_cond_only ) continue;
                l_addr = ((dap_chain_tx_out_t*)l_item)->addr;
                l_value = ((dap_chain_tx_out_t*)l_item)->header.value;
                l_token = a_token ? l_cur->cache_data.token_ticker : NULL;
                break;
            case TX_ITEM_TYPE_OUT_OLD:
                ++l_out_idx;
                if ( a_cond_only ) continue;
                l_addr = ((dap_chain_tx_out_old_t*)l_item)->addr;
                l_value = GET_256_FROM_64( ((dap_chain_tx_out_old_t*)l_item)->header.value );
                l_token = a_token ? l_cur->cache_data.token_ticker : NULL;
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                ++l_out_idx;
                if ( a_cond_only ) continue;
                l_addr = ((dap_chain_tx_out_ext_t*)l_item)->addr;
                l_value = ((dap_chain_tx_out_ext_t*)l_item)->header.value;
                l_token = a_token ? ((dap_chain_tx_out_ext_t*)l_item)->token : NULL;
                break;
            case TX_ITEM_TYPE_OUT_STD:
                ++l_out_idx;
                if ( a_cond_only ) continue;
                if ( ((dap_chain_tx_out_std_t*)l_item)->ts_unlock > dap_ledger_get_blockchain_time(a_ledger) )
                    continue;
                l_addr = ((dap_chain_tx_out_std_t*)l_item)->addr;
                l_value = ((dap_chain_tx_out_std_t*)l_item)->value;
                l_token = a_token ? ((dap_chain_tx_out_std_t*)l_item)->token : NULL;
                break;
            case TX_ITEM_TYPE_OUT_COND:
                ++l_out_idx;
                if ( a_cond_only
                    && ( a_cond_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL
                        ? ((dap_chain_tx_out_cond_t*)l_item)->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE
                        : ((dap_chain_tx_out_cond_t*)l_item)->header.subtype == a_cond_subtype ) )
                {
                    l_token = *l_cur->cache_data.token_ticker ? l_cur->cache_data.token_ticker : a_token;
                    l_value = ((dap_chain_tx_out_cond_t*)l_item)->header.value;
                    break;
                }
            default:
                continue;
            }
            if ( s_ledger_tx_hash_is_used_out_item(l_cur, l_out_idx, NULL) )
                continue;
            if ( a_token && dap_strcmp(l_token, a_token) )
                continue;
            if ( a_cond_only ) {
                dap_hash_fast_t l_owner_tx_hash = s_first_chain_tx_hash(a_ledger, l_cur->tx, ((dap_chain_tx_out_cond_t*)l_item)->header.subtype, NULL, true);
                dap_chain_datum_tx_t *l_tx = dap_hash_fast_is_blank(&l_owner_tx_hash)
                    ? l_cur->tx : s_tx_find_by_hash_locked(a_ledger, &l_owner_tx_hash);
                if ( !l_tx )
                    continue;
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
                dap_hash_fast_t l_sign_hash;
                if ( !dap_sign_get_pkey_hash(l_sign, &l_sign_hash)
                    || !dap_hash_fast_compare(&l_sign_hash, &a_addr->data.hash_fast) )
                    continue;
            } else if ( a_addr && !dap_chain_addr_compare(a_addr, &l_addr) ) {
                debug_if(s_debug_more, L_DEBUG, "UTXO address mismatch: search=%s utxo=%s",
                        dap_chain_addr_to_str_static(a_addr), dap_chain_addr_to_str_static(&l_addr));
                continue;
            }
            // CRITICAL: Check if UTXO is blocked in token-specific blocklist
            // This prevents blocked UTXOs from being selected for transactions
            // Check applies to ALL output types (regular OUT, OUT_EXT, OUT_STD, and OUT_COND)
            // Blocked UTXO cannot be used in any transaction type
            // Skip this check for arbitrage transactions (a_skip_blocklist = true)
            // The token lookup is memoized: s_ledger_find_token per UTXO took
            // a tokens_rwlock round trip per matching output.
            if (!a_skip_blocklist && l_token) {
                if (!l_bl_token_cached || strcmp(l_bl_token_cached, l_token)) {
                    l_bl_token_cached = l_token;
                    l_bl_token_item = s_ledger_find_token(a_ledger, l_token);
                }
                // Advisory early-out: an empty blocklist (the common case)
                // can't block anything. The count is monotonic (entries are
                // never unlinked) and published atomically, so a zero read
                // here reliably means "no blocked UTXOs for this token yet".
                if (l_bl_token_item &&
                    !(l_bl_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) &&
                    atomic_load_explicit(&l_bl_token_item->utxo_blocklist_count, memory_order_acquire) &&
                    dap_ledger_utxo_is_blocked(l_bl_token_item, &l_cur->tx_hash_fast, l_out_idx, a_ledger)) {
                    debug_if(s_debug_more, L_DEBUG, "UTXO %s:%d is blocked for token %s - skipping",
                            dap_hash_fast_to_str_static(&l_cur->tx_hash_fast), l_out_idx, l_token);
                    continue;
                }
            }
            if (a_mempool_check && dap_chain_mempool_out_is_used(a_ledger->net, &l_cur->tx_hash_fast, l_out_idx))
                continue;
            dap_chain_tx_used_out_item_t *l_utxo = DAP_NEW(dap_chain_tx_used_out_item_t);
            *l_utxo = (dap_chain_tx_used_out_item_t) { l_cur->tx_hash_fast, (uint32_t)l_out_idx, l_value };
            log_it(L_DEBUG, "UTXO: tx %s out #%d",
                dap_hash_fast_to_str_static(&l_cur->tx_hash_fast), l_out_idx);
            l_ret = dap_list_append(l_ret, l_utxo);
            if (a_out_value) {
                SUM_256_256(*a_out_value, l_value, a_out_value);
                if ( a_limit && compare256(*a_out_value, *a_limit) != -1 ) {
                    a_limit = NULL;
                    goto complete;
                }
            }
        }
    }
complete:
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    if ( a_limit ) {
        log_it(L_INFO, "Limit not reached"); // TODO: extend log with new static output
        dap_list_free_full(l_ret, NULL);
        l_ret = NULL;
    }
    return l_ret;
}


// Add new verificator callback with associated subtype. Returns 1 if callback replaced, -1 error, overwise returns 0
int dap_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype, dap_ledger_verificator_callback_t a_callback, dap_ledger_updater_callback_t a_callback_added, dap_ledger_delete_callback_t a_callback_deleted)
{
    dap_ledger_verificator_t *l_new_verificator = NULL;
    int l_tmp = (int)a_subtype;
    pthread_rwlock_rdlock(&s_verificators_rwlock);
    HASH_FIND_INT(s_verificators, &l_tmp, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    if (l_new_verificator) {
        l_new_verificator->callback = a_callback;
        return 1;
    }
    l_new_verificator = DAP_NEW(dap_ledger_verificator_t);
    if (!l_new_verificator) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    l_new_verificator->subtype = (int)a_subtype;
    l_new_verificator->callback = a_callback;
    l_new_verificator->callback_added = a_callback_added;
    l_new_verificator->callback_deleted = a_callback_deleted;
    pthread_rwlock_wrlock(&s_verificators_rwlock);
    HASH_ADD_INT(s_verificators, subtype, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    return 0;
}

int dap_chain_ledger_voting_verificator_add(dap_chain_ledger_voting_callback_t a_callback, dap_chain_ledger_voting_delete_callback_t a_callback_delete)
{
    if (!a_callback)
        return -1;

    if (!s_voting_callbacks.voting_callback || !s_voting_callbacks.voting_delete_callback){
        s_voting_callbacks.voting_callback = a_callback;
        s_voting_callbacks.voting_delete_callback = a_callback_delete;
        return 1;
    }

    s_voting_callbacks.voting_callback = a_callback;
    s_voting_callbacks.voting_delete_callback = a_callback_delete;
    return 0;
}

dap_list_t *dap_ledger_get_txs(dap_ledger_t *a_ledger, size_t a_count, size_t a_page, bool a_reverse, bool a_unspent_only)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
    size_t l_offset = a_page < 2 ? 0 : a_count * (a_page - 1);
    if (!l_ledger_pvt->ledger_items || l_offset > HASH_COUNT(l_ledger_pvt->ledger_items)){
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        return NULL;
    }
    dap_list_t *l_list = NULL;
    size_t l_counter = 0, l_count_got = 0;
    dap_ledger_tx_item_t *l_item_current, *l_item_tmp;
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_item_current, l_item_tmp) {
        if (l_counter++ >= l_offset) {
            if (!a_unspent_only || !l_item_current->cache_data.ts_spent) {
                l_list = a_reverse
                        ? dap_list_prepend(l_list, l_item_current->tx)
                        : dap_list_append(l_list, l_item_current->tx);
                // A page request used to keep walking the whole (hundreds of
                // thousands of items) table and return everything from the
                // offset to the end; stop once the page is full. a_count == 0
                // keeps the old "everything from offset" behavior.
                if (a_count && ++l_count_got >= a_count)
                    break;
            }
        }
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    return l_list;
}

dap_ledger_datum_iter_t *dap_ledger_datum_iter_create(dap_chain_net_t *a_net)
{
    dap_ledger_datum_iter_t *l_ret = DAP_NEW_Z(dap_ledger_datum_iter_t);
    if(!l_ret){
        log_it(L_CRITICAL, "Memory allocation error!");
        return NULL;
    }
    l_ret->net = a_net;
    return l_ret;
}

void dap_ledger_datum_iter_delete(dap_ledger_datum_iter_t *a_iter)
{
    DAP_DEL_Z(a_iter);
}

dap_chain_datum_tx_t *dap_ledger_datum_iter_get_first(dap_ledger_datum_iter_t *a_iter)
{
    if (!a_iter)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_iter->net->pub.ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    if (!l_ledger_pvt->ledger_items) {
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
        return NULL;
    }
    a_iter->cur_ledger_tx_item = l_ledger_pvt->ledger_items;
    a_iter->cur = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->tx;
    a_iter->cur_hash = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->tx_hash_fast;
    a_iter->is_unspent = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->cache_data.ts_spent ? false : true;
    a_iter->ret_code = 0;
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return a_iter->cur;
}

dap_chain_datum_tx_t *dap_ledger_datum_iter_get_next(dap_ledger_datum_iter_t *a_iter)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_iter->net->pub.ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    a_iter->cur_ledger_tx_item = a_iter->cur_ledger_tx_item ? ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->hh.next : NULL;
    if (a_iter->cur_ledger_tx_item){
        a_iter->cur = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->tx;
        a_iter->cur_hash = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->tx_hash_fast;
        a_iter->ret_code = 0;
        a_iter->is_unspent = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->cache_data.ts_spent ? false : true;
    } else {
        a_iter->cur = NULL;
        memset(&a_iter->cur_hash, 0, sizeof(dap_hash_fast_t));
        a_iter->ret_code = 0;
        a_iter->is_unspent = false;
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return a_iter->cur;
}

dap_chain_datum_tx_t *dap_ledger_datum_iter_get_last(dap_ledger_datum_iter_t *a_iter)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_iter->net->pub.ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    a_iter->cur_ledger_tx_item = HASH_LAST(l_ledger_pvt->ledger_items);
    a_iter->cur = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->tx;
    a_iter->cur_hash = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->tx_hash_fast;
    a_iter->is_unspent = ((dap_ledger_tx_item_t *)(a_iter->cur_ledger_tx_item))->cache_data.ts_spent ? false : true;
    a_iter->ret_code = 0;
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return a_iter->cur;
}

/**
 * Get the transaction in the cache by the addr in sig item
 *
 * a_addr[in] public key that signed the transaction
 * a_tx_first_hash [in/out] hash of the initial transaction/ found transaction, if 0 start from the beginning
 */
dap_chain_tx_out_cond_t *dap_ledger_out_cond_unspent_find_by_addr(dap_ledger_t *a_ledger, const char *a_token, dap_chain_tx_out_cond_subtype_t a_subtype,
                                                                  const dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash, int *a_out_idx)
{
    if (!a_addr || !a_token)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_tx_out_cond_t *ret = NULL;
    dap_ledger_tx_item_t *l_iter_start = NULL, *it;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    if (a_tx_first_hash && !dap_hash_fast_is_blank(a_tx_first_hash)) {
        HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_first_hash, sizeof(dap_hash_t), l_iter_start);
        if (!l_iter_start || !l_iter_start->hh.next) {
            pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
            return NULL;
        }
        // start searching from the next hash after a_tx_first_hash
        l_iter_start = l_iter_start->hh.next;
    } else
        l_iter_start = l_ledger_pvt->ledger_items;
    for (it = l_iter_start; it; it = it->hh.next, ret = NULL) {
        // If a_token is setup we check if its not our token - miss it
        if (*it->cache_data.token_ticker && dap_strcmp(it->cache_data.token_ticker, a_token))
            continue;
        // Get 'out_cond' item from transaction
        byte_t *l_item; size_t l_size; int i, l_out_idx = 0;
        dap_chain_tx_out_cond_subtype_t l_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
        TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, it->tx) {
            if (*l_item == TX_ITEM_TYPE_OUT_COND) {
                l_subtype = ((dap_chain_tx_out_cond_t *)l_item)->header.subtype;
                if (l_subtype == a_subtype ||
                        (a_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL && l_subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)) {
                    ret = (dap_chain_tx_out_cond_t *)l_item;
                    break;
                }
            }
            l_out_idx++;
        }
        // Don't return regular tx or spent conditions
        if (!ret || !dap_hash_fast_is_blank(&it->cache_data.tx_hash_spent_fast[l_out_idx]))
            continue;
        dap_hash_fast_t l_owner_tx_hash = s_first_chain_tx_hash(a_ledger, it->tx, l_subtype, NULL, true);
        dap_chain_datum_tx_t *l_tx = dap_hash_fast_is_blank(&l_owner_tx_hash) ? it->tx
                                                                              : s_tx_find_by_hash_locked(a_ledger, &l_owner_tx_hash);
        if (!l_tx) {
            log_it(L_ERROR, "Can't find owner for tx %s", dap_hash_fast_to_str_static(&it->tx_hash_fast));
            continue;
        }
        // Get sign item from transaction
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        // Get dap_sign_t from item
        dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
        // compare public key in transaction with a_public_key
        dap_chain_hash_fast_t l_sign_hash = {};
        dap_sign_get_pkey_hash(l_sign, &l_sign_hash);
        if (dap_hash_fast_compare(&l_sign_hash, &a_addr->data.hash_fast)) {
            if (a_tx_first_hash)
                *a_tx_first_hash = it->tx_hash_fast;
            if (a_out_idx)
                *a_out_idx = l_out_idx;
            break;
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return ret;
}

dap_list_t *dap_ledger_get_list_tx_cond_outs(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_subtype,
                                             const char *a_token_ticker,  const dap_chain_addr_t *a_addr_from)
{
    return dap_ledger_get_list_tx_outs_unspent_by_addr(a_ledger, a_token_ticker, a_addr_from, NULL, NULL, true, a_subtype, false, false);
}

bool dap_ledger_check_condition_owner(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, dap_chain_tx_out_cond_subtype_t a_cond_subtype,
                                      int a_out_idx, dap_sign_t *a_owner_sign)
{
    dap_return_val_if_fail(a_ledger && a_tx_hash && a_owner_sign, false);
    // Get first tx
    dap_chain_datum_tx_t *l_check_tx = dap_ledger_tx_find_by_hash(a_ledger, a_tx_hash);
    if (!l_check_tx) {
        log_it(L_ERROR, "Can't find tx %s", dap_hash_fast_to_str_static(a_tx_hash));
        return false;
    }
    if (!dap_chain_datum_tx_out_cond_get(l_check_tx, a_cond_subtype, NULL)) {
        log_it(L_ERROR, "Can't find owner for tx %s", dap_hash_fast_to_str_static(a_tx_hash));
        return false;
    }
    dap_hash_fast_t l_first_tx_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, l_check_tx, a_cond_subtype);
    dap_chain_datum_tx_t *l_first_tx = dap_hash_fast_is_blank(&l_first_tx_hash) ? l_check_tx
                                                                                : dap_ledger_tx_find_by_hash(a_ledger, &l_first_tx_hash);
    if (!l_first_tx) {
        log_it(L_ERROR, "Can't find owner tx %s", dap_hash_fast_to_str_static(&l_first_tx_hash));
        return false;
    }
    dap_chain_tx_sig_t *l_first_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_first_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_first_tx_sig);
    if (!l_sign) {
        log_it(L_ERROR, "Can't find signature for tx %s", dap_hash_fast_to_str_static(&l_first_tx_hash));
        return false;
    }
    return dap_sign_compare_pkeys(a_owner_sign, l_sign);
}

void dap_ledger_tx_add_notify(dap_ledger_t *a_ledger, dap_ledger_tx_add_notify_t a_callback, void *a_arg) {
    if (!a_ledger) {
        log_it(L_ERROR, "NULL ledger passed to dap_ledger_tx_add_notify()");
        return;
    }
    if (!a_callback) {
        log_it(L_ERROR, "NULL callback passed to dap_ledger_tx_add_notify()");
        return;
    }
    dap_ledger_tx_notifier_t *l_notifier = DAP_NEW(dap_ledger_tx_notifier_t);
    if (!l_notifier){
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_ledger_tx_add_notify()");
        return;
    }
    l_notifier->callback = a_callback;
    l_notifier->arg = a_arg;
    PVT(a_ledger)->tx_add_notifiers = dap_list_append(PVT(a_ledger)->tx_add_notifiers, l_notifier);
}

void dap_ledger_bridged_tx_notify_add(dap_ledger_t *a_ledger, dap_ledger_bridged_tx_notify_t a_callback, void *a_arg)
{
    if (!a_ledger || !a_callback)
        return;
    dap_ledger_bridged_tx_notifier_t *l_notifier = DAP_NEW_Z(dap_ledger_bridged_tx_notifier_t);
    if (!l_notifier) {
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_ledger_tx_add_notify()");
        return;
    }
    l_notifier->callback = a_callback;
    l_notifier->arg = a_arg;
    PVT(a_ledger)->bridged_tx_notifiers = dap_list_append(PVT(a_ledger)->bridged_tx_notifiers, l_notifier);
}

/**
 * @brief Add notification callback for event transactions
 * @param a_ledger Ledger instance
 * @param a_callback Callback function to be called when a new event is added
 * @param a_arg User data to be passed to the callback
 */
void dap_ledger_event_notify_add(dap_ledger_t *a_ledger, dap_ledger_event_notify_t a_callback, void *a_arg)
{
    if (!a_ledger || !a_callback)
        return;
    
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    
    dap_ledger_event_notifier_t *l_notifier = DAP_NEW_Z(dap_ledger_event_notifier_t);
    if (!l_notifier) {
        log_it(L_CRITICAL, "Memory allocation error in dap_ledger_event_notify_add()");
        return;
    }
    
    l_notifier->callback = a_callback;
    l_notifier->arg = a_arg;
    
    l_ledger_pvt->event_notifiers = dap_list_append(l_ledger_pvt->event_notifiers, l_notifier);
}

bool dap_ledger_cache_enabled(dap_ledger_t *a_ledger)
{
    return PVT(a_ledger)->cached;
}

void dap_ledger_set_cache_tx_check_callback(dap_ledger_t *a_ledger, dap_ledger_cache_tx_check_callback_t a_callback)
{
    PVT(a_ledger)->cache_tx_check_callback = a_callback;
}

dap_chain_token_ticker_str_t dap_ledger_tx_calculate_main_ticker_(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, int *a_ledger_rc)
{
    dap_hash_fast_t l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    dap_chain_token_ticker_str_t l_ret = { };
    int l_rc = s_tx_cache_check(a_ledger, a_tx, &l_tx_hash, false, NULL, NULL, (char*)&l_ret, NULL, NULL, false, false);
    if (l_rc == DAP_LEDGER_CHECK_ALREADY_CACHED)
        dap_strncpy( (char*)&l_ret, dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_hash), DAP_CHAIN_TICKER_SIZE_MAX );
    if (a_ledger_rc)
        *a_ledger_rc = l_rc;
    return l_ret;
}

static dap_chain_tx_event_t *s_ledger_event_to_tx_event(dap_ledger_event_t *a_event)
{
    dap_chain_tx_event_t *l_tx_event = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_event_t, NULL);
    *l_tx_event = (dap_chain_tx_event_t) {
        .group_name = dap_strdup(a_event->group_name),
        .tx_hash = a_event->tx_hash,
        .pkey_hash = a_event->pkey_hash,
        .event_type = a_event->event_type,
        .event_data_size = a_event->event_data_size,
        .timestamp = a_event->timestamp,
        .srv_uid = a_event->srv_uid
    };
    if (a_event->event_data_size)
        l_tx_event->event_data = DAP_DUP_SIZE_RET_VAL_IF_FAIL(a_event->event_data, a_event->event_data_size, NULL);
    return l_tx_event;
}

dap_chain_tx_event_t *dap_ledger_event_find(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    HASH_FIND(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_fast_t), l_event);
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    if (!l_event)
        return NULL;
    return s_ledger_event_to_tx_event(l_event);
}

dap_list_t *dap_ledger_event_get_list_ex(dap_ledger_t *a_ledger, const char *a_group_name, bool a_need_lock)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    if (a_need_lock)
        pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_list_t *l_list = NULL;
    for (dap_ledger_event_t *it = l_ledger_pvt->events; it; it = it->hh.next) {
        if (a_group_name && dap_strcmp(it->group_name, a_group_name))
            continue;
        dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(it);
        if (!l_tx_event) {
            log_it(L_ERROR, "Can't allocate memory for tx event in dap_ledger_event_get_list()");
            if (a_need_lock)
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            dap_list_free_full(l_list, dap_chain_datum_tx_event_delete);
            return NULL;
        }
        l_list = dap_list_append(l_list, l_tx_event);
    }
    if (a_need_lock)
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    return l_list;
}


static int s_ledger_event_remove(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    HASH_FIND(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_fast_t), l_event);
    if (!l_event) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -1;
    }
    
    // Create a copy of the event for notifiers
    dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(l_event);
    
    // Remove the event from hash table
    HASH_DEL(l_ledger_pvt->events, l_event);
    DAP_DEL_MULTY(l_event->event_data, l_event->group_name, l_event);
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    
    // Call event notifiers
    if (l_tx_event) {
        for (dap_list_t *it = l_ledger_pvt->event_notifiers; it; it = it->next) {
            dap_ledger_event_notifier_t *l_notifier = (dap_ledger_event_notifier_t *)it->data;
            if (l_notifier && l_notifier->callback) {
                l_notifier->callback(l_notifier->arg, a_ledger, l_tx_event, a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
            }
        }
        dap_chain_datum_tx_event_delete(l_tx_event);
    }
    
    return 0;
}
static int s_ledger_event_verify_add(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, dap_chain_datum_tx_t *a_tx, bool a_apply, bool a_check_for_apply)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    if (a_apply)
        pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    else
        pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    unsigned int l_hash_value = 0;
    HASH_VALUE(a_tx_hash, sizeof(dap_hash_fast_t), l_hash_value);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_fast_t), l_hash_value, l_event);
    if (l_event) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -1;
    }
    dap_chain_tx_item_event_t *l_event_item = NULL;
    dap_tsd_t *l_event_tsd = NULL;
    dap_sign_t *l_event_sign = NULL;
    byte_t *l_item; size_t l_tx_item_size;
    int l_event_count = 0, l_tsd_count = 0, l_sign_count = 0;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_EVENT:
            if (l_event_count++) {
                log_it(L_WARNING, "Multiple event items in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -2;
            }
            l_event_item = (dap_chain_tx_item_event_t *)l_item;
            if (l_event_item->version != DAP_CHAIN_TX_EVENT_VERSION) {
                log_it(L_WARNING, "Event version is not supported in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -3;
            }
            if (!l_event_item->group_name_size) {
                log_it(L_WARNING, "Event group size is 0 in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -4;
            }
            break;
        case TX_ITEM_TYPE_TSD: {
            dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)l_item;
            if (l_tsd->header.size < sizeof(dap_tsd_t)) {
                log_it(L_WARNING, "TSD size is less than expected in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -5;
            }
            dap_tsd_t *l_tsd_data = (dap_tsd_t *)(l_item + sizeof(dap_chain_tx_tsd_t));
            if (l_tsd_data->size + sizeof(dap_tsd_t) != l_tsd->header.size) {
                log_it(L_WARNING, "TSD size is not equal to expected in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -5;
            }
            if (l_tsd_data->type != DAP_CHAIN_TX_TSD_TYPE_EVENT_DATA)
                continue;
            if (l_tsd_count++) {
                log_it(L_WARNING, "Multiple TSD items in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -6;
            }
            l_event_tsd = l_tsd_data;
        } break;
        case TX_ITEM_TYPE_SIG:
            if (++l_sign_count == 2)
                l_event_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_item);
            break;
        default:
            break;
       }
    }
    if (!l_event_item || !l_event_sign) {
        log_it(L_WARNING, "Event item or sign not found in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -7;
    }
    if (dap_chain_datum_tx_verify_sign(a_tx, 1)) {
        log_it(L_WARNING, "Sign verification failed in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -8;
    }
    dap_hash_t l_event_pkey_hash = {};
    dap_sign_get_pkey_hash(l_event_sign, &l_event_pkey_hash);
    // If no keys are in the allowed list, all keys are allowed by default, change comparision to != 0 to block keys with empty list
    if (dap_ledger_event_pkey_check(a_ledger, &l_event_pkey_hash) == -1) {
        log_it(L_WARNING, "Event pkey %s is not allowed in tx %s", dap_hash_fast_to_str_static(&l_event_pkey_hash),
                                                                   dap_hash_fast_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -9;
    }
    if (l_event_item->event_type == DAP_CHAIN_TX_EVENT_TYPE_SERVICE_DECREE) {
        struct srv_callback_decree_item_t *l_decree_callback_item = NULL;
        uint64_t l_srv_uid = l_event_item->srv_uid.uint64;
        HASH_FIND(hh, l_ledger_pvt->srv_callbacks_decree, &l_srv_uid, sizeof(uint64_t), l_decree_callback_item);
        int ret = -1;
        if (l_decree_callback_item) {
            ret = l_decree_callback_item->callback(a_ledger, a_apply, (dap_tsd_t *)l_event_tsd->data, l_event_tsd->size);
        }
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return a_check_for_apply ? 0 : ret;
    }
    char *l_event_group_name = DAP_NEW_SIZE(char, l_event_item->group_name_size + 1);
    if (!l_event_group_name) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -11;
    }
    dap_strncpy(l_event_group_name, (char *)l_event_item->group_name, l_event_item->group_name_size);
    struct srv_callback_event_verify_item_t *l_event_verify_callback_item = NULL;
    uint64_t l_srv_uid = l_event_item->srv_uid.uint64;
    HASH_FIND(hh, l_ledger_pvt->srv_callbacks_event_verify, &l_srv_uid, sizeof(uint64_t), l_event_verify_callback_item);
    int ret = -1;
    if (l_event_verify_callback_item) {
        ret = l_event_verify_callback_item->callback(a_ledger, l_event_group_name, l_event_item->event_type,
                                                     l_event_tsd ? (dap_tsd_t *)l_event_tsd->data : NULL,
                                                     l_event_tsd ? l_event_tsd->size : 0, a_tx_hash);
    }
    if (ret || !a_apply) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        DAP_DELETE(l_event_group_name);
        if (ret)
            log_it(L_WARNING, "Event %s rejected by service verificator with code %d", dap_hash_fast_to_str_static(a_tx_hash), ret);
        return a_check_for_apply ? 0 : ret;
    }

    if (!a_apply) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return 0;
    }

    l_event = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_event_t, -8);
    *l_event = (dap_ledger_event_t) {
        .group_name = l_event_group_name,
        .tx_hash = *a_tx_hash,
        .event_type = l_event_item->event_type,
        .event_data_size = l_event_tsd ? l_event_tsd->size : 0,
        .pkey_hash = l_event_pkey_hash, 
        .timestamp = l_event_item->timestamp,
        .srv_uid = l_event_item->srv_uid
    };

    if (l_event_tsd) {
        l_event->event_data = DAP_DUP_SIZE((byte_t *)l_event_tsd->data, l_event_tsd->size);
        if (!l_event->event_data) {
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            DAP_DEL_Z(l_event);
            return -12;
        }
    }
    HASH_ADD_BYHASHVALUE(hh, l_ledger_pvt->events, tx_hash, sizeof(dap_hash_fast_t), l_hash_value, l_event);
    // Call event notifiers
    dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(l_event);
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    
    if (l_tx_event) {
        for (dap_list_t *it = l_ledger_pvt->event_notifiers; it; it = it->next) {
            dap_ledger_event_notifier_t *l_notifier = (dap_ledger_event_notifier_t *)it->data;
            if (l_notifier && l_notifier->callback) {
                l_notifier->callback(l_notifier->arg, a_ledger, l_tx_event, a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
            }
        }
        dap_chain_datum_tx_event_delete(l_tx_event);
    }

    return 0;
}


/**
 * @brief dap_ledger_check_event_pkey
 * @param a_ledger The ledger instance
 * @param a_pkey_hash Hash of the public key to check
 * @return 1 if no keys set, 0 if the key is allowed, -1 if not allowed
 */
 int dap_ledger_event_pkey_check(dap_ledger_t *a_ledger, dap_hash_fast_t *a_pkey_hash)
 {
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->event_pkeys_rwlock);
    dap_ledger_event_pkey_item_t *l_item = NULL;
    if (!l_ledger_pvt->event_pkeys_allowed) {
        pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
        return 1;
    }    
    HASH_FIND(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_fast_t), l_item);
    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
     
     // If key found in allowed list - it's allowed
     return l_item ? 0 : -1;
 }
 
 /**
  * @brief dap_ledger_event_pkey_add
  * @param a_ledger The ledger instance
  * @param a_pkey_hash Hash of the public key to add to allowed list
  * @return 0 on success, -1 on error
  */
 int dap_ledger_event_pkey_add(dap_ledger_t *a_ledger, dap_hash_fast_t *a_pkey_hash)
 {
     if (!a_ledger || !a_pkey_hash)
         return -1;
     
     dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
     pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);
     
     dap_ledger_event_pkey_item_t *l_item = NULL;
     HASH_FIND(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_fast_t), l_item);
     if (l_item) {
         // Already exists
         pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
         return -1;
     }
     
     l_item = DAP_NEW_Z(dap_ledger_event_pkey_item_t);
     if (!l_item) {
         pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
         log_it(L_CRITICAL, "Memory allocation error");
         return -1;
     }
     
     memcpy(&l_item->pkey_hash, a_pkey_hash, sizeof(dap_hash_fast_t));
     HASH_ADD(hh, l_ledger_pvt->event_pkeys_allowed, pkey_hash, sizeof(dap_hash_fast_t), l_item);
     
     pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
     return 0;
 }
 
 /**
  * @brief dap_ledger_event_pkey_rm
  * @param a_ledger The ledger instance
  * @param a_pkey_hash Hash of the public key to remove from allowed list
  * @return 0 on success, -1 on error or if not found
  */
 int dap_ledger_event_pkey_rm(dap_ledger_t *a_ledger, dap_hash_fast_t *a_pkey_hash)
 {
     if (!a_ledger || !a_pkey_hash)
         return -1;
     
     dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
     pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);
     
     dap_ledger_event_pkey_item_t *l_item = NULL;
     HASH_FIND(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_fast_t), l_item);
     if (!l_item) {
         // Not found
         pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
         return -1;
     }
     
     HASH_DEL(l_ledger_pvt->event_pkeys_allowed, l_item);
     DAP_DELETE(l_item);
     
     pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
     return 0;
 }
 
 /**
  * @brief dap_ledger_event_pkey_list
  * @param a_ledger The ledger instance
  * @return dap_list_t* List of dap_hash_fast_t* pointers to allowed public key hashes, NULL if empty or on error
  */
 dap_list_t *dap_ledger_event_pkey_list(dap_ledger_t *a_ledger)
 {
     if (!a_ledger)
         return NULL;
     
     dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
     pthread_rwlock_rdlock(&l_ledger_pvt->event_pkeys_rwlock);
     
     dap_list_t *l_list = NULL;
     dap_ledger_event_pkey_item_t *l_item = NULL, *l_tmp = NULL;
     
     HASH_ITER(hh, l_ledger_pvt->event_pkeys_allowed, l_item, l_tmp) {
         dap_hash_fast_t *l_hash_copy = DAP_NEW_Z(dap_hash_fast_t);
         if (!l_hash_copy) {
             log_it(L_CRITICAL, "%s", c_error_memory_alloc);
             break;
         }
         memcpy(l_hash_copy, &l_item->pkey_hash, sizeof(dap_hash_fast_t));
         l_list = dap_list_append(l_list, l_hash_copy);
     }
     
     pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
     return l_list;
 }

int dap_ledger_srv_callback_decree_add(dap_ledger_t *a_ledger, dap_chain_net_srv_uid_t a_srv_uid, dap_ledger_srv_callback_decree_t a_callback)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->srv_callbacks_rwlock);
    struct srv_callback_decree_item_t *l_item = NULL;
    uint64_t l_srv_uid = a_srv_uid.uint64;
    HASH_FIND(hh, l_ledger_pvt->srv_callbacks_decree, &l_srv_uid, sizeof(uint64_t), l_item);
    if (l_item) {
        log_it(L_WARNING, "Service callback for decree already exists for srv %" DAP_UINT64_FORMAT_U, a_srv_uid.uint64);
        pthread_rwlock_unlock(&l_ledger_pvt->srv_callbacks_rwlock);
        return 1;
    }
    l_item = DAP_NEW_Z(struct srv_callback_decree_item_t);
    if (!l_item) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        pthread_rwlock_unlock(&l_ledger_pvt->srv_callbacks_rwlock);
        return -1;
    }
    l_item->srv_uid = a_srv_uid.uint64;
    l_item->callback = a_callback;
    HASH_ADD(hh, l_ledger_pvt->srv_callbacks_decree, srv_uid, sizeof(uint64_t), l_item);
    pthread_rwlock_unlock(&l_ledger_pvt->srv_callbacks_rwlock);
    return 0;
}

int dap_ledger_srv_callback_event_verify_add(dap_ledger_t *a_ledger, dap_chain_net_srv_uid_t a_srv_uid, dap_ledger_srv_callback_event_verify_t a_callback)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->srv_callbacks_rwlock);
    struct srv_callback_event_verify_item_t *l_item = NULL;
    uint64_t l_srv_uid = a_srv_uid.uint64;
    HASH_FIND(hh, l_ledger_pvt->srv_callbacks_event_verify, &l_srv_uid, sizeof(uint64_t), l_item);
    if (l_item) {
        log_it(L_WARNING, "Service callback for event verify already exists for srv %" DAP_UINT64_FORMAT_U, a_srv_uid.uint64);
        pthread_rwlock_unlock(&l_ledger_pvt->srv_callbacks_rwlock);
        return 1;
    }
    l_item = DAP_NEW_Z(struct srv_callback_event_verify_item_t);
    if (!l_item) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        pthread_rwlock_unlock(&l_ledger_pvt->srv_callbacks_rwlock);
        return -1;
    }
    l_item->srv_uid = a_srv_uid.uint64;
    l_item->callback = a_callback;
    HASH_ADD(hh, l_ledger_pvt->srv_callbacks_event_verify, srv_uid, sizeof(uint64_t), l_item);
    pthread_rwlock_unlock(&l_ledger_pvt->srv_callbacks_rwlock);
    return 0;
}

// UTXO blocklist functions moved to dap_chain_ledger_utxo.c module
// Arbitrage transaction support functions moved to dap_chain_arbitrage.c module
﻿/*
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

#include "dap_common.h"
#include <dirent.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
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
#include "dap_chain_datum_tx_in_ems.h"
#include "dap_chain_datum_token.h"
#include "dap_global_db.h"
#include "dap_chain_ledger.h"
#include "json.h"
#include "json_object.h"
#include "dap_notify_srv.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_datum_tx_voting.h"

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
    UT_hash_handle hh;
} dap_ledger_service_info_t;

static dap_ledger_verificator_t *s_verificators;
static dap_ledger_service_info_t *s_services;

static  pthread_rwlock_t s_verificators_rwlock;
static  pthread_rwlock_t s_services_rwlock;

static dap_chain_ledger_votings_callbacks_t s_voting_callbacks;

typedef struct dap_ledger_stake_lock_item {
    dap_chain_hash_fast_t	tx_for_stake_lock_hash;
    dap_chain_hash_fast_t	tx_used_out;
    UT_hash_handle hh;
} dap_ledger_stake_lock_item_t;

typedef struct dap_ledger_token_emission_item {
    dap_chain_hash_fast_t datum_token_emission_hash;
    dap_chain_datum_token_emission_t *datum_token_emission;
    size_t datum_token_emission_size;
    dap_chain_hash_fast_t tx_used_out;
    dap_nanotime_t ts_added;
    UT_hash_handle hh;
} dap_ledger_token_emission_item_t;

typedef struct dap_ledger_token_update_item {
    dap_hash_fast_t			update_token_hash;
    dap_chain_datum_token_t	*datum_token_update;
    size_t					datum_token_update_size;
    time_t					updated_time;
    UT_hash_handle hh;
} dap_ledger_token_update_item_t;

typedef struct dap_ledger_token_item {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint16_t subtype;
    dap_chain_datum_token_t *datum_token;
    uint64_t datum_token_size;

    uint256_t total_supply;
    uint256_t current_supply;

    pthread_rwlock_t token_emissions_rwlock;
    dap_ledger_token_emission_item_t * token_emissions;

    pthread_rwlock_t token_ts_updated_rwlock;
    dap_ledger_token_update_item_t * token_ts_updated;
    time_t last_update_token_time;

    // for auth operations

    dap_pkey_t ** auth_pkeys;
    dap_chain_hash_fast_t *auth_pkey_hashes;
    size_t auth_signs_total;
    size_t auth_signs_valid;
    uint32_t           flags;
    dap_chain_addr_t * tx_recv_allow;
    size_t             tx_recv_allow_size;
    dap_chain_addr_t * tx_recv_block;
    size_t             tx_recv_block_size;
    dap_chain_addr_t * tx_send_allow;
    size_t             tx_send_allow_size;
    dap_chain_addr_t * tx_send_block;
    size_t             tx_send_block_size;
    char *description;
    // For delegated tokens
    bool is_delegated;
    char delegated_from[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t emission_rate;

    UT_hash_handle hh;
} dap_ledger_token_item_t;

// ledger cache item - one of unspent outputs
typedef struct dap_ledger_tx_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    dap_nanotime_t ts_added;
    UT_hash_handle hh;
    struct {
        dap_time_t ts_created;      // Transation datum timestamp mirrored & cached
        uint32_t n_outs;
        uint32_t n_outs_used;
        char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        byte_t padding[6];
        byte_t multichannel;
        dap_time_t ts_spent;
        byte_t pad[7];
        dap_chain_net_srv_uid_t tag; //tag (or service this tx is belong to)
        dap_chain_tx_tag_action_type_t action;
        dap_chain_hash_fast_t tx_hash_spent_fast[]; // spent outs list
    } DAP_ALIGN_PACKED cache_data;
} dap_ledger_tx_item_t;

typedef struct  dap_ledger_cache_gdb_record {
    uint64_t cache_size;
    uint64_t datum_size;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_ledger_cache_gdb_record_t;

typedef struct dap_ledger_tokenizer {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t sum;
    UT_hash_handle hh;
} dap_ledger_tokenizer_t;

typedef struct dap_ledger_reward_key {
    dap_hash_fast_t block_hash;
    dap_hash_fast_t sign_pkey_hash;
} DAP_ALIGN_PACKED dap_ledger_reward_key_t;

typedef struct dap_ledger_reward_item {
    dap_ledger_reward_key_t key;
    dap_hash_fast_t spender_tx;
    UT_hash_handle hh;
} dap_ledger_reward_item_t;

typedef struct dap_ledger_tx_bound {
    uint8_t type;
    uint16_t prev_out_idx;
    uint256_t value;
    union {
        dap_ledger_token_item_t *token_item;    // For current_supply update on emissions
        dap_chain_tx_out_cond_t *cond;          // For conditional output
        struct {
            char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_addr_t addr_from;
        } in;
    };
    union {
        dap_ledger_tx_item_t *prev_item;        // For not emission TX
        dap_ledger_token_emission_item_t *emission_item;
        dap_ledger_stake_lock_item_t *stake_lock_item;
        dap_ledger_reward_key_t reward_key;
    };
} dap_ledger_tx_bound_t;

// in-memory wallet balance
typedef struct dap_ledger_wallet_balance {
    char *key;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t balance;
    UT_hash_handle hh;
} dap_ledger_wallet_balance_t;

typedef struct dap_ledger_cache_item {
    dap_chain_hash_fast_t *hash;
    bool found;
} dap_ledger_cache_item_t;

typedef struct dap_ledger_cache_str_item {
    char *key;
    bool found;
} dap_ledger_cache_str_item_t;

typedef struct dap_ledger_tx_notifier {
    dap_ledger_tx_add_notify_t callback;
    void *arg;
} dap_ledger_tx_notifier_t;

typedef struct dap_ledger_bridged_tx_notifier {
    dap_ledger_bridged_tx_notify_t callback;
    void *arg;
} dap_ledger_bridged_tx_notifier_t;

typedef struct dap_ledger_hal_item {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_ledger_hal_item_t;

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
    // Save/load operations condition
    pthread_mutex_t load_mutex;
    pthread_cond_t load_cond;
    bool load_end;
    // Ledger flags
    bool check_ds, check_cells_ds, check_token_emission, cached, mapped, threshold_enabled;
    dap_chain_cell_id_t local_cell_id;
    //notifiers
    dap_list_t *bridged_tx_notifiers;
    dap_list_t *tx_add_notifiers;
    dap_ledger_cache_tx_check_callback_t cache_tx_check_callback;
    // White- and blacklist
    dap_ledger_hal_item_t *hal_items, *hrl_items;
} dap_ledger_private_t;

#define PVT(a) ( (dap_ledger_private_t *) a->_internal )

static void s_threshold_emissions_proc( dap_ledger_t * a_ledger);
static void s_threshold_txs_proc( dap_ledger_t * a_ledger);
static void s_threshold_txs_free(dap_ledger_t *a_ledger);
static int s_sort_ledger_tx_item(dap_ledger_tx_item_t* a, dap_ledger_tx_item_t* b);

static size_t s_threshold_emissions_max = 1000;
static size_t s_threshold_txs_max = 10000;
static bool s_debug_more = true;
static size_t s_threshold_free_timer_tick = 900000; // 900000 ms = 15 minutes.

struct json_object *wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t* a_bal);
int dap_ledger_pvt_balance_update_for_addr(dap_ledger_t *a_ledger, dap_chain_addr_t *a_addr, const char *a_token_ticker, uint256_t a_value, bool a_reverse);

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

dap_chain_tx_out_cond_t* dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(dap_ledger_t *a_ledger, dap_chain_tx_in_cond_t *a_in_cond)
{
        dap_hash_fast_t *l_tx_prev_hash = &a_in_cond->header.tx_prev_hash;    
        uint32_t l_tx_prev_out_idx = a_in_cond->header.tx_out_prev_idx;
        dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash (a_ledger,l_tx_prev_hash);
        
        if (!l_tx_prev) return NULL;
        byte_t* l_item_res = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
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

    l_new_sinfo = DAP_NEW(dap_ledger_service_info_t);
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

/**
 * @brief dap_ledger_init
 * current function version set s_debug_more parameter, if it define in config, and returns 0
 * @return
 */
int dap_ledger_init()
{
    s_debug_more = dap_config_get_item_bool_default(g_config,"ledger","debug_more",false);
    
    pthread_rwlock_init(&s_verificators_rwlock, NULL);
    pthread_rwlock_init(&s_services_rwlock, NULL);

    //register native ledger services
    dap_chain_net_srv_uid_t l_uid_transfer = { .uint64 = DAP_CHAIN_NET_SRV_TRANSFER_ID };
    dap_ledger_service_add(l_uid_transfer, "transfer", s_tag_check_transfer);

    dap_chain_net_srv_uid_t l_uid_breward = { .uint64 = DAP_CHAIN_NET_SRV_BLOCK_REWARD_ID };
    dap_ledger_service_add(l_uid_breward, "block_reward", s_tag_check_block_reward);
    return 0;
}

/**
 * @brief dap_ledger_deinit
 * nothing do
 */
void dap_ledger_deinit()
{
    pthread_rwlock_destroy(&s_verificators_rwlock);
    pthread_rwlock_destroy(&s_services_rwlock);
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
    pthread_rwlock_init(&l_ledger_pvt->ledger_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->tokens_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->threshold_txs_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->balance_accounts_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->stake_lock_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->rewards_rwlock, NULL);
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
    // Destroy Read/Write Lock
    pthread_rwlock_destroy(&PVT(a_ledger)->ledger_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->tokens_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->threshold_txs_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->balance_accounts_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->stake_lock_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->rewards_rwlock);
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
    debug_if(s_debug_more && ret, L_MSG, "Datum %s is whitelisted", dap_hash_fast_to_str_static(a_hal_hash));
    return ret;
}

bool dap_ledger_datum_is_blacklisted(dap_ledger_t *a_ledger, dap_hash_fast_t a_hash) {
    dap_ledger_hal_item_t *ret = NULL;
    HASH_FIND(hh, PVT(a_ledger)->hrl_items, &a_hash, sizeof(dap_hash_fast_t), ret);
    return debug_if(s_debug_more && ret, L_MSG, "Datum %s is blacklisted", dap_hash_fast_to_str_static(&a_hash)), !!ret;
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
 * @param a_ledger
 * @param a_item_apply_to
 * @param a_token
 * @param a_token_size
 * @return int
 */
static int s_token_tsd_parse(dap_ledger_token_item_t *a_item_apply_to, dap_chain_datum_token_t *a_current_datum,
                             dap_ledger_t *a_ledger, byte_t *a_tsd, size_t a_tsd_total_size, bool a_apply)
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
    dap_chain_addr_t *l_new_tx_recv_allow = NULL, *l_new_tx_recv_block = NULL,
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
                l_new_tx_recv_allow = DAP_DUP_SIZE(a_item_apply_to->tx_recv_allow, l_new_tx_recv_allow_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_recv_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_allow_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_recv_allow_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_recv_allow + i, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_RECEIVER_ALLOWED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            dap_chain_addr_t *l_tmp = DAP_REALLOC_COUNT(l_new_tx_recv_allow, l_new_tx_recv_allow_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_recv_allow = l_tmp;
            l_new_tx_recv_allow[l_new_tx_recv_allow_size++] = *l_add_addr;
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
                l_new_tx_recv_allow = DAP_DUP_SIZE(a_item_apply_to->tx_recv_allow, l_new_tx_recv_allow_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_recv_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_allow_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_recv_allow_size; i++) // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_recv_allow + i, l_add_addr))
                    break;
            if (i == l_new_tx_recv_allow_size) {
                log_it(L_WARNING, "TSD param TX_RECEIVER_ALLOWED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing
            if (--l_new_tx_recv_allow_size > i)
                memmove(l_new_tx_recv_allow + i, l_new_tx_recv_allow + i + 1,
                        (l_new_tx_recv_allow_size - i - 1) * sizeof(dap_chain_addr_t));
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
            l_was_tx_recv_block_copied = true;
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
                l_new_tx_recv_block = DAP_DUP_SIZE(a_item_apply_to->tx_recv_block, l_new_tx_recv_block_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_recv_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_block_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_recv_block_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_recv_block + i, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_RECEIVER_BLOCKED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            dap_chain_addr_t *l_tmp = DAP_REALLOC_COUNT(l_new_tx_recv_block, l_new_tx_recv_block_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_recv_block = l_tmp;
            l_new_tx_recv_block[l_new_tx_recv_block_size++] = *l_add_addr;
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
                l_new_tx_recv_block = DAP_DUP_SIZE(a_item_apply_to->tx_recv_block, l_new_tx_recv_block_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_recv_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_recv_block_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_recv_block_size; i++) // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_recv_block + i, l_add_addr))
                    break;
            if (i == l_new_tx_recv_block_size) {
                log_it(L_WARNING, "TSD param TX_RECEIVER_BLOCKED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing
            if (--l_new_tx_recv_block_size > i)
                memmove(l_new_tx_recv_block + i, l_new_tx_recv_block + i + 1,
                        (l_new_tx_recv_block_size - i - 1) * sizeof(dap_chain_addr_t));
            // Memory clearing
            if (l_new_tx_recv_block_size)
                l_new_tx_recv_block = DAP_REALLOC(l_new_tx_recv_block,
                                                          l_new_tx_recv_block_size * sizeof(dap_chain_addr_t));
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
                l_new_tx_send_allow = DAP_DUP_SIZE(a_item_apply_to->tx_send_allow, l_new_tx_send_allow_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_send_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_allow_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_send_allow_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_send_allow + i, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_SENDER_ALLOWED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            dap_chain_addr_t *l_tmp = DAP_REALLOC_COUNT(l_new_tx_send_allow, l_new_tx_send_allow_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_send_allow = l_tmp;
            l_new_tx_send_allow[l_new_tx_send_allow_size++] = *l_add_addr;
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
                l_new_tx_send_allow = DAP_DUP_SIZE(a_item_apply_to->tx_send_allow, l_new_tx_send_allow_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_send_allow) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_allow_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_send_allow_size; i++) // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_send_allow + i, l_add_addr))
                    break;
            if (i == l_new_tx_send_allow_size) {
                log_it(L_WARNING, "TSD param TX_SENDER_ALLOWED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing
            if (--l_new_tx_send_allow_size > i)
                memmove(l_new_tx_send_allow + i, l_new_tx_send_allow + i + 1,
                        (l_new_tx_send_allow_size - i - 1) * sizeof(dap_chain_addr_t));
            // Memory clearing
            if (l_new_tx_send_allow_size)
                l_new_tx_send_allow = DAP_REALLOC(l_new_tx_send_allow,
                                                          l_new_tx_send_allow_size * sizeof(dap_chain_addr_t));
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
                l_new_tx_send_block = DAP_DUP_SIZE(a_item_apply_to->tx_send_block, l_new_tx_send_block_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_send_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_block_copied = true;
            // Check if its already present
            for (size_t i = 0; i < l_new_tx_send_block_size; i++) { // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_send_block + i, l_add_addr)) { // Found
                    log_it(L_WARNING, "TSD param TX_SENDER_BLOCKED_ADD has address %s thats already present in list",
                                                                    dap_chain_addr_to_str_static(l_add_addr));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
                }
            }
            if (!a_apply)
                break;
            dap_chain_addr_t *l_tmp = DAP_REALLOC_COUNT(l_new_tx_send_block, l_new_tx_send_block_size + 1);
            if (!l_tmp) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            }
            l_new_tx_send_block = l_tmp;
            l_new_tx_send_block[l_new_tx_send_block_size++] = *l_add_addr;
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
                l_new_tx_send_block = DAP_DUP_SIZE(a_item_apply_to->tx_send_block, l_new_tx_send_block_size * sizeof(dap_chain_addr_t));
                if (!l_new_tx_send_block) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return m_ret_cleanup(DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
                }
            }
            l_was_tx_send_block_copied = true;
            // Check if its already present
            size_t i = 0;
            for ( ; i < l_new_tx_send_block_size; i++) // Check for all the list
                if (dap_chain_addr_compare(l_new_tx_send_block + i, l_add_addr))
                    break;
            if (i == l_new_tx_send_block_size) {
                log_it(L_WARNING, "TSD param TX_SENDER_BLOCKED_REMOVE has address %s thats not present in list",
                        dap_chain_addr_to_str_static(l_add_addr));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH);
            }
            // Addr removing
            if (--l_new_tx_send_block_size > i)
                memmove(l_new_tx_send_block + i, l_new_tx_send_block + i + 1,
                        (l_new_tx_send_block_size - i - 1) * sizeof(dap_chain_addr_t));
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
            // Check if its already present
            dap_hash_t l_new_auth_pkey_hash;
            dap_pkey_get_hash(l_new_auth_pkey, &l_new_auth_pkey_hash);
            for (size_t i = 0; i < l_new_signs_total; i++) {
                if (dap_pkey_compare(l_new_auth_pkey, l_new_pkeys[i])) {
                    log_it(L_WARNING, "TSD param TOTAL_PKEYS_ADD has pkey %s thats already present in list",
                                                                    dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                    return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_PKEY_MISMATCH);
                }
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
                log_it(L_WARNING, "TSD param TOTAL_PKEYS_REMOVE has public key hash %s thats not present in list",
                                                    dap_hash_fast_to_str_static(&l_new_auth_pkey_hash));
                return m_ret_cleanup(DAP_LEDGER_TOKEN_ADD_CHECK_TSD_PKEY_MISMATCH);
            }
            // Pkey removing
            DAP_DELETE(l_new_pkeys[i]);
            if (--l_new_signs_total > i) {
                memmove(l_new_pkeys + i, l_new_pkeys + i + 1, (l_new_signs_total - i - 1) * sizeof(dap_pkey_t *));
                memmove(l_new_pkey_hashes + i, l_new_pkey_hashes + i + 1, (l_new_signs_total - i - 1) * sizeof(dap_hash_t));
            }
            // Memory clearing
            if (l_new_signs_total) {
                l_new_pkeys = DAP_REALLOC_COUNT(l_new_pkeys, l_new_signs_total);
                l_new_pkey_hashes = DAP_REALLOC_COUNT(l_new_pkey_hashes, l_new_signs_total);
            } else
                DAP_DEL_MULTY(l_new_pkeys, l_new_pkey_hashes);
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
    int ret = s_token_tsd_parse(l_token_item, l_token, a_ledger, l_token->tsd_n_signs, l_size_tsd_section, false);
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
 * @brief update current_supply in token cache
 *
 * @param a_ledger ledger object
 * @param l_token_item token item object
 */
void s_ledger_token_cache_update(dap_ledger_t *a_ledger, dap_ledger_token_item_t *l_token_item)
{
    if (!PVT(a_ledger)->cached)
        return;
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TOKENS_STR);
    size_t l_cache_size = l_token_item->datum_token_size + sizeof(uint256_t);
    uint8_t *l_cache = DAP_NEW_STACK_SIZE(uint8_t, l_cache_size);
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
int dap_ledger_token_add(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size)
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
                .flags = 0
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
        ret = s_token_tsd_parse(l_token_item, l_token, a_ledger, l_token->tsd_n_signs, l_tsd_total_size, true);
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

int dap_ledger_token_load(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size)
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
    return dap_ledger_token_add(a_ledger, a_token, a_token_size);
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

json_object *dap_ledger_threshold_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, dap_chain_hash_fast_t *a_threshold_hash, bool a_head, int a_version)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_tx_item = NULL, *l_tx_tmp;
    json_object *json_arr_out = json_object_new_array();
    if (!json_arr_out)
        return NULL;
    uint32_t l_counter = 0;
    size_t l_arr_start = 0;
    size_t l_arr_end = 0;
    dap_chain_set_offset_limit_json(json_arr_out, &l_arr_start, &l_arr_end, a_limit, a_offset, HASH_COUNT(l_ledger_pvt->threshold_txs),false);

    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
    if (a_threshold_hash) {
        json_object *json_obj_tx = json_object_new_object();
        if (!json_obj_tx) {
            pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            json_object_put(json_arr_out);
            return NULL;
        }
        HASH_FIND(hh, l_ledger_pvt->threshold_txs, a_threshold_hash, sizeof(dap_hash_t), l_tx_item);
        if (l_tx_item) {
            json_object_object_add(json_obj_tx, a_version == 1 ? "Hash was found in ledger tx threshold" : "tx_hash", json_object_new_string(dap_hash_fast_to_str_static(a_threshold_hash)));
            json_object_array_add(json_arr_out, json_obj_tx);
        } else {
            json_object_object_add(json_obj_tx, a_version == 1 ? "Hash wasn't found in ledger" : "tx_hash", json_object_new_string("empty"));
            json_object_array_add(json_arr_out, json_obj_tx);
        }
    } else {
        size_t i_tmp = 0;
        if (a_head)
        HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp) {
            if (i_tmp < l_arr_start || i_tmp >= l_arr_end)
            {
                i_tmp++;                
                continue;
            }
            i_tmp++;
            if (s_pack_ledger_threshold_info_json(json_arr_out, l_tx_item, a_version)) {
                pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
                json_object_put(json_arr_out);
                return NULL;
            }            
            l_counter++;
        }
        else
        {
            l_tx_item = HASH_LAST(l_ledger_pvt->threshold_txs);
            for(; l_tx_item; l_tx_item = l_tx_item->hh.prev, i_tmp++){
                if (i_tmp < l_arr_start || i_tmp >= l_arr_end)
                    continue;
                if (s_pack_ledger_threshold_info_json(json_arr_out, l_tx_item, a_version)) {
                    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
                    json_object_put(json_arr_out);
                    return NULL;
                }
                l_counter++;
            }
        }
        if (!l_counter) {
            json_object* json_obj_tx = json_object_new_object();
            json_object_object_add(json_obj_tx, "status", json_object_new_string("0 items in ledger tx threshold"));
            json_object_array_add(json_arr_out, json_obj_tx);
        }
        pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
    }

    return json_arr_out;
}

json_object *dap_ledger_balance_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, bool a_head, int a_version)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    json_object * json_arr_out = json_object_new_array();
    pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
    uint32_t l_counter = 0;
    dap_ledger_wallet_balance_t *l_balance_item, *l_balance_tmp;
    size_t l_arr_start = 0;
    size_t l_arr_end = 0;
    dap_chain_set_offset_limit_json(json_arr_out, &l_arr_start, &l_arr_end, a_limit, a_offset, HASH_COUNT(l_ledger_pvt->balance_accounts),false);

    size_t i_tmp = 0;
    if (a_head)
        HASH_ITER(hh, l_ledger_pvt->balance_accounts, l_balance_item, l_balance_tmp) {
            if (i_tmp < l_arr_start || i_tmp >= l_arr_end) {
                i_tmp++;
                continue;
            }
            i_tmp++;
            s_pack_ledger_balance_info_json(json_arr_out, l_balance_item, a_version);
            l_counter +=1;
        }
    else {
        l_balance_item = HASH_LAST(l_ledger_pvt->balance_accounts);
            for(; l_balance_item; l_balance_item = l_balance_item->hh.prev, i_tmp++){
                if (i_tmp < l_arr_start || i_tmp >= l_arr_end)
                    continue;
                s_pack_ledger_balance_info_json(json_arr_out, l_balance_item, a_version);
                l_counter++;
            }
    }
    if (!l_counter){
        json_object* json_obj_tx = json_object_new_object();
        json_object_object_add(json_obj_tx, a_version == 1 ? "No items in ledger balance_accounts" : "info_status", json_object_new_string("empty"));
        json_object_array_add(json_arr_out, json_obj_tx);
    } 
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
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
    debug_if(s_debug_more, L_INFO, " ! Token %s : total %lu auth signs", a_token_ticker, l_token_item->auth_signs_total);
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

json_object *s_token_item_to_json(dap_ledger_token_item_t *a_token_item, int a_version)
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
        dap_chain_addr_t l_addr = a_token_item->tx_recv_allow[i];
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        json_object_array_add(l_json_arr_tx_recv_allow, json_object_new_string(l_addr_str));
    }
    json_object *l_json_arr_tx_recv_block = json_object_new_array();
    for (size_t i = 0; i < a_token_item->tx_recv_block_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_recv_block[i];
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        json_object_array_add(l_json_arr_tx_recv_block, json_object_new_string(l_addr_str));
    }
    json_object *l_json_arr_tx_send_allow = json_object_new_array();
    for (size_t i = 0; i < a_token_item->tx_send_allow_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_send_allow[i];
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        json_object_array_add(l_json_arr_tx_send_allow, json_object_new_string(l_addr_str));
    }
    json_object *l_json_arr_tx_send_block = json_object_new_array();
    for (size_t i = 0; i < a_token_item->tx_send_block_size; i++) {
        dap_chain_addr_t l_addr = a_token_item->tx_send_block[i];
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
        json_object_array_add(l_json_arr_tx_send_block, json_object_new_string(l_addr_str));
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
    json_object_object_add(json_obj_datum, a_version == 1 ? "Total emissions" : "total_emissions", json_object_new_int(HASH_COUNT(a_token_item->token_emissions)));
    return json_obj_datum;
}

/**
 * @brief Compose string list of all tokens with information
 * @param a_ledger
 * @return
 */
json_object *dap_ledger_token_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, int a_version)
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
        json_obj_datum = s_token_item_to_json(l_token_item, a_version);
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
json_object *dap_ledger_token_info_by_name(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version)
{
    dap_ledger_token_item_t *l_token_item = NULL;
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token_ticker, l_token_item);
    if (l_token_item)
        return s_token_item_to_json(l_token_item, a_version);
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
                if ( !l_ledger_pvt->mapped )
                    DAP_DELETE(l_tx_item->tx);
                DAP_DELETE(l_tx_item);
                l_success = true;
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
            if ( !l_pvt->mapped )
                DAP_DELETE(l_current->tx);
            DAP_DELETE(l_current);
            log_it(L_NOTICE, "Removed transaction %s form threshold ledger", l_tx_hash_str);
        }
    }
    pthread_rwlock_unlock(&l_pvt->threshold_txs_rwlock);
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
    for (size_t i = 0; i < a_values_count; i++) {
        dap_ledger_cache_gdb_record_t *l_current_record = (dap_ledger_cache_gdb_record_t*)a_values[i].value;
        if (a_values[i].value_len != l_current_record->cache_size + l_current_record->datum_size + sizeof(dap_ledger_cache_gdb_record_t)) {
            log_it(L_ERROR, "Worng ledger_cache_gdb_record size");
            return false;
        }
        dap_ledger_tx_item_t *l_tx_item = DAP_NEW_Z_SIZE(dap_ledger_tx_item_t, sizeof(dap_ledger_tx_item_t) - sizeof(l_tx_item->cache_data) + l_current_record->cache_size);
        if ( !l_tx_item ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return false;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_tx_item->tx_hash_fast);
        l_tx_item->tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, l_current_record->datum_size);
        if ( !l_tx_item->tx ) {
            DAP_DELETE(l_tx_item);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return false;
        }
        memcpy(&l_tx_item->cache_data, l_current_record->data, l_current_record->cache_size);
        memcpy(l_tx_item->tx, l_current_record->data + l_current_record->cache_size, l_current_record->datum_size);
        l_tx_item->ts_added = dap_nanotime_now();
        HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item, s_sort_ledger_tx_item);
    }
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

    char* l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_LEDGER_TXS_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_txs_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
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

    char* l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_LEDGER_STAKE_LOCK_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_stake_lock_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
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
    if(a_rc) {
        log_it(L_NOTICE, "No ledger cache found");
        pthread_mutex_lock(&l_ledger_pvt->load_mutex);
        l_ledger_pvt->load_end = true;
        pthread_cond_broadcast(&l_ledger_pvt->load_cond );
        pthread_mutex_unlock(&l_ledger_pvt->load_mutex);

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
        dap_ledger_token_add(l_ledger, (byte_t *)l_token, l_token_size);
        dap_ledger_token_item_t *l_token_item = s_ledger_find_token(l_ledger, l_token->ticker);
        if (l_token_item)
            l_token_item->current_supply = *(uint256_t*)a_values[i].value;
    }

    char *l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_LEDGER_EMISSIONS_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_emissions_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
    return true;
}

/**
 * @brief Load ledger from cache (stored in GDB)
 * @param a_ledger
 */
void dap_ledger_load_cache(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TOKENS_STR);

    pthread_mutex_lock(& l_ledger_pvt->load_mutex);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_tokens_callback, a_ledger);
    while (!l_ledger_pvt->load_end)
        pthread_cond_wait(& l_ledger_pvt->load_cond, &l_ledger_pvt->load_mutex);
    pthread_mutex_unlock(& l_ledger_pvt->load_mutex);

    DAP_DELETE(l_gdb_group);
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
    if (l_ledger_pvt->threshold_enabled)
        l_ledger_pvt->threshold_txs_free_timer = dap_interval_timer_create(s_threshold_free_timer_tick,
                                                                      (dap_timer_callback_t)s_threshold_txs_free, l_ledger);
    pthread_cond_init(&l_ledger_pvt->load_cond, NULL);
    pthread_mutex_init(&l_ledger_pvt->load_mutex, NULL);

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
    if ( l_ledger_pvt->cached )
        // load ledger cache from GDB
        dap_ledger_load_cache(l_ledger);
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
static bool s_ledger_permissions_check(dap_ledger_token_item_t *a_token_item, enum ledger_permissions a_permission_id, dap_chain_addr_t *a_addr)
{
    dap_chain_addr_t *l_addrs = NULL;
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
        if (dap_chain_addr_compare(l_addrs + n, a_addr))
            return true;
    return false;
}

dap_ledger_check_error_t s_ledger_addr_check(dap_ledger_token_item_t *a_token_item, dap_chain_addr_t *a_addr, bool a_receive)
{
    dap_return_val_if_fail(a_token_item && a_addr, DAP_LEDGER_CHECK_INVALID_ARGS);
    if (dap_chain_addr_is_blank(a_addr))
        return DAP_LEDGER_CHECK_OK;
    if (a_receive) {
        if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN)) {
            // Check we are in white list
            if (!s_ledger_permissions_check(a_token_item, LEDGER_PERMISSION_RECEIVER_ALLOWED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        } else if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN)) {
            // Check we are in black list
            if (s_ledger_permissions_check(a_token_item, LEDGER_PERMISSION_RECEIVER_BLOCKED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        }
    } else {
        if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN)) {
            // Check we are in white list
            if (!s_ledger_permissions_check(a_token_item, LEDGER_PERMISSION_SENDER_ALLOWED, a_addr))
                return DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
        } else if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED) ||
                (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN)) {
            // Check we are in black list
            if (s_ledger_permissions_check(a_token_item, LEDGER_PERMISSION_SENDER_BLOCKED, a_addr))
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
        dap_ledger_check_error_t ret = s_ledger_addr_check(l_token_item, &l_emission->hdr.address, true);
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
        for (uint16_t i = 0; i < l_signs_unique; i++) {
            for (uint16_t k = 0; k < l_token_item->auth_signs_total; k++) {
                if (dap_pkey_compare_with_sign(l_token_item->auth_pkeys[k], l_signs[i])) {
                    // Verify if token emission is signed
                    if (!dap_sign_verify(l_signs[i], l_emission, l_sign_data_check_size))
                        l_aproves++;
                    break;
                }
            }
        }
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
    if (!PVT(a_ledger)->cached)
        return;
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_EMISSIONS_STR);
    size_t l_cache_size = a_emission_item->datum_token_emission_size + sizeof(dap_hash_fast_t);
    uint8_t *l_cache = DAP_NEW_STACK_SIZE(uint8_t, l_cache_size);
    memcpy(l_cache, &a_emission_item->tx_used_out, sizeof(dap_hash_fast_t));
    memcpy(l_cache + sizeof(dap_hash_fast_t), a_emission_item->datum_token_emission, a_emission_item->datum_token_emission_size);
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_emission_item->datum_token_emission_hash, l_hash_str, sizeof(l_hash_str));
    if (dap_global_db_set(l_gdb_group, l_hash_str, l_cache, l_cache_size, false, NULL, NULL)) {
        log_it(L_WARNING, "Ledger cache mismatch");
    }
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
         l_emission_item = s_emission_item_find(a_ledger, l_item->ticker, a_token_emission_hash, NULL);
         if (l_emission_item)
             break;
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_emission_item ? l_emission_item->datum_token_emission : NULL;
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
    return l_item ? l_item->cache_data.token_ticker : NULL;
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
                pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
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
        size_t l_count = HASH_COUNT(PVT(a_ledger)->balance_accounts);
        if(l_count && a_tickers){
            char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            if (!l_tickers) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
                return;
            }
            l_count = 0;
            const char *l_addr = dap_chain_addr_to_str_static(a_addr);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_ITER(hh, PVT(a_ledger)->balance_accounts, wallet_balance, tmp) {
                char **l_keys = dap_strsplit(wallet_balance->key, " ", -1);
                if (!dap_strcmp(l_keys[0], l_addr)) {
                    l_tickers[l_count] = dap_strdup(wallet_balance->token_ticker);
                    ++l_count;
                }
                dap_strfreev(l_keys);
            }
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            *a_tickers = l_tickers;
        }
        if(a_tickers_size)
            *a_tickers_size = l_count;
    }
}

const char *dap_ledger_get_description_by_ticker(dap_ledger_t *a_ledger, const char *a_token_ticker){
    if (!a_ledger || !a_token_ticker)
        return NULL;
    return s_ledger_find_token(a_ledger, a_token_ticker)->description;
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
        if (!a_unspent_only || !l_tx_item->cache_data.ts_spent) {
            l_tx_ret = l_tx_item->tx;
            if(a_item_out)
                *a_item_out = l_tx_item;
        }
    }
    return l_tx_ret;
}

dap_hash_fast_t dap_ledger_get_first_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_subtype_t a_cond_type)
{
    dap_hash_fast_t l_hash = { }, l_hash_tmp;
    dap_return_val_if_fail(a_ledger && a_tx, l_hash);
    dap_chain_datum_tx_t *l_prev_tx = a_tx;
    byte_t *l_iter = a_tx->tx_items;
    while (( l_iter = dap_chain_datum_tx_item_get(l_prev_tx, NULL, l_iter, TX_ITEM_TYPE_IN_COND, NULL) )) {
        l_hash_tmp =  ((dap_chain_tx_in_cond_t *)l_iter)->header.tx_prev_hash;
        if ( dap_hash_fast_is_blank(&l_hash_tmp) )
            return l_hash_tmp;
        if (( l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_hash_tmp) ) &&
                ( dap_chain_datum_tx_out_cond_get(l_prev_tx, a_cond_type, NULL) )) {
            l_hash = l_hash_tmp;
        }
    }
    return l_hash;
}

dap_hash_fast_t dap_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only)
{
    dap_chain_hash_fast_t l_hash = { };
    dap_return_val_if_fail(a_ledger && a_tx_hash && !dap_hash_fast_is_blank(a_tx_hash), l_hash);
    dap_chain_datum_tx_t *l_tx = NULL;
    l_hash = *a_tx_hash;
    dap_ledger_tx_item_t *l_item = NULL;
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

bool dap_ledger_tx_poa_signed(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx)
{
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
    return dap_list_find(a_ledger->net->pub.keys, l_sign, s_callback_sign_compare);
}

inline static bool s_ledger_check_token_ticker(const char *a_ticker)
{
    const char *c = a_ticker;
    for (int i = 0; i < DAP_CHAIN_TICKER_SIZE_MAX; i++, c++)
        if (*c == '\0')
            return true;
    return false;
}

/*
services we know now
0x01 - VPN
0x02 - xchange
0x03, 0x13 -  pos_delegate
0x04 bridge
0x.05 - custom datum
0x06 voting
0x12 - stake_lock 
*/

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
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_VOTING_CANCEL) return "voting_cancel";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_HOLD) return "hold";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_TAKE) return "take";
    if (a_tag == DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_REFILL) return "refill";

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

    if (l_deductions_ok > 1)
    {
        char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_t l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
        dap_chain_hash_fast_to_str(&l_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

        log_it(L_WARNING, "Transaction %s identyfied by multiple services (%d):", l_tx_hash_str, l_deductions_ok);
    
        pthread_rwlock_rdlock(&s_services_rwlock);
        HASH_ITER(hh, s_services , l_sinfo_current, l_sinfo_tmp) {
            dap_chain_tx_tag_action_type_t action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
            if (l_sinfo_current->callback && l_sinfo_current->callback(a_ledger, a_tx, &l_items_groups,&action))  {
                log_it(L_WARNING, "%s %s", l_sinfo_current->tag_str, dap_ledger_tx_action_str(action));
            }
        } 

        pthread_rwlock_unlock(&s_services_rwlock);
    }
    
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
                            bool a_check_for_removing)
{
    dap_return_val_if_fail(a_ledger && a_tx && a_tx_hash, DAP_LEDGER_CHECK_INVALID_ARGS);
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

    int l_err_num = DAP_LEDGER_CHECK_OK;
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

                dap_chain_tx_out_cond_t *l_tx_stake_lock_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_stake_lock, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, NULL);
                if (!l_tx_stake_lock_out_cond) {
                    debug_if(s_debug_more, L_WARNING, "No OUT_COND of stake_lock subtype for IN_EMS [%s]", l_tx_in_ems->header.ticker);
                    l_err_num = DAP_LEDGER_TX_CHECK_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS;
                    break;
                }
                uint256_t l_value_expected ={};
                if (MULT_256_COIN(l_tx_stake_lock_out_cond->header.value, l_delegated_item->emission_rate, &l_value_expected)) {
                    if (s_debug_more) {
                        char *l_emission_rate_str = dap_chain_balance_to_coins(l_delegated_item->emission_rate);
                        const char *l_locked_value_str; dap_uint256_to_char(l_tx_stake_lock_out_cond->header.value, &l_locked_value_str);
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
                    debug_if(s_debug_more, L_WARNING, l_girdled_ems ? "No OUT_EXT for girdled IN_EMS [%s]"
                                                                      : "Can't find OUT nor OUT_EXT item for base TX with IN_EMS [%s]", l_tx_in_ems->header.ticker);
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
                l_bound_item->type = TX_ITEM_TYPE_IN_EMS_LOCK;
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
                if (s_ledger_addr_check(l_token_item, l_addr_from, false) == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
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

                int l_verificator_error = l_verificator->callback(a_ledger, l_tx_prev_out_cond, a_tx, l_owner);
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
            strcpy(l_value_cur->token_ticker, l_token);
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
    uint256_t l_value = {}, l_fee_sum = {}, l_tax_sum = {};
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
            l_value = dap_chain_uint256_from(l_tx_out->header.value);
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
            l_value = l_tx_out->header.value;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_EXT: { // 256
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)it;
            l_value = l_tx_out->header.value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_tx_out = (dap_chain_tx_out_std_t *)it;
            l_value = l_tx_out->value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t *)it;
            l_token = l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE ? a_ledger->net->pub.native_ticker : l_main_ticker;
            if (!l_token) {
                l_err_num = DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER;
                break;
            }
            l_value = l_tx_out->header.value;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
            if (l_tax_check && l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE &&
                    SUBTRACT_256_256(l_taxed_value, l_value, &l_taxed_value)) {
                log_it(L_WARNING, "Fee is greater than sum of inputs");
                l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
                break;
            }
        } break;
        default:
            continue;
        }
        if (!dap_chain_addr_is_blank(&l_tx_out_to)) {
            if (l_tx_out_to.net_id.uint64 != a_ledger->net->pub.id.uint64) {
                if (!l_cross_network) {
                    l_cross_network = true;
                } else {
                    log_it(L_WARNING, "The transaction was rejected because it contains multiple outputs to other network.");
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
            strcpy(l_value_cur->token_ticker, l_token);
            HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
        }
        if (SUM_256_256(l_value_cur->sum, l_value, &l_value_cur->sum)) {
            debug_if(s_debug_more, L_WARNING, "Sum result overflow for tx_add_check with ticker %s",
                                    l_value_cur->token_ticker);
            l_err_num = DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
            break;
        }

        // Find token item
        dap_ledger_token_item_t *l_token_item = s_ledger_find_token(a_ledger, l_token);
        if (!l_token_item) {
            debug_if(s_debug_more, L_WARNING, "Token with ticker %s not found", l_token);
            l_err_num = DAP_LEDGER_CHECK_TICKER_NOT_FOUND;
            break;
        }
        // Check permissions
        if (s_ledger_addr_check(l_token_item, &l_tx_out_to, true) == DAP_LEDGER_CHECK_ADDR_FORBIDDEN) {
            debug_if(s_debug_more, L_WARNING, "No permission to receive for addr %s", dap_chain_addr_to_str_static(&l_tx_out_to));
            l_err_num = DAP_LEDGER_CHECK_ADDR_FORBIDDEN;
            break;
        }
        if (l_fee_check && dap_chain_addr_compare(&l_tx_out_to, &a_ledger->net->pub.fee_addr) &&
                !dap_strcmp(l_value_cur->token_ticker, a_ledger->net->pub.native_ticker))
            SUM_256_256(l_fee_sum, l_value, &l_fee_sum);

        if (l_tax_check && dap_chain_addr_compare(&l_tx_out_to, &l_key_item->sovereign_addr) &&
                !dap_strcmp(l_value_cur->token_ticker, a_ledger->net->pub.native_ticker))
            SUM_256_256(l_tax_sum, l_value, &l_tax_sum);
    }

    // Check for transaction consistency (sum(ins) == sum(outs))
    if ( !l_err_num && !s_check_hal(a_ledger, a_tx_hash) ) {
        if ( HASH_COUNT(l_values_from_prev_tx) != HASH_COUNT(l_values_from_cur_tx) ) {
            log_it(L_ERROR, "Token tickers IN and OUT mismatch: %u != %u",
                            HASH_COUNT(l_values_from_prev_tx), HASH_COUNT(l_values_from_cur_tx));
            l_err_num = DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS;
        } else {
            HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
                HASH_FIND_STR(l_values_from_cur_tx, l_value_cur->token_ticker, l_res);
                if (!l_res || !EQUAL_256(l_res->sum, l_value_cur->sum) ) {
                    if (s_debug_more) {
                        char *l_balance = dap_chain_balance_to_coins(l_res ? l_res->sum : uint256_0);
                        char *l_balance_cur = dap_chain_balance_to_coins(l_value_cur->sum);
                        log_it(L_ERROR, "Sum of values of out items from current tx (%s) is not equal outs from previous txs (%s) for token %s",
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
            log_it(L_WARNING, "Fee value is invalid, expected %s pointed %s", l_expected_fee, l_current_fee);
            l_err_num = DAP_LEDGER_TX_CHECK_NOT_ENOUGH_FEE;
            DAP_DEL_Z(l_current_fee);
            DAP_DEL_Z(l_expected_fee);
        }
        if (l_tax_check && SUBTRACT_256_256(l_taxed_value, l_fee_sum, &l_taxed_value)) {
            log_it(L_WARNING, "Fee is greater than sum of inputs");
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
            log_it(L_WARNING, "Tax value is invalid, expected %s pointed %s", l_expected_tax_str, l_current_tax_str);
            l_err_num = DAP_LEDGER_TX_CHECK_NOT_ENOUGH_TAX;
            DAP_DEL_Z(l_current_tax_str);
            DAP_DEL_Z(l_expected_tax_str);
        }
    }

    if (!l_err_num) {
        // TODO move it to service tag deduction
        if ( dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_VOTING, NULL ) ) {
            if (s_voting_callbacks.voting_callback) {
                if ((l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx, a_tx_hash, false))) {
                    debug_if(s_debug_more, L_WARNING, "Verificator check error %d for voting", l_err_num);
                    l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                }
            } else {
                debug_if(s_debug_more, L_WARNING, "Verificator check error for voting item");
                l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
            }
            // if (a_tag)
            //     a_tag->uint64 = DAP_CHAIN_TX_TAG_ACTION_VOTING;
            if (a_action)
               *a_action = DAP_CHAIN_TX_TAG_ACTION_VOTING;
        } else if ( dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL) ) {
           if (s_voting_callbacks.voting_callback) {
               if (!s_check_hal(a_ledger, a_tx_hash) &&
                       (l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx, a_tx_hash, false))) {
                   debug_if(s_debug_more, L_WARNING, "Verificator check error %d for vote", l_err_num);
                   l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
               }
           } else {
               debug_if(s_debug_more, L_WARNING, "Verificator check error for vote item");
               l_err_num = DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET;
           }
           if (a_action) 
               *a_action = DAP_CHAIN_TX_TAG_ACTION_VOTE;
        } else if ( dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_TSD, NULL) ) {
            dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_TSD, NULL);
            dap_tsd_t *l_tsd_data = (dap_tsd_t *)l_tsd->tsd;
            if (l_tsd_data->type == VOTING_TSD_TYPE_CANCEL) {
                if (s_voting_callbacks.voting_callback) {
                    if ((l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_TSD, a_tx, a_tx_hash, false))) {
                        debug_if(s_debug_more, L_WARNING, "Verificator check error %d for voting", l_err_num);
                        l_err_num = DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE;
                    }
                }
                if (a_action)
                    *a_action = DAP_CHAIN_TX_TAG_ACTION_VOTING_CANCEL;
            }
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
    int l_ret_check = s_tx_cache_check(a_ledger, a_tx, a_datum_hash, false, NULL, NULL, NULL, NULL, NULL, false);
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
    if (PVT(a_ledger)->cached) {
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
    const char *l_addr_str = dap_chain_addr_to_str_static(a_addr);
    dap_ledger_wallet_balance_t *l_wallet_balance = NULL;
    char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, a_token_ticker, (char*)NULL);
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
        strcpy(l_wallet_balance->token_ticker, a_token_ticker);
        SUM_256_256(l_wallet_balance->balance, a_value, &l_wallet_balance->balance);
        debug_if(s_debug_more, L_DEBUG, "Create new balance item: %s %s", l_addr_str, a_token_ticker);
        HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, l_wallet_balance->key,
                        strlen(l_wallet_balance_key), l_wallet_balance);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    // Update the cache
    s_balance_cache_update(a_ledger, l_wallet_balance);
    return 0;
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
                                                       l_main_token_ticker, &l_tag, &l_action, false))) {                                                        
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
    if (PVT(a_ledger)->cached) {
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

        if ((l_type == TX_ITEM_TYPE_IN_EMS_LOCK || l_type == TX_ITEM_TYPE_IN_REWARD) &&
                !s_ledger_token_supply_check_update(a_ledger, l_bound_item->token_item, l_bound_item->value, false))
            log_it(L_ERROR, "Insufficient supply for token %s", l_bound_item->token_item->ticker);

        switch (l_type) {
        case TX_ITEM_TYPE_IN_EMS:
            // Mark it as used with current tx hash
            l_bound_item->emission_item->tx_used_out = *a_tx_hash;
            s_ledger_emission_cache_update(a_ledger, l_bound_item->emission_item);
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_EMS_LOCK:
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
            const char *l_addr_str = dap_chain_addr_to_str_static(&l_bound_item->in.addr_from);
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
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
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_cur_token_ticker);
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
        l_prev_item_out->cache_data.tx_hash_spent_fast[l_bound_item->prev_out_idx] = *a_tx_hash;
        l_prev_item_out->cache_data.n_outs_used++;
        if (PVT(a_ledger)->cached) {
            // mirror it in the cache
            size_t l_cache_size = sizeof(l_prev_item_out->cache_data) + l_prev_item_out->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
            dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_STACK_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
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
    int l_err_num = 0;
    if (s_voting_callbacks.voting_callback) {
        if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTING)
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx, a_tx_hash, true);
        else if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTE)
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx, a_tx_hash, true);
        else if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTING_CANCEL)
            l_err_num = s_voting_callbacks.voting_callback(a_ledger, TX_ITEM_TYPE_TSD, a_tx, a_tx_hash, true);
    }
    if (!s_check_hal(a_ledger, a_tx_hash))
        assert(!l_err_num);

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
    l_tx_item->cache_data.n_outs = l_outs_count;
    l_tx_item->cache_data.tag = l_tag;
    l_tx_item->cache_data.action = l_action;
    dap_stpcpy(l_tx_item->cache_data.token_ticker, l_main_token_ticker);

    l_tx_item->cache_data.multichannel = l_multichannel;
    l_tx_item->ts_added = dap_nanotime_now();
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    if (dap_chain_net_get_load_mode(a_ledger->net) || dap_chain_net_get_state(a_ledger->net) == NET_STATE_SYNC_CHAINS)
        HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
    else
        HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t),
                         l_tx_item, s_sort_ledger_tx_item); // tx_hash_fast: name of key field
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    // Callable callback
    dap_list_t *l_notifier;
    DL_FOREACH(PVT(a_ledger)->tx_add_notifiers, l_notifier) {
        dap_ledger_tx_notifier_t *l_notify = (dap_ledger_tx_notifier_t*)l_notifier->data;
        l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx,  a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
    }
    if (l_cross_network) {
        dap_list_t *l_notifier;
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notifiers, l_notifier) {
            dap_ledger_bridged_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
        }
    }
    if (PVT(a_ledger)->cached) {
        // Add it to cache
        size_t l_cache_size = sizeof(l_tx_item->cache_data) + l_tx_item->cache_data.n_outs * sizeof(dap_chain_hash_fast_t);
        size_t l_tx_cache_sz = l_tx_size + l_cache_size + sizeof(dap_ledger_cache_gdb_record_t);
        dap_ledger_cache_gdb_record_t *l_tx_cache = DAP_NEW_STACK_SIZE(dap_ledger_cache_gdb_record_t, l_tx_cache_sz);
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
        if (dap_global_db_set_raw(l_cache_used_outs, l_outs_used + 1, NULL, NULL))
            debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch");
    }
    if (!a_from_threshold && l_ledger_pvt->threshold_enabled)
        s_threshold_txs_proc(a_ledger);
FIN:
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    if (PVT(a_ledger)->cached) {
        if (l_cache_used_outs) {
            for (size_t i = 1; i <= l_outs_used; i++) {
                DAP_DEL_Z(l_cache_used_outs[i].key);
                DAP_DEL_Z(l_cache_used_outs[i].value);
            }
        }
        DAP_DEL_Z(l_cache_used_outs);
        DAP_DEL_Z(l_ledger_cache_group);
    }
    return l_ret;
}

void dap_ledger_load_end(dap_ledger_t *a_ledger)
{
    pthread_rwlock_wrlock(&PVT(a_ledger)->ledger_rwlock);
    HASH_SORT(PVT(a_ledger)->ledger_items, s_sort_ledger_tx_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
}

/**
 * @brief Remove transaction from the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
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
                                                       l_main_token_ticker, &l_tag, &l_action, true))) {
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
        if ((l_type == TX_ITEM_TYPE_IN_EMS_LOCK || l_type == TX_ITEM_TYPE_IN_REWARD) &&
                !s_ledger_token_supply_check_update(a_ledger, l_bound_item->token_item, l_bound_item->value, true))
            log_it(L_ERROR, "Insufficient supply for token %s", l_bound_item->token_item->ticker);

        switch (l_type) {
        case TX_ITEM_TYPE_IN_EMS:
            // Mark it as unused
            memset(&(l_bound_item->emission_item->tx_used_out), 0, sizeof(dap_hash_fast_t));
            s_ledger_emission_cache_update(a_ledger, l_bound_item->emission_item);
            l_outs_used--; // Do not calc this output with tx used items
            continue;

        case TX_ITEM_TYPE_IN_EMS_LOCK:
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
            const char *l_addr_str = dap_chain_addr_to_str_static(&l_bound_item->in.addr_from);
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
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
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_cur_token_ticker);
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

    if (s_voting_callbacks.voting_delete_callback) {
        if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTING)
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTING, a_tx);
        else if (l_action == DAP_CHAIN_TX_TAG_ACTION_VOTE)
            s_voting_callbacks.voting_delete_callback(a_ledger, TX_ITEM_TYPE_VOTE, a_tx);
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
            l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx, a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
        }
    }
    if (!PVT(a_ledger)->mapped)
        DAP_DELETE(l_tx_item->tx);
    DAP_DELETE(l_tx_item);
    if (l_cross_network) {
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notifiers, l_notifier) {
            dap_ledger_bridged_tx_notifier_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
        }
    }

    if (PVT(a_ledger)->cached) {
        // Add it to cache
        dap_global_db_del_sync(l_ledger_cache_group, l_tx_hash_str);
        // Apply it with single DB transaction
        if (dap_global_db_set_raw(l_cache_used_outs, l_outs_used, NULL, NULL))
            debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch");
    }
FIN:
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    if (PVT(a_ledger)->cached) {
        if (l_cache_used_outs) {
            for (size_t i = 1; i < l_outs_used; i++) {
                DAP_DEL_Z(l_cache_used_outs[i].key);
                DAP_DEL_Z(l_cache_used_outs[i].value);
            }
        }
        DAP_DEL_Z(l_cache_used_outs);
        DAP_DEL_Z(l_ledger_cache_group);
    }
    return l_ret;
}

int dap_ledger_tx_load(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash, dap_ledger_datum_iter_data_t *a_datum_index_data)
{
#ifndef DAP_LEDGER_TEST
    if (dap_chain_net_get_load_mode(a_ledger->net)) {
        if (PVT(a_ledger)->cache_tx_check_callback)
            PVT(a_ledger)->cache_tx_check_callback(a_ledger, a_tx_hash);
        dap_ledger_tx_item_t *l_tx_item = NULL;
        unsigned l_hash_value;
        HASH_VALUE(a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value);
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (l_tx_item)
            return DAP_LEDGER_CHECK_ALREADY_CACHED;
    }
#endif
    return dap_ledger_tx_add(a_ledger, a_tx, a_tx_hash, false, a_datum_index_data);
}

/**
 * Delete all transactions from the cache
 */
void dap_ledger_purge(dap_ledger_t *a_ledger, bool a_preserve_db)
{
    dap_return_if_fail(a_ledger);
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
        if (!l_ledger_pvt->mapped)
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
        if (!l_ledger_pvt->mapped)
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

    l_ledger_pvt->load_end = false;
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
uint64_t dap_ledger_count_from_to(dap_ledger_t * a_ledger, dap_nanotime_t a_ts_from, dap_nanotime_t a_ts_to)
{
    uint64_t l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_ledger_tx_item_t *l_iter_current, *l_item_tmp;
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

/**
 * Calculate balance of addr
 *
 */
uint256_t dap_ledger_calc_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                        const char *a_token_ticker)
{
    uint256_t l_ret = uint256_0;

    dap_ledger_wallet_balance_t *l_balance_item = NULL;// ,* l_balance_item_tmp = NULL;
    const char *l_addr = dap_chain_addr_to_str_static(a_addr);
    char *l_wallet_balance_key = dap_strjoin(" ", l_addr, a_token_ticker, (char*)NULL);
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
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_iter_current, l_item_tmp) {
        dap_chain_datum_tx_t *l_tx = l_iter_current->tx;
        byte_t *item; size_t l_size;
        TX_ITEM_ITER_TX(item, l_size, l_tx) {
            if (*item == TX_ITEM_TYPE_OUT_COND && ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64 == a_srv_uid.uint64)
                l_ret = dap_list_append(l_ret, l_tx);
        }
    }
    return l_ret;
}

/**
 * @brief dap_ledger_get_list_tx_outs_with_val
 * @param a_ledger
 * @param a_token_ticker
 * @param a_addr_from
 * @param a_value_need
 * @param a_value_transfer
 * @return list of dap_chain_tx_used_out_item_t
 */
dap_list_t *dap_ledger_get_list_tx_outs_with_val(dap_ledger_t *a_ledger, const char *a_token_ticker, const dap_chain_addr_t *a_addr_from,
                                                       uint256_t a_value_need, uint256_t *a_value_transfer)
{
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_hash_fast_t l_tx_cur_hash = { };
    uint256_t l_value_transfer = { };
    dap_chain_datum_tx_t *l_tx;
    while ( compare256(l_value_transfer, a_value_need) == -1 
            && (l_tx = dap_ledger_tx_find_by_addr(a_ledger, a_token_ticker, a_addr_from, &l_tx_cur_hash, true)) )
    {
        // Get all item from transaction by type
        byte_t *it; size_t l_size; int i, l_out_idx_tmp = -1;
        dap_chain_addr_t l_out_addr = { };
        TX_ITEM_ITER_TX_TYPE(it, TX_ITEM_TYPE_OUT_ALL, l_size, i, l_tx) {
            ++l_out_idx_tmp;
            dap_chain_tx_item_type_t l_type = *it;
            uint256_t l_value;
            switch (l_type) {
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t*)it;
                l_out_addr = l_out->addr;
                if ( !l_out->header.value || !dap_chain_addr_compare(a_addr_from, &l_out_addr) )
                    continue;
                l_value = GET_256_FROM_64(l_out->header.value);
            } break;
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t*)it;
                l_out_addr = l_out->addr;
                if ( !dap_chain_addr_compare(a_addr_from, &l_out_addr) 
                || dap_strcmp(dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_cur_hash), a_token_ticker)
                || IS_ZERO_256(l_out->header.value) )
                    continue;
                l_value = l_out->header.value;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t*)it;
                l_out_addr = l_out_ext->addr;
                if ( !dap_chain_addr_compare(a_addr_from, &l_out_addr)
                || strcmp((char *)a_token_ticker, l_out_ext->token)
                || IS_ZERO_256(l_out_ext->header.value) )
                    continue;
                l_value = l_out_ext->header.value;
            } break;
            case TX_ITEM_TYPE_OUT_STD: {
                dap_chain_tx_out_std_t *l_out_std = (dap_chain_tx_out_std_t *)it;
                l_out_addr = l_out_std->addr;
                if ( !dap_chain_addr_compare(a_addr_from, &l_out_addr)
                || strcmp((char *)a_token_ticker, l_out_std->token)
                || IS_ZERO_256(l_out_std->value)
                || l_out_std->ts_unlock > dap_ledger_get_blockchain_time(a_ledger))
                    continue;
                l_value = l_out_std->value;
            } break;
            default:
                continue;
            }
            // Check whether used 'out' items
            dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
            *l_item = (dap_chain_tx_used_out_item_t) { l_tx_cur_hash, (uint32_t)l_out_idx_tmp, l_value };
            l_list_used_out = dap_list_append(l_list_used_out, l_item);
            SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
            // already accumulated the required value, finish the search for 'out' items
            if ( compare256(l_value_transfer, a_value_need) != -1 ) {
                break;
            }
        }
    }
    return compare256(l_value_transfer, a_value_need) >= 0 && l_list_used_out
        ? ({ if (a_value_transfer) *a_value_transfer = l_value_transfer; l_list_used_out; })
        : ( dap_list_free_full(l_list_used_out, NULL), NULL );
}

dap_list_t *dap_ledger_get_list_tx_outs(dap_ledger_t *a_ledger, const char *a_token_ticker, const dap_chain_addr_t *a_addr_from,
                                        uint256_t *a_value_transfer)
{
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_hash_fast_t l_tx_cur_hash = { };
    uint256_t l_value_transfer = {};
    dap_chain_datum_tx_t *l_tx;
    while (( l_tx = dap_ledger_tx_find_by_addr(a_ledger, a_token_ticker, a_addr_from, &l_tx_cur_hash, true) )) {
        byte_t *it; size_t l_size; int i, l_out_idx_tmp = -1;
        dap_chain_addr_t l_out_addr = { };
        TX_ITEM_ITER_TX_TYPE(it, TX_ITEM_TYPE_OUT_ALL, l_size, i, l_tx) {
            ++l_out_idx_tmp;
            uint256_t l_value;
            switch (*it) {
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t*)it;
                l_out_addr = l_out->addr;
                if ( !l_out->header.value || !dap_chain_addr_compare(a_addr_from, &l_out_addr) )
                    continue;
                l_value = GET_256_FROM_64(l_out->header.value);
            } break;
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t*)it;
                l_out_addr = l_out->addr;
                if ( !dap_chain_addr_compare(a_addr_from, &l_out_addr)
                || dap_strcmp( dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_cur_hash), a_token_ticker )
                || IS_ZERO_256(l_out->header.value))
                    continue;
                l_value = l_out->header.value;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t *)it;
                l_out_addr = l_out_ext->addr;
                if ( !dap_chain_addr_compare(a_addr_from, &l_out_addr)
                || strcmp((char*)a_token_ticker, l_out_ext->token)
                || IS_ZERO_256(l_out_ext->header.value) )
                    continue;
                l_value = l_out_ext->header.value;
            } break;
            case TX_ITEM_TYPE_OUT_STD: {
                dap_chain_tx_out_std_t *l_out_std = (dap_chain_tx_out_std_t *)it;
                l_out_addr = l_out_std->addr;
                if ( !dap_chain_addr_compare(a_addr_from, &l_out_addr)
                || strcmp((char*)a_token_ticker, l_out_std->token)
                || IS_ZERO_256(l_out_std->value)
                || l_out_std->ts_unlock > dap_ledger_get_blockchain_time(a_ledger))
                    continue;
                l_value = l_out_std->value;
            } break;
            default:
                continue;
            }
            // Check whether used 'out' items
            dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
            *(l_item) = (dap_chain_tx_used_out_item_t) { l_tx_cur_hash, (uint32_t)l_out_idx_tmp, l_value };
            l_list_used_out = dap_list_append(l_list_used_out, l_item);
            SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
        }
    }
    if (a_value_transfer) *a_value_transfer = l_value_transfer;
    return l_list_used_out;
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
    size_t l_counter = 0;
    dap_ledger_tx_item_t *l_item_current, *l_item_tmp;
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_item_current, l_item_tmp) {
        if (l_counter++ >= l_offset) {
            if (!a_unspent_only || !l_item_current->cache_data.ts_spent)
                l_list = a_reverse
                        ? dap_list_prepend(l_list, l_item_current->tx)
                        : dap_list_append(l_list, l_item_current->tx);
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
        dap_hash_fast_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, it->tx, l_subtype);
        dap_chain_datum_tx_t *l_tx = dap_hash_fast_is_blank(&l_owner_tx_hash) ? it->tx
                                                                              : dap_ledger_tx_find_by_hash(a_ledger, &l_owner_tx_hash);
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
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_hash_fast_t l_tx_cur_hash = { };
    int l_out_idx;
    dap_chain_tx_out_cond_t *l_cond;
    while ( (l_cond = dap_ledger_out_cond_unspent_find_by_addr(a_ledger, a_token_ticker, a_subtype, a_addr_from, &l_tx_cur_hash, &l_out_idx)) ) {
        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        *l_item = (dap_chain_tx_used_out_item_t) { l_tx_cur_hash, (uint32_t)l_out_idx, l_cond->header.value };
        l_list_used_out = dap_list_append(l_list_used_out, l_item);
    }
    return l_list_used_out;
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
    PVT(a_ledger)->bridged_tx_notifiers = dap_list_append(PVT(a_ledger)->bridged_tx_notifiers , l_notifier);
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
    int l_rc = s_tx_cache_check(a_ledger, a_tx, &l_tx_hash, false, NULL, NULL, (char*)&l_ret, NULL, NULL, false);
    if (l_rc == DAP_LEDGER_CHECK_ALREADY_CACHED)
        dap_strncpy( (char*)&l_ret, dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_hash), DAP_CHAIN_TICKER_SIZE_MAX );
    if (a_ledger_rc)
        *a_ledger_rc = l_rc;
    return l_ret;
}

/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2024
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_common.h"
#include <dirent.h>
#include "uthash.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_common.h"
#include "dap_chain_cell.h"
#include "dap_chain_srv.h"
#include "dap_math_ops.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_chain_datum_token.h"
#include "dap_global_db.h"
#include "dap_chain_ledger.h"
#include "json_object.h"

#define LOG_TAG "dap_ledger"

typedef struct dap_ledger_service_info {
    dap_chain_srv_uid_t service_uid;    // hash key
    char tag_str[32];   // tag string name
    dap_ledger_tag_check_callback_t callback; //callback for check if a tx for particular service
    UT_hash_handle hh;
} dap_ledger_service_info_t;

static dap_ledger_service_info_t *s_services;
static pthread_rwlock_t s_services_rwlock = PTHREAD_RWLOCK_INITIALIZER;

bool g_debug_ledger = true;

static void s_threshold_txs_free(dap_ledger_t *a_ledger);
static size_t s_threshold_txs_max = 10000;
static size_t s_threshold_free_timer_tick = 900000; // 900000 ms = 15 minutes.

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
        dap_chain_addr_t addr_to = {0};
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
    if (a_items_grp->items_vote || a_items_grp->items_voting || dap_list_length(a_items_grp->items_tsd) > 1 || (a_items_grp->items_tsd && !dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT)))
        return false;

    //not tsd sects (staking!) or only batching tsd
    if(a_action) {
        *a_action = DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR;
    }
    return true;
}

int dap_ledger_service_add(dap_chain_srv_uid_t a_uid, char *tag_str, dap_ledger_tag_check_callback_t a_callback)
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
    dap_strncpy(l_new_sinfo->tag_str, tag_str, sizeof(l_new_sinfo->tag_str));
    
    pthread_rwlock_wrlock(&s_services_rwlock);
    HASH_ADD_INT(s_services, service_uid.raw_ui64, l_new_sinfo);
    pthread_rwlock_unlock(&s_services_rwlock);

    log_it(L_NOTICE, "Successfully registered service tag %s with uid %02" DAP_UINT64_FORMAT_X, tag_str, a_uid.raw_ui64);

    return 0;
}

/**
 * @brief dap_ledger_init
 * current function version set g_debug_ledger parameter, if it define in config, and returns 0
 * @return
 */
int dap_ledger_init()
{
    g_debug_ledger = dap_config_get_item_bool_default(g_config, "ledger", "debug_more",false);
    
    //register native ledger services
    dap_chain_srv_uid_t l_uid_transfer = { .uint64 = DAP_CHAIN_NET_SRV_TRANSFER_ID };
    dap_ledger_service_add(l_uid_transfer, "transfer", s_tag_check_transfer);

    dap_chain_srv_uid_t l_uid_breward = { .uint64 = DAP_CHAIN_NET_SRV_BLOCK_REWARD_ID };
    dap_ledger_service_add(l_uid_breward, "block_reward", s_tag_check_block_reward);
    return 0;
}

/**
 * @brief dap_ledger_deinit
 * nothing do
 */
void dap_ledger_deinit()
{
    pthread_rwlock_destroy(&s_services_rwlock);
}

/**
 * @brief dap_ledger_handle_new
 * Create empty dap_ledger_t structure
 * @return dap_ledger_t*
 */
static dap_ledger_t *dap_ledger_handle_new(void)
{
    dap_ledger_t *l_ledger = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_t, NULL);
    dap_ledger_private_t *l_ledger_pvt = l_ledger->_internal = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_private_t, NULL, l_ledger);
    pthread_rwlock_init(&l_ledger_pvt->ledger_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->tokens_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->threshold_txs_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->balance_accounts_rwlock, NULL);
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
    // Destroy Read/Write Lock
    pthread_rwlock_destroy(&PVT(a_ledger)->ledger_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->tokens_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->threshold_txs_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->balance_accounts_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->stake_lock_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->rewards_rwlock);
    DAP_DEL_MULTY(PVT(a_ledger), a_ledger);
    log_it(L_INFO,"Ledger for network %s destroyed", a_ledger->net->pub.name);

}

bool dap_ledger_datum_is_enforced(dap_ledger_t *a_ledger, dap_hash_fast_t *a_hash, bool a_accept) {
    dap_ledger_hal_item_t *l_wanted = NULL;
    HASH_FIND(hh, a_accept ? PVT(a_ledger)->hal_items : PVT(a_ledger)->hrl_items, a_hash, sizeof(dap_hash_fast_t), l_wanted);
    debug_if(g_debug_ledger && l_wanted, L_DEBUG, "Datum %s is %slisted", dap_hash_fast_to_str_static(a_hash), a_accept ? "white" : "black");
    return !!l_wanted;
}


static void s_tx_header_print(json_object *a_json_out, dap_chain_datum_tx_t *a_tx,
                              const char *a_hash_out_type, dap_chain_hash_fast_t *a_tx_hash)
{
    char l_time_str[DAP_TIME_STR_SIZE] = "unknown";
    if (a_tx->header.ts_created)
        dap_time_to_str_rfc822(l_time_str, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
    const char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
            : dap_chain_hash_fast_to_str_static(a_tx_hash);
    json_object_object_add(a_json_out, "tx_hash ", json_object_new_string(l_tx_hash_str));
    json_object_object_add(a_json_out, "time ", json_object_new_string(l_time_str));
}

static void s_dump_datum_tx_for_addr(dap_ledger_tx_item_t *a_item, bool a_unspent, dap_ledger_t *a_ledger, 
            dap_chain_addr_t *a_addr, const char *a_hash_out_type, json_object *json_arr_out) {
    if (a_unspent && a_item->cache_data.ts_spent) {
        // With 'unspent' flag spent ones are ignored
        return;
    }
    dap_chain_datum_tx_t *l_tx = a_item->tx;
    dap_chain_hash_fast_t l_tx_hash = a_item->tx_hash_fast;
    dap_chain_addr_t l_src_addr = { }, l_dst_addr = { };
    bool l_base_tx = false;
    const char *l_src_token = NULL;
    int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
    dap_hash_fast_t l_tx_prev_hash = { };
    byte_t *l_item; size_t l_size; int idx, l_tx_prev_out_idx;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_IN_ALL, l_size, idx, l_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_IN: {
            dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t*)l_item;
            l_tx_prev_hash = l_tx_in->header.tx_prev_hash;
            l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
        } break;
        case TX_ITEM_TYPE_IN_COND: {
            dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t*)l_item;
            l_tx_prev_hash = l_tx_in_cond->header.tx_prev_hash;
            l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
        } break;
        default:
            continue;
        }
        if ( dap_hash_fast_is_blank(&l_tx_prev_hash) ) {
            l_base_tx = true;
            dap_chain_tx_in_ems_t *l_token = (dap_chain_tx_in_ems_t*)
                dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_IN_EMS, NULL);
            if (l_token)
                l_src_token = l_token->header.ticker;
            break;
        }
        dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, &l_tx_prev_hash);
        if ( !l_tx_prev )
            continue;
        uint8_t *l_prev_out_union = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
        if (!l_prev_out_union)
            continue;
        switch (*l_prev_out_union) {
        case TX_ITEM_TYPE_OUT:
            l_src_addr = ((dap_chain_tx_out_t *)l_prev_out_union)->addr;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_src_addr = ((dap_chain_tx_out_ext_t *)l_prev_out_union)->addr;
            l_src_token = (const char*)(((dap_chain_tx_out_ext_t *)l_prev_out_union)->token);
            break;
        case TX_ITEM_TYPE_OUT_COND:
            l_src_subtype = ((dap_chain_tx_out_cond_t *)l_prev_out_union)->header.subtype;
        default:
            break;
        }
        if ( !dap_chain_addr_compare(&l_src_addr, a_addr) )
            break;  //it's not our addr
        if (!l_src_token) {
            l_src_token = a_item->cache_data.token_ticker;
        }
    }

    bool l_header_printed = false;
    l_item = NULL;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, idx, l_tx) {
        dap_chain_tx_item_type_t l_type = *l_item;
        uint256_t l_value;
        switch (l_type) {
        case TX_ITEM_TYPE_OUT:
            l_dst_addr = ((dap_chain_tx_out_t*)l_item)->addr;
            l_value = ((dap_chain_tx_out_t*)l_item)->header.value;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_dst_addr = ((dap_chain_tx_out_ext_t*)l_item)->addr;
            l_value = ((dap_chain_tx_out_ext_t *)l_item)->header.value;
            break;
        case TX_ITEM_TYPE_OUT_COND:
            l_value = ((dap_chain_tx_out_cond_t *)l_item)->header.value;
        default:
            break;
        }
        if ( !dap_chain_addr_is_blank(&l_src_addr) && !dap_chain_addr_is_blank(&l_dst_addr) 
            && dap_chain_addr_compare(&l_dst_addr, &l_src_addr) )
            continue;   // send to self
        if ( dap_chain_addr_compare(&l_src_addr, a_addr)) {
            json_object * l_json_obj_datum = json_object_new_object();
            if (!l_header_printed) {
                s_tx_header_print(l_json_obj_datum, l_tx, a_hash_out_type, &l_tx_hash);
                l_header_printed = true;
            }
            //const char *l_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash);
            const char *l_dst_addr_str = !dap_chain_addr_is_blank(&l_dst_addr) 
                ? dap_chain_addr_to_str_static(&l_dst_addr)
                : dap_chain_tx_out_cond_subtype_to_str( ((dap_chain_tx_out_cond_t *)l_item)->header.subtype );
            json_object_object_add(l_json_obj_datum, "send", json_object_new_string(dap_uint256_to_char(l_value, NULL)));
            json_object_object_add(l_json_obj_datum, "to_addr", json_object_new_string(l_dst_addr_str));
            json_object_object_add(l_json_obj_datum, "token", l_src_token ? json_object_new_string(l_src_token) : json_object_new_string("UNKNOWN"));
            json_object_array_add(json_arr_out, l_json_obj_datum);
        }
        if ( dap_chain_addr_compare(&l_dst_addr, a_addr) ) {
            json_object * l_json_obj_datum = json_object_new_object();
            if (!l_header_printed) {
               s_tx_header_print(l_json_obj_datum, l_tx, a_hash_out_type, &l_tx_hash);
               l_header_printed = true;
            }
            const char *l_dst_token = (l_type == TX_ITEM_TYPE_OUT_EXT) ?
                        (const char *)(((dap_chain_tx_out_ext_t *)l_item)->token) : NULL;
            const char *l_src_addr_str = l_base_tx 
                ? "emission"
                : ( !dap_chain_addr_is_blank(&l_src_addr) 
                    ? dap_chain_addr_to_str_static(&l_src_addr)
                    : dap_chain_tx_out_cond_subtype_to_str(l_src_subtype) );
            json_object_object_add(l_json_obj_datum, "recv", json_object_new_string(dap_uint256_to_char(l_value, NULL)));
            json_object_object_add(l_json_obj_datum, "token", l_dst_token ? json_object_new_string(l_dst_token) :
                                  (l_src_token ? json_object_new_string(l_src_token) : json_object_new_string("UNKNOWN")));
            json_object_object_add(l_json_obj_datum, "from", json_object_new_string(l_src_addr_str));
            json_object_array_add(json_arr_out, l_json_obj_datum);
        }
    }
}

json_object *dap_ledger_token_tx_item_list(dap_ledger_t * a_ledger, dap_chain_addr_t *a_addr, const char *a_hash_out_type, bool a_unspent_only)
{
    json_object * json_arr_out = json_object_new_array();
    if (!json_arr_out) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    dap_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
    dap_ledger_private_t * l_ledger_pvt = PVT(a_ledger);

    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_tx_item, l_tx_tmp) {
        s_dump_datum_tx_for_addr(l_tx_item, a_unspent_only, a_ledger, a_addr, a_hash_out_type, json_arr_out);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);

    // if no history
    if(!json_arr_out)
    {
        json_object * json_obj_addr = json_object_new_object();
        json_object_object_add(json_obj_addr, "status", json_object_new_string("empty"));
        json_object_array_add(json_arr_out, json_obj_addr);
    }
    return json_arr_out;
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

int dap_ledger_pvt_threshold_txs_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash)
{
    dap_ledger_tx_item_t *l_item = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    unsigned l_hash_value = 0;
    HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
    pthread_rwlock_wrlock(&l_ledger_pvt->threshold_txs_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->threshold_txs, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item);
    unsigned long long l_threshold_txs_count = HASH_COUNT(l_ledger_pvt->threshold_txs);
    if (!l_item) {
        if (l_threshold_txs_count >= s_threshold_txs_max) {
            pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            debug_if(g_debug_ledger, L_WARNING, "Threshold for transactions is overfulled (%zu max), dropping down tx %s, added nothing",
                                                s_threshold_txs_max, dap_hash_fast_to_str_static(a_tx_hash));
            return -2;
        }
        if (!( l_item = DAP_NEW_Z(dap_ledger_tx_item_t) )) {
            pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -1;
        }
        l_item->tx_hash_fast = *a_tx_hash;
        l_item->tx = is_ledger_mapped(l_ledger_pvt) ? a_tx : DAP_DUP_SIZE(a_tx, dap_chain_datum_tx_get_size(a_tx));
        if ( !l_item->tx ) {
            DAP_DELETE(l_item);
            pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -1;
        }
        l_item->ts_added = dap_nanotime_now();
        l_item->cache_data.ts_created = a_tx->header.ts_created;
        HASH_ADD_BYHASHVALUE(hh, l_ledger_pvt->threshold_txs, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item);
        debug_if(g_debug_ledger, L_DEBUG, "Tx %s added to threshold", dap_hash_fast_to_str_static(a_tx_hash));
    }
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
    return 0;
}

void dap_ledger_pvt_threshold_txs_proc(dap_ledger_t *a_ledger)
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
                if ( !is_ledger_mapped(l_ledger_pvt) )
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
            if ( !is_ledger_mapped(l_pvt) )
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
bool dap_ledger_pvt_cache_gdb_load_balances_callback(dap_global_db_instance_t *a_dbi,
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
        if (l_ptr++)
            dap_strncpy(l_balance_item->token_ticker, l_ptr, sizeof(l_balance_item->token_ticker));
        l_balance_item->balance = *(uint256_t *)a_values[i].value;
        HASH_ADD_KEYPTR(hh, l_ledger_pvt->balance_accounts, l_balance_item->key,
                        strlen(l_balance_item->key), l_balance_item);
    }
    pthread_mutex_lock( &l_ledger_pvt->load_mutex );
    l_ledger_pvt->load_end = true;
    pthread_cond_broadcast( &l_ledger_pvt->load_cond );
    pthread_mutex_unlock( &l_ledger_pvt->load_mutex );
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
    dap_global_db_get_all(l_gdb_group, 0, dap_ledger_pvt_cache_gdb_load_tokens_callback, a_ledger);
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
 * @param a_net_name char * network name, for example "kelvin-testnet"
 * @return dap_ledger_t*
 */
dap_ledger_t *dap_ledger_create(dap_chain_net_t *a_net, uint16_t a_flags)
{
    dap_ledger_t *l_ledger = dap_ledger_handle_new();
    dap_return_val_if_fail(l_ledger, NULL);

    l_ledger->net = a_net;
    dap_ledger_private_t *l_ledger_pvt = PVT(l_ledger);
    l_ledger_pvt->flags = a_flags;
    if ( is_ledger_threshld(l_ledger_pvt) )
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
    if ( is_ledger_cached(l_ledger_pvt) )
        // load ledger cache from GDB
        dap_ledger_load_cache(l_ledger);
#endif
    // Decrees initializing
    dap_ledger_decree_init(l_ledger);
    dap_chain_t *l_default_tx_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (l_default_tx_chain) {
        dap_chain_add_callback_timer(l_default_tx_chain, s_blockchain_timer_callback, NULL);
        dap_chain_atom_confirmed_notify_add(l_default_tx_chain, s_blockchain_cutoff_callback, NULL, 0);
    } else
        log_it(L_WARNING, "Can't get deafult chain for transactions, timelocks for it will be disabled");
    return l_ledger;
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
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_tx_sig);
    return dap_list_find(a_ledger->net->pub.keys, l_sign, s_callback_sign_compare);
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
    if (strcmp("voting", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_VOTING;
    if (strcmp("vote", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_VOTE;
    if (strcmp("hold", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_HOLD;
    if (strcmp("take", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_TAKE;
    if (strcmp("refill", a_str) == 0) return DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_REFILL;


    return DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
}

bool dap_ledger_tx_service_info(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, 
                                dap_chain_srv_uid_t *a_uid, char **a_service_name,  dap_chain_tx_tag_action_type_t *a_action)
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

bool dap_ledger_deduct_tx_tag(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, char **a_service_name, dap_chain_srv_uid_t *a_tag, dap_chain_tx_tag_action_type_t *a_action)
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

const char *dap_ledger_tx_tag_str_by_uid(dap_chain_srv_uid_t a_service_uid)
{
    dap_ledger_service_info_t *l_new_sinfo = NULL;
    
    int l_tmp = a_service_uid.raw_ui64;

    pthread_rwlock_rdlock(&s_services_rwlock);
    HASH_FIND_INT(s_services, &l_tmp, l_new_sinfo);
    pthread_rwlock_unlock(&s_services_rwlock);
    
    return l_new_sinfo ? l_new_sinfo->tag_str : "unknown";
}


/**
 * Delete all transactions from the cache
 */
void dap_ledger_purge(dap_ledger_t *a_ledger, bool a_preserve_db)
{
    dap_ledger_tx_purge(a_ledger, a_preserve_db);
    dap_ledger_token_purge(a_ledger, a_preserve_db);
    dap_ledger_decree_purge(a_ledger);
    PVT(a_ledger)->load_end = false;
}

int dap_ledger_chain_purge(dap_chain_t *a_chain, size_t a_atom_size)
{
    dap_return_val_if_fail(a_chain, -1);
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    dap_ledger_tx_purge(l_net->pub.ledger, false);
    if (dap_ledger_anchor_purge(l_net->pub.ledger, a_chain->id))
        return -2;
    if (dap_chain_srv_purge_all(a_chain->net_id))
        return -3;
    if (a_atom_size && dap_chain_cell_truncate(a_chain, c_dap_chain_cell_id_null, a_atom_size))
        return -4;
    dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net);
    if (dap_chain_cell_remove(a_chain, c_dap_chain_cell_id_null, l_role.enums == NODE_ROLE_ARCHIVE))
        return -5;
    if (dap_chain_purge(a_chain))
        return -6;
    if (dap_chain_cell_create(a_chain, c_dap_chain_cell_id_null))
        return -7;
    return 0;
}

void dap_ledger_tx_purge(dap_ledger_t *a_ledger, bool a_preserve_db)
{
    dap_return_if_fail(a_ledger);
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->threshold_txs_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->stake_lock_rwlock);

    /* Delete regular transactions */
    dap_ledger_tx_item_t *l_item_current, *l_item_tmp;
    char *l_gdb_group;
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_pvt->ledger_items, l_item_current);
        if (!is_ledger_mapped(l_ledger_pvt))
            DAP_DELETE(l_item_current->tx);
        DAP_DELETE(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete balances */
    dap_ledger_wallet_balance_t *l_balance_current, *l_balance_tmp;
    HASH_ITER(hh, l_ledger_pvt->balance_accounts, l_balance_current, l_balance_tmp) {
        HASH_DEL(l_ledger_pvt->balance_accounts, l_balance_current);
        DAP_DEL_MULTY(l_balance_current->key, l_balance_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_BALANCES_STR);
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
        if (!is_ledger_mapped(l_ledger_pvt))
            DAP_DELETE(l_item_current->tx);
        DAP_DEL_Z(l_item_current);
    }

    l_ledger_pvt->ledger_items         = NULL;
    l_ledger_pvt->balance_accounts     = NULL;
    l_ledger_pvt->threshold_txs        = NULL;

    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);
}

void dap_ledger_token_purge(dap_ledger_t *a_ledger, bool a_preserve_db)
{
    dap_return_if_fail(a_ledger);
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    pthread_rwlock_wrlock(&l_ledger_pvt->tokens_rwlock);

    /* Delete tokens and their emissions */
    dap_ledger_token_item_t *l_token_current, *l_token_tmp;
    dap_ledger_token_emission_item_t *l_emission_current, *l_emission_tmp;
    HASH_ITER(hh, l_ledger_pvt->tokens, l_token_current, l_token_tmp) {
        HASH_DEL(l_ledger_pvt->tokens, l_token_current);
        pthread_rwlock_wrlock(&l_token_current->token_emissions_rwlock);
        HASH_ITER(hh, l_token_current->token_emissions, l_emission_current, l_emission_tmp) {
            HASH_DEL(l_token_current->token_emissions, l_emission_current);
            DAP_DEL_MULTY(l_emission_current->datum_token_emission, l_emission_current);
        }
        pthread_rwlock_unlock(&l_token_current->token_emissions_rwlock);
        pthread_rwlock_destroy(&l_token_current->token_emissions_rwlock);
        DAP_DEL_MULTY(l_token_current->datum_token, l_token_current->datum_token, l_token_current->auth_pkeys, l_token_current->auth_pkey_hashes,
            l_token_current->tx_recv_allow, l_token_current->tx_recv_block, l_token_current->tx_send_allow, l_token_current->tx_send_block, l_token_current);
    }
    if (!a_preserve_db) {
        char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TOKENS_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
        l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_EMISSIONS_STR);
        dap_global_db_erase_table(l_gdb_group, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    l_ledger_pvt->tokens               = NULL;
    pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
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
        debug_if(g_debug_ledger, L_INFO, "Found address in cache with balance %s",
            dap_uint256_to_char(l_balance_item->balance, NULL));
        l_ret = l_balance_item->balance;
    } else {
        debug_if(g_debug_ledger, L_WARNING, "Balance item %s not found", l_wallet_balance_key);
    }
    DAP_DELETE(l_wallet_balance_key);
    return l_ret;
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
dap_list_t* dap_ledger_tx_cache_find_out_cond_all(dap_ledger_t *a_ledger, dap_chain_srv_uid_t a_srv_uid)
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
        ret = NULL;
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
        if (!ret || !dap_hash_fast_is_blank(&it->out_metadata[l_out_idx].tx_spent_hash_fast))
            continue;
        dap_hash_fast_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, l_subtype, &it->tx_hash_fast);
        dap_chain_datum_tx_t *l_tx = dap_hash_fast_is_blank(&l_owner_tx_hash) ? it->tx
                                                                              : dap_ledger_tx_find_by_hash(a_ledger, &l_owner_tx_hash);
        if (!l_tx) {
            log_it(L_ERROR, "Can't find owner for tx %s", dap_hash_fast_to_str_static(&it->tx_hash_fast));
            continue;
        }
        // Get sign item from transaction
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        // Get dap_sign_t from item
        dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign(l_tx_sig);
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
    dap_hash_fast_t l_first_tx_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, a_cond_subtype, a_tx_hash);
    dap_chain_datum_tx_t *l_first_tx = dap_hash_fast_is_blank(&l_first_tx_hash) ? l_check_tx
                                                                                : dap_ledger_tx_find_by_hash(a_ledger, &l_first_tx_hash);
    if (!l_first_tx) {
        log_it(L_ERROR, "Can't find owner tx %s", dap_hash_fast_to_str_static(&l_first_tx_hash));
        return false;
    }
    dap_chain_tx_sig_t *l_first_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_first_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_first_tx_sig);
    if (!l_sign) {
        log_it(L_ERROR, "Can't find signature for tx %s", dap_hash_fast_to_str_static(&l_first_tx_hash));
        return false;
    }
    return dap_sign_compare_pkeys(a_owner_sign, l_sign);
}

bool dap_ledger_cache_enabled(dap_ledger_t *a_ledger)
{
    return is_ledger_cached(PVT(a_ledger));
}
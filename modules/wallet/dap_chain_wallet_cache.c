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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>

#include "dap_chain_wallet_cache.h"
#include "dap_chain_wallet.h"
#include "dap_chain.h"
#include "dap_common.h"



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
    void* tx_out;
    int tx_out_idx;
} dap_wallet_tx_cache_output_t;

typedef struct dap_wallet_tx_cache {
    dap_hash_fast_t tx_hash;
    dap_hash_fast_t atom_hash;
    dap_chain_datum_tx_t *tx;
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
    dap_wallet_tx_cache_output_t *output;
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

static dap_s_wallets_cache_type_t s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_LOCAL;
static dap_wallet_cache_t *s_wallets_cache = NULL;
static pthread_rwlock_t s_wallet_cache_rwlock;
static bool s_debug_more = false;

static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx,
                                    dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                    dap_chain_net_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action, char a_cache_op);
static int s_save_cache_for_addr_in_net(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr);
static void s_callback_datum_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_hash_fast_t *a_atom_hash, void *a_datum, 
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, 
                                    dap_chain_net_srv_uid_t a_uid);
static void s_callback_datum_removed_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum);
static void s_wallet_opened_callback(dap_chain_wallet_t *a_wallet, void *a_arg);

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

int dap_chain_wallet_cache_init()
{
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

    s_debug_more = dap_config_get_item_bool_default(g_config,"wallet","debug_more", s_debug_more);

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        debug_if(s_debug_more, L_DEBUG, "Wallet cache is disabled.");
        return 0;
    }

    log_it(L_INFO, "Wallet cache type: %s", s_wallet_cache_type_to_str(s_wallets_cache_type));

    pthread_rwlock_init(&s_wallet_cache_rwlock, NULL);

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
                    dap_chain_add_callback_datum_index_notify(l_chain, s_callback_datum_notify, l_pt, l_arg);
                    dap_chain_add_callback_datum_removed_from_index_notify(l_chain, s_callback_datum_removed_notify, l_pt, l_arg);
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

    return 0;
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
    if (!l_wallet_item || l_wallet_item->is_loading){
        log_it(L_INFO, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return -101;
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
        bool skip = false;
        if (a_token){
            skip = true;
            if (*l_current_wallet_tx_iter->token_ticker &&
                !dap_strcmp(l_current_wallet_tx_iter->token_ticker, a_token))
            {
                skip = false;
            } else if (l_current_wallet_tx_iter->multichannel){
                for (dap_list_t *l_temp = l_current_wallet_tx_iter->tx_wallet_outputs; l_temp; l_temp=l_temp->next){
                    dap_wallet_tx_cache_output_t *l_cur_out_cache = (dap_wallet_tx_cache_output_t*)l_temp->data;
                    if ((*(dap_chain_tx_item_type_t*)l_cur_out_cache->tx_out == TX_ITEM_TYPE_OUT_EXT) && !dap_strcmp(a_token, ((dap_chain_tx_out_ext_t*)l_cur_out_cache->tx_out)->token)){
                        skip = false;
                        break;
                    }
                }
            }
        }
        
        if (skip)
            continue;

        // Now work with it
        *a_tx_hash_curr = l_current_wallet_tx_iter->tx_hash;
        if (a_datum)
            *a_datum = l_current_wallet_tx_iter->tx;
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
    if (!l_wallet_item || l_wallet_item->is_loading){
        debug_if(s_debug_more, L_DEBUG, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return -101;
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
        // Now work with it
        *a_tx_hash_curr = l_current_wallet_tx->tx_hash;
        if (a_datum)
            *a_datum = l_current_wallet_tx->tx;
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

int dap_chain_wallet_cache_tx_find_outs(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t *a_value_transfer)
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
    if (!l_wallet_item|| l_wallet_item->is_loading){
        debug_if(s_debug_more, L_DEBUG, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return -101;
    }

    dap_wallet_cache_unspent_outs_t *l_item_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_wallet_item->unspent_outputs, l_item_cur, l_tmp){

        if (dap_strcmp(l_item_cur->token_ticker, a_token_ticker))
            continue;
        else {
            dap_wallet_tx_cache_output_t *l_out_cur = (dap_wallet_tx_cache_output_t*)l_item_cur->output;
            dap_chain_tx_item_type_t l_type = *(dap_chain_tx_item_type_t*)l_out_cur->tx_out;
            uint256_t l_value = { };
            switch (l_type) {
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t*)l_out_cur->tx_out;
                if (!l_out->header.value)
                    continue;
                l_value = GET_256_FROM_64(l_out->header.value);
            } break;
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t*)l_out_cur->tx_out;
                if (IS_ZERO_256(l_out->header.value) )
                    continue;
                l_value = l_out->header.value;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t*)l_out_cur->tx_out;
                if (dap_strcmp(l_out_ext->token, a_token_ticker))
                    continue;
                if (IS_ZERO_256(l_out_ext->header.value) )
                    continue;
                l_value = l_out_ext->header.value;
            } break;
            default:
                continue;
            }

            dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
            *l_item = (dap_chain_tx_used_out_item_t) { l_item_cur->key.tx_hash, (uint32_t)l_item_cur->key.out_idx, l_value};
            l_list_used_out = dap_list_append(l_list_used_out, l_item);
            SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
        } 
    }
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);

    *a_outs_list = l_list_used_out;
    if (a_value_transfer)
        *a_value_transfer = l_value_transfer;
   
    return 0;
}

int dap_chain_wallet_cache_tx_find_outs_with_val(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t a_value_need, uint256_t *a_value_transfer)
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
    if (!l_wallet_item || l_wallet_item->is_loading){
        debug_if(s_debug_more, L_DEBUG, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return -101;
    }

    dap_wallet_cache_unspent_outs_t *l_item_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_wallet_item->unspent_outputs, l_item_cur, l_tmp){

        if (dap_strcmp(l_item_cur->token_ticker, a_token_ticker))
            continue;
        else {
            dap_wallet_tx_cache_output_t *l_out_cur = (dap_wallet_tx_cache_output_t*)l_item_cur->output;
            dap_chain_tx_item_type_t l_type = *(dap_chain_tx_item_type_t*)l_out_cur->tx_out;
            uint256_t l_value = { };
            switch (l_type) {
            case TX_ITEM_TYPE_OUT_OLD: {
                dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t*)l_out_cur->tx_out;
                if (!l_out->header.value)
                    continue;
                l_value = GET_256_FROM_64(l_out->header.value);
            } break;
            case TX_ITEM_TYPE_OUT: {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t*)l_out_cur->tx_out;
                if (IS_ZERO_256(l_out->header.value) )
                    continue;
                l_value = l_out->header.value;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t*)l_out_cur->tx_out;
                if (dap_strcmp(l_out_ext->token, a_token_ticker))
                    continue;
                if (IS_ZERO_256(l_out_ext->header.value) )
                    continue;
                l_value = l_out_ext->header.value;
            } break;
            default:
                continue;
            }

            dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
            *l_item = (dap_chain_tx_used_out_item_t) { l_item_cur->key.tx_hash, (uint32_t)l_item_cur->key.out_idx, l_value};
            l_list_used_out = dap_list_append(l_list_used_out, l_item);
            SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
        } 
        if ( compare256(l_value_transfer, a_value_need) >= 0 ) {
            break;
        }
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

                for (dap_chain_datum_t *l_datum = l_chain->callback_datum_iter_get_first(l_iter);
                        l_datum;
                        l_datum = l_chain->callback_datum_iter_get_next(l_iter)){

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

static void s_callback_datum_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_hash_fast_t *a_atom_hash, void *a_datum, 
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, dap_chain_net_srv_uid_t a_uid)
{
    dap_atom_notify_arg_t *l_arg = (dap_atom_notify_arg_t*)a_arg;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*)a_datum;
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

typedef struct wallet_cache_load_args {
    dap_chain_net_t *net;
    dap_chain_addr_t addr;
    dap_wallet_cache_t *wallet_item;
} wallet_cache_load_args_t;

static void *s_wallet_load(void *a_arg)
{
    wallet_cache_load_args_t *l_args = (wallet_cache_load_args_t*)a_arg;

    s_save_cache_for_addr_in_net(l_args->net, &l_args->addr);

    l_args->wallet_item->is_loading = false;
    DAP_DEL_Z(a_arg);

    return NULL;
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
            continue;
        }

        l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
        memcpy (&l_wallet_item->wallet_addr, l_addr, sizeof(dap_chain_addr_t));
        l_wallet_item->is_loading = true;
        HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);

        wallet_cache_load_args_t *l_args = DAP_NEW_Z(wallet_cache_load_args_t);
        l_args->net = l_net;
        l_args->addr = *l_addr;
        l_args->wallet_item = l_wallet_item;

        pthread_t l_tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&l_tid, &attr, s_wallet_load, l_args);
        
        // s_save_cache_for_addr_in_net(l_net, l_addr); 
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
    int l_ret_val = 0, l_items_cnt = 0, l_out_idx = 0, l_prev_idx;
    bool l_multichannel = false;
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
        int l_prev_idx;

        switch(*l_tx_item) {
        case TX_ITEM_TYPE_IN: {
            l_prev_tx_hash = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_prev_hash;
            if ( dap_hash_fast_is_blank(&l_prev_tx_hash) )
                continue;
            dap_chain_datum_t *l_prev_datum = a_chain->callback_datum_find_by_hash(a_chain, &l_prev_tx_hash, NULL, NULL);
            dap_chain_datum_tx_t *l_tx_prev = l_prev_datum ? (dap_chain_datum_tx_t *)(l_prev_datum->data) : NULL;
            if (!l_tx_prev) {
                log_it(L_ERROR, "Can't find previous transaction by hash \"%s\"", dap_hash_fast_to_str_static(&l_prev_tx_hash));
                continue;
            }
            l_prev_idx = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_out_prev_idx;
            l_prev_item = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_prev_idx);
            if (!l_prev_item) {
                log_it(L_ERROR, "Can't find output %d in tx \"%s\"", l_prev_idx, dap_hash_fast_to_str_static(&l_prev_tx_hash));
                continue;
            }
            switch (*l_prev_item) {
            case TX_ITEM_TYPE_OUT_OLD:
                l_value = GET_256_FROM_64(((dap_chain_tx_out_old_t*)l_prev_item)->header.value);
                l_addr = ((dap_chain_tx_out_old_t*)l_prev_item)->addr;
                break;
            case TX_ITEM_TYPE_OUT:
            case TX_ITEM_TYPE_OUT_EXT:
                l_value = ((dap_chain_tx_out_ext_t*)l_prev_item)->header.value;
                l_addr = ((dap_chain_tx_out_ext_t*)l_prev_item)->addr;
                break;
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
        case TX_ITEM_TYPE_OUT_COND:
        /* Make it explicit for possible future STAKE_LOCK adoption */
        // TODO
            ++l_out_idx;
        default:
            continue;
        }

        if ( !m_check_addr(l_addr) ) {
            l_out_idx += (int)(*l_tx_item != TX_ITEM_TYPE_IN);
            continue;
        }

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
                *l_wallet_tx_item = (dap_wallet_tx_cache_t){ .tx_hash = *a_tx_hash, .atom_hash = *a_atom_hash, .tx = a_tx,
                    .multichannel = l_multichannel, .ret_code = a_ret_code, .srv_uid = a_srv_uid, .action = a_action };
                dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            }
            break;
        case 'd': {
            if (!l_wallet_item)
                continue;
            HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            if (l_wallet_tx_item){
                HASH_DEL(l_wallet_item->wallet_txs, l_wallet_tx_item);
                dap_list_free_full(l_wallet_tx_item->tx_wallet_inputs, NULL);
                dap_list_free_full(l_wallet_tx_item->tx_wallet_outputs, NULL);
                DAP_DELETE(l_wallet_tx_item);
            }
        }
        default:
            continue;
        }

        switch (*l_tx_item) {
        case TX_ITEM_TYPE_IN:
            switch (a_cache_op) {
            case 'a': {
                dap_wallet_tx_cache_input_t *l_tx_in = DAP_NEW(dap_wallet_tx_cache_input_t);
                *l_tx_in = (dap_wallet_tx_cache_input_t) { .tx_prev_hash = l_prev_tx_hash, .tx_out_prev_idx = l_prev_idx, .value = l_value };
                l_wallet_tx_item->tx_wallet_inputs = dap_list_append(l_wallet_tx_item->tx_wallet_inputs, l_tx_in);
                /* Delete unspent out from cache */
                if (!a_ret_code) {
                    unspent_cache_hh_key key = { .tx_hash = l_prev_tx_hash, .out_idx = l_prev_idx };
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    HASH_FIND(hh, l_wallet_item->unspent_outputs, &key, sizeof(unspent_cache_hh_key), l_item);
                    if (l_item) {
                        HASH_DEL(l_wallet_item->unspent_outputs, l_item);
                        DAP_DELETE(l_item);
                    }
                }
            } break;
            case 'd': {
                dap_wallet_tx_cache_t *l_wallet_prev_tx_item = NULL;
                HASH_FIND(hh, l_wallet_item->wallet_txs, &l_prev_tx_hash, sizeof(dap_hash_fast_t), l_wallet_prev_tx_item);
                if ( l_wallet_prev_tx_item && !l_wallet_prev_tx_item->ret_code ) {
                    dap_wallet_tx_cache_output_t l_sought_out = { .tx_out_idx = l_prev_idx };
                    void *l_out = dap_list_find(l_wallet_prev_tx_item->tx_wallet_outputs, &l_sought_out, s_out_idx_cmp);
                    if (l_out) {
                        dap_wallet_cache_unspent_outs_t *l_unspent_out = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
                        *l_unspent_out = (dap_wallet_cache_unspent_outs_t) { .key = { .tx_hash = l_prev_tx_hash, .out_idx = l_prev_idx },
                            .output = l_out };
                        dap_strncpy(l_unspent_out->token_ticker, *l_prev_item == TX_ITEM_TYPE_OUT_EXT ? ((dap_chain_tx_out_ext_t*)l_tx_item)->token
                                    : l_wallet_prev_tx_item->token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                        HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_unspent_out);
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
                dap_wallet_tx_cache_output_t *l_out = DAP_NEW(dap_wallet_tx_cache_output_t);
                *l_out = (dap_wallet_tx_cache_output_t){ .tx_out = l_tx_item, .tx_out_idx = l_out_idx };
                l_wallet_tx_item->tx_wallet_outputs = dap_list_append(l_wallet_tx_item->tx_wallet_outputs, l_out);
                /* Add unspent out to cache */ 
                if (!a_ret_code) {
                    dap_wallet_cache_unspent_outs_t *l_unspent_out = DAP_NEW(dap_wallet_cache_unspent_outs_t);
                    *l_unspent_out = (dap_wallet_cache_unspent_outs_t) {
                        .key = { .tx_hash = *a_tx_hash, .out_idx = l_out_idx },
                        .output = l_out
                    };
                    dap_strncpy(l_unspent_out->token_ticker, *l_tx_item == TX_ITEM_TYPE_OUT_EXT ? ((dap_chain_tx_out_ext_t*)l_tx_item)->token
                                : a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);                   
                    HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_unspent_out);
                }
                ++l_out_idx;
            } break;
            case 'd': {
                if ( !l_wallet_item->wallet_txs ) {
                    HASH_DEL(s_wallets_cache, l_wallet_item);
                    DAP_DELETE(l_wallet_item);
                }            
                unspent_cache_hh_key key = { .tx_hash = *a_tx_hash, .out_idx = l_out_idx };
                dap_wallet_cache_unspent_outs_t *l_item = NULL;
                HASH_FIND(hh, l_wallet_item->unspent_outputs, &key, sizeof(unspent_cache_hh_key), l_item);
                if (l_item) {
                    HASH_DEL(l_wallet_item->unspent_outputs, l_item);
                    DAP_DELETE(l_item);
                }
            } break;
            default:
                break;
            }
            break;
        }
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    }
    return l_ret_val;
}

static void s_wallet_cache_iter_fill(dap_chain_wallet_cache_iter_t *a_cache_iter, dap_wallet_tx_cache_t *a_cache_index)
{
    a_cache_iter->cur_item = (void*)a_cache_index;
    if (a_cache_index) {
        a_cache_iter->cur_tx = a_cache_index->tx;
        a_cache_iter->cur_hash = &a_cache_index->tx_hash;
        a_cache_iter->cur_atom_hash = &a_cache_index->atom_hash;
        a_cache_iter->ret_code = a_cache_index->ret_code;
        a_cache_iter->action = a_cache_index->action;
        a_cache_iter->uid = a_cache_index->srv_uid;    
        a_cache_iter->token_ticker = dap_strcmp(a_cache_index->token_ticker, "0") ? a_cache_index->token_ticker : NULL;
    } else {
        a_cache_iter->cur_tx = NULL;
        a_cache_iter->cur_hash = NULL;
        a_cache_iter->cur_atom_hash = NULL;
        a_cache_iter->ret_code = 0;
        a_cache_iter->token_ticker = NULL;
        a_cache_iter->action = 0;
        a_cache_iter->uid.uint64 = 0;
    }
}


dap_chain_wallet_cache_iter_t *dap_chain_wallet_cache_iter_create(dap_chain_addr_t a_addr)
{
    dap_chain_wallet_cache_iter_t *l_iter = NULL;

    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
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
        
    switch (a_type){
        case DAP_CHAIN_WALLET_CACHE_GET_FIRST:{
            pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_cache = (dap_wallet_cache_t*)a_iter->cur_addr_cache;
            s_wallet_cache_iter_fill(a_iter, l_wallet_cache ? l_wallet_cache->wallet_txs : NULL);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        case DAP_CHAIN_WALLET_CACHE_GET_LAST:{
            pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_cache = (dap_wallet_cache_t*)a_iter->cur_addr_cache;
            dap_wallet_tx_cache_t *l_tx_cache = NULL;
            if (l_wallet_cache)
                l_tx_cache = HASH_LAST(l_wallet_cache->wallet_txs);
            s_wallet_cache_iter_fill(a_iter, l_tx_cache);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        case DAP_CHAIN_WALLET_CACHE_GET_NEXT:{
            pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
            dap_wallet_tx_cache_t *l_tx_cache = a_iter->cur_item ? (dap_wallet_tx_cache_t*)a_iter->cur_item : NULL;
            l_tx_cache = l_tx_cache && l_tx_cache->hh.next ? l_tx_cache->hh.next : NULL;
            s_wallet_cache_iter_fill(a_iter, l_tx_cache);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        case DAP_CHAIN_WALLET_CACHE_GET_PREVIOUS:{
            pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
            dap_wallet_tx_cache_t *l_tx_cache = a_iter->cur_item ? (dap_wallet_tx_cache_t*)a_iter->cur_item : NULL;
            l_tx_cache = l_tx_cache && l_tx_cache->hh.prev ? l_tx_cache->hh.prev : NULL;
            s_wallet_cache_iter_fill(a_iter, l_tx_cache);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        } break;
        default:
            break;
    }

    return a_iter->cur_tx;
}

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
    dap_list_t *tx_wallet_outputs;
    dap_list_t *history_items_list;
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

    UT_hash_handle hh;
} dap_wallet_cache_t;

typedef struct dap_atom_notify_arg {
    dap_chain_t *chain;
    dap_chain_net_t *net;
} dap_atom_notify_arg_t;

static dap_s_wallets_cache_type_t s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_ALL;
static dap_wallet_cache_t *s_wallets_cache = NULL;
static pthread_rwlock_t s_wallet_cache_rwlock;

static int s_save_tx_into_wallet_cache(dap_chain_t *a_chain, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                                dap_chain_net_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action);
static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                                dap_chain_net_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action);
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

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        log_it( L_WARNING, "Wallet cache is disabled.");
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
                    dap_chain_datum_iter_t *l_iter = l_chain->callback_datum_iter_create(l_chain);
                    for (dap_chain_datum_t *l_datum = l_chain->callback_datum_iter_get_first(l_iter);
                            l_datum;
                            l_datum = l_chain->callback_datum_iter_get_next(l_iter)){

                        s_callback_datum_notify(l_arg, l_iter->cur_hash, l_iter->cur_atom_hash, l_datum, l_iter->cur_size, l_iter->ret_code, l_iter->action, l_iter->uid);
                    }
                    l_chain->callback_datum_iter_delete(l_iter);
                    dap_chain_add_callback_datum_index_notify(l_chain, s_callback_datum_notify, NULL, l_arg);
                    dap_chain_add_callback_datum_removed_from_index_notify(l_chain, s_callback_datum_removed_notify, NULL, l_arg);
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
            log_it(L_ERROR, "Wallet %s saved.", dap_chain_addr_to_str_static(l_addr));
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
    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    HASH_FIND(hh, s_wallets_cache, a_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    if (!l_wallet_item){
        log_it(L_ERROR, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        return -101;
    }
    dap_wallet_tx_cache_t *l_current_wallet_tx = NULL;
    if (!dap_hash_fast_is_blank(a_tx_hash_curr)) {
        // find start transaction
        HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash_curr, sizeof(dap_chain_hash_fast_t), l_current_wallet_tx);
        if (!l_current_wallet_tx){
            log_it(L_ERROR, "Can't find tx %s for address %s", dap_hash_fast_to_str_static(a_tx_hash_curr), dap_chain_addr_to_str_static(a_addr));
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

    if (!a_tx_hash_curr)
        return -100;

    pthread_rwlock_rdlock(&s_wallet_cache_rwlock);
    HASH_FIND(hh, s_wallets_cache, a_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    if (!l_wallet_item){
        log_it(L_ERROR, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
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
    if (!l_wallet_item){
        log_it(L_ERROR, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
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
    if (!l_wallet_item){
        log_it(L_ERROR, "Can't find wallet with address %s", dap_chain_addr_to_str_static(a_addr));
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

static int s_save_tx_into_wallet_cache(dap_chain_t *a_chain, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                                dap_chain_net_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action)
{
    int l_ret_val = 0;
    int l_items_cnt = 0;

    
    bool l_multichannel = false;
    int l_out_idx = 0, i = 0;
    uint8_t *l_tx_item = NULL;
    size_t l_size;

    bool l_is_need_correction = false;
    bool l_continue = true;
    uint256_t l_corr_value = {}, l_cond_value = {};
    bool l_recv_from_cond = false, l_send_to_same_cond = false;
        
    dap_chain_addr_t *l_src_addr = NULL;
    bool l_base_tx = false, l_reward_collect = false;
    const char *l_noaddr_token = NULL;

    dap_chain_addr_t  l_net_fee_addr = {};
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, NULL, &l_net_fee_addr);
    const char *l_native_ticker = l_net->pub.native_ticker;

    int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
    uint8_t *l_tx_item = NULL;
    size_t l_size; int i, q = 0;
    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_IN_ALL, l_size, i, a_tx) {
        dap_chain_hash_fast_t *l_tx_prev_hash = NULL;
        int l_tx_prev_out_idx;
        dap_chain_datum_tx_t *l_tx_prev = NULL;
        switch (*l_tx_item) {
        case TX_ITEM_TYPE_IN: {
            dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)l_tx_item;
            l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
            l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
        } break;
        case TX_ITEM_TYPE_IN_COND: {
            dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_tx_item;
            l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
            l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
        } break;
        case TX_ITEM_TYPE_IN_EMS: {
            dap_chain_tx_in_ems_t *l_tx_in_ems = (dap_chain_tx_in_ems_t *)l_tx_item;
            l_base_tx = true;
            l_noaddr_token = l_tx_in_ems->header.ticker;
        } break;
        case TX_ITEM_TYPE_IN_REWARD: {
            l_base_tx = l_reward_collect = true;
            l_noaddr_token = l_native_ticker;
        }
        default:
            continue;
        }

        dap_chain_datum_t *l_datum_prev = l_tx_prev_hash ?
                    a_chain->callback_datum_find_by_hash(a_chain, l_tx_prev_hash, NULL, NULL) : NULL;
        l_tx_prev = l_datum_prev && l_datum_prev->header.type_id == DAP_CHAIN_DATUM_TX ? (dap_chain_datum_tx_t *)l_datum_prev->data : NULL;
        if (l_tx_prev) {
            uint8_t *l_prev_out_union = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
            if (!l_prev_out_union)
                continue;
            switch (*l_prev_out_union) {
            case TX_ITEM_TYPE_OUT:
                l_src_addr = &((dap_chain_tx_out_t *)l_prev_out_union)->addr;
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                l_src_addr = &((dap_chain_tx_out_ext_t *)l_prev_out_union)->addr;
                break;
            case TX_ITEM_TYPE_OUT_COND: {
                dap_chain_tx_out_cond_t *l_cond_prev = (dap_chain_tx_out_cond_t *)l_prev_out_union;
                l_src_subtype = l_cond_prev->header.subtype;
                if (l_cond_prev->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                    l_noaddr_token = l_native_ticker;
                else {
                    l_recv_from_cond = true;
                    l_cond_value = l_cond_prev->header.value;
                    l_noaddr_token = a_main_token_ticker;
                }
            } break;
            default:
                break;
            }
        }
        // if (l_src_addr && !dap_chain_addr_compare(l_src_addr, a_addr))
        //     break;  //it's not our addr        
    }
    
    uint256_t l_fee_sum = uint256_0;
    uint8_t *l_tx_item = NULL;
    size_t l_size; int i, q = 0;
    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_tx) {
        dap_chain_addr_t *l_dst_addr = NULL;
        uint8_t l_type = *l_tx_item;
        uint256_t l_value;
        const char *l_dst_token = NULL;
        switch (l_type) {
        case TX_ITEM_TYPE_OUT:
            l_dst_addr = &((dap_chain_tx_out_t *)l_tx_item)->addr;
            l_value = ((dap_chain_tx_out_t *)l_tx_item)->header.value;
            l_dst_token = a_main_token_ticker;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_dst_addr = &((dap_chain_tx_out_ext_t *)l_tx_item)->addr;
            l_value = ((dap_chain_tx_out_ext_t *)l_tx_item)->header.value;
            l_dst_token = ((dap_chain_tx_out_ext_t *)l_tx_item)->token;
            break;
        case TX_ITEM_TYPE_OUT_COND:
            l_value = ((dap_chain_tx_out_cond_t *)l_tx_item)->header.value;
            if (((dap_chain_tx_out_cond_t *)l_tx_item)->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                SUM_256_256(l_fee_sum, ((dap_chain_tx_out_cond_t *)l_tx_item)->header.value, &l_fee_sum);
                l_dst_token = l_native_ticker;
            } else
                l_dst_token = a_main_token_ticker;
        default:
            break;
        }

        if (l_src_addr && l_dst_addr &&
                dap_chain_addr_compare(l_dst_addr, l_src_addr) &&
                dap_strcmp(l_noaddr_token, l_dst_token))
            continue;   // sent to self (coinback)

        if (l_dst_addr && l_net_fee_used && dap_chain_addr_compare(&l_net_fee_addr, l_dst_addr))
            SUM_256_256(l_fee_sum, l_value, &l_fee_sum);
        
        if (l_dst_addr) {  

            dap_wallet_cache_history_item_t *l_item = DAP_NEW_Z(dap_wallet_cache_history_item_t);
            const char *l_src_str = NULL;
            if (l_base_tx){
                l_src_str = l_reward_collect ? "reward collecting" : "emission";
                if (l_reward_collect)
                    l_item->addr.src.reward = true;
                else
                    l_item->addr.src.emission = true;
            } else if (l_src_addr && dap_strcmp(l_dst_token, l_noaddr_token)) { 
                l_src_str = dap_chain_addr_to_str_static(l_src_addr);
                l_item->addr.src.addr = *l_src_addr;
            } else {
                l_src_str = dap_chain_tx_out_cond_subtype_to_str(l_src_subtype);
                l_item->addr.src.subtype = l_src_subtype;
            }

            if (l_recv_from_cond)
                l_value = l_cond_value;
            else if (!dap_strcmp(l_native_ticker, l_noaddr_token)) {
                l_is_need_correction = true;
                l_corr_value = l_value;
            }

            l_item->type = DAP_CHAIN_WALLET_CACHE_HISTORY_ITEM_TYPE_RECV;
            if(l_dst_token)
                dap_strncpy(l_item->token_ticker, l_dst_token, DAP_CHAIN_TICKER_SIZE_MAX);
            else
                dap_strncpy(l_item->token_ticker, "UNKNOWN", DAP_CHAIN_TICKER_SIZE_MAX);

            l_item->value = l_value;
                                     
            if (l_recv_from_cond && !l_cond_recv_object)
                // l_cond_recv_object = j_obj_data;
            else
                // json_object_array_add(j_arr_data, j_obj_data);

            if (l_is_need_correction){
                // l_corr_object = j_obj_data;
            }
                

            // Save into cache
            
        } else if (!l_src_addr || dap_chain_addr_compare(l_src_addr, a_addr)) {
            if (!l_dst_addr && ((dap_chain_tx_out_cond_t *)l_tx_item)->header.subtype == l_src_subtype && l_src_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                continue;
            if (!l_src_addr && l_dst_addr && !dap_chain_addr_compare(l_dst_addr, &l_net_fee_addr))
                continue;
            const char *l_dst_addr_str = NULL;
            if (l_dst_addr)
                l_dst_addr_str = dap_chain_addr_to_str_static(l_dst_addr);
            else {
                dap_chain_tx_out_cond_subtype_t l_dst_subtype = ((dap_chain_tx_out_cond_t *)l_tx_item)->header.subtype;
                l_dst_addr_str = dap_chain_tx_out_cond_subtype_to_str(l_dst_subtype);
                if (l_recv_from_cond && l_dst_subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE && l_dst_subtype == l_src_subtype)
                    l_send_to_same_cond = true;
            }
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_value, &l_coins_str);
                            
  
            json_object_object_add(j_obj_data, "tx_type", json_object_new_string("send"));
            json_object_object_add(j_obj_data, "send_coins", json_object_new_string(l_coins_str));
            json_object_object_add(j_obj_data, "send_datoshi", json_object_new_string(l_value_str));
            json_object_object_add(j_obj_data, "token", l_dst_token ? json_object_new_string(l_dst_token)
                                                                    : json_object_new_string("UNKNOWN"));
            json_object_object_add(j_obj_data, "destination_address", json_object_new_string(l_dst_addr_str));
            if (l_send_to_same_cond && !l_cond_send_object)
                l_cond_send_object = j_obj_data;
            else
                json_object_array_add(j_arr_data, j_obj_data);
        }
    }  
    if (l_is_need_correction) {
        SUM_256_256(l_corr_value, l_fee_sum, &l_corr_value);
        const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_corr_value, &l_coins_str);
        json_object_object_add(l_corr_object, "recv_coins", json_object_new_string(l_coins_str));
        json_object_object_add(l_corr_object, "recv_datoshi", json_object_new_string(l_value_str));
    }
    if (l_send_to_same_cond) {
        json_object *l_cond_recv_value_obj = json_object_object_get(l_cond_recv_object, "recv_datoshi");
        const char *l_cond_recv_value_str = json_object_get_string(l_cond_recv_value_obj);
        uint256_t l_cond_recv_value = dap_uint256_scan_uninteger(l_cond_recv_value_str);
        json_object *l_cond_send_value_obj = json_object_object_get(l_cond_send_object, "send_datoshi");
        const char *l_cond_send_value_str = json_object_get_string(l_cond_send_value_obj);
        uint256_t l_cond_send_value = dap_uint256_scan_uninteger(l_cond_send_value_str);
        assert(!IS_ZERO_256(l_cond_recv_value) && !IS_ZERO_256(l_cond_send_value));
        int l_direction = compare256(l_cond_recv_value, l_cond_send_value);
        if (l_direction > 0) {
            SUBTRACT_256_256(l_cond_recv_value, l_cond_send_value, &l_cond_recv_value);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_cond_recv_value, &l_coins_str);
            json_object_object_add(l_cond_recv_object, "recv_coins", json_object_new_string(l_coins_str));
            json_object_object_add(l_cond_recv_object, "recv_datoshi", json_object_new_string(l_value_str));
            json_object_array_add(j_arr_data, l_cond_recv_object);
        } else if (l_direction < 0) {
            SUBTRACT_256_256(l_cond_send_value, l_cond_recv_value, &l_cond_send_value);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_cond_send_value, &l_coins_str);
            json_object_object_add(l_cond_send_object, "send_coins", json_object_new_string(l_coins_str));
            json_object_object_add(l_cond_send_object, "send_datoshi", json_object_new_string(l_value_str));
            json_object_array_add(j_arr_data, l_cond_send_object);
        }
    } else if (l_recv_from_cond)
        json_object_array_add(j_arr_data, l_cond_recv_object);
























    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_tx) {
        uint8_t l_out_type = *l_tx_item;
        dap_chain_addr_t l_addr = {};
        switch(l_out_type){
            case TX_ITEM_TYPE_OUT_OLD: {
                l_addr = ((dap_chain_tx_out_old_t*)l_tx_item)->addr;
            } break;
            case TX_ITEM_TYPE_OUT: {
                l_addr = ((dap_chain_tx_out_t*)l_tx_item)->addr;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                l_addr = ((dap_chain_tx_out_ext_t*)l_tx_item)->addr;
                l_multichannel = true;
            } break;
            default:{
                l_out_idx++;
                continue;
            }
                
        }

        if(!dap_chain_addr_is_blank(&l_addr) && 
                ((s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_LOCAL &&
                dap_chain_wallet_addr_cache_get_name(&l_addr) != NULL) || s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL) &&
                l_addr.net_id.uint64 == a_chain->net_id.uint64
            ){
            pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_item = NULL;
            HASH_FIND(hh, s_wallets_cache, &l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            if (!l_wallet_item){
                l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
                memcpy (&l_wallet_item->wallet_addr, &l_addr, sizeof(dap_chain_addr_t));
                HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            }
            dap_wallet_tx_cache_t *l_wallet_tx_item = NULL;
            HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            if (!l_wallet_tx_item){
                l_wallet_tx_item = DAP_NEW_Z(dap_wallet_tx_cache_t);
                l_wallet_tx_item->tx_hash = *a_tx_hash;
                l_wallet_tx_item->atom_hash = *a_atom_hash;
                l_wallet_tx_item->tx = a_tx;
                dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                l_wallet_tx_item->ret_code = a_ret_code;
                l_wallet_tx_item->srv_uid = a_srv_uid;
                l_wallet_tx_item->action = a_action;
                HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            } 
            l_wallet_tx_item->multichannel = l_multichannel;
            dap_wallet_tx_cache_output_t *l_out = DAP_NEW_Z(dap_wallet_tx_cache_output_t);
            l_out->tx_out = l_tx_item;
            l_out->tx_out_idx = l_out_idx;
            l_wallet_tx_item->tx_wallet_outputs = dap_list_append(l_wallet_tx_item->tx_wallet_outputs, l_out);
            // Add unspent out into cache
            if (!a_ret_code){
                dap_wallet_cache_unspent_outs_t *l_unspent_out = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
                l_unspent_out->key.tx_hash = *a_tx_hash;
                l_unspent_out->key.out_idx = l_out_idx;
                l_unspent_out->output = l_out;
                if (l_out_type != TX_ITEM_TYPE_OUT_EXT)
                    dap_strncpy(l_unspent_out->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                else
                    dap_strncpy(l_unspent_out->token_ticker, ((dap_chain_tx_out_ext_t*)l_tx_item)->token, DAP_CHAIN_TICKER_SIZE_MAX);
                HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_unspent_out);
            }
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        }
        l_out_idx++;
    }

    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_IN_ALL, l_size, i, a_tx) {
        uint8_t l_cond_type = *l_tx_item;
        uint256_t l_value = {};
        dap_chain_addr_t l_addr_from = {};
        if(l_cond_type == TX_ITEM_TYPE_IN){
            dap_hash_fast_t l_prev_tx_hash = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_prev_hash;
            int l_prev_idx = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_out_prev_idx;
            if (dap_hash_fast_is_blank(&l_prev_tx_hash))
                continue;
            dap_chain_datum_tx_t *l_tx_prev = (dap_chain_datum_tx_t *)(a_chain->callback_datum_find_by_hash(a_chain, &l_prev_tx_hash, NULL, NULL)->data);
            if (!l_tx_prev)
                continue;
            uint8_t* l_prev_item = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_prev_idx);
            if (!l_prev_item)
                continue;
            uint8_t l_out_type = *(uint8_t *)l_prev_item;
            switch(l_out_type){
                case TX_ITEM_TYPE_OUT_OLD: {
                    l_value = GET_256_FROM_64(((dap_chain_tx_out_old_t*)l_prev_item)->header.value);
                    l_addr_from = ((dap_chain_tx_out_old_t*)l_prev_item)->addr;
                } break;
                case TX_ITEM_TYPE_OUT:
                case TX_ITEM_TYPE_OUT_EXT: {
                    l_value = ((dap_chain_tx_out_ext_t*)l_prev_item)->header.value;
                    l_addr_from = ((dap_chain_tx_out_ext_t*)l_prev_item)->addr;
                } break;
                default:
                    continue;
            }

            if(!dap_chain_addr_is_blank(&l_addr_from) && ((s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_LOCAL &&
                dap_chain_wallet_addr_cache_get_name(&l_addr_from) != NULL) || s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL) &&
                l_addr_from.net_id.uint64 == a_chain->net_id.uint64
                ){
                pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
                dap_wallet_cache_t *l_wallet_item = NULL;
                HASH_FIND(hh, s_wallets_cache, &l_addr_from, sizeof(dap_chain_addr_t), l_wallet_item);
                if (!l_wallet_item){
                    l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
                    memcpy (&l_wallet_item->wallet_addr, &l_addr_from, sizeof(dap_chain_addr_t));
                    HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
                }
                dap_wallet_tx_cache_t *l_wallet_tx_item = NULL;
                HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                if (!l_wallet_tx_item){
                    l_wallet_tx_item = DAP_NEW_Z(dap_wallet_tx_cache_t);
                    l_wallet_tx_item->tx_hash = *a_tx_hash;
                    l_wallet_tx_item->atom_hash = *a_atom_hash;
                    l_wallet_tx_item->tx = a_tx;
                    dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                    l_wallet_tx_item->multichannel = l_multichannel;
                    l_wallet_tx_item->ret_code = a_ret_code;
                    l_wallet_tx_item->srv_uid = a_srv_uid;
                    l_wallet_tx_item->action = a_action;
                    HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                }
                if (!a_ret_code){
                    unspent_cache_hh_key key = {0};
                    key.tx_hash = l_prev_tx_hash;
                    key.out_idx = l_prev_idx;
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    HASH_FIND(hh, l_wallet_item->unspent_outputs, &key, sizeof(unspent_cache_hh_key), l_item);
                    if (l_item){
                        HASH_DEL(l_wallet_item->unspent_outputs, l_item);
                        DAP_DELETE(l_item);
                    }
                }
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            }
        }
    }

    return l_ret_val;
}


static int s_save_cache_for_addr_in_net(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr)
{
    // Find chain with transactions    
    dap_hash_fast_t l_curr_tx_hash = {0};
    if (dap_chain_wallet_cache_tx_find_in_history(a_addr, NULL, NULL, NULL, NULL, NULL, &l_curr_tx_hash) == 0)
        return 0;

    dap_chain_t *l_chain = a_net->pub.chains;
    while (l_chain){
        for(int i = 0; i < l_chain->datum_types_count; i++) {
            if(l_chain->datum_types[i] == CHAIN_TYPE_TX){
                dap_chain_datum_iter_t *l_iter = l_chain->callback_datum_iter_create(l_chain);

                for (dap_chain_datum_t *l_datum = l_chain->callback_datum_iter_get_first(l_iter);
                        l_datum;
                        l_datum = l_chain->callback_datum_iter_get_next(l_iter)){

                    s_save_tx_cache_for_addr(l_chain, a_addr, (dap_chain_datum_tx_t*)l_datum->data, l_iter->cur_hash, l_iter->cur_atom_hash, l_iter->ret_code, l_iter->token_ticker, l_iter->uid, l_iter->action);
                }
                break;
            }
        }
        l_chain=l_chain->next;
    }

    return 0;
}

static void s_callback_datum_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_hash_fast_t *a_atom_hash,void *a_datum, 
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, 
                                    dap_chain_net_srv_uid_t a_uid)
{
    dap_atom_notify_arg_t *l_arg = (dap_atom_notify_arg_t*)a_arg;

    dap_chain_datum_t *l_datum = (dap_chain_datum_t*)a_datum;
    if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return;

    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)l_datum->data;

    const char* l_main_token_ticker = NULL;

    l_main_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_arg->net->pub.ledger, a_datum_hash);
    s_save_tx_into_wallet_cache(l_arg->chain, l_tx, a_datum_hash, a_atom_hash, a_ret_code, (char*)l_main_token_ticker, a_uid, a_action);
}

static void s_wallet_opened_callback(dap_chain_wallet_t *a_wallet, void *a_arg)
{
    for(dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net=dap_chain_net_iter_next(l_net)){
        // get wallet addr in current net
        dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(a_wallet, l_net->pub.id);
        pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
        dap_wallet_cache_t *l_wallet_item = NULL;
        HASH_FIND(hh, s_wallets_cache, l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
        if (!l_wallet_item){
            l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
            memcpy (&l_wallet_item->wallet_addr, l_addr, sizeof(dap_chain_addr_t));
            HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            s_save_cache_for_addr_in_net(l_net, l_addr);
        } else 
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    }
}


static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                                dap_chain_net_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action)
{
    int l_ret_val = 0;
    int l_items_cnt = 0;

    bool l_multichannel = false;
    int l_out_idx = 0, i = 0;
    uint8_t *l_tx_item = NULL;
    size_t l_size;
    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_tx) {
        uint8_t l_out_type = *l_tx_item;
        dap_chain_addr_t l_addr = {};
        switch(l_out_type){
            case TX_ITEM_TYPE_OUT_OLD: {
                l_addr = ((dap_chain_tx_out_old_t*)l_tx_item)->addr;
            } break;
            case TX_ITEM_TYPE_OUT: {
                l_addr = ((dap_chain_tx_out_t*)l_tx_item)->addr;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                l_addr = ((dap_chain_tx_out_ext_t*)l_tx_item)->addr;
                l_multichannel = true;
            } break;
            default:{
                l_out_idx++;
                continue;
            }
        }

        if(!dap_chain_addr_is_blank(&l_addr) && dap_chain_addr_compare(&l_addr, a_addr) &&
                l_addr.net_id.uint64 == a_chain->net_id.uint64
            ){
            pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_item = NULL;
            HASH_FIND(hh, s_wallets_cache, &l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            if (!l_wallet_item){
                l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
                memcpy (&l_wallet_item->wallet_addr, &l_addr, sizeof(dap_chain_addr_t));
                HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            }
            dap_wallet_tx_cache_t *l_wallet_tx_item = NULL;
            HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            if (!l_wallet_tx_item){
                l_wallet_tx_item = DAP_NEW_Z(dap_wallet_tx_cache_t);
                l_wallet_tx_item->tx_hash = *a_tx_hash;
                l_wallet_tx_item->atom_hash = *a_atom_hash;
                l_wallet_tx_item->tx = a_tx;
                dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                l_wallet_tx_item->ret_code = a_ret_code;
                l_wallet_tx_item->srv_uid = a_srv_uid;
                l_wallet_tx_item->action = a_action;
                HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            } 
            l_wallet_tx_item->multichannel = l_multichannel;
            dap_wallet_tx_cache_output_t *l_out = DAP_NEW_Z(dap_wallet_tx_cache_output_t);
            l_out->tx_out = l_tx_item;
            l_out->tx_out_idx = l_out_idx;
            l_wallet_tx_item->tx_wallet_outputs = dap_list_append(l_wallet_tx_item->tx_wallet_outputs, l_out);
            // Add unspent out into cache
            if (!a_ret_code){
                dap_wallet_cache_unspent_outs_t *l_unspent_out = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
                l_unspent_out->key.tx_hash = *a_tx_hash;
                l_unspent_out->key.out_idx = l_out_idx;
                l_unspent_out->output = l_out;
                if (l_out_type != TX_ITEM_TYPE_OUT_EXT)
                    dap_strncpy(l_unspent_out->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                else
                    dap_strncpy(l_unspent_out->token_ticker, ((dap_chain_tx_out_ext_t*)l_tx_item)->token, DAP_CHAIN_TICKER_SIZE_MAX);
                HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_unspent_out);
            }
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        }
        l_out_idx++;
    }

    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_IN_ALL, l_size, i, a_tx) {
        uint8_t l_item_type = *l_tx_item;
        uint256_t l_value = {};
        dap_chain_addr_t l_addr_from = {};
        if(l_item_type == TX_ITEM_TYPE_IN){
            dap_hash_fast_t l_prev_tx_hash = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_prev_hash;
            int l_prev_idx = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_out_prev_idx;
            if (dap_hash_fast_is_blank(&l_prev_tx_hash))
                continue;
            dap_chain_datum_tx_t *l_tx_prev = (dap_chain_datum_tx_t *)(a_chain->callback_datum_find_by_hash(a_chain, &l_prev_tx_hash, NULL, NULL)->data);
            if (!l_tx_prev)
                continue;
            uint8_t* l_prev_item = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_prev_idx);
            if (!l_prev_item)
                continue;
            uint8_t l_out_type = *(uint8_t *)l_tx_item;
            switch(l_out_type){
                case TX_ITEM_TYPE_OUT_OLD: {
                    l_value = GET_256_FROM_64(((dap_chain_tx_out_old_t*)l_tx_item)->header.value);
                    l_addr_from = ((dap_chain_tx_out_old_t*)l_tx_item)->addr;
                } break;
                case TX_ITEM_TYPE_OUT:
                case TX_ITEM_TYPE_OUT_EXT: {
                    l_value = ((dap_chain_tx_out_ext_t*)l_tx_item)->header.value;
                    l_addr_from = ((dap_chain_tx_out_ext_t*)l_tx_item)->addr;
                } break;
                default:
                    continue;
            }

            if(!dap_chain_addr_is_blank(&l_addr_from)  && dap_chain_addr_compare(&l_addr_from, a_addr) &&
                l_addr_from.net_id.uint64 == a_chain->net_id.uint64
                ){
                pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
                dap_wallet_cache_t *l_wallet_item = NULL;
                HASH_FIND(hh, s_wallets_cache, &l_addr_from, sizeof(dap_chain_addr_t), l_wallet_item);
                if (!l_wallet_item){
                    l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
                    memcpy (&l_wallet_item->wallet_addr, &l_addr_from, sizeof(dap_chain_addr_t));
                    HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
                }
                dap_wallet_tx_cache_t *l_wallet_tx_item = NULL;
                HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                if (!l_wallet_tx_item){
                    l_wallet_tx_item = DAP_NEW_Z(dap_wallet_tx_cache_t);
                    l_wallet_tx_item->tx_hash = *a_tx_hash;
                    l_wallet_tx_item->atom_hash = *a_atom_hash;
                    l_wallet_tx_item->tx = a_tx;
                    dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);
                    l_wallet_tx_item->multichannel = l_multichannel;
                    l_wallet_tx_item->ret_code = a_ret_code;
                    l_wallet_tx_item->srv_uid = a_srv_uid;
                    l_wallet_tx_item->action = a_action;
                    HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                }
                // Delete unspent out from unspent outs cache
                if (!a_ret_code){
                    unspent_cache_hh_key key;
                    key.tx_hash = l_prev_tx_hash;
                    key.out_idx = l_prev_idx;
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    HASH_FIND(hh, l_wallet_item->unspent_outputs, &key, sizeof(unspent_cache_hh_key), l_item);
                    if (l_item){
                        HASH_DEL(l_wallet_item->unspent_outputs, l_item);
                        DAP_DELETE(l_item);
                    }
                }                
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            }
        }
    }

    return l_ret_val;
}

static void s_callback_datum_removed_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum)
{
    if (!a_datum_hash || !a_datum || a_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return;

    dap_atom_notify_arg_t *l_arg = (dap_atom_notify_arg_t*)a_arg;
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)a_datum->data;
    int l_out_idx = 0, i = 0;
    uint8_t *l_tx_item = NULL;
    size_t l_size;
    // remove this tx outs from unspent outs cache
    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, l_tx) {
        uint8_t l_out_type = *l_tx_item;
        dap_chain_addr_t l_addr = {};
        switch(l_out_type){
            case TX_ITEM_TYPE_OUT_OLD: {
                l_addr = ((dap_chain_tx_out_old_t*)l_tx_item)->addr;
            } break;
            case TX_ITEM_TYPE_OUT: {
                l_addr = ((dap_chain_tx_out_t*)l_tx_item)->addr;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                l_addr = ((dap_chain_tx_out_ext_t*)l_tx_item)->addr;
            } break;
            default:{
                l_out_idx++;
                continue;
            }   
        }

        if(!dap_chain_addr_is_blank(&l_addr) && 
                ((s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_LOCAL &&
                dap_chain_wallet_addr_cache_get_name(&l_addr) != NULL) || s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL) &&
                l_addr.net_id.uint64 == l_arg->chain->net_id.uint64
            ){
            pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
            dap_wallet_cache_t *l_wallet_item = NULL;
            HASH_FIND(hh, s_wallets_cache, &l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            if (l_wallet_item){
                dap_wallet_tx_cache_t *l_wallet_tx_item = NULL;
                HASH_FIND(hh, l_wallet_item->wallet_txs, a_datum_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                if (l_wallet_tx_item){
                    HASH_DEL(l_wallet_item->wallet_txs, l_wallet_tx_item);
                    dap_list_free_full(l_wallet_tx_item->tx_wallet_outputs, NULL);
                    DAP_DEL_Z(l_wallet_tx_item);
                }
                if (!l_wallet_item->wallet_txs){
                    HASH_DEL(s_wallets_cache, l_wallet_item);
                    DAP_DEL_Z(l_wallet_item);
                }
                                
                unspent_cache_hh_key key = {0};
                key.tx_hash = *a_datum_hash;
                key.out_idx = l_out_idx;
                dap_wallet_cache_unspent_outs_t *l_item = NULL;
                HASH_FIND(hh, l_wallet_item->unspent_outputs, &key, sizeof(unspent_cache_hh_key), l_item);
                if (l_item){
                    HASH_DEL(l_wallet_item->unspent_outputs, l_item);
                    DAP_DELETE(l_item);
                }
            }
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        }
        l_out_idx++;
    }

    // return previous transactions outs to unspent outs cache
    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_IN_ALL, l_size, i, l_tx) {
        uint8_t l_cond_type = *l_tx_item;
        dap_chain_addr_t l_addr_from = {};
        if(l_cond_type == TX_ITEM_TYPE_IN){
            dap_hash_fast_t l_prev_tx_hash = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_prev_hash;
            int l_prev_idx = ((dap_chain_tx_in_t*)l_tx_item)->header.tx_out_prev_idx;
            if (dap_hash_fast_is_blank(&l_prev_tx_hash))
                continue;
            dap_chain_datum_tx_t *l_tx_prev = (dap_chain_datum_tx_t *)(l_arg->chain->callback_datum_find_by_hash(l_arg->chain, &l_prev_tx_hash, NULL, NULL)->data);
            if (!l_tx_prev)
                continue;
            uint8_t* l_prev_item = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_prev_idx);
            if (!l_prev_item)
                continue;
            uint8_t l_out_type = *(uint8_t *)l_prev_item;
            switch(l_out_type){
                case TX_ITEM_TYPE_OUT_OLD: {
                    l_addr_from = ((dap_chain_tx_out_old_t*)l_prev_item)->addr;
                } break;
                case TX_ITEM_TYPE_OUT:
                case TX_ITEM_TYPE_OUT_EXT: {
                    l_addr_from = ((dap_chain_tx_out_ext_t*)l_prev_item)->addr;
                } break;
                default:
                    continue;
            }

            if(!dap_chain_addr_is_blank(&l_addr_from) && ((s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_LOCAL &&
                dap_chain_wallet_addr_cache_get_name(&l_addr_from) != NULL) || s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL) &&
                l_addr_from.net_id.uint64 == l_arg->chain->net_id.uint64
                ){
                pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
                dap_wallet_cache_t *l_wallet_item = NULL;
                HASH_FIND(hh, s_wallets_cache, &l_addr_from, sizeof(dap_chain_addr_t), l_wallet_item);
                if (l_wallet_item){
                    dap_wallet_tx_cache_t *l_wallet_tx_item = NULL;
                    HASH_FIND(hh, l_wallet_item->wallet_txs, a_datum_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                    if (l_wallet_tx_item){
                        HASH_DEL(l_wallet_item->wallet_txs, l_wallet_tx_item);
                        dap_list_free_full(l_wallet_tx_item->tx_wallet_outputs, NULL);
                        DAP_DEL_Z(l_wallet_tx_item);
                    }
                    // Add unspent out into cache
                    dap_wallet_tx_cache_t *l_wallet_prev_tx_item = NULL;
                    HASH_FIND(hh, l_wallet_item->wallet_txs, &l_prev_tx_hash, sizeof(dap_hash_fast_t), l_wallet_prev_tx_item);
                    if (l_wallet_prev_tx_item){
                        if (!l_wallet_prev_tx_item->ret_code){
                            void *l_out = NULL;
                            for (dap_list_t *it = l_wallet_prev_tx_item->tx_wallet_outputs; it; it=it->next){
                                if (((dap_wallet_tx_cache_output_t *)it->data)->tx_out_idx == l_prev_idx)
                                    l_out = ((dap_wallet_tx_cache_output_t *)it->data)->tx_out;
                            }
                            if (l_out){
                                dap_wallet_cache_unspent_outs_t *l_unspent_out = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
                                l_unspent_out->key.tx_hash = l_prev_tx_hash;
                                l_unspent_out->key.out_idx = l_prev_idx;
                                l_unspent_out->output = l_out;
                                if (l_out_type != TX_ITEM_TYPE_OUT_EXT)
                                    dap_strncpy(l_unspent_out->token_ticker, l_wallet_prev_tx_item->token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                                else
                                    dap_strncpy(l_unspent_out->token_ticker, ((dap_chain_tx_out_ext_t*)l_tx_item)->token, DAP_CHAIN_TICKER_SIZE_MAX);
                                HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_unspent_out);
                            }
                        }   
                    }
                    
                }
                pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            }               
        }
    }            
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

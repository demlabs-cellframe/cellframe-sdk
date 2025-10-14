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

#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>

#include "dap_chain_wallet_cache.h"
#include "dap_chain_wallet_cache_db.h"
#include "dap_chain_wallet.h"
#include "dap_chain.h"
#include "dap_common.h"
#include "dap_chain_cell.h"
#include "dap_chain_block.h"



#define LOG_TAG "dap_chain_wallet_cache"

typedef enum dap_s_wallets_cache_type{
    DAP_WALLET_CACHE_TYPE_DISABLED = 0,
    DAP_WALLET_CACHE_TYPE_LOCAL,
    DAP_WALLET_CACHE_TYPE_ALL
} dap_s_wallets_cache_type_t;

// Storage backend for wallet cache
typedef enum dap_wallet_cache_storage_mode {
    DAP_WALLET_CACHE_STORAGE_RAM = 0,      // Legacy: in-memory hash tables (default)
    DAP_WALLET_CACHE_STORAGE_GLOBALDB = 1  // New: persistent GlobalDB storage
} dap_wallet_cache_storage_mode_t;

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
    dap_chain_datum_tx_t *tx;  // Legacy: RAM pointer (for backward compatibility, may be NULL)
    // NEW: File-based storage (RAM → GlobalDB migration)
    dap_chain_cell_id_t cell_id;    // Cell ID where transaction is stored
    off_t file_offset;               // File offset of BLOCK in file (points to SIZE field before block data)
    size_t datum_offset_in_block;    // Offset of THIS datum WITHIN the block (from start of meta_n_datum_n_sign)
    dap_chain_t *chain;              // Chain context for reading via dap_chain_cell_read_atom_by_offset()
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    bool multichannel;
    int ret_code;
    dap_chain_srv_uid_t srv_uid;
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
static dap_wallet_cache_storage_mode_t s_wallet_cache_storage_mode = DAP_WALLET_CACHE_STORAGE_RAM; // Default: RAM
static dap_wallet_cache_t *s_wallets_cache = NULL;
static pthread_rwlock_t s_wallet_cache_rwlock;
static bool s_debug_more = false;

static dap_chain_datum_tx_t* s_get_tx_from_cache_entry(dap_wallet_tx_cache_t *a_entry);
static int s_load_wallet_cache_from_gdb(dap_chain_addr_t *a_wallet_addr, dap_chain_t *a_chain);
static int s_save_wallet_cache_to_gdb(dap_wallet_cache_t *a_wallet_item, dap_chain_t *a_chain);
static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx,
                                    dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                    dap_chain_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action, char a_cache_op,
                                    dap_chain_cell_id_t a_cell_id, off_t a_file_offset, size_t a_datum_offset_in_block);
static int s_save_cache_for_addr_in_net(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr);
static void s_callback_datum_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_hash_fast_t *a_atom_hash, void *a_datum, 
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, 
                                    dap_chain_srv_uid_t a_uid);
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

static char * s_wallet_cache_storage_mode_to_str(dap_wallet_cache_storage_mode_t a_mode)
{
    switch (a_mode){
        case DAP_WALLET_CACHE_STORAGE_RAM:
            return "RAM";
        case DAP_WALLET_CACHE_STORAGE_GLOBALDB:
            return "GlobalDB";
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

    // Read cache storage mode from config
    const char *l_cache_storage_mode_str = dap_config_get_item_str(g_config, "wallet", "cache_storage_mode");
    if (l_cache_storage_mode_str) {
        if (!dap_strcmp(l_cache_storage_mode_str, "ram")) {
            s_wallet_cache_storage_mode = DAP_WALLET_CACHE_STORAGE_RAM;
        } else if (!dap_strcmp(l_cache_storage_mode_str, "globaldb") || !dap_strcmp(l_cache_storage_mode_str, "db")) {
            s_wallet_cache_storage_mode = DAP_WALLET_CACHE_STORAGE_GLOBALDB;
        } else {
            log_it(L_WARNING, "Unknown cache storage mode '%s' in config. Using default: %s", 
                   l_cache_storage_mode_str, s_wallet_cache_storage_mode_to_str(s_wallet_cache_storage_mode));
        }
    }

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        debug_if(s_debug_more, L_DEBUG, "Wallet cache is disabled.");
        return 0;
    }

    log_it(L_INFO, "Wallet cache type: %s, storage mode: %s", 
           s_wallet_cache_type_to_str(s_wallets_cache_type),
           s_wallet_cache_storage_mode_to_str(s_wallet_cache_storage_mode));

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
    
    // Load wallet caches from GlobalDB if GlobalDB mode is enabled
    if (s_wallet_cache_storage_mode == DAP_WALLET_CACHE_STORAGE_GLOBALDB) {
        log_it(L_INFO, "Loading wallet caches from GlobalDB...");
        int l_loaded_count = 0;
        
        // Iterate through all nets and chains to load cache data
        for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
            for (dap_chain_t *l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
                // Load cache for each local wallet address
                for (dap_list_t *it = l_local_addr_list; it; it = it->next) {
                    dap_chain_addr_t *l_addr = (dap_chain_addr_t *)it->data;
                    if (s_load_wallet_cache_from_gdb(l_addr, l_chain) == 0) {
                        l_loaded_count++;
                    }
                }
            }
        }
        log_it(L_INFO, "Loaded %d wallet cache(s) from GlobalDB", l_loaded_count);
    }
    
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    dap_list_free_full(l_local_addr_list, NULL);
    dap_chain_wallet_add_wallet_opened_notify(s_wallet_opened_callback, NULL);
    dap_chain_wallet_add_wallet_created_notify(s_wallet_opened_callback, NULL);

    return 0;
}

int dap_chain_wallet_cache_deinit()
{
    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED) {
        return 0;
    }
    
    pthread_rwlock_wrlock(&s_wallet_cache_rwlock);
    
    dap_wallet_cache_t *l_wallet_item, *l_wallet_tmp;
    
    // Save all wallet caches to GlobalDB before cleanup (ONLY if GlobalDB mode enabled)
    if (s_wallet_cache_storage_mode == DAP_WALLET_CACHE_STORAGE_GLOBALDB) {
        log_it(L_INFO, "Saving wallet caches to GlobalDB...");
        int l_saved_count = 0;
        
        // Iterate through all nets and chains to save cache data
        for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
            for (dap_chain_t *l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
                // Find wallets for this chain
                HASH_ITER(hh, s_wallets_cache, l_wallet_item, l_wallet_tmp) {
                    // Check if wallet has transactions for this chain
                    dap_wallet_tx_cache_t *l_tx_item, *l_tx_tmp;
                    HASH_ITER(hh, l_wallet_item->wallet_txs, l_tx_item, l_tx_tmp) {
                        if (l_tx_item->chain == l_chain) {
                            // Save this wallet's cache for this chain
                            if (s_save_wallet_cache_to_gdb(l_wallet_item, l_chain) == 0) {
                                l_saved_count++;
                            }
                            break; // One save per wallet per chain
                        }
                    }
                }
            }
        }
        log_it(L_INFO, "Saved %d wallet cache(s) to GlobalDB", l_saved_count);
    }
    
    // Now free all cache entries
    HASH_ITER(hh, s_wallets_cache, l_wallet_item, l_wallet_tmp) {
        // Free all transactions for this wallet
        dap_wallet_tx_cache_t *l_tx_item, *l_tx_tmp;
        HASH_ITER(hh, l_wallet_item->wallet_txs, l_tx_item, l_tx_tmp) {
            HASH_DEL(l_wallet_item->wallet_txs, l_tx_item);
            
            // Free transaction data if cached
            if (l_tx_item->tx) {
                DAP_DELETE(l_tx_item->tx);
            }
            
            // Free lists
            dap_list_free_full(l_tx_item->tx_wallet_inputs, NULL);
            dap_list_free_full(l_tx_item->tx_wallet_outputs, NULL);
            
            DAP_DELETE(l_tx_item);
        }
        
        // Free wallet item
        HASH_DEL(s_wallets_cache, l_wallet_item);
        DAP_DELETE(l_wallet_item);
    }
    
    pthread_rwlock_unlock(&s_wallet_cache_rwlock);
    pthread_rwlock_destroy(&s_wallet_cache_rwlock);
    
    debug_if(s_debug_more, L_INFO, "Wallet cache deinitialized and memory freed");
    
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
    if ( l_wallet_item ) {
        if ( l_wallet_item->is_loading ) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            log_it( L_WARNING, "Wallet address \"%s\" is pending...", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        if ( s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL ) {
            log_it(L_INFO, "Wallet \"%s\" is empty", dap_chain_addr_to_str_static(a_addr));
            return 0;
        } else {
            log_it(L_ERROR, "Can't find wallet address \"%s\" in cache", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
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
                    dap_wallet_tx_cache_output_t *l_cur_out_cache = (dap_wallet_tx_cache_output_t *)l_temp->data;
                    byte_t l_out_type = *(dap_chain_tx_item_type_t*)l_cur_out_cache->tx_out;
                    if (l_out_type == TX_ITEM_TYPE_OUT_EXT && !dap_strcmp(a_token, ((dap_chain_tx_out_ext_t *)l_cur_out_cache->tx_out)->token)) {
                        skip = false;
                        break;
                    }
                    if (l_out_type == TX_ITEM_TYPE_OUT_STD && !dap_strcmp(a_token, ((dap_chain_tx_out_std_t *)l_cur_out_cache->tx_out)->token)) {
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
            *a_datum = s_get_tx_from_cache_entry(l_current_wallet_tx_iter);  // Lazy loading with file offset
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
                                    dap_chain_srv_uid_t *a_uid, dap_chain_datum_tx_t **a_datum, dap_hash_fast_t *a_tx_hash_curr)
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
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        if ( s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL ) {
            log_it(L_INFO, "Wallet \"%s\" is empty", dap_chain_addr_to_str_static(a_addr));
            return 0;
        } else {
            log_it(L_ERROR, "Can't find wallet address \"%s\" in cache", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
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
            *a_datum = s_get_tx_from_cache_entry(l_current_wallet_tx);  // Lazy loading with file offset
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
    if ( l_wallet_item ) {
        if ( l_wallet_item->is_loading ) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            log_it( L_WARNING, "Wallet address \"%s\" is pending...", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        if ( s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL ) {
            log_it(L_INFO, "Wallet \"%s\" is empty", dap_chain_addr_to_str_static(a_addr));
            return 0;
        } else {
            log_it(L_ERROR, "Can't find wallet address \"%s\" in cache", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
    }

    dap_wallet_cache_unspent_outs_t *l_item_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_wallet_item->unspent_outputs, l_item_cur, l_tmp) {
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
            case TX_ITEM_TYPE_OUT_STD: {
                dap_chain_tx_out_std_t *l_out_std = (dap_chain_tx_out_std_t *)l_out_cur->tx_out;
                if (dap_strcmp(l_out_std->token, a_token_ticker))
                    continue;
                if (IS_ZERO_256(l_out_std->value) )
                    continue;
                if (l_out_std->ts_unlock > dap_ledger_get_blockchain_time(a_net->pub.ledger))
                    continue;
                l_value = l_out_std->value;
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
    if ( l_wallet_item ) {
        if ( l_wallet_item->is_loading ) {
            pthread_rwlock_unlock(&s_wallet_cache_rwlock);
            log_it( L_WARNING, "Wallet address \"%s\" is pending...", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
    } else {
        pthread_rwlock_unlock(&s_wallet_cache_rwlock);
        if ( s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL ) {
            log_it(L_INFO, "Wallet \"%s\" is empty", dap_chain_addr_to_str_static(a_addr));
            return 0;
        } else {
            log_it(L_ERROR, "Can't find wallet address \"%s\" in cache", dap_chain_addr_to_str_static(a_addr));
            return -101;
        }
    }

    dap_wallet_cache_unspent_outs_t *l_item_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_wallet_item->unspent_outputs, l_item_cur, l_tmp) {
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
            case TX_ITEM_TYPE_OUT_STD: {
                dap_chain_tx_out_std_t *l_out_std = (dap_chain_tx_out_std_t *)l_out_cur->tx_out;
                if (dap_strcmp(l_out_std->token, a_token_ticker))
                    continue;
                if (IS_ZERO_256(l_out_std->value) )
                    continue;
                if (l_out_std->ts_unlock > dap_ledger_get_blockchain_time(a_net->pub.ledger))
                    continue;
                l_value = l_out_std->value;
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
                                                 l_iter->ret_code, l_iter->token_ticker, l_iter->uid, l_iter->action, 'a',
                                                 l_iter->cur_cell_id, l_iter->cur_file_offset, 
                                                 l_iter->cur_datum_offset_in_block);  // Get datum offset from iterator!
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
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, dap_chain_srv_uid_t a_uid)
{
    dap_atom_notify_arg_t *l_arg = (dap_atom_notify_arg_t*)a_arg;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*)a_datum;
    if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return;

    // NOTE: For new incoming datums, we don't have cell_id/file_offset yet
    // They will be updated on next full scan via s_save_cache_for_addr_in_net()
    s_save_tx_cache_for_addr(l_arg->chain, NULL, (dap_chain_datum_tx_t*)l_datum->data, a_datum_hash, a_atom_hash, a_ret_code,
                             (char*)dap_ledger_tx_get_token_ticker_by_hash(l_arg->net->pub.ledger, a_datum_hash),
                             a_uid, a_action, 'a',
                             (dap_chain_cell_id_t){.uint64 = 0}, 0, 0);  // cell_id=0, file_offset=0, datum_offset=0 for new datums
}

static void s_callback_datum_removed_notify(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum)
{
    if (!a_datum_hash || !a_datum || a_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return;

    dap_atom_notify_arg_t *l_arg = (dap_atom_notify_arg_t*)a_arg;
    // NOTE: For delete operation, cell_id/file_offset are not needed
    s_save_tx_cache_for_addr(l_arg->chain, NULL, (dap_chain_datum_tx_t*)a_datum->data, a_datum_hash, NULL, 0,
                             NULL, (dap_chain_srv_uid_t){ }, DAP_CHAIN_TX_TAG_ACTION_UNKNOWN, 'd',
                             (dap_chain_cell_id_t){.uint64 = 0}, 0, 0);  // cell_id=0, file_offset=0, datum_offset=0 for delete
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
    return DAP_DELETE(a_arg), NULL;
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
        DAP_DELETE(l_addr);
        // s_save_cache_for_addr_in_net(l_net, l_addr); 
    }
}

static int s_out_idx_cmp(dap_list_t *a_l1, dap_list_t *a_l2) {
    dap_wallet_tx_cache_output_t *o1 = a_l1->data,
                                 *o2 = a_l2->data;
    return o1->tx_out_idx != o2->tx_out_idx;
}

/**
 * @brief Get transaction from cache entry with lazy loading from file
 * @param a_entry Cache entry
 * @return Transaction pointer (may be cached or newly loaded), or NULL on error
 * @note If transaction is loaded from file, it's cached in a_entry->tx for future access
 */
/**
 * @brief Load wallet cache from GlobalDB with full transaction deserialization
 * @param a_wallet_addr Wallet address to load (must not be NULL)
 * @param a_chain Chain context for DB key generation (must not be NULL)
 * @return 0 on success, negative error codes:
 *         -1: NULL parameters
 *         -2: Transaction allocation failure
 *         -3: Input allocation failure
 *         -4: Output allocation failure
 *         -5: Unspent output allocation failure
 * 
 * @details This function loads wallet cache from GlobalDB and deserializes
 *          all transactions including their inputs and outputs back into
 *          RAM-based hash table structures for fast access.
 * 
 * @note Lazy Loading: Transaction data (tx pointer) is set to NULL initially
 *       and will be loaded from disk on first access via s_get_tx_from_cache_entry().
 *       Only metadata (hashes, offsets, token ticker, etc.) is loaded into RAM.
 * 
 * @note For each transaction:
 *       - tx->chain is set to a_chain for lazy loading context
 *       - tx->tx is set to NULL (will be lazy-loaded when accessed)
 *       - tx->cell_id, file_offset, datum_offset_in_block are loaded from DB
 *       - All inputs and outputs are deserialized into dap_list_t structures
 * 
 * @note For unspent outputs:
 *       - output->output pointer is set to NULL (resolved when tx is loaded)
 *       - Only key (tx_hash, out_idx) and token_ticker are restored
 * 
 * @note If no cache is found in GlobalDB, this is not an error (returns 0).
 *       This is normal for new wallets that haven't been used yet.
 * 
 * @note Error handling: On any allocation failure, all previously allocated
 *       structures are properly cleaned up to prevent memory leaks.
 * 
 * @see s_save_wallet_cache_to_gdb() for serialization
 * @see s_get_tx_from_cache_entry() for lazy loading implementation
 * @see dap_wallet_cache_db_load() for actual GlobalDB read operation
 */
static int s_load_wallet_cache_from_gdb(dap_chain_addr_t *a_wallet_addr, dap_chain_t *a_chain)
{
    if (!a_wallet_addr || !a_chain) {
        return -1;
    }
    
    // Load from GlobalDB
    dap_wallet_cache_db_t *l_cache_db = dap_wallet_cache_db_load(
        a_wallet_addr,
        a_chain->net_id,
        a_chain->net_name,
        a_chain->name
    );
    
    if (!l_cache_db) {
        // No cache found in DB - this is normal for new wallets
        debug_if(s_debug_more, L_DEBUG, "No wallet cache found in GlobalDB for wallet=%s, chain=%s",
                 dap_chain_addr_to_str_static(a_wallet_addr), a_chain->name);
        return 0; // Not an error
    }
    
    debug_if(s_debug_more, L_INFO, "Loaded wallet cache from GlobalDB: wallet=%s, chain=%s, tx_count=%u, unspent_count=%u",
             dap_chain_addr_to_str_static(a_wallet_addr), a_chain->name, l_cache_db->tx_count, l_cache_db->unspent_count);
    
    // Find or create wallet item in RAM cache
    dap_wallet_cache_t *l_wallet_item = NULL;
    HASH_FIND(hh, s_wallets_cache, a_wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    
    if (!l_wallet_item) {
        l_wallet_item = DAP_NEW_Z(dap_wallet_cache_t);
        memcpy(&l_wallet_item->wallet_addr, a_wallet_addr, sizeof(dap_chain_addr_t));
        HASH_ADD(hh, s_wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
    }
    
    // Deserialize transactions from DB format into RAM structures
    uint8_t *l_var_data_ptr = (uint8_t*)DAP_WALLET_CACHE_DB_TXS(l_cache_db);
    
    for (uint32_t i = 0; i < l_cache_db->tx_count; i++) {
        dap_wallet_tx_cache_db_t *l_db_tx = (dap_wallet_tx_cache_db_t*)l_var_data_ptr;
        
        // Create RAM transaction entry
        dap_wallet_tx_cache_t *l_tx_item = DAP_NEW_Z(dap_wallet_tx_cache_t);
        if (!l_tx_item) {
            log_it(L_ERROR, "Failed to allocate transaction cache entry (wallet=%s, chain=%s, tx=%u/%u)",
                   dap_chain_addr_to_str_static(a_wallet_addr),
                   a_chain->name,
                   i + 1, l_cache_db->tx_count);
            dap_wallet_cache_db_free(l_cache_db);
            return -2;
        }
        
        // Copy transaction metadata
        l_tx_item->tx_hash = l_db_tx->tx_hash;
        l_tx_item->atom_hash = l_db_tx->atom_hash;
        l_tx_item->cell_id = l_db_tx->cell_id;
        l_tx_item->file_offset = l_db_tx->file_offset;
        l_tx_item->datum_offset_in_block = l_db_tx->datum_offset_in_block;
        l_tx_item->chain = a_chain; // Store chain context for lazy loading
        l_tx_item->tx = NULL; // Will be lazy-loaded when needed
        
        dap_stpcpy(l_tx_item->token_ticker, l_db_tx->token_ticker);
        l_tx_item->multichannel = l_db_tx->multichannel;
        l_tx_item->ret_code = l_db_tx->ret_code;
        l_tx_item->srv_uid = l_db_tx->srv_uid;
        l_tx_item->action = l_db_tx->action;
        
        // Move pointer to inputs section
        l_var_data_ptr += sizeof(dap_wallet_tx_cache_db_t);
        dap_wallet_tx_cache_input_db_t *l_db_inputs = (dap_wallet_tx_cache_input_db_t*)l_var_data_ptr;
        
        // Deserialize inputs
        l_tx_item->tx_wallet_inputs = NULL;
        for (uint16_t j = 0; j < l_db_tx->inputs_count; j++) {
            dap_wallet_tx_cache_input_t *l_input = DAP_NEW_Z(dap_wallet_tx_cache_input_t);
            if (!l_input) {
                log_it(L_ERROR, "Failed to allocate input entry (wallet=%s, chain=%s, tx=%u/%u, input=%u/%u)",
                       dap_chain_addr_to_str_static(a_wallet_addr),
                       a_chain->name,
                       i + 1, l_cache_db->tx_count,
                       j + 1, l_db_tx->inputs_count);
                // Cleanup already allocated inputs
                dap_list_free_full(l_tx_item->tx_wallet_inputs, NULL);
                DAP_DELETE(l_tx_item);
                dap_wallet_cache_db_free(l_cache_db);
                return -3;
            }
            
            l_input->tx_prev_hash = l_db_inputs[j].tx_prev_hash;
            l_input->tx_out_prev_idx = l_db_inputs[j].tx_out_prev_idx;
            l_input->value = l_db_inputs[j].value;
            
            l_tx_item->tx_wallet_inputs = dap_list_append(l_tx_item->tx_wallet_inputs, l_input);
        }
        l_var_data_ptr += sizeof(dap_wallet_tx_cache_input_db_t) * l_db_tx->inputs_count;
        
        // Deserialize outputs
        dap_wallet_tx_cache_output_db_t *l_db_outputs = (dap_wallet_tx_cache_output_db_t*)l_var_data_ptr;
        
        l_tx_item->tx_wallet_outputs = NULL;
        for (uint16_t j = 0; j < l_db_tx->outputs_count; j++) {
            dap_wallet_tx_cache_output_t *l_output = DAP_NEW_Z(dap_wallet_tx_cache_output_t);
            if (!l_output) {
                log_it(L_ERROR, "Failed to allocate output entry (wallet=%s, chain=%s, tx=%u/%u, output=%u/%u)",
                       dap_chain_addr_to_str_static(a_wallet_addr),
                       a_chain->name,
                       i + 1, l_cache_db->tx_count,
                       j + 1, l_db_tx->outputs_count);
                // Cleanup
                dap_list_free_full(l_tx_item->tx_wallet_inputs, NULL);
                dap_list_free_full(l_tx_item->tx_wallet_outputs, NULL);
                DAP_DELETE(l_tx_item);
                dap_wallet_cache_db_free(l_cache_db);
                return -4;
            }
            
            l_output->tx_out_idx = l_db_outputs[j].tx_out_idx;
            l_output->tx_out = NULL; // Will be resolved when transaction is lazy-loaded
            
            l_tx_item->tx_wallet_outputs = dap_list_append(l_tx_item->tx_wallet_outputs, l_output);
        }
        l_var_data_ptr += sizeof(dap_wallet_tx_cache_output_db_t) * l_db_tx->outputs_count;
        
        // Add transaction to hash table
        HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_tx_item);
    }
    
    // Deserialize unspent outputs
    dap_wallet_unspent_out_db_t *l_db_unspents = DAP_WALLET_CACHE_DB_UNSPENTS(l_cache_db);
    
    for (uint32_t i = 0; i < l_cache_db->unspent_count; i++) {
        dap_wallet_cache_unspent_outs_t *l_unspent_item = DAP_NEW_Z(dap_wallet_cache_unspent_outs_t);
        if (!l_unspent_item) {
            log_it(L_ERROR, "Failed to allocate unspent output entry (wallet=%s, chain=%s, unspent=%u/%u)",
                   dap_chain_addr_to_str_static(a_wallet_addr),
                   a_chain->name,
                   i + 1, l_cache_db->unspent_count);
            dap_wallet_cache_db_free(l_cache_db);
            return -5;
        }
        
        // Copy unspent output data
        l_unspent_item->key.tx_hash = l_db_unspents[i].tx_hash;
        l_unspent_item->key.out_idx = l_db_unspents[i].out_idx;
        dap_stpcpy(l_unspent_item->token_ticker, l_db_unspents[i].token_ticker);
        
        // Output pointer will be resolved when transaction is loaded
        l_unspent_item->output = NULL;
        
        // Add to hash table
        HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_unspent_item);
    }
    
    uint32_t l_tx_count = l_cache_db->tx_count;
    uint32_t l_unspent_count = l_cache_db->unspent_count;
    
    dap_wallet_cache_db_free(l_cache_db);
    
    debug_if(s_debug_more, L_INFO, "Successfully restored wallet cache: %u transactions, %u unspent outputs",
             l_tx_count, l_unspent_count);
    
    return 0;
}

/**
 * @brief Save wallet cache to GlobalDB with full transaction serialization
 * @param a_wallet_item Wallet cache structure to save (must not be NULL)
 * @param a_chain Chain context for DB key generation (must not be NULL)
 * @return 0 on success, negative error codes:
 *         -1: NULL parameters
 *         -2: Memory allocation failure
 *         -3: GlobalDB save failure
 * 
 * @details This function performs complete serialization of all transactions
 *          including their inputs and outputs. The serialized data is stored
 *          in GlobalDB using the group/key format: 
 *          wallet.cache.{net_id}.{chain_name}/{wallet_addr_base58}
 * 
 * @note Memory layout of serialized structure:
 *       [dap_wallet_cache_db_t header]
 *       [tx1: dap_wallet_tx_cache_db_t + inputs[] + outputs[]]
 *       [tx2: dap_wallet_tx_cache_db_t + inputs[] + outputs[]]
 *       ...
 *       [unspent_outputs[]: dap_wallet_unspent_out_db_t array]
 * 
 * @note The function dynamically calculates total size based on actual
 *       number of transactions, inputs, and outputs to avoid wasted space.
 * 
 * @note For unspent outputs, file location info is extracted from the
 *       corresponding transaction's metadata (cell_id, file_offset).
 * 
 * @see s_load_wallet_cache_from_gdb() for deserialization
 * @see dap_wallet_cache_db_save() for actual GlobalDB write operation
 */
static int s_save_wallet_cache_to_gdb(dap_wallet_cache_t *a_wallet_item, dap_chain_t *a_chain)
{
    if (!a_wallet_item || !a_chain) {
        return -1;
    }
    
    // Count transactions and calculate total size needed
    uint32_t l_tx_count = 0;
    uint32_t l_unspent_count = 0;
    size_t l_total_size = sizeof(dap_wallet_cache_db_t);
    
    // First pass: count and calculate sizes
    dap_wallet_tx_cache_t *l_tx_item, *l_tx_tmp;
    HASH_ITER(hh, a_wallet_item->wallet_txs, l_tx_item, l_tx_tmp) {
        l_tx_count++;
        
        // Count inputs and outputs for this transaction
        uint16_t l_inputs_count = 0;
        uint16_t l_outputs_count = 0;
        
        for (dap_list_t *l_it = l_tx_item->tx_wallet_inputs; l_it; l_it = l_it->next) {
            l_inputs_count++;
        }
        for (dap_list_t *l_it = l_tx_item->tx_wallet_outputs; l_it; l_it = l_it->next) {
            l_outputs_count++;
        }
        
        // Add size for this transaction record + its inputs/outputs
        l_total_size += sizeof(dap_wallet_tx_cache_db_t);
        l_total_size += sizeof(dap_wallet_tx_cache_input_db_t) * l_inputs_count;
        l_total_size += sizeof(dap_wallet_tx_cache_output_db_t) * l_outputs_count;
    }
    
    // Count unspent outputs
    dap_wallet_cache_unspent_outs_t *l_unspent_item, *l_unspent_tmp;
    HASH_ITER(hh, a_wallet_item->unspent_outputs, l_unspent_item, l_unspent_tmp) {
        l_unspent_count++;
    }
    l_total_size += sizeof(dap_wallet_unspent_out_db_t) * l_unspent_count;
    
    if (l_tx_count == 0) {
        // No transactions to save
        debug_if(s_debug_more, L_DEBUG, "No transactions to save for wallet %s",
                 dap_chain_addr_to_str_static(&a_wallet_item->wallet_addr));
        return 0;
    }
    
    // Allocate full structure with all variable data
    dap_wallet_cache_db_t *l_cache_db = DAP_NEW_Z_SIZE(dap_wallet_cache_db_t, l_total_size);
    if (!l_cache_db) {
        log_it(L_ERROR, "Failed to allocate wallet cache DB structure (%zu bytes)", l_total_size);
        return -2;
    }
    
    // Fill header
    l_cache_db->version = DAP_WALLET_CACHE_DB_VERSION;
    l_cache_db->wallet_addr = a_wallet_item->wallet_addr;
    l_cache_db->net_id = a_chain->net_id;
    l_cache_db->chain_id = a_chain->id;
    l_cache_db->tx_count = l_tx_count;
    l_cache_db->unspent_count = l_unspent_count;
    l_cache_db->last_update = dap_time_now();
    
    // Get pointers to variable data sections
    dap_wallet_tx_cache_db_t *l_db_txs = DAP_WALLET_CACHE_DB_TXS(l_cache_db);
    dap_wallet_unspent_out_db_t *l_db_unspents = DAP_WALLET_CACHE_DB_UNSPENTS(l_cache_db);
    
    // Second pass: serialize transactions
    uint8_t *l_var_data_ptr = (uint8_t*)l_db_txs;
    
    HASH_ITER(hh, a_wallet_item->wallet_txs, l_tx_item, l_tx_tmp) {
        dap_wallet_tx_cache_db_t *l_db_tx = (dap_wallet_tx_cache_db_t*)l_var_data_ptr;
        
        // Copy transaction metadata
        l_db_tx->tx_hash = l_tx_item->tx_hash;
        l_db_tx->atom_hash = l_tx_item->atom_hash;
        l_db_tx->cell_id = l_tx_item->cell_id;
        l_db_tx->file_offset = l_tx_item->file_offset;
        l_db_tx->datum_offset_in_block = l_tx_item->datum_offset_in_block;
        
        // Calculate transaction size if available
        if (l_tx_item->tx) {
            l_db_tx->tx_size = dap_chain_datum_tx_get_size(l_tx_item->tx);
        } else {
            l_db_tx->tx_size = 0; // Will be read from file when needed
        }
        
        dap_stpcpy(l_db_tx->token_ticker, l_tx_item->token_ticker);
        l_db_tx->multichannel = l_tx_item->multichannel;
        l_db_tx->ret_code = l_tx_item->ret_code;
        l_db_tx->srv_uid = l_tx_item->srv_uid;
        l_db_tx->action = l_tx_item->action;
        
        // Count and serialize inputs
        uint16_t l_inputs_count = 0;
        for (dap_list_t *l_it = l_tx_item->tx_wallet_inputs; l_it; l_it = l_it->next) {
            l_inputs_count++;
        }
        l_db_tx->inputs_count = l_inputs_count;
        
        // Move pointer after transaction header
        l_var_data_ptr += sizeof(dap_wallet_tx_cache_db_t);
        dap_wallet_tx_cache_input_db_t *l_db_inputs = (dap_wallet_tx_cache_input_db_t*)l_var_data_ptr;
        
        uint16_t l_input_idx = 0;
        for (dap_list_t *l_it = l_tx_item->tx_wallet_inputs; l_it; l_it = l_it->next) {
            dap_wallet_tx_cache_input_t *l_input = (dap_wallet_tx_cache_input_t*)l_it->data;
            l_db_inputs[l_input_idx].tx_prev_hash = l_input->tx_prev_hash;
            l_db_inputs[l_input_idx].tx_out_prev_idx = l_input->tx_out_prev_idx;
            l_db_inputs[l_input_idx].value = l_input->value;
            l_input_idx++;
        }
        l_var_data_ptr += sizeof(dap_wallet_tx_cache_input_db_t) * l_inputs_count;
        
        // Count and serialize outputs
        uint16_t l_outputs_count = 0;
        for (dap_list_t *l_it = l_tx_item->tx_wallet_outputs; l_it; l_it = l_it->next) {
            l_outputs_count++;
        }
        l_db_tx->outputs_count = l_outputs_count;
        
        dap_wallet_tx_cache_output_db_t *l_db_outputs = (dap_wallet_tx_cache_output_db_t*)l_var_data_ptr;
        
        uint16_t l_output_idx = 0;
        for (dap_list_t *l_it = l_tx_item->tx_wallet_outputs; l_it; l_it = l_it->next) {
            dap_wallet_tx_cache_output_t *l_output = (dap_wallet_tx_cache_output_t*)l_it->data;
            l_db_outputs[l_output_idx].tx_out_idx = l_output->tx_out_idx;
            // Get output type from the actual output structure
            if (l_output->tx_out) {
                l_db_outputs[l_output_idx].out_type = *(uint8_t*)l_output->tx_out;
            } else {
                l_db_outputs[l_output_idx].out_type = 0;
            }
            l_output_idx++;
        }
        l_var_data_ptr += sizeof(dap_wallet_tx_cache_output_db_t) * l_outputs_count;
    }
    
    // Serialize unspent outputs
    uint32_t l_unspent_idx = 0;
    HASH_ITER(hh, a_wallet_item->unspent_outputs, l_unspent_item, l_unspent_tmp) {
        l_db_unspents[l_unspent_idx].tx_hash = l_unspent_item->key.tx_hash;
        l_db_unspents[l_unspent_idx].out_idx = l_unspent_item->key.out_idx;
        
        // Find corresponding transaction to get file location info
        dap_wallet_tx_cache_t *l_tx_for_unspent = NULL;
        HASH_FIND(hh, a_wallet_item->wallet_txs, &l_unspent_item->key.tx_hash, sizeof(dap_hash_fast_t), l_tx_for_unspent);
        
        if (l_tx_for_unspent) {
            l_db_unspents[l_unspent_idx].cell_id = l_tx_for_unspent->cell_id;
            l_db_unspents[l_unspent_idx].file_offset = l_tx_for_unspent->file_offset;
            if (l_tx_for_unspent->tx) {
                l_db_unspents[l_unspent_idx].tx_size = dap_chain_datum_tx_get_size(l_tx_for_unspent->tx);
            } else {
                l_db_unspents[l_unspent_idx].tx_size = 0;
            }
        } else {
            // No transaction found - zero out file location
            l_db_unspents[l_unspent_idx].cell_id.uint64 = 0;
            l_db_unspents[l_unspent_idx].file_offset = 0;
            l_db_unspents[l_unspent_idx].tx_size = 0;
        }
        
        // Get output type and value from output structure if available
        if (l_unspent_item->output && l_unspent_item->output->tx_out) {
            l_db_unspents[l_unspent_idx].out_type = *(uint8_t*)l_unspent_item->output->tx_out;
            // Try to extract value from output (this depends on output type)
            // For now, set to zero - can be enhanced later
            memset(&l_db_unspents[l_unspent_idx].value, 0, sizeof(uint256_t));
        } else {
            l_db_unspents[l_unspent_idx].out_type = 0;
            memset(&l_db_unspents[l_unspent_idx].value, 0, sizeof(uint256_t));
        }
        
        dap_stpcpy(l_db_unspents[l_unspent_idx].token_ticker, l_unspent_item->token_ticker);
        l_unspent_idx++;
    }
    
    // Save to GlobalDB with proper size
    int l_ret = dap_wallet_cache_db_save(l_cache_db, l_total_size, a_chain->net_name, a_chain->name);
    
    dap_wallet_cache_db_free(l_cache_db);
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to save wallet cache to GlobalDB: %d", l_ret);
        return -3;
    }
    
    debug_if(s_debug_more, L_DEBUG, "Saved wallet cache to GlobalDB: wallet=%s, %u transactions, %u unspent outputs, %zu bytes",
             dap_chain_addr_to_str_static(&a_wallet_item->wallet_addr), l_tx_count, l_unspent_count, l_total_size);
    
    return 0;
}

static dap_chain_datum_tx_t* s_get_tx_from_cache_entry(dap_wallet_tx_cache_t *a_entry)
{
    // If already cached in RAM - return immediately
    if (a_entry->tx) {
        return a_entry->tx;
    }
    
    // Check if we have necessary information to read from file
    if (!a_entry->file_offset || !a_entry->chain) {
        debug_if(s_debug_more, L_DEBUG, "Cannot read tx from offset: missing file_offset or chain");
        return NULL;
    }
    
    // Read block from file by offset
    size_t l_block_size = 0;
    void *l_block_data = dap_chain_cell_read_atom_by_offset(
        a_entry->chain,
        a_entry->cell_id,
        a_entry->file_offset,
        &l_block_size
    );
    
    if (!l_block_data) {
        log_it(L_ERROR, "Failed to read block from offset %lld", (long long)a_entry->file_offset);
        return NULL;
    }
    
    // Cast to block structure
    dap_chain_block_t *l_block = (dap_chain_block_t *)l_block_data;
    
    // Verify block signature
    if (l_block->hdr.signature != DAP_CHAIN_BLOCK_SIGNATURE) {
        log_it(L_ERROR, "Invalid block signature at offset %lld", (long long)a_entry->file_offset);
        DAP_DELETE(l_block_data);
        return NULL;
    }
    
    // Find our datum within the block using datum_offset_in_block
    if (a_entry->datum_offset_in_block >= l_block_size) {
        log_it(L_ERROR, "datum_offset_in_block (%zu) exceeds block size (%zu)", 
               a_entry->datum_offset_in_block, l_block_size);
        DAP_DELETE(l_block_data);
        return NULL;
    }
    
    // Extract datum from block
    byte_t *l_datum_ptr = l_block->meta_n_datum_n_sign + a_entry->datum_offset_in_block;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_datum_ptr;
    
    // Verify it's a transaction
    if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
        log_it(L_ERROR, "Datum at offset is not a transaction (type=%d)", l_datum->header.type_id);
        DAP_DELETE(l_block_data);
        return NULL;
    }
    
    // Calculate transaction size
    size_t l_tx_size = l_datum->header.data_size;
    
    // Allocate and copy transaction
    a_entry->tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, l_tx_size);
    if (!a_entry->tx) {
        log_it(L_ERROR, "Failed to allocate memory for transaction (%zu bytes)", l_tx_size);
        DAP_DELETE(l_block_data);
        return NULL;
    }
    
    memcpy(a_entry->tx, l_datum->data, l_tx_size);
    
    // Free the block (we only need the transaction)
    DAP_DELETE(l_block_data);
    
    debug_if(s_debug_more, L_DEBUG, "Loaded transaction from file: offset=%lld, datum_offset=%zu, size=%zu",
             (long long)a_entry->file_offset, a_entry->datum_offset_in_block, l_tx_size);
    
    return a_entry->tx;
}

static int s_save_tx_cache_for_addr(dap_chain_t *a_chain, dap_chain_addr_t *a_addr, dap_chain_datum_tx_t *a_tx, 
                                    dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_atom_hash, int a_ret_code, char* a_main_token_ticker,
                                    dap_chain_srv_uid_t a_srv_uid, dap_chain_tx_tag_action_type_t a_action, char a_cache_op,
                                    dap_chain_cell_id_t a_cell_id, off_t a_file_offset, size_t a_datum_offset_in_block)
{
    int l_ret_val = 0, l_items_cnt = 0, l_out_idx = -1;
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
        int l_prev_idx = 0;

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
            case TX_ITEM_TYPE_OUT_STD:
                l_value = ((dap_chain_tx_out_std_t *)l_prev_item)->value;
                l_addr = ((dap_chain_tx_out_std_t *)l_prev_item)->addr;
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
        case TX_ITEM_TYPE_OUT_STD:
            l_addr = ((dap_chain_tx_out_std_t *)l_tx_item)->addr;
            l_multichannel = true;
            break;
        case TX_ITEM_TYPE_OUT_COND:
        /* Make it explicit for possible future STAKE_LOCK adoption */
        // TODO
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
                *l_wallet_tx_item = (dap_wallet_tx_cache_t){ .tx_hash = *a_tx_hash, .atom_hash = *a_atom_hash, .tx = a_tx,
                    .cell_id = a_cell_id, .file_offset = a_file_offset, .datum_offset_in_block = a_datum_offset_in_block,
                    .chain = a_chain,  // Store chain context for lazy loading
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
                // Free cached transaction data if loaded from file
                if (l_wallet_tx_item->tx) {
                    DAP_DELETE(l_wallet_tx_item->tx);
                }
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
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    unspent_cache_hh_key key = { .tx_hash = l_prev_tx_hash, .out_idx = l_prev_idx };
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
                    dap_list_t *l_out_item = dap_list_find(l_wallet_prev_tx_item->tx_wallet_outputs, &l_sought_out, s_out_idx_cmp);
                    if (l_out_item) {
                        dap_wallet_cache_unspent_outs_t *l_item = NULL;
                        unspent_cache_hh_key l_key = { .tx_hash = l_prev_tx_hash, .out_idx = l_prev_idx };
                        HASH_FIND(hh, l_wallet_item->unspent_outputs, &l_key, sizeof(unspent_cache_hh_key), l_item);
                        if ( !l_item ) {
                            l_item = DAP_NEW(dap_wallet_cache_unspent_outs_t);
                            *l_item = (dap_wallet_cache_unspent_outs_t) { .key = l_key, .output = l_out_item->data };
                            dap_strncpy(l_item->token_ticker, *l_prev_item == TX_ITEM_TYPE_OUT_EXT ? ((dap_chain_tx_out_ext_t*)l_prev_item)->token
                                        : *l_prev_item == TX_ITEM_TYPE_OUT_STD ? ((dap_chain_tx_out_std_t *)l_prev_item)->token
                                        : l_wallet_prev_tx_item->token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                            HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_item);
                        }
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
                dap_wallet_tx_cache_output_t *l_out = NULL;
                dap_wallet_tx_cache_output_t l_sought_out = { .tx_out_idx = l_out_idx };
                dap_list_t *l_out_item = dap_list_find(l_wallet_tx_item->tx_wallet_outputs, &l_sought_out, s_out_idx_cmp);
                if ( !l_out_item ) {
                    l_out = DAP_NEW(dap_wallet_tx_cache_output_t);
                    *l_out = (dap_wallet_tx_cache_output_t){ .tx_out = l_tx_item, .tx_out_idx = l_out_idx };
                    l_wallet_tx_item->tx_wallet_outputs = dap_list_append(l_wallet_tx_item->tx_wallet_outputs, l_out);
                } else 
                    l_out = l_out_item->data;
                /* Add unspent out to cache */ 
                if (!a_ret_code) {
                    dap_wallet_cache_unspent_outs_t *l_item = NULL;
                    unspent_cache_hh_key l_key = { .tx_hash = *a_tx_hash, .out_idx = l_out_idx };
                    HASH_FIND(hh, l_wallet_item->unspent_outputs, &l_key, sizeof(unspent_cache_hh_key), l_item);
                    if ( !l_item ) {
                        l_item = DAP_NEW(dap_wallet_cache_unspent_outs_t);
                        *l_item = (dap_wallet_cache_unspent_outs_t) { .key = l_key, .output = l_out };
                        dap_strncpy(l_item->token_ticker, *l_tx_item == TX_ITEM_TYPE_OUT_EXT ? ((dap_chain_tx_out_ext_t*)l_tx_item)->token
                                : *l_tx_item == TX_ITEM_TYPE_OUT_STD ? ((dap_chain_tx_out_std_t *)l_tx_item)->token
                                : a_main_token_ticker ? a_main_token_ticker : "0", DAP_CHAIN_TICKER_SIZE_MAX);                   
                        HASH_ADD(hh, l_wallet_item->unspent_outputs, key, sizeof(unspent_cache_hh_key), l_item);
                    }
                }
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
        a_cache_iter->cur_tx = s_get_tx_from_cache_entry(a_cache_index);  // Lazy loading with file offset
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

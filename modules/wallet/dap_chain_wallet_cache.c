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
#include "dap_chain_ledger.h"
#include "dap_common.h"


#define LOG_TAG "dap_chain_wallet_cache"

typedef enum dap_ledger_wallets_cache_type{
    DAP_WALLET_CACHE_TYPE_DISABLED = 0,
    DAP_WALLET_CACHE_TYPE_LOCAL,
    DAP_WALLET_CACHE_TYPE_ALL
} dap_ledger_wallets_cache_type_t;

typedef struct dap_ledger_wallet_tx_cache_input{
    dap_chain_hash_fast_t tx_prev_hash; 
    uint32_t tx_out_prev_idx;
    uint256_t value;
} dap_ledger_wallet_tx_cache_input_t;

typedef struct dap_ledger_wallet_tx_cache_output{
    void* tx_out;
    uint32_t tx_out_idx;
} dap_ledger_wallet_tx_cache_output_t;

typedef struct dap_ledger_wallet_tx_cache {
    dap_hash_fast_t tx_hash;
    dap_chain_datum_tx_t *tx;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    bool multichannel;
    int ret_code;
    dap_chain_net_srv_uid_t tag; 
    dap_chain_tx_tag_action_type_t action;
    dap_list_t *tx_wallet_inputs;
    dap_list_t *tx_wallet_outputs;
    UT_hash_handle hh;
} dap_ledger_wallet_tx_cache_t;

typedef struct dap_ledger_wallets_cache {
    dap_chain_addr_t wallet_addr;
    dap_ledger_wallet_tx_cache_t *wallet_txs;
    UT_hash_handle hh;
} dap_ledger_wallet_cache_t;


static dap_ledger_wallets_cache_type_t s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_LOCAL;
static dap_ledger_wallet_cache_t *wallets_cache = NULL;
static pthread_rwlock_t wallet_cache_rwlock;



static int s_save_tx_into_wallet_cache(dap_ledger_t* a_ledger, dap_chain_datum_tx_t *a_tx, 
                                                dap_hash_fast_t *a_tx_hash, int a_ret_code, char* a_main_token_ticker,
                                                dap_chain_net_srv_uid_t a_tag, dap_chain_tx_tag_action_type_t a_action);
static int s_save_cache_for_addr_in_net(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr);


static char * s_wallet_cache_type_to_str(dap_ledger_wallets_cache_type_t a_type)
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
    char *l_walet_cache_type_str = dap_config_get_item_str(g_config,"ledger","wallets_cache");
    if (l_walet_cache_type_str){
        if (dap_strcmp(l_walet_cache_type_str, "disable")){
            s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_DISABLED;
        } else if (dap_strcmp(l_walet_cache_type_str, "local")){
            s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_LOCAL;
        } else if (dap_strcmp(l_walet_cache_type_str, "all")){
            s_wallets_cache_type = DAP_WALLET_CACHE_TYPE_ALL;
        } else {
            log_it( L_WARNING, "Unknown cache type in config. Remain default: %s", s_wallet_cache_type_to_str(s_wallets_cache_type));
        }
    }

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_DISABLED){
        log_it( L_WARNING, "Wallet cache is disabled.");
        return 0;
    }

    log_it( L_INFO, "Wallet cache type: %s", s_wallet_cache_type_to_str(s_wallets_cache_type));

    pthread_rwlock_init(&wallet_cache_rwlock, NULL);

    if (s_wallets_cache_type == DAP_WALLET_CACHE_TYPE_ALL){
        // save all history for all addresses in all nets
    } else {
        // Get list all local wallets adresses in all nets

        // Find history for each local wallet in appropriate net and chain
    }


    return 0;
}

int dap_chain_wallet_cache_deinit()
{
    return 0;
}

int dap_chain_wallet_cache_tx_find(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr, dap_chain_datum_t **a_datum, dap_hash_fast_t *a_tx_hash_curr)
{

    return 0;
}

int dap_chain_wallet_cache_tx_find_outs_with_val(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr, dap_list_t **a_outs_list, uint256_t l_value_needed, uint256_t *l_value_transfer)
{

    return 0;
}

static int s_save_tx_into_wallet_cache(dap_ledger_t* a_ledger, dap_chain_datum_tx_t *a_tx, 
                                                dap_hash_fast_t *a_tx_hash, int a_ret_code, char* a_main_token_ticker,
                                                dap_chain_net_srv_uid_t a_tag, dap_chain_tx_tag_action_type_t a_action)
{
    int l_ret_val = 0;
    int l_items_cnt = 0;

    dap_list_t *l_out_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, &l_items_cnt);
    bool l_multichannel = false;
    int l_out_idx = 0;
    for (dap_list_t *it=l_out_list; it; it=it->next, l_out_idx++){
        uint8_t l_out_type = *(uint8_t *)it->data;
        dap_chain_addr_t l_addr = {};
        switch(l_out_type){
            case TX_ITEM_TYPE_OUT_OLD: {
                l_addr = ((dap_chain_tx_out_old_t*)it->data)->addr;
            } break;
            case TX_ITEM_TYPE_OUT: {
                l_addr = ((dap_chain_tx_out_t*)it->data)->addr;
            } break;
            case TX_ITEM_TYPE_OUT_EXT: {
                l_addr = ((dap_chain_tx_out_ext_t*)it->data)->addr;
                l_multichannel = true;
            } break;
            default:
                continue;
        }

        if(!dap_chain_addr_is_blank(&l_addr)){
            pthread_rwlock_wrlock(&wallet_cache_rwlock);
            dap_ledger_wallet_cache_t *l_wallet_item = NULL;
            HASH_FIND(hh, wallets_cache, &l_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            if (!l_wallet_item){
                l_wallet_item = DAP_NEW_Z(dap_ledger_wallet_cache_t);
                l_wallet_item->wallet_addr = l_addr;
                HASH_ADD(hh, wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
            }
            dap_ledger_wallet_tx_cache_t *l_wallet_tx_item = NULL;
            HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            if (!l_wallet_tx_item){
                l_wallet_tx_item = DAP_NEW_Z(dap_ledger_wallet_tx_cache_t);
                l_wallet_tx_item->tx_hash = *a_tx_hash;
                l_wallet_tx_item->tx = a_tx;
                if (a_main_token_ticker)
                    dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                l_wallet_tx_item->ret_code = a_ret_code;
                l_wallet_tx_item->tag = a_tag;
                l_wallet_tx_item->action = a_action;
                HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
            }
            l_wallet_tx_item->multichannel = l_multichannel;
            dap_ledger_wallet_tx_cache_output_t *l_out = DAP_NEW_Z(dap_ledger_wallet_tx_cache_output_t);
            l_out->tx_out = it->data;
            l_out->tx_out_idx = l_out_idx;
            l_wallet_tx_item->tx_wallet_outputs = dap_list_append(l_wallet_tx_item->tx_wallet_outputs, l_out);
            pthread_rwlock_unlock(&wallet_cache_rwlock);
        }
    }

    dap_list_t *l_in_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN_ALL, &l_items_cnt);
    for (dap_list_t *it=l_out_list; it; it=it->next ){
        uint8_t l_cond_type = *(uint8_t *)it->data;
        uint256_t l_value = {};
        dap_chain_addr_t l_addr_from = {};
        if(l_cond_type == TX_ITEM_TYPE_IN){
            dap_hash_fast_t l_prev_tx_hash = ((dap_chain_tx_in_t*)it->data)->header.tx_prev_hash;
            int l_prev_idx = ((dap_chain_tx_in_t*)it->data)->header.tx_out_prev_idx;
            uint8_t* l_prev_item = dap_chain_datum_tx_item_get_nth(a_tx, TX_ITEM_TYPE_IN, l_prev_idx);
            if (l_prev_item){
                uint8_t l_out_type = *(uint8_t *)it->data;
                switch(l_out_type){
                    case TX_ITEM_TYPE_OUT_OLD: {
                        l_value = GET_256_FROM_64(((dap_chain_tx_out_old_t*)it->data)->header.value);
                        l_addr_from = ((dap_chain_tx_out_old_t*)it->data)->addr;
                    } break;
                    case TX_ITEM_TYPE_OUT:
                    case TX_ITEM_TYPE_OUT_EXT: {
                        l_value = ((dap_chain_tx_out_ext_t*)it->data)->header.value;
                        l_addr_from = ((dap_chain_tx_out_ext_t*)it->data)->addr;
                    } break;
                    default:
                        continue;
                }
            } else {
                continue;
            }

            if(!dap_chain_addr_is_blank(&l_addr_from)){
                pthread_rwlock_wrlock(&wallet_cache_rwlock);
                dap_ledger_wallet_cache_t *l_wallet_item = NULL;
                HASH_FIND(hh, wallets_cache, &l_addr_from, sizeof(dap_chain_addr_t), l_wallet_item);
                if (!l_wallet_item){
                    l_wallet_item = DAP_NEW_Z(dap_ledger_wallet_cache_t);
                    l_wallet_item->wallet_addr = l_addr_from;
                    HASH_ADD(hh, wallets_cache, wallet_addr, sizeof(dap_chain_addr_t), l_wallet_item);
                }
                dap_ledger_wallet_tx_cache_t *l_wallet_tx_item = NULL;
                HASH_FIND(hh, l_wallet_item->wallet_txs, a_tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                if (!l_wallet_tx_item){
                    l_wallet_tx_item = DAP_NEW_Z(dap_ledger_wallet_tx_cache_t);
                    l_wallet_tx_item->tx_hash = *a_tx_hash;
                    l_wallet_tx_item->tx = a_tx;
                    if(a_main_token_ticker)
                        dap_strncpy(l_wallet_tx_item->token_ticker, a_main_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
                    l_wallet_tx_item->multichannel = l_multichannel;
                    l_wallet_tx_item->ret_code = a_ret_code;
                    l_wallet_tx_item->tag = a_tag;
                    l_wallet_tx_item->action = a_action;
                    HASH_ADD(hh, l_wallet_item->wallet_txs, tx_hash, sizeof(dap_hash_fast_t), l_wallet_tx_item);
                }
                dap_ledger_wallet_tx_cache_input_t *l_tx_in = DAP_NEW_Z(dap_ledger_wallet_tx_cache_input_t);
                l_tx_in->tx_prev_hash = l_prev_tx_hash;
                l_tx_in->tx_out_prev_idx = l_prev_idx;
                l_tx_in->value = l_value;
                l_wallet_tx_item->tx_wallet_inputs = dap_list_append(l_wallet_tx_item->tx_wallet_inputs, l_tx_in);
                pthread_rwlock_unlock(&wallet_cache_rwlock);
            }

        }
    }

    if (l_out_list)
        dap_list_free(l_out_list);

    if (l_in_list)
        dap_list_free(l_in_list);

    return l_ret_val;
}


static int s_save_cache_for_addr_in_net(dap_chain_net_t *a_net, dap_chain_addr_t *a_addr)
{


    return 0;
}
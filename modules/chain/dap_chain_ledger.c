/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
//#include <malloc.h>

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

#include "dap_list.h"
#include "dap_hash.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_cert.h"
#include "dap_timerfd.h"
#include "dap_chain_datum_tx_token.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_mempool.h"
#include "dap_chain_global_db.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_ledger"

typedef struct dap_chain_ledger_verificator {
    int subtype;    // hash key
    dap_chain_ledger_verificator_callback_t callback;
    UT_hash_handle hh;
} dap_chain_ledger_verificator_t;

static dap_chain_ledger_verificator_t *s_verificators;
static  pthread_rwlock_t s_verificators_rwlock;

#define MAX_OUT_ITEMS   10
typedef struct dap_chain_ledger_token_emission_item {
    dap_chain_hash_fast_t datum_token_emission_hash;
    dap_chain_datum_token_emission_t *datum_token_emission;
    size_t datum_token_emission_size;
    UT_hash_handle hh;
} dap_chain_ledger_token_emission_item_t;

typedef struct dap_chain_ledger_token_item {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint16_t type;
    dap_chain_datum_token_t * datum_token;

    uint64_t total_supply;
    uint64_t current_supply;
    pthread_rwlock_t token_emissions_rwlock;
    dap_chain_ledger_token_emission_item_t * token_emissions;

    // for auth operations
    dap_sign_t ** auth_signs;
    dap_chain_hash_fast_t * auth_signs_pkey_hash;
    size_t auth_signs_total;
    size_t auth_signs_valid;
    uint16_t           flags;
    dap_chain_addr_t * tx_recv_allow;
    size_t             tx_recv_allow_size;
    dap_chain_addr_t * tx_recv_block;
    size_t             tx_recv_block_size;
    dap_chain_addr_t * tx_send_allow;
    size_t             tx_send_allow_size;
    dap_chain_addr_t * tx_send_block;
    size_t             tx_send_block_size;
    UT_hash_handle hh;
} dap_chain_ledger_token_item_t;

// ledger cache item - one of unspent outputs
typedef struct dap_chain_ledger_tx_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    struct {
        time_t ts_created;
        int n_outs;
        int n_outs_used;
        char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        // TODO dynamically allocates the memory in order not to limit the number of outputs in transaction
        dap_chain_hash_fast_t tx_hash_spent_fast[MAX_OUT_ITEMS]; // spent outs list
    } cache_data;
    UT_hash_handle hh;
} dap_chain_ledger_tx_item_t;

typedef struct dap_chain_ledger_tx_spent_item {
    dap_chain_hash_fast_t tx_hash_fast;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    UT_hash_handle hh;
} dap_chain_ledger_tx_spent_item_t;


typedef struct dap_chain_ledger_tokenizer {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t sum;
    UT_hash_handle hh;
} dap_chain_ledger_tokenizer_t;

typedef struct dap_chain_ledger_tx_bound {
    dap_chain_hash_fast_t tx_prev_hash_fast;
    dap_chain_datum_tx_t *tx_prev;
    union {
        dap_chain_tx_in_t *tx_cur_in;
        dap_chain_tx_in_cond_t *tx_cur_in_cond;
    } in;
    union {
        dap_chain_tx_out_t *tx_prev_out;
        dap_chain_tx_out_ext_t *tx_prev_out_ext;
        dap_chain_tx_out_cond_t *tx_prev_out_cond;
    } out;
    dap_chain_ledger_tx_item_t *item_out;
} dap_chain_ledger_tx_bound_t;

// in-memory wallet balance
typedef struct dap_ledger_wallet_balance {
    char *key;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint128_t balance;
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

// dap_ledget_t private section
typedef struct dap_ledger_private {
    dap_chain_net_t * net;
    // List of ledger - unspent transactions cache
    dap_chain_ledger_tx_item_t *treshold_txs;
    dap_chain_ledger_token_emission_item_t * treshold_emissions;

    dap_chain_ledger_tx_item_t *ledger_items;
    dap_chain_ledger_tx_spent_item_t *spent_items;

    dap_chain_ledger_token_item_t *tokens;

    dap_ledger_wallet_balance_t *balance_accounts;

    // for separate access to ledger
    pthread_rwlock_t ledger_rwlock;
    // for separate access to tokens
    pthread_rwlock_t tokens_rwlock;

    pthread_rwlock_t treshold_txs_rwlock;
    pthread_rwlock_t treshold_emissions_rwlock;
    pthread_rwlock_t balance_accounts_rwlock;

    uint16_t check_flags;
    bool check_ds;
    bool check_cells_ds;
    bool check_token_emission;
    dap_chain_cell_id_t local_cell_id;

    bool load_mode;
    // TPS section
    dap_timerfd_t *tps_timer;
    struct timespec tps_start_time;
    struct timespec tps_current_time;
    struct timespec tps_end_time;
    size_t tps_count;
} dap_ledger_private_t;
#define PVT(a) ( (dap_ledger_private_t* ) a->_internal )


static  dap_chain_ledger_tx_item_t* tx_item_find_by_addr(dap_ledger_t *a_ledger,
        const dap_chain_addr_t *a_addr, const char * a_token, dap_chain_hash_fast_t *a_tx_first_hash);
static void s_treshold_emissions_proc( dap_ledger_t * a_ledger);
static void s_treshold_txs_proc( dap_ledger_t * a_ledger);
static int s_token_tsd_parse(dap_ledger_t * a_ledger, dap_chain_ledger_token_item_t *a_token_item , dap_chain_datum_token_t * a_token, size_t a_token_size);
static int s_ledger_permissions_check(dap_chain_ledger_token_item_t *  a_token_item, uint16_t a_permission_id, const void * a_data,size_t a_data_size );
static bool s_ledger_tps_callback(void *a_arg);

static size_t s_treshold_emissions_max = 1000;
static size_t s_treshold_txs_max = 10000;
static bool s_debug_more = false;

/**
 * @brief dap_chain_ledger_init
 * current function version set s_debug_more parameter, if it define in config, and returns 0
 * @return
 */
int dap_chain_ledger_init()
{
    s_debug_more = dap_config_get_item_bool_default(g_config,"ledger","debug_more",false);
    return 0;
}

/**
 * @brief dap_chain_ledger_deinit
 * nothing do
 */
void dap_chain_ledger_deinit()
{
    uint16_t l_net_count = 0;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for(uint16_t i =0; i < l_net_count; i++) {
        dap_chain_ledger_purge(l_net_list[i]->pub.ledger, true);
    }
    DAP_DELETE(l_net_list);
}

/**
 * @brief dap_chain_ledger_handle_new
 * Create empty dap_ledger_t structure
 * @return dap_ledger_t* 
 */
static dap_ledger_t * dap_chain_ledger_handle_new(void)
{
    dap_ledger_t *l_ledger = DAP_NEW_Z(dap_ledger_t);
    dap_ledger_private_t * l_ledger_pvt;
    l_ledger->_internal = l_ledger_pvt = DAP_NEW_Z(dap_ledger_private_t);

    // Initialize Read/Write Lock Attribute
    pthread_rwlock_init(&l_ledger_pvt->ledger_rwlock, NULL); // PTHREAD_RWLOCK_INITIALIZER;
    pthread_rwlock_init(&l_ledger_pvt->tokens_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->treshold_txs_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->treshold_emissions_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->balance_accounts_rwlock , NULL);
    return l_ledger;
}

/**
 * @brief dap_chain_ledger_handle_free
 * Remove dap_ledger_t structure
 * @param a_ledger 
 */
void dap_chain_ledger_handle_free(dap_ledger_t *a_ledger)
{
    if(!a_ledger)
        return;
    log_it(L_INFO,"Ledger %s destroyed", a_ledger->net_name);
    // Destroy Read/Write Lock
    pthread_rwlock_destroy(&PVT(a_ledger)->ledger_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->tokens_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->treshold_txs_rwlock );
    pthread_rwlock_destroy(&PVT(a_ledger)->treshold_emissions_rwlock );
    pthread_rwlock_destroy(&PVT(a_ledger)->balance_accounts_rwlock );
    DAP_DELETE(PVT(a_ledger));
    DAP_DELETE(a_ledger);

}

void dap_chain_ledger_load_end(dap_ledger_t *a_ledger)
{
    PVT(a_ledger)->load_mode = false;
}


/**
 * @brief dap_chain_ledger_token_check
 * @param a_ledger
 * @param a_token
 * @return
 */
int dap_chain_ledger_token_decl_add_check(dap_ledger_t * a_ledger,  dap_chain_datum_token_t *a_token)
{
    if ( !a_ledger){
        if(s_debug_more)
            log_it(L_ERROR, "NULL ledger, can't add datum with token declaration!");
        return  -1;
    }

    dap_chain_ledger_token_item_t * l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens,a_token->ticker,l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    if ( l_token_item != NULL ){
        log_it(L_WARNING,"Duplicate token declaration for ticker '%s' ", a_token->ticker);
        return -3;
    }
    // Checks passed
    return 0;
}

/**
 * @brief dap_chain_ledger_token_ticker_check
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
int dap_chain_ledger_token_ticker_check(dap_ledger_t * a_ledger, const char *a_token_ticker)
{
    if ( !a_ledger){
        if(s_debug_more)
            log_it(L_WARNING, "NULL ledger, can't find token ticker");
        return  -2;
    }
    dap_chain_ledger_token_item_t *l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token_ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return (size_t)l_token_item;
}

/**
 * @brief dap_chain_ledger_token_add
 * @param a_token
 * @param a_token_size
 * @return
 */
int dap_chain_ledger_token_add(dap_ledger_t * a_ledger,  dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if ( !a_ledger){
        if(s_debug_more)
            log_it(L_ERROR, "NULL ledger, can't add datum with token declaration!");
        return  -1;
    }

    dap_chain_ledger_token_item_t * l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens,a_token->ticker,l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);

    if (l_token_item) {
        if(s_debug_more)
            log_it(L_WARNING,"Duplicate token declaration for ticker '%s' ", a_token->ticker);
        return -3;
    }

    l_token_item = DAP_NEW_Z(dap_chain_ledger_token_item_t);
    dap_snprintf(l_token_item->ticker,sizeof (l_token_item->ticker),"%s",a_token->ticker);
    pthread_rwlock_init(&l_token_item->token_emissions_rwlock,NULL);
    l_token_item->datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, a_token_size);
    memcpy(l_token_item->datum_token, a_token,a_token_size);
    pthread_rwlock_wrlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_ADD_STR(PVT(a_ledger)->tokens, ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    // Add it to cache
    dap_chain_datum_token_t *l_token_cache = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, a_token_size);
    memcpy(l_token_cache, a_token, a_token_size);
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TOKENS_STR);
    if (!dap_chain_global_db_gr_set(dap_strdup(a_token->ticker), l_token_cache, a_token_size, l_gdb_group)) {
        if(s_debug_more)
            log_it(L_WARNING, "Ledger cache mismatch");
        DAP_DELETE(l_token_cache);
    }
    DAP_DELETE(l_gdb_group);
    l_token_item->type = a_token->type;
    switch(a_token->type){
    case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE: {
        l_token_item->total_supply = a_token->header_private.total_supply;
        l_token_item->auth_signs= dap_chain_datum_token_simple_signs_parse(a_token,a_token_size,
                                                                                   &l_token_item->auth_signs_total,
                                                                                   &l_token_item->auth_signs_valid );
        if(l_token_item->auth_signs_total){
            l_token_item->auth_signs_pkey_hash = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t,sizeof (dap_chain_hash_fast_t)* l_token_item->auth_signs_total);
            for(uint16_t k=0; k<l_token_item->auth_signs_total;k++){
                dap_sign_get_pkey_hash(l_token_item->auth_signs[k],&l_token_item->auth_signs_pkey_hash[k]);
            }
            if(s_debug_more)
                log_it(L_NOTICE, "Simple token %s added (total_supply = %.1Lf total_signs_valid=%hu signs_total=%hu type=DAP_CHAIN_DATUM_TOKEN_PRIVATE )",
                   a_token->ticker, dap_chain_datoshi_to_coins(a_token->header_private.total_supply),
                   a_token->header_private.signs_valid, a_token->header_private.signs_total);
        }
        break;
    }

    case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL: {
        if(s_debug_more)
            log_it( L_NOTICE, "Private token %s type=DAP_CHAIN_DATUM_TOKEN_PRIVATE_DECL ", a_token->ticker);
        s_token_tsd_parse(a_ledger,l_token_item, a_token, a_token_size);
        break;
    }
    case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE: {
        if(s_debug_more)
            log_it( L_WARNING, "Private token %s type=DAP_CHAIN_DATUM_TOKEN_PRIVATE_UPDATE. Not processed, wait for software update", a_token->ticker);
                // TODO: Check authorithy
                //s_token_tsd_parse(a_ledger,l_token_item, a_token, a_token_size);
        break;
    }
    default:
        if(s_debug_more)
            log_it(L_WARNING,"Unknown token declaration type 0x%04X", a_token->type );
    }
    // Proc emissions tresholds
    s_treshold_emissions_proc( a_ledger); //TODO process thresholds only for no-consensus chains

    return  0;
}

/**
 * @brief s_token_tsd_parse
 * 
 * @param a_ledger 
 * @param a_token_item 
 * @param a_token 
 * @param a_token_size 
 * @return int 
 */
static int s_token_tsd_parse(dap_ledger_t * a_ledger, dap_chain_ledger_token_item_t *a_token_item , dap_chain_datum_token_t * a_token, size_t a_token_size)
{
    UNUSED(a_ledger);
    dap_tsd_t * l_tsd= dap_chain_datum_token_tsd_get(a_token,a_token_size);
    size_t l_tsd_size=0;
    size_t l_tsd_total_size =a_token_size-  (((byte_t*)l_tsd)- (byte_t*) a_token );

    for( size_t l_offset=0; l_tsd && l_offset < l_tsd_total_size;  l_offset += l_tsd_size ){
        l_tsd = (dap_tsd_t *) (((byte_t*)l_tsd ) +l_offset);
        l_tsd_size =  l_tsd? dap_tsd_size(l_tsd): 0;
        if( l_tsd_size==0 ){
            if(s_debug_more)
                log_it(L_ERROR,"Wrong zero TSD size, exiting TSD parse");
            break;
        }else if (l_tsd_size + l_offset > l_tsd_total_size ){
            if(s_debug_more)
                log_it(L_ERROR,"Wrong %zd TSD size, exiting TSD parse", l_tsd_size);
            break;
        }
        switch (l_tsd->type) {
           // set flags
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS:{
                a_token_item->flags |= dap_tsd_get_scalar(l_tsd,uint16_t);
            }break;

           // unset flags
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS:{
                a_token_item->flags ^= dap_tsd_get_scalar(l_tsd,uint16_t);
            }break;

            // set total supply
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY:{
                a_token_item->total_supply = dap_tsd_get_scalar(l_tsd,uint64_t);
            }break;

            // Set total signs count value to set to be valid
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID:{
                a_token_item->auth_signs_valid = dap_tsd_get_scalar(l_tsd,uint16_t);
            }break;

            // Remove owner signature by pkey fingerprint
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_REMOVE:{
                dap_hash_fast_t l_hash = dap_tsd_get_scalar(l_tsd,dap_hash_fast_t);
                for( size_t i=0; i<a_token_item->auth_signs_total; i++){
                    if (dap_hash_fast_compare(&l_hash, &a_token_item->auth_signs_pkey_hash[i] )){
                        if (i+1 != a_token_item->auth_signs_total){
                            memmove(a_token_item->auth_signs+i,a_token_item->auth_signs+i+1,
                                   (a_token_item->auth_signs_total-i-1)*sizeof (void*));
                            memmove(a_token_item->auth_signs_pkey_hash+i,a_token_item->auth_signs_pkey_hash+i+1,
                                   (a_token_item->auth_signs_total-i-1)*sizeof (void*));
                        }
                        a_token_item->auth_signs_total--;
                        if(a_token_item->auth_signs_total){
                            a_token_item->auth_signs = DAP_REALLOC(a_token_item->auth_signs,a_token_item->auth_signs_total*sizeof (void*) );
                            a_token_item->auth_signs_pkey_hash = DAP_REALLOC(a_token_item->auth_signs_pkey_hash,a_token_item->auth_signs_total*sizeof (void*) );
                        }else{
                            DAP_DEL_Z(a_token_item->auth_signs);
                            DAP_DEL_Z(a_token_item->auth_signs_pkey_hash);
                        }

                        break;
                    }
                }
            }break;

            // Add owner signature's pkey fingerprint
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_ADD:{
                if(l_tsd->size == sizeof (dap_hash_fast_t) ){
                    a_token_item->auth_signs_total++;
                    a_token_item->auth_signs = DAP_REALLOC(a_token_item->auth_signs,a_token_item->auth_signs_total*sizeof (void*) );
                    a_token_item->auth_signs_pkey_hash = DAP_REALLOC(a_token_item->auth_signs_pkey_hash,a_token_item->auth_signs_total*sizeof (void*) );
                    a_token_item->auth_signs[a_token_item->auth_signs_total-1] = NULL;
                    memcpy( &a_token_item->auth_signs_pkey_hash[a_token_item->auth_signs_total-1], l_tsd->data, l_tsd->size ) ;
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_ADD expected to have %zd bytes data length, not %zd",
                           sizeof (dap_hash_fast_t), l_tsd_size );
                }
            }break;

            //Allowed tx receiver addres list add, remove or clear
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    dap_chain_addr_t * l_addrs = a_token_item->tx_recv_allow? DAP_NEW_Z_SIZE( dap_chain_addr_t,
                                                                                              sizeof(*a_token_item->tx_recv_allow) )
                                : DAP_REALLOC(a_token_item->tx_recv_allow,(a_token_item->tx_recv_allow_size+1)*sizeof (*a_token_item->tx_recv_allow) );

                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD (code %d)",
                               l_add_addr_check);
                        DAP_DELETE(l_addrs);
                        return -12;
                    }
                    // Check if its already present
                    if (a_token_item->tx_recv_allow)
                        for( size_t i=0; i < a_token_item->tx_recv_allow_size; i++){ // Check for all the list
                            if ( memcmp(&a_token_item->tx_recv_allow[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                                char * l_addr_str= dap_chain_addr_to_str((dap_chain_addr_t*) l_tsd->data );
                                if(s_debug_more)
                                    log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD has address %s thats already present in list",
                                       l_addr_str);
                                DAP_DELETE(l_addr_str);
                                DAP_DELETE(l_addrs);
                                return -11;
                            }
                        }
                    if( l_addrs){
                        memcpy(&l_addrs[a_token_item->tx_recv_allow_size], l_tsd->data,l_tsd->size);
                        a_token_item->tx_recv_allow_size++;
                        a_token_item->tx_recv_allow = l_addrs;

                    }else{
                        log_it(L_ERROR,"Out of memory! Can't extend TX_RECEIVER_ALLOWED array");
                        DAP_DELETE(l_addrs);
                        return -20;
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                    return -10;
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE (code %d)",
                               l_add_addr_check);
                        return -12;
                    }
                    bool l_was_found=false;
                    for( size_t i=0; i < a_token_item->tx_recv_allow_size; i++){ // Check for all the list
                        if ( memcmp(&a_token_item->tx_recv_allow[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                            if( i +1 != a_token_item->tx_recv_allow_size )
                                memmove(&a_token_item->tx_recv_allow[i],&a_token_item->tx_recv_allow[i+1],
                                        sizeof(*a_token_item->tx_recv_allow)*(a_token_item->tx_recv_allow_size-i-1 ) );
                            a_token_item->tx_recv_allow_size--;
                            l_was_found = true;
                            break;
                        }
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                    return -10;
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_CLEAR:{
                if( l_tsd->size == 0 ){
                    if( a_token_item->tx_recv_allow )
                        DAP_DEL_Z(a_token_item->tx_recv_allow);
                    a_token_item->tx_recv_allow_size = 0;
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_CLEAR expected to have 0 bytes data length, not %u",
                           l_tsd->size );
                    return -10;
                }
            }break;


            //Blocked tx receiver addres list add, remove or clear
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    dap_chain_addr_t * l_addrs = a_token_item->tx_recv_block? DAP_NEW_Z_SIZE( dap_chain_addr_t,
                                                                                              sizeof(*a_token_item->tx_recv_block) )
                                : DAP_REALLOC(a_token_item->tx_recv_block,(a_token_item->tx_recv_block_size+1)*sizeof (*a_token_item->tx_recv_block) );
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD (code %d)",
                               l_add_addr_check);
                        DAP_DELETE(l_addrs);
                        return -12;
                    }
                    // Check if its already present
                    if(a_token_item->tx_recv_block)
                        for( size_t i=0; i < a_token_item->tx_recv_block_size; i++){ // Check for all the list
                            if ( memcmp(&a_token_item->tx_recv_block[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                                char * l_addr_str= dap_chain_addr_to_str((dap_chain_addr_t*) l_tsd->data );
                                if(s_debug_more)
                                    log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD has address %s thats already present in list",
                                       l_addr_str);
                                DAP_DELETE(l_addr_str);
                                DAP_DELETE(l_addrs);
                                return -11;
                            }
                        }

                    if( l_addrs){
                        memcpy(&l_addrs[a_token_item->tx_recv_block_size], l_tsd->data,l_tsd->size);
                        a_token_item->tx_recv_block_size++;
                        a_token_item->tx_recv_block = l_addrs;

                    }else{
                        log_it(L_ERROR,"Out of memory! Can't extend TX_RECEIVER_BLOCKED array");
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                    return -10;
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE (code %d)",
                               l_add_addr_check);
                        return -12;
                    }
                    bool l_was_found=false;
                    for( size_t i=0; i < a_token_item->tx_recv_block_size; i++){ // Check for all the list
                        if ( memcmp(&a_token_item->tx_recv_block[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                            if( i +1 != a_token_item->tx_recv_block_size )
                                memmove(&a_token_item->tx_recv_block[i],&a_token_item->tx_recv_block[i+1],
                                        sizeof(*a_token_item->tx_recv_block)*(a_token_item->tx_recv_block_size-i-1 ) );
                            a_token_item->tx_recv_block_size--;
                            l_was_found = true;
                            break;
                        }
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                    return -10;
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_CLEAR:{
                if( l_tsd->size == 0 ){
                    if( a_token_item->tx_recv_block )
                        DAP_DEL_Z(a_token_item->tx_recv_block);
                    a_token_item->tx_recv_block_size = 0;
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_CLEAR expected to have 0 bytes data length, not %u",
                           l_tsd->size );
                    return -10;
                }
            }break;

            //Allowed tx sender addres list add, remove or clear
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    dap_chain_addr_t * l_addrs = a_token_item->tx_send_allow ? DAP_NEW_Z_SIZE( dap_chain_addr_t,
                                                                                              sizeof(*a_token_item->tx_send_allow) )
                                : DAP_REALLOC(a_token_item->tx_send_allow,(a_token_item->tx_send_allow_size+1)*sizeof (*a_token_item->tx_send_allow) );
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD (code %d)",
                               l_add_addr_check);
                        DAP_DELETE(l_addrs);
                        return -12;
                    }
                    // Check if its already present
                    for( size_t i=0; i < a_token_item->tx_send_allow_size; i++){ // Check for all the list
                        if ( memcmp(&a_token_item->tx_send_allow[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                            char * l_addr_str= dap_chain_addr_to_str((dap_chain_addr_t*) l_tsd->data );
                            if(s_debug_more)
                                log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD has address %s thats already present in list",
                                   l_addr_str);
                            DAP_DELETE(l_addr_str);
                            DAP_DELETE(l_addrs);
                            return -11;
                        }
                    }
                    if( l_addrs){
                        memcpy(&l_addrs[a_token_item->tx_send_allow_size], l_tsd->data,l_tsd->size);
                        a_token_item->tx_send_allow_size++;
                        a_token_item->tx_send_allow = l_addrs;

                    }else{
                        log_it(L_ERROR,"Out of memory! Can't extend TX_SENDER_ALLOWED array");
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE (code %d)",
                               l_add_addr_check);
                        return -12;
                    }
                    bool l_was_found=false;
                    for( size_t i=0; i < a_token_item->tx_send_allow_size; i++){ // Check for all the list
                        if ( memcmp(&a_token_item->tx_send_allow[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                            if( i +1 != a_token_item->tx_send_allow_size )
                                memmove(&a_token_item->tx_send_allow[i],&a_token_item->tx_send_allow[i+1],
                                        sizeof(*a_token_item->tx_send_allow)*(a_token_item->tx_send_allow_size-i-1 ) );
                            a_token_item->tx_send_allow_size--;
                            l_was_found = true;
                            break;
                        }
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                    return -10;
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_CLEAR:{
                if( l_tsd->size == 0 ){
                    if( a_token_item->tx_send_allow )
                        DAP_DEL_Z(a_token_item->tx_send_allow);
                    a_token_item->tx_send_allow_size = 0;
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_CLEAR expected to have 0 bytes data length, not %u",
                           l_tsd->size );
                    return -10;
                }
            }break;


            //Blocked tx sender addres list add, remove or clear
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    dap_chain_addr_t * l_addrs = a_token_item->tx_send_block ? DAP_NEW_Z_SIZE( dap_chain_addr_t,
                                                                                              sizeof(*a_token_item->tx_send_block) )
                                : DAP_REALLOC(a_token_item->tx_send_block,(a_token_item->tx_send_block_size+1)*sizeof (*a_token_item->tx_send_block) );
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD (code %d)",
                               l_add_addr_check);
                        DAP_DELETE(l_addrs);
                        return -12;
                    }
                    // Check if its already present
                    for( size_t i=0; i < a_token_item->tx_send_block_size; i++){ // Check for all the list
                        if ( memcmp(&a_token_item->tx_send_block[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                            char * l_addr_str= dap_chain_addr_to_str((dap_chain_addr_t*) l_tsd->data );
                            if(s_debug_more)
                                log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD has address %s thats already present in list",
                                   l_addr_str);
                            DAP_DELETE(l_addr_str);
                            DAP_DELETE(l_addrs);
                            return -11;
                        }
                    }
                    if( l_addrs){
                        memcpy(&l_addrs[a_token_item->tx_send_block_size], l_tsd->data,l_tsd->size);
                        a_token_item->tx_send_block_size++;
                        a_token_item->tx_send_block = l_addrs;

                    }else{
                        log_it(L_ERROR,"Out of memory! Can't extend TX_SENDER_BLOCKED array");
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=0){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE (code %d)",
                               l_add_addr_check);
                        return -12;
                    }
                    bool l_was_found=false;
                    for( size_t i=0; i < a_token_item->tx_send_block_size; i++){ // Check for all the list
                        if ( memcmp(&a_token_item->tx_send_block[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                            if( i +1 != a_token_item->tx_send_block_size )
                                memmove(&a_token_item->tx_send_block[i],&a_token_item->tx_send_block[i+1],
                                        sizeof(*a_token_item->tx_send_block)*(a_token_item->tx_send_block_size-i-1 ) );
                            a_token_item->tx_send_block_size--;
                            l_was_found = true;
                            break;
                        }
                    }
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE expected to have %zu bytes data length, not %u",
                           sizeof (dap_chain_addr_t), l_tsd->size );
                    return -10;
                }
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_CLEAR:{
                if( l_tsd->size == 0 ){
                    if( a_token_item->tx_send_block )
                        DAP_DEL_Z(a_token_item->tx_send_block);
                    a_token_item->tx_send_block_size = 0;
                }else{
                    if(s_debug_more)
                        log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_CLEAR expected to have 0 bytes data length, not %u",
                           l_tsd->size );
                    return -10;
                }
            }break;
            default:{}
        }
    }
    return 0;
}

int dap_chain_ledger_token_load(dap_ledger_t *a_ledger,  dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if (!PVT(a_ledger)->load_mode) {
        return dap_chain_ledger_token_add(a_ledger, a_token, a_token_size);
    } else {
        dap_chain_ledger_token_item_t *l_token_item;
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->tokens, a_token->ticker, l_token_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        if (!l_token_item)
            return dap_chain_ledger_token_add(a_ledger, a_token, a_token_size);
    }
    return 0;
}

dap_list_t *dap_chain_ledger_token_info(dap_ledger_t *a_ledger)
{
    dap_list_t *l_ret_list = NULL;
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        const char *l_type_str;
        switch (l_token_item->type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:
            l_type_str = "SIMPLE"; break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
            l_type_str = "PRIVATE_DECL"; break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
            l_type_str = "PRIVATE_UPDATE"; break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC:
            l_type_str = "PUBLIC";
        default:
            l_type_str = "UNKNOWN"; break;
        }
        char *l_item_str = dap_strdup_printf("Token name '%s', type %s, flags %hu\n"
                                             "\tSupply (current/total) %"DAP_UINT64_FORMAT_U"/%"DAP_UINT64_FORMAT_U"\n"
                                             "\tAuth signs (valid/total) %zu/%zu\n"
                                             "\tTotal emissions %u\n",
                                             &l_token_item->ticker, l_type_str, l_token_item->flags,
                                             l_token_item->current_supply, l_token_item->total_supply,
                                             l_token_item->auth_signs_valid, l_token_item->auth_signs_total,
                                             HASH_COUNT(l_token_item->token_emissions));
        l_ret_list = dap_list_append(l_ret_list, l_item_str);
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_ret_list;
}

/**
 * @brief s_treshold_emissions_proc
 * @param a_ledger
 */
static void s_treshold_emissions_proc(dap_ledger_t * a_ledger)
{ 
    bool l_success;
    do {
        l_success = false;
        dap_chain_ledger_token_emission_item_t *l_emission_item, *l_emission_tmp;
        pthread_rwlock_rdlock(&PVT(a_ledger)->treshold_emissions_rwlock);
        HASH_ITER(hh, PVT(a_ledger)->treshold_emissions, l_emission_item, l_emission_tmp) {
            pthread_rwlock_unlock(&PVT(a_ledger)->treshold_emissions_rwlock);
            int l_res = dap_chain_ledger_token_emission_add(a_ledger, (byte_t *)l_emission_item->datum_token_emission,
                                                            l_emission_item->datum_token_emission_size);
            if (l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN) {
                pthread_rwlock_wrlock(&PVT(a_ledger)->treshold_emissions_rwlock);
                HASH_DEL(PVT(a_ledger)->treshold_emissions, l_emission_item);
                pthread_rwlock_unlock(&PVT(a_ledger)->treshold_emissions_rwlock);
                DAP_DELETE(l_emission_item);
                l_success = true;
            }

            pthread_rwlock_rdlock(&PVT(a_ledger)->treshold_emissions_rwlock);
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->treshold_emissions_rwlock);
    } while (l_success); 
}

/**
 * @brief s_treshold_txs_proc
 * @param a_ledger
 */
static void s_treshold_txs_proc( dap_ledger_t *a_ledger)
{  
    bool l_success;
    dap_ledger_private_t * l_ledger_pvt = PVT(a_ledger);
    do {
        l_success = false;
        dap_chain_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
        pthread_rwlock_rdlock(&l_ledger_pvt->treshold_txs_rwlock);
        HASH_ITER(hh, l_ledger_pvt->treshold_txs, l_tx_item, l_tx_tmp) {            
            pthread_rwlock_unlock(& l_ledger_pvt->treshold_txs_rwlock );
            int l_res = dap_chain_ledger_tx_add(a_ledger, l_tx_item->tx, &l_tx_item->tx_hash_fast, true);
            if (l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION &&
                    l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS) {
                pthread_rwlock_wrlock(&l_ledger_pvt->treshold_txs_rwlock);
                HASH_DEL(l_ledger_pvt->treshold_txs, l_tx_item);
                pthread_rwlock_unlock(& l_ledger_pvt->treshold_txs_rwlock );                          
                DAP_DELETE(l_tx_item);
                l_success = true;
            }
            pthread_rwlock_rdlock(&l_ledger_pvt->treshold_txs_rwlock);
        }
        pthread_rwlock_unlock(& l_ledger_pvt->treshold_txs_rwlock );
    } while (l_success);
}


void dap_chain_ledger_load_cache(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TOKENS_STR);
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        dap_chain_ledger_token_item_t *l_token_item = DAP_NEW_Z(dap_chain_ledger_token_item_t);
        strncpy(l_token_item->ticker, l_objs[i].key, sizeof(l_token_item->ticker) - 1);
        l_token_item->ticker[sizeof(l_token_item->ticker) - 1] = '\0';
        l_token_item->datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_objs[i].value_len);
        memcpy(l_token_item->datum_token, l_objs[i].value, l_objs[i].value_len);
        pthread_rwlock_init(&l_token_item->token_emissions_rwlock, NULL);
        if (l_token_item->datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE) {
            l_token_item->total_supply = l_token_item->datum_token->header_private.total_supply;
            l_token_item->auth_signs= dap_chain_datum_token_simple_signs_parse(l_token_item->datum_token, l_objs[i].value_len,
                                                                                       &l_token_item->auth_signs_total,
                                                                                       &l_token_item->auth_signs_valid );
            if (l_token_item->auth_signs_total) {
                l_token_item->auth_signs_pkey_hash = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t,
                                                                    sizeof(dap_chain_hash_fast_t) * l_token_item->auth_signs_total);
                for (uint16_t k=0; k < l_token_item->auth_signs_total; k++) {
                    dap_sign_get_pkey_hash(l_token_item->auth_signs[k], &l_token_item->auth_signs_pkey_hash[k]);
                }
            }
        }
        HASH_ADD_STR(l_ledger_pvt->tokens, ticker, l_token_item);
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);

    l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
    l_objs_count = 0;
    l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        if (!l_objs[i].value_len)
            continue;
        dap_chain_ledger_token_emission_item_t *l_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_emission_item->datum_token_emission_hash);
        size_t l_emission_size = l_objs[i].value_len;
        const char *c_token_ticker = ((dap_chain_datum_token_emission_t *)l_objs[i].value)->hdr.ticker;
        dap_chain_ledger_token_item_t *l_token_item = NULL;
        HASH_FIND_STR(l_ledger_pvt->tokens, c_token_ticker, l_token_item);
        l_emission_item->datum_token_emission = l_token_item
                                                           ? dap_chain_datum_emission_read(l_objs[i].value, &l_emission_size)
                                                           : DAP_DUP_SIZE(l_objs[i].value, l_objs[i].value_len);
        l_emission_item->datum_token_emission_size = l_emission_size;
        if (l_token_item) {
            HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash,
                     sizeof(dap_chain_hash_fast_t), l_emission_item);
        } else {
            HASH_ADD(hh, l_ledger_pvt->treshold_emissions, datum_token_emission_hash,
                     sizeof(dap_chain_hash_fast_t), l_emission_item);
        }
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);

    l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
    l_objs_count = 0;
    l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        dap_chain_ledger_tx_item_t *l_tx_item = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_tx_item->tx_hash_fast);
        l_tx_item->tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, l_objs[i].value_len - sizeof(l_tx_item->cache_data));
        memcpy(l_tx_item->tx, l_objs[i].value + sizeof(l_tx_item->cache_data), l_objs[i].value_len - sizeof(l_tx_item->cache_data));
        memcpy(&l_tx_item->cache_data, l_objs[i].value, sizeof(l_tx_item->cache_data));
        HASH_ADD(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item);
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);

    l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
    l_objs_count = 0;
    l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        dap_chain_ledger_tx_spent_item_t *l_tx_spent_item = DAP_NEW_Z(dap_chain_ledger_tx_spent_item_t);
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_tx_spent_item->tx_hash_fast);
        strncpy(l_tx_spent_item->token_ticker, (char *)l_objs[i].value, DAP_CHAIN_TICKER_SIZE_MAX);
        HASH_ADD(hh, l_ledger_pvt->spent_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_spent_item);
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);

    l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
    l_objs_count = 0;
    l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        dap_ledger_wallet_balance_t *l_balance_item = DAP_NEW_Z(dap_ledger_wallet_balance_t);
        l_balance_item->key = DAP_NEW_Z_SIZE(char, strlen(l_objs[i].key) + 1);
        strcpy(l_balance_item->key, l_objs[i].key);
        char *l_ptr = strchr(l_balance_item->key, ' ');
        if (l_ptr++) {
            strcpy(l_balance_item->token_ticker, l_ptr);
        }
        l_balance_item->balance = *(uint128_t *)l_objs[i].value;
        HASH_ADD_KEYPTR(hh, l_ledger_pvt->balance_accounts, l_balance_item->key,
                        strlen(l_balance_item->key), l_balance_item);
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);
}

/**
 * @brief 
 * create ledger for specific net
 * load ledger cache
 * @param a_check_flags checking flags
 *          DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION
 *          DAP_CHAIN_LEDGER_CHECK_CELLS_DS
 *          DAP_CHAIN_LEDGER_CHECK_CELLS_DS
 * @param a_net_name char * network name, for example "kelvin-testnet"
 * @return dap_ledger_t* 
 */
dap_ledger_t* dap_chain_ledger_create(uint16_t a_check_flags, char *a_net_name)
{
    dap_ledger_t *l_ledger = dap_chain_ledger_handle_new();
    l_ledger->net_name = a_net_name;
    dap_ledger_private_t *l_ledger_priv = PVT(l_ledger);
    l_ledger_priv->check_flags = a_check_flags;
    l_ledger_priv->check_ds = a_check_flags & DAP_CHAIN_LEDGER_CHECK_LOCAL_DS;
    l_ledger_priv->check_cells_ds = a_check_flags & DAP_CHAIN_LEDGER_CHECK_CELLS_DS;
    l_ledger_priv->check_token_emission = a_check_flags & DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION;
    l_ledger_priv->net = dap_chain_net_by_name(a_net_name);
    l_ledger_priv->load_mode = true;
    l_ledger_priv->tps_timer = NULL;
    l_ledger_priv->tps_count = 0;

    log_it(L_DEBUG,"Created ledger \"%s\"",a_net_name);
    if (dap_config_get_item_bool_default(g_config, "ledger", "cached", true)) {
        // load ledger cache from GDB
        dap_chain_ledger_load_cache(l_ledger);
    }
    return l_ledger;
}

int dap_chain_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size)
{
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);

    const char * c_token_ticker = ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.ticker;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
    HASH_FIND_STR(l_ledger_priv->tokens, c_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);

    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;

    // check if such emission is already present in table
    dap_chain_hash_fast_t l_token_emission_hash={0};
    //dap_chain_hash_fast_t * l_token_emission_hash_ptr = &l_token_emission_hash;
    dap_hash_fast(a_token_emission, a_token_emission_size, &l_token_emission_hash);
    char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_token_emission_hash);
    pthread_rwlock_rdlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_priv->treshold_emissions_rwlock);
    HASH_FIND(hh,l_token_item ? l_token_item->token_emissions : l_ledger_priv->treshold_emissions,
              &l_token_emission_hash, sizeof(l_token_emission_hash), l_token_emission_item);
    unsigned long long l_threshold_emissions_count = HASH_COUNT( l_ledger_priv->treshold_emissions);
    pthread_rwlock_unlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_priv->treshold_emissions_rwlock);
    if(l_token_emission_item ) {
        if(s_debug_more)
            log_it(L_ERROR, "Can't add token emission datum of %"DAP_UINT64_FORMAT_U" %s ( %s ): already present in cache",
                l_token_emission_item->datum_token_emission->hdr.value, c_token_ticker, l_hash_str);
        l_ret = -1;
    }else if ( (! l_token_item) && ( l_threshold_emissions_count >= s_treshold_emissions_max)) {
        if(s_debug_more)
            log_it(L_WARNING,"Treshold for emissions is overfulled (%zu max)",
               s_treshold_emissions_max);
        l_ret = -2;
    }
    DAP_DELETE(l_hash_str);
    if (l_ret || !PVT(a_ledger)->check_token_emission)
        return l_ret;
    // Check emission correctness
    size_t l_emission_size = a_token_emission_size;
    dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_token_emission, &l_emission_size);
    switch (l_emission->hdr.type){
        case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:{
            dap_chain_ledger_token_item_t *l_token_item=NULL;
            pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->tokens, l_emission->hdr.ticker, l_token_item);
            pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
            if (l_token_item){
                assert(l_token_item->datum_token);
                dap_sign_t *l_sign = (dap_sign_t *)l_emission->data.type_auth.signs;
                size_t l_offset = (byte_t *)l_sign - (byte_t *)l_emission;
                uint16_t l_aproves = 0, l_aproves_valid = l_token_item->auth_signs_valid;
                for (uint16_t i = 0; i < l_emission->data.type_auth.signs_count && l_offset < l_emission_size; i++) {
                    if (dap_sign_verify_size(l_sign, l_emission_size - l_offset)) {
                        dap_chain_hash_fast_t l_sign_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                        // Find pkey in auth hashes
                        for (uint16_t k=0; k< l_token_item->auth_signs_total; k++) {
                            if (dap_hash_fast_compare(&l_sign_pkey_hash, &l_token_item->auth_signs_pkey_hash[k])) {
                                // Verify if its token emission header signed
                                if (dap_sign_verify(l_sign, &l_emission->hdr, sizeof(l_emission->hdr)) == 1) {
                                    l_aproves++;
                                    break;
                                }
                            }
                        }
                        size_t l_sign_size = dap_sign_get_size(l_sign);
                        l_offset += l_sign_size;
                        l_sign = (dap_sign_t *)((byte_t *)l_emission + l_offset);
                    } else
                        break;
                }

                if (l_aproves < l_aproves_valid ){
                    if(s_debug_more)
                        log_it(L_WARNING, "Emission of %"DAP_UINT64_FORMAT_U" datoshi of %s:%s is wrong: only %u valid aproves when %u need",
                           l_emission->hdr.value, a_ledger->net_name, l_emission->hdr.ticker, l_aproves, l_aproves_valid );
                    l_ret = -3;
                }
            }else{
                if(s_debug_more)
                    log_it(L_WARNING,"Can't find token declaration %s:%s thats pointed in token emission datum", a_ledger->net_name, l_emission->hdr.ticker);
                l_ret = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN;
            }
        }break;
        default:{}
    }
    DAP_DELETE(l_emission);
    return l_ret;
}

/**
 * @brief dap_chain_ledger_token_emission_add
 * @param a_token_emission
 * @param a_token_emision_size
 * @return
 */
int dap_chain_ledger_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size)
{
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);

    const char * c_token_ticker = ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.ticker;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
    HASH_FIND_STR(l_ledger_priv->tokens, c_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
    // check if such emission is already present in table
    dap_chain_hash_fast_t l_token_emission_hash = {};
    dap_hash_fast(a_token_emission, a_token_emission_size, &l_token_emission_hash);
    char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_token_emission_hash);
    pthread_rwlock_rdlock( l_token_item ? &l_token_item->token_emissions_rwlock
                                        : &l_ledger_priv->treshold_emissions_rwlock);
    HASH_FIND(hh,l_token_item ? l_token_item->token_emissions : l_ledger_priv->treshold_emissions,
              &l_token_emission_hash, sizeof(l_token_emission_hash), l_token_emission_item);
    unsigned long long l_threshold_emissions_count = HASH_COUNT( l_ledger_priv->treshold_emissions);
    pthread_rwlock_unlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_priv->treshold_emissions_rwlock);
    if(l_token_emission_item == NULL ) {
        if ( l_token_item || l_threshold_emissions_count < s_treshold_emissions_max  ) {
            l_token_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
            size_t l_emission_size = a_token_emission_size;
            l_token_emission_item->datum_token_emission = l_token_item
                                                                     ? dap_chain_datum_emission_read(a_token_emission, &l_emission_size)
                                                                     : DAP_DUP_SIZE(a_token_emission, a_token_emission_size);
            memcpy(l_token_emission_item->datum_token_emission, a_token_emission, a_token_emission_size);
            memcpy(&l_token_emission_item->datum_token_emission_hash,
                   &l_token_emission_hash, sizeof(l_token_emission_hash));
            l_token_emission_item->datum_token_emission_size = a_token_emission_size;
            pthread_rwlock_wrlock( l_token_item ? &l_token_item->token_emissions_rwlock
                                                : &l_ledger_priv->treshold_emissions_rwlock);
            if (l_token_item) {
                HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash,
                         sizeof(l_token_emission_hash), l_token_emission_item);
            } else {
                HASH_ADD(hh, l_ledger_priv->treshold_emissions, datum_token_emission_hash,
                         sizeof(l_token_emission_hash), l_token_emission_item);
                l_ret = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN;
            }
            pthread_rwlock_unlock( l_token_item ? &l_token_item->token_emissions_rwlock
                                                : &l_ledger_priv->treshold_emissions_rwlock);
            if (l_token_item) {
                // Add it to cache
                dap_chain_datum_token_emission_t *l_emission_cache = DAP_DUP_SIZE(a_token_emission, a_token_emission_size);
                char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
                if (!dap_chain_global_db_gr_set(dap_strdup(l_hash_str), l_emission_cache, a_token_emission_size, l_gdb_group)) {
                    log_it(L_WARNING, "Ledger cache mismatch");
                    DAP_DELETE(l_emission_cache);
                }
                DAP_DELETE(l_gdb_group);
            }            char * l_token_emission_address_str = dap_chain_addr_to_str(&(l_token_emission_item->datum_token_emission->hdr.address) );
            if(s_debug_more)
                log_it(L_NOTICE, "Added token emission datum to %s: type=%s value=%.1Lf token=%s to_addr=%s ",
                           l_token_item?"emissions cache":"emissions treshold",
                           c_dap_chain_datum_token_emission_type_str[l_token_emission_item->datum_token_emission->hdr.type ] ,
                           dap_chain_datoshi_to_coins(l_token_emission_item->datum_token_emission->hdr.value), c_token_ticker,
                           l_token_emission_address_str);
            DAP_DELETE(l_token_emission_address_str);
            if (l_token_item)
                s_treshold_txs_proc(a_ledger);
        }else{
            if(s_debug_more)
                log_it(L_WARNING,"Treshold for emissions is overfulled (%zu max), dropping down new data, added nothing",
                   s_treshold_emissions_max);
            l_ret = -2;
        }
    } else {
        if (l_token_item) {
            if(s_debug_more)
                log_it(L_ERROR, "Duplicate token emission datum of %"DAP_UINT64_FORMAT_U" %s ( %s )",
                                ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.value,
                                c_token_ticker, l_hash_str);
        }
        l_ret = -1;
    }
    DAP_DELETE(l_hash_str);
    return l_ret;
}

int dap_chain_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size)
{
    if (!PVT(a_ledger)->load_mode) {
        return dap_chain_ledger_token_emission_add(a_ledger, a_token_emission, a_token_emission_size);
    } else {
        dap_chain_hash_fast_t l_token_emission_hash = {};
        dap_hash_fast(a_token_emission, a_token_emission_size, &l_token_emission_hash);
        dap_chain_ledger_token_emission_item_t *l_token_emission_item;
        dap_chain_ledger_token_item_t *l_token_item, *l_item_tmp;
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_item_tmp) {
            pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
            HASH_FIND(hh, l_token_item->token_emissions, &l_token_emission_hash, sizeof(l_token_emission_hash),
                    l_token_emission_item);
            pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
            if (l_token_emission_item) {
                pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
                return 0;
            }
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        pthread_rwlock_rdlock(&PVT(a_ledger)->treshold_emissions_rwlock);
        HASH_FIND(hh, PVT(a_ledger)->treshold_emissions, &l_token_emission_hash, sizeof(l_token_emission_hash),
                l_token_emission_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->treshold_emissions_rwlock);
        if (l_token_emission_item) {
            return DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN;
        }
    }
    return dap_chain_ledger_token_emission_add(a_ledger, a_token_emission, a_token_emission_size);
}

/**
 * @brief dap_chain_ledger_token_emission_find
 * @param a_token_ticker
 * @param a_token_emission_hash
 * @return
 */
dap_chain_datum_token_emission_t * dap_chain_ledger_token_emission_find(dap_ledger_t *a_ledger,
        const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_datum_token_emission_t * l_token_emission = NULL;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
    HASH_FIND_STR(l_ledger_priv->tokens, a_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);

    if(l_token_item) {
        dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
        pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
        HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash),
                l_token_emission_item);
        pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
        if( l_token_emission_item)
            l_token_emission = l_token_emission_item->datum_token_emission;
    }
    return l_token_emission;
}

/**
 * @brief dap_chain_ledger_set_local_cell_id
 * @param a_local_cell_id
 */
void dap_chain_ledger_set_local_cell_id(dap_ledger_t *a_ledger, dap_chain_cell_id_t a_local_cell_id)
{
    PVT(a_ledger)->local_cell_id.uint64 = a_local_cell_id.uint64;
}

/**
 * @brief dap_chain_ledger_tx_get_token_ticker_by_hash
 * @param a_ledger
 * @param a_tx_hash
 * @return
 */
const char* dap_chain_ledger_tx_get_token_ticker_by_hash(dap_ledger_t *a_ledger,dap_chain_hash_fast_t *a_tx_hash)
{
    if(!a_ledger || !a_tx_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);

    if ( dap_hash_fast_is_blank(a_tx_hash) )
        return NULL;

    dap_chain_ledger_tx_item_t *l_item;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof (*a_tx_hash), l_item);
    if (l_item) {
        pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
        return l_item->cache_data.token_ticker;
    }
    dap_chain_ledger_tx_spent_item_t *l_spent_item;
    HASH_FIND(hh, l_ledger_priv->spent_items, a_tx_hash, sizeof (*a_tx_hash), l_spent_item);
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_spent_item ? l_spent_item->token_ticker : NULL;
}


/**
 * @brief dap_chain_ledger_addr_get_token_ticker_all
 * @param a_addr
 * @param a_tickers
 * @param a_tickers_size
 */
void dap_chain_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size)
{
    dap_chain_hash_fast_t l_tx_first_hash = { 0 };
    const dap_chain_ledger_tx_item_t * l_tx_item = tx_item_find_by_addr(a_ledger, a_addr,NULL, &l_tx_first_hash);
    char ** l_tickers = NULL;
    size_t l_tickers_size = 10;
    size_t l_tickers_pos = 0;

    if(l_tx_item) {
        l_tickers_size = 10;
        l_tickers = DAP_NEW_Z_SIZE(char *, l_tickers_size * sizeof(char*));
        while(l_tx_item) {
            bool l_is_not_in_list = true;
            for(size_t i = 0; i < l_tickers_size; i++) {
                if (l_tickers[i]==NULL)
                    break;
                if(l_tickers[i] && strcmp(l_tickers[i], l_tx_item->cache_data.token_ticker) == 0) {
                    l_is_not_in_list = false;
                    break;
                }
            }
            if(l_is_not_in_list) {
                if((l_tickers_pos + 1) == l_tickers_size) {
                    l_tickers_size += (l_tickers_size / 2);
                    l_tickers = DAP_REALLOC(l_tickers, l_tickers_size);
                }
                l_tickers[l_tickers_pos] = dap_strdup(l_tx_item->cache_data.token_ticker);
                l_tickers_pos++;
            }
            dap_chain_hash_fast_t* l_tx_hash = dap_chain_node_datum_tx_calc_hash(l_tx_item->tx);
            l_tx_item = tx_item_find_by_addr(a_ledger, a_addr, NULL, l_tx_hash);
            DAP_DELETE(l_tx_hash);
        }
        l_tickers_size = l_tickers_pos + 1;
        l_tickers = DAP_REALLOC(l_tickers, l_tickers_size * sizeof(char*));
    }
    *a_tickers = l_tickers;
    *a_tickers_size = l_tickers_pos;
}

void dap_chain_ledger_addr_get_token_ticker_all_fast(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size) {
    dap_ledger_wallet_balance_t *wallet_balance, *tmp;
    size_t l_count = HASH_COUNT(PVT(a_ledger)->balance_accounts);
    if(l_count){
        char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
        l_count = 0;
        char *l_addr = dap_chain_addr_to_str(a_addr);
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
    *a_tickers_size = l_count;
}



/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
static dap_chain_datum_tx_t* s_find_datum_tx_by_hash(dap_ledger_t *a_ledger,
        dap_chain_hash_fast_t *a_tx_hash, dap_chain_ledger_tx_item_t **a_item_out)
{
    if(!a_tx_hash)
        return NULL;

//    log_it( L_ERROR, "s_find_datum_tx_by_hash( )...");

    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_datum_tx_t *l_tx_ret = NULL;
    dap_chain_ledger_tx_item_t *l_tx_item;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item); // tx_hash already in the hash?
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    if(l_tx_item) {
        l_tx_ret = l_tx_item->tx;
        if(a_item_out)
            *a_item_out = l_tx_item;
    }
    return l_tx_ret;
}

/**
 * @brief dap_chain_ledger_tx_find_by_hash
 * @param a_tx_hash
 * @return
 */

dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash)
{
    return s_find_datum_tx_by_hash(a_ledger, a_tx_hash, NULL);
}

/**
 * Check whether used 'out' items (local function)
 */
static bool dap_chain_ledger_item_is_used_out(dap_chain_ledger_tx_item_t *a_item, int a_idx_out)
{
    bool l_used_out = false;
    if (!a_item || !a_item->cache_data.n_outs) {
        //log_it(L_DEBUG, "list_cached_item is NULL");
        return true;
    }
    if(a_idx_out >= MAX_OUT_ITEMS) {
        if(s_debug_more)
            log_it(L_ERROR, "Too big index(%d) of 'out'items (max=%d)", a_idx_out, MAX_OUT_ITEMS);
    }
    assert(a_idx_out < MAX_OUT_ITEMS);
    // if there are used 'out' items
    if(a_item->cache_data.n_outs_used > 0) {
        if(!dap_hash_fast_is_blank(&(a_item->cache_data.tx_hash_spent_fast[a_idx_out])))
            l_used_out = true;
    }
    return l_used_out;
}

/**
 * @brief dap_chain_ledger_permissions_check
 * @param a_token_item
 * @param a_permission_id
 * @param a_data
 * @param a_data_size
 * @return
 */
static int s_ledger_permissions_check(dap_chain_ledger_token_item_t *  a_token_item, uint16_t a_permission_id, const void * a_data,size_t a_data_size )
{
    dap_chain_addr_t * l_addrs = NULL;
    size_t l_addrs_count =0;
    switch (a_permission_id) {
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
            l_addrs = a_token_item->tx_recv_allow;
            l_addrs_count = a_token_item->tx_recv_allow_size;
        break;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
            l_addrs = a_token_item->tx_recv_block;
            l_addrs_count = a_token_item->tx_recv_block_size;
        break;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
            l_addrs = a_token_item->tx_send_allow;
            l_addrs_count = a_token_item->tx_send_allow_size;
        break;
        case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
            l_addrs = a_token_item->tx_send_block;
            l_addrs_count = a_token_item->tx_send_block_size;
        break;
    }
    if ( l_addrs && l_addrs_count){
        if (a_data_size != sizeof (*l_addrs)){
            log_it(L_ERROR,"Wrong data size %zd for ledger permission check", a_data_size);
            return -2;
        }
        for(size_t n=0; n<l_addrs_count;n++ ){
            if (memcmp(&l_addrs[n],a_data,a_data_size)==0)
                return 0;
        }
        return -1;
    }
    return -10;
}

/**
 * Checking a new transaction before adding to the cache
 *
 * return 1 OK, -1 error
 */
// Checking a new transaction before adding to the cache
int dap_chain_ledger_tx_cache_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
        dap_list_t **a_list_bound_items, dap_list_t **a_list_tx_out)
{
    /*
     Steps of checking for current transaction tx2 and every previous transaction tx1:
     1. !is_used_out(tx1.dap_chain_datum_tx_out)
     &&
     2. valid(tx2.dap_chain_datum_tx_sig.pkey)
     &&
     3. hash(tx1) == tx2.dap_chain_datump_tx_in.tx_prev_hash
     &&
     4. tx1.dap_chain_datum_tx_out.addr.data.key == tx2.dap_chain_datum_tx_sig.pkey for unconditional output
     \\
     5a. tx1.dap_chain_datum_tx_sig.pkey == tx2.dap_chain_datum_tx_sig.pkey for conditional owner
     \\
     5b. tx1.dap_chain_datum_tx_out.condition == verify_svc_type(tx2) for conditional output
     &&
     6. sum(  find (tx2.input.tx_prev_hash).output[tx2.input_tx_prev_idx].value )  ==  sum (tx2.outputs.value) per token
     */

    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    if(!a_tx){
        log_it(L_DEBUG, "NULL transaction, check broken");
        return -1;
    }

    dap_list_t *l_list_bound_items = NULL;

    bool l_is_first_transaction = false;
    // sum of values in 'out' items from the previous transactions
    dap_chain_ledger_tokenizer_t *l_values_from_prev_tx = NULL, *l_values_from_cur_tx = NULL,
                                 *l_value_cur = NULL, *l_tmp = NULL, *l_res = NULL;
    char *l_token = NULL;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    dap_chain_hash_fast_t *l_emission_hash;

    // check all previous transactions
    int l_err_num = 0;
    int l_prev_tx_count = 0;

    // ----------------------------------------------------------------
    // find all 'in' items in current transaction
    dap_list_t *l_list_in = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_IN,
                                                          &l_prev_tx_count);
    // find all conditional 'in' items in current transaction
    dap_list_t *l_list_tmp = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t *)a_tx, TX_ITEM_TYPE_IN_COND,
                                                          &l_prev_tx_count);
    if (l_list_tmp) {
        // add conditional input to common list
        l_list_in = dap_list_append(l_list_in, l_list_tmp->data);
        dap_list_free(l_list_tmp);
    }
    l_list_tmp = l_list_in;
    dap_chain_ledger_tx_bound_t *bound_item;
    int l_list_tmp_num = 0;
     // find all previous transactions
    for (dap_list_t *l_list_tmp = l_list_in; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_list_tmp_num++) {
        bound_item = DAP_NEW_Z(dap_chain_ledger_tx_bound_t);
        dap_chain_tx_in_t *l_tx_in = NULL;
        dap_chain_addr_t l_tx_in_from={0};
        dap_chain_tx_in_cond_t *l_tx_in_cond;
        dap_chain_hash_fast_t l_tx_prev_hash={0};
        uint8_t l_cond_type = *(uint8_t *)l_list_tmp->data;
        // one of the previous transaction
        if (l_cond_type == TX_ITEM_TYPE_IN) {
            l_tx_in = (dap_chain_tx_in_t *)l_list_tmp->data;
            l_tx_prev_hash = l_tx_in->header.tx_prev_hash;
            bound_item->in.tx_cur_in = l_tx_in;
        } else { // TX_ITEM_TYPE_IN_COND
            l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_list_tmp->data;
            l_tx_prev_hash = l_tx_in_cond->header.tx_prev_hash;
            bound_item->in.tx_cur_in_cond = l_tx_in_cond;
        }
        memcpy(&bound_item->tx_prev_hash_fast, &l_tx_prev_hash, sizeof(dap_chain_hash_fast_t));

        bool l_is_blank = dap_hash_fast_is_blank(&l_tx_prev_hash);
        char l_tx_prev_hash_str[70]={[0]='\0'};
        if (l_is_blank){
            if(s_debug_more)
                log_it(L_DEBUG, "Tx check: blank prev hash ");
           dap_snprintf(l_tx_prev_hash_str,sizeof( l_tx_prev_hash_str),"BLANK");
        }else{
            dap_chain_hash_fast_to_str(&l_tx_prev_hash,l_tx_prev_hash_str,sizeof(l_tx_prev_hash_str));
        }

        if(l_is_blank || l_is_first_transaction) {
            // if at least one blank hash is present, then all the hashes should be blank
            if((!l_is_first_transaction && l_list_tmp_num > 1) || !l_is_blank) {
                l_err_num = -3;
                break;
            }
            l_is_first_transaction = true;
            if (!l_token) {
                dap_chain_tx_token_t *l_tx_token = (dap_chain_tx_token_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL);
                if (!l_tx_token) {
                    l_err_num = -4;
                    break;
                }
                l_token = l_tx_token->header.ticker;
                l_emission_hash = &l_tx_token->header.token_emission_hash;
            }
            DAP_DELETE(bound_item);
            continue;
        }
        // Get previous transaction in the cache by hash
        dap_chain_ledger_tx_item_t *l_item_out = NULL;
        dap_chain_datum_tx_t *l_tx_prev =
                s_find_datum_tx_by_hash(a_ledger, &l_tx_prev_hash, &l_item_out); // dap_chain_datum_tx_t *l_tx_prev = (dap_chain_datum_tx_t*) dap_chain_node_datum_tx_cache_find(&tx_prev_hash);
        bound_item->item_out = l_item_out;
        if(!l_tx_prev) { // Unchained transaction
            //if(s_debug_more)  // Too many messages with thresholds processing
            //    log_it(L_DEBUG,"No previous transaction was found for hash %s",l_tx_prev_hash_str);
            l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
            break;
        }
        if(s_debug_more)
            log_it(L_INFO,"Previous transaction was found for hash %s",l_tx_prev_hash_str);
        bound_item->tx_prev = l_tx_prev;

        // 1. Check if out in previous transaction has spent
        int l_idx = (l_cond_type == TX_ITEM_TYPE_IN) ? l_tx_in->header.tx_out_prev_idx : l_tx_in_cond->header.tx_out_prev_idx;
        if (dap_chain_ledger_item_is_used_out(l_item_out, l_idx)) {
            l_err_num = -6;
            break;
        }

        // 2. Verify signature in current transaction
        if(dap_chain_datum_tx_verify_sign(a_tx) != 1)
            return -2;

        // 3. Compare hash in previous transaction with hash inside 'in' item
        // calculate hash of previous transaction anew
        dap_chain_hash_fast_t *l_hash_prev = dap_chain_node_datum_tx_calc_hash(l_tx_prev);
        int l_res_hash = dap_hash_fast_compare(l_hash_prev, &l_tx_prev_hash);

        DAP_DELETE(l_hash_prev);
        if (l_res_hash != 1) {
            l_err_num = -7;
            break;
        }

        uint64_t l_value;
        // Get list of all 'out' items from previous transaction
        dap_list_t *l_list_prev_out = dap_chain_datum_tx_items_get(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, NULL);
        // Get one 'out' item in previous transaction bound with current 'in' item
        void *l_tx_prev_out = dap_list_nth_data(l_list_prev_out, l_idx);
        dap_list_free(l_list_prev_out);
        if(!l_tx_prev_out) {
            l_err_num = -8;
            break;
        }
        if (l_cond_type == TX_ITEM_TYPE_IN) {
            dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_prev_out;
            if (l_type == TX_ITEM_TYPE_OUT) {
                bound_item->out.tx_prev_out = l_tx_prev_out;
                memcpy(&l_tx_in_from, &bound_item->out.tx_prev_out->addr,sizeof (bound_item->out.tx_prev_out->addr));
            } else if (l_type == TX_ITEM_TYPE_OUT_EXT) {
                bound_item->out.tx_prev_out_ext = l_tx_prev_out;
                memcpy(&l_tx_in_from, &bound_item->out.tx_prev_out_ext->addr,sizeof (bound_item->out.tx_prev_out_ext->addr));
            } else {
                l_err_num = -8;
                break;
            }
            // calculate hash of public key in current transaction
            dap_chain_hash_fast_t l_hash_pkey;
            {
                // Get sign item
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(a_tx, NULL,
                        TX_ITEM_TYPE_SIG, NULL);
                // Get sign from sign item
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*) l_tx_sig);
                // Get public key from sign
                size_t l_pkey_ser_size = 0;
                const uint8_t *l_pkey_ser = dap_sign_get_pkey(l_sign, &l_pkey_ser_size);
                // calculate hash from public key
                dap_hash_fast(l_pkey_ser, l_pkey_ser_size, &l_hash_pkey);
                // hash of public key in 'out' item of previous transaction
                uint8_t *l_prev_out_addr_key = (l_type == TX_ITEM_TYPE_OUT) ?
                                                bound_item->out.tx_prev_out->addr.data.key :
                                                bound_item->out.tx_prev_out_ext->addr.data.key;
                // 4. compare public key hashes in the signature of the current transaction and in the 'out' item of the previous transaction
                if(memcmp(&l_hash_pkey, l_prev_out_addr_key, sizeof(dap_chain_hash_fast_t))) {
                    l_err_num = -9;
                    break;
                }
            }
            if (l_type == TX_ITEM_TYPE_OUT) {
                l_value = bound_item->out.tx_prev_out->header.value;
            } else {
                l_value = bound_item->out.tx_prev_out_ext->header.value;
                l_token = bound_item->out.tx_prev_out_ext->token;
            }
        } else { // TX_ITEM_TYPE_IN_COND
            if(*(uint8_t *)l_tx_prev_out != TX_ITEM_TYPE_OUT_COND) {
                l_err_num = -8;
                break;
            }
            if (! l_token_item){
                l_err_num = -16;
                log_it(L_ERROR,"Can't find token item for conditioned tx out");
                break;
            }
            // 5a. Check for condition owner
            dap_chain_tx_sig_t *l_tx_prev_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_tx_prev, NULL, TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_prev_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_prev_sig);
            size_t l_prev_pkey_ser_size = 0;
            const uint8_t *l_prev_pkey_ser = dap_sign_get_pkey(l_prev_sign, &l_prev_pkey_ser_size);
            dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
            size_t l_pkey_ser_size = 0;
            const uint8_t *l_pkey_ser = dap_sign_get_pkey(l_sign, &l_pkey_ser_size);
            dap_chain_tx_out_cond_t *l_tx_prev_out_cond = (dap_chain_tx_out_cond_t *)l_tx_prev_out;
            bool l_owner = false;
            if (l_pkey_ser_size == l_prev_pkey_ser_size &&
                    !memcmp(l_prev_pkey_ser, l_pkey_ser, l_prev_pkey_ser_size)) {
                l_owner = true;
            }
            // 5b. Call verificator for conditional output
            dap_chain_ledger_verificator_t *l_verificator;
            int l_tmp = (int)l_tx_prev_out_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (!l_verificator || !l_verificator->callback) {
                if(s_debug_more)
                    log_it(L_ERROR, "No verificator set for conditional output subtype %d", l_tmp);
                l_err_num = -13;
                break;
            }
            if (l_verificator->callback(l_tx_prev_out_cond, a_tx, l_owner) == false) {
                l_err_num = -14;
                break;
            }
            bound_item->out.tx_prev_out_cond = l_tx_prev_out_cond;
            // calculate sum of values from previous transactions
            l_value = l_tx_prev_out_cond->header.value;
            l_token = NULL;
        }
        if (!l_token || !*l_token) {
            l_token = l_item_out->cache_data.token_ticker;
        }
        if (! l_token || !*l_token ) {
            log_it(L_WARNING, "No token ticker found in previous transaction");
            l_err_num = -15;
            break;
        }
        // Get permissions
        l_token_item = NULL;
        pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
        HASH_FIND_STR(l_ledger_priv->tokens, l_token, l_token_item);
        pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
        if (! l_token_item){
            if(s_debug_more)
                log_it(L_WARNING, "No token item found for token %s", l_token);
            l_err_num = -15;
            break;
        }
        // Check permissions
        if ( (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED ) ||  // If all is blocked - check if we're
             (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN) ){ // in white list

            if(s_ledger_permissions_check(l_token_item, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD,&l_tx_in_from,
                                          sizeof (l_tx_in_from)) != 0 ){
                char * l_tmp_tx_in_from = dap_chain_addr_to_str(&l_tx_in_from);
                if(s_debug_more)
                    log_it(L_WARNING, "No permission for addr %s", l_tmp_tx_in_from?l_tmp_tx_in_from:"(null)");
                DAP_DELETE(l_tmp_tx_in_from);
                l_err_num = -20;
                break;
            }
        }
        if ((l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED ) || // If all is allowed - check if we're
            (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN ) ){ // in black list
            if(s_ledger_permissions_check(l_token_item, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD ,&l_tx_in_from,
                                          sizeof (l_tx_in_from)) == 0 ){
                char * l_tmp_tx_in_from = dap_chain_addr_to_str(&l_tx_in_from);
                if(s_debug_more)
                    log_it(L_WARNING, "No permission for addr %s", l_tmp_tx_in_from?l_tmp_tx_in_from:"(null)");
                DAP_DELETE(l_tmp_tx_in_from);
                l_err_num = -20;
                break;
            }
        }

        HASH_FIND_STR(l_values_from_prev_tx, l_token, l_value_cur);
        if (!l_value_cur) {
            l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
            strcpy(l_value_cur->token_ticker, l_token);
            HASH_ADD_STR(l_values_from_prev_tx, token_ticker, l_value_cur);
        }
        // calculate sum of values from previous transactions per each token
        l_value_cur->sum += l_value;
        l_list_bound_items = dap_list_append(l_list_bound_items, bound_item);
    }
    if (l_list_in)
        dap_list_free(l_list_in);

    if (l_err_num) {
        DAP_DELETE(bound_item);
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, free);
        HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
            DAP_DELETE(l_value_cur);
        }
        return l_err_num;
    }

    // 6. Compare sum of values in 'out' items in the current transaction and in the previous transactions
    // Calculate the sum of values in 'out' items from the current transaction
    bool l_multichannel = false;
    if (HASH_COUNT(l_values_from_prev_tx) > 1) {
        l_multichannel = true;
    } else {
        l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
        if(l_token)
            strcpy(l_value_cur->token_ticker, l_token);
        HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
    }
    dap_list_t *l_list_tx_out = NULL;
    bool emission_flag = !l_is_first_transaction || (l_is_first_transaction && l_ledger_priv->check_token_emission);
    // find 'out' items
    dap_list_t *l_list_out = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
    uint64_t l_value=0;
    for (l_list_tmp = l_list_out; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp)) {
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
        dap_chain_addr_t l_tx_out_to={0};
        if (l_type == TX_ITEM_TYPE_OUT)
        {
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)l_list_tmp->data;
            if (l_multichannel) { // token ticker is mandatory for multichannel transactions
                l_err_num = -16;
                break;
            }
            if (emission_flag) {
                 l_value = l_tx_out->header.value;
            }
            memcpy(&l_tx_out_to , &l_tx_out->addr, sizeof (l_tx_out_to));
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } else if (l_type == TX_ITEM_TYPE_OUT_EXT) {
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
            if (!l_multichannel) { // token ticker is depricated for single-channel transactions
                l_err_num = -16;
                break;
            }
            if (emission_flag) {
                 l_value = l_tx_out->header.value;
                 l_token = l_tx_out->token;
            }
            memcpy(&l_tx_out_to , &l_tx_out->addr, sizeof (l_tx_out_to));
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } else if (l_type == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t *)l_list_tmp->data;
            if (emission_flag) {
                l_value = l_tx_out->header.value;
            }
            if (l_multichannel) { // out_cond have no field .token
                log_it(L_WARNING, "No conditional output support for multichannel transaction");
                l_err_num = -18;
                break;
            }
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        }
        if (l_multichannel) {
            HASH_FIND_STR(l_values_from_cur_tx, l_token, l_value_cur);
            if (!l_value_cur) {
                l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
                strcpy(l_value_cur->token_ticker, l_token);
                HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
            }
        }
        l_value_cur->sum += l_value;

        // Get permissions for token
        l_token_item = NULL;
        pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
        if(l_ledger_priv->tokens)
            HASH_FIND_STR(l_ledger_priv->tokens,l_token, l_token_item);
        pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
        if (! l_token_item){
            if(s_debug_more)
                log_it(L_WARNING, "No token item found for token %s", l_token);
            l_err_num = -15;
            break;
        }
        // Check permissions

        if ( (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED )||   //  If all is blocked or frozen
             (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN) ){ //  check if we're in white list
            if(s_ledger_permissions_check(l_token_item, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD,&l_tx_out_to ,
                                          sizeof (l_tx_out_to)) != 0 ){
                char * l_tmp_tx_out_to = dap_chain_addr_to_str(&l_tx_out_to);
                if(s_debug_more)
                    log_it(L_WARNING, "No permission for addr %s", l_tmp_tx_out_to?l_tmp_tx_out_to:"(null)");
                DAP_DELETE(l_tmp_tx_out_to);
                l_err_num = -20;
                break;
            }
        }
        if ( (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED )||
             (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN )
             ){ // If all is allowed - check if we're in black list
            if(s_ledger_permissions_check(l_token_item, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD ,&l_tx_out_to,
                                          sizeof (l_tx_out_to)) == 0 ){
                char * l_tmp_tx_out_to = dap_chain_addr_to_str(&l_tx_out_to);
                if(s_debug_more)
                    log_it(L_WARNING, "No permission for addr %s", l_tmp_tx_out_to?l_tmp_tx_out_to:"(null)");
                DAP_DELETE(l_tmp_tx_out_to);
                l_err_num = -20;
                break;
            }
        }
    }


    if ( l_list_out )
        dap_list_free(l_list_out);

    // Additional check whether the transaction is first
    while (l_is_first_transaction && !l_err_num) {
        if (l_ledger_priv->check_token_emission) { // Check the token emission
            dap_chain_datum_token_emission_t * l_token_emission = dap_chain_ledger_token_emission_find(a_ledger, l_token, l_emission_hash);
            if (l_token_emission) {
                if (l_token_emission->hdr.value != l_value_cur->sum) {
                    l_err_num = -10;
                }
                l_value_cur = NULL;
            } else {
                log_it(L_WARNING, "Emission for tx_token wasn't found");
                l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
                break;
            }
        }
        break;
    }
    while (!l_is_first_transaction && !l_err_num) {
        HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
            HASH_FIND_STR(l_values_from_cur_tx, l_value_cur->token_ticker, l_res);
            if (!l_res || l_res->sum != l_value_cur->sum) {
                if(s_debug_more)
                    log_it(L_ERROR, "Sum of values in out items of current tx (%"DAP_UINT64_FORMAT_U") is not equal outs from previous tx (%"DAP_UINT64_FORMAT_U") for token %s",
                       l_res ? l_res->sum : 0, l_value_cur->sum, l_value_cur->token_ticker);
                l_err_num = -12;
                break;
            }
        }
        break;
    }

    HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
        DAP_DELETE(l_value_cur);
    }
    HASH_ITER(hh, l_values_from_cur_tx, l_value_cur, l_tmp) {
        DAP_DELETE(l_value_cur);
    }
    if (!a_list_bound_items || l_err_num) {
        dap_list_free_full(l_list_bound_items, free);
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
 * @brief dap_chain_ledger_tx_check
 * @param a_ledger
 * @param a_tx
 * @return
 */
int dap_chain_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx)
{
    if(!a_tx)
        return -2;
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;

    int l_ret_check;
    if( (l_ret_check = dap_chain_ledger_tx_cache_check(
             a_ledger, a_tx, &l_list_bound_items, &l_list_tx_out)) < 0){
        if(s_debug_more)
            log_it (L_DEBUG, "dap_chain_ledger_tx_add_check() tx not passed the check: code %d ",l_ret_check);
        return l_ret_check;
    }
    dap_chain_hash_fast_t *l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    char l_tx_hash_str[70];
    dap_chain_hash_fast_to_str(l_tx_hash,l_tx_hash_str,sizeof(l_tx_hash_str));
    if(s_debug_more)
        log_it ( L_INFO, "dap_chain_ledger_tx_add_check() check passed for tx %s",l_tx_hash_str);
    return 0;
}

static int s_balance_cache_update(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_balance)
{
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
    uint128_t *l_balance_value = DAP_NEW_Z(uint128_t);
    *l_balance_value = a_balance->balance;
    if (!dap_chain_global_db_gr_set(dap_strdup(a_balance->key), l_balance_value, sizeof(uint128_t), l_gdb_group)) {
        if(s_debug_more)
            log_it(L_WARNING, "Ledger cache mismatch");
        DAP_DELETE(l_balance_value);
        return -1;
    }
    DAP_DELETE(l_gdb_group);
    return 0;
}

static int s_tx_cache_update(dap_ledger_t *a_ledger, dap_chain_ledger_tx_item_t *a_item)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_item->tx);
    uint8_t *l_tx_cache = DAP_NEW_Z_SIZE(uint8_t, l_tx_size + sizeof(a_item->cache_data));
    memcpy(l_tx_cache, &a_item->cache_data, sizeof(a_item->cache_data));
    memcpy(l_tx_cache + sizeof(a_item->cache_data), a_item->tx, l_tx_size);
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&a_item->tx_hash_fast);
    if (!dap_chain_global_db_gr_set(l_tx_hash_str, l_tx_cache, l_tx_size + sizeof(a_item->cache_data), l_gdb_group)) {
        if(s_debug_more)
            log_it(L_WARNING, "Ledger cache mismatch");
        DAP_DELETE(l_tx_cache);
        return -1;
    }
    DAP_DELETE(l_gdb_group);
    return 0;
}

/**
 * Add new transaction to the cache list
 *
 * return 1 OK, -1 error
 */
int dap_chain_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold)
{
    if(!a_tx){
        if(s_debug_more)
            log_it(L_ERROR, "NULL tx detected");
        return -1;
    }
    int ret = 1;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;
    dap_chain_ledger_tx_item_t *l_item_tmp = NULL;
    if (!l_ledger_priv->tps_timer) {
        clock_gettime(CLOCK_REALTIME, &l_ledger_priv->tps_start_time);
        l_ledger_priv->tps_current_time.tv_sec = l_ledger_priv->tps_start_time.tv_sec;
        l_ledger_priv->tps_current_time.tv_nsec = l_ledger_priv->tps_start_time.tv_nsec;
        l_ledger_priv->tps_count = 0;
        l_ledger_priv->tps_timer = dap_timerfd_start(500, s_ledger_tps_callback, l_ledger_priv);
    }
    bool l_from_threshold = a_from_threshold;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp);
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    char l_tx_hash_str[70];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
    if (l_item_tmp) {     // transaction already present in the cache list
        if(s_debug_more)
            log_it(L_WARNING, "Transaction %s already present in the cache", l_tx_hash_str);
        return -1;
    }
    int l_ret_check;
    l_item_tmp = NULL;
    if( (l_ret_check = dap_chain_ledger_tx_cache_check(
             a_ledger, a_tx, &l_list_bound_items, &l_list_tx_out)) < 0) {
        if (l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS) {
            if (!l_from_threshold) {
                pthread_rwlock_rdlock(&l_ledger_priv->treshold_txs_rwlock);
                HASH_FIND(hh, l_ledger_priv->treshold_txs, a_tx_hash, sizeof(*a_tx_hash), l_item_tmp);
                unsigned long long l_threshold_txs_count = HASH_COUNT(l_ledger_priv->treshold_txs);
                if (!l_item_tmp) {
                    if (l_threshold_txs_count >= s_treshold_txs_max) {
                        if(s_debug_more)
                            log_it(L_WARNING,"Treshold for tranactions is overfulled (%zu max), dropping down new data, added nothing",
                                       s_treshold_txs_max);
                    } else {
                        l_item_tmp = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
                        memcpy(&l_item_tmp->tx_hash_fast, a_tx_hash, sizeof(dap_chain_hash_fast_t));
                        size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
                        l_item_tmp->tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, l_tx_size);
                        memcpy(l_item_tmp->tx, a_tx, l_tx_size);
                        HASH_ADD(hh, l_ledger_priv->treshold_txs, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_item_tmp);
                        if(s_debug_more)
                            log_it (L_DEBUG, "Tx %s added to threshold", l_tx_hash_str);
                    }
                }
                pthread_rwlock_unlock(&l_ledger_priv->treshold_txs_rwlock);
            }
        } else {
            if(s_debug_more)
                log_it (L_WARNING, "dap_chain_ledger_tx_add() tx %s not passed the check: code %d ",l_tx_hash_str, l_ret_check);
        }
        return l_ret_check;
    }
    if(s_debug_more)
        log_it ( L_DEBUG, "dap_chain_ledger_tx_add() check passed for tx %s",l_tx_hash_str);

    char l_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX]      = { '\0'},
         l_token_ticker_old[DAP_CHAIN_TICKER_SIZE_MAX]  = { '\0'};

    //char *l_token_ticker = NULL, *l_token_ticker_old = NULL;
    bool l_multichannel = false;
    // Mark 'out' items in cache if they were used & delete previous transactions from cache if it need
    // find all bound pairs 'in' and 'out'
    dap_list_t *l_list_tmp = l_list_bound_items;
    char *l_ticker_trl = NULL, *l_ticker_old_trl = NULL;
    bool l_stake_updated = false;
    // Update balance: deducts
    while(l_list_tmp) {
        dap_chain_ledger_tx_bound_t *bound_item = l_list_tmp->data;
        void *l_item_in = *(void **)&bound_item->in;
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_item_in;
        dap_chain_ledger_tx_item_t *l_prev_item_out = bound_item->item_out;
        l_ticker_trl = *l_prev_item_out->cache_data.token_ticker
                ? dap_stpcpy(l_token_ticker, l_prev_item_out->cache_data.token_ticker)
                : dap_stpcpy(l_token_ticker, bound_item->out.tx_prev_out_ext->token);
        if (!l_multichannel && l_ticker_old_trl && strcmp(l_token_ticker, l_token_ticker_old)) {
            l_multichannel = true;
        }
        l_ticker_old_trl = dap_stpcpy(l_token_ticker_old, l_token_ticker);
        int l_tx_prev_out_used_idx;
        if (l_type == TX_ITEM_TYPE_IN) {
            dap_chain_tx_in_t *l_tx_in = bound_item->in.tx_cur_in;
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            void *l_item_out = *(void **)&bound_item->out;
            dap_chain_tx_item_type_t l_out_type = *(uint8_t *)l_item_out;
            dap_chain_addr_t *l_addr = (l_out_type == TX_ITEM_TYPE_OUT) ?
                                        &bound_item->out.tx_prev_out->addr :
                                        &bound_item->out.tx_prev_out_ext->addr;
            char *l_addr_str = dap_chain_addr_to_str(l_addr);
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_token_ticker, (char*)NULL);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            if (wallet_balance) {
                uint64_t l_value = (l_out_type == TX_ITEM_TYPE_OUT) ?
                                    bound_item->out.tx_prev_out->header.value :
                                    bound_item->out.tx_prev_out_ext->header.value;
                if(s_debug_more)
                    log_it(L_DEBUG,"SPEND %"DAP_UINT64_FORMAT_U" from addr: %s", l_value, l_wallet_balance_key);
                uint128_t l_sub = dap_chain_uint128_from(l_value);
                wallet_balance->balance = dap_uint128_substract(wallet_balance->balance, l_sub);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                if(s_debug_more)
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_token_ticker);
            }
            DAP_DELETE(l_addr_str);
            DAP_DELETE(l_wallet_balance_key);
            /// Mark 'out' item in cache because it used
            l_tx_prev_out_used_idx = l_tx_in->header.tx_out_prev_idx;
        } else { // TX_ITEM_TYPE_IN_COND
            // all balance deducts performed with previous conditional transaction
            dap_chain_tx_in_cond_t *l_tx_in_cond = bound_item->in.tx_cur_in_cond;
            /// Mark 'out' item in cache because it used
            l_tx_prev_out_used_idx = l_tx_in_cond->header.tx_out_prev_idx;
            // Update stakes if any
            dap_chain_tx_out_cond_t *l_cond = bound_item->out.tx_prev_out_cond;
            if (l_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE) {
                dap_chain_ledger_verificator_t *l_verificator;
                int l_tmp = (int)DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_UPDATE;
                pthread_rwlock_rdlock(&s_verificators_rwlock);
                HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
                pthread_rwlock_unlock(&s_verificators_rwlock);
                if (l_verificator && l_verificator->callback) {
                    l_verificator->callback(l_cond, a_tx, true);
                }
                l_stake_updated = true;
            }
        }
        // add a used output
        memcpy(&(l_prev_item_out->cache_data.tx_hash_spent_fast[l_tx_prev_out_used_idx]), a_tx_hash, sizeof(dap_chain_hash_fast_t));
        l_prev_item_out->cache_data.n_outs_used++;
        // mirror it in the cache
        s_tx_cache_update(a_ledger, l_prev_item_out);

        // delete previous transactions from cache because all out is used
        if(l_prev_item_out->cache_data.n_outs_used == l_prev_item_out->cache_data.n_outs) {
            dap_chain_hash_fast_t l_tx_prev_hash_to_del = bound_item->tx_prev_hash_fast;
            // remove from memory ledger
            int res = dap_chain_ledger_tx_remove(a_ledger, &l_tx_prev_hash_to_del);
            if(res == -2) {
                if(s_debug_more) {
                    char * l_tx_prev_hash_str = dap_chain_hash_fast_to_str_new(&l_tx_prev_hash_to_del);
                    log_it(L_ERROR, "Can't delete previous transactions because hash=%s not found", l_tx_prev_hash_str);
                    DAP_DELETE(l_tx_prev_hash_str);
                }
                dap_list_free_full(l_list_bound_items, free);
                return -100;
            }
            else if(res != 1) {
                if(s_debug_more) {
                    char * l_tx_prev_hash_str = dap_chain_hash_fast_to_str_new(&l_tx_prev_hash_to_del);
                    log_it(L_ERROR, "Can't delete previous transactions with hash=%s", l_tx_prev_hash_str);
                    DAP_DELETE(l_tx_prev_hash_str);
                }
                dap_list_free_full(l_list_bound_items, free);
                return -101;
            }
        }
        // go to next previous transaction
        l_list_tmp = dap_list_next(l_list_tmp);
    }
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, free);

    // Try to find token ticker if wasn't
    if (!l_ticker_trl){
        //int l_base_tx_count = 0;
        //dap_list_t *l_base_tx_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_TOKEN, &l_base_tx_count );
        //if (l_base_tx_count >=1  && l_base_tx_list){
        dap_chain_tx_token_t * l_tx_token = (dap_chain_tx_token_t *) dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL);
        if (l_tx_token)
            l_ticker_trl = dap_stpcpy(l_token_ticker, l_tx_token->header.ticker);
        //}
    }

    //Update balance : raise
    for (dap_list_t *l_tx_out = l_list_tx_out; l_tx_out; l_tx_out = dap_list_next(l_tx_out)) {
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_out->data;
        if (l_type == TX_ITEM_TYPE_OUT_COND) {
            // Update stakes if any
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_tx_out->data;
            if (l_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE && !l_stake_updated) {
                dap_chain_ledger_verificator_t *l_verificator;
                int l_tmp = (int)DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_UPDATE;
                pthread_rwlock_rdlock(&s_verificators_rwlock);
                HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
                pthread_rwlock_unlock(&s_verificators_rwlock);
                if (l_verificator && l_verificator->callback) {
                    l_verificator->callback(NULL, a_tx, true);
                }
            }
            continue;   // balance raise will be with next conditional transaction
        }
        dap_chain_tx_out_t *l_out_item = NULL;
        dap_chain_tx_out_ext_t *l_out_item_ext = NULL;
        if (l_type == TX_ITEM_TYPE_OUT) {
            l_out_item = (dap_chain_tx_out_t *)l_tx_out->data;
        } else {
            l_out_item_ext = (dap_chain_tx_out_ext_t *)l_tx_out->data;
        }
        if ((l_out_item  || l_out_item_ext) && l_ticker_trl) {
             dap_chain_addr_t *l_addr = (l_type == TX_ITEM_TYPE_OUT) ?
                                        &l_out_item->addr :
                                        &l_out_item_ext->addr;
            char *l_addr_str = dap_chain_addr_to_str(l_addr);

            //log_it (L_DEBUG, "Check unspent %.03Lf %s for addr %s",
            //        (long double) l_out_item->header.value/ 1000000000000.0L,
            //        l_token_ticker, l_addr_str);
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            if (l_multichannel) {
                l_ticker_trl = dap_stpcpy(l_token_ticker, l_out_item_ext->token);
            }
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_token_ticker, (char*)NULL);
            uint64_t l_value =  (l_type == TX_ITEM_TYPE_OUT) ? l_out_item->header.value : l_out_item_ext->header.value;

            if(s_debug_more)
                log_it (L_DEBUG,"GOT %"DAP_UINT64_FORMAT_U" to addr: %s", l_value, l_wallet_balance_key);
            pthread_rwlock_rdlock(&l_ledger_priv->balance_accounts_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            pthread_rwlock_unlock(&l_ledger_priv->balance_accounts_rwlock);
            if (wallet_balance) {
                if(s_debug_more)
                    log_it(L_DEBUG, "Balance item is present in cache");
                uint128_t l_add = dap_chain_uint128_from(l_value);
                wallet_balance->balance = dap_uint128_add(wallet_balance->balance, l_add);
                DAP_DELETE (l_wallet_balance_key);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                wallet_balance = DAP_NEW_Z(dap_ledger_wallet_balance_t);
                wallet_balance->key = l_wallet_balance_key;
                strcpy(wallet_balance->token_ticker, l_token_ticker);
                uint128_t l_add = dap_chain_uint128_from(l_value);
                wallet_balance->balance = dap_uint128_add(wallet_balance->balance, l_add);
                if(s_debug_more)
                    log_it(L_DEBUG,"!!! Create new balance item: %s %s", l_addr_str, l_token_ticker);
                pthread_rwlock_wrlock(&l_ledger_priv->balance_accounts_rwlock);
                HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, wallet_balance->key,
                                strlen(l_wallet_balance_key), wallet_balance);
                pthread_rwlock_unlock(&l_ledger_priv->balance_accounts_rwlock);
                // Add it to cache
                s_balance_cache_update(a_ledger, wallet_balance);
            }
            DAP_DELETE (l_addr_str);
        } else {
            if(s_debug_more)
                log_it(L_WARNING, "Can't detect tx ticker or matching output, can't append balances cache");
        }
    }

    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);

    // add transaction to the cache list
    if(ret == 1){
        l_item_tmp = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
        memcpy(&l_item_tmp->tx_hash_fast, a_tx_hash, sizeof(dap_chain_hash_fast_t));
        l_item_tmp->tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, dap_chain_datum_tx_get_size(a_tx));
        l_item_tmp->cache_data.ts_created = time(NULL); // Time of transasction added to ledger
        dap_list_t *l_tist_tmp = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, &l_item_tmp->cache_data.n_outs);
        // If debug mode dump the UTXO
        if (dap_log_level_get() == L_DEBUG && s_debug_more) {
            for (size_t i =0; i < (size_t) l_item_tmp->cache_data.n_outs; i++){
                dap_chain_tx_out_t * l_tx_out = l_tist_tmp->data;
                char * l_tx_out_addr_str = dap_chain_addr_to_str( &l_tx_out->addr );
                log_it(L_DEBUG,"Added tx out to %s",l_tx_out_addr_str );
                DAP_DELETE (l_tx_out_addr_str);
            }
        }
        if(l_tist_tmp)
            dap_list_free(l_tist_tmp);
        if (!l_ticker_trl) { //No token ticker in previous txs
            if(s_debug_more)
                log_it(L_DEBUG, "No token ticker in previous txs");
            //int l_tokens_count = 0;
            //dap_list_t *l_tokens_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_TOKEN, &l_tokens_count );
            //if ( l_tokens_count>0 ){
                //dap_chain_tx_token_t * l_token = (dap_chain_tx_token_t*) l_tokens_list->data;
            dap_chain_tx_token_t *l_token = (dap_chain_tx_token_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL);
            l_ticker_trl = l_token
                    ? dap_stpcpy(l_token_ticker, l_token->header.ticker)
                    : NULL;
                //dap_list_free(l_tokens_list);
            //}
        }
        if (l_ticker_trl && !l_multichannel)
            dap_stpcpy(l_item_tmp->cache_data.token_ticker, l_token_ticker);

        size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
        memcpy(l_item_tmp->tx, a_tx, l_tx_size);
        pthread_rwlock_wrlock(&l_ledger_priv->ledger_rwlock);
        HASH_ADD(hh, l_ledger_priv->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash_fast: name of key field
        pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
        // Count TPS
        clock_gettime(CLOCK_REALTIME, &l_ledger_priv->tps_end_time);
        l_ledger_priv->tps_count++;
        // Add it to cache
        uint8_t *l_tx_cache = DAP_NEW_Z_SIZE(uint8_t, l_tx_size + sizeof(l_item_tmp->cache_data));
        memcpy(l_tx_cache, &l_item_tmp->cache_data, sizeof(l_item_tmp->cache_data));
        memcpy(l_tx_cache + sizeof(l_item_tmp->cache_data), a_tx, l_tx_size);
        char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
        if (!dap_chain_global_db_gr_set(dap_strdup(l_tx_hash_str), l_tx_cache, l_tx_size + sizeof(l_item_tmp->cache_data), l_gdb_group)) {
            if(s_debug_more)
                log_it(L_WARNING, "Ledger cache mismatch");
            DAP_DELETE(l_tx_cache);
        }
        DAP_DELETE(l_gdb_group);
        if (!l_from_threshold)
            s_treshold_txs_proc(a_ledger);
        ret = 1;
    }
    return ret;
}

static bool s_ledger_tps_callback(void *a_arg)
{
    dap_ledger_private_t *l_ledger_pvt = (dap_ledger_private_t *)a_arg;
    if (l_ledger_pvt->tps_current_time.tv_sec != l_ledger_pvt->tps_end_time.tv_sec ||
            l_ledger_pvt->tps_current_time.tv_nsec != l_ledger_pvt->tps_end_time.tv_nsec) {
        l_ledger_pvt->tps_current_time.tv_sec = l_ledger_pvt->tps_end_time.tv_sec;
        l_ledger_pvt->tps_current_time.tv_nsec = l_ledger_pvt->tps_end_time.tv_nsec;
        return true;
    }
    l_ledger_pvt->tps_timer = NULL;
    return false;
}

int dap_chain_ledger_tx_load(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash)
{
    dap_chain_hash_fast_t l_tx_hash;
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);
    if (a_tx_hash)
        memcpy(a_tx_hash, &l_tx_hash, sizeof(l_tx_hash));
    if (!PVT(a_ledger)->load_mode) {
        return dap_chain_ledger_tx_add(a_ledger, a_tx, &l_tx_hash, false);
    } else {
        dap_chain_ledger_tx_item_t *l_tx_item;
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND(hh, PVT(a_ledger)->ledger_items, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
        if (l_tx_item) {
            pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
            return 1;
        }
        HASH_FIND(hh, PVT(a_ledger)->treshold_txs, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
        if (l_tx_item) {
            pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
            return DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
        }
        dap_chain_ledger_tx_spent_item_t *l_tx_spent_item;
        HASH_FIND(hh, PVT(a_ledger)->spent_items, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_spent_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (l_tx_spent_item)
            return 1;
    }
    return dap_chain_ledger_tx_add(a_ledger, a_tx, &l_tx_hash, false);
}

/**
 * Delete transaction from the cache
 *
 * return 1 OK, -1 error, -2 tx_hash not found
 */
int dap_chain_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash)
{
    if(!a_tx_hash)
        return -1;
    int l_ret = -1;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp);
    if(l_item_tmp != NULL) {
        HASH_DEL(l_ledger_priv->ledger_items, l_item_tmp);
        // Remove it from cache
        char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
        dap_chain_global_db_gr_del(dap_chain_hash_fast_to_str_new(a_tx_hash), l_gdb_group);
        DAP_DELETE(l_gdb_group);
        l_ret = 1;
        dap_chain_ledger_tx_spent_item_t *l_item_used;
        HASH_FIND(hh, l_ledger_priv->spent_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_used);
        if (!l_item_used) {   // Add it to spent items
            l_item_used = DAP_NEW_Z(dap_chain_ledger_tx_spent_item_t);
            memcpy(&l_item_used->tx_hash_fast, a_tx_hash, sizeof(dap_chain_hash_fast_t));
            strncpy(l_item_used->token_ticker, l_item_tmp->cache_data.token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
            HASH_ADD(hh, l_ledger_priv->spent_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_item_used);
            // Add it to cache
            char *l_cache_data = DAP_NEW_Z_SIZE(char, DAP_CHAIN_TICKER_SIZE_MAX);
            strncpy(l_cache_data, l_item_used->token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
            l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
            char *l_tx_hash_str = dap_hash_fast_to_str_new(a_tx_hash);
            if (!dap_chain_global_db_gr_set(l_tx_hash_str, l_cache_data, -1, l_gdb_group)) {
                if(s_debug_more)
                    log_it(L_WARNING, "Ledger cache mismatch");
                DAP_DELETE(l_cache_data);
            }
            DAP_DELETE(l_gdb_group);
        }
        // del struct for hash
        DAP_DELETE(l_item_tmp);
    }
    else
        // hash not found in the cache
        l_ret = -2;
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_ret;
}

/**
 * Delete all transactions from the cache
 */
void dap_chain_ledger_purge(dap_ledger_t *a_ledger, bool a_preserve_db)
{
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_priv->ledger_rwlock);
    pthread_rwlock_wrlock(&l_ledger_priv->tokens_rwlock);
    pthread_rwlock_wrlock(&l_ledger_priv->treshold_emissions_rwlock);
    pthread_rwlock_wrlock(&l_ledger_priv->treshold_txs_rwlock);
    pthread_rwlock_wrlock(&l_ledger_priv->balance_accounts_rwlock);

    // delete transactions
    dap_chain_ledger_tx_item_t *l_item_current, *l_item_tmp;
    char *l_gdb_group;
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_priv->ledger_items, l_item_current);
        DAP_DELETE(l_item_current->tx);
        DAP_DELETE(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    // delete spent transactions
    dap_chain_ledger_tx_spent_item_t *l_spent_item_current, *l_spent_item_tmp;
    HASH_ITER(hh, l_ledger_priv->spent_items, l_spent_item_current, l_spent_item_tmp) {
        HASH_DEL(l_ledger_priv->spent_items, l_spent_item_current);
        DAP_DELETE(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    // delete balances
    dap_ledger_wallet_balance_t *l_balance_current, *l_balance_tmp;
    HASH_ITER(hh, l_ledger_priv->balance_accounts, l_balance_current, l_balance_tmp) {
        HASH_DEL(l_ledger_priv->balance_accounts, l_balance_current);
        DAP_DELETE(l_balance_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    // delete tokens & its emissions
    dap_chain_ledger_token_item_t *l_token_current, *l_token_tmp;
    dap_chain_ledger_token_emission_item_t *l_emission_current, *l_emission_tmp;
    HASH_ITER(hh, l_ledger_priv->tokens, l_token_current, l_token_tmp) {
        HASH_DEL(l_ledger_priv->tokens, l_token_current);
        pthread_rwlock_wrlock(&l_token_current->token_emissions_rwlock);
        HASH_ITER(hh, l_token_current->token_emissions, l_emission_current, l_emission_tmp) {
            HASH_DEL(l_token_current->token_emissions, l_emission_current);
            DAP_DELETE(l_emission_current->datum_token_emission);
            DAP_DELETE(l_emission_current);
        }
        pthread_rwlock_unlock(&l_token_current->token_emissions_rwlock);
        DAP_DELETE(l_token_current->datum_token);
        pthread_rwlock_destroy(&l_token_current->token_emissions_rwlock);
        DAP_DELETE(l_token_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TOKENS_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    // delete threshold emissions
    HASH_ITER(hh, l_ledger_priv->treshold_emissions, l_emission_current, l_emission_tmp) {
        HASH_DEL(l_ledger_priv->treshold_emissions, l_emission_current);
        DAP_DELETE(l_emission_current->datum_token_emission);
        DAP_DELETE(l_emission_current);
    }
    // delete threshold transactions
    HASH_ITER(hh, l_ledger_priv->treshold_txs, l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_priv->treshold_txs, l_item_current);
        DAP_DELETE(l_item_current->tx);
        DAP_DELETE(l_item_current);
    }

    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->treshold_emissions_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->treshold_txs_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->balance_accounts_rwlock);
}

/**
 * Return number transactions from the cache
 * According to UT_hash_handle size of return value is sizeof(unsigned int)
 */
unsigned dap_chain_ledger_count(dap_ledger_t *a_ledger)
{
    pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
    unsigned long ret = HASH_COUNT(PVT(a_ledger)->ledger_items);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    return ret;
}

/**
 * @brief dap_chain_ledger_count_from_to
 * @param a_ledger
 * @param a_ts_from
 * @param a_ts_to
 * @return
 */
uint64_t dap_chain_ledger_count_from_to(dap_ledger_t * a_ledger, time_t a_ts_from, time_t a_ts_to )
{
    uint64_t l_ret = 0;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    if ( a_ts_from && a_ts_to) {
        HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->cache_data.ts_created >= a_ts_from && l_iter_current->cache_data.ts_created <= a_ts_to )
            l_ret++;
        }
    } else if ( a_ts_to ){
        HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->cache_data.ts_created <= a_ts_to )
            l_ret++;
        }
    } else if ( a_ts_from ){
        HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->cache_data.ts_created >= a_ts_from )
            l_ret++;
        }
    }else {
        HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp){
            l_ret++;
        }
    }

    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_ret;
}

size_t dap_chain_ledger_count_tps(dap_ledger_t *a_ledger, struct timespec *a_ts_from, struct timespec *a_ts_to)
{
    if (!a_ledger)
        return 0;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    if (a_ts_from) {
        a_ts_from->tv_sec = l_ledger_priv->tps_start_time.tv_sec;
        a_ts_from->tv_nsec = l_ledger_priv->tps_start_time.tv_nsec;
    }
    if (a_ts_to) {
        a_ts_to->tv_sec = l_ledger_priv->tps_end_time.tv_sec;
        a_ts_to->tv_nsec = l_ledger_priv->tps_end_time.tv_nsec;
    }
    return l_ledger_priv->tps_count;
}

/**
 * Check whether used 'out' items
 */
bool dap_chain_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out)
{
    dap_chain_ledger_tx_item_t *l_item_out = NULL;
    //dap_chain_datum_tx_t *l_tx =
    s_find_datum_tx_by_hash(a_ledger, a_tx_hash, &l_item_out);
    return dap_chain_ledger_item_is_used_out(l_item_out, a_idx_out);
}

/**
 * Calculate balance of addr
 *
 */
uint128_t dap_chain_ledger_calc_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                        const char *a_token_ticker)
{
#ifdef DAP_GLOBAL_IS_INT128
    uint128_t l_ret = 0;
#else
    uint128_t l_ret = {};
#endif
    dap_ledger_wallet_balance_t *l_balance_item = NULL;// ,* l_balance_item_tmp = NULL;
    char *l_addr = dap_chain_addr_to_str(a_addr);
    char *l_wallet_balance_key = dap_strjoin(" ", l_addr, a_token_ticker, (char*)NULL);
    pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, l_balance_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
    if (l_balance_item) {
        if(s_debug_more)
            log_it (L_INFO,"Found address in cache with balance %s",
                            dap_chain_balance_print(l_balance_item->balance));
        l_ret = l_balance_item->balance;
    } else {
        if (s_debug_more)
            log_it (L_WARNING, "Balance item %s not found", l_wallet_balance_key);
    }
    DAP_DELETE(l_addr);
    DAP_DELETE(l_wallet_balance_key);
    return l_ret;
}

uint128_t dap_chain_ledger_calc_balance_full(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                             const char *a_token_ticker)
{
#ifdef DAP_GLOBAL_IS_INT128
    uint128_t balance = 0;
#else
    uint128_t balance = {0};
#endif
    if(!a_addr || !dap_chain_addr_check_sum(a_addr))
        return balance;
    /* proto
     *
    dap_ledger_wallet_balance_t *wallet_balance = NULL;
    HASH_FIND(hh, balance_accounts, a_addr, sizeof(*a_addr), wallet_balance);
    if (wallet_balance) {
        balance = wallet_balance->balance;
    }

    */
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_cur_tx = l_iter_current->tx;

        //        dap_chain_hash_fast_t *l_cur_tx_hash = &l_iter_current->tx_hash_fast;
        //        int l_n_outs_used = l_iter_current->n_outs_used; // number of used 'out' items

        // Get 'out' items from transaction
        int l_out_item_count = 0;
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_cur_tx, TX_ITEM_TYPE_OUT_ALL, &l_out_item_count);
        if(l_out_item_count >= MAX_OUT_ITEMS) {
            if(s_debug_more)
                log_it(L_ERROR, "Too many 'out' items=%d in transaction (max=%d)", l_out_item_count, MAX_OUT_ITEMS);
            if (l_out_item_count >= MAX_OUT_ITEMS){
                uint128_t l_ret;
                memset(&l_ret,0,sizeof(l_ret));
                return l_ret;
            }
        }
        int l_out_idx_tmp = 0;
        for (dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_out_idx_tmp++) {
            assert(l_list_tmp->data);
            dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
            if (l_type == TX_ITEM_TYPE_OUT_COND) {
                continue;
            }
            if (l_type == TX_ITEM_TYPE_OUT) {
                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
                // Check for token name
                if (!strcmp(a_token_ticker, l_iter_current->cache_data.token_ticker))
                {   // if transaction has the out item with requested addr
                    if (!memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                        // if 'out' item not used & transaction is valid
                        if(!dap_chain_ledger_item_is_used_out(l_iter_current, l_out_idx_tmp) &&
                                dap_chain_datum_tx_verify_sign(l_cur_tx)) {

                            uint128_t l_add = dap_chain_uint128_from(l_tx_out->header.value);
                            balance = dap_uint128_add(balance, l_add);
                        }
                    }
                }
            }
            if (l_type == TX_ITEM_TYPE_OUT_EXT) {
                const dap_chain_tx_out_ext_t *l_tx_out = (const dap_chain_tx_out_ext_t*) l_list_tmp->data;
                // Check for token name
                if (!strcmp(a_token_ticker, l_tx_out->token))
                {   // if transaction has the out item with requested addr
                    if (!memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                        // if 'out' item not used & transaction is valid
                        if(!dap_chain_ledger_item_is_used_out(l_iter_current, l_out_idx_tmp) &&
                                dap_chain_datum_tx_verify_sign(l_cur_tx)) {
                            uint128_t l_add = dap_chain_uint128_from(l_tx_out->header.value);
                            balance = dap_uint128_add(balance, l_add);
                        }
                    }
                }
            }
        }
        dap_list_free(l_list_out_items);
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return balance;
}

/**
 * Get the transaction in the cache by the addr in out item
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 * a_tx_first_hash [in/out] hash of the initial transaction/ found transaction, if 0 start from the beginning
 */
static dap_chain_ledger_tx_item_t* tx_item_find_by_addr(dap_ledger_t *a_ledger,
        const dap_chain_addr_t *a_addr,const char * a_token, dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_addr || !a_tx_first_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    bool is_tx_found = false;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp)
    {
        // If a_token is setup we check if its not our token - miss it
        if (a_token && *l_iter_current->cache_data.token_ticker &&
                dap_strcmp(l_iter_current->cache_data.token_ticker, a_token))
            continue;
        // Now work with it
        dap_chain_datum_tx_t *l_tx = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get 'out' items from transaction
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
        for(dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp)) {
            assert(l_list_tmp->data);
            dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
            if (l_type == TX_ITEM_TYPE_OUT_COND) {
                continue;
            }
            if (l_type == TX_ITEM_TYPE_OUT) {
                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t *)l_list_tmp->data;
                // if transaction has the out item with requested addr
                if(!memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                    memcpy(a_tx_first_hash, l_tx_hash, sizeof(dap_chain_hash_fast_t));
                    is_tx_found = true;
                    break;
                }
            }
            if (l_type == TX_ITEM_TYPE_OUT_EXT) {
                const dap_chain_tx_out_ext_t *l_tx_out_ext = (const dap_chain_tx_out_ext_t *)l_list_tmp->data;
                // If a_token is setup we check if its not our token - miss it
                if (a_token && dap_strcmp(l_tx_out_ext->token, a_token)) {
                    continue;
                }                // if transaction has the out item with requested addr
                if(!memcmp(a_addr, &l_tx_out_ext->addr, sizeof(dap_chain_addr_t))) {
                    memcpy(a_tx_first_hash, l_tx_hash, sizeof(dap_chain_hash_fast_t));
                    is_tx_found = true;
                    break;
                }
            }
        }
        dap_list_free(l_list_out_items);
        // already found transaction
        if(is_tx_found)
            break;

    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    if(is_tx_found)
        return l_iter_current;
    else
        return NULL;
}

/**
 * @brief dap_chain_ledger_tx_find_by_addr
 * @param a_addr
 * @param a_tx_first_hash
 * @return
 */
 dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_addr(dap_ledger_t *a_ledger , const char * a_token ,
         const dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash)
{
    dap_chain_ledger_tx_item_t* l_tx_item = tx_item_find_by_addr(a_ledger, a_addr, a_token, a_tx_first_hash);
    return (l_tx_item) ? l_tx_item->tx : NULL;
}



/**
 * Get the transaction in the cache by the public key that signed the transaction,
 * starting from the next hash after a_tx_first_hash
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 * a_tx_first_hash [in/out] hash of the initial transaction/ found transaction, if 0 start from the beginning
 */
const dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_pkey(dap_ledger_t *a_ledger,
        char *a_public_key, size_t a_public_key_size, dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_public_key || !a_tx_first_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp)
    {
        pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);

        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash_tmp, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get sign item from transaction
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(l_tx_tmp, NULL,
                TX_ITEM_TYPE_SIG, NULL);
        // Get dap_sign_t from item
        dap_sign_t *l_sig = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
        if(l_sig) {
            // compare public key in transaction with a_public_key
            if(a_public_key_size == l_sig->header.sign_pkey_size &&
                    !memcmp(a_public_key, l_sig->pkey_n_sign, a_public_key_size)) {
                l_cur_tx = l_tx_tmp;
                memcpy(a_tx_first_hash, l_tx_hash_tmp, sizeof(dap_chain_hash_fast_t));
                break;
            }
        }
        pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_cur_tx;
}

/**
 * Get the transaction in the cache with the out_cond item
 *
 * a_addr[in] wallet address, whose owner can use the service
 */
dap_chain_datum_tx_t* dap_chain_ledger_tx_cache_find_out_cond(dap_ledger_t *a_ledger,
        dap_chain_hash_fast_t *a_tx_first_hash, dap_chain_tx_out_cond_t **a_out_cond, int *a_out_cond_idx, char *a_token_ticker)
{
    if (!a_tx_first_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current = NULL, *l_item_tmp = NULL;
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    int l_tx_out_cond_idx;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items, l_iter_current, l_item_tmp)
    {
        pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash_tmp, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get out_cond item from transaction
        l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_tmp, &l_tx_out_cond_idx);

        if(l_tx_out_cond) {
            l_cur_tx = l_tx_tmp;
            memcpy(a_tx_first_hash, l_tx_hash_tmp, sizeof(dap_chain_hash_fast_t));
            if (a_token_ticker) {
                strcpy(a_token_ticker, l_iter_current->cache_data.token_ticker);
            }
            break;
        }
        pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    if (a_out_cond) {
        *a_out_cond = l_tx_out_cond;
    }
    if (a_out_cond_idx) {
        *a_out_cond_idx = l_tx_out_cond_idx;
    }
    return l_cur_tx;
}

/**
 * Get the value from all transactions in the cache with out_cond item
 *
 * a_addr[in] wallet address, whose owner can use the service
 * a_sign [in] signature of a_addr hash for check valid key
 * a_sign_size [in] signature size
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 */
uint64_t dap_chain_ledger_tx_cache_get_out_cond_value(dap_ledger_t *a_ledger, dap_chain_addr_t *a_addr,
        dap_chain_tx_out_cond_t **tx_out_cond)
{
    uint64_t l_ret_value = 0;

    dap_chain_datum_tx_t *l_tx_tmp;
    dap_chain_hash_fast_t l_tx_first_hash = { 0 }; // start hash
    //memcpy(&l_tx_first_hash, 0, sizeof(dap_chain_hash_fast_t));
    /* size_t l_pub_key_size = a_key_from->pub_key_data_size;
     uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_key_from, &l_pub_key_size);*/
    dap_chain_tx_out_cond_t *l_tx_out_cond;
    // Find all transactions
    do {

        l_tx_tmp = dap_chain_ledger_tx_cache_find_out_cond(a_ledger, &l_tx_first_hash, &l_tx_out_cond, NULL, NULL);

        // Get out_cond item from transaction
        if(l_tx_tmp) {
            UNUSED(a_addr);
            // TODO check relations a_addr with cond_data and public key

            if(l_tx_out_cond) {
                l_ret_value += l_tx_out_cond->header.value;
                if(tx_out_cond)
                    *tx_out_cond = l_tx_out_cond;
            }
        }
    } while(l_tx_tmp);
    return l_ret_value;
}

/**
 * @brief dap_chain_ledger_get_list_tx_outs_with_val
 * @param a_ledger
 * @param a_token_ticker
 * @param a_addr_from
 * @param a_value_need
 * @param a_value_transfer
 * @return
 */
dap_list_t *dap_chain_ledger_get_list_tx_outs_with_val(dap_ledger_t *a_ledger, const char *a_token_ticker, const dap_chain_addr_t *a_addr_from,
                                                       uint64_t a_value_need, uint64_t *a_value_transfer)
{
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_hash_fast_t l_tx_cur_hash = { 0 };
    uint64_t l_value_transfer = 0;
    while(l_value_transfer < a_value_need)
    {
        // Get the transaction in the cache by the addr in out item
        dap_chain_datum_tx_t *l_tx = dap_chain_ledger_tx_find_by_addr(a_ledger, a_token_ticker, a_addr_from,
                                                                             &l_tx_cur_hash);
        if(!l_tx)
            break;
        // Get all item from transaction by type
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);

        uint32_t l_out_idx_tmp = 0; // current index of 'out' item
        for (dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_out_idx_tmp++) {
            dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
            if (l_type == TX_ITEM_TYPE_OUT_COND) {
                continue;
            }
            uint64_t l_value;
            if (l_type == TX_ITEM_TYPE_OUT) {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_list_tmp->data;
                if (!l_out->header.value || memcmp(a_addr_from, &l_out->addr, sizeof(dap_chain_addr_t))) {
                    continue;
                }
                l_value =  l_out->header.value;
            } else { // TX_ITEM_TYPE_OUT_EXT
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
                if (!l_out_ext->header.value || memcmp(a_addr_from, &l_out_ext->addr, sizeof(dap_chain_addr_t)) ||
                        strcmp((char *)a_token_ticker, l_out_ext->token)) {
                    continue;
                }
                l_value =  l_out_ext->header.value;
            }
            // Check whether used 'out' items
            if (!dap_chain_ledger_tx_hash_is_used_out_item (a_ledger, &l_tx_cur_hash, l_out_idx_tmp)) {
                list_used_item_t *item = DAP_NEW(list_used_item_t);
                memcpy(&item->tx_hash_fast, &l_tx_cur_hash, sizeof(dap_chain_hash_fast_t));
                item->num_idx_out = l_out_idx_tmp;
                item->value = l_value;
                l_list_used_out = dap_list_append(l_list_used_out, item);
                l_value_transfer += item->value;
                // already accumulated the required value, finish the search for 'out' items
                if (l_value_transfer >= a_value_need) {
                    break;
                }
            }
        }
        dap_list_free(l_list_out_items);
    }

    // nothing to tranfer (not enough funds)
    if(!l_list_used_out || l_value_transfer < a_value_need) {
        dap_list_free_full(l_list_used_out, free);
        return NULL;
    }

    if (a_value_transfer) {
        *a_value_transfer = l_value_transfer;
    }
    return l_list_used_out;
}

// Add new verificator callback with associated subtype. Returns 1 if callback replaced, overwise returns 0
int dap_chain_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype, dap_chain_ledger_verificator_callback_t a_callback)
{
    dap_chain_ledger_verificator_t *l_new_verificator;
    int l_tmp = (int)a_subtype;
    pthread_rwlock_rdlock(&s_verificators_rwlock);
    HASH_FIND_INT(s_verificators, &l_tmp, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    if (l_new_verificator) {
        l_new_verificator->callback = a_callback;
        return 1;
    }
    l_new_verificator = DAP_NEW(dap_chain_ledger_verificator_t);
    l_new_verificator->subtype = (int)a_subtype;
    l_new_verificator->callback = a_callback;
    pthread_rwlock_wrlock(&s_verificators_rwlock);
    HASH_ADD_INT(s_verificators, subtype, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    return 0;
}

int dap_chain_ledger_verificator_rwlock_init(void) {
    return pthread_rwlock_init(&s_verificators_rwlock, NULL);
}

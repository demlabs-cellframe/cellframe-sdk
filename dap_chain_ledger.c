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
#include "dap_chain_datum_tx_token.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_mempool.h"
#include "dap_chain_global_db.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_ledger"

#define MAX_OUT_ITEMS   10
typedef struct dap_chain_ledger_token_emission_item {
    dap_chain_hash_fast_t datum_token_emission_hash;
    // while these are not needed
    //dap_chain_hash_fast_t datum_tx_token_hash;
    //dap_chain_tx_token_t * tx_token;

    dap_chain_datum_token_emission_t *datum_token_emission;
    UT_hash_handle hh;
} dap_chain_ledger_token_emission_item_t;

typedef struct dap_chain_ledger_token_item {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_hash_fast_t datum_token_hash;
    uint8_t padding[6];
    dap_chain_datum_token_t * datum_token;
    uint64_t total_supply;
    pthread_rwlock_t token_emissions_rwlock;
    dap_chain_ledger_token_emission_item_t * token_emissions;
    UT_hash_handle hh;
} dap_chain_ledger_token_item_t;

// ledger cache item - one of unspendet outputs
typedef struct dap_chain_ledger_tx_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    time_t ts_created;
    int n_outs;
    int n_outs_used;
    char token_tiker[10];
    // TODO dynamically allocates the memory in order not to limit the number of outputs in transaction
    dap_chain_hash_fast_t tx_hash_spent_fast[MAX_OUT_ITEMS]; // spent outs list
    uint8_t padding[6];
    UT_hash_handle hh;
} dap_chain_ledger_tx_item_t;

typedef struct dap_chain_ledger_tx_bound {
    dap_chain_hash_fast_t tx_prev_hash_fast;
    dap_chain_datum_tx_t *tx_prev;
    dap_chain_tx_in_t *tx_cur_in;
    dap_chain_tx_out_t *tx_prev_out;
    dap_chain_ledger_tx_item_t *item_out;
} dap_chain_ledger_tx_bound_t;

// Gotta use a regular null-terminated string instead, for uthash usability
/*typedef struct dap_ledger_wallet_balance_key{
    dap_chain_addr_t addr;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
} DAP_ALIGN_PACKED dap_ledger_wallet_balance_key_t; */

// in-memory wallet balance
typedef struct dap_ledger_wallet_balance {
    //dap_ledger_wallet_balance_key_t key;
    char *key;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint128_t balance;
    UT_hash_handle hh;
} dap_ledger_wallet_balance_t;

// dap_ledget_t private section
typedef struct dap_ledger_private {
    // List of ledger - unspent transactions cache
    dap_chain_ledger_tx_item_t *treshold_txs;
    dap_chain_ledger_token_emission_item_t * treshold_emissions;

    dap_chain_ledger_tx_item_t *ledger_items;

    dap_chain_ledger_token_item_t *tokens;

    dap_ledger_wallet_balance_t *balance_accounts;

    // for separate access to ledger
    pthread_rwlock_t ledger_rwlock;
    // for separate access to tokens
    pthread_rwlock_t tokens_rwlock;

    pthread_rwlock_t treshold_txs_rwlock;
    pthread_rwlock_t treshold_emissions_rwlock;

    uint16_t check_flags;
    bool check_ds;
    bool check_cells_ds;
    bool check_token_emission;
    dap_chain_cell_id_t local_cell_id;
} dap_ledger_private_t;
#define PVT(a) ( (dap_ledger_private_t* ) a->_internal )


static  dap_chain_ledger_tx_item_t* tx_item_find_by_addr(dap_ledger_t *a_ledger,
        const dap_chain_addr_t *a_addr, const char * a_token, dap_chain_hash_fast_t *a_tx_first_hash);

static void s_treshold_emissions_proc( dap_ledger_t * a_ledger);
static void s_treshold_txs_proc( dap_ledger_t * a_ledger);

static size_t s_treshold_emissions_max = 1000;
static size_t s_treshold_txs_max = 10000;
/**
 * Create dap_ledger_t structure
 */
static dap_ledger_t * dap_chain_ledger_handle_new(void)
{
    dap_ledger_t *l_ledger = DAP_NEW_Z(dap_ledger_t);
    l_ledger->_internal = (void*)DAP_NEW_Z(dap_ledger_private_t);

    // Initialize Read/Write Lock Attribute
    pthread_rwlock_init(&PVT(l_ledger)->ledger_rwlock, NULL); // PTHREAD_RWLOCK_INITIALIZER;
    pthread_rwlock_init(&PVT(l_ledger)->tokens_rwlock, NULL);
    pthread_rwlock_init(&PVT(l_ledger)->treshold_txs_rwlock , NULL);
    pthread_rwlock_init(&PVT(l_ledger)->treshold_emissions_rwlock , NULL);

    return l_ledger;
}

/**
 * Remove dap_ledger_t structure
 */
void dap_chain_ledger_handle_free(dap_ledger_t *a_ledger)
{
    if(!a_ledger)
        return;
    // Destroy Read/Write Lock
    pthread_rwlock_destroy(&PVT(a_ledger)->ledger_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->tokens_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->treshold_txs_rwlock );
    pthread_rwlock_destroy(&PVT(a_ledger)->treshold_emissions_rwlock );
    DAP_DELETE(PVT(a_ledger));
    DAP_DELETE(a_ledger);
}


static int compare_datum_items(const void * l_a, const void * l_b)
{
    const dap_chain_datum_t *l_item_a = (const dap_chain_datum_t*) l_a;
    const dap_chain_datum_t *l_item_b = (const dap_chain_datum_t*) l_b;
    if(l_item_a->header.ts_create == l_item_b->header.ts_create)
        return 0;
    if(l_item_a->header.ts_create < l_item_b->header.ts_create)
        return -1;
    return 1;
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
        log_it(L_ERROR, "NULL ledger, can't add datum with token declaration!");
        return  -1;
    }

    dap_chain_ledger_token_item_t * l_token_item;
    HASH_FIND_STR(PVT(a_ledger)->tokens,a_token->header_auth.ticker,l_token_item);

    if ( l_token_item == NULL ){
        l_token_item = DAP_NEW_Z(dap_chain_ledger_token_item_t);
        dap_snprintf(l_token_item->ticker,sizeof (l_token_item->ticker),"%s",a_token->header_auth.ticker);
        l_token_item->datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, a_token_size);
        memcpy(l_token_item->datum_token, a_token,a_token_size);
        l_token_item->total_supply = a_token->header_auth.total_supply;
        pthread_rwlock_init(&l_token_item->token_emissions_rwlock,NULL);
        dap_hash_fast(a_token,a_token_size, &l_token_item->datum_token_hash);

        HASH_ADD_STR(PVT(a_ledger)->tokens, ticker, l_token_item) ;
        log_it(L_NOTICE,"Token %s added (total_supply = %.1llf signs_valid=%hu signs_total=%hu type=%hu )",
               a_token->header_auth.ticker ,
               (long double) a_token->header_auth.total_supply / 1000000000000.0L,
               a_token->header_auth.signs_valid,a_token->header_auth.signs_total, a_token->header_auth.type);
        // Proc emissions tresholds
        s_treshold_emissions_proc( a_ledger);
    }else{
        log_it(L_WARNING,"Duplicate token declaration for ticker '%s' ", a_token->header_auth.ticker);
        return -1;
    }
    return  0;
}

/**
 * @brief s_treshold_emissions_proc
 * @param a_ledger
 */
static void s_treshold_emissions_proc( dap_ledger_t * a_ledger)
{
    // TODO
}

/**
 * @brief s_treshold_txs_proc
 * @param a_ledger
 */
static void s_treshold_txs_proc( dap_ledger_t * a_ledger)
{
    // TODO
}


/**
 * @brief dap_chain_ledger_create
 * @param a_check_flags
 * @return dap_ledger_t
 */
dap_ledger_t* dap_chain_ledger_create(uint16_t a_check_flags)
{
    dap_ledger_t *l_ledger = dap_chain_ledger_handle_new();
    dap_ledger_private_t *l_ledger_priv = PVT(l_ledger);
    l_ledger_priv->check_flags = a_check_flags;
    l_ledger_priv->check_ds = a_check_flags & DAP_CHAIN_LEDGER_CHECK_LOCAL_DS;
    l_ledger_priv->check_cells_ds = a_check_flags & DAP_CHAIN_LEDGER_CHECK_CELLS_DS;
    l_ledger_priv->check_token_emission = a_check_flags & DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION;
    // load ledger from mempool
    return l_ledger; //dap_chain_ledger_load(l_ledger, "kelvin-testnet", "plasma");
}

/**
 * @brief dap_chain_ledger_token_emission_add
 * @param a_token_emission
 * @param a_token_emision_size
 * @return
 */
int dap_chain_ledger_token_emission_add(dap_ledger_t *a_ledger,
        const dap_chain_datum_token_emission_t *a_token_emission, size_t a_token_emission_size)
{
    int ret = 0;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);

    const char * c_token_ticker = a_token_emission->hdr.ticker;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
    HASH_FIND_STR(l_ledger_priv->tokens, c_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);

    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
    // check if such emission is already present in table
    dap_chain_hash_fast_t l_token_emission_hash={0};
    dap_chain_hash_fast_t * l_token_emission_hash_ptr = &l_token_emission_hash;
    dap_hash_fast(a_token_emission, a_token_emission_size, &l_token_emission_hash);
    char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_token_emission_hash);
    pthread_rwlock_wrlock( l_token_item ?
                               &l_token_item->token_emissions_rwlock :
                               &l_ledger_priv->treshold_emissions_rwlock
                               );
    HASH_FIND(hh,l_token_item ? l_token_item->token_emissions : l_ledger_priv->treshold_emissions,
              &l_token_emission_hash, sizeof(l_token_emission_hash), l_token_emission_item);
    if(l_token_emission_item == NULL ) {
        if ( l_token_item || HASH_COUNT( l_ledger_priv->treshold_emissions) < s_treshold_emissions_max  ) {
            l_token_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
            l_token_emission_item->datum_token_emission =
                    DAP_NEW_Z_SIZE(dap_chain_datum_token_emission_t, a_token_emission_size);
            memcpy(l_token_emission_item->datum_token_emission, a_token_emission, a_token_emission_size);
            memcpy(&l_token_emission_item->datum_token_emission_hash,
                    l_token_emission_hash_ptr, sizeof(l_token_emission_hash));
            dap_chain_ledger_token_emission_item_t * l_token_emissions =  l_token_item ?
                        l_token_item->token_emissions : l_ledger_priv->treshold_emissions;
            HASH_ADD(hh, l_token_emissions ,
                     datum_token_emission_hash, sizeof(l_token_emission_hash),
                    l_token_emission_item);
            // save pointer to structure
            if(l_token_item)
                l_token_item->token_emissions = l_token_emissions;
            else
                l_ledger_priv->treshold_emissions = l_token_emissions;
            char * l_token_emission_address_str = dap_chain_addr_to_str( &(a_token_emission->hdr.address) );
            log_it(L_NOTICE,
             "Added token emission datum to %s: type=%s value=%.1llf token=%s to_addr=%s ",
                   l_token_item?"emissions cache":"emissions treshold",
                     c_dap_chain_datum_token_emission_type_str[ a_token_emission->hdr.type ] ,
                   ((long double)a_token_emission->hdr.value) / DATOSHI_LD, c_token_ticker,
                   l_token_emission_address_str);
            DAP_DELETE(l_token_emission_address_str);
        }else{
            log_it(L_WARNING,"Treshold for emissions is overfulled (%lu max), dropping down new data, added nothing",
                   s_treshold_emissions_max);
            ret = -2;
        }
    } else {
        log_it(L_ERROR, "Can't add token emission datum of %llu %s ( 0x%s )",
                a_token_emission->hdr.value, c_token_ticker, l_hash_str);
        ret = -1;
    }
    pthread_rwlock_unlock(l_token_item ?
                              &l_token_item->token_emissions_rwlock :
                              &l_ledger_priv->treshold_emissions_rwlock);
    DAP_DELETE(l_hash_str);

    return ret;
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

    if(l_token_item) {
        dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
        pthread_rwlock_rdlock( &l_token_item->token_emissions_rwlock);
        HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash),
                l_token_emission_item);
        if( l_token_emission_item)
            l_token_emission = l_token_emission_item->datum_token_emission;
        pthread_rwlock_unlock( &l_token_item->token_emissions_rwlock);
    }
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
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

    dap_chain_ledger_tx_item_t *l_item= NULL;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof ( *a_tx_hash), l_item );
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_item? l_item->token_tiker: NULL;
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
                if(l_tickers[i] && strcmp(l_tickers[i], l_tx_item->token_tiker) == 0) {
                    l_is_not_in_list = false;
                    break;
                }
            }
            if(l_is_not_in_list) {
                if((l_tickers_pos + 1) == l_tickers_size) {
                    l_tickers_size += (l_tickers_size / 2);
                    l_tickers = DAP_REALLOC(l_tickers, l_tickers_size);
                }
                l_tickers[l_tickers_pos] = dap_strdup(l_tx_item->token_tiker);
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
    char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
    l_count = 0;
    char *l_addr = dap_chain_addr_to_str(a_addr);
    HASH_ITER(hh, PVT(a_ledger)->balance_accounts, wallet_balance, tmp) {
        char **l_keys = dap_strsplit(wallet_balance->key, " ", -1);
        if (!dap_strcmp(l_keys[0], l_addr)) {
            l_tickers[l_count] = dap_strdup(wallet_balance->token_ticker);
            ++l_count;
        }
        dap_strfreev(l_keys);
    }
    *a_tickers = l_tickers;
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
    if(l_tx_item) {
        l_tx_ret = l_tx_item->tx;
        if(a_item_out)
            *a_item_out = l_tx_item;
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);

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
     1. valid(tx2.dap_chain_datum_tx_sig.pkey )
     &&
     2. valid (tx1.dap_chain_datum_tx_sig.pkey)
     &&
     3. hash(tx1) == tx2.dap_chain_datump_tx_in.tx_prev_hash
     &&
     4. tx1.dap_chain_datum_tx_out.addr.data.key == tx2.dap_chain_datum_tx_sig.pkey
     &&
     5. sum(  find (tx2.input.tx_prev_hash).output[tx2.input_tx_prev_idx].value )  ==  sum (tx2.outputs.value)
     */

    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    if(!a_tx)
        return -1;

    dap_list_t *l_list_bound_items = NULL;

    bool l_is_first_transaction = false;
    // sum of values in 'out' items from the previous transactions
    uint64_t l_values_from_prev_tx = 0;

    // 1. Verify signature in current transaction
    if(dap_chain_datum_tx_verify_sign(a_tx) != 1)
        return -2;

    // calculate hash for current transactions
    dap_chain_hash_fast_t l_tx_hash;
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);

    // check all previous transactions
    bool l_is_err = false;
    int l_prev_tx_count = 0;

    // ----------------------------------------------------------------
    // find all 'in' items in current transaction
    dap_list_t *l_list_in = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_IN,
            &l_prev_tx_count);
    // find all previous transactions
    dap_list_t *l_list_tmp = l_list_in;
    int l_list_tmp_num = 0;

    //log_it(L_DEBUG,"Tx check: %d inputs",l_prev_tx_count);
    while(l_list_tmp) {
        dap_chain_ledger_tx_bound_t *bound_item = DAP_NEW_Z(dap_chain_ledger_tx_bound_t);
        l_list_tmp_num++;
        dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t*) l_list_tmp->data;
        // one of the previous transaction
        dap_chain_hash_fast_t l_tx_prev_hash = l_tx_in->header.tx_prev_hash;
        bound_item->tx_cur_in = l_tx_in;
        memcpy(&bound_item->tx_prev_hash_fast, &l_tx_prev_hash, sizeof(dap_chain_hash_fast_t));

        bool l_is_blank = dap_hash_fast_is_blank(&l_tx_prev_hash);
        char l_tx_prev_hash_str[70];
        if (l_is_blank){
           //log_it(L_DEBUG, "Tx check: blank prev hash ");
           dap_snprintf(l_tx_prev_hash_str,sizeof( l_tx_prev_hash_str),"BLANK");
        }else{
            dap_chain_hash_fast_to_str(&l_tx_prev_hash,l_tx_prev_hash_str,sizeof(l_tx_prev_hash_str));
            //log_it(L_DEBUG, "Tx check:  tx prev hash %s",l_tx_prev_hash_str);
        }

        if(l_is_blank || l_is_first_transaction) {
            // if at least one blank hash is present, then all the hashes should be blank
            if((!l_is_first_transaction && l_list_tmp_num > 1) || !l_is_blank) {
                l_is_err = true;
                DAP_DELETE(bound_item);
                break;
            }
            l_is_first_transaction = true;
        }
        // Get previous transaction in the cache by hash
        dap_chain_ledger_tx_item_t *l_item_out = NULL;
        dap_chain_datum_tx_t *l_tx_prev =
                s_find_datum_tx_by_hash(a_ledger, &l_tx_prev_hash, &l_item_out); // dap_chain_datum_tx_t *l_tx_prev = (dap_chain_datum_tx_t*) dap_chain_node_datum_tx_cache_find(&tx_prev_hash);
        bound_item->item_out = l_item_out;
        if(!l_tx_prev) { // First transaction
            log_it(L_INFO,"No previous transaction was found for hash %s",l_tx_prev_hash_str);
            DAP_DELETE(bound_item);

            // go to next previous transaction
            l_list_tmp = dap_list_next(l_list_tmp);
            continue;
        } else {
            //log_it(L_INFO,"Previous transaction was found for hash %s",l_tx_prev_hash_str);

            bound_item->tx_prev = l_tx_prev;

            // 2. Verify signature in previous transaction
            int l_res_sign = dap_chain_datum_tx_verify_sign(l_tx_prev);

            // calculate hash of previous transaction anew
            dap_chain_hash_fast_t *l_hash_prev = dap_chain_node_datum_tx_calc_hash(l_tx_prev);
            // 3. Compare hash in previous transaction with hash inside 'in' item
            int l_res_hash = dap_hash_fast_compare(l_hash_prev, &l_tx_prev_hash);

            if(l_res_sign != 1 || l_res_hash != 1) {
                l_is_err = true;
                DAP_DELETE(bound_item);
                break;
            }
            DAP_DELETE(l_hash_prev);

            // Get list of all 'out' items from previous transaction
            dap_list_t *l_list_prev_out = dap_chain_datum_tx_items_get(l_tx_prev, TX_ITEM_TYPE_OUT, NULL);
            // Get one 'out' item in previous transaction bound with current 'in' item
            dap_chain_tx_out_t *l_tx_prev_out = dap_list_nth_data(l_list_prev_out, l_tx_in->header.tx_out_prev_idx);
            if(!l_tx_prev_out) {
                l_is_err = true;
                DAP_DELETE(bound_item);
                break;
            }
            dap_list_free(l_list_prev_out);
            bound_item->tx_prev_out = l_tx_prev_out;

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
            }
            // hash of public key in 'out' item of previous transaction
            uint8_t *l_prev_out_addr_key = l_tx_prev_out->addr.data.key;

            // 4. compare public key hashes in the signature of the current transaction and in the 'out' item of the previous transaction
            if(memcmp(&l_hash_pkey, l_prev_out_addr_key, sizeof(dap_chain_hash_fast_t))) {
                l_is_err = true;
                DAP_DELETE(bound_item);
                break;
            }

            // calculate sum of values from previous transactions
            l_values_from_prev_tx += l_tx_prev_out->header.value;

            l_list_bound_items = dap_list_append(l_list_bound_items, bound_item);

            // go to next previous transaction
            l_list_tmp = dap_list_next(l_list_tmp);

        }
    }
    if (l_list_in)
        dap_list_free(l_list_in);

    if(l_is_err) {
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, free);
        return -3;
    }

    // Calculate the sum of values in 'out' items from the current transaction
    dap_list_t *l_list_tx_out = NULL;
    uint64_t l_values_from_cur_tx = 0;
    bool emission_flag = !l_is_first_transaction || (l_is_first_transaction && l_ledger_priv->check_token_emission);
    // find 'out' items
    dap_list_t *l_list_out = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_OUT, NULL);
    dap_list_t *l_list_out_cond = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_OUT_COND, NULL);
    // accumalate value ​from all  'out' transactions
    l_list_tmp = l_list_out;
    while(l_list_tmp) {
        dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*) l_list_tmp->data;
        if (emission_flag) {
            l_values_from_cur_tx += l_tx_out->header.value;
        }
        l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        l_list_tmp = dap_list_next(l_list_tmp);
    }
    // accumalate value ​from all  'ut_cond' transactions
    l_list_tmp = l_list_out_cond;
    while(l_list_tmp) {
        dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t*) l_list_tmp->data;
        if (emission_flag) {
            l_values_from_cur_tx += l_tx_out->header.value;
        }
        l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        l_list_tmp = dap_list_next(l_list_tmp);
    }
    if ( l_list_out )
        dap_list_free(l_list_out);
    if ( l_list_out_cond)
        dap_list_free(l_list_out_cond);

    // Additional check whether the transaction is first
    if(l_is_first_transaction)
    {
        // Get sign item
        size_t l_tx_token_size;
        dap_chain_tx_token_t * l_tx_token;
        if(!(l_tx_token = (dap_chain_tx_token_t*) dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL))) {
            if ( l_list_bound_items )
                dap_list_free_full(l_list_bound_items, free);
            if (l_list_tx_out)
                dap_list_free(l_list_tx_out);
            return -4;
        }
        l_tx_token_size = dap_chain_datum_item_tx_get_size((uint8_t*) l_tx_token);

        if(l_ledger_priv->check_token_emission) { // Check the token emission
            dap_chain_datum_token_emission_t * l_token_emission =
                    dap_chain_ledger_token_emission_find(a_ledger, l_tx_token->header.ticker,
                            &l_tx_token->header.token_emission_hash);
            if(l_token_emission) {
                if(l_token_emission->hdr.value != l_values_from_cur_tx) {
                    if ( l_list_bound_items )
                        dap_list_free_full(l_list_bound_items, free);
                    if (l_list_tx_out)
                        dap_list_free(l_list_tx_out);
                    return -5;
                }
            } else {
                if ( l_list_bound_items )
                    dap_list_free_full(l_list_bound_items, free);
                if (l_list_tx_out)
                    dap_list_free(l_list_tx_out);
                return -6;
            }
        }

    } else if(l_values_from_cur_tx != l_values_from_prev_tx) { // 5. Compare sum of values in 'out' items in
                                                               // the current transaction and in the previous transactions
        log_it(L_ERROR, "Sum of values in out items of current tx (%llu) is not equal outs from previous tx (%llu)",
               l_values_from_cur_tx, l_values_from_prev_tx);
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, free);
        if (l_list_tx_out)
            dap_list_free(l_list_tx_out);
        return -7;
    }

    if(a_list_bound_items)
        *a_list_bound_items = l_list_bound_items;
    else if ( l_list_bound_items )
        dap_list_free_full(l_list_bound_items, free);
    if (a_list_tx_out)
        *a_list_tx_out = l_list_tx_out;
    else if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    return 0;
}

/**
 * Add new transaction to the cache list
 *
 * return 1 OK, -1 error
 */
int dap_chain_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx)
{
    if(!a_tx)
        return -1;
    int ret = 1;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;

    int l_ret_check;
    if( (l_ret_check = dap_chain_ledger_tx_cache_check(
             a_ledger, a_tx, &l_list_bound_items, &l_list_tx_out)) < 0){
        log_it (L_WARNING, "dap_chain_ledger_tx_add() tx not passed the check: code %d ",l_ret_check);
        return -1;
    }
    dap_chain_hash_fast_t *l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    char l_tx_hash_str[70];
    dap_chain_hash_fast_to_str(l_tx_hash,l_tx_hash_str,sizeof(l_tx_hash_str));
    //log_it ( L_INFO, "dap_chain_ledger_tx_add() check passed for tx %s",l_tx_hash_str);


    char * l_token_ticker = NULL;
    dap_chain_ledger_tx_item_t *l_item_tmp = NULL;
    pthread_rwlock_wrlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, l_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash already in the hash?
    // transaction already present in the cache list
    if(l_item_tmp) {
        // delete transaction from the cache list
        //ret = dap_chain_ledger_tx_remove(a_ledger, l_tx_hash);
        // there should be no duplication
        log_it(L_WARNING, "Transaction (hash=0x%x)  deleted from cache because there is an attempt to add it to cache",
                l_tx_hash);
        ret = 1;
        goto FIN;
    }
    if (ret == -1) {
        goto FIN;
    }
    // Mark 'out' items in cache if they were used & delete previous transactions from cache if it need
    // find all bound pairs 'in' and 'out'
    dap_list_t *l_list_tmp = l_list_bound_items;
//    int l_list_tmp_num = 0;
    while(l_list_tmp) {
        dap_chain_ledger_tx_bound_t *bound_item = l_list_tmp->data;
        dap_chain_tx_in_t *l_tx_in = bound_item->tx_cur_in;
        dap_chain_ledger_tx_item_t *l_prev_item_out = bound_item->item_out;
        if ( l_token_ticker == NULL)
            l_token_ticker = dap_strdup (l_prev_item_out->token_tiker);

        // Update balance: deducts
        dap_ledger_wallet_balance_t *wallet_balance = NULL;
        char *l_addr_str = dap_chain_addr_to_str(&bound_item->tx_prev_out->addr);
        char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_token_ticker, (char*)NULL);
        HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
        if (wallet_balance) {
            //log_it(L_DEBUG,"SPEND %lu from addr: %s", bound_item->tx_prev_out->header.value, l_wallet_balance_key);
            wallet_balance->balance -= bound_item->tx_prev_out->header.value;
        } else {
            log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_token_ticker);
        }
        DAP_DELETE(l_addr_str);
        DAP_DELETE(l_wallet_balance_key);

        /// Mark 'out' item in cache because it used
        dap_chain_hash_fast_t *l_tx_prev_hash =
                &(l_prev_item_out->tx_hash_spent_fast[l_tx_in->header.tx_out_prev_idx]);
        memcpy(l_tx_prev_hash, l_tx_hash, sizeof(dap_chain_hash_fast_t));
        // add a used output
        l_prev_item_out->n_outs_used++;
        char * l_tx_prev_hash_str = dap_chain_hash_fast_to_str_new(l_tx_prev_hash);

        // delete previous transactions from cache because all out is used
        if(l_prev_item_out->n_outs_used == l_prev_item_out->n_outs) {
            dap_chain_hash_fast_t l_tx_prev_hash_to_del = bound_item->tx_prev_hash_fast;
            // remove from memory ledger
            int res = dap_chain_ledger_tx_remove(a_ledger, &l_tx_prev_hash_to_del);
            if(res == -2) {
                log_it(L_ERROR, "Can't delete previous transactions because hash=0x%x not found", l_tx_prev_hash_str);
                ret = -2;
                DAP_DELETE(l_tx_prev_hash_str);
                dap_list_free_full(l_list_bound_items, free);
                goto FIN;
            }
            else if(res != 1) {
                log_it(L_ERROR, "Can't delete previous transactions with hash=0x%x", l_tx_prev_hash_str);
                ret = -3;
                DAP_DELETE(l_tx_prev_hash_str);
                dap_list_free_full(l_list_bound_items, free);
                goto FIN;
            }
            // TODO restore when the blockchain appears
            // remove from mempool ledger
            /*char *l_tx_prev_hash_to_del_str = dap_chain_hash_fast_to_str_new(&l_tx_prev_hash_to_del);
             if(!dap_chain_global_db_gr_del( dap_strdup(l_tx_prev_hash_to_del_str), c_dap_datum_mempool_gdb_group)) {
             log_it(L_ERROR, "Can't delete previous transactions from mempool with hash=0x%x",
             l_tx_prev_hash_str);
             }
             DAP_DELETE( l_tx_prev_hash_to_del_str);*/
        }
        DAP_DELETE(l_tx_prev_hash_str);
        // go to next previous transaction
        l_list_tmp = dap_list_next(l_list_tmp);
    }
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, free);

    // Try to find token ticker if wasn't
    if ( l_token_ticker == NULL){
        int l_base_tx_count = 0;
        dap_list_t *l_base_tx_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_TOKEN, &l_base_tx_count );
        if (l_base_tx_count >=1  && l_base_tx_list){
            dap_chain_tx_token_t * l_tx_token =(dap_chain_tx_token_t *) l_base_tx_list->data;
            if ( l_tx_token )
                l_token_ticker = dap_strdup( l_tx_token->header.ticker);
        }
    }

    //Update balance : raise
    for (dap_list_t *l_tx_out = l_list_tx_out; l_tx_out; l_tx_out = dap_list_next(l_tx_out)) {
        dap_chain_tx_out_t *l_out_item = l_tx_out->data;
        if (l_out_item && l_token_ticker) {
            char *l_addr_str = dap_chain_addr_to_str(&l_out_item->addr);
            //log_it (L_DEBUG, "Check unspent %.03Lf %s for addr %s",
            //        (long double) l_out_item->header.value/ 1000000000000.0L,
            //        l_token_ticker, l_addr_str);
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_token_ticker, (char*)NULL);
            //log_it (L_DEBUG,"\t\tAddr: %s token: %s", l_addr_str, l_token_ticker);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            if (wallet_balance) {
                //log_it(L_DEBUG, "Balance item is present in cache");
                wallet_balance->balance += l_out_item->header.value;
                DAP_DELETE (l_wallet_balance_key);
            } else {
                wallet_balance = DAP_NEW_Z(dap_ledger_wallet_balance_t);
                wallet_balance->key = l_wallet_balance_key;
                wallet_balance->balance += l_out_item->header.value;
                dap_stpcpy(wallet_balance->token_ticker, l_token_ticker);
                //log_it(L_DEBUG,"!!! Create new balance item: %s %s", l_addr_str, l_token_ticker);
                HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, wallet_balance->key,
                                strlen(l_wallet_balance_key), wallet_balance);
            }
#ifdef __ANDROID__
            log_it(L_INFO, "Updated balance +%.3Lf %s on addr %s",
                   dap_chain_balance_to_coins (l_out_item->header.value),
                    l_token_ticker,
                   l_addr_str);
#else
            //log_it(L_INFO, "Updated balance +%.3Lf %s, now %.3Lf on addr %s",
            //       dap_chain_balance_to_coins (l_out_item->header.value),
            //        l_token_ticker,
            //       dap_chain_balance_to_coins (wallet_balance->balance),
            //       l_addr_str);
#endif
            DAP_DELETE (l_addr_str);
        } else {
            log_it(L_WARNING, "Can't detect tx ticker or matching output, can't append balances cache");
        }
    }

    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);

    // add transaction to the cache list
    if(ret == 1){
        l_item_tmp = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
        memcpy(&l_item_tmp->tx_hash_fast, l_tx_hash, sizeof(dap_chain_hash_fast_t));
        l_item_tmp->tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, dap_chain_datum_tx_get_size(a_tx));
        l_item_tmp->ts_created = (time_t) a_tx->header.ts_created;
        //calculate l_item_tmp->n_outs;

        // If debug mode dump the UTXO
        if ( dap_log_level_get() == L_DEBUG){
            l_item_tmp->n_outs = 0;
            if( l_item_tmp->n_outs){
                dap_list_t *l_tist_tmp = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT, &l_item_tmp->n_outs);
                for (size_t i =0; i < (size_t) l_item_tmp->n_outs; i++){
                    dap_chain_tx_out_t * l_tx_out = l_tist_tmp->data;
                    char * l_tx_out_addr_str = dap_chain_addr_to_str( &l_tx_out->addr );
                    //log_it(L_DEBUG,"Added tx out to %s",l_tx_out_addr_str );
                    DAP_DELETE (l_tx_out_addr_str);
                }
                if(l_tist_tmp)
                    dap_list_free(l_tist_tmp);
            }
        }

        if ( l_token_ticker == NULL) { //No token ticker in previous txs
            //log_it(L_DEBUG, "No token ticker in previous txs");
            int l_tokens_count = 0;
            dap_list_t *l_tokens_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_TOKEN, &l_tokens_count );
            if ( l_tokens_count>0 ){
                dap_chain_tx_token_t * l_token = (dap_chain_tx_token_t*) l_tokens_list->data;
                l_token_ticker = dap_strdup (l_token->header.ticker);
                dap_list_free(l_tokens_list);
            }
        }
        if (l_token_ticker)
            strncpy(l_item_tmp->token_tiker,l_token_ticker,sizeof (l_item_tmp->token_tiker));

        memcpy(l_item_tmp->tx, a_tx, dap_chain_datum_tx_get_size(a_tx));
        HASH_ADD(hh, l_ledger_priv->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash_fast: name of key field
        ret = 1;
    }
FIN:
    pthread_rwlock_tryrdlock (&l_ledger_priv->ledger_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    if (l_token_ticker) {
        DAP_DELETE(l_token_ticker);
    }
    DAP_DELETE(l_tx_hash);
    return ret;
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
    pthread_rwlock_wrlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp);
    if(l_item_tmp != NULL) {
        HASH_DEL(l_ledger_priv->ledger_items, l_item_tmp);
        l_ret = 1;
    }
    else
        // hash not found in the cache
        l_ret = -2;
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    if(!l_ret) {
        // delete transaction
        DAP_DELETE(l_item_tmp->tx);
        // del struct for hash
        DAP_DELETE(l_item_tmp);
    }
    return l_ret;
}

/**
 * Delete all transactions from the cache
 */
void dap_chain_ledger_purge(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_wrlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp)
    {
        // delete transaction
        DAP_DELETE(l_iter_current->tx);
        // del struct for hash
        HASH_DEL(l_ledger_priv->ledger_items, l_iter_current);
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
}

/**
 * Return number transactions from the cache
 */
_dap_int128_t dap_chain_ledger_count(dap_ledger_t *a_ledger)
{
    _dap_int128_t l_ret = 0;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp)
    {
        l_ret++;
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_ret;
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
            if ( l_iter_current->ts_created >= a_ts_from && l_iter_current->ts_created <= a_ts_to )
            l_ret++;
        }
    } else if ( a_ts_to ){
        HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->ts_created <= a_ts_to )
            l_ret++;
        }
    } else if ( a_ts_from ){
        HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->ts_created >= a_ts_from )
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

/**
 * Check whether used 'out' items (local function)
 */
static bool dap_chain_ledger_item_is_used_out(dap_chain_ledger_tx_item_t *a_item, int a_idx_out)
{
    bool l_used_out = false;
    if(!a_item) {
        //log_it(L_DEBUG, "list_cached_item is NULL");
        return false;
    }
    if(a_idx_out >= MAX_OUT_ITEMS) {
        log_it(L_ERROR, "Too big index(%d) of 'out'items (max=%d)", a_idx_out, MAX_OUT_ITEMS);
    }
    assert(a_idx_out < MAX_OUT_ITEMS);
    // if there are used 'out' items
    if(a_item->n_outs_used > 0) {
        if(!dap_hash_fast_is_blank(&(a_item->tx_hash_spent_fast[a_idx_out])))
            l_used_out = true;
    }
    return l_used_out;
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
uint64_t dap_chain_ledger_calc_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
        const char *a_token_ticker)
{
    uint64_t l_ret = 0;
    dap_ledger_wallet_balance_t *l_balance_item = NULL ,* l_balance_item_tmp = NULL;
    char *l_addr = dap_chain_addr_to_str(a_addr);
    char *l_wallet_balance_key = dap_strjoin(" ", l_addr, a_token_ticker, (char*)NULL);

    HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, l_balance_item);
    if (l_balance_item) {
        log_it (L_INFO,"Found address in cache with balance %llu", l_balance_item->balance);
        l_ret = l_balance_item->balance;
    } /*else {
        //char * l_addr_str = dap_chain_addr_to_str( a_addr);
        log_it (L_WARNING,"Can't find balance for address %s token \"%s\" in cache", l_addr,
                a_token_ticker?a_token_ticker: "???");
        //DAP_DELETE(l_addr_str);
        log_it (L_DEBUG,"Total size of hashtable %u", HASH_COUNT( PVT(a_ledger)->balance_accounts ) );
        HASH_ITER(hh,PVT(a_ledger)->balance_accounts,l_balance_item, l_balance_item_tmp ){
            //char * l_addr_str = dap_chain_addr_to_str( &l_balance_item->key.addr);
            log_it (L_DEBUG,"\t\tAddr: %s token: %s", l_addr, l_balance_item->key.ticker  );
            //DAP_DELETE(l_addr_str);
            if ( memcmp(&l_balance_item->key.addr, a_addr,sizeof(*a_addr) ) == 0 )
                if ( strcmp (l_balance_item->key.ticker, a_token_ticker) ==0 ) {
                    l_ret = l_balance_item->balance;
                    break;
                }
        }

    }*/
    DAP_DELETE(l_addr);
    DAP_DELETE(l_wallet_balance_key);
    return l_ret;
}

uint64_t dap_chain_ledger_calc_balance_full(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
            const char *a_token_ticker)
{
    uint64_t balance = 0;
    if(!a_addr || !dap_chain_addr_check_sum(a_addr))
        return 0;
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

        // Check for token name
        if(strcmp(a_token_ticker, l_iter_current->token_tiker) == 0) {
            //        dap_chain_hash_fast_t *l_cur_tx_hash = &l_iter_current->tx_hash_fast;
            //        int l_n_outs_used = l_iter_current->n_outs_used; // number of used 'out' items

            // Get 'out' items from transaction
            int l_out_item_count = 0;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_cur_tx, TX_ITEM_TYPE_OUT, &l_out_item_count);
            if(l_out_item_count >= MAX_OUT_ITEMS) {
                log_it(L_ERROR, "Too many 'out' items=%d in transaction (max=%d)", l_out_item_count, MAX_OUT_ITEMS);
                assert(l_out_item_count < MAX_OUT_ITEMS);
            }
            dap_list_t *l_list_tmp = l_list_out_items;
            int l_out_idx_tmp = 0;
            while(l_list_tmp) {
                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;

                // if transaction has the out item with requested addr
                if(l_tx_out
                        && !memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t)
                                )) {
                    // if 'out' item not used & transaction is valid
                    if(!dap_chain_ledger_item_is_used_out(l_iter_current, l_out_idx_tmp) &&
                            dap_chain_datum_tx_verify_sign(l_cur_tx))
                        balance += l_tx_out->header.value;
                }
                // go to the next 'out' item in l_tx_tmp transaction
                l_out_idx_tmp++;

                l_list_tmp = dap_list_next(l_list_tmp);
            }
            dap_list_free(l_list_tmp);
        }
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
        if (a_token)
            if ( dap_strcmp(l_iter_current->token_tiker,a_token) !=0 )
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
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
        dap_list_t *l_list_tmp = l_list_out_items;
        while(l_list_tmp) {
            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
            // if transaction has the out item with requested addr
            if(l_tx_out &&
                    !memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))
                            ) {
                memcpy(a_tx_first_hash, l_tx_hash, sizeof(dap_chain_hash_fast_t));
                is_tx_found = true;
                break;
            }
            l_list_tmp = dap_list_next(l_list_tmp);
        }
        dap_list_free(l_list_tmp);
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
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_cur_tx;
}

/**
 * Get the transaction in the cache with the out_cond item
 *
 * a_addr[in] wallet address, whose owner can use the service
 */
const dap_chain_datum_tx_t* dap_chain_ledger_tx_cache_find_out_cond(dap_ledger_t *a_ledger,
        dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_addr || !a_tx_first_hash)
        return NULL;
    int l_ret = -1;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items, l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash_tmp, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get sign item from transaction
        int l_tx_out_cond_size = 0;
        const dap_chain_tx_out_cond_t *l_tx_out_cond = (const dap_chain_tx_out_cond_t*) dap_chain_datum_tx_item_get(
                l_tx_tmp, NULL, TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size);

        if(l_tx_out_cond) {
            l_cur_tx = l_tx_tmp;
            memcpy(a_tx_first_hash, l_tx_hash_tmp, sizeof(dap_chain_hash_fast_t));
            break;
        }
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
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

    // Find all transactions
    do {
        l_tx_tmp = dap_chain_ledger_tx_cache_find_out_cond(a_ledger, a_addr, &l_tx_first_hash);

        // Get out_cond item from transaction
        if(l_tx_tmp) {
           dap_chain_tx_out_cond_t *l_tx_out_cond  =(dap_chain_tx_out_cond_t *)dap_chain_datum_tx_item_get(
                     l_tx_tmp, NULL, TX_ITEM_TYPE_OUT_COND, NULL);

            // TODO check relations a_addr with cond_data and public key

            if(l_tx_out_cond) {
                l_ret_value += l_tx_out_cond->header.value;
                if(tx_out_cond)
                    *tx_out_cond = (dap_chain_tx_out_cond_t*) l_tx_out_cond;
            }
        }
    }
    while(l_tx_tmp);
    return l_ret_value;
}


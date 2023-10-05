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


#define LOG_TAG "dap_chain_ledger"

typedef struct dap_chain_ledger_verificator {
    int subtype;    // hash key
    dap_chain_ledger_verificator_callback_t callback;
    dap_chain_ledger_updater_callback_t callback_added;
    UT_hash_handle hh;
} dap_chain_ledger_verificator_t;

static dap_chain_ledger_verificator_t *s_verificators;
static  pthread_rwlock_t s_verificators_rwlock;

#define MAX_OUT_ITEMS   10

static const char *s_ledger_tx_check_err_str[] = {
    [DAP_CHAIN_LEDGER_TX_CHECK_OK] = "DAP_CHAIN_LEDGER_TX_CHECK_OK",
    [DAP_CHAIN_LEDGER_TX_CHECK_NULL_TX] = "DAP_CHAIN_LEDGER_TX_CHECK_NULL_TX",
    [DAP_CHAIN_LEDGER_TX_CHECK_INVALID_TX_SIZE] = "DAP_CHAIN_LEDGER_TX_CHECK_INVALID_TX_SIZE",
    [DAP_CHAIN_LEDGER_TX_ALREADY_CACHED] = "DAP_CHAIN_LEDGER_TX_ALREADY_CACHED",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NULL_TX] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NULL_TX",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_INVALID_TX_SIGN] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_INVALID_TX_SIGN",
    [DAP_CHAIN_LEDGER_TX_CACHE_IN_EMS_ALREADY_USED] = "DAP_CHAIN_LEDGER_TX_CACHE_IN_EMS_ALREADY_USED",
    [DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_IN_EMS_ALREADY_USED] = "DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_IN_EMS_ALREADY_USED",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_EMISSION_NOT_FOUND] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_EMISSION_NOT_FOUND",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TX_NO_VALID_INPUTS] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TX_NO_VALID_INPUTS",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TICKER_NOT_FOUND] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TICKER_NOT_FOUND",
    [DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_INVALID_TOKEN] = "DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_INVALID_TOKEN",
    [DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS] = "DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS",
    [DAP_CHAIN_LEDGER_TX_CACHE_MULT256_OVERFLOW_EMS_LOCKED_X_RATE] = "DAP_CHAIN_LEDGER_TX_CACHE_MULT256_OVERFLOW_EMS_LOCKED_X_RATE",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS",
    [DAP_CHAIN_LEDGER_TX_CACHE_NO_OUT_ITEMS_FOR_BASE_TX] = "DAP_CHAIN_LEDGER_TX_CACHE_NO_OUT_ITEMS_FOR_BASE_TX",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TOKEN_EMS_VALUE_EXEEDS_CUR_SUPPLY] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TOKEN_EMS_VALUE_EXEEDS_CUR_SUPPLY",
    [DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_UNEXPECTED_VALUE] = "DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_UNEXPECTED_VALUE",
    [DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_TICKER_NOT_FOUND] = "DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_TICKER_NOT_FOUND",
    [DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_OTHER_TICKER_EXPECTED] = "DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_OTHER_TICKER_EXPECTED",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_OUT_ITEM_ALREADY_USED] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_OUT_ITEM_ALREADY_USED",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TX_NOT_FOUND] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TX_NOT_FOUND",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ITEM_NOT_FOUND] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ITEM_NOT_FOUND",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PKEY_HASHES_DONT_MATCH] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PKEY_HASHES_DONT_MATCH",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_VERIFICATOR_SET] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_VERIFICATOR_SET",
    [DAP_CHAIN_LEDGER_TX_CACHE_VERIFICATOR_CHECK_FAILURE] = "DAP_CHAIN_LEDGER_TX_CACHE_VERIFICATOR_CHECK_FAILURE",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TICKER_NOT_FOUND] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TICKER_NOT_FOUND",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TOKEN_NOT_FOUND] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TOKEN_NOT_FOUND",
    [DAP_CHAIN_LEDGER_PERMISSION_CHECK_FAILED] = "DAP_CHAIN_LEDGER_PERMISSION_CHECK_FAILED",
    [DAP_CHAIN_LEDGER_TX_CACHE_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS] = "DAP_CHAIN_LEDGER_TX_CACHE_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS"
};

static const char *s_ledger_emission_add_err_str[] = {
    [DAP_CHAIN_LEDGER_EMISSION_ADD_OK] = "DAP_CHAIN_LEDGER_EMISSION_ADD_OK",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_IS_NULL] = "DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_IS_NULL",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_ALREADY_CACHED] = "DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_ALREADY_CACHED",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_THRESHOLD_OVERFLOW] = "DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_THRESHOLD_OVERFLOW",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_VALUE_EXEEDS_CURRENT_SUPPLY] = "DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_VALUE_EXEEDS_CURRENT_SUPPLY",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_NOT_ENOUGH_VALID_SIGNS] = "DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_NOT_ENOUGH_VALID_SIGNS",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_CANT_FIND_DECLARATION_TOKEN] = "DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_CANT_FIND_DECLARATION_TOKEN",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_ZERO_VALUE] = "DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_ZERO_VALUE",
    [DAP_CHAIN_LEDGER_EMISSION_ADD_TSD_CHECK_FAILED] = "DAP_CHAIN_LEDGER_EMISSION_ADD_TSD_CHECK_FAILED"
};

static const char *s_ledger_token_decl_err_str[] = {
    [DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_OK] = "DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_OK",
    [DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_LEDGER_IS_NULL] = "DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_LEDGER_IS_NULL",
    [DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_DECL_DUPLICATE] = "DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_DECL_DUPLICATE",
    [DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_CHECK] = "DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_CHECK",
    [DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_ABSENT_TOKEN] = "DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_ABSENT_TOKEN",
    [DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_NOT_ENOUGH_VALID_SIGN] = "DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_NOT_ENOUGH_VALID_SIGN",
    [DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOTAL_SIGNS_EXCEED_UNIQUE_SIGNS] = "DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOTAL_SIGNS_EXCEED_UNIQUE_SIGNS"
};

char *dap_chain_ledger_tx_check_err_str(int a_code) {
    return (a_code >= DAP_CHAIN_LEDGER_TX_CHECK_OK) && (a_code < DAP_CHAIN_LEDGER_TX_CHECK_UNKNOWN)
            ? (char*)s_ledger_tx_check_err_str[(dap_chain_ledger_tx_check_t)a_code]
            : dap_itoa(a_code);
}

typedef struct dap_chain_ledger_stake_lock_item {
    dap_chain_hash_fast_t	tx_for_stake_lock_hash;
    dap_chain_hash_fast_t	tx_used_out;
    uint256_t ems_value;
    UT_hash_handle hh;
} dap_chain_ledger_stake_lock_item_t;

typedef struct dap_chain_ledger_token_emission_item {
    dap_chain_hash_fast_t datum_token_emission_hash;
    dap_chain_datum_token_emission_t *datum_token_emission;
    size_t datum_token_emission_size;
    dap_chain_hash_fast_t tx_used_out;
    dap_nanotime_t ts_added;
    UT_hash_handle hh;
} dap_chain_ledger_token_emission_item_t;

typedef struct dap_chain_ledger_token_update_item {
    dap_hash_fast_t			update_token_hash;
    dap_chain_datum_token_t	*datum_token_update;
    size_t					datum_token_update_size;
    time_t					updated_time;
    UT_hash_handle hh;
} dap_chain_ledger_token_update_item_t;

typedef struct dap_chain_ledger_token_item {
    uint16_t version;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint16_t type;
    uint16_t subtype;
    dap_chain_datum_token_t * datum_token;
    uint64_t datum_token_size;

    uint256_t total_supply;
    uint256_t current_supply;

    pthread_rwlock_t token_emissions_rwlock;
    dap_chain_ledger_token_emission_item_t * token_emissions;

    pthread_rwlock_t token_ts_updated_rwlock;
    dap_chain_ledger_token_update_item_t * token_ts_updated;
    time_t last_update_token_time;

    // for auth operations
    dap_pkey_t ** auth_pkeys;
    dap_chain_hash_fast_t *auth_pkeys_hash;
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
    dap_nanotime_t ts_added;
    struct {
        dap_time_t ts_created;
        uint32_t n_outs;
        uint32_t n_outs_used;
        char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        byte_t padding[6];
        byte_t multichannel;
        byte_t pad[15];
        // TODO dynamically allocates the memory in order not to limit the number of outputs in transaction
        dap_chain_hash_fast_t tx_hash_spent_fast[MAX_OUT_ITEMS]; // spent outs list
    } DAP_ALIGN_PACKED cache_data;
    UT_hash_handle hh;
} dap_chain_ledger_tx_item_t;

typedef struct dap_chain_ledger_tx_spent_item {
    dap_chain_hash_fast_t tx_hash_fast;
    struct {
        dap_time_t spent_time;
        char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        char padding[22];
        dap_chain_hash_fast_t tx_hash_spent_fast; // spent outs list
    } DAP_ALIGN_PACKED cache_data;
    UT_hash_handle hh;
} dap_chain_ledger_tx_spent_item_t;

typedef struct dap_chain_ledger_tokenizer {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t sum;
    UT_hash_handle hh;
} dap_chain_ledger_tokenizer_t;

typedef struct dap_chain_ledger_tx_bound {
    dap_chain_hash_fast_t tx_prev_hash;
    dap_chain_datum_tx_t *tx_prev;
    union {
        dap_chain_tx_in_t *tx_cur_in;
        dap_chain_tx_in_cond_t *tx_cur_in_cond;
        dap_chain_tx_in_ems_t *tx_cur_in_ems;
    } in;
    union {
        dap_chain_tx_out_old_t *tx_prev_out;
        // 256
        dap_chain_tx_out_t *tx_prev_out_256;
        dap_chain_tx_out_ext_t *tx_prev_out_ext_256;
        dap_chain_tx_out_cond_t *tx_prev_out_cond_256;
    } out;
    union {
        dap_chain_ledger_tx_item_t *item_out;
        dap_chain_ledger_token_emission_item_t *item_emission;
        dap_chain_ledger_stake_lock_item_t *stake_lock_item;
    };
} dap_chain_ledger_tx_bound_t;

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

typedef struct dap_chain_ledger_tx_notifier {
    dap_chain_ledger_tx_add_notify_t callback;
    void *arg;
} dap_chain_ledger_tx_notifier_t;

typedef struct dap_chain_ledger_bridged_tx_notificator {
    dap_chain_ledger_bridged_tx_notify_t callback;
    void *arg;
} dap_chain_ledger_bridged_tx_notificator_t;

// dap_ledget_t private section
typedef struct dap_ledger_private {
    const char *net_native_ticker;
    uint256_t fee_value;
    dap_chain_addr_t fee_addr;
    dap_list_t *poa_certs;
    // List of ledger - unspent transactions cache
    dap_chain_ledger_tx_item_t *threshold_txs;
    dap_chain_ledger_token_emission_item_t * threshold_emissions;

    dap_chain_ledger_tx_item_t *ledger_items;
    dap_chain_ledger_tx_spent_item_t *spent_items;
    dap_chain_ledger_token_item_t *tokens;
    dap_chain_ledger_stake_lock_item_t *emissions_for_stake_lock;
    dap_ledger_wallet_balance_t *balance_accounts;

    // for separate access to ledger
    pthread_rwlock_t ledger_rwlock;
    // for separate access to tokens
    pthread_rwlock_t tokens_rwlock;
    pthread_rwlock_t stake_lock_rwlock;
    pthread_rwlock_t threshold_txs_rwlock;
    pthread_rwlock_t threshold_emissions_rwlock;
    pthread_rwlock_t balance_accounts_rwlock;

    // Save/load operations condition
    pthread_mutex_t load_mutex;
    pthread_cond_t load_cond;
    bool load_end;

    uint16_t flags;
    bool check_ds;
    bool check_cells_ds;
    bool check_token_emission;
    dap_chain_cell_id_t local_cell_id;

    //Notificators
    dap_list_t *bridged_tx_notificators;
    dap_list_t *tx_add_notifiers;

    bool load_mode;
    bool cached;
    dap_chain_ledger_cache_tx_check_callback_t cache_tx_check_callback;
    // TPS section
    dap_timerfd_t *tps_timer;
    struct timespec tps_start_time;
    struct timespec tps_current_time;
    struct timespec tps_end_time;
    size_t tps_count;
    // Threshold fee
    dap_interval_timer_t threshold_txs_free_timer, threshold_emissions_free_timer;
} dap_ledger_private_t;
#define PVT(a) ( (dap_ledger_private_t* ) a->_internal )

typedef struct dap_ledger_hal_item {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_ledger_hal_item_t;

static dap_ledger_hal_item_t *s_hal_items = NULL;

static  dap_chain_ledger_tx_item_t* tx_item_find_by_addr(dap_ledger_t *a_ledger,
        const dap_chain_addr_t *a_addr, const char * a_token, dap_chain_hash_fast_t *a_tx_first_hash);
static void s_threshold_emissions_proc( dap_ledger_t * a_ledger);
static void s_threshold_txs_proc( dap_ledger_t * a_ledger);
static void s_threshold_txs_free(dap_ledger_t *a_ledger);
static void s_threshold_emission_free(dap_ledger_t *a_ledger);
static int s_token_tsd_parse(dap_ledger_t * a_ledger, dap_chain_ledger_token_item_t *a_token_item , dap_chain_datum_token_t * a_token, size_t a_token_size);
static int s_tsd_sign_apply(dap_ledger_t *a_ledger, dap_chain_ledger_token_item_t *a_token_item , dap_chain_datum_token_t *a_token, size_t a_token_size);
static int s_ledger_permissions_check(dap_chain_ledger_token_item_t *  a_token_item, uint16_t a_permission_id, const void * a_data,size_t a_data_size );
static bool s_ledger_tps_callback(void *a_arg);
static int s_sort_ledger_tx_item(dap_chain_ledger_tx_item_t* a, dap_chain_ledger_tx_item_t* b);

static inline int s_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold, bool a_safe_call);
static int s_tx_add_unsafe(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold);

static int s_token_emission_add_unsafe(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size,
                                        dap_hash_fast_t *a_emission_hash, bool a_from_threshold);
static inline int s_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size,
                                        dap_hash_fast_t *a_emission_hash, bool a_from_threshold, bool a_safe_call);

static size_t s_threshold_emissions_max = 1000;
static size_t s_threshold_txs_max = 10000;
static bool s_debug_more = false;
static size_t s_threshold_free_timer_tick = 900000; // 900000 ms = 15 minutes.

struct json_object *wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t* a_bal);

/**
 * @brief dap_chain_ledger_init
 * current function version set s_debug_more parameter, if it define in config, and returns 0
 * @return
 */
int dap_chain_ledger_init()
{
    s_debug_more = dap_config_get_item_bool_default(g_config,"ledger","debug_more",false);
    pthread_rwlock_init(&s_verificators_rwlock, NULL);
    return 0;
}

/**
 * @brief dap_chain_ledger_deinit
 * nothing do
 */
void dap_chain_ledger_deinit()
{
    // TODO write correct deinit of all net ledgers
/*    uint16_t l_net_count = 0;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for(uint16_t i =0; i < l_net_count; i++) {
        dap_chain_ledger_purge(l_net_list[i]->pub.ledger, true);
    }
    DAP_DELETE(l_net_list); */
    pthread_rwlock_destroy(&s_verificators_rwlock);
}

/**
 * @brief dap_chain_ledger_handle_new
 * Create empty dap_ledger_t structure
 * @return dap_ledger_t*
 */
static dap_ledger_t * dap_chain_ledger_handle_new(void)
{
    dap_ledger_t *l_ledger = DAP_NEW_Z(dap_ledger_t);
    if ( !l_ledger ) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    dap_ledger_private_t * l_ledger_pvt;
    l_ledger->_internal = l_ledger_pvt = DAP_NEW_Z(dap_ledger_private_t);
    if ( !l_ledger_pvt ) {
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_ledger);
        return NULL;
    }
    // Initialize Read/Write Lock Attribute
    pthread_rwlock_init(&l_ledger_pvt->ledger_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->tokens_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->threshold_txs_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->threshold_emissions_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->balance_accounts_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->stake_lock_rwlock, NULL);
    l_ledger_pvt->threshold_txs_free_timer = dap_interval_timer_create(s_threshold_free_timer_tick,
                                                                      (dap_timer_callback_t)s_threshold_txs_free, l_ledger);
    l_ledger_pvt->threshold_emissions_free_timer = dap_interval_timer_create(s_threshold_free_timer_tick,
                                                                            (dap_timer_callback_t) s_threshold_emission_free, l_ledger);
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
    pthread_rwlock_destroy(&PVT(a_ledger)->threshold_txs_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->threshold_emissions_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->balance_accounts_rwlock);
    pthread_rwlock_destroy(&PVT(a_ledger)->stake_lock_rwlock);
    DAP_DELETE(PVT(a_ledger));
    DAP_DELETE(a_ledger);

}

void dap_chain_ledger_load_end(dap_ledger_t *a_ledger)
{
    PVT(a_ledger)->load_mode = false;
}

struct json_object *wallet_info_json_collect(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_bal) {
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class", json_object_new_string("Wallet"));
    struct json_object *l_network = json_object_new_object();
    json_object_object_add(l_network, "name", json_object_new_string(a_ledger->net_name));
    char *pos = strrchr(a_bal->key, ' ');
    if (pos) {
        size_t l_addr_len = pos - a_bal->key;
        char *l_addr_str = DAP_NEW_STACK_SIZE(char, l_addr_len + 1);
        if ( !l_addr_str )
        log_it(L_CRITICAL, "Memory allocation error");
        memcpy(l_addr_str, a_bal->key, pos - a_bal->key);
        *(l_addr_str + l_addr_len) = '\0';
        json_object_object_add(l_network, "address", json_object_new_string(l_addr_str));
    } else {
        json_object_object_add(l_network, "address", json_object_new_string("Unknown"));
    }
    struct json_object *l_token = json_object_new_object();
    json_object_object_add(l_token, "name", json_object_new_string(a_bal->token_ticker));
    char *l_balance_coins = dap_chain_balance_to_coins(a_bal->balance);
    char *l_balance_datoshi = dap_chain_balance_print(a_bal->balance);
    json_object_object_add(l_token, "full_balance", json_object_new_string(l_balance_coins));
    json_object_object_add(l_token, "datoshi", json_object_new_string(l_balance_datoshi));
    DAP_DELETE(l_balance_coins);
    DAP_DELETE(l_balance_datoshi);
    json_object_object_add(l_network, "tokens", l_token);
    json_object_object_add(l_json, "networks", l_network);
    return l_json;
}

/**
 * @brief s_chain_ledger_token_update_check
 * @param a_cur_token_item
 * @param a_token_update
 * @param a_token_update_size
 * @return true or false
 */
static bool s_ledger_token_update_check(dap_chain_ledger_token_item_t *a_cur_token_item, dap_chain_datum_token_t *a_token_update, size_t a_token_update_size)
{
    dap_sign_t								**l_signs_upd_token;
    size_t									auth_signs_total = 0;
    size_t									auth_signs_valid = 0;
    dap_chain_ledger_token_update_item_t	*l_token_update_item;
    dap_hash_fast_t							l_hash_token_update;

    dap_hash_fast(a_token_update, a_token_update_size, &l_hash_token_update);
    pthread_rwlock_rdlock(&a_cur_token_item->token_ts_updated_rwlock);
    HASH_FIND(hh, a_cur_token_item->token_ts_updated, &l_hash_token_update, sizeof(dap_hash_fast_t),
              l_token_update_item);
    pthread_rwlock_unlock(&a_cur_token_item->token_ts_updated_rwlock);
    if (l_token_update_item
    &&	a_cur_token_item->last_update_token_time == l_token_update_item->updated_time) {
        if (s_debug_more)
            log_it(L_WARNING,"This update for token '%s' was already applied", a_token_update->ticker);
        return false;
    }

    /*if (a_cur_token_item->auth_signs_total != a_token_update->signs_total
    ||	a_cur_token_item->auth_signs_valid != a_token_update->signs_valid) {
        if(s_debug_more)
            log_it(L_WARNING,"Can't update token with ticker '%s' because: "
                             "l_token_item auth signs total/valid == %lu/%lu | "
                             "token_update auth signs total/valid == %hu/%hu",
                   a_token_update->ticker,
                   a_cur_token_item->auth_signs_total, a_cur_token_item->auth_signs_valid,
                   a_token_update->signs_total, a_token_update->signs_valid);
        return false;
    }*/

    l_signs_upd_token = dap_chain_datum_token_signs_parse(a_token_update, a_token_update_size,
                                                          &auth_signs_total, &auth_signs_valid);
    if (a_cur_token_item->auth_signs_valid > auth_signs_total) {
        DAP_DEL_Z(l_signs_upd_token);
        if(s_debug_more)
            log_it(L_WARNING,"Can't update token with ticker '%s' because: "
                             "l_token_item auth signs total/valid == %lu/%lu | "
                             "token_update auth signs total/valid == %lu/%lu",
                   a_token_update->ticker,
                   a_cur_token_item->auth_signs_total, a_cur_token_item->auth_signs_valid,
                   auth_signs_total, auth_signs_valid);
        return false;
    }
    if(auth_signs_total) {
        size_t l_valid_pkeys = 0;
        for(uint16_t i = 0; i < auth_signs_total; i++){
            dap_pkey_t *l_pkey_upd_token = dap_pkey_get_from_sign_deserialization(l_signs_upd_token[i]);
            for (size_t j = 0; j < a_cur_token_item->auth_signs_total; j++) {
                if (dap_pkey_match(a_cur_token_item->auth_pkeys[j], l_pkey_upd_token)) {
                    l_valid_pkeys++;
                    break;
                }
            }
            DAP_DELETE(l_pkey_upd_token);
        }
        if (a_cur_token_item->auth_signs_valid > l_valid_pkeys) {
            DAP_DEL_Z(l_signs_upd_token);
            if (s_debug_more)
                log_it(L_WARNING, "Can't update token with ticker '%s' because: Insufficient number of valid signatures "
                                  "for an token update. Verified %zu needs %zu.", a_token_update->ticker, l_valid_pkeys,
                                  a_cur_token_item->auth_signs_valid);
            return false;
        }
    }
    DAP_DEL_Z(l_signs_upd_token);
    if (!IS_ZERO_256(a_token_update->total_supply)){
        if (compare256(a_token_update->total_supply, a_cur_token_item->total_supply) < 0) {//compare old 'total_supply' to updated
            if(s_debug_more)
                log_it(L_WARNING, "Can't update token with ticker '%s' because: the new 'total_supply' cannot be smaller than the old one", a_token_update->ticker);
            return false;
        }
    }
    // Check edit auth signs
    size_t l_tsd_total_size = 0;
    if (a_token_update->subtype  == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)
        l_tsd_total_size = a_token_update->header_native_update.tsd_total_size;
    else if (a_token_update->subtype  == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
        l_tsd_total_size = a_token_update->header_native_update.tsd_total_size;
    // Checking that the TSD section with the threshold change is the only one.
    //And getting lists of TSD sections with the removal and addition of certificates.
    int l_quantity_tsd_section_edit_signs_emission = 0;
    dap_tsd_t *l_tsd_signs_valid = NULL;
    dap_list_t *l_tsd_list_remote_pkeys = NULL, *l_tsd_list_added_pkeys = NULL;
    int l_quantity_tsd_remote_pkeys = 0, l_quantity_tsd_add_pkeys = 0;
    for (size_t l_tsd_offset = 0; l_tsd_offset < l_tsd_total_size; ) {
        dap_tsd_t *l_tsd = (dap_tsd_t*)((byte_t*)a_token_update->data_n_tsd + l_tsd_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if (l_tsd_size == 0) {
            if (s_debug_more)
                log_it(L_ERROR, "Token refresh datum %s contains a non-valid TSD section. Size TSD section is 0.", a_token_update->ticker);
            return false;
        } else if (l_tsd_size + l_tsd_offset > l_tsd_total_size) {
            if (s_debug_more)
                log_it(L_ERROR, "Token refresh datum %s contains a non-valid TSD section. "
                                "The size of the TSD section and the offset exceed the set size of the TSD sections.", a_token_update->ticker);
            return false;
        }
        switch (l_tsd->type) {
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID:
                l_quantity_tsd_section_edit_signs_emission++;
                l_tsd_signs_valid = l_tsd;
                break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE:
                l_quantity_tsd_remote_pkeys++;
                l_tsd_list_remote_pkeys = dap_list_append(l_tsd_list_remote_pkeys, l_tsd);
                break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD:
                l_quantity_tsd_add_pkeys++;
                l_tsd_list_added_pkeys = dap_list_append(l_tsd_list_added_pkeys, l_tsd);
                break;
        }
        l_tsd_offset += l_tsd_size;
    }
    if (l_quantity_tsd_section_edit_signs_emission > 1) {
        if (s_debug_more) {
            log_it(L_ERROR, "Datum contains %ud TSD sections of type DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID which is not true. "
                            "There can be at most one such TSD section.", l_quantity_tsd_section_edit_signs_emission);
        }
        dap_list_free(l_tsd_list_added_pkeys);
        dap_list_free(l_tsd_list_remote_pkeys);
        return false;
    }
    //Check new count signs
    size_t l_new_signs_total = auth_signs_total + l_quantity_tsd_add_pkeys - l_quantity_tsd_remote_pkeys;
    if (l_tsd_signs_valid) {
        uint16_t l_signs_valid_from_tsd = 0;
        _dap_tsd_get_scalar(l_tsd_signs_valid, &l_signs_valid_from_tsd);
        if (l_new_signs_total < (size_t)l_signs_valid_from_tsd || l_signs_valid_from_tsd < 1) {
            dap_list_free(l_tsd_list_added_pkeys);
            dap_list_free(l_tsd_list_remote_pkeys);
            return false;
        }
    } else {
        if (l_new_signs_total < auth_signs_valid){
            dap_list_free(l_tsd_list_added_pkeys);
            dap_list_free(l_tsd_list_remote_pkeys);
            return false;
        }
    }
    //Check valid remove_signs
    bool isAccepted = false;
    if (!l_tsd_list_remote_pkeys)
        isAccepted = true;
    else {
        for (dap_list_t *l_ptr = l_tsd_list_remote_pkeys; l_ptr; l_ptr = dap_list_next(l_ptr)) {
            dap_tsd_t *l_tsd = (dap_tsd_t *) l_ptr->data;
            dap_hash_fast_t l_hash = { };
            _dap_tsd_get_scalar(l_tsd, &l_hash);
            bool accepted = false;
            for (size_t i = 0; i < auth_signs_total; i++) {
                if (dap_hash_fast_compare(&a_cur_token_item->auth_pkeys_hash[i], &l_hash)) {
                    accepted = true;
                    break;
                }
            }
            if (!accepted) {
                if (s_debug_more) {
                    char *l_hash_str = dap_hash_fast_to_str_new(&l_hash);
                    log_it(L_ERROR,
                           "It is expected that the TSD parameter DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE will contain only "
                           "the hashes of the public keys of the signatures with which the given token was previously signed. But not %s",
                           l_hash_str);
                    DAP_DELETE(l_hash_str);
                }
            }
            isAccepted = accepted;
        }
    }
    if (!isAccepted) {
        dap_list_free(l_tsd_list_added_pkeys);
        dap_list_free(l_tsd_list_remote_pkeys);
        return false;
    }
    //Check added signs
    dap_chain_datum_token_t *l_token_tmp = DAP_DUP_SIZE(a_token_update, a_token_update_size);
    if (!l_token_tmp) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_list_free(l_tsd_list_added_pkeys);
        dap_list_free(l_tsd_list_remote_pkeys);
        return false;
    }

    l_token_tmp->header_native_update.tsd_total_size = 0;
    isAccepted = true;
    for (dap_list_t *l_ptr = l_tsd_list_added_pkeys; l_ptr; l_ptr = dap_list_next(l_ptr)) {
        dap_tsd_t *l_tsd = (dap_tsd_t*)l_ptr->data;
        if (l_tsd->size >= sizeof(dap_pkey_t)) {
            dap_pkey_t *l_pkey = (dap_pkey_t *) l_tsd->data;
            dap_hash_fast_t l_hf_pkey = {0};
            if (!dap_pkey_get_hash(l_pkey, &l_hf_pkey)) {
                if (s_debug_more)
                    log_it(L_ERROR, "Failed to calculate the hash for the public key located in the "
                                    "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD section of the TSD");
                isAccepted = false;
                break;
            }
            for (size_t i = 0; i < a_cur_token_item->auth_signs_total; i++) {
                if (dap_hash_fast_compare(&l_hf_pkey, &a_cur_token_item->auth_pkeys_hash[i])) {
                    if (s_debug_more) {
                        char *l_hf_str = dap_hash_fast_to_str_new(&l_hf_pkey);
                        log_it(L_ERROR, "The public key with hash %s from the TSD section of the type "
                                        "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD cannot be added, because such "
                                        "a key already exists in the ledger.", l_hf_str);
                        DAP_DELETE(l_hf_str);
                    }
                    isAccepted = false;
                    break;
                }
            }
        } else {
            if (s_debug_more)
                log_it(L_ERROR, "It is expected that the size %zu of information from the TSD section of type "
                                "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD will be greater than or equal to %zu.",
                       dap_tsd_size(l_tsd), sizeof(dap_pkey_t));
            isAccepted = false;
            break;
        }
    }
    dap_list_free(l_tsd_list_added_pkeys);
    dap_list_free(l_tsd_list_remote_pkeys);
    DAP_DELETE(l_token_tmp);
    return isAccepted;
}


/**
 * @brief dap_chain_ledger_token_check
 * @param a_ledger
 * @param a_token
 * @param a_token_size
 * @return
 */
int dap_chain_ledger_token_decl_add_check(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if ( !a_ledger){
        if(s_debug_more)
            log_it(L_ERROR, "NULL ledger, can't add datum with token declaration!");
        return  DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_LEDGER_IS_NULL;
    }


    bool update_token = false;
    dap_chain_ledger_token_item_t *l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token->ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    if (a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE)
        update_token = true;

    if	(l_token_item != NULL) {
        if (update_token == false) {
            log_it(L_WARNING,"Duplicate token declaration for ticker '%s' ", a_token->ticker);
            return DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_DECL_DUPLICATE;
        } else if (s_ledger_token_update_check(l_token_item, a_token, a_token_size) == false) {
            return DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_CHECK;
        }
    }
    else if	(l_token_item == NULL && update_token == true) {
        log_it(L_WARNING,"Can't update token that doesn't exist for ticker '%s' ", a_token->ticker);
        return DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_ABSENT_TOKEN;
    }
    // Check signs
    size_t l_signs_unique = 0;
    size_t l_size_tsd_section = 0;
    switch (a_token->type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL: {
            switch (a_token->subtype) {
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
                    l_size_tsd_section = a_token->header_private_decl.tsd_total_size; break;
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
                    l_size_tsd_section = a_token->header_native_decl.tsd_total_size; break;
            }
        }break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE: {
            switch (a_token->subtype) {
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
                    l_size_tsd_section = a_token->header_private_update.tsd_total_size; break;
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
                    l_size_tsd_section = a_token->header_native_update.tsd_total_size; break;
            }
        } break;
    }
    size_t l_signs_size = a_token_size - sizeof(dap_chain_datum_token_t) - l_size_tsd_section;
    dap_sign_t **l_signs = dap_sign_get_unique_signs(a_token->data_n_tsd + l_size_tsd_section, l_signs_size, &l_signs_unique);
    if (l_signs_unique == a_token->signs_total){
        size_t l_signs_approve = 0;
        uint16_t l_tmp_auth_signs = a_token->signs_total;
        if (a_token->version == 2) a_token->signs_total = 0;
        for (size_t i=0; i < l_signs_unique; i++)
            if (!dap_sign_verify_all(l_signs[i], l_signs_size, a_token, sizeof(dap_chain_datum_token_t)+l_size_tsd_section))
                l_signs_approve++;
        a_token->signs_total = l_tmp_auth_signs;
        if (l_signs_approve == a_token->signs_total){
            return DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_OK;
        } else {
            log_it(L_WARNING, "The token declaration has %zu valid signatures out of %hu.", l_signs_approve, a_token->signs_total);
            return DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_NOT_ENOUGH_VALID_SIGN;
        }
    } else {
        log_it(L_WARNING, "The number of unique token signs %zu is less than total token signs set to %hu.",
               l_signs_unique, a_token->signs_total);
        return DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOTAL_SIGNS_EXCEED_UNIQUE_SIGNS;
    }
    // Checks passed
    return DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_OK;
}

char *dap_chain_ledger_token_decl_add_err_code_to_str(int a_code) {
    return (a_code >= DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_OK) && (a_code < DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_UNKNOWN)
            ? (char*)s_ledger_token_decl_err_str[(dap_chain_ledger_token_decl_add_err_t)a_code]
            : dap_itoa(a_code);
}

/**
 * @brief dap_chain_ledger_token_ticker_check
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
dap_chain_datum_token_t *dap_chain_ledger_token_ticker_check(dap_ledger_t * a_ledger, const char *a_token_ticker)
{
    if ( !a_ledger){
        if(s_debug_more)
            log_it(L_WARNING, "NULL ledger, can't find token ticker");
        return NULL;
    }
    dap_chain_ledger_token_item_t *l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token_ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_token_item ? l_token_item->datum_token : NULL;
}

/**
 * @brief s_tx_header_print
 * prepare data for print, add time
 *
 * return history string
 * @param a_tx
 * @param a_tx_hash
 * @param a_hash_out_type
 * @return a_str_out
 */

static void s_tx_header_print(dap_string_t *a_str_out, dap_chain_datum_tx_t *a_tx,
                              const char *a_hash_out_type, dap_chain_hash_fast_t *a_tx_hash)
{
    char l_time_str[32] = "unknown";
    if (a_tx->header.ts_created) {
        uint64_t l_ts = a_tx->header.ts_created;
        dap_ctime_r(&l_ts, l_time_str);
    }
    char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str(a_tx_hash)
            : dap_chain_hash_fast_to_str_new(a_tx_hash);
    dap_string_append_printf(a_str_out, "TX hash %s  \n\t%s",l_tx_hash_str, l_time_str);
    DAP_DELETE(l_tx_hash_str);
}

char * dap_ledger_token_tx_item_list(dap_ledger_t * a_ledger, dap_chain_addr_t *a_addr, const char *a_hash_out_type)
{
        dap_string_t *l_str_out =dap_string_new(NULL);
        if (!l_str_out) {
        log_it(L_CRITICAL, "Memory allocation error");
            return NULL;
        }

        //dap_chain_tx_hash_processed_ht_t *l_tx_data_ht = NULL;
        dap_chain_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
        dap_ledger_private_t * l_ledger_pvt = PVT(a_ledger);

        pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
        //unsigned test = dap_chain_ledger_count(a_ledger);
        HASH_ITER(hh, l_ledger_pvt->ledger_items, l_tx_item, l_tx_tmp) {

            dap_chain_datum_tx_t *l_tx = l_tx_item->tx;
            dap_chain_hash_fast_t *l_tx_hash = &l_tx_item->tx_hash_fast;
            dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_ALL, NULL);
            if (!l_list_in_items) { // a bad tx
                continue;
            }
            dap_chain_addr_t *l_src_addr = NULL;
            bool l_base_tx = false;
            const char *l_src_token = NULL;
            int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
            dap_list_t *l_in_item;
            DL_FOREACH(l_list_in_items, l_in_item) {
                //assert(it->data);
                dap_chain_hash_fast_t *l_tx_prev_hash;
                int l_tx_prev_out_idx;
                dap_chain_datum_tx_t *l_tx_prev = NULL;
                if (*(byte_t*)l_in_item->data == TX_ITEM_TYPE_IN) {
                    dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t*)l_in_item->data;
                    l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                    l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
                } else { // TX_ITEM_TYPE_IN_COND
                    dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t*)l_in_item->data;
                    l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                    l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
                }
                if (dap_hash_fast_is_blank(l_tx_prev_hash)) {
                    l_base_tx = true;
                    dap_chain_tx_in_ems_t *l_token = (dap_chain_tx_in_ems_t *)dap_chain_datum_tx_item_get(
                                                                            l_tx, NULL, TX_ITEM_TYPE_IN_EMS, NULL);
                    if (l_token)
                        l_src_token = l_token->header.ticker;
                    break;
                }
                l_tx_prev = dap_chain_ledger_tx_find_by_hash (a_ledger,l_tx_prev_hash);
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
                        l_src_token = (const char *)(((dap_chain_tx_out_ext_t *)l_prev_out_union)->token);
                        break;
                    case TX_ITEM_TYPE_OUT_COND:
                        l_src_subtype = ((dap_chain_tx_out_cond_t *)l_prev_out_union)->header.subtype;
                    default:
                        break;
                    }
                }
                else
                {
                    continue; //temporary stub
                }
                if (!l_src_token){
                    l_src_token = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, l_tx_prev_hash);
                    l_src_token = l_tx_item->cache_data.token_ticker;
                }
                if (l_src_addr && memcmp(l_src_addr, a_addr, sizeof(dap_chain_addr_t)))
                    break;  //it's not our addr
            }
            dap_list_free(l_list_in_items);

            bool l_header_printed = false;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
            if(!l_list_out_items)
                continue;
            for(dap_list_t *l_list_out = l_list_out_items; l_list_out; l_list_out = dap_list_next(l_list_out)) {
                assert(l_list_out->data);
                dap_chain_addr_t *l_dst_addr = NULL;
                dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_out->data;
                uint256_t l_value;
                switch (l_type) {
                case TX_ITEM_TYPE_OUT:
                    l_dst_addr = &((dap_chain_tx_out_t *)l_list_out->data)->addr;
                    l_value = ((dap_chain_tx_out_t *)l_list_out->data)->header.value;
                    break;
                case TX_ITEM_TYPE_OUT_EXT:
                    l_dst_addr = &((dap_chain_tx_out_ext_t *)l_list_out->data)->addr;
                    l_value = ((dap_chain_tx_out_ext_t *)l_list_out->data)->header.value;
                    break;
                case TX_ITEM_TYPE_OUT_COND:
                    l_value = ((dap_chain_tx_out_cond_t *)l_list_out->data)->header.value;
                default:
                    break;
                }
                if (l_src_addr && l_dst_addr && !memcmp(l_dst_addr, l_src_addr, sizeof(dap_chain_addr_t)))
                    continue;   // send to self
                if (l_src_addr && !memcmp(l_src_addr, a_addr, sizeof(dap_chain_addr_t))) {
                    if (!l_header_printed) {
                        s_tx_header_print(l_str_out, l_tx, a_hash_out_type, l_tx_hash);
                        l_header_printed = true;
                    }
                    //const char *l_token_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash);
                    const char *l_dst_addr_str = l_dst_addr ? dap_chain_addr_to_str(l_dst_addr)
                                                            : dap_chain_tx_out_cond_subtype_to_str(
                                                                  ((dap_chain_tx_out_cond_t *)l_list_out->data)->header.subtype);
                    char *l_value_str = dap_chain_balance_print(l_value);
                    dap_string_append_printf(l_str_out, "\tsend %s %s to %s\n",
                                             l_value_str,
                                             l_src_token ? l_src_token : "UNKNOWN",
                                             l_dst_addr_str);
                    if (l_dst_addr)
                        DAP_DELETE(l_dst_addr_str);
                    DAP_DELETE(l_value_str);
                }
                if (l_dst_addr && !memcmp(l_dst_addr, a_addr, sizeof(dap_chain_addr_t))) {
                    if (!l_header_printed) {
                       s_tx_header_print(l_str_out, l_tx, a_hash_out_type, l_tx_hash);
                       l_header_printed = true;
                    }
                    const char *l_dst_token = (l_type == TX_ITEM_TYPE_OUT_EXT) ?
                                (const char *)(((dap_chain_tx_out_ext_t *)l_list_out->data)->token) : NULL;
                    const char *l_src_addr_str = l_base_tx ? "emission"
                                                           : (l_src_addr ? dap_chain_addr_to_str(l_src_addr)
                                                                         : dap_chain_tx_out_cond_subtype_to_str(
                                                                               l_src_subtype));
                    char *l_value_str = dap_chain_balance_print(l_value);
                    dap_string_append_printf(l_str_out, "\trecv %s %s from %s\n",
                                             l_value_str,
                                             l_dst_token ? l_dst_token :
                                                           (l_src_token ? l_src_token : "UNKNOWN"),
                                             l_src_addr_str);
                    if (l_src_addr)
                        DAP_DELETE(l_src_addr_str);
                    DAP_DELETE(l_value_str);
                }
            }
            dap_list_free(l_list_out_items);
        }
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);

        // if no history
        if(!l_str_out->len)
            dap_string_append(l_str_out, "\tempty");
        char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
        return l_ret_str;
}

/**
 * @brief update current_supply in token cache
 *
 * @param a_ledger ledger object
 * @param l_token_item token item object
 */
void s_ledger_token_cache_update(dap_ledger_t *a_ledger, dap_chain_ledger_token_item_t *l_token_item)
{
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TOKENS_STR);
    size_t l_cache_size = l_token_item->datum_token_size + sizeof(uint256_t);
    uint8_t *l_cache = DAP_NEW_STACK_SIZE(uint8_t, l_cache_size);
    if ( !l_cache ) {
        log_it(L_CRITICAL, "Memory allocation error");
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

/**
 * @brief s_ledger_update_token_add_in_hash_table
 * @param a_cur_token_item
 * @param a_token_update
 * @param a_token_update_size
 * @return true or false
 */
static bool s_ledger_update_token_add_in_hash_table(dap_chain_ledger_token_item_t *a_cur_token_item, dap_chain_datum_token_t *a_token_update, size_t a_token_update_size)
{
    dap_chain_ledger_token_update_item_t	*l_token_update_item;
    dap_hash_fast_t							l_hash_token_update;
    bool									new_item = false;

    dap_hash_fast(a_token_update, a_token_update_size, &l_hash_token_update);
    pthread_rwlock_rdlock(&a_cur_token_item->token_ts_updated_rwlock);
    HASH_FIND(hh, a_cur_token_item->token_ts_updated, &l_hash_token_update, sizeof(dap_hash_fast_t),
              l_token_update_item);
    pthread_rwlock_unlock(&a_cur_token_item->token_ts_updated_rwlock);
    if (l_token_update_item
    &&	a_cur_token_item->last_update_token_time == l_token_update_item->updated_time) {
        if (s_debug_more)
            log_it(L_WARNING, "Error: item 'dap_chain_ledger_token_update_item_t' already exist in hash-table");
        return false;
    } else if (!l_token_update_item){
        new_item = true;
        l_token_update_item = DAP_NEW(dap_chain_ledger_token_update_item_t);
        if (!l_token_update_item) {
            if (s_debug_more)
                log_it(L_ERROR, "Error: memory allocation when try adding item 'dap_chain_ledger_token_update_item_t' to hash-table");
            return false;
        }
        *l_token_update_item = (dap_chain_ledger_token_update_item_t) {
                .update_token_hash			= l_hash_token_update,
                .datum_token_update			= a_token_update,
                .datum_token_update_size	= a_token_update_size
        };
    }

    l_token_update_item->updated_time		= dap_time_now();

    if (new_item) {
        pthread_rwlock_wrlock(&a_cur_token_item->token_ts_updated_rwlock);
        HASH_ADD(hh, a_cur_token_item->token_ts_updated, update_token_hash, sizeof(dap_chain_hash_fast_t), l_token_update_item);
        pthread_rwlock_unlock(&a_cur_token_item->token_ts_updated_rwlock);
    }

    if (!l_token_update_item) {
        if (s_debug_more)
            log_it(L_ERROR, "Error: adding to hash-table. Be careful, there may be leaks");
        return false;
    }

    a_cur_token_item->last_update_token_time = l_token_update_item->updated_time;

    return true;
}

/**
 * @brief dap_chain_ledger_token_add
 * @param a_token
 * @param a_token_size
 * @return
 */
int dap_chain_ledger_token_add(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size) {
    if (!a_ledger || !a_token) {
        debug_if(s_debug_more, L_ERROR, "NULL ledger, can't add datum with token declaration!");
        return -1;
    }

    dap_chain_datum_token_t *l_token = NULL;
    size_t l_token_size = a_token_size;

    switch (a_token->type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
            l_token = dap_chain_datum_token_read((byte_t *) a_token, &l_token_size);
            break;
        default:
            l_token = DAP_DUP_SIZE(a_token, a_token_size);
            if ( !l_token ) {
        log_it(L_CRITICAL, "Memory allocation error");
                return -6;
            }
            break;
    }

    dap_chain_ledger_token_item_t *l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, l_token->ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);

    if (l_token_item) {
        if (l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE) {
            log_it(L_ERROR, "Duplicate token declaration for ticker '%s'", l_token->ticker);
            DAP_DEL_Z(l_token);
            return -3;
        }
        if (s_ledger_token_update_check(l_token_item, l_token, l_token_size)) {
            if (!s_ledger_update_token_add_in_hash_table(l_token_item, l_token, l_token_size)) {
                log_it(L_ERROR, "Failed to update token with ticker '%s' in ledger", l_token->ticker);
                DAP_DEL_Z(l_token);
                return -5;
            }
            if (!IS_ZERO_256(l_token->total_supply)) {
                SUBTRACT_256_256(l_token_item->total_supply, l_token_item->current_supply, &l_token_item->current_supply);
                SUBTRACT_256_256(l_token->total_supply, l_token_item->current_supply, &l_token_item->current_supply);
            } else {
                l_token_item->current_supply = l_token->total_supply;
            }
            l_token_item->total_supply = l_token->total_supply;
            DAP_DELETE(l_token_item->datum_token);
        } else {
            log_it(L_ERROR, "Token with ticker '%s' update check failed", l_token->ticker);
            DAP_DEL_Z(l_token);
            return -2;
        }
    } else if (l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE) {
        log_it(L_WARNING, "Token with ticker '%s' does not yet exist, declare it first", l_token->ticker);
        DAP_DEL_Z(l_token);
        return -6;
    }

    if (!l_token_item) {
        size_t l_auth_signs_total, l_auth_signs_valid;
        dap_sign_t **l_signs = dap_chain_datum_token_signs_parse(l_token, l_token_size, &l_auth_signs_total, &l_auth_signs_valid);
        if (!l_signs || !l_auth_signs_total) {
            log_it(L_ERROR, "No auth signs in token '%s' datum!", l_token->ticker);
            DAP_DEL_Z(l_token);
            return -7;
        }
        l_token_item = DAP_NEW_Z(dap_chain_ledger_token_item_t);
        if ( !l_token_item ) {
            DAP_DEL_Z(l_token);
        log_it(L_CRITICAL, "Memory allocation error");
            return -8;
        }
        *l_token_item = (dap_chain_ledger_token_item_t) {
                .version        = l_token->version,
                .type           = l_token->type,
                .subtype        = l_token->subtype,
                .total_supply   = l_token->total_supply,
                .current_supply = l_token->total_supply,
                .token_emissions_rwlock     = PTHREAD_RWLOCK_INITIALIZER,
                .token_ts_updated_rwlock    = PTHREAD_RWLOCK_INITIALIZER,
                .auth_pkeys         = DAP_NEW_Z_SIZE(dap_pkey_t*, sizeof(dap_pkey_t*) * l_token->signs_total),
                .auth_pkeys_hash    = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, sizeof(dap_chain_hash_fast_t) * l_token->signs_total),
                .auth_signs_total   = l_auth_signs_total,
                .auth_signs_valid   = l_auth_signs_valid
        };
        if ( !l_token_item->auth_pkeys ) {
            if (l_token)
                DAP_DELETE(l_token);
            DAP_DELETE(l_token_item);
        log_it(L_CRITICAL, "Memory allocation error");
            return -6;
        };
        if ( !l_token_item->auth_pkeys ) {
            if (l_token)
                DAP_DELETE(l_token);
            DAP_DEL_Z(l_token_item->auth_pkeys);
            DAP_DELETE(l_token_item);
        log_it(L_CRITICAL, "Memory allocation error");
            return -6;
        }
        dap_stpcpy(l_token_item->ticker, l_token->ticker);
        for (uint16_t k = 0; k < l_token_item->auth_signs_total; k++) {
            l_token_item->auth_pkeys[k] = dap_pkey_get_from_sign_deserialization(l_signs[k]);
            dap_pkey_get_hash(l_token_item->auth_pkeys[k], &l_token_item->auth_pkeys_hash[k]);
        }
        DAP_DELETE(l_signs);
    }


    l_token_item->datum_token_size  = l_token_size;
    l_token_item->datum_token       = l_token;
    l_token_item->datum_token->type = l_token->type;

    if (l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE) {
        pthread_rwlock_wrlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_ADD_STR(PVT(a_ledger)->tokens, ticker, l_token_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    }
    int l_res_token_tsd_parse = 0;

    char *l_balance_dbg = s_debug_more ? dap_chain_balance_to_coins(l_token->total_supply) : NULL;

#define CLEAN_UP do { DAP_DELETE(l_token); \
    DAP_DELETE(l_token_item->auth_pkeys); \
    DAP_DELETE(l_token_item->auth_pkeys_hash); \
    DAP_DELETE(l_token_item); \
    DAP_DELETE(l_balance_dbg); } while (0);

    switch (l_token->type) {
    case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:
            debug_if(s_debug_more, L_INFO, "Simple token %s declared, total_supply: %s, total_signs_valid: %hu, signs_total: %hu",
                   l_token->ticker, l_balance_dbg,
                   l_token->signs_valid, l_token->signs_total);
            break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            debug_if(s_debug_more, L_INFO, "Private token %s declared, total_supply: %s, total_signs_valid: %hu, signs_total: %hu",
                    l_token->ticker, l_balance_dbg,
                    l_token->signs_valid, l_token->signs_total);
            l_res_token_tsd_parse = s_token_tsd_parse(a_ledger, l_token_item, l_token, l_token_size);
            s_tsd_sign_apply(a_ledger, l_token_item, l_token, l_token_size);
            break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            debug_if(s_debug_more, L_INFO, "CF20 token %s declared, total_supply: %s, total_signs_valid: %hu, signs_total: %hu",
                    l_token->ticker, l_balance_dbg,
                    l_token->signs_valid, l_token->signs_total);
            l_res_token_tsd_parse = s_token_tsd_parse(a_ledger, l_token_item, l_token, l_token_size);
            s_tsd_sign_apply(a_ledger, l_token_item, l_token, l_token_size);
            break;
        default:
            /* Bogdanoff, unknown token subtype declaration. What shall we TODO? */
            debug_if(s_debug_more, L_ERROR, "Unknown token subtype '0x%04X' declaration! Ticker: %s, total_supply: %s, total_signs_valid: %hu, signs_total: %hu"
                     "Dump it!",
                   l_token->type, l_token->ticker, l_balance_dbg,
                   l_token->signs_valid, l_token->signs_total);
            /* Dump it right now */
            CLEAN_UP;
            return -8;
        } break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
        switch (l_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:
            debug_if(s_debug_more, L_INFO, "Simple token %s updated, total_supply: %s, total_signs_valid: %hu, signs_total: %hu",
                   l_token->ticker, l_balance_dbg,
                   l_token->signs_valid, l_token->signs_total);
            break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
            debug_if(s_debug_more, L_INFO, "Private token %s updated, total_supply: %s, total_signs_valid: %hu, signs_total: %hu",
                    l_token->ticker, l_balance_dbg,
                    l_token->signs_valid, l_token->signs_total);
            l_res_token_tsd_parse = s_token_tsd_parse(a_ledger, l_token_item, l_token, l_token_size);
            s_tsd_sign_apply(a_ledger, l_token_item, l_token, l_token_size);
            break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
            debug_if(s_debug_more, L_INFO, "CF20 token %s updated, total_supply: %s, total_signs_valid: %hu, signs_total: %hu",
                    l_token->ticker, l_balance_dbg,
                    l_token->signs_valid, l_token->signs_total);
            l_res_token_tsd_parse = s_token_tsd_parse(a_ledger, l_token_item, l_token, l_token_size);
            s_tsd_sign_apply(a_ledger, l_token_item, l_token, l_token_size);
            break;
        default:
            /* Bogdanoff, unknown token type update. What shall we TODO? */
            debug_if(s_debug_more, L_ERROR, "Unknown token subtype '0x%04X' update! Ticker: %s, total_supply: %s, total_signs_valid: %hu, signs_total: %hu"
                     "Dump it!",
                   l_token->type, l_token->ticker, l_balance_dbg,
                   l_token->signs_valid, l_token->signs_total);
            /* Dump it right now */
            CLEAN_UP;
            return -8;
        } break;
    default:
        debug_if(s_debug_more, L_ERROR, "Unknown token type 0x%04X, Dump it!", l_token->type);
        CLEAN_UP;
        return -8;
    }
    if (l_res_token_tsd_parse) {
        debug_if(s_debug_more, L_ERROR, "Can't parse tsd section for %s token, code error: %i", l_token->ticker, l_res_token_tsd_parse);
        CLEAN_UP;
        return -1;
    }
#undef CLEAN_UP
    DAP_DELETE(l_balance_dbg);
    s_threshold_emissions_proc(a_ledger); /* TODO process thresholds only for no-consensus chains */
    if (PVT(a_ledger)->cached)
        s_ledger_token_cache_update(a_ledger, l_token_item);
    return 0;
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
    size_t l_tsd_total_size = a_token->header_native_decl.tsd_total_size;
    a_token_item->flags = a_token->header_native_decl.flags;

    for( size_t l_offset=0; l_offset < l_tsd_total_size;  l_offset += l_tsd_size ){
        l_tsd = (dap_tsd_t *)(((byte_t *)l_tsd ) + l_tsd_size);
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
                uint16_t l_flags = 0;
                a_token_item->flags |= _dap_tsd_get_scalar(l_tsd, &l_flags);
            }break;

           // unset flags
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS:{
                uint16_t l_flags = 0;
                a_token_item->flags &= ~_dap_tsd_get_scalar(l_tsd, &l_flags);
            }break;

            // set total supply
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY:{ // 256
                a_token_item->total_supply = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &a_token_item->total_supply);
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_OLD:{ // 128
                uint128_t l_total_supply128 = uint128_0;
                a_token_item->total_supply = GET_256_FROM_128(_dap_tsd_get_scalar(l_tsd,&l_total_supply128));
            }break;

            // Set total signs count value to set to be valid
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID:{
                uint16_t l_signs_valid = 0;
                a_token_item->auth_signs_valid = _dap_tsd_get_scalar(l_tsd, &l_signs_valid);
            }break;

            //Allowed tx receiver addres list add, remove or clear
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){
                    a_token_item->tx_recv_allow = a_token_item->tx_recv_allow
                            ? DAP_REALLOC(a_token_item->tx_recv_allow, (a_token_item->tx_recv_allow_size + 1) * sizeof(*a_token_item->tx_recv_allow))
                            : DAP_NEW_Z_SIZE(dap_chain_addr_t,sizeof(*a_token_item->tx_recv_allow));

                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr))!=1){
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD (code %d)",
                               l_add_addr_check);
                        return -12;
                    }
                    // Check if its already present
                    if (a_token_item->tx_recv_allow) {
                        for( size_t i=0; i < a_token_item->tx_recv_allow_size; i++){ // Check for all the list
                            if ( memcmp(&a_token_item->tx_recv_allow[i], l_tsd->data, l_tsd->size) == 0 ){ // Found
                                char * l_addr_str= dap_chain_addr_to_str((dap_chain_addr_t*) l_tsd->data );
                                if(s_debug_more)
                                    log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD has address %s thats already present in list",
                                       l_addr_str);
                                DAP_DELETE(l_addr_str);
                                DAP_DELETE(a_token_item->tx_recv_allow);
                                a_token_item->tx_recv_allow = NULL;
                                return -11;
                            }
                        }
                        if(a_token_item->tx_recv_allow){
                            a_token_item->tx_recv_allow[a_token_item->tx_recv_allow_size] = *(dap_chain_addr_t*)l_tsd->data;
                            a_token_item->tx_recv_allow_size++;
                        }

                    }else{
                        log_it(L_ERROR,"Out of memory! Can't extend TX_RECEIVER_ALLOWED array");
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
                    // TODO
                    UNUSED(l_was_found);
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
                    dap_chain_addr_t * l_addrs = a_token_item->tx_recv_block
                            ? DAP_NEW_Z_SIZE(dap_chain_addr_t, sizeof(*a_token_item->tx_recv_block))
                            : DAP_REALLOC(a_token_item->tx_recv_block,
                                          (a_token_item->tx_recv_block_size + 1) * sizeof(*a_token_item->tx_recv_block));
                    // Check if its correct
                    dap_chain_addr_t * l_add_addr = (dap_chain_addr_t *) l_tsd->data;
                    int l_add_addr_check;
                    if ((l_add_addr_check=dap_chain_addr_check_sum(l_add_addr)) != 1) {
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
                                char * l_addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) l_tsd->data );
                                if(s_debug_more)
                                    log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD has address %s thats already present in list",
                                       l_addr_str);
                                DAP_DELETE(l_addr_str);
                                DAP_DELETE(l_addrs);
                                DAP_DEL_Z(a_token_item->tx_recv_allow);
                                return -11;
                            }
                        }

                    if(l_addrs) {
                        l_addrs[a_token_item->tx_recv_block_size] = *(dap_chain_addr_t*)l_tsd->data;
                        a_token_item->tx_recv_block_size++;
                        a_token_item->tx_recv_block = l_addrs;

                    } else {
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
                    // TODO
                    UNUSED(l_was_found);
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
                    if (  (l_add_addr_check=dap_chain_addr_check_sum(l_add_addr)) != 1){
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
                    if(l_addrs) {
                        l_addrs[a_token_item->tx_send_allow_size] = *(dap_chain_addr_t*)l_tsd->data;
                        a_token_item->tx_send_allow_size++;
                        a_token_item->tx_send_allow = l_addrs;

                    } else {
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
                    // TODO
                    UNUSED(l_was_found);
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
                    if ((l_add_addr_check=dap_chain_addr_check_sum(l_add_addr)) != 1) {
                        if(s_debug_more)
                            log_it(L_ERROR,"Wrong address checksum in TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD (code %d)",
                               l_add_addr_check);
                        if (l_addrs)
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
                            if (l_addrs)
                                DAP_DELETE(l_addrs);
                            return -11;
                        }
                    }
                    if(l_addrs) {
                        l_addrs[a_token_item->tx_send_block_size] = *(dap_chain_addr_t*)l_tsd->data;
                        a_token_item->tx_send_block_size++;
                        a_token_item->tx_send_block = l_addrs;

                    } else {
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
                    // TODO
                    UNUSED(l_was_found);
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

static int s_tsd_sign_apply(dap_ledger_t *a_ledger, dap_chain_ledger_token_item_t *a_token_item , dap_chain_datum_token_t *a_token, size_t a_token_size){
    dap_tsd_t * l_tsd= dap_chain_datum_token_tsd_get(a_token,a_token_size);
    size_t l_tsd_size=0;
    size_t l_tsd_total_size = a_token->header_native_decl.tsd_total_size;
    dap_tsd_t *l_new_signs_valid = NULL;
    dap_list_t *l_remove_pkeys = NULL;
    dap_list_t *l_added_pkeys = NULL;

    for( size_t l_offset=0; l_offset < l_tsd_total_size;  l_offset += l_tsd_size ){
        l_tsd = (dap_tsd_t *) (((byte_t*)l_tsd) + l_tsd_size);
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
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID:
                l_new_signs_valid = l_tsd;
                break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD:
                l_added_pkeys = dap_list_append(l_added_pkeys, l_tsd->data);
                break;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE:
                l_remove_pkeys = dap_list_append(l_remove_pkeys, l_tsd);
                break;
        }
    }
    for (dap_list_t *l_ptr = l_remove_pkeys; l_ptr; l_ptr = dap_list_next(l_ptr)) {
        dap_tsd_t *l_tsd = l_ptr->data;
        dap_hash_fast_t l_hash = { };
        _dap_tsd_get_scalar(l_tsd, &l_hash);
        for( size_t i=0; i<a_token_item->auth_signs_total; i++){
            if (dap_hash_fast_compare(&l_hash, &a_token_item->auth_pkeys_hash[i] )){
                if (i+1 != a_token_item->auth_signs_total){
                    memmove(a_token_item->auth_pkeys+i,a_token_item->auth_pkeys+i+1,
                            (a_token_item->auth_signs_total-i-1)*sizeof (void*));
                    memmove(a_token_item->auth_pkeys_hash+i,a_token_item->auth_pkeys_hash+i+1,
                            (a_token_item->auth_signs_total-i-1)*sizeof(dap_chain_hash_fast_t));
                }
                a_token_item->auth_signs_total--;
                if(a_token_item->auth_signs_total) {
                    // Type sizeof's misunderstanding in realloc?
                    a_token_item->auth_pkeys = DAP_REALLOC(a_token_item->auth_pkeys,a_token_item->auth_signs_total*sizeof (dap_pkey_t*) );
                    a_token_item->auth_pkeys_hash = DAP_REALLOC(a_token_item->auth_pkeys_hash,a_token_item->auth_signs_total*sizeof(dap_chain_hash_fast_t));
                } else {
                    DAP_DEL_Z(a_token_item->auth_pkeys);
                    DAP_DEL_Z(a_token_item->auth_pkeys_hash);
                }
                break;
            }
        }
    }
    for (dap_list_t *l_ptr = l_added_pkeys; l_ptr; l_ptr = dap_list_next(l_ptr)) {
        dap_pkey_t *l_pkey = (dap_pkey_t*)l_ptr->data;
        a_token_item->auth_signs_total++;
        // Type sizeof's misunderstanding in realloc?
        a_token_item->auth_pkeys = DAP_REALLOC(a_token_item->auth_pkeys,a_token_item->auth_signs_total*sizeof (dap_pkey_t*) );
        a_token_item->auth_pkeys_hash = DAP_REALLOC(a_token_item->auth_pkeys_hash,a_token_item->auth_signs_total*sizeof (dap_chain_hash_fast_t));
        a_token_item->auth_pkeys[a_token_item->auth_signs_total-1] = DAP_NEW_SIZE(dap_pkey_t, sizeof(dap_pkey_t)+l_pkey->header.size);
        memcpy(a_token_item->auth_pkeys[a_token_item->auth_signs_total-1], l_pkey, sizeof(dap_pkey_t)+l_pkey->header.size);
        dap_pkey_get_hash(l_pkey, &a_token_item->auth_pkeys_hash[a_token_item->auth_signs_total-1]);
    }
    if (l_new_signs_valid) {
        uint16_t l_tmp = 0;
        a_token_item->auth_signs_valid = _dap_tsd_get_scalar(l_new_signs_valid, &l_tmp);
    }
    return 0;
}

int dap_chain_ledger_token_load(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if (PVT(a_ledger)->load_mode) {
        dap_chain_ledger_token_item_t *l_token_item;
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->tokens, a_token->ticker, l_token_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        if (l_token_item && a_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE)
            return 0;
    }
    return dap_chain_ledger_token_add(a_ledger, a_token, a_token_size);
}

dap_string_t *dap_chain_ledger_threshold_info(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
    dap_string_t *l_str_ret = dap_string_new("");
    uint32_t l_counter = 0;
    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
    HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp){
        char l_tx_prev_hash_str[70]={0};
        char l_time[1024] = {0};
        char l_item_size[70] = {0};
        dap_chain_hash_fast_to_str(&l_tx_item->tx_hash_fast,l_tx_prev_hash_str,sizeof(l_tx_prev_hash_str));
        dap_time_to_str_rfc822(l_time, sizeof(l_time), l_tx_item->tx->header.ts_created);
        //log_it(L_DEBUG,"Ledger thresholded tx_hash_fast %s, time_created: %s, tx_item_size: %d", l_tx_prev_hash_str, l_time, l_tx_item->tx->header.tx_items_size);
        dap_string_append(l_str_ret, "Ledger thresholded tx_hash_fast");
        dap_string_append(l_str_ret, l_tx_prev_hash_str);
        dap_string_append(l_str_ret, ", time_created:");
        dap_string_append(l_str_ret, l_time);
        dap_string_append(l_str_ret, "");
        sprintf(l_item_size, ", tx_item_size: %d\n", l_tx_item->tx->header.tx_items_size);
        dap_string_append(l_str_ret, l_item_size);
        l_counter +=1;
    }
    if (!l_counter)
        dap_string_append(l_str_ret, "0 items in ledger tx threshold\n");
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);

    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_emissions_rwlock);
    l_counter = 0;
    dap_chain_ledger_token_emission_item_t *l_emission_item, *l_emission_tmp;
    HASH_ITER(hh, l_ledger_pvt->threshold_emissions, l_emission_item, l_emission_tmp){
        char l_emission_hash_str[70]={0};
        char l_item_size[70] = {0};
        dap_chain_hash_fast_to_str(&l_emission_item->datum_token_emission_hash,l_emission_hash_str,sizeof(l_emission_hash_str));
       //log_it(L_DEBUG,"Ledger thresholded datum_token_emission_hash %s, emission_item_size: %lld", l_emission_hash_str, l_emission_item->datum_token_emission_size);
        dap_string_append(l_str_ret, "Ledger thresholded datum_token_emission_hash: ");
        dap_string_append(l_str_ret, l_emission_hash_str);
        sprintf(l_item_size, ", tx_item_size: %zu\n", l_emission_item->datum_token_emission_size);
        dap_string_append(l_str_ret, l_item_size);
        l_counter +=1;
    }
    if (!l_counter)
        dap_string_append(l_str_ret, "0 items in ledger emission threshold\n");
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_emissions_rwlock);

    return l_str_ret;
}

dap_string_t *dap_chain_ledger_threshold_hash_info(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *l_threshold_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
    dap_string_t *l_str_ret = dap_string_new("");
    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
    HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp){
        if (!memcmp(l_threshold_hash,&l_tx_item->tx_hash_fast, sizeof(dap_chain_hash_fast_t))){
            char l_tx_hash_str[70]={0};
            dap_chain_hash_fast_to_str(l_threshold_hash,l_tx_hash_str,sizeof(l_tx_hash_str));
            dap_string_append(l_str_ret, "Hash was found in ledger tx threshold:");
            dap_string_append(l_str_ret, l_tx_hash_str);
            dap_string_append(l_str_ret, "\n");
            pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            return l_str_ret;
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);

    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_emissions_rwlock);
    dap_chain_ledger_token_emission_item_t *l_emission_item, *l_emission_tmp;
    HASH_ITER(hh, l_ledger_pvt->threshold_emissions, l_emission_item, l_emission_tmp){
        if (!memcmp(&l_emission_item->datum_token_emission_hash,l_threshold_hash, sizeof(dap_chain_hash_fast_t))){
            char l_emission_hash_str[70]={0};
            dap_chain_hash_fast_to_str(l_threshold_hash,l_emission_hash_str,sizeof(l_emission_hash_str));
            dap_string_append(l_str_ret, "Hash was found in ledger emission threshold: ");
            dap_string_append(l_str_ret, l_emission_hash_str);
            dap_string_append(l_str_ret, "\n");
            pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            return l_str_ret;
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_emissions_rwlock);
    dap_string_append(l_str_ret, "Hash wasn't found in ledger\n");
    return l_str_ret;
}

dap_string_t *dap_chain_ledger_balance_info(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_string_t *l_str_ret = dap_string_new("");
    pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
    uint32_t l_counter = 0;
    dap_ledger_wallet_balance_t *l_balance_item, *l_balance_tmp;
    HASH_ITER(hh, l_ledger_pvt->balance_accounts, l_balance_item, l_balance_tmp) {
        //log_it(L_DEBUG,"Ledger balance key %s, token_ticker: %s, balance: %s", l_balance_key, l_balance_item->token_ticker,
        //                        dap_chain_balance_print(l_balance_item->balance));
        dap_string_append(l_str_ret, "Ledger balance key: ");
        dap_string_append(l_str_ret, l_balance_item->key);
        dap_string_append(l_str_ret, ", token_ticker:");
        dap_string_append(l_str_ret, l_balance_item->token_ticker);
        dap_string_append(l_str_ret, ", balance:");
        char *l_balance = dap_chain_balance_print(l_balance_item->balance);
        dap_string_append(l_str_ret, l_balance);
        DAP_DELETE(l_balance);
        dap_string_append(l_str_ret, "\n");
        l_counter +=1;
    }
    if (!l_counter)
        dap_string_append(l_str_ret, "0 items in ledger balance_accounts\n");
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    return l_str_ret;
}

/**
 * @breif dap_chain_ledger_token_auth_signs_valid
 * @param a_ledger
 * @param a_token_ticker
 * @return 0 if no ticker found
 */
size_t dap_chain_ledger_token_auth_signs_valid(dap_ledger_t *a_ledger, const char * a_token_ticker)
{
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    size_t l_res = 0;
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (!dap_strcmp(l_token_item->ticker, a_token_ticker)) {
            l_res = l_token_item->auth_signs_valid;
            break;
        }
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_res;
}

/**
 * @breif dap_chain_ledger_token_auth_signs_total
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
size_t dap_chain_ledger_token_auth_signs_total(dap_ledger_t *a_ledger, const char * a_token_ticker)
{
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    size_t l_res = 0;
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (!dap_strcmp(l_token_item->ticker, a_token_ticker)) {
            l_res = l_token_item->auth_signs_total;
            break;
        }
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_res;
}

/**
 * @breif dap_chain_ledger_token_auth_signs_hashes
 * @param a_ledger
 * @param a_token_ticker
 * @return
 */
dap_list_t * dap_chain_ledger_token_auth_pkeys_hashes(dap_ledger_t *a_ledger, const char * a_token_ticker)
{
    dap_list_t * l_ret = NULL;
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (!dap_strcmp(l_token_item->ticker, a_token_ticker)) {
            debug_if(s_debug_more, L_INFO, " ! Token %s : total %lu auth signs", a_token_ticker, l_token_item->auth_signs_total);
            for (size_t i = 0; i < l_token_item->auth_signs_total; i++) {
                l_ret = dap_list_append(l_ret, (dap_chain_hash_fast_t*)(&l_token_item->auth_pkeys_hash[i]));
            }
            break;
        }
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_ret;
}

/**
 * @brief Compose string list of all tokens with information
 * @param a_ledger
 * @return
 */
dap_list_t *dap_chain_ledger_token_info(dap_ledger_t *a_ledger)
{
    dap_list_t *l_ret_list = NULL;
    dap_string_t *l_str_tmp;// = dap_string_new("");
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        l_str_tmp = dap_string_new("");
        const char *l_type_str;
        const char *l_flags_str = s_flag_str_from_code(l_token_item->datum_token->header_private_decl.flags);
        switch (l_token_item->type) {
            case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL: {
                switch (l_token_item->subtype) {
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
            }break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE: {
                switch (l_token_item->subtype) {
                    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE:
                        l_type_str = "SIMPLE"; break;
                    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
                        l_type_str = "PRIVATE_UPDATE"; break;
                    case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
                        l_type_str = "CF20_UPDATE"; break;
                    default: l_type_str = "UNKNOWN"; break;
                }
            } break;
            default:
                l_type_str = "UNKNOWN"; break;
        }
       char *l_item_str = NULL;

        if ((l_token_item->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE)
                ||	(l_token_item->type != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC)) {
            char *l_balance_cur = dap_chain_balance_print(l_token_item->current_supply);
            char *l_balance_total = dap_chain_balance_print(l_token_item->total_supply);
            s_datum_token_dump_tsd(l_str_tmp, l_token_item->datum_token, l_token_item->datum_token_size, "hex");
            size_t l_certs_field_size = l_token_item->datum_token_size - sizeof(*l_token_item->datum_token) - l_token_item->datum_token->header_native_decl.tsd_total_size;
            dap_chain_datum_token_certs_dump(l_str_tmp, l_token_item->datum_token->data_n_tsd + l_token_item->datum_token->header_native_decl.tsd_total_size,
                                         l_certs_field_size, "hex");
            l_item_str = dap_strdup_printf("-->Token name '%s', type %s, flags: %s\n"
                                            "\tSupply (current/total) %s/%s\n"
                                            "\tDecimals: 18\n"
                                            "\tAuth signs (valid/total) %zu/%zu\n"
                                            "TSD and Signs:\n"
                                            "%s"
                                            "\tTotal emissions %u\n___\n",
                                            l_token_item->ticker, l_type_str, s_flag_str_from_code(l_token_item->datum_token->header_native_decl.flags),
                                            l_balance_cur, l_balance_total,
                                            l_token_item->auth_signs_valid, l_token_item->auth_signs_total,
                                            l_str_tmp->str,
                                            HASH_COUNT(l_token_item->token_emissions));
            DAP_DEL_Z(l_balance_cur);
            DAP_DEL_Z(l_balance_total);
        } else {
                char *l_balance_cur = dap_chain_balance_print(l_token_item->current_supply);
                char *l_balance_total = dap_chain_balance_print(l_token_item->total_supply);
                size_t l_certs_field_size = l_token_item->datum_token_size - sizeof(*l_token_item->datum_token);
                dap_chain_datum_token_certs_dump(l_str_tmp, l_token_item->datum_token->data_n_tsd,
                                                 l_certs_field_size, "hex");
                l_item_str = dap_strdup_printf("-->Token name '%s', type %s, flags: %s\n"
                                                "\tSupply (current/total) %s/%s\n"
                                                "\tDecimals: 18\n"
                                                "\tAuth signs (valid/total) %zu/%zu\n"
                                                "%s"
                                                "\tTotal emissions %u\n___\n",
                                                l_token_item->ticker, l_type_str, "SIMPLE token has no flags",
                                                l_balance_cur, l_balance_total,
                                                l_token_item->auth_signs_valid, l_token_item->auth_signs_total,
                                                l_str_tmp->str,
                                                HASH_COUNT(l_token_item->token_emissions));
                DAP_DEL_Z(l_balance_cur);
                DAP_DEL_Z(l_balance_total);
        }
        l_ret_list = dap_list_append(l_ret_list, l_item_str);
        dap_string_free(l_str_tmp, true);
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_ret_list;
}

/**
 * @brief Get all token declatations
 * @param a_ledger
 * @return
 */
dap_list_t* dap_chain_ledger_token_decl_all(dap_ledger_t *a_ledger)
{
    dap_list_t * l_ret = NULL;
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);

    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        dap_chain_datum_token_t *l_token = l_token_item->datum_token;
        l_ret = dap_list_append(l_ret, l_token);
    }
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    return l_ret;
}


/**
 * @brief s_threshold_emissions_proc
 * @param a_ledger
 */
static void s_threshold_emissions_proc(dap_ledger_t * a_ledger)
{
    bool l_success;
    do {
        l_success = false;
        dap_chain_ledger_token_emission_item_t *l_emission_item, *l_emission_tmp;
        pthread_rwlock_wrlock(&PVT(a_ledger)->threshold_emissions_rwlock);
        HASH_ITER(hh, PVT(a_ledger)->threshold_emissions, l_emission_item, l_emission_tmp) {
            int l_res = s_token_emission_add_unsafe(a_ledger, (byte_t *)l_emission_item->datum_token_emission,
                                                            l_emission_item->datum_token_emission_size,
                                                            &l_emission_item->datum_token_emission_hash, true);
            if (l_res != DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE) {
                HASH_DEL(PVT(a_ledger)->threshold_emissions, l_emission_item);
                if (l_res)
                    DAP_DELETE(l_emission_item->datum_token_emission);
                DAP_DELETE(l_emission_item);
                l_success = true;
            }

        }
        pthread_rwlock_unlock(&PVT(a_ledger)->threshold_emissions_rwlock);
    } while (l_success);
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
        dap_chain_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
        HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp) {
            int l_res = s_tx_add_unsafe(a_ledger, l_tx_item->tx, &l_tx_item->tx_hash_fast, true);
            if (l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION &&
                    l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS) {
                HASH_DEL(l_ledger_pvt->threshold_txs, l_tx_item);
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
static void s_threshold_txs_free(dap_ledger_t *a_ledger){
    log_it(L_DEBUG, "Start free threshold txs");
    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_current = NULL, *l_tmp = NULL;
    dap_nanotime_t l_time_cut_off = dap_nanotime_now() - dap_nanotime_from_sec(7200); //7200 sec = 2 hours.
    pthread_rwlock_wrlock(&l_pvt->threshold_txs_rwlock);
    HASH_ITER(hh, l_pvt->threshold_txs, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            HASH_DEL(l_pvt->threshold_txs, l_current);
            char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_current->tx_hash_fast, l_tx_hash_str, sizeof(l_tx_hash_str));
            DAP_DELETE(l_current->tx);
            DAP_DELETE(l_current);
            log_it(L_NOTICE, "Removed transaction %s form threshold ledger", l_tx_hash_str);
        }
    }
    pthread_rwlock_unlock(&l_pvt->threshold_txs_rwlock);
}

/**
 * @breif s_treshold_emission_free
 * @param a_ledger
 */
static void s_threshold_emission_free(dap_ledger_t *a_ledger){
    log_it(L_DEBUG, "Start free threshold emission");
    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_chain_ledger_token_emission_item_t *l_current = NULL, *l_tmp = NULL;
    dap_nanotime_t l_time_cut_off = dap_nanotime_now() - dap_nanotime_from_sec(7200); //7200 sec = 2 hours.
    pthread_rwlock_wrlock(&l_pvt->threshold_emissions_rwlock);
    HASH_ITER(hh, l_pvt->threshold_emissions, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            char l_token_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_current->datum_token_emission_hash, l_token_hash_str, sizeof(l_token_hash_str));
            HASH_DEL(l_pvt->threshold_emissions, l_current);
            DAP_DELETE(l_current->datum_token_emission);
            log_it(L_NOTICE, "Removed token emission %s form threshold ledger", l_token_hash_str);
        }
    }
    pthread_rwlock_unlock(&l_pvt->threshold_emissions_rwlock);
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
        log_it(L_CRITICAL, "Memory allocation error");
            return false;
        }
        l_balance_item->key = DAP_NEW_Z_SIZE(char, strlen(a_values[i].key) + 1);
        if (!l_balance_item->key) {
        log_it(L_CRITICAL, "Memory allocation error");
            DAP_DEL_Z(l_balance_item);
            return false;
        }
        strcpy(l_balance_item->key, a_values[i].key);
        char *l_ptr = strchr(l_balance_item->key, ' ');
        if (l_ptr++) {
            strcpy(l_balance_item->token_ticker, l_ptr);
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
 * @brief s_load_cache_gdb_loaded_spent_txs_callback
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
static bool s_load_cache_gdb_loaded_spent_txs_callback(dap_global_db_instance_t *a_dbi,
                                                       int a_rc, const char *a_group,
                                                       const size_t a_values_total, const size_t a_values_count,
                                                       dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_ledger_t * l_ledger = (dap_ledger_t*) a_arg;
    dap_ledger_private_t * l_ledger_pvt = PVT(l_ledger);

    for (size_t i = 0; i < a_values_count; i++) {
        dap_chain_ledger_tx_spent_item_t *l_tx_spent_item = DAP_NEW_Z(dap_chain_ledger_tx_spent_item_t);
        if ( !l_tx_spent_item ) {
        log_it(L_CRITICAL, "Memory allocation error");
            return false;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_tx_spent_item->tx_hash_fast);
        l_tx_spent_item->cache_data = *(typeof(l_tx_spent_item->cache_data)*)a_values[i].value;
        HASH_ADD(hh, l_ledger_pvt->spent_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_spent_item);
    }

    char *l_gdb_group = dap_chain_ledger_get_gdb_group(l_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_balances_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
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
        dap_chain_ledger_tx_item_t *l_tx_item = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
        if ( !l_tx_item ) {
            log_it(L_CRITICAL, "Memory allocation error");
            return false;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_tx_item->tx_hash_fast);
        l_tx_item->tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, a_values[i].value_len - sizeof(l_tx_item->cache_data));
        if ( !l_tx_item->tx ) {
            DAP_DELETE(l_tx_item);
            log_it(L_CRITICAL, "Memory allocation error");
            return false;
        }
        memcpy(&l_tx_item->cache_data, a_values[i].value, sizeof(l_tx_item->cache_data));
        memcpy(l_tx_item->tx, a_values[i].value + sizeof(l_tx_item->cache_data), a_values[i].value_len - sizeof(l_tx_item->cache_data));
        l_tx_item->ts_added = dap_nanotime_now();
        HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item, s_sort_ledger_tx_item);
    }

    char *l_gdb_group = dap_chain_ledger_get_gdb_group(l_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_spent_txs_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
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
        dap_chain_ledger_stake_lock_item_t *l_new_stake_lock_emission = DAP_NEW(dap_chain_ledger_stake_lock_item_t);
        if (!l_new_stake_lock_emission) {
            debug_if(s_debug_more, L_ERROR, "Error: memory allocation when try adding item 'dap_chain_ledger_stake_lock_item_t' to hash-table");
            continue;
        }
        dap_chain_hash_fast_from_str(a_values[i].key, &l_new_stake_lock_emission->tx_for_stake_lock_hash);
        l_new_stake_lock_emission->tx_used_out = *(dap_hash_fast_t *)(a_values[i].value);
        HASH_ADD(hh, l_ledger_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
    }

    char* l_gdb_group = dap_chain_ledger_get_gdb_group(l_ledger, DAP_CHAIN_LEDGER_TXS_STR);
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
        dap_chain_ledger_token_item_t *l_token_item = NULL;
        HASH_FIND_STR(l_ledger_pvt->tokens, c_token_ticker, l_token_item);
        if (!l_token_item) {
            log_it(L_WARNING, "Not found token with ticker [%s], need to 'ledger reload' to update cache", c_token_ticker);
            continue;
        }
        dap_chain_ledger_token_emission_item_t *l_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
        if ( !l_emission_item ) {
            log_it(L_CRITICAL, "Memory allocation error");
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

    char* l_gdb_group = dap_chain_ledger_get_gdb_group(l_ledger, DAP_CHAIN_LEDGER_STAKE_LOCK_STR);
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
        dap_chain_ledger_token_add(l_ledger, l_token, l_token_size);
        dap_chain_ledger_token_item_t *l_token_item = NULL;
        HASH_FIND_STR(l_ledger_pvt->tokens, l_token->ticker, l_token_item);
        if (!l_token_item) {
            log_it(L_WARNING, "Can't load token with ticker [%s], need to 'ledger reload' to update cache", l_token->ticker);
            continue;
        }
        l_token_item->current_supply = *(uint256_t*)a_values[i].value;
    }

    char *l_gdb_group = dap_chain_ledger_get_gdb_group(l_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_emissions_callback, l_ledger);
    DAP_DELETE(l_gdb_group);
    return true;
}

/**
 * @brief Load ledger from cache (stored in GDB)
 * @param a_ledger
 */
void dap_chain_ledger_load_cache(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TOKENS_STR);

    pthread_mutex_lock(& l_ledger_pvt->load_mutex);
    dap_global_db_get_all(l_gdb_group, 0, s_load_cache_gdb_loaded_tokens_callback, a_ledger);
    while (!l_ledger_pvt->load_end)
        pthread_cond_wait(& l_ledger_pvt->load_cond, &l_ledger_pvt->load_mutex);
    pthread_mutex_unlock(& l_ledger_pvt->load_mutex);

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
dap_ledger_t *dap_chain_ledger_create(uint16_t a_flags, dap_chain_net_id_t a_net_id, char *a_net_name, const char *a_net_native_ticker, dap_list_t *a_poa_certs)
{
    dap_ledger_t *l_ledger = dap_chain_ledger_handle_new();
    if (!l_ledger) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_ledger->net_name = a_net_name;
    l_ledger->net_id = a_net_id;
    dap_ledger_private_t *l_ledger_pvt = PVT(l_ledger);
    l_ledger_pvt->net_native_ticker = a_net_native_ticker;
    l_ledger_pvt->poa_certs = a_poa_certs;
    l_ledger_pvt->flags = a_flags;
    l_ledger_pvt->check_ds = a_flags & DAP_CHAIN_LEDGER_CHECK_LOCAL_DS;
    l_ledger_pvt->check_cells_ds = a_flags & DAP_CHAIN_LEDGER_CHECK_CELLS_DS;
    l_ledger_pvt->check_token_emission = a_flags & DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION;
    l_ledger_pvt->cached = a_flags & DAP_CHAIN_LEDGER_CACHE_ENABLED;
    pthread_cond_init(&l_ledger_pvt->load_cond, NULL);
    pthread_mutex_init(&l_ledger_pvt->load_mutex, NULL);

#ifndef DAP_CHAIN_LEDGER_TEST
    char * l_chains_path = dap_strdup_printf("%s/network/%s", dap_config_path(), a_net_name);
    DIR * l_chains_dir = opendir(l_chains_path);
    DAP_DEL_Z(l_chains_path);

    struct dirent * l_dir_entry;
    while ( (l_dir_entry = readdir(l_chains_dir) )!= NULL ){
        if (l_dir_entry->d_name[0] == '\0')
            continue;
        char * l_entry_name = dap_strdup(l_dir_entry->d_name);
        if (strlen(l_entry_name) > 4) {
            if ( strncmp (l_entry_name + strlen(l_entry_name)-4,".cfg",4) == 0 ) { // its .cfg file
                l_entry_name [strlen(l_entry_name)-4] = 0;
                log_it(L_DEBUG,"Open chain config \"%s\"...",l_entry_name);
                l_chains_path = dap_strdup_printf("network/%s/%s", a_net_name, l_entry_name);
                dap_config_t * l_cfg = dap_config_open(l_chains_path);
                uint16_t l_whitelist_size;
                char **l_whitelist = dap_config_get_array_str(l_cfg, "ledger", "hard_accept_list", &l_whitelist_size);
                for (uint16_t i = 0; i < l_whitelist_size; ++i) {
                    dap_ledger_hal_item_t *l_hal_item = DAP_NEW_Z(dap_ledger_hal_item_t);
                    if (!l_hal_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        DAP_DEL_Z(l_ledger_pvt);
                        DAP_DEL_Z(l_ledger);
                        dap_config_close(l_cfg);
                        DAP_DELETE (l_entry_name);
                        closedir(l_chains_dir);
                        return NULL;
                    }
                    dap_chain_hash_fast_from_str(l_whitelist[i], &l_hal_item->hash);
                    HASH_ADD(hh, s_hal_items, hash, sizeof(l_hal_item->hash), l_hal_item);
                }
                dap_config_close(l_cfg);
                log_it(L_DEBUG, "HAL items count for chain %s : %d", l_entry_name, l_whitelist_size);
            }
        }
        DAP_DELETE (l_entry_name);
    }
    closedir(l_chains_dir);

    if ( l_ledger_pvt->cached )
        // load ledger cache from GDB
        dap_chain_ledger_load_cache(l_ledger);
#endif

    return l_ledger;
}

void dap_chain_ledger_set_fee(dap_ledger_t *a_ledger, uint256_t a_fee, dap_chain_addr_t a_fee_addr)
{
    PVT(a_ledger)->fee_value = a_fee;
    PVT(a_ledger)->fee_addr = a_fee_addr;
}

int dap_chain_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_chain_hash_fast_t *a_emission_hash)
{
    if (!a_token_emission || !a_token_emission_size)
        return DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_IS_NULL;

    int l_ret = DAP_CHAIN_LEDGER_EMISSION_ADD_OK;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    const char *l_token_ticker = ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.ticker;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->tokens_rwlock);
    HASH_FIND_STR(l_ledger_pvt->tokens, l_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);

    if (!l_token_item) {
        log_it(L_ERROR, "Check emission: token %s was not found", l_token_ticker);
        return DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_CANT_FIND_DECLARATION_TOKEN;
    }

    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
    // check if such emission is already present in table
    pthread_rwlock_rdlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_pvt->threshold_emissions_rwlock);
    HASH_FIND(hh,l_token_item ? l_token_item->token_emissions : l_ledger_pvt->threshold_emissions,
              a_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    unsigned long long l_threshold_emissions_count = HASH_COUNT( l_ledger_pvt->threshold_emissions);
    pthread_rwlock_unlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_pvt->threshold_emissions_rwlock);
    if(l_token_emission_item ) {
        if(s_debug_more) {
            char l_token_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(a_emission_hash, l_token_hash_str, sizeof(l_token_hash_str));
            if ( l_token_emission_item->datum_token_emission->hdr.version >= 2 ) {
                char *l_balance = dap_chain_balance_print(l_token_emission_item->datum_token_emission->hdr.value_256);
                log_it(L_ERROR, "Can't add token emission datum of %s %s ( %s ): already present in cache",
                        l_balance, l_token_ticker, l_token_hash_str);
                DAP_DELETE(l_balance);
            }
            else
                log_it(L_ERROR, "Can't add token emission datum of %"DAP_UINT64_FORMAT_U" %s ( %s ): already present in cache",
                    l_token_emission_item->datum_token_emission->hdr.value, l_token_ticker, l_token_hash_str);
        }
        l_ret = DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_ALREADY_CACHED;
    }else if ( (! l_token_item) && ( l_threshold_emissions_count >= s_threshold_emissions_max)) {
        if(s_debug_more)
            log_it(L_WARNING,"Emissions threshold overflow, max %zu items", s_threshold_emissions_max);
        l_ret = DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_THRESHOLD_OVERFLOW;
    }
    if (l_ret || !PVT(a_ledger)->check_token_emission)
        return l_ret;

    if (s_hal_items) {
        dap_ledger_hal_item_t *l_hash_found = NULL;
        HASH_FIND(hh, s_hal_items, a_emission_hash, sizeof(*a_emission_hash), l_hash_found);
        if (l_hash_found) {
            char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
            dap_chain_hash_fast_to_str(a_emission_hash, l_hash_str, sizeof(l_hash_str));
            debug_if(s_debug_more, L_MSG, "Event %s is whitelisted", l_hash_str);
            return l_ret;
        }
    }

    // Check emission correctness
    size_t l_emission_size = a_token_emission_size;
    dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_token_emission, &l_emission_size);

    if (IS_ZERO_256((l_emission->hdr.value_256))) {
        log_it(L_ERROR, "Emission check: zero %s emission value", l_token_item->ticker);
        DAP_DELETE(l_emission);
        return DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_ZERO_VALUE;
    }

    // if total_supply > 0 we can check current_supply
    if (!IS_ZERO_256(l_token_item->total_supply)){
        if(compare256(l_token_item->current_supply, l_emission->hdr.value_256) < 0) {
            char *l_balance_cur = dap_chain_balance_print(l_token_item->current_supply);
            char *l_balance_em = dap_chain_balance_print(l_emission->hdr.value_256);
            log_it(L_ERROR, "Emission check: current_supply %s < emission value %s",
                    l_balance_cur, l_balance_em);
            DAP_DELETE(l_balance_cur);
            DAP_DELETE(l_balance_em);
            DAP_DELETE(l_emission);
            return DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_VALUE_EXEEDS_CURRENT_SUPPLY;
        }
    }

    //additional check for private tokens
    if ((l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
        ||  (l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)) {
        //s_ledger_permissions_check(l_token_item)
        //    return -5;

    }
    switch (l_emission->hdr.type){
        case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:{
            dap_chain_ledger_token_item_t *l_token_item=NULL;
            pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->tokens, l_emission->hdr.ticker, l_token_item);
            pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
            if (l_token_item){
                assert(l_token_item->datum_token);
                dap_sign_t *l_sign = (dap_sign_t *)(l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size);
                size_t l_offset = (byte_t *)l_sign - (byte_t *)l_emission;
                uint16_t l_aproves = 0, l_aproves_valid = l_token_item->auth_signs_valid;
                size_t l_sign_data_check_size = sizeof(l_emission->hdr);
                size_t l_sign_auth_count = l_emission->data.type_auth.signs_count;
                size_t l_sign_auth_size = l_emission->data.type_auth.size;
                void *l_emi_ptr_check_size = &l_emission->hdr;
                if (l_emission->hdr.version == 3) {
                    l_sign_data_check_size = sizeof(dap_chain_datum_token_emission_t) + l_emission->data.type_auth.tsd_total_size;
                    l_emission->data.type_auth.signs_count = 0;
                    l_emission->data.type_auth.size = 0;
                    l_emi_ptr_check_size = l_emission;
                }
                for (uint16_t i = 0; i < l_sign_auth_count && l_offset < l_emission_size; i++) {
                    if (dap_sign_verify_size(l_sign, l_emission_size - l_offset)) {
                        dap_chain_hash_fast_t l_sign_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                        // Find pkey in auth hashes
                        for (uint16_t k=0; k< l_token_item->auth_signs_total; k++) {
                            if (dap_hash_fast_compare(&l_sign_pkey_hash, &l_token_item->auth_pkeys_hash[k])) {
                                // Verify if its token emission header signed
                                if (dap_sign_verify(l_sign, l_emi_ptr_check_size, l_sign_data_check_size) == 1) {
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
                if (l_emission->hdr.version == 3) {
                    l_emission->data.type_auth.signs_count = l_sign_auth_count;
                    l_emission->data.type_auth.size = l_sign_auth_size;
                }
                if (l_aproves < l_aproves_valid ){
                    if(s_debug_more) {
                        char *l_balance = dap_chain_balance_print(l_emission->hdr.value_256);
                        log_it(L_WARNING, "Emission of %s datoshi of %s:%s is wrong: only %u valid aproves when %u need",
                                l_balance, a_ledger->net_name, l_emission->hdr.ticker, l_aproves, l_aproves_valid);
                        DAP_DELETE(l_balance);
                    }
                    l_ret = DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_NOT_ENOUGH_VALID_SIGNS;
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                    dap_chain_hash_fast_to_str(a_emission_hash, l_hash_str, sizeof(l_hash_str));
                    log_it(L_MSG, "!!! Datum hash for HAL: %s", l_hash_str);
                }
            }else{
                if(s_debug_more)
                    log_it(L_WARNING,"Can't find token declaration %s:%s thats pointed in token emission datum", a_ledger->net_name, l_emission->hdr.ticker);
                l_ret = DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_CANT_FIND_DECLARATION_TOKEN;
            }
        }break;
        default:{}
    }
    DAP_DELETE(l_emission);
    return l_ret;
}

bool s_chain_ledger_token_address_check(dap_chain_addr_t * a_addrs, dap_chain_datum_token_emission_t *a_token_emission, size_t a_addrs_count)
{
    // if l_addrs is empty - nothing to check
    dap_return_val_if_pass(!a_addrs, true);

    for(size_t n = 0; n < a_addrs_count; n++ ){
        dap_chain_addr_t l_addr = a_addrs[n];
        if (memcmp(&l_addr,&a_token_emission->hdr.address,sizeof(dap_chain_addr_t))==0)
            return true;
    }

    return false;
}

bool s_chain_ledger_token_tsd_check(dap_chain_ledger_token_item_t * a_token_item, dap_chain_datum_token_emission_t *a_token_emission)
{
    if (!a_token_item){
        log_it(L_WARNING, "Token object is null. Probably, you set unknown token ticker in -token parameter");
        return false;
    }

    // tsd section was parsed in s_token_tsd_parse

    if ((a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED) ||
        (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN)) { // in white list
        if (!s_chain_ledger_token_address_check(a_token_item->tx_recv_allow, a_token_emission, a_token_item->tx_recv_allow_size)){
            log_it(L_WARNING, "Address %s is not in tx_recv_allow for emission for token %s",
                   dap_chain_addr_to_str(&a_token_emission->hdr.address), a_token_item->ticker);
            return false;
        }
        return true;
    }

    if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED) {
        if (s_chain_ledger_token_address_check(a_token_item->tx_recv_block, a_token_emission, a_token_item->tx_recv_block_size)){
            log_it(L_WARNING, "Address %s is in tx_recv_block for emission for token %s",
                   dap_chain_addr_to_str(&a_token_emission->hdr.address), a_token_item->ticker);
            return false;
        }
    }

    return true;
}

static void s_ledger_emission_cache_update(dap_ledger_t *a_ledger, dap_chain_ledger_token_emission_item_t *a_emission_item)
{
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
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
 * @brief dap_chain_ledger_token_emission_add
 * @param a_token_emission
 * @param a_token_emision_size
 * @return
 */

int dap_chain_ledger_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size,
                                        dap_hash_fast_t *a_emission_hash, bool a_from_threshold)
{
    return s_token_emission_add(a_ledger, a_token_emission, a_token_emission_size, a_emission_hash, a_from_threshold, true);
}

/**
 * @brief s_token_emission_add_unsafe
 * @param a_ledger
 * @param a_token_emission
 * @param a_token_emission_size
 * @param a_emission_hash
 * @param a_from_threshold
 * @return
 */
static int s_token_emission_add_unsafe(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size,
                                        dap_hash_fast_t *a_emission_hash, bool a_from_threshold)
{
    return s_token_emission_add(a_ledger, a_token_emission, a_token_emission_size, a_emission_hash, a_from_threshold, false);
}

/**
 * @brief s_token_emission_add
 * @param a_ledger
 * @param a_token_emission
 * @param a_token_emission_size
 * @param a_emission_hash
 * @param a_from_threshold
 * @param a_safe_call
 * @return
 */
static inline int s_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size,
                                        dap_hash_fast_t *a_emission_hash, bool a_from_threshold, bool a_safe_call)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_emission_hash, l_hash_str, sizeof(l_hash_str));
    int l_ret = dap_chain_ledger_token_emission_add_check(a_ledger, a_token_emission, a_token_emission_size, a_emission_hash);
    if (l_ret) {
        if (l_ret == DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE) { // TODO remove emissions threshold
            if (HASH_COUNT(l_ledger_pvt->threshold_emissions) < s_threshold_emissions_max) {
                l_token_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
                if ( !l_token_emission_item ) {
        log_it(L_CRITICAL, "Memory allocation error");
                    return DAP_CHAIN_LEDGER_EMISSION_ADD_MEMORY_PROBLEM;
                }
                l_token_emission_item->datum_token_emission = DAP_DUP_SIZE(a_token_emission, a_token_emission_size);
                if ( !l_token_emission_item->datum_token_emission ) {
                    DAP_DELETE(l_token_emission_item);
        log_it(L_CRITICAL, "Memory allocation error");
                    return DAP_CHAIN_LEDGER_EMISSION_ADD_MEMORY_PROBLEM;
                }
                l_token_emission_item->datum_token_emission_size = a_token_emission_size;
                dap_hash_fast_t l_emi_hash = {0};
                dap_hash_fast(a_token_emission, a_token_emission_size, &l_emi_hash);
                pthread_rwlock_wrlock(&l_ledger_pvt->threshold_emissions_rwlock);
                l_token_emission_item->datum_token_emission_hash = l_emi_hash;
                l_token_emission_item->ts_added = dap_nanotime_now();
                HASH_ADD(hh, l_ledger_pvt->threshold_emissions, datum_token_emission_hash,
                         sizeof(*a_emission_hash), l_token_emission_item);
                pthread_rwlock_unlock(&l_ledger_pvt->threshold_emissions_rwlock);
            } else {
                if(s_debug_more)
                    log_it(L_WARNING,"threshold for emissions is overfulled (%zu max), dropping down new data, added nothing",
                           s_threshold_emissions_max);
            }
        }
        return l_ret;
    }
    const char * c_token_ticker = ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.ticker;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->tokens_rwlock);
    HASH_FIND_STR(l_ledger_pvt->tokens, c_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
    if (!l_token_item && a_from_threshold)
        return DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_CANT_FIND_DECLARATION_TOKEN;

    // check if such emission is already present in table
    if(a_safe_call) pthread_rwlock_rdlock( l_token_item ? &l_token_item->token_emissions_rwlock
                                        : &l_ledger_pvt->threshold_emissions_rwlock);
    HASH_FIND(hh,l_token_item ? l_token_item->token_emissions : l_ledger_pvt->threshold_emissions,
              a_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    if(a_safe_call) pthread_rwlock_unlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_pvt->threshold_emissions_rwlock);
    if (!l_token_emission_item) {
        l_token_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
        if ( !l_token_emission_item ) {
        log_it(L_CRITICAL, "Memory allocation error");
            return DAP_CHAIN_LEDGER_EMISSION_ADD_MEMORY_PROBLEM;
        }
        l_token_emission_item->datum_token_emission_size = a_token_emission_size;
        l_token_emission_item->datum_token_emission_hash = *a_emission_hash;
        if (l_token_item) {
            l_token_emission_item->datum_token_emission = dap_chain_datum_emission_read(a_token_emission,
                                                                                        &l_token_emission_item->datum_token_emission_size);

            //additional check for private tokens
            if((l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
                ||  (l_token_item->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)) {
                if (!s_chain_ledger_token_tsd_check(l_token_item, (dap_chain_datum_token_emission_t *)a_token_emission)) {
                    DAP_DELETE(l_token_emission_item->datum_token_emission);
                    DAP_DELETE(l_token_emission_item);
                    return DAP_CHAIN_LEDGER_EMISSION_ADD_TSD_CHECK_FAILED;
                }
            }
            //Update value in ledger memory object
            if (!IS_ZERO_256(l_token_item->total_supply)) {
                uint256_t l_emission_value = l_token_emission_item->datum_token_emission->hdr.value_256;
                if (compare256(l_token_item->current_supply, l_emission_value) >= 0){
                    SUBTRACT_256_256(l_token_item->current_supply, l_emission_value, &l_token_item->current_supply);
                    char *l_balance = dap_chain_balance_print(l_token_item->current_supply);
                    log_it(L_DEBUG,"New current supply %s for token %s", l_balance, l_token_item->ticker);
                    DAP_DELETE(l_balance);
                } else {
                    char *l_balance = dap_chain_balance_print(l_token_item->current_supply);
                    char *l_value = dap_chain_balance_print(l_emission_value);

                    log_it(L_WARNING,"Token %s current supply %s < emission value %s",
                                        l_token_item->ticker, l_balance, l_value);
                    DAP_DELETE(l_balance);
                    DAP_DELETE(l_value);
                    DAP_DELETE(l_token_emission_item->datum_token_emission);
                    DAP_DELETE(l_token_emission_item);
                    return DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_VALUE_EXEEDS_CURRENT_SUPPLY;
                }
                if (PVT(a_ledger)->cached)
                    s_ledger_token_cache_update(a_ledger, l_token_item);
            }

            pthread_rwlock_wrlock(&l_token_item->token_emissions_rwlock);
            HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash,
                     sizeof(*a_emission_hash), l_token_emission_item);
            pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
            if (PVT(a_ledger)->cached)
                // Add it to cache
                s_ledger_emission_cache_update(a_ledger, l_token_emission_item);
            if(s_debug_more) {
                char * l_token_emission_address_str = dap_chain_addr_to_str(&(l_token_emission_item->datum_token_emission->hdr.address));
                char *l_balance = dap_chain_balance_to_coins(l_token_emission_item->datum_token_emission->hdr.value_256);
                log_it(L_NOTICE, "Added token emission datum to emissions cache: type=%s value=%s token=%s to_addr=%s ",
                               c_dap_chain_datum_token_emission_type_str[l_token_emission_item->datum_token_emission->hdr.type],
                               l_balance, c_token_ticker, l_token_emission_address_str);
                DAP_DELETE(l_token_emission_address_str);
                DAP_DELETE(l_balance);
            }
            s_threshold_txs_proc(a_ledger);
        } else if (HASH_COUNT(l_ledger_pvt->threshold_emissions) < s_threshold_emissions_max) {
            l_token_emission_item->datum_token_emission = DAP_DUP_SIZE(a_token_emission, a_token_emission_size);
            l_token_emission_item->datum_token_emission_size = a_token_emission_size;
            if(a_safe_call) pthread_rwlock_wrlock(&l_ledger_pvt->threshold_emissions_rwlock);
            l_token_emission_item->ts_added = dap_nanotime_now();
            dap_chain_hash_fast_t l_emi_hash = {0};
            dap_hash_fast(a_token_emission, a_token_emission_size, &l_emi_hash);
            l_token_emission_item->datum_token_emission_hash = l_emi_hash;
            HASH_ADD(hh, l_ledger_pvt->threshold_emissions, datum_token_emission_hash,
                     sizeof(*a_emission_hash), l_token_emission_item);
            if(a_safe_call) pthread_rwlock_unlock(&l_ledger_pvt->threshold_emissions_rwlock);
            l_ret = -5;
            if(s_debug_more) {
                char * l_token_emission_address_str = dap_chain_addr_to_str(&(l_token_emission_item->datum_token_emission->hdr.address));
                log_it(L_NOTICE, "Added token emission datum to emissions threshold: type=%s value=%.1Lf token=%s to_addr=%s ",
                               c_dap_chain_datum_token_emission_type_str[l_token_emission_item->datum_token_emission->hdr.type],
                               dap_chain_datoshi_to_coins(l_token_emission_item->datum_token_emission->hdr.value),
                               c_token_ticker, l_token_emission_address_str);
                DAP_DELETE(l_token_emission_address_str);
            }
        } else {
            DAP_DELETE(l_token_emission_item->datum_token_emission);
            DAP_DELETE(l_token_emission_item);
            if(s_debug_more)
                log_it(L_WARNING,"threshold for emissions is overfulled (%zu max), dropping down new data, added nothing",
                   s_threshold_emissions_max);
            l_ret = DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_THRESHOLD_OVERFLOW;
        }
    } else {
        if (l_token_item) {
            if(s_debug_more) {
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(a_emission_hash, l_hash_str, sizeof(l_hash_str));
                if ( ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.version == 2 ) {
                    char *l_balance = dap_chain_balance_print(((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.value_256);
                    log_it(L_ERROR, "Duplicate token emission datum of %s %s ( %s )", l_balance, c_token_ticker, l_hash_str);
                    DAP_DELETE(l_balance);
                }
                else
                    log_it(L_ERROR, "Duplicate token emission datum of %"DAP_UINT64_FORMAT_U" %s ( %s )",
                            ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.value, c_token_ticker, l_hash_str);
            }
        }
        l_ret = DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_ALREADY_CACHED;
    }
    return l_ret;
}

void s_ledger_stake_lock_cache_update(dap_ledger_t *a_ledger, dap_chain_ledger_stake_lock_item_t *a_stake_lock_item)
{
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_stake_lock_item->tx_for_stake_lock_hash, l_hash_str, sizeof(l_hash_str));
    char *l_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_STAKE_LOCK_STR);
    if (dap_global_db_set(l_group, l_hash_str, &a_stake_lock_item->tx_used_out, sizeof(dap_hash_fast_t), false, NULL, NULL))
        log_it(L_WARNING, "Ledger cache mismatch");
    DAP_DEL_Z(l_group);
}

int dap_chain_ledger_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_stake_lock_item_t *l_new_stake_lock_emission;
    pthread_rwlock_rdlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_pvt->emissions_for_stake_lock, a_tx_hash, sizeof(dap_hash_fast_t),
              l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);
    if (l_new_stake_lock_emission) {
        return -1;
    }
    l_new_stake_lock_emission = DAP_NEW_Z(dap_chain_ledger_stake_lock_item_t);
    if (!l_new_stake_lock_emission) {
        if (s_debug_more) {
            log_it(L_ERROR, "Error: memory allocation when try adding item 'dap_chain_ledger_stake_lock_item_t' to hash-table");
        }
        return -13;
    }
    l_new_stake_lock_emission->tx_for_stake_lock_hash = *a_tx_hash;
    pthread_rwlock_wrlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_ADD(hh, l_ledger_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);

    if (!l_new_stake_lock_emission)
        debug_if(s_debug_more, L_ERROR, "Error: adding to hash-table. Be careful, there may be leaks");
    else if (PVT(a_ledger)->cached)
        s_ledger_stake_lock_cache_update(a_ledger, l_new_stake_lock_emission);

    return 0;

}

dap_chain_ledger_stake_lock_item_t *s_emissions_for_stake_lock_item_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_stake_lock_item_t *l_new_stake_lock_emission;
    pthread_rwlock_rdlock(&l_ledger_pvt->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_pvt->emissions_for_stake_lock, a_token_emission_hash, sizeof(dap_chain_hash_fast_t),
              l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);
    return l_new_stake_lock_emission;
}


int dap_chain_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission,
                                         size_t a_token_emission_size, dap_hash_fast_t *a_token_emission_hash)
{
    if (PVT(a_ledger)->load_mode) {
        dap_chain_ledger_token_emission_item_t *l_token_emission_item;
        dap_chain_ledger_token_item_t *l_token_item, *l_item_tmp;
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
        pthread_rwlock_rdlock(&PVT(a_ledger)->threshold_emissions_rwlock);
        HASH_FIND(hh, PVT(a_ledger)->threshold_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash),
                l_token_emission_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->threshold_emissions_rwlock);
        if (l_token_emission_item) {
            return -5;
        }
    }
    return dap_chain_ledger_token_emission_add(a_ledger, a_token_emission, a_token_emission_size, a_token_emission_hash, false);
}

char *dap_chain_ledger_token_emission_err_code_to_str(int a_code) {
    return (a_code >= DAP_CHAIN_LEDGER_EMISSION_ADD_OK && a_code < DAP_CHAIN_LEDGER_EMISSION_ADD_UNKNOWN)
            ? (char*)s_ledger_emission_add_err_str[(dap_chain_ledger_emission_err_code_t)a_code]
            : dap_itoa(a_code);
}

dap_chain_ledger_token_emission_item_t *s_emission_item_find(dap_ledger_t *a_ledger,
                const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_pvt->tokens_rwlock);
    HASH_FIND_STR(l_ledger_pvt->tokens, a_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);

    if (!l_token_item)
        return NULL;
    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
    pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash),
            l_token_emission_item);
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    return l_token_emission_item;
}

/**
 * @brief dap_chain_ledger_token_emission_find
 * @param a_token_ticker
 * @param a_token_emission_hash
 * @return
 */
dap_chain_datum_token_emission_t *dap_chain_ledger_token_emission_find(dap_ledger_t *a_ledger,
        const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_chain_ledger_token_emission_item_t *l_emission_item = s_emission_item_find(a_ledger, a_token_ticker, a_token_emission_hash);
    return l_emission_item ? l_emission_item->datum_token_emission : NULL;
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
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    if ( dap_hash_fast_is_blank(a_tx_hash) )
        return NULL;

    dap_chain_ledger_tx_item_t *l_item;
    unsigned l_hash_value;
    HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item);
    if (l_item) {
        pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
        return l_item->cache_data.token_ticker;
    }
    dap_chain_ledger_tx_spent_item_t *l_spent_item;
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->spent_items, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_spent_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return l_spent_item ? l_spent_item->cache_data.token_ticker : NULL;

}

/**
 * @brief dap_chain_ledger_addr_get_token_ticker_all_depricated
 * @param a_addr
 * @param a_tickers
 * @param a_tickers_size
 */
void dap_chain_ledger_addr_get_token_ticker_all_depricated(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size)
{
    dap_chain_hash_fast_t l_tx_first_hash = { 0 };
    const dap_chain_ledger_tx_item_t * l_tx_item = tx_item_find_by_addr(a_ledger, a_addr,NULL, &l_tx_first_hash);
    char ** l_tickers = NULL;
    size_t l_tickers_size = 10;
    size_t l_tickers_pos = 0;

    if(l_tx_item) {
        l_tickers = DAP_NEW_Z_SIZE(char *, l_tickers_size * sizeof(char*));
        if ( !l_tickers ) {
            log_it(L_CRITICAL, "Memory allocation error");
            return;
        }
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
                    if ( !l_tickers ) {
            log_it(L_CRITICAL, "Memory allocation error");
                        return;
                    }
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
        if ( !l_tickers ) {
            log_it(L_CRITICAL, "Memory allocation error");
            return;
        }
    }
    *a_tickers = l_tickers;
    *a_tickers_size = l_tickers_pos;
}


/**
 * @brief Get list of all tickets for ledger and address. If address is NULL returns all the tockens present in system
 * @param a_ledger
 * @param a_addr
 * @param a_tickers
 * @param a_tickers_size
 */
void dap_chain_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size)
{
    if (a_addr == NULL){ // Get all tockens
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        size_t l_count = HASH_COUNT(PVT(a_ledger)->tokens);
        if (l_count && a_tickers){
            dap_chain_ledger_token_item_t * l_token_item, *l_tmp;
            char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            if (!l_tickers) {
                log_it(L_CRITICAL, "Memory allocation error");
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
                log_it(L_CRITICAL, "Memory allocation error");
                pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
                return;
            }
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
        if(a_tickers_size)
            *a_tickers_size = l_count;
    }
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

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_datum_tx_t *l_tx_ret = NULL;
    dap_chain_ledger_tx_item_t *l_tx_item;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
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

void *dap_chain_ledger_tx_spent_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash)
{
    dap_chain_ledger_tx_spent_item_t *l_tx_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
    HASH_FIND(hh, PVT(a_ledger)->spent_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    return l_tx_item;
}

dap_hash_fast_t *dap_chain_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash)
{
    if (!a_ledger || !a_tx_hash || dap_hash_fast_is_blank(a_tx_hash))
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_item;
    unsigned l_hash_value;
    dap_chain_hash_fast_t *l_tx_hash = a_tx_hash;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    while (l_tx_hash) {
        HASH_VALUE(l_tx_hash, sizeof(*l_tx_hash), l_hash_value);
        HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->ledger_items, l_tx_hash, sizeof(*l_tx_hash), l_hash_value, l_item);
        if (l_item) {
            int l_out_num = 0;
            dap_chain_datum_tx_out_cond_get(l_item->tx, a_cond_type, &l_out_num);
            if (l_out_num != -1 && l_out_num < MAX_OUT_ITEMS) {
                if (dap_hash_fast_is_blank(&l_item->cache_data.tx_hash_spent_fast[l_out_num]))
                    break;      // We have unused conditional output
                else {
                    l_tx_hash = &l_item->cache_data.tx_hash_spent_fast[l_out_num];
                    continue;   // Conditional output is used out
                }
            } else {            // No conditional output found
                l_tx_hash = NULL;
                break;
            }
        }
        dap_chain_ledger_tx_spent_item_t *l_spent_item;
        HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->spent_items, l_tx_hash, sizeof(*l_tx_hash), l_hash_value, l_spent_item);
        if (l_spent_item && // We have condional output with spent item
                !dap_hash_fast_is_blank(&l_spent_item->cache_data.tx_hash_spent_fast)) {
            l_tx_hash = &l_spent_item->cache_data.tx_hash_spent_fast;
        } else
            l_tx_hash = NULL;   // We can't find pointed hash in the ledger or it's a not conditional tx
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return l_tx_hash;
}

/**
 * Check whether used 'out' items (local function)
 */
static bool s_ledger_tx_hash_is_used_out_item(dap_chain_ledger_tx_item_t *a_item, int a_idx_out, dap_hash_fast_t *a_out_spender_hash)
{
    if (!a_item || !a_item->cache_data.n_outs) {
        //log_it(L_DEBUG, "list_cached_item is NULL");
        return true;
    }
    if(a_idx_out >= MAX_OUT_ITEMS) {
        if(s_debug_more)
            log_it(L_ERROR, "Too big index(%d) of 'out' items (max=%d)", a_idx_out, MAX_OUT_ITEMS);
    }
    assert(a_idx_out < MAX_OUT_ITEMS);
    // if there are used 'out' items
    if ((a_item->cache_data.n_outs_used > 0) && !dap_hash_fast_is_blank(&(a_item->cache_data.tx_hash_spent_fast[a_idx_out]))) {
        if (a_out_spender_hash)
            *a_out_spender_hash = a_item->cache_data.tx_hash_spent_fast[a_idx_out];
        return true;
    }
    return false;
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
        if (a_data_size != sizeof (dap_chain_addr_t)){
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
 * Match the signature of the emission with the transaction
 *
 * return true or false
 */
bool s_tx_match_sign(dap_chain_datum_token_emission_t *a_datum_emission, dap_chain_datum_tx_t *a_tx)
{
    if(!a_datum_emission || !a_tx) {
        return false;
    }
    // First emission sign
    dap_sign_t *l_emission_sign = (dap_sign_t*) (a_datum_emission->tsd_n_signs + a_datum_emission->data.type_auth.tsd_total_size);
    size_t l_emission_sign_offset = (byte_t*) l_emission_sign - (byte_t*) a_datum_emission;
    int l_emission_sign_num = a_datum_emission->data.type_auth.signs_count;

    // Get all tx signs
    int l_tx_sign_num = 0;
    dap_list_t *l_list_sig = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_SIG, &l_tx_sign_num);

    if(!l_emission_sign_num || !l_tx_sign_num)
        return false;

    size_t l_emission_size = dap_chain_datum_emission_get_size((uint8_t*) a_datum_emission);
    dap_sign_t *l_sign = (dap_sign_t*) (a_datum_emission->tsd_n_signs + a_datum_emission->data.type_auth.tsd_total_size);
    size_t l_offset = (byte_t*) l_sign - (byte_t*) a_datum_emission;
    for(uint16_t i = 0; i < a_datum_emission->data.type_auth.signs_count && l_offset < l_emission_size; i++) {
        if(dap_sign_verify_size(l_sign, l_emission_size - l_offset)) {
            dap_chain_hash_fast_t l_sign_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);

            size_t l_sign_size = dap_sign_get_size(l_sign);
            l_offset += l_sign_size;
            l_sign = (dap_sign_t*) ((byte_t*) a_datum_emission + l_offset);
        } else
            break;
    }
    // For each emission signs
    for(int l_sign_em_num = 0; l_sign_em_num < l_emission_sign_num && l_emission_sign_offset < l_emission_size; l_sign_em_num++) {
        // For each tx signs
        for(dap_list_t *l_list_tmp = l_list_sig; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp)) {
            dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) l_list_tmp->data;
            // Get sign from sign item
            dap_sign_t *l_tx_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*) l_tx_sig);
            // Compare signs
            if(dap_sign_match_pkey_signs(l_emission_sign, l_tx_sign)) {
                dap_list_free(l_list_sig);
                return true;
            }
        }
        // Go to the next emission sign
        size_t l_sign_size = dap_sign_get_size(l_emission_sign);
        l_emission_sign_offset += l_sign_size;
        l_emission_sign = (dap_sign_t*) ((byte_t*) a_datum_emission + l_emission_sign_offset);
    }
    dap_list_free(l_list_sig);
    return false;
}

static int s_callback_sign_compare(dap_list_t *a_list_elem, dap_list_t *a_sign_elem)
{
    dap_pkey_t *l_key = (dap_pkey_t *)a_list_elem->data;
    dap_sign_t *l_sign = (dap_sign_t *)a_sign_elem->data;
    if (!l_key || !l_sign) {
        log_it(L_CRITICAL, "Invalid argument");
        return -1;
    }
    return !dap_pkey_match_sign(l_key, l_sign);
}

bool dap_chain_ledger_tx_poa_signed(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx)
{
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
    return dap_list_find(PVT(a_ledger)->poa_certs, l_sign, s_callback_sign_compare);
}


/**
 * Checking a new transaction before adding to the cache
 *
 * return 0 OK, otherwise error
 */
// Checking a new transaction before adding to the cache
int dap_chain_ledger_tx_cache_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash,
                                    bool a_from_threshold, dap_list_t **a_list_bound_items, dap_list_t **a_list_tx_out, char **a_main_ticker)
{
    if (!PVT(a_ledger)->load_mode && !a_from_threshold) {
        dap_chain_ledger_tx_item_t *l_ledger_item;
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_ledger_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (l_ledger_item) {     // transaction already present in the cache list
            if (s_debug_more) {
                char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
                log_it(L_WARNING, "Transaction %s already present in the cache", l_tx_hash_str);
            }
            return DAP_CHAIN_LEDGER_TX_ALREADY_CACHED;
        }
    }
/*
 * Steps of checking for current transaction tx2 and every previous transaction tx1:
 * 1. valid(tx2.dap_chain_datum_tx_sig.pkey)
 * &&
 * 2. !is_used_out(tx1.dap_chain_datum_tx_out)
 * &&
 * 3. tx1.output != tx2.bound_items.outputs.used
 * &&
 * 4. tx1.dap_chain_datum_tx_out.addr.data.key == tx2.dap_chain_datum_tx_sig.pkey for unconditional output
 * \\
 * 5. tx1.dap_chain_datum_tx_out.condition == verify_svc_type(tx2) for conditional output
 * &&
 * 6. sum(  find (tx2.input.tx_prev_hash).output[tx2.input_tx_prev_idx].value )  ==  sum (tx2.outputs.value) per token
 * &&
 * 7. valid(fee)
*/
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    if(!a_tx){
        log_it(L_DEBUG, "NULL transaction, check broken");
        return DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NULL_TX;
    }

    dap_list_t *l_list_bound_items = NULL;

    dap_list_t* l_list_tx_out = NULL;
    if (a_list_tx_out)
        *a_list_tx_out = l_list_tx_out;

    // sum of values in 'out' items from the previous transactions
    dap_chain_ledger_tokenizer_t *l_values_from_prev_tx = NULL, *l_values_from_cur_tx = NULL,
                                 *l_value_cur = NULL, *l_tmp = NULL, *l_res = NULL;
    const char *l_token = NULL, *l_main_ticker = NULL;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    dap_chain_hash_fast_t *l_emission_hash = NULL;

    // check all previous transactions
    int l_err_num = DAP_CHAIN_LEDGER_TX_CHECK_OK;
    int l_prev_tx_count = 0;

    // 1. Verify signature in current transaction
    if (!a_from_threshold && dap_chain_datum_tx_verify_sign(a_tx) != 1)
        return DAP_CHAIN_LEDGER_TX_CACHE_CHECK_INVALID_TX_SIGN;

    // ----------------------------------------------------------------
    // find all 'in' & conditional 'in' items in current transaction
    dap_list_t *l_list_in = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN_ALL,
                                                          &l_prev_tx_count);
    if (!l_list_in) {
        log_it(L_WARNING, "Tx check: no valid inputs found");
        return DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TX_NO_VALID_INPUTS;
    }
    dap_chain_ledger_tx_bound_t *bound_item;
    dap_chain_hash_fast_t l_hash_pkey = {};
    bool l_girdled_ems_used = false;
     // find all previous transactions
    dap_list_t *l_list_tmp = l_list_in;
    for (int l_list_tmp_num = 0; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_list_tmp_num++) {
        bound_item = DAP_NEW_Z(dap_chain_ledger_tx_bound_t);
        if (!bound_item) {
        log_it(L_CRITICAL, "Memory allocation error");
            if ( l_list_bound_items )
                dap_list_free_full(l_list_bound_items, NULL);
            if (l_list_tx_out)
                dap_list_free(l_list_tx_out);
            HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
                HASH_DEL(l_values_from_prev_tx, l_value_cur);
                DAP_DELETE(l_value_cur);
            }
            HASH_ITER(hh, l_values_from_cur_tx, l_value_cur, l_tmp) {
                HASH_DEL(l_values_from_cur_tx, l_value_cur);
                DAP_DELETE(l_value_cur);
            }
            return -1;
        }
        dap_chain_tx_in_t *l_tx_in = NULL;
        dap_chain_addr_t l_tx_in_from={0};
        dap_chain_tx_in_cond_t *l_tx_in_cond = NULL;
        dap_chain_tx_in_ems_t * l_tx_in_ems = NULL;
        dap_chain_hash_fast_t l_tx_prev_hash={0};
        uint8_t l_cond_type = *(uint8_t *)l_list_tmp->data;
        // one of the previous transaction
        switch (l_cond_type) {
        case TX_ITEM_TYPE_IN:
            l_tx_in = (dap_chain_tx_in_t *)l_list_tmp->data;
            l_tx_prev_hash = l_tx_in->header.tx_prev_hash;
            bound_item->in.tx_cur_in = l_tx_in;
            if (dap_hash_fast_is_blank(&l_tx_prev_hash))
                continue; // old base tx compliance
            break;
        case TX_ITEM_TYPE_IN_COND:
            l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_list_tmp->data;
            l_tx_prev_hash = l_tx_in_cond->header.tx_prev_hash;
            bound_item->in.tx_cur_in_cond = l_tx_in_cond;
            break;
        case TX_ITEM_TYPE_IN_EMS:
            l_tx_in_ems = (dap_chain_tx_in_ems_t *)l_list_tmp->data;
            l_tx_prev_hash =l_tx_in_ems->header.token_emission_hash;
            bound_item->in.tx_cur_in_ems = l_tx_in_ems;
            break;
        default:
            break;
        }
        bound_item->tx_prev_hash = l_tx_prev_hash;

        char l_tx_prev_hash_str[70]={[0]='\0'};
        dap_chain_hash_fast_to_str(&l_tx_prev_hash, l_tx_prev_hash_str, sizeof(l_tx_prev_hash_str));
        uint256_t l_value;
        void *l_tx_prev_out = NULL;
        dap_chain_datum_tx_t *l_tx_prev = NULL;
        dap_chain_ledger_token_emission_item_t *l_emission_item = NULL;
        dap_chain_ledger_stake_lock_item_t *l_stake_lock_emission = NULL;
        bool l_girdled_ems = false;
        if (l_cond_type == TX_ITEM_TYPE_IN_EMS) {   // It's the emission (base) TX
            l_token = l_tx_in_ems->header.ticker;
            l_emission_hash = &l_tx_in_ems->header.token_emission_hash;
            if ( (l_emission_item = s_emission_item_find(a_ledger, l_token, l_emission_hash)) ) {
                // check AUTH token emission
                if (!dap_hash_fast_is_blank(&l_emission_item->tx_used_out)) {
                    debug_if(s_debug_more, L_WARNING, "Emission for IN_EMS [%s] is already used", l_tx_in_ems->header.ticker);
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_IN_EMS_ALREADY_USED;
                    break;
                }
                bound_item->item_emission = l_emission_item;
            } else if ((l_girdled_ems = dap_hash_fast_is_blank(l_emission_hash)) ||
                            (l_stake_lock_emission = s_emissions_for_stake_lock_item_find(a_ledger, l_emission_hash))) {
                dap_chain_datum_tx_t *l_tx_stake_lock = a_tx;
                // check emission for STAKE_LOCK
                if (!dap_hash_fast_is_blank(l_emission_hash)) {
                    dap_hash_fast_t cur_tx_hash;
                    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &cur_tx_hash);
                    if (!dap_hash_fast_is_blank(&l_stake_lock_emission->tx_used_out)) {
                        if (!dap_hash_fast_compare(&cur_tx_hash, &l_stake_lock_emission->tx_used_out))
                            debug_if(s_debug_more, L_WARNING, "stake_lock_emission already present in cache for IN_EMS [%s]", l_token);
                        else
                            debug_if(s_debug_more, L_WARNING, "stake_lock_emission is used out for IN_EMS [%s]", l_token);
                        l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_IN_EMS_ALREADY_USED;
                        break;
                    }
                    l_tx_stake_lock = dap_chain_ledger_tx_find_by_hash(a_ledger, l_emission_hash);
                } else {
                    if (l_girdled_ems_used) {    // Only one allowed item with girdled emission
                        debug_if(s_debug_more, L_WARNING, "stake_lock_emission is used out for IN_EMS [%s]", l_token);
                        l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_IN_EMS_ALREADY_USED;
                        break;
                    } else
                        l_girdled_ems_used = true;
                }
                if (!l_tx_stake_lock) {
                    debug_if(s_debug_more, L_WARNING, "Not found stake_lock transaction");
                    l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
                    break;
                }
                dap_tsd_t *l_tsd;
                dap_chain_ledger_token_item_t *l_delegated_item = NULL;
                pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
                HASH_FIND_STR(PVT(a_ledger)->tokens, l_token, l_delegated_item);
                pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
                if (!l_delegated_item) {
                    debug_if(s_debug_more, L_WARNING, "Token [%s] not found", l_token);
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TICKER_NOT_FOUND;
                    break;
                }
                dap_chain_datum_token_t *l_datum_token = l_delegated_item->datum_token;
                if (l_datum_token->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE ||
                        !(l_tsd = dap_tsd_find(l_datum_token->data_n_tsd,
                                                  l_datum_token->header_native_decl.tsd_total_size,
                                                  DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
                    debug_if(s_debug_more, L_WARNING, "Token [%s] not valid for stake_lock transaction", l_token);
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_INVALID_TOKEN;
                    break;
                }
                dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
                if (!dap_chain_ledger_token_ticker_check(a_ledger, (char*)l_tsd_section->ticker_token_from)) {
                    debug_if(s_debug_more, L_WARNING, "Token [%s] not found", l_tsd_section->ticker_token_from);
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TICKER_NOT_FOUND;
                    break;
                }

                if (l_girdled_ems)
                    l_main_ticker = (const char *)l_tsd_section->ticker_token_from;

                dap_chain_tx_out_cond_t *l_tx_stake_lock_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_stake_lock, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, NULL);
                if (!l_tx_stake_lock_out_cond) {
                    debug_if(s_debug_more, L_WARNING, "No OUT_COND of stake_lock subtype for IN_EMS [%s]", l_tx_in_ems->header.ticker);
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS;
                    break;
                }
                uint256_t l_value_expected ={};
                if (MULT_256_COIN(l_tx_stake_lock_out_cond->header.value, l_tsd_section->emission_rate, &l_value_expected)!=0){
                    if(s_debug_more){
                        char * l_emission_rate_str = dap_chain_balance_print(l_tsd_section->emission_rate);
                        char * l_locked_value_str = dap_chain_balance_print(l_tx_stake_lock_out_cond->header.value);
                        log_it( L_WARNING, "Multiplication overflow for %s emission: locked value %s emission rate %s"
                        , l_tx_in_ems->header.ticker, l_locked_value_str, l_emission_rate_str);
                        DAP_DEL_Z(l_emission_rate_str);
                        DAP_DEL_Z(l_locked_value_str);
                    }
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_MULT256_OVERFLOW_EMS_LOCKED_X_RATE;
                    break;
                }
                dap_chain_tx_out_ext_t *l_tx_out_ext = NULL;
                uint256_t l_stake_lock_ems_value = {};
                int l_item_idx = 0;
                do {
                    l_tx_out_ext = (dap_chain_tx_out_ext_t *)dap_chain_datum_tx_item_get(a_tx, &l_item_idx, TX_ITEM_TYPE_OUT_EXT, NULL);
                    if (!l_tx_out_ext) {
                        if (l_girdled_ems) {
                            debug_if(s_debug_more, L_WARNING, "No OUT_EXT for girdled IN_EMS [%s]", l_tx_in_ems->header.ticker);
                            l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS;
                        }
                        break;
                    }
                    l_item_idx++;
                } while (strcmp(l_tx_out_ext->token, l_token));
                if (!l_tx_out_ext) {
                    dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_OUT, NULL);
                    if (!l_tx_out) {
                        debug_if(true, L_WARNING, "Can't find OUT nor OUT_EXT item for base TX with IN_EMS [%s]", l_tx_in_ems->header.ticker);
                        l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_NO_OUT_ITEMS_FOR_BASE_TX;
                        break;
                    } else
                        l_stake_lock_ems_value = l_tx_out->header.value;
                } else
                    l_stake_lock_ems_value = l_tx_out_ext->header.value;
                if (!IS_ZERO_256(l_delegated_item->total_supply) &&
                        compare256(l_delegated_item->current_supply, l_stake_lock_ems_value) < 0) {
                    char *l_balance = dap_chain_balance_print(l_delegated_item->current_supply);
                    char *l_value_ch = dap_chain_balance_print(l_stake_lock_ems_value);
                    log_it(L_WARNING, "Token current supply %s < emission value %s",
                           l_balance, l_value_ch);
                    DAP_DEL_Z(l_balance);
                    DAP_DEL_Z(l_value_ch);
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TOKEN_EMS_VALUE_EXEEDS_CUR_SUPPLY;
                    break;
                }
                if (!EQUAL_256(l_value_expected, l_stake_lock_ems_value)) {
                    char *l_value_expected_str = dap_chain_balance_print(l_value_expected);
                    char *l_locked_value_str = dap_chain_balance_print(l_stake_lock_ems_value);

                    debug_if(s_debug_more, L_WARNING, "Value %s != %s expected for [%s]",l_locked_value_str, l_value_expected_str,
                             l_tx_in_ems->header.ticker);

                    DAP_DEL_Z(l_value_expected_str);
                    DAP_DEL_Z(l_locked_value_str);
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_UNEXPECTED_VALUE;
                    break;
                }
                if (!l_girdled_ems) {
                    // check tiker
                    const char *l_tx_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, l_emission_hash);
                    if (!l_tx_ticker) {
                        debug_if(s_debug_more, L_WARNING, "No ticker found for stake_lock tx [expected '%s']", l_tx_in_ems->header.ticker);
                        l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_TICKER_NOT_FOUND;
                        break;
                    }
                    if (strcmp(l_tx_ticker, (char *)l_tsd_section->ticker_token_from)) {
                        debug_if(s_debug_more, L_WARNING, "Ticker '%s' != expected '%s'", l_tx_ticker, l_tx_in_ems->header.ticker);
                        l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_OTHER_TICKER_EXPECTED;
                        break;
                    }
                }
                debug_if(s_debug_more, L_NOTICE, "Check emission passed for IN_EMS [%s]", l_tx_in_ems->header.ticker);
                bound_item->tx_prev = l_tx_stake_lock;
                if (l_stake_lock_emission) {
                    bound_item->stake_lock_item = l_stake_lock_emission;
                    bound_item->stake_lock_item->ems_value = l_value_expected;
                } else // girdled emission
                    bound_item->out.tx_prev_out_ext_256 = l_tx_out_ext;
            } else {
                l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
                break;
            }
        } else { //It's not the emission TX
            // Get previous transaction in the cache by hash
            dap_chain_ledger_tx_item_t *l_item_out = NULL;
            l_tx_prev = s_find_datum_tx_by_hash(a_ledger, &l_tx_prev_hash, &l_item_out);
            if (!l_tx_prev) { // Unchained transaction or previous TX was already spent and removed from ledger
                dap_chain_ledger_tx_spent_item_t *l_used_item = dap_chain_ledger_tx_spent_find_by_hash(a_ledger, &l_tx_prev_hash);
                if (l_used_item) {
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_OUT_ITEM_ALREADY_USED;
                    debug_if(s_debug_more, L_INFO, "All 'out' items of previous tx %s were already spent", l_tx_prev_hash_str);
                    break;
                }
                debug_if(s_debug_more && !a_from_threshold, L_DEBUG, "No previous transaction was found for hash %s", l_tx_prev_hash_str);
                l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
                break;
            }
            bound_item->item_out = l_item_out;
            l_token = l_item_out->cache_data.token_ticker;
            debug_if(s_debug_more && !a_from_threshold, L_INFO, "Previous transaction was found for hash %s",l_tx_prev_hash_str);
            bound_item->tx_prev = l_tx_prev;

            // 2. Check if out in previous transaction has spent
            int l_idx = (l_cond_type == TX_ITEM_TYPE_IN) ? l_tx_in->header.tx_out_prev_idx : l_tx_in_cond->header.tx_out_prev_idx;
            dap_hash_fast_t l_spender;
            if (s_ledger_tx_hash_is_used_out_item(l_item_out, l_idx, &l_spender)) {
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_OUT_ITEM_ALREADY_USED;
                char l_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(&l_spender, l_hash, sizeof(l_hash));
                debug_if(s_debug_more, L_INFO, "'Out' item of previous tx %s already spent by %s", l_tx_prev_hash_str, l_hash);
                break;
            }

            // Get one 'out' item in previous transaction bound with current 'in' item
            l_tx_prev_out = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_idx);
            if(!l_tx_prev_out) {
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ITEM_NOT_FOUND;
                break;
            }
            // 3. Compare out in previous transaction with currently used out
            dap_list_t *l_bound_item;
            DL_FOREACH(l_list_bound_items, l_bound_item) {
                if (l_tx_prev_out == ((dap_chain_ledger_tx_bound_t*)l_bound_item->data)->out.tx_prev_out) {
                    debug_if(s_debug_more, L_ERROR, "Previous transaction output already used in current tx");
                    l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX;
                    break;
                }
            }
        }
        if (l_err_num)
            break;

        if (l_cond_type == TX_ITEM_TYPE_IN) {
            dap_chain_tx_item_type_t l_type = *(uint8_t *)l_tx_prev_out;
            dap_hash_fast_t *l_prev_out_addr_key = NULL;
            switch (l_type) {
            case TX_ITEM_TYPE_OUT_OLD:
                bound_item->out.tx_prev_out = l_tx_prev_out;
                l_tx_in_from = bound_item->out.tx_prev_out->addr;
                l_prev_out_addr_key = &bound_item->out.tx_prev_out->addr.data.hash_fast;
                l_value = dap_chain_uint256_from(bound_item->out.tx_prev_out->header.value);
                break;
            case TX_ITEM_TYPE_OUT: // 256
                bound_item->out.tx_prev_out_256 = l_tx_prev_out;
                l_tx_in_from = bound_item->out.tx_prev_out_256->addr;
                l_prev_out_addr_key = &bound_item->out.tx_prev_out_256->addr.data.hash_fast;
                l_value = bound_item->out.tx_prev_out_256->header.value;
                break;
            case TX_ITEM_TYPE_OUT_EXT: // 256
                bound_item->out.tx_prev_out_ext_256 = l_tx_prev_out;
                l_tx_in_from = bound_item->out.tx_prev_out_ext_256->addr;
                l_prev_out_addr_key = &bound_item->out.tx_prev_out_ext_256->addr.data.hash_fast;
                l_value = bound_item->out.tx_prev_out_ext_256->header.value;
                l_token = bound_item->out.tx_prev_out_ext_256->token;
                break;
            default:
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ITEM_NOT_FOUND;
                break;
            }
            if (l_err_num)
                break;

            // 4. compare public key hashes in the signature of the current transaction and in the 'out' item of the previous transaction
            if (dap_hash_fast_is_blank(&l_hash_pkey)) {
                // Get sign item
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(a_tx, NULL,
                        TX_ITEM_TYPE_SIG, NULL);
                // Get sign from sign item
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
                // calculate hash from sign public key
                dap_sign_get_pkey_hash(l_sign, &l_hash_pkey);
            }
            if (!dap_hash_fast_compare(&l_hash_pkey, l_prev_out_addr_key)) {
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PKEY_HASHES_DONT_MATCH;
                break;
            }
        } else if(l_cond_type == TX_ITEM_TYPE_IN_COND) { // TX_ITEM_TYPE_IN_COND
            if(*(uint8_t *)l_tx_prev_out != TX_ITEM_TYPE_OUT_COND) {
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ITEM_NOT_FOUND;
                break;
            }
            // 5a. Check for condition owner
            dap_chain_tx_sig_t *l_tx_prev_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_tx_prev, NULL, TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_prev_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_prev_sig);
            dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);

            dap_chain_tx_out_cond_t *l_tx_prev_out_cond = NULL;
            l_tx_prev_out_cond = (dap_chain_tx_out_cond_t *)l_tx_prev_out;
            if (l_tx_prev_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                l_main_ticker = l_token;
            else
                l_token = l_main_ticker = l_ledger_pvt->net_native_ticker;

            bool l_owner = false;
            l_owner = dap_sign_match_pkey_signs(l_prev_sign,l_sign);

            // 5b. Call verificator for conditional output
            dap_chain_ledger_verificator_t *l_verificator;
            int l_sub_tmp = l_tx_prev_out_cond->header.subtype;

            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_sub_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (!l_verificator || !l_verificator->callback) {
                debug_if(s_debug_more, L_ERROR, "No verificator set for conditional output subtype %d", l_sub_tmp);
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_VERIFICATOR_SET;
                break;
            }
            if (l_verificator->callback(a_ledger, l_tx_prev_out_cond, a_tx, l_owner) == false) {
                debug_if(s_debug_more, L_WARNING, "Verificator check error for conditional output %s",
                                                    dap_chain_tx_out_cond_subtype_to_str(l_sub_tmp));
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_VERIFICATOR_CHECK_FAILURE;
                break;
            }
            // calculate sum of values from previous transactions
            bound_item->out.tx_prev_out_cond_256 = l_tx_prev_out_cond;
            l_value = l_tx_prev_out_cond->header.value;
        } else if(l_cond_type == TX_ITEM_TYPE_IN_EMS) {
            if (l_stake_lock_emission) {
                l_token = bound_item->in.tx_cur_in_ems->header.ticker;
                l_value = bound_item->stake_lock_item->ems_value;
            } else if (l_girdled_ems) {
                l_token = bound_item->in.tx_cur_in_ems->header.ticker;
                l_value = bound_item->out.tx_prev_out_ext_256->header.value;
            } else {
                l_token = bound_item->item_emission->datum_token_emission->hdr.ticker;
                l_value = bound_item->item_emission->datum_token_emission->hdr.value_256;
            }
        }
        if (! l_token || !*l_token ) {
            log_it(L_WARNING, "No token ticker found in previous transaction");
            l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TICKER_NOT_FOUND;
            break;
        }
        // Get permissions
        l_token_item = NULL;
        pthread_rwlock_rdlock(&l_ledger_pvt->tokens_rwlock);
        HASH_FIND_STR(l_ledger_pvt->tokens, l_token, l_token_item);
        pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
        if (! l_token_item){
            if(s_debug_more)
                log_it(L_WARNING, "No token item found for token %s", l_token);
            l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TOKEN_NOT_FOUND;
            break;
        }
        // Check permissions
        if ( (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED ) ||  // If all is blocked - check if we're
             (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN) ){ // in white list

            if(!dap_chain_addr_is_blank(&l_tx_in_from) && s_ledger_permissions_check(l_token_item,
                                           DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD,&l_tx_in_from,
                                          sizeof (l_tx_in_from)) != 0 ){
                char * l_tmp_tx_in_from = dap_chain_addr_to_str(&l_tx_in_from);
                if(s_debug_more)
                    log_it(L_WARNING, "No permission for addr %s", l_tmp_tx_in_from?l_tmp_tx_in_from:"(null)");
                DAP_DELETE(l_tmp_tx_in_from);
                l_err_num = DAP_CHAIN_LEDGER_PERMISSION_CHECK_FAILED;
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
                l_err_num = DAP_CHAIN_LEDGER_PERMISSION_CHECK_FAILED;
                break;
            }
        }

        HASH_FIND_STR(l_values_from_prev_tx, l_token, l_value_cur);
        if (!l_value_cur) {
            l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
            if ( !l_value_cur ) {
        log_it(L_CRITICAL, "Memory allocation error");
                if (bound_item)
                    DAP_DELETE(bound_item);
                if ( l_list_bound_items )
                    dap_list_free_full(l_list_bound_items, NULL);
                if (l_list_tx_out)
                    dap_list_free(l_list_tx_out);
                return -1;
            }
            strcpy(l_value_cur->token_ticker, l_token);
            HASH_ADD_STR(l_values_from_prev_tx, token_ticker, l_value_cur);
        }
        // calculate  from previous transactions per each token
        SUM_256_256(l_value_cur->sum, l_value, &l_value_cur->sum);

        l_list_bound_items = dap_list_append(l_list_bound_items, bound_item);
    }

    if (l_list_in)
        dap_list_free(l_list_in);

    if (l_err_num) {
        DAP_DELETE(bound_item);
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, NULL);
        HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
            HASH_DEL(l_values_from_prev_tx, l_value_cur);
            DAP_DELETE(l_value_cur);
        }
        return l_err_num;
    }

    // 6. Compare sum of values in 'out' items in the current transaction and in the previous transactions
    // Calculate the sum of values in 'out' items from the current transaction
    bool l_multichannel = false;
    if (HASH_COUNT(l_values_from_prev_tx) > 1) {
        l_multichannel = true;
        if (HASH_COUNT(l_values_from_prev_tx) == 2 && !l_main_ticker) {
            HASH_FIND_STR(l_values_from_prev_tx, PVT(a_ledger)->net_native_ticker, l_value_cur);
            if (l_value_cur) {
                l_value_cur = l_value_cur->hh.next ? l_value_cur->hh.next : l_value_cur->hh.prev;
                l_main_ticker = l_value_cur->token_ticker;
            }
        }
    } else {
        l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
        if ( !l_value_cur ) {
        log_it(L_CRITICAL, "Memory allocation error");
            if (bound_item)
                DAP_DELETE(bound_item);
            if ( l_list_bound_items )
                dap_list_free_full(l_list_bound_items, NULL);
            if (l_list_tx_out)
                dap_list_free(l_list_tx_out);
            return -1;
        }
        dap_stpcpy(l_value_cur->token_ticker, l_token);
        if (!l_main_ticker)
            l_main_ticker = l_value_cur->token_ticker;
        HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
    }

    // find 'out' items
    dap_list_t *l_list_out = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
    uint256_t l_value = {}, l_fee_sum = {};
    bool l_fee_check = !IS_ZERO_256(l_ledger_pvt->fee_value) && !dap_chain_addr_is_blank(&l_ledger_pvt->fee_addr);
    int l_item_idx = 0;
    for (l_list_tmp = l_list_out; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_item_idx++) {
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
        dap_chain_addr_t l_tx_out_to={0};
        switch (l_type) {
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_tx_out = (dap_chain_tx_out_old_t *)l_list_tmp->data;
            if (l_multichannel) { // token ticker is mandatory for multichannel transactions
                l_err_num = -16;
                break;
            }
            l_value = dap_chain_uint256_from(l_tx_out->header.value);
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT: { // 256
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)l_list_tmp->data;
            if (l_multichannel) { // token ticker is mandatory for multichannel transactions
                if (l_main_ticker)
                    l_token = l_main_ticker;
                else {
                    l_err_num = -16;
                    break;
                }
            }
            l_value = l_tx_out->header.value;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_EXT: { // 256
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
            if (!l_multichannel) { // token ticker is depricated for single-channel transactions
                l_err_num = -16;
                break;
            }
            l_value = l_tx_out->header.value;
            l_token = l_tx_out->token;
            l_tx_out_to = l_tx_out->addr;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t *)l_list_tmp->data;
            if (l_multichannel) {
                if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                    l_token = (char *)PVT(a_ledger)->net_native_ticker;
                else if (l_main_ticker)
                    l_token = l_main_ticker;
                else {
                    log_it(L_WARNING, "No conditional output support for multichannel transaction");
                    l_err_num = -18;
                    break;
                }
            }
            l_value = l_tx_out->header.value;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        default: {}
        }
        if (l_multichannel) {
            HASH_FIND_STR(l_values_from_cur_tx, l_token, l_value_cur);
            if (!l_value_cur) {
                l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
                if ( !l_value_cur ) {
                    log_it(L_CRITICAL, "Memory allocation error");
                    if (bound_item)
                        DAP_DELETE(bound_item);
                    if ( l_list_bound_items )
                        dap_list_free_full(l_list_bound_items, NULL);
                    if (l_list_tx_out)
                        dap_list_free(l_list_tx_out);
                    return -1;
                }
                strcpy(l_value_cur->token_ticker, l_token);
                HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
            }
        }
        if (SUM_256_256(l_value_cur->sum, l_value, &l_value_cur->sum)) {
            debug_if(s_debug_more, L_WARNING, "Sum result overflow for tx_add_check with ticker %s",
                                    l_value_cur->token_ticker);
            l_err_num = -77;
            break;
        }

        // Get permissions for token
        l_token_item = NULL;
        pthread_rwlock_rdlock(&l_ledger_pvt->tokens_rwlock);
        if(l_ledger_pvt->tokens)
            HASH_FIND_STR(l_ledger_pvt->tokens,l_token, l_token_item);
        pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
        if (! l_token_item){
            if(s_debug_more)
                log_it(L_WARNING, "No token item found for token %s", l_token);
            l_err_num = -15;
            break;
        }
        // Check permissions

        if ( (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED )||   //  If all is blocked or frozen
             (l_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN) ){ //  check if we're in white list
            if(!dap_chain_addr_is_blank(&l_tx_out_to) && s_ledger_permissions_check(l_token_item, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD,&l_tx_out_to ,
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

        if (l_fee_check && dap_chain_addr_compare(&l_tx_out_to, &l_ledger_pvt->fee_addr) &&
                !dap_strcmp(l_value_cur->token_ticker, PVT(a_ledger)->net_native_ticker)) {
            SUM_256_256(l_fee_sum, l_value, &l_fee_sum);
        }
    }

    if ( l_list_out )
        dap_list_free(l_list_out);

    // Check for transaction consistency (sum(ins) == sum(outs))
    if (!l_err_num) {
        HASH_ITER(hh, l_values_from_prev_tx, l_value_cur, l_tmp) {
            HASH_FIND_STR(l_values_from_cur_tx, l_value_cur->token_ticker, l_res);
            if (!l_res || !EQUAL_256(l_res->sum, l_value_cur->sum) ) {
                if (s_debug_more) {
                    char *l_balance = dap_chain_balance_to_coins(l_res ? l_res->sum : uint256_0);
                    char *l_balance_cur = dap_chain_balance_to_coins(l_value_cur->sum);
                    log_it(L_ERROR, "Sum of values of out items from current tx (%s) is not equal outs from previous tx (%s) for token %s",
                            l_balance, l_balance_cur, l_value_cur->token_ticker);
                    DAP_DELETE(l_balance);
                    DAP_DELETE(l_balance_cur);
                }
                l_err_num = DAP_CHAIN_LEDGER_TX_CACHE_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS;
                break;
            }
        }
    }

    // 7. Check the network fee
    if (l_fee_check && compare256(l_fee_sum, l_ledger_pvt->fee_value) == -1) {
        // Check for PoA-cert-signed "service" no-tax tx
        if (!dap_chain_ledger_tx_poa_signed(a_ledger, a_tx)) {
            char *l_current_fee = dap_chain_balance_to_coins(l_fee_sum);
            char *l_expected_fee = dap_chain_balance_to_coins(l_ledger_pvt->fee_value);
            log_it(L_ERROR, "Fee value is invalid, expected %s pointed %s", l_expected_fee, l_current_fee);
            l_err_num = -55;
            DAP_DEL_Z(l_current_fee);
            DAP_DEL_Z(l_expected_fee);
        }
    }

    if (a_main_ticker && !l_err_num)
        *a_main_ticker = dap_strdup(l_main_ticker);

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
 * @brief dap_chain_ledger_tx_check
 * @param a_ledger
 * @param a_tx
 * @return
 */
int dap_chain_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, size_t a_datum_size, dap_hash_fast_t *a_datum_hash)
{
    if (!a_tx)
        return DAP_CHAIN_LEDGER_TX_CHECK_NULL_TX;

    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    if (l_tx_size != a_datum_size) {
        log_it (L_WARNING, "Inconsistent datum TX: datum size %zu != tx size %zu", a_datum_size, l_tx_size);
        return DAP_CHAIN_LEDGER_TX_CHECK_INVALID_TX_SIZE;
    }

    int l_ret_check = dap_chain_ledger_tx_cache_check(a_ledger, a_tx, a_datum_hash,
                                                      false, NULL, NULL, NULL);
    if(s_debug_more) {
        char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(a_datum_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
        if (l_ret_check)
            log_it(L_NOTICE, "Ledger TX adding check not passed for TX %s: error %s",
                   l_tx_hash_str, dap_chain_ledger_tx_check_err_str(l_ret_check));
        else
            log_it(L_INFO, "Ledger TX adding check passed for TX %s", l_tx_hash_str);
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
        char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
        if (dap_global_db_set(l_gdb_group, a_balance->key, &a_balance->balance, sizeof(uint256_t), false, NULL, NULL)) {
            debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch");
            return -1;
        }
        DAP_DELETE(l_gdb_group);
    }
    /* Notify the world*/
    struct json_object *l_json = wallet_info_json_collect(a_ledger, a_balance);
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    return 0;
}

static int s_sort_ledger_tx_item(dap_chain_ledger_tx_item_t* a, dap_chain_ledger_tx_item_t* b)
{
    return a->tx->header.ts_created == b->tx->header.ts_created ? 0 :
                a->tx->header.ts_created < b->tx->header.ts_created ? -1 : 1;
}


/**
 * @brief Add new transaction to the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
 * @return return 1 OK, -1 error
 */
int dap_chain_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold)
{
    return s_tx_add(a_ledger,a_tx,a_tx_hash,a_from_threshold,true);
}

/**
 * @brief Add new transaction to the cache list, without rwlocks lock
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
 * @return return 1 OK, -1 error
 */
static int s_tx_add_unsafe(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold)
{
    return s_tx_add(a_ledger,a_tx,a_tx_hash,a_from_threshold,false);
}

void dap_chain_ledger_set_tps_start_time(dap_ledger_t *a_ledger)
{
    clock_gettime(CLOCK_REALTIME, &PVT(a_ledger)->tps_start_time);
}

/**
 * @brief Add new transaction to the cache list
 * @param a_ledger
 * @param a_tx
 * @param a_tx_hash
 * @param a_from_threshold
 * @param a_safe_call True if we need to lock rwlock, false if not
 * @return return 1 OK, -1 error
 */
static inline int s_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold, bool a_safe_call)
{
    if(!a_tx) {
        debug_if(s_debug_more, L_ERROR, "NULL tx detected");
        return -1;
    }
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_list_t *l_list_bound_items = NULL;
    dap_list_t *l_list_tx_out = NULL;
    dap_chain_ledger_tx_item_t *l_item_tmp = NULL;
    char *l_main_token_ticker = NULL;

    if (!l_ledger_pvt->tps_timer) {
#ifndef DAP_TPS_TEST
        dap_chain_ledger_set_tps_start_time(a_ledger);
#endif
        l_ledger_pvt->tps_current_time.tv_sec = l_ledger_pvt->tps_start_time.tv_sec;
        l_ledger_pvt->tps_current_time.tv_nsec = l_ledger_pvt->tps_start_time.tv_nsec;
        l_ledger_pvt->tps_count = 0;
        if (dap_events_workers_init_status())
            l_ledger_pvt->tps_timer = dap_timerfd_start(500, s_ledger_tps_callback, l_ledger_pvt);
        else
            l_ledger_pvt->tps_timer = NULL;
    }
    bool l_from_threshold = a_from_threshold;
    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    int l_ret_check;
    l_item_tmp = NULL;
    if( (l_ret_check = dap_chain_ledger_tx_cache_check(a_ledger, a_tx, a_tx_hash, a_from_threshold,
                                                       &l_list_bound_items, &l_list_tx_out,
                                                       &l_main_token_ticker))) {
        if (l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS ||
                l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION) {
            if (!l_from_threshold) {
                unsigned l_hash_value = 0;
                HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
                pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
                HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->threshold_txs, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item_tmp);
                unsigned long long l_threshold_txs_count = HASH_COUNT(l_ledger_pvt->threshold_txs);
                if (!l_item_tmp) {
                    if (l_threshold_txs_count >= s_threshold_txs_max) {
                        if(s_debug_more)
                            log_it(L_WARNING, "Threshold for tranactions is overfulled (%zu max), dropping down new data, added nothing",
                                       s_threshold_txs_max);
                    } else {
                        l_item_tmp = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
                        if ( !l_item_tmp ) {
                            log_it(L_CRITICAL, "Memory allocation error");
                            return -1;
                        }
                        l_item_tmp->tx_hash_fast = *a_tx_hash;
                        l_item_tmp->tx = DAP_DUP_SIZE(a_tx, dap_chain_datum_tx_get_size(a_tx));
                        if ( !l_item_tmp->tx ) {
                            DAP_DELETE(l_item_tmp);
                            log_it(L_CRITICAL, "Memory allocation error");
                            return -1;
                        }
                        l_item_tmp->ts_added = dap_nanotime_now();
                        HASH_ADD_BYHASHVALUE(hh, l_ledger_pvt->threshold_txs, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_tmp);
                        if(s_debug_more)
                            log_it (L_DEBUG, "Tx %s added to threshold", l_tx_hash_str);
                    }
                }
                pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
            }
        } else {
            debug_if(s_debug_more, L_WARNING, "dap_chain_ledger_tx_add() tx %s not passed the check: %s ", l_tx_hash_str,
                        dap_chain_ledger_tx_check_err_str(l_ret_check));
        }
        return l_ret_check;
    }
    if(s_debug_more)
        log_it ( L_DEBUG, "dap_chain_ledger_tx_add() check passed for tx %s",l_tx_hash_str);

    // Mark 'out' items in cache if they were used & delete previous transactions from cache if it need
    // find all bound pairs 'in' and 'out'
    size_t l_outs_used = dap_list_length(l_list_bound_items);

    dap_store_obj_t *l_cache_used_outs = NULL;
    char *l_ledger_cache_group = NULL;
    if (PVT(a_ledger)->cached) {
        dap_store_obj_t *l_cache_used_outs = DAP_NEW_Z_SIZE(dap_store_obj_t, sizeof(dap_store_obj_t) * (l_outs_used + 1));
        if ( !l_cache_used_outs ) {
            if (l_item_tmp) {
                DAP_DEL_Z(l_item_tmp->tx);
                DAP_DELETE(l_item_tmp);
            }
            dap_list_free(l_list_bound_items);
            log_it(L_CRITICAL, "Memory allocation error");
            return -1;
        }
        l_ledger_cache_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
    }
    const char *l_cur_token_ticker = NULL;
    dap_list_t *l_list_tmp = l_list_bound_items;
    // Update balance: deducts
    for (int i = 1; l_list_tmp; i++) {
        dap_chain_ledger_tx_bound_t *bound_item = l_list_tmp->data;
        void *l_item_in = *(void **)&bound_item->in;
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_item_in;
        if (l_type == TX_ITEM_TYPE_IN_EMS) {
             // It's the emission behind
            dap_chain_tx_in_ems_t *l_in_ems = bound_item->in.tx_cur_in_ems;
            const char *l_delegated_ticker_str = l_in_ems->header.ticker;
            if (bound_item->tx_prev) { // It's the stake lock emission
                dap_chain_ledger_token_item_t *l_token_item = NULL;
                pthread_rwlock_rdlock(&l_ledger_pvt->tokens_rwlock);
                HASH_FIND_STR(l_ledger_pvt->tokens, l_delegated_ticker_str, l_token_item);
                pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
                if (l_token_item) {
                    if (!IS_ZERO_256(l_token_item->total_supply)) {
                        uint256_t *l_value = bound_item->stake_lock_item ?
                                    &bound_item->stake_lock_item->ems_value :
                                    &bound_item->out.tx_prev_out_ext_256->header.value;
                        SUBTRACT_256_256(l_token_item->current_supply, *l_value,
                                         &l_token_item->current_supply);
                        char *l_balance = dap_chain_balance_print(l_token_item->current_supply);
                        log_it(L_DEBUG, "New current supply %s for token %s", l_balance, l_token_item->ticker);
                        DAP_DEL_Z(l_balance);
                        if (PVT(a_ledger)->cached)
                            s_ledger_token_cache_update(a_ledger, l_token_item);
                    }
                } else
                    log_it(L_ERROR, "No token item found for token %s", l_delegated_ticker_str);
                if (bound_item->stake_lock_item) {
                    bound_item->stake_lock_item->tx_used_out = *a_tx_hash;
                    if (PVT(a_ledger)->cached)
                        // Mirror it in cache
                        s_ledger_stake_lock_cache_update(a_ledger, bound_item->stake_lock_item);
                }
            } else {    // It's the general emission
                // Mark it as used with base tx hash
                bound_item->item_emission->tx_used_out = *a_tx_hash;
                if (PVT(a_ledger)->cached)
                    // Mirror it in cache
                    s_ledger_emission_cache_update(a_ledger, bound_item->item_emission);
            }
            l_list_tmp = dap_list_next(l_list_tmp);
            i--;    // Do not calc this output with tx used items
            l_outs_used--;
            continue;
        }
        dap_chain_ledger_tx_item_t *l_prev_item_out = bound_item->item_out;
        if (l_prev_item_out->cache_data.n_outs <= l_prev_item_out->cache_data.n_outs_used) {
            log_it(L_ERROR, "[!] Irrelevant prev tx: out items mismatch %d <= %d",
                   l_prev_item_out->cache_data.n_outs, l_prev_item_out->cache_data.n_outs_used);
            l_list_tmp = dap_list_next(l_list_tmp);
            i--;
            l_outs_used--;
            continue;
        }
        l_cur_token_ticker = l_prev_item_out->cache_data.token_ticker;
        int l_tx_prev_out_used_idx = 0;
        if (l_type == TX_ITEM_TYPE_IN) {
            dap_chain_tx_in_t *l_tx_in = bound_item->in.tx_cur_in;
            dap_ledger_wallet_balance_t *wallet_balance = NULL;
            uint256_t l_value = {};
            dap_chain_addr_t *l_addr = NULL;
            void *l_item_out = *(void **)&bound_item->out;
            dap_chain_tx_item_type_t l_out_type = *(uint8_t *)l_item_out;
            switch (l_out_type) {
            case TX_ITEM_TYPE_OUT:
                l_addr = &bound_item->out.tx_prev_out_256->addr;
                l_value = bound_item->out.tx_prev_out_256->header.value;
                break;
            case TX_ITEM_TYPE_OUT_OLD:
                l_addr = &bound_item->out.tx_prev_out->addr;
                l_value = GET_256_FROM_64(bound_item->out.tx_prev_out->header.value);
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                l_addr = &bound_item->out.tx_prev_out_ext_256->addr;
                l_value = bound_item->out.tx_prev_out_ext_256->header.value;
                l_cur_token_ticker = bound_item->out.tx_prev_out_ext_256->token;
                break;
            default:
                log_it(L_DEBUG, "Unknown item type %d", l_out_type);
                break;
            }
            char *l_addr_str = dap_chain_addr_to_str(l_addr);
            char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
            pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
            HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
            pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
            if (wallet_balance) {
                if(s_debug_more) {
                    char *l_balance = dap_chain_balance_print(l_value);
                    log_it(L_DEBUG,"SPEND %s from addr: %s", l_balance, l_wallet_balance_key);
                    DAP_DELETE(l_balance);
                }
                SUBTRACT_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
                // Update the cache
                s_balance_cache_update(a_ledger, wallet_balance);
            } else {
                if(s_debug_more)
                    log_it(L_ERROR,"!!! Attempt to SPEND from some non-existent balance !!!: %s %s", l_addr_str, l_cur_token_ticker);
            }
            DAP_DELETE(l_addr_str);
            DAP_DELETE(l_wallet_balance_key);
            /// Mark 'out' item in cache because it used
            l_tx_prev_out_used_idx = l_tx_in->header.tx_out_prev_idx;
        } else {//TX_ITEM_TYPE_IN_COND
            // all balance deducts performed with previous conditional transaction
            dap_chain_tx_in_cond_t *l_tx_in_cond = bound_item->in.tx_cur_in_cond;
            /// Mark 'out' item in cache because it used
            l_tx_prev_out_used_idx = l_tx_in_cond->header.tx_out_prev_idx;
            dap_chain_tx_out_cond_t *l_cond = bound_item->out.tx_prev_out_cond_256;
            if (l_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                l_cur_token_ticker = (char *)PVT(a_ledger)->net_native_ticker;
            // Update service items if any
            dap_chain_ledger_verificator_t *l_verificator;
            int l_tmp = l_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_added)
                l_verificator->callback_added(a_ledger, a_tx, l_cond);
        }

        // add a used output
        l_prev_item_out->cache_data.tx_hash_spent_fast[l_tx_prev_out_used_idx] = *a_tx_hash;
        l_prev_item_out->cache_data.n_outs_used++;
        if (PVT(a_ledger)->cached) {
            // mirror it in the cache
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
            size_t l_tx_cache_sz = l_tx_size + sizeof(l_prev_item_out->cache_data);
            byte_t *l_tx_cache = DAP_NEW_Z_SIZE(byte_t, l_tx_cache_sz);
            memcpy(l_tx_cache, &l_prev_item_out->cache_data, sizeof(l_prev_item_out->cache_data));
            memcpy(l_tx_cache + sizeof(l_prev_item_out->cache_data), l_prev_item_out->tx, l_tx_size);
            char *l_tx_i_hash = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast);
            l_cache_used_outs[i] = (dap_store_obj_t) {
                    .key        = l_tx_i_hash,
                    .value      = l_tx_cache,
                    .value_len  = l_tx_cache_sz,
                    .group      = l_ledger_cache_group,
                    .type       = DAP_GLOBAL_DB_OPTYPE_ADD
            };
            l_cache_used_outs[i].timestamp = dap_nanotime_now();
        }

        // delete previous transactions from cache because all out is used
        if(l_prev_item_out->cache_data.n_outs_used == l_prev_item_out->cache_data.n_outs) {
            dap_chain_hash_fast_t *l_tx_prev_hash_to_del = &l_prev_item_out->tx_hash_fast; //&bound_item->tx_prev_hash;
            char l_tx_prev_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(l_tx_prev_hash_to_del, l_tx_prev_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            // remove from memory ledger
            int res = dap_chain_ledger_tx_remove(a_ledger, l_tx_prev_hash_to_del, a_tx->header.ts_created);
            switch (res) {
            case 1:
                debug_if(s_debug_more, L_INFO, "Deleted prev tx %s from ledger", l_tx_prev_hash_str);
                break;
            case -2:
                debug_if(s_debug_more, L_ERROR, "Can't delete previous transactions %s: hash not found", l_tx_prev_hash_str);
                l_ret = -100;
                l_outs_used = i;
                goto FIN;
            default:
                debug_if(s_debug_more, L_ERROR, "Can't delete previous transaction %s, res code %d", l_tx_prev_hash_str, res);
                l_ret = -101;
                l_outs_used = i;
                goto FIN;
            }
        }
        // go to next previous transaction
        l_list_tmp = dap_list_next(l_list_tmp);
    }


    //Update balance : raise
    bool l_multichannel = false;
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
            dap_chain_ledger_verificator_t *l_verificator;
            int l_tmp = l_cond->header.subtype;
            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (l_verificator && l_verificator->callback_added)
                l_verificator->callback_added(a_ledger, a_tx, NULL);
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
            l_multichannel = true;
        } break;
        default:
            log_it(L_DEBUG, "Unknown item type %d", l_type);
            break;
        }
        if (!l_addr)
            continue;
        else if (l_addr->net_id.uint64 != a_ledger->net_id.uint64 &&
                 !dap_chain_addr_is_blank(l_addr))
            l_cross_network = true;
        char *l_addr_str = dap_chain_addr_to_str(l_addr);
        dap_ledger_wallet_balance_t *wallet_balance = NULL;
        char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
        if(s_debug_more) {
            char *l_balance = dap_chain_balance_print(l_value);
            log_it(L_DEBUG, "GOT %s to addr: %s", l_balance, l_wallet_balance_key);
            DAP_DELETE(l_balance);
        }
        pthread_rwlock_rdlock(&l_ledger_pvt->balance_accounts_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
        pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
        if (wallet_balance) {
            //if(s_debug_more)
            //    log_it(L_DEBUG, "Balance item is present in cache");
            SUM_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            DAP_DELETE (l_wallet_balance_key);
            // Update the cache
            s_balance_cache_update(a_ledger, wallet_balance);
        } else {
            wallet_balance = DAP_NEW_Z(dap_ledger_wallet_balance_t);
            if (!wallet_balance) {
                log_it(L_ERROR, "Memoru allocation error in s_load_cache_gdb_loaded_txs_callback");
                l_ret = -1;
                goto FIN;
            }
            wallet_balance->key = l_wallet_balance_key;
            strcpy(wallet_balance->token_ticker, l_cur_token_ticker);
            SUM_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            if(s_debug_more)
                log_it(L_DEBUG, "Create new balance item: %s %s", l_addr_str, l_cur_token_ticker);
            pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
            HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, wallet_balance->key,
                            strlen(l_wallet_balance_key), wallet_balance);
            pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
            // Add it to cache
            s_balance_cache_update(a_ledger, wallet_balance);
        }
        DAP_DELETE (l_addr_str);
    }

    // add transaction to the cache list
    dap_chain_ledger_tx_item_t *l_tx_item = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
    if ( !l_tx_item ) {
        log_it(L_CRITICAL, "Memory allocation error");
        l_ret = -1;
        goto FIN;
    }
    l_tx_item->tx_hash_fast = *a_tx_hash;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    l_tx_item->tx = DAP_DUP_SIZE(a_tx, l_tx_size);
    l_tx_item->cache_data.ts_created = dap_time_now(); // Time of transasction added to ledger
    int l_outs_count = 0;
    dap_list_t *l_list_tmp2 = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, &l_outs_count);
    l_tx_item->cache_data.n_outs = l_outs_count;
    // TODO: dump the UTXO in debug mode if need

    if(l_list_tmp2)
        dap_list_free(l_list_tmp2);
    dap_stpcpy(l_tx_item->cache_data.token_ticker, l_main_token_ticker);

    l_tx_item->cache_data.multichannel = l_multichannel;
    if(a_safe_call) pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    l_tx_item->ts_added = dap_nanotime_now();
    HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t),
                         l_tx_item, s_sort_ledger_tx_item); // tx_hash_fast: name of key field
    if(a_safe_call) pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    // Callable callback
    dap_list_t *l_notifier;
    DL_FOREACH(PVT(a_ledger)->tx_add_notifiers, l_notifier) {
        dap_chain_ledger_tx_notifier_t *l_notify = (dap_chain_ledger_tx_notifier_t*)l_notifier->data;
        l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx);
    }
    if (l_cross_network) {
        dap_list_t *l_notifier;
        DL_FOREACH(PVT(a_ledger)->bridged_tx_notificators, l_notifier) {
            dap_chain_ledger_bridged_tx_notificator_t *l_notify = l_notifier->data;
            l_notify->callback(a_ledger, a_tx, a_tx_hash, l_notify->arg);
        }
    }
    // Count TPS
    clock_gettime(CLOCK_REALTIME, &l_ledger_pvt->tps_end_time);
    l_ledger_pvt->tps_count++;
    if (PVT(a_ledger)->cached) {
        // Add it to cache
        size_t l_tx_cache_sz = l_tx_size + sizeof(l_tx_item->cache_data);
        uint8_t *l_tx_cache = DAP_NEW_STACK_SIZE(uint8_t, l_tx_cache_sz);
        memcpy(l_tx_cache, &l_tx_item->cache_data, sizeof(l_tx_item->cache_data));
        memcpy(l_tx_cache + sizeof(l_tx_item->cache_data), a_tx, l_tx_size);
        l_cache_used_outs[0] = (dap_store_obj_t) {
                .key        = l_tx_hash_str,
                .value      = l_tx_cache,
                .value_len  = l_tx_cache_sz,
                .group      = l_ledger_cache_group,
                .type       = DAP_GLOBAL_DB_OPTYPE_ADD
        };
        l_cache_used_outs[0].timestamp = dap_nanotime_now();
        // Apply it with single DB transaction
        if (dap_global_db_set_raw(l_cache_used_outs, l_outs_used + 1, NULL, NULL))
            debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch");
    }
    if (!a_from_threshold)
        s_threshold_txs_proc(a_ledger);
FIN:
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, NULL);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    DAP_DEL_Z(l_main_token_ticker);
    if (PVT(a_ledger)->cached) {
        for (size_t i = 1; i <= l_outs_used; i++) {
            DAP_DEL_Z(l_cache_used_outs[i].key);
            DAP_DEL_Z(l_cache_used_outs[i].value);
        }
        DAP_DELETE(l_cache_used_outs);
        DAP_DELETE(l_ledger_cache_group);
    }
    return l_ret;
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
    if (PVT(a_ledger)->load_mode) {
        if (PVT(a_ledger)->cache_tx_check_callback)
            PVT(a_ledger)->cache_tx_check_callback(a_tx_hash);
        dap_chain_ledger_tx_item_t *l_tx_item;
        unsigned l_hash_value;
        HASH_VALUE(a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value);
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_item);
        if (l_tx_item) {
            pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
            return DAP_CHAIN_LEDGER_TX_ALREADY_CACHED;
        }
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->threshold_txs, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_item);
        if (l_tx_item) {
            pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
            return DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
        }
        dap_chain_ledger_tx_spent_item_t *l_tx_spent_item;
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->spent_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_spent_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
        if (l_tx_spent_item)
            return DAP_CHAIN_LEDGER_TX_CACHE_CHECK_OUT_ITEM_ALREADY_USED;
    }
    return dap_chain_ledger_tx_add(a_ledger, a_tx, a_tx_hash, false);
}

/**
 * Delete transaction from the cache
 *
 * return 1 OK, -1 error, -2 tx_hash not found
 */
int dap_chain_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, dap_time_t a_spent_time)
{
    if(!a_tx_hash)
        return -1;
    int l_ret = -1;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_item_tmp;
    unsigned l_hash_value;
    HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_tmp);
    if(l_item_tmp != NULL) {
        HASH_DEL(l_ledger_pvt->ledger_items, l_item_tmp);
        if (PVT(a_ledger)->cached) {
            // Remove it from cache
            char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
            char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
            dap_global_db_del(l_gdb_group, l_tx_hash_str, NULL, NULL);
            DAP_DELETE(l_gdb_group);
        }
        l_ret = 1;
        dap_chain_ledger_tx_spent_item_t *l_item_used;
        HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->spent_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_used);
        if (!l_item_used) {   // Add it to spent items
            l_item_used = DAP_NEW_Z(dap_chain_ledger_tx_spent_item_t);
            if ( !l_item_used ) {
                log_it(L_CRITICAL, "Memory allocation error");
                if (l_item_tmp->tx)
                    DAP_DELETE(l_item_tmp->tx);
                if (l_item_tmp)
                    DAP_DELETE(l_item_tmp);
                pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
                return -1;
            }
            l_item_used->tx_hash_fast = *a_tx_hash;
            l_item_used->cache_data.spent_time = a_spent_time;
            strncpy(l_item_used->cache_data.token_ticker, l_item_tmp->cache_data.token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
            int l_out_num = 0;
            dap_chain_datum_tx_out_cond_get(l_item_tmp->tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL, &l_out_num);
            if (l_out_num != -1 && l_out_num < MAX_OUT_ITEMS)
                l_item_used->cache_data.tx_hash_spent_fast = l_item_tmp->cache_data.tx_hash_spent_fast[l_out_num];
            HASH_ADD_BYHASHVALUE(hh, l_ledger_pvt->spent_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_used);
           if (PVT(a_ledger)->cached) {
                // Add it to cache
                char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
                char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
                if (dap_global_db_set(l_gdb_group, l_tx_hash_str, &l_item_used->cache_data, sizeof(l_item_used->cache_data), false, NULL, NULL))
                    debug_if(s_debug_more, L_WARNING, "Ledger cache mismatch");
                DAP_DELETE(l_gdb_group);
           }
        }
        // delete tx & its item
        DAP_DEL_Z(l_item_tmp->tx);
        DAP_DELETE(l_item_tmp);
    }
    else
        // hash not found in the cache
        l_ret = -2;
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return l_ret;
}

/**
 * Delete all transactions from the cache
 */
void dap_chain_ledger_purge(dap_ledger_t *a_ledger, bool a_preserve_db)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->ledger_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->tokens_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->threshold_emissions_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->threshold_txs_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->balance_accounts_rwlock);
    pthread_rwlock_wrlock(&l_ledger_pvt->stake_lock_rwlock);

    /* Delete regular transactions */
    dap_chain_ledger_tx_item_t *l_item_current, *l_item_tmp;
    char *l_gdb_group;
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_pvt->ledger_items, l_item_current);
        DAP_DELETE(l_item_current->tx);
        DAP_DEL_Z(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
        dap_global_db_del(l_gdb_group, NULL, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete spent transactions */
    dap_chain_ledger_tx_spent_item_t *l_spent_item_current, *l_spent_item_tmp;
    HASH_ITER(hh, l_ledger_pvt->spent_items, l_spent_item_current, l_spent_item_tmp) {
        HASH_DEL(l_ledger_pvt->spent_items, l_spent_item_current);
        DAP_DEL_Z(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
        dap_global_db_del(l_gdb_group, NULL, NULL, NULL);
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
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
        dap_global_db_del(l_gdb_group, NULL, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete tokens and their emissions */
    dap_chain_ledger_token_item_t *l_token_current, *l_token_tmp;
    dap_chain_ledger_token_emission_item_t *l_emission_current, *l_emission_tmp;
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
        DAP_DELETE(l_token_current->auth_pkeys_hash);
        DAP_DEL_Z(l_token_current->tx_recv_allow);
        DAP_DEL_Z(l_token_current->tx_recv_block);
        DAP_DEL_Z(l_token_current->tx_send_allow);
        DAP_DEL_Z(l_token_current->tx_send_block);
        pthread_rwlock_destroy(&l_token_current->token_emissions_rwlock);
        DAP_DELETE(l_token_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TOKENS_STR);
        dap_global_db_del(l_gdb_group, NULL, NULL, NULL);
        DAP_DELETE(l_gdb_group);
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
        dap_global_db_del(l_gdb_group, NULL, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete stake-lock items */
    dap_chain_ledger_stake_lock_item_t *l_stake_item_current, *l_stake_item_tmp;
    HASH_ITER(hh, l_ledger_pvt->emissions_for_stake_lock, l_stake_item_current, l_stake_item_tmp) {
        HASH_DEL(l_ledger_pvt->emissions_for_stake_lock, l_stake_item_current);
        DAP_DELETE(l_stake_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_STAKE_LOCK_STR);
        dap_global_db_del(l_gdb_group, NULL, NULL, NULL);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete threshold emissions */
    HASH_ITER(hh, l_ledger_pvt->threshold_emissions, l_emission_current, l_emission_tmp) {
        HASH_DEL(l_ledger_pvt->threshold_emissions, l_emission_current);
        DAP_DELETE(l_emission_current->datum_token_emission);
        DAP_DEL_Z(l_emission_current);
    }
    /* Delete threshold transactions */
    HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_pvt->threshold_txs, l_item_current);
        DAP_DELETE(l_item_current->tx);
        DAP_DEL_Z(l_item_current);
    }

    l_ledger_pvt->ledger_items         = NULL;
    l_ledger_pvt->spent_items          = NULL;
    l_ledger_pvt->balance_accounts     = NULL;
    l_ledger_pvt->tokens               = NULL;
    l_ledger_pvt->threshold_emissions  = NULL;
    l_ledger_pvt->threshold_txs        = NULL;

    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->tokens_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_emissions_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->balance_accounts_rwlock);
    pthread_rwlock_unlock(&l_ledger_pvt->stake_lock_rwlock);

    l_ledger_pvt->load_end = false;
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
uint64_t dap_chain_ledger_count_from_to(dap_ledger_t * a_ledger, dap_time_t a_ts_from, dap_time_t a_ts_to)
{
    uint64_t l_ret = 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    if ( a_ts_from && a_ts_to) {
        HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->cache_data.ts_created >= a_ts_from && l_iter_current->cache_data.ts_created <= a_ts_to )
            l_ret++;
        }
    } else if ( a_ts_to ){
        HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->cache_data.ts_created <= a_ts_to )
            l_ret++;
        }
    } else if ( a_ts_from ){
        HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp){
            if ( l_iter_current->cache_data.ts_created >= a_ts_from )
            l_ret++;
        }
    }else {
        HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp){
            l_ret++;
        }
    }

    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return l_ret;
}

size_t dap_chain_ledger_count_tps(dap_ledger_t *a_ledger, struct timespec *a_ts_from, struct timespec *a_ts_to)
{
    if (!a_ledger)
        return 0;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    if (a_ts_from) {
        a_ts_from->tv_sec = l_ledger_pvt->tps_start_time.tv_sec;
        a_ts_from->tv_nsec = l_ledger_pvt->tps_start_time.tv_nsec;
    }
    if (a_ts_to) {
        a_ts_to->tv_sec = l_ledger_pvt->tps_end_time.tv_sec;
        a_ts_to->tv_nsec = l_ledger_pvt->tps_end_time.tv_nsec;
    }
    return l_ledger_pvt->tps_count;
}

/**
 * Check whether used 'out' items
 */
bool dap_chain_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out, dap_hash_fast_t *a_out_spender)
{
    dap_chain_ledger_tx_item_t *l_item_out = NULL;
    //dap_chain_datum_tx_t *l_tx =
    s_find_datum_tx_by_hash(a_ledger, a_tx_hash, &l_item_out);
    return s_ledger_tx_hash_is_used_out_item(l_item_out, a_idx_out, a_out_spender);
}

/**
 * Calculate balance of addr
 *
 */
uint256_t dap_chain_ledger_calc_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                        const char *a_token_ticker)
{
    uint256_t l_ret = uint256_0;

    dap_ledger_wallet_balance_t *l_balance_item = NULL;// ,* l_balance_item_tmp = NULL;
    char *l_addr = dap_chain_addr_to_str(a_addr);
    char *l_wallet_balance_key = dap_strjoin(" ", l_addr, a_token_ticker, (char*)NULL);
    pthread_rwlock_rdlock(&PVT(a_ledger)->balance_accounts_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, l_balance_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->balance_accounts_rwlock);
    if (l_balance_item) {
        if(s_debug_more) {
            char *l_balance = dap_chain_balance_print(l_balance_item->balance);
            log_it(L_INFO, "Found address in cache with balance %s", l_balance);
            DAP_DELETE(l_balance);
        }
        l_ret = l_balance_item->balance;
    } else {
        if (s_debug_more)
            log_it (L_WARNING, "Balance item %s not found", l_wallet_balance_key);
    }
    DAP_DELETE(l_addr);
    DAP_DELETE(l_wallet_balance_key);
    return l_ret;
}

uint256_t dap_chain_ledger_calc_balance_full(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                             const char *a_token_ticker)
{
    uint256_t balance = uint256_0;

    if(!a_addr || !dap_chain_addr_check_sum(a_addr))
        return balance;

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp)
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
                // uint128_t l_ret;
                uint256_t l_ret = uint256_0;
                memset(&l_ret,0,sizeof(l_ret));
                return l_ret;
            }
        }
        int l_out_idx_tmp = 0;
        for (dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_out_idx_tmp++) {
            assert(l_list_tmp->data);
            dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
            if (l_type == TX_ITEM_TYPE_OUT_COND_OLD || (l_type == TX_ITEM_TYPE_OUT_COND)) {
                continue;
            }
            if (l_type == TX_ITEM_TYPE_OUT_OLD) {
                const dap_chain_tx_out_old_t *l_tx_out = (const dap_chain_tx_out_old_t*) l_list_tmp->data;
                // Check for token name
                if (!strcmp(a_token_ticker, l_iter_current->cache_data.token_ticker))
                {   // if transaction has the out item with requested addr
                    if (!memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                        // if 'out' item not used & transaction is valid
                        if(!s_ledger_tx_hash_is_used_out_item(l_iter_current, l_out_idx_tmp, NULL) &&
                                dap_chain_datum_tx_verify_sign(l_cur_tx)) {
                            // uint128_t l_add = dap_chain_uint128_from(l_tx_out->header.value);
                            // balance = dap_uint128_add(balance, l_add);
                            uint256_t l_add = dap_chain_uint256_from(l_tx_out->header.value);
                            SUM_256_256(balance, l_add, &balance);
                        }
                    }
                }
            }
            if (l_type == TX_ITEM_TYPE_OUT) { // 256
                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
                // const dap_chain_tx_out_old_t *l_tx_out = (const dap_chain_tx_out_old_t*) l_list_tmp->data;
                // Check for token name
                if (!strcmp(a_token_ticker, l_iter_current->cache_data.token_ticker))
                {   // if transaction has the out item with requested addr
                    if (!memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                        // if 'out' item not used & transaction is valid
                        if(!s_ledger_tx_hash_is_used_out_item(l_iter_current, l_out_idx_tmp, NULL) &&
                                dap_chain_datum_tx_verify_sign(l_cur_tx)) {
                            SUM_256_256(balance, l_tx_out->header.value, &balance);
                        }
                    }
                }
            }
            if (l_type == TX_ITEM_TYPE_OUT_EXT) { // 256
                const dap_chain_tx_out_ext_t *l_tx_out = (const dap_chain_tx_out_ext_t*) l_list_tmp->data;
                // const dap_chain_tx_out_ext_t *l_tx_out = (const dap_chain_tx_out_ext_t*) l_list_tmp->data;
                // Check for token name
                if (!strcmp(a_token_ticker, l_tx_out->token))
                {   // if transaction has the out item with requested addr
                    if (!memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                        // if 'out' item not used & transaction is valid
                        if(!s_ledger_tx_hash_is_used_out_item(l_iter_current, l_out_idx_tmp, NULL) &&
                                dap_chain_datum_tx_verify_sign(l_cur_tx)) {
                            SUM_256_256(balance, l_tx_out->header.value, &balance);
                        }
                    }
                }
            }
        }
        dap_list_free(l_list_out_items);
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
static dap_chain_ledger_tx_item_t* tx_item_find_by_addr(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                                        const char * a_token, dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_addr || !a_tx_first_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    bool is_tx_found = false;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp)
    {
        // If a_token is setup we check if its not our token - miss it
        if (a_token && *l_iter_current->cache_data.token_ticker &&
                dap_strcmp(l_iter_current->cache_data.token_ticker, a_token) &&
                !l_iter_current->cache_data.multichannel)
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
            if (l_type == TX_ITEM_TYPE_OUT_COND || l_type == TX_ITEM_TYPE_OUT_COND_OLD) {
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
            if (l_type == TX_ITEM_TYPE_OUT_OLD) {
                const dap_chain_tx_out_old_t *l_tx_out = (const dap_chain_tx_out_old_t *)l_list_tmp->data;
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
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
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
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current, *l_item_tmp;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items , l_iter_current, l_item_tmp) {
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
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
    return l_cur_tx;
}

/**
 * @brief Get all transactions from the cache with the out_cond item
 * @param a_ledger
 * @param a_srv_uid
 * @return
 */
dap_list_t* dap_chain_ledger_tx_cache_find_out_cond_all(dap_ledger_t *a_ledger, dap_chain_net_srv_uid_t a_srv_uid)
{
    dap_list_t * l_ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_iter_current, l_item_tmp) {
        dap_chain_datum_tx_t *l_tx = l_iter_current->tx;
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_COND, NULL), *l_out_item;
        DL_FOREACH(l_list_out_items, l_out_item) {
            if (((dap_chain_tx_out_cond_t*)l_out_item->data)->header.srv_uid.uint64 == a_srv_uid.uint64) // is srv uid is same as we're searching for?
                l_ret = dap_list_append(l_ret, l_tx);
        }
        dap_list_free(l_list_out_items);
    }
    return l_ret;
}


/**
 * Get the transaction in the cache with the out_cond item
 *
 * a_addr[in] wallet address, whose owner can use the service
 */
dap_chain_datum_tx_t* dap_chain_ledger_tx_cache_find_out_cond(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type,
        dap_chain_hash_fast_t *a_tx_first_hash, dap_chain_tx_out_cond_t **a_out_cond, int *a_out_cond_idx, char *a_token_ticker)
{
    if (!a_tx_first_hash)
        return NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current = NULL, *l_item_tmp = NULL;
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    int l_tx_out_cond_idx = 0;
    pthread_rwlock_rdlock(&l_ledger_pvt->ledger_rwlock);
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_iter_current, l_item_tmp) {
        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash_tmp, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get out_cond item from transaction
        l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_tmp, a_cond_type, &l_tx_out_cond_idx);

        if(l_tx_out_cond) {
            l_cur_tx = l_tx_tmp;
            memcpy(a_tx_first_hash, l_tx_hash_tmp, sizeof(dap_chain_hash_fast_t));
            if (a_token_ticker) {
                strcpy(a_token_ticker, l_iter_current->cache_data.token_ticker);
            }
            break;
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->ledger_rwlock);
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
uint256_t dap_chain_ledger_tx_cache_get_out_cond_value(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type,
                                                       dap_chain_addr_t *a_addr, dap_chain_tx_out_cond_t **tx_out_cond)

{
    uint256_t l_ret_value = {};

    dap_chain_datum_tx_t *l_tx_tmp;
    dap_chain_hash_fast_t l_tx_first_hash = { 0 }; // start hash
    /* size_t l_pub_key_size = a_key_from->pub_key_data_size;
     uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(a_key_from, &l_pub_key_size);*/
    dap_chain_tx_out_cond_t *l_tx_out_cond;
    // Find all transactions
    do {
        l_tx_tmp = dap_chain_ledger_tx_cache_find_out_cond(a_ledger, a_cond_type, &l_tx_first_hash, &l_tx_out_cond, NULL, NULL);
        // Get out_cond item from transaction
        if(l_tx_tmp) {
            UNUSED(a_addr);
            // TODO check relations a_addr with cond_data and public key
            if(l_tx_out_cond) {
                l_ret_value = l_tx_out_cond->header.value;
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
 * @return list of dap_chain_tx_used_out_item_t
 */
dap_list_t *dap_chain_ledger_get_list_tx_outs_with_val(dap_ledger_t *a_ledger, const char *a_token_ticker, const dap_chain_addr_t *a_addr_from,
                                                       uint256_t a_value_need, uint256_t *a_value_transfer)
{
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_hash_fast_t l_tx_cur_hash = { 0 };
    uint256_t l_value_transfer = {};
    while(compare256(l_value_transfer, a_value_need) == -1)
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
            uint256_t l_value = {};
            switch (l_type) {
                case TX_ITEM_TYPE_OUT_OLD: {
                    dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t *)l_list_tmp->data;
                    if (!l_out->header.value || memcmp(a_addr_from, &l_out->addr, sizeof(dap_chain_addr_t)))
                        continue;
                    l_value = GET_256_FROM_64(l_out->header.value);
                } break;
                case TX_ITEM_TYPE_OUT: {
                    dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_list_tmp->data;
                    if (memcmp(a_addr_from, &l_out->addr, sizeof(dap_chain_addr_t)) ||
                            dap_strcmp(dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_cur_hash), a_token_ticker) ||
                            IS_ZERO_256(l_out->header.value))
                        continue;
                    l_value = l_out->header.value;
                } break;
                case TX_ITEM_TYPE_OUT_EXT: {
                    dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
                    if (memcmp(a_addr_from, &l_out_ext->addr, sizeof(dap_chain_addr_t)) ||
                            strcmp((char *)a_token_ticker, l_out_ext->token) ||
                            IS_ZERO_256(l_out_ext->header.value) ) {
                        continue;
                    }
                    l_value = l_out_ext->header.value;
                } break;
                case TX_ITEM_TYPE_OUT_COND_OLD:
                case TX_ITEM_TYPE_OUT_COND:
                default:
                    continue;
            }
            // Check whether used 'out' items
            if (!dap_chain_ledger_tx_hash_is_used_out_item (a_ledger, &l_tx_cur_hash, l_out_idx_tmp, NULL)) {
                dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
                if ( !l_item ) {
                    log_it(L_CRITICAL, "Out of memory");
                    if (l_list_used_out)
                        dap_list_free_full(l_list_used_out, NULL);
                    dap_list_free(l_list_out_items);
                    return NULL;
                }
                l_item->tx_hash_fast = l_tx_cur_hash;
                l_item->num_idx_out = l_out_idx_tmp;
                l_item->value = l_value;
                l_list_used_out = dap_list_append(l_list_used_out, l_item);
                SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
                // already accumulated the required value, finish the search for 'out' items
                if (compare256(l_value_transfer, a_value_need) != -1) {
                    break;
                }
            }
        }
        dap_list_free(l_list_out_items);
    }

    // nothing to tranfer (not enough funds)
    if(!l_list_used_out || compare256(l_value_transfer, a_value_need) == -1) {
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }

    if (a_value_transfer) {
        *a_value_transfer = l_value_transfer;
    }
    return l_list_used_out;
}

// Add new verificator callback with associated subtype. Returns 1 if callback replaced, -1 error, overwise returns 0
int dap_chain_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype, dap_chain_ledger_verificator_callback_t a_callback, dap_chain_ledger_updater_callback_t a_callback_added)
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
    if (!l_new_verificator) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    l_new_verificator->subtype = (int)a_subtype;
    l_new_verificator->callback = a_callback;
    l_new_verificator->callback_added = a_callback_added;
    pthread_rwlock_wrlock(&s_verificators_rwlock);
    HASH_ADD_INT(s_verificators, subtype, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    return 0;
}

dap_list_t * dap_chain_ledger_get_txs(dap_ledger_t *a_ledger, size_t a_count, size_t a_page, bool a_reverse)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    size_t l_offset = a_page < 2 ? 0 : a_count * (a_page - 1);
    if (!l_ledger_pvt->ledger_items || l_offset > HASH_COUNT(l_ledger_pvt->ledger_items)){
        return NULL;
    }
    dap_list_t *l_list = NULL;
    size_t l_counter = 0;
    size_t l_end = l_offset + a_count;
    dap_chain_ledger_tx_item_t *l_item_current, *l_item_tmp;
    HASH_ITER(hh, l_ledger_pvt->ledger_items, l_item_current, l_item_tmp) {
        if (l_counter++ >= l_offset) {
            l_list = a_reverse
                    ? dap_list_prepend(l_list, l_item_current->tx)
                    : dap_list_append(l_list, l_item_current->tx);
        }
    }
    return l_list;
}

/**
 * @brief dap_chain_ledger_get_list_tx_cond_outs_with_val
 * @param a_ledger
 * @param a_token_ticker
 * @param a_addr_from
 * @param a_subtype
 * @param a_value_need
 * @param a_value_transfer
 * @return
 */
dap_list_t *dap_chain_ledger_get_list_tx_cond_outs_with_val(dap_ledger_t *a_ledger, const char *a_token_ticker,  const dap_chain_addr_t *a_addr_from,
        dap_chain_tx_out_cond_subtype_t a_subtype, uint256_t a_value_need, uint256_t *a_value_transfer)
{
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_hash_fast_t l_tx_cur_hash = { 0 };
    uint256_t l_value_transfer = { };
    while(compare256(l_value_transfer, a_value_need) == -1)
    {
        // Get the transaction in the cache by the addr in out item
        dap_chain_datum_tx_t *l_tx = dap_chain_ledger_tx_find_by_addr(a_ledger, a_token_ticker, a_addr_from, &l_tx_cur_hash);
        if(!l_tx)
            break;
        // Get all item from transaction by type
        dap_list_t *l_list_out_cond_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_COND, NULL);

        uint32_t l_out_idx_tmp = 0; // current index of 'out' item
        for(dap_list_t *l_list_tmp = l_list_out_cond_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_out_idx_tmp++) {
            dap_chain_tx_item_type_t l_type = *(uint8_t*) l_list_tmp->data;
            uint256_t l_value = { };
            switch (l_type) {
            case TX_ITEM_TYPE_OUT_COND: {
                dap_chain_tx_out_cond_t *l_out_cond = (dap_chain_tx_out_cond_t*) l_list_tmp->data;
                if(IS_ZERO_256(l_out_cond->header.value) || a_subtype != l_out_cond->header.subtype) {
                    continue;
                }
                l_value = l_out_cond->header.value;
            }
                break;
            default:
                continue;
            }
            if (!IS_ZERO_256(l_value)) {
                dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
                if ( !l_item ) {
                    if (l_list_used_out)
                        dap_list_free_full(l_list_used_out, NULL);
                    dap_list_free(l_list_out_cond_items);
                    return NULL;
                }
                l_item->tx_hash_fast = l_tx_cur_hash;
                l_item->num_idx_out = l_out_idx_tmp;
                l_item->value = l_value;
                l_list_used_out = dap_list_append(l_list_used_out, l_item);
                SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
                // already accumulated the required value, finish the search for 'out' items
                if (compare256(l_value_transfer, a_value_need) != -1) {
                    break;
                }
            }
        }
        dap_list_free(l_list_out_cond_items);
    }

    // nothing to tranfer (not enough funds)
    if(!l_list_used_out || compare256(l_value_transfer, a_value_need) == -1) {
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }

    if (a_value_transfer) {
        *a_value_transfer = l_value_transfer;
    }
    return l_list_used_out;
}

void dap_chain_ledger_tx_add_notify(dap_ledger_t *a_ledger, dap_chain_ledger_tx_add_notify_t a_callback, void *a_arg) {
    if (!a_ledger) {
        log_it(L_ERROR, "NULL ledger passed to dap_chain_ledger_tx_add_notify()");
        return;
    }
    if (!a_callback) {
        log_it(L_ERROR, "NULL callback passed to dap_chain_ledger_tx_add_notify()");
        return;
    }
    dap_chain_ledger_tx_notifier_t *l_notifier = DAP_NEW(dap_chain_ledger_tx_notifier_t);
    if (!l_notifier){
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_chain_ledger_tx_add_notify()");
        return;
    }
    l_notifier->callback = a_callback;
    l_notifier->arg = a_arg;
    PVT(a_ledger)->tx_add_notifiers = dap_list_append(PVT(a_ledger)->tx_add_notifiers, l_notifier);
}

void dap_chain_ledger_bridged_tx_notify_add(dap_ledger_t *a_ledger, dap_chain_ledger_bridged_tx_notify_t a_callback, void *a_arg)
{
    if (!a_ledger || !a_callback)
        return;
    dap_chain_ledger_bridged_tx_notificator_t *l_notifier = DAP_NEW_Z(dap_chain_ledger_bridged_tx_notificator_t);
    if (!l_notifier) {
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_chain_ledger_tx_add_notify()");
        return;
    }
    l_notifier->callback = a_callback;
    l_notifier->arg = a_arg;
    PVT(a_ledger)->bridged_tx_notificators = dap_list_append(PVT(a_ledger)->bridged_tx_notificators , l_notifier);
}

bool dap_chain_ledger_cache_enabled(dap_ledger_t *a_ledger)
{
    return PVT(a_ledger)->cached;
}

void dap_chain_ledger_set_cache_tx_check_callback(dap_ledger_t *a_ledger, dap_chain_ledger_cache_tx_check_callback_t a_callback)
{
    PVT(a_ledger)->cache_tx_check_callback = a_callback;
}

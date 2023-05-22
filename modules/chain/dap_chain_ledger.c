﻿/*
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
#include "dap_chain_datum_tx_token.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_mempool.h"
#include "dap_chain_global_db.h"
#include "dap_chain_ledger.h"
#include "dap_chain_pvt.h"
#include "json.h"
#include "dap_notify_srv.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stake_lock.h"

#define LOG_TAG "dap_chain_ledger"

typedef struct dap_chain_ledger_verificator {
    int subtype;    // hash key
    dap_chain_ledger_verificator_callback_t callback;
    dap_chain_ledger_verificator_callback_out_t callback_added;
    UT_hash_handle hh;
} dap_chain_ledger_verificator_t;

static dap_chain_ledger_verificator_t *s_verificators;
static  pthread_rwlock_t s_verificators_rwlock;

#define MAX_OUT_ITEMS   10

typedef struct dap_chain_ledger_stake_lock_item {
    dap_chain_hash_fast_t	tx_for_stake_lock_hash;
	dap_chain_hash_fast_t	tx_used_out;
//	const char 				datum_token_emission_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
	UT_hash_handle hh;
} dap_chain_ledger_stake_lock_item_t;

typedef struct dap_chain_ledger_token_emission_item {
    dap_chain_hash_fast_t datum_token_emission_hash;
    dap_chain_datum_token_emission_t *datum_token_emission;
    size_t datum_token_emission_size;
    dap_chain_hash_fast_t tx_used_out;
    dap_gdb_time_t ts_added;
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
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint16_t type;
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
    dap_chain_hash_fast_t * auth_pkeys_hash;
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
    dap_gdb_time_t ts_added;
    struct {
        dap_time_t ts_created;
        uint32_t n_outs;
        uint32_t n_outs_used;
        char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        char padding[6];
        byte_t multichannel;
        char pad[15];
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

// dap_ledget_t private section
typedef struct dap_ledger_private {
    dap_chain_net_t * net;
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

    pthread_rwlock_t threshold_txs_rwlock;
    pthread_rwlock_t threshold_emissions_rwlock;
    pthread_rwlock_t balance_accounts_rwlock;
    pthread_rwlock_t stake_lock_rwlock;
    uint16_t check_flags;
    bool check_ds;
    bool check_cells_ds;
    bool check_token_emission;
    dap_chain_cell_id_t local_cell_id;

    bool load_mode;
    bool cached;
    // TPS section
    dap_timerfd_t *tps_timer;
    struct timespec tps_start_time;
    struct timespec tps_current_time;
    struct timespec tps_end_time;
    size_t tps_count;
    // Threshold fee
    dap_timerfd_t *threshold_txs_fee_timer;
    dap_timerfd_t *threshold_emissions_fee_timer;
} dap_ledger_private_t;
#define PVT(a) ( (dap_ledger_private_t* ) a->_internal )


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
    uint16_t l_net_count = 0;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for(uint16_t i =0; i < l_net_count; i++) {
        dap_chain_ledger_purge(l_net_list[i]->pub.ledger, true);
    }
    DAP_DELETE(l_net_list);
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
    dap_ledger_private_t * l_ledger_pvt;
    l_ledger->_internal = l_ledger_pvt = DAP_NEW_Z(dap_ledger_private_t);

    // Initialize Read/Write Lock Attribute
    pthread_rwlock_init(&l_ledger_pvt->ledger_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->tokens_rwlock, NULL);
    pthread_rwlock_init(&l_ledger_pvt->threshold_txs_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->threshold_emissions_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->balance_accounts_rwlock , NULL);
    pthread_rwlock_init(&l_ledger_pvt->stake_lock_rwlock, NULL);
    l_ledger_pvt->threshold_txs_fee_timer = dap_interval_timer_create(s_threshold_free_timer_tick,
                                                                     (dap_timer_callback_t)s_threshold_txs_free, l_ledger);
    l_ledger_pvt->threshold_emissions_fee_timer = dap_interval_timer_create(s_threshold_free_timer_tick,
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
        char *l_addr_str = DAP_NEW_S_SIZE(char, l_addr_len + 1);
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
            log_it(L_WARNING,"This upadate already applied for token with ticker '%s' ", a_token_update->ticker);
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
	if (a_cur_token_item->auth_signs_total != auth_signs_total
	||	a_cur_token_item->auth_signs_valid != auth_signs_valid) {
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
		for(uint16_t i = 0; i < auth_signs_total; i++){
            dap_pkey_t *l_pkey_upd_token = dap_sign_get_pkey_deserialization(l_signs_upd_token[i]);
			if (!dap_pkey_match(a_cur_token_item->auth_pkeys[i], l_pkey_upd_token)) {
				DAP_DEL_Z(l_signs_upd_token);
                DAP_DELETE(l_pkey_upd_token);
				if(s_debug_more)
					log_it(L_WARNING, "Can't update token with ticker '%s' because: Signs not compare", a_token_update->ticker);
				return false;
			}
            DAP_DELETE(l_pkey_upd_token);
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
    if (a_token_update->type  == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
        l_tsd_total_size = a_token_update->header_native_update.tsd_total_size;
    else if (a_token_update->type  == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE)
        l_tsd_total_size = a_token_update->header_native_update.tsd_total_size;
    // Checking that the TSD section with the threshold change is the only one.
    //And getting lists of TSD sections with the removal and addition of certificates.
    int l_quantity_tsd_section_edit_signs_emission = 0;
    dap_tsd_t *l_tsd_signs_valid = NULL;
    dap_list_t *l_tsd_list_remote_pkeys = NULL;
    int l_quantity_tsd_remote_pkeys = 0;
    dap_list_t *l_tsd_list_added_pkeys = NULL;
    int l_quantity_tsd_add_pkeys = 0;
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
        dap_list_free1(l_tsd_list_added_pkeys);
        dap_list_free1(l_tsd_list_remote_pkeys);
        return false;
    }
    //Check new count signs
    size_t l_new_signs_total = auth_signs_total + l_quantity_tsd_add_pkeys - l_quantity_tsd_remote_pkeys;
    if (l_tsd_signs_valid) {
        size_t l_signs_valid_from_tsd = (size_t)(dap_tsd_get_scalar(l_tsd_signs_valid,uint16_t));
        if (l_new_signs_total < l_signs_valid_from_tsd || l_signs_valid_from_tsd < 1) {
            dap_list_free1(l_tsd_list_added_pkeys);
            dap_list_free1(l_tsd_list_remote_pkeys);
            return false;
        }
    } else {
        if (l_new_signs_total < auth_signs_valid){
            dap_list_free1(l_tsd_list_added_pkeys);
            dap_list_free1(l_tsd_list_remote_pkeys);
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
            dap_hash_fast_t l_hash = dap_tsd_get_scalar(l_tsd, dap_hash_fast_t);
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
        dap_list_free1(l_tsd_list_added_pkeys);
        dap_list_free1(l_tsd_list_remote_pkeys);
        return false;
    }
    //Check added signs
    dap_chain_datum_token_t *l_token_tmp = DAP_DUP_SIZE(a_token_update, a_token_update_size);
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
    dap_list_free1(l_tsd_list_added_pkeys);
    dap_list_free1(l_tsd_list_remote_pkeys);
    DAP_DELETE(l_token_tmp);
    return isAccepted;
}

/**
 * @brief dap_chain_ledger_token_check
 * @param a_ledger
 * @param a_token
 * @return
 */
int dap_chain_ledger_token_decl_add_check(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if ( !a_ledger){
        if(s_debug_more)
            log_it(L_ERROR, "NULL ledger, can't add datum with token declaration!");
        return  -1;
    }

	bool update_token = false;
    dap_chain_ledger_token_item_t *l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token->ticker, l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);

	if (a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE
	||	a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
		update_token = true;

    if	(l_token_item != NULL) {
		if (update_token == false) {
        	log_it(L_WARNING,"Duplicate token declaration for ticker '%s' ", a_token->ticker);
        	return -3;
		} else if (s_ledger_token_update_check(l_token_item, a_token, a_token_size) == false) {
			return -2;
		}
    }
	else if	(l_token_item == NULL && update_token == true) {
		log_it(L_WARNING,"Can't update token that doesn't exist for ticker '%s' ", a_token->ticker);
		return -6;
	}
    // Check signs
    size_t l_signs_unique = 0;
    size_t l_size_tsd_section = 0;
    switch (a_token->type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL:
			l_size_tsd_section = a_token->header_native_decl.tsd_total_size;
			break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
            l_size_tsd_section = a_token->header_private_decl.tsd_total_size;
            break;
		case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE:
			l_size_tsd_section = a_token->header_native_update.tsd_total_size;
			break;
		case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
			l_size_tsd_section = a_token->header_private_update.tsd_total_size;
			break;
    }
    size_t l_signs_size = a_token_size - sizeof(dap_chain_datum_token_t) - l_size_tsd_section;
    dap_sign_t **l_signs = dap_sign_get_unique_signs(a_token->data_n_tsd + l_size_tsd_section, l_signs_size, &l_signs_unique);
    if (l_signs_unique >= a_token->signs_total){
        size_t l_signs_approve = 0;
        for (size_t i=0; i < l_signs_unique; i++) {
            dap_sign_t *l_sign = l_signs[i];
            if (!dap_sign_verify_all(l_sign, l_signs_size, a_token, sizeof(dap_chain_datum_token_t) - sizeof(uint16_t))) {
                l_signs_approve++;
            }
        }
        if (l_signs_approve >= a_token->signs_total){
            return 0;
        } else {
            log_it(L_WARNING, "The token declaration has %zu valid signatures out of %hu.", l_signs_approve, a_token->signs_total);
            return -5;
        }
    } else {
        log_it(L_WARNING, "The number of unique token signs %zu is less than total token signs set to %hu.",
               l_signs_unique, a_token->signs_total);
        return -4;
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
    // transaction time
    char l_time_str[32] = "unknown";
    if (a_tx->header.ts_created) {
        uint64_t l_ts = a_tx->header.ts_created;
        dap_ctime_r(&l_ts, l_time_str);
    }
    char *l_tx_hash_str;
    if (!dap_strcmp(a_hash_out_type, "hex")) {
        l_tx_hash_str = dap_chain_hash_fast_to_str_new(a_tx_hash);
    } else {
        l_tx_hash_str = dap_enc_base58_encode_hash_to_str(a_tx_hash);
    }
    dap_string_append_printf(a_str_out, "TX hash %s  \n\t%s",l_tx_hash_str, l_time_str);
    DAP_DELETE(l_tx_hash_str);
}

char * dap_ledger_token_tx_item_list(dap_ledger_t * a_ledger, dap_chain_addr_t *a_addr, const char *a_hash_out_type)
{
        dap_string_t *l_str_out =dap_string_new(NULL);

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
            for (dap_list_t *it = l_list_in_items; it; it = it->next) {
                assert(it->data);
                dap_chain_hash_fast_t *l_tx_prev_hash;
                int l_tx_prev_out_idx;
                dap_chain_datum_tx_t *l_tx_prev = NULL;
                if (*(byte_t *)l_list_in_items->data == TX_ITEM_TYPE_IN) {
                    dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)l_list_in_items->data;
                    l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                    l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
                } else { // TX_ITEM_TYPE_IN_COND
                    dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_list_in_items->data;
                    l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                    l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
                }
                if (dap_hash_fast_is_blank(l_tx_prev_hash)) {
                    l_base_tx = true;
                    dap_chain_tx_token_t *l_token = (dap_chain_tx_token_t *)dap_chain_datum_tx_item_get(
                                                                            l_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL);
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
    uint8_t *l_cache = DAP_NEW_S_SIZE(uint8_t, l_cache_size);
    memcpy(l_cache, &l_token_item->current_supply, sizeof(uint256_t));
    memcpy(l_cache + sizeof(uint256_t), l_token_item->datum_token, l_token_item->datum_token_size);
    if (!dap_chain_global_db_gr_set(l_token_item->ticker, l_cache, l_cache_size, l_gdb_group)) {
        char *l_supply = dap_chain_balance_print(l_token_item->current_supply);
        log_it(L_WARNING, "Ledger cache mismatch, can't add token [%s] with supply %s", l_token_item->ticker, l_supply);
        DAP_FREE(l_supply);
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
int dap_chain_ledger_token_add(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if (!a_ledger){
        if(s_debug_more)
            log_it(L_ERROR, "NULL ledger, can't add datum with token declaration!");
        return  -1;
    }

	bool update_token = false;
	if (a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE
	||	a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
		update_token = true;

    dap_chain_ledger_token_item_t * l_token_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_FIND_STR(PVT(a_ledger)->tokens, a_token->ticker,l_token_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);

	if	(l_token_item != NULL) {
		if (update_token == false) {
			log_it(L_WARNING,"Duplicate token declaration for ticker '%s' ", a_token->ticker);
			return -3;
		} else if (s_ledger_token_update_check(l_token_item, a_token, a_token_size) == true) {
			if (s_ledger_update_token_add_in_hash_table(l_token_item, a_token, a_token_size) == false) {
				if (s_debug_more)
					log_it(L_ERROR, "Failed to add ticker '%s' to hash-table", a_token->ticker);
				return -5;
			}
			if (!IS_ZERO_256(a_token->total_supply)){
				SUBTRACT_256_256(l_token_item->total_supply, l_token_item->current_supply, &l_token_item->current_supply);
				SUBTRACT_256_256(a_token->total_supply, l_token_item->current_supply, &l_token_item->current_supply);
			} else {
				l_token_item->current_supply = a_token->total_supply;
			}
			l_token_item->total_supply = a_token->total_supply;
            DAP_DEL_Z(l_token_item->datum_token);
		} else {
			return -2;
		}
	}
	else if	(l_token_item == NULL && update_token == true) {
		log_it(L_WARNING,"Can't update token that doesn't exist for ticker '%s' ", a_token->ticker);
		return -6;
	}

	dap_chain_datum_token_t *l_token = a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE ?
									   dap_chain_datum_token_read((byte_t *)a_token, &a_token_size) : a_token;

	if (update_token == false) {//create new token
    	l_token_item = DAP_NEW_Z(dap_chain_ledger_token_item_t);
        dap_snprintf(l_token_item->ticker,sizeof (l_token_item->ticker), "%s", l_token->ticker);
    	pthread_rwlock_init(&l_token_item->token_emissions_rwlock,NULL);
    	pthread_rwlock_init(&l_token_item->token_ts_updated_rwlock,NULL);
        l_token_item->type = l_token->type;
        l_token_item->total_supply      = l_token->total_supply;
        l_token_item->current_supply	= l_token_item->total_supply;
        l_token_item->auth_signs_total  = l_token->signs_total;
        l_token_item->auth_signs_valid  = l_token->signs_valid;
        dap_sign_t **l_signs		= dap_chain_datum_token_signs_parse(l_token, a_token_size,
                                                                     &l_token_item->auth_signs_total,&l_token_item->auth_signs_valid);
        if (l_token_item->auth_signs_total) {
            l_token_item->auth_pkeys = DAP_NEW_Z_SIZE(dap_pkey_t*, sizeof(dap_pkey_t*) * l_token_item->auth_signs_total);
            l_token_item->auth_pkeys_hash = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, sizeof(dap_chain_hash_fast_t) * l_token_item->auth_signs_total);
            for(uint16_t k=0; k<l_token_item->auth_signs_total;k++){
                l_token_item->auth_pkeys[k] = dap_sign_get_pkey_deserialization(l_signs[k]);
                dap_pkey_get_hash(l_token_item->auth_pkeys[k], &l_token_item->auth_pkeys_hash[k]);
            }
        }
    }

    l_token_item->datum_token_size  = a_token_size;
    l_token_item->datum_token       = DAP_DUP_SIZE(l_token, a_token_size);
    l_token_item->datum_token->type = l_token_item->type;

	if (update_token == false) {
		pthread_rwlock_wrlock(&PVT(a_ledger)->tokens_rwlock);
		HASH_ADD_STR(PVT(a_ledger)->tokens, ticker, l_token_item);
		pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
	}

    switch(a_token->type) {
    case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
    case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:
        if(s_debug_more) {
            char *l_balance = dap_chain_balance_to_coins(l_token->total_supply);
            log_it(L_NOTICE, "Simple token %s added (total_supply = %s total_signs_valid=%hu signs_total=%hu)",
                    l_token->ticker, l_balance,
                    l_token->signs_valid, l_token->signs_total);
            DAP_DEL_Z(l_balance);
        }
        break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
        if(s_debug_more) {
            char *l_balance = dap_chain_balance_to_coins(a_token->total_supply);
            log_it(L_NOTICE, "Private token %s added (total_supply = %s total_signs_valid=%hu signs_total=%hu)",
                    a_token->ticker, l_balance,
                    a_token->signs_valid, a_token->signs_total);
            DAP_DEL_Z(l_balance);
        }
        s_token_tsd_parse(a_ledger,l_token_item, a_token, a_token_size);
        break;
   case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL:
        if(s_debug_more) {
            char *l_balance = dap_chain_balance_to_coins(a_token->total_supply);
            log_it(L_NOTICE, "CF20 token %s added (total_supply = %s total_signs_valid=%hu signs_total=%hu)",
                    a_token->ticker, l_balance,
                    a_token->signs_valid, a_token->signs_total);
            DAP_DEL_Z(l_balance);
        }
        s_token_tsd_parse(a_ledger,l_token_item, a_token, a_token_size);
        break;
    case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
        if(s_debug_more) {
			char *l_balance = dap_chain_balance_to_coins(a_token->total_supply);
			log_it(L_NOTICE, "Private token %s updated (total_supply = %s total_signs_valid=%hu signs_total=%hu)",
				   a_token->ticker, l_balance,
				   a_token->signs_valid, a_token->signs_total);
			DAP_DEL_Z(l_balance);
		}
//      log_it( L_WARNING, "Private token %s type=DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE. Not processed, wait for software update", a_token->ticker);
//		TODO: Check authorithy
        s_token_tsd_parse(a_ledger,l_token_item, a_token, a_token_size);
        s_tsd_sign_apply(a_ledger, l_token_item, a_token, a_token_size);
        break;
	case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE:
		if(s_debug_more) {
			char *l_balance = dap_chain_balance_to_coins(a_token->total_supply);
			log_it(L_NOTICE, "CF20 token %s updated (total_supply = %s total_signs_valid=%hu signs_total=%hu)",
				   a_token->ticker, l_balance,
				   a_token->signs_valid, a_token->signs_total);
			DAP_DEL_Z(l_balance);
		}
//      log_it( L_WARNING, "Private token %s type=DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE. Not processed, wait for software update", a_token->ticker);
// 		TODO: Check authorithy
		s_token_tsd_parse(a_ledger,l_token_item, a_token, a_token_size);
        s_tsd_sign_apply(a_ledger, l_token_item, a_token, a_token_size);
		break;
    default:
        if(s_debug_more)
            log_it(L_WARNING,"Unknown token declaration type 0x%04X", a_token->type );
    }

    s_threshold_emissions_proc(a_ledger); //TODO process thresholds only for no-consensus chains
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
           // set flags
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS:{
                a_token_item->flags |= dap_tsd_get_scalar(l_tsd,uint16_t);
            }break;

           // unset flags
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS:{
                a_token_item->flags ^= dap_tsd_get_scalar(l_tsd,uint16_t);
            }break;

            // set total supply
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY:{ // 256
                a_token_item->total_supply = dap_tsd_get_scalar(l_tsd,uint256_t);
            }break;

            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_OLD:{ // 128
                a_token_item->total_supply = GET_256_FROM_128(dap_tsd_get_scalar(l_tsd,uint128_t));
            }break;

            //Allowed tx receiver addres list add, remove or clear
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:{
                if( l_tsd->size == sizeof (dap_chain_addr_t) ){

                    if (a_token_item->tx_recv_allow)
                        a_token_item->tx_recv_allow = DAP_REALLOC(a_token_item->tx_recv_allow,(a_token_item->tx_recv_allow_size+1)*sizeof (*a_token_item->tx_recv_allow));
                    else
                        a_token_item->tx_recv_allow = DAP_NEW_Z_SIZE( dap_chain_addr_t,sizeof(*a_token_item->tx_recv_allow));

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
                                char * l_addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) l_tsd->data );
                                if(s_debug_more)
                                    log_it(L_ERROR,"TSD param DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD has address %s thats already present in list",
                                       l_addr_str);
                                DAP_DELETE(l_addr_str);
                                DAP_DELETE(l_addrs);
                                DAP_DEL_Z(a_token_item->tx_recv_allow)
                                return -11;
                            }
                        }

                    if(l_addrs){
                        l_addrs[a_token_item->tx_recv_block_size] = *(dap_chain_addr_t*)l_tsd->data;
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
                        l_addrs[a_token_item->tx_send_allow_size] = *(dap_chain_addr_t*)l_tsd->data;
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
                        l_addrs[a_token_item->tx_send_block_size] = *(dap_chain_addr_t*)l_tsd->data;
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
        dap_hash_fast_t l_hash = dap_tsd_get_scalar(l_tsd, dap_chain_hash_fast_t);
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
        a_token_item->auth_signs_valid = dap_tsd_get_scalar(l_new_signs_valid,uint16_t);
    }
    return 0;
}

/**
 * @brief dap_chain_ledger_get_net
 * @param a_ledger
 * @return
 */
dap_chain_net_t * dap_chain_ledger_get_net(dap_ledger_t * a_ledger)
{
    return PVT(a_ledger)->net;
}

int dap_chain_ledger_token_load(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if (PVT(a_ledger)->load_mode) {
		bool update_token = (a_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE && a_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE) ? false : true;
        dap_chain_ledger_token_item_t *l_token_item;
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->tokens, a_token->ticker, l_token_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        if (l_token_item && update_token == false)
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
        dap_sprintf(l_item_size, ", tx_item_size: %zu\n", l_emission_item->datum_token_emission_size);
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
    uint32_t l_counter = 0;
    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
    HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp){ 
        if (!memcmp(l_threshold_hash,&l_tx_item->tx_hash_fast, sizeof(dap_chain_hash_fast_t))){
            char l_tx_hash_str[70]={0};
            dap_chain_hash_fast_to_str(l_threshold_hash,l_tx_hash_str,sizeof(l_tx_hash_str));
            dap_string_append(l_str_ret, "Hash was found in ledger tx threshold: ");
            dap_string_append(l_str_ret, l_tx_hash_str);
            dap_string_append(l_str_ret, "\n");
            return l_str_ret;
        }
    }
    pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock);

    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_emissions_rwlock);
    l_counter = 0;
    dap_chain_ledger_token_emission_item_t *l_emission_item, *l_emission_tmp;
    HASH_ITER(hh, l_ledger_pvt->threshold_emissions, l_emission_item, l_emission_tmp){  
        if (!memcmp(&l_emission_item->datum_token_emission_hash,l_threshold_hash, sizeof(dap_chain_hash_fast_t))){
            char l_emission_hash_str[70]={0};
            dap_chain_hash_fast_to_str(l_threshold_hash,l_emission_hash_str,sizeof(l_emission_hash_str));
            dap_string_append(l_str_ret, "Hash was found in ledger emission threshold: ");
            dap_string_append(l_str_ret, l_emission_hash_str);
            dap_string_append(l_str_ret, "\n");
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
    HASH_ITER(hh, l_ledger_pvt->balance_accounts, l_balance_item, l_balance_tmp){  
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

dap_list_t *dap_chain_ledger_token_info(dap_ledger_t *a_ledger)
{
    dap_list_t		*l_ret_list = NULL;
	dap_string_t	*l_str_tmp;
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
		l_str_tmp = dap_string_new(NULL);
        const char *l_type_str;
        const char *l_flags_str = s_flag_str_from_code(l_token_item->datum_token->header_private_decl.flags);;
        switch (l_token_item->type) {
            case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE: // 256
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
                l_type_str = "SIMPLE"; break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL: // 256
                l_type_str = "PRIVATE"; break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE: // 256
                l_type_str = "PRIVATE_UPDATE"; break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL: // 256
                l_type_str = "CF20"; break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE: // 256
                l_type_str = "CF20_UPDATE"; break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC: // 256
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
                l_type_str = "PUBLIC";
            default:
                l_type_str = "UNKNOWN"; break;
        }
       char *l_item_str = NULL;

        if ((l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL)
		||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
		||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL)
		||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE)){
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
                                                &l_token_item->ticker, l_type_str, s_flag_str_from_code(l_token_item->datum_token->header_native_decl.flags),
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
                                                &l_token_item->ticker, l_type_str, "SIMPLE token has no flags",
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

//returns -1 if no ticker found
size_t dap_chain_ledger_token_auth_signs_valid(dap_ledger_t *a_ledger, const char * a_token_ticker)
{
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    size_t l_res = -1;
    
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (!dap_strcmp(l_token_item->ticker, a_token_ticker)) {
            l_res = l_token_item->auth_signs_valid;
            break;
        }
    }

    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    
    return l_res;
}

size_t dap_chain_ledger_token_auth_signs_total(dap_ledger_t *a_ledger, const char * a_token_ticker)
{
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    size_t l_res = -1;
    
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (!dap_strcmp(l_token_item->ticker, a_token_ticker)) {
            l_res = l_token_item->auth_signs_total;
            break;
        }
    }

    pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
    
    return l_res;
}

dap_list_t * dap_chain_ledger_token_auth_signs_hashes(dap_ledger_t *a_ledger, const char * a_token_ticker)
{
    dap_list_t * l_ret = NULL;
    dap_chain_ledger_token_item_t *l_token_item, *l_tmp_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
    
    HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp_item) {
        if (!dap_strcmp(l_token_item->ticker, a_token_ticker))
        {
            debug_if(s_debug_more, L_INFO, " ! Token %s : total %lu auth signs", a_token_ticker, l_token_item->auth_signs_total);
            for (uint16_t i=0; i< l_token_item->auth_signs_total; i++) {
                l_ret = dap_list_append(l_ret, (dap_chain_hash_fast_t*)(&l_token_item->auth_pkeys_hash[i]));
            }
            break;
        }
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
        pthread_rwlock_rdlock(&PVT(a_ledger)->threshold_emissions_rwlock);
        HASH_ITER(hh, PVT(a_ledger)->threshold_emissions, l_emission_item, l_emission_tmp) {
            pthread_rwlock_unlock(&PVT(a_ledger)->threshold_emissions_rwlock);
            int l_res = dap_chain_ledger_token_emission_add(a_ledger, (byte_t *)l_emission_item->datum_token_emission,
                                                            l_emission_item->datum_token_emission_size,
                                                            &l_emission_item->datum_token_emission_hash, true);
            if (l_res != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN) {
                pthread_rwlock_wrlock(&PVT(a_ledger)->threshold_emissions_rwlock);
                HASH_DEL(PVT(a_ledger)->threshold_emissions, l_emission_item);
                pthread_rwlock_unlock(&PVT(a_ledger)->threshold_emissions_rwlock);
                if (l_res)
                    DAP_DELETE(l_emission_item->datum_token_emission);
                DAP_DELETE(l_emission_item);
                l_success = true;
            }

            pthread_rwlock_rdlock(&PVT(a_ledger)->threshold_emissions_rwlock);
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
    pthread_rwlock_rdlock(&l_ledger_pvt->threshold_txs_rwlock);
    do {
        l_success = false;
        dap_chain_ledger_tx_item_t *l_tx_item, *l_tx_tmp;
        HASH_ITER(hh, l_ledger_pvt->threshold_txs, l_tx_item, l_tx_tmp) {
            pthread_rwlock_unlock(&l_ledger_pvt->threshold_txs_rwlock );
            int l_res = dap_chain_ledger_tx_add(a_ledger, l_tx_item->tx, &l_tx_item->tx_hash_fast, true);
            pthread_rwlock_wrlock(&l_ledger_pvt->threshold_txs_rwlock);
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
 * @breif s_threshold_txs_free
 * @param a_ledger
 */
static void s_threshold_txs_free(dap_ledger_t *a_ledger){
    log_it(L_DEBUG, "Start free treshold txs");
    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_current = NULL, *l_tmp = NULL;
    dap_gdb_time_t l_time_cut_off = dap_gdb_time_now() - dap_gdb_time_from_sec(7200); //7200 sec = 2 hours.
    pthread_rwlock_wrlock(&l_pvt->threshold_txs_rwlock);
    HASH_ITER(hh, l_pvt->threshold_txs, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            HASH_DEL(l_pvt->threshold_txs, l_current);
            char *l_hash_tx = dap_chain_hash_fast_to_str_new(&l_current->tx_hash_fast);
            DAP_DELETE(l_current->tx);
            DAP_DELETE(l_current);
            log_it(L_NOTICE, "Removed transaction %s form treshold ledger", l_hash_tx);
            DAP_DELETE(l_hash_tx);
        }
    }
    pthread_rwlock_unlock(&l_pvt->threshold_txs_rwlock);
}

/**
 * @breif s_threshold_emission_free
 * @param a_ledger
 */
static void s_threshold_emission_free(dap_ledger_t *a_ledger){
    log_it(L_DEBUG, "Start free treshold emission");
    dap_ledger_private_t *l_pvt = PVT(a_ledger);
    dap_chain_ledger_token_emission_item_t *l_current = NULL, *l_tmp = NULL;
    dap_gdb_time_t l_time_cut_off = dap_gdb_time_now() - dap_gdb_time_from_sec(7200); //7200 sec = 2 hours.
    pthread_rwlock_wrlock(&l_pvt->threshold_emissions_rwlock);
    HASH_ITER(hh, l_pvt->threshold_emissions, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            char *l_hash_token = dap_chain_hash_fast_to_str_new(&l_current->datum_token_emission_hash);
            HASH_DEL(l_pvt->threshold_emissions, l_current);
            DAP_DELETE(l_current->datum_token_emission);
            log_it(L_NOTICE, "Removed token emission %s form treshold ledger", l_hash_token);
            DAP_DELETE(l_hash_token);
        }
    }
    pthread_rwlock_unlock(&l_pvt->threshold_emissions_rwlock);
}

void dap_chain_ledger_load_cache(dap_ledger_t *a_ledger)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TOKENS_STR);
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        if (l_objs[i].value_len <= sizeof(uint256_t))
            continue;
        dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t *)(l_objs[i].value + sizeof(uint256_t));
        size_t l_token_size = l_objs[i].value_len - sizeof(uint256_t);
        if (strcmp(l_token->ticker, l_objs[i].key)) {
            log_it(L_WARNING, "Corrupted token with ticker [%s], need to 'ledger reload' to update cache", l_objs[i].key);
            continue;
        }
        dap_chain_ledger_token_add(a_ledger, l_token, l_token_size);
        dap_chain_ledger_token_item_t *l_token_item = NULL;
        HASH_FIND_STR(l_ledger_pvt->tokens, l_token->ticker, l_token_item);
        if (!l_token_item) {
            log_it(L_WARNING, "Can't load token with ticker [%s], need to 'ledger reload' to update cache", l_token->ticker);
            continue;
        }
        l_token_item->current_supply = *(uint256_t*)l_objs[i].value;
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);

    l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
    l_objs_count = 0;
    l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        if (l_objs[i].value_len <= sizeof(dap_hash_fast_t))
            continue;
        const char *c_token_ticker = ((dap_chain_datum_token_emission_t *)
                                      (l_objs[i].value + sizeof(dap_hash_fast_t)))->hdr.ticker;
        dap_chain_ledger_token_item_t *l_token_item = NULL;
        HASH_FIND_STR(l_ledger_pvt->tokens, c_token_ticker, l_token_item);
        if (!l_token_item) {
            log_it(L_WARNING, "Not found token with ticker [%s], need to 'ledger reload' to update cache", c_token_ticker);
            continue;
        }
        dap_chain_ledger_token_emission_item_t *l_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_emission_item->datum_token_emission_hash);
        l_emission_item->tx_used_out = *(dap_hash_fast_t*)l_objs[i].value;
        l_emission_item->datum_token_emission = DAP_DUP_SIZE(l_objs[i].value + sizeof(dap_hash_fast_t),
                                                             l_objs[i].value_len - sizeof(dap_hash_fast_t));
        l_emission_item->datum_token_emission_size = l_objs[i].value_len - sizeof(dap_hash_fast_t);
        HASH_ADD(hh, l_token_item->token_emissions, datum_token_emission_hash,
                 sizeof(dap_chain_hash_fast_t), l_emission_item);
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);

	l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_STAKE_LOCK_STR);
	l_objs_count = 0;
	l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
	for (size_t i = 0; i < l_objs_count; i++) {
        if (l_objs[i].value_len != sizeof(dap_hash_fast_t))
			continue;
        dap_chain_ledger_stake_lock_item_t *l_new_stake_lock_emission = DAP_NEW(dap_chain_ledger_stake_lock_item_t);
        if (!l_new_stake_lock_emission) {
            debug_if(s_debug_more, L_ERROR, "Error: memory allocation when try adding item 'dap_chain_ledger_stake_lock_item_t' to hash-table");
			continue;
		}
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_new_stake_lock_emission->tx_for_stake_lock_hash);
        l_new_stake_lock_emission->tx_used_out = *(dap_hash_fast_t *)(l_objs[i].value);
        HASH_ADD(hh, l_ledger_pvt->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
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
        memcpy(&l_tx_item->cache_data, l_objs[i].value, sizeof(l_tx_item->cache_data));
        memcpy(l_tx_item->tx, l_objs[i].value + sizeof(l_tx_item->cache_data), l_objs[i].value_len - sizeof(l_tx_item->cache_data));
        l_tx_item->ts_added = dap_gdb_time_now();
        HASH_ADD_INORDER(hh, l_ledger_pvt->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_tx_item, s_sort_ledger_tx_item);
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);

    l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
    l_objs_count = 0;
    l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; i++) {
        dap_chain_ledger_tx_spent_item_t *l_tx_spent_item = DAP_NEW_Z(dap_chain_ledger_tx_spent_item_t);
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_tx_spent_item->tx_hash_fast);
        l_tx_spent_item->cache_data = *(typeof(((dap_chain_ledger_tx_spent_item_t*)0)->cache_data)*)l_objs[i].value;
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
        l_balance_item->balance = *(uint256_t *)l_objs[i].value;
        HASH_ADD_KEYPTR(hh, l_ledger_pvt->balance_accounts, l_balance_item->key,
                        strlen(l_balance_item->key), l_balance_item);
        /* Notify the world */
        /*struct json_object *l_json = wallet_info_json_collect(a_ledger, l_balance_item);
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);*/ // TODO: unstable and spammy
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

    log_it(L_DEBUG,"Created ledger \"%s\"",a_net_name);
    l_ledger_priv->load_mode = true;
    l_ledger_priv->tps_timer = NULL;
    l_ledger_priv->tps_count = 0;
    if (dap_config_get_item_bool_default(g_config, "ledger", "cache_enabled", true)) {
        dap_chain_node_role_t l_role = dap_chain_net_get_role(l_ledger_priv->net);
        if (l_role.enums != NODE_ROLE_MASTER && l_role.enums != NODE_ROLE_ROOT) {
            l_ledger_priv->cached = true;
            // load ledger cache from GDB
            dap_chain_ledger_load_cache(l_ledger);
        }
    }

    return l_ledger;
}

int dap_chain_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size)
{
    if (!a_token_emission || !a_token_emission_size)
        return -100;
    int l_ret = 0;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);

    const char * c_token_ticker = ((dap_chain_datum_token_emission_t *)a_token_emission)->hdr.ticker;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
    HASH_FIND_STR(l_ledger_priv->tokens, c_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);

    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;

    if (!l_token_item){
        log_it(L_WARNING,"Ledger_token_emission_add_check. Token ticker %s was not found",c_token_ticker);
        return DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN; // old return -5
    }

    // check if such emission is already present in table
    dap_chain_hash_fast_t l_token_emission_hash={0};
    //dap_chain_hash_fast_t * l_token_emission_hash_ptr = &l_token_emission_hash;
    dap_hash_fast(a_token_emission, a_token_emission_size, &l_token_emission_hash);
    char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_token_emission_hash);
    pthread_rwlock_rdlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_priv->threshold_emissions_rwlock);
    HASH_FIND(hh,l_token_item ? l_token_item->token_emissions : l_ledger_priv->threshold_emissions,
              &l_token_emission_hash, sizeof(l_token_emission_hash), l_token_emission_item);
    unsigned long long l_threshold_emissions_count = HASH_COUNT( l_ledger_priv->threshold_emissions);
    pthread_rwlock_unlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_priv->threshold_emissions_rwlock);
    if(l_token_emission_item ) {
        if(s_debug_more) {
            if ( l_token_emission_item->datum_token_emission->hdr.version == 2 ) {
                char *l_balance = dap_chain_balance_print(l_token_emission_item->datum_token_emission->hdr.value_256);
                log_it(L_ERROR, "Can't add token emission datum of %s %s ( %s ): already present in cache",
                        l_balance, c_token_ticker, l_hash_str);
                DAP_DELETE(l_balance);
            }
            else
                log_it(L_ERROR, "Can't add token emission datum of %"DAP_UINT64_FORMAT_U" %s ( %s ): already present in cache",
                    l_token_emission_item->datum_token_emission->hdr.value, c_token_ticker, l_hash_str);
        }
        l_ret = -1;
    }else if ( (! l_token_item) && ( l_threshold_emissions_count >= s_threshold_emissions_max)) {
        if(s_debug_more)
            log_it(L_WARNING,"threshold for emissions is overfulled (%zu max)",
               s_threshold_emissions_max);
        l_ret = -2;
    }
    DAP_DELETE(l_hash_str);
    if (l_ret || !PVT(a_ledger)->check_token_emission)
        return l_ret;
    // Check emission correctness
    size_t l_emission_size = a_token_emission_size;
    dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_token_emission, &l_emission_size);

    // if total_supply > 0 we can check current_supply
    if (!IS_ZERO_256(l_token_item->total_supply)){
        if(compare256(l_token_item->current_supply, l_emission->hdr.value_256) < 0) {
            char *l_balance_cur = dap_chain_balance_print(l_token_item->current_supply);
            char *l_balance_em = dap_chain_balance_print(l_emission->hdr.value_256);
            log_it(L_WARNING, "Ledger_token_emission_add_check. current_supply %s is lower, then l_emission->hdr.value_256: %s",
                    l_balance_cur, l_balance_em);
            DAP_DELETE(l_balance_cur);
            DAP_DELETE(l_balance_em);
            DAP_DELETE(l_emission);
            return -4;
        }
    }
        
    //additional check for private tokens
    if ((l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL)
	||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE)
	||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL)
	||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)) {
        //s_ledger_permissions_check(l_token_item)
        //    return -5;  /*TODO: ???*/
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
                for (uint16_t i = 0; i < l_emission->data.type_auth.signs_count && l_offset < l_emission_size; i++) {
                    if (dap_sign_verify_size(l_sign, l_emission_size - l_offset)) {
                        dap_chain_hash_fast_t l_sign_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                        // Find pkey in auth hashes
                        for (uint16_t k=0; k< l_token_item->auth_signs_total; k++) {
                            if (dap_hash_fast_compare(&l_sign_pkey_hash, &l_token_item->auth_pkeys_hash[k])) {
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
                    if(s_debug_more) {
                        char *l_balance = dap_chain_balance_print(l_emission->hdr.value_256);
                        log_it(L_WARNING, "Emission of %s datoshi of %s:%s is wrong: only %u valid aproves when %u need",
                                l_balance, a_ledger->net_name, l_emission->hdr.ticker, l_aproves, l_aproves_valid);
                        DAP_DELETE(l_balance);
                    }
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

bool s_chain_ledger_token_address_check(dap_chain_addr_t * l_addrs, dap_chain_datum_token_emission_t *a_token_emission, size_t l_addrs_count)
{
    // if l_addrs is empty - nothing to check
    if (!l_addrs)
        return true;

    for(size_t n=0; n<l_addrs_count;n++ ){
        if (memcmp(&l_addrs[n],&a_token_emission->hdr.address,sizeof(dap_chain_addr_t))==0)
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
    if (!s_chain_ledger_token_address_check(a_token_item->tx_recv_allow, a_token_emission, a_token_item->tx_recv_allow_size)){
        log_it(L_WARNING, "Address %s is not in tx_recv_allow for emission for token %s",
                dap_chain_addr_to_str(&a_token_emission->hdr.address), a_token_item->ticker);
        return false;
    }

    if (!s_chain_ledger_token_address_check(a_token_item->tx_recv_block, a_token_emission, a_token_item->tx_recv_block_size)){
        log_it(L_WARNING, "Address %s is not in tx_recv_block for emission for token %s",
                dap_chain_addr_to_str(&a_token_emission->hdr.address), a_token_item->ticker);
        return false;
    }

    if (!s_chain_ledger_token_address_check(a_token_item->tx_send_allow, a_token_emission, a_token_item->tx_send_allow_size)){
        log_it(L_WARNING, "Address %s is not in tx_send_allow for emission for token %s",
                dap_chain_addr_to_str(&a_token_emission->hdr.address), a_token_item->ticker);
        return false;
    }

    if (!s_chain_ledger_token_address_check(a_token_item->tx_send_block, a_token_emission, a_token_item->tx_send_block_size)){
        log_it(L_WARNING, "Address %s is not in tx_send_block for emission for token %s",
                dap_chain_addr_to_str(&a_token_emission->hdr.address), a_token_item->ticker);
        return false;
    }

    return true;
}


static void s_ledger_emission_cache_update(dap_ledger_t *a_ledger, dap_chain_ledger_token_emission_item_t *a_emission_item)
{
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
    size_t l_cache_size = a_emission_item->datum_token_emission_size + sizeof(dap_hash_fast_t);
    uint8_t *l_cache = DAP_NEW_S_SIZE(uint8_t, l_cache_size);
    memcpy(l_cache, &a_emission_item->tx_used_out, sizeof(dap_hash_fast_t));
    memcpy(l_cache + sizeof(dap_hash_fast_t), a_emission_item->datum_token_emission, a_emission_item->datum_token_emission_size);
    char *l_hash_str = dap_hash_fast_to_str_new(&a_emission_item->datum_token_emission_hash);
    if (!dap_chain_global_db_gr_set(l_hash_str, l_cache, l_cache_size, l_gdb_group)) {
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
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
    int l_ret = dap_chain_ledger_token_emission_add_check(a_ledger, a_token_emission, a_token_emission_size);
    if (l_ret) {
        if (l_ret == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN) {
            if (HASH_COUNT(l_ledger_priv->threshold_emissions) < s_threshold_emissions_max) {
                l_token_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
                l_token_emission_item->datum_token_emission = DAP_DUP_SIZE(a_token_emission, a_token_emission_size);
                l_token_emission_item->datum_token_emission_size = a_token_emission_size;
                dap_hash_fast_t l_emi_hash = {0};
                dap_hash_fast(a_token_emission, a_token_emission_size, &l_emi_hash);
                pthread_rwlock_wrlock(&l_ledger_priv->threshold_emissions_rwlock);
                l_token_emission_item->datum_token_emission_hash = l_emi_hash;
                l_token_emission_item->ts_added = dap_gdb_time_now();
                HASH_ADD(hh, l_ledger_priv->threshold_emissions, datum_token_emission_hash,
                         sizeof(*a_emission_hash), l_token_emission_item);
                pthread_rwlock_unlock(&l_ledger_priv->threshold_emissions_rwlock);

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
    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
    HASH_FIND_STR(l_ledger_priv->tokens, c_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
    if (!l_token_item && a_from_threshold)
        return DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN;

    // check if such emission is already present in table
    pthread_rwlock_rdlock( l_token_item ? &l_token_item->token_emissions_rwlock
                                        : &l_ledger_priv->threshold_emissions_rwlock);
    HASH_FIND(hh,l_token_item ? l_token_item->token_emissions : l_ledger_priv->threshold_emissions,
              a_emission_hash, sizeof(*a_emission_hash), l_token_emission_item);
    pthread_rwlock_unlock(l_token_item ? &l_token_item->token_emissions_rwlock
                                       : &l_ledger_priv->threshold_emissions_rwlock);
    char *l_hash_str = dap_chain_hash_fast_to_str_new(a_emission_hash);
    if (!l_token_emission_item) {
        l_token_emission_item = DAP_NEW_Z(dap_chain_ledger_token_emission_item_t);
        l_token_emission_item->datum_token_emission_size = a_token_emission_size;
        l_token_emission_item->datum_token_emission_hash = *a_emission_hash;
        if (l_token_item) {
            l_token_emission_item->datum_token_emission = dap_chain_datum_emission_read(a_token_emission,
                                                                                        &l_token_emission_item->datum_token_emission_size);

            //additional check for private tokens
            if ((l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL)
			||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE)
			||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL)
			||	(l_token_item->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)) {
                if (!s_chain_ledger_token_tsd_check(l_token_item, (dap_chain_datum_token_emission_t *)a_token_emission)) {
                    DAP_DELETE(l_token_emission_item->datum_token_emission);
                    DAP_DELETE(l_token_emission_item);
                    DAP_DELETE(l_hash_str);
                    return -114;
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
                    log_it(L_WARNING,"Token current supply %s lower, than emission value = %s",
                                        l_balance, l_value);
                    DAP_DELETE(l_balance);
                    DAP_DELETE(l_value);
                    DAP_DELETE(l_token_emission_item->datum_token_emission);
                    DAP_DELETE(l_token_emission_item);
                    DAP_DELETE(l_hash_str);
                    return -4;
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
        } else if (HASH_COUNT(l_ledger_priv->threshold_emissions) < s_threshold_emissions_max) {
            l_token_emission_item->datum_token_emission = DAP_DUP_SIZE(a_token_emission, a_token_emission_size);
            l_token_emission_item->datum_token_emission_size = a_token_emission_size;
            pthread_rwlock_wrlock(&l_ledger_priv->threshold_emissions_rwlock);
            l_token_emission_item->ts_added = dap_gdb_time_now();
            dap_chain_hash_fast_t l_emi_hash = {0};
            dap_hash_fast(a_token_emission, a_token_emission_size, &l_emi_hash);
            l_token_emission_item->datum_token_emission_hash = l_emi_hash;
            HASH_ADD(hh, l_ledger_priv->threshold_emissions, datum_token_emission_hash,
                     sizeof(*a_emission_hash), l_token_emission_item);
            pthread_rwlock_unlock(&l_ledger_priv->threshold_emissions_rwlock);
            l_ret = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN;
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
            l_ret = -2;
        }
    } else {
        if (l_token_item) {
            if(s_debug_more) {
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
        l_ret = -1;
    }
    DAP_DELETE(l_hash_str);
    return l_ret;
}

int dap_chain_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size)
{
    dap_chain_hash_fast_t l_token_emission_hash = {};
    dap_hash_fast(a_token_emission, a_token_emission_size, &l_token_emission_hash);
    if (PVT(a_ledger)->load_mode) {
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
        pthread_rwlock_rdlock(&PVT(a_ledger)->threshold_emissions_rwlock);
        HASH_FIND(hh, PVT(a_ledger)->threshold_emissions, &l_token_emission_hash, sizeof(l_token_emission_hash),
                l_token_emission_item);
        pthread_rwlock_unlock(&PVT(a_ledger)->threshold_emissions_rwlock);
        if (l_token_emission_item) {
            return DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN;
        }
    }
    return dap_chain_ledger_token_emission_add(a_ledger, a_token_emission, a_token_emission_size, &l_token_emission_hash, false);
}

dap_chain_ledger_token_emission_item_t *s_emission_item_find(dap_ledger_t *a_ledger,
                const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash)
{
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
    HASH_FIND_STR(l_ledger_priv->tokens, a_token_ticker, l_token_item);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);

    if (!l_token_item)
        return NULL;
    dap_chain_ledger_token_emission_item_t * l_token_emission_item = NULL;
    pthread_rwlock_rdlock(&l_token_item->token_emissions_rwlock);
    HASH_FIND(hh, l_token_item->token_emissions, a_token_emission_hash, sizeof(*a_token_emission_hash),
            l_token_emission_item);
    pthread_rwlock_unlock(&l_token_item->token_emissions_rwlock);
    return l_token_emission_item;
}

void s_ledger_stake_lock_cache_update(dap_ledger_t *a_ledger, dap_chain_ledger_stake_lock_item_t *a_stake_lock_item)
{
    char *l_hash_str = dap_chain_hash_fast_to_str_new(&a_stake_lock_item->tx_for_stake_lock_hash);
    char *l_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_STAKE_LOCK_STR);
    if (!dap_chain_global_db_gr_set(l_hash_str, &a_stake_lock_item->tx_used_out, sizeof(dap_hash_fast_t), l_group))
        log_it(L_WARNING, "Ledger cache mismatch");
    DAP_DEL_Z(l_hash_str);
    DAP_DEL_Z(l_group);
}

int dap_chain_ledger_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash)
{
	dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_stake_lock_item_t *l_new_stake_lock_emission;
    pthread_rwlock_rdlock(&l_ledger_priv->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_priv->emissions_for_stake_lock, a_tx_hash, sizeof(dap_hash_fast_t),
			  l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_priv->stake_lock_rwlock);
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
    pthread_rwlock_wrlock(&l_ledger_priv->stake_lock_rwlock);
    HASH_ADD(hh, l_ledger_priv->emissions_for_stake_lock, tx_for_stake_lock_hash, sizeof(dap_chain_hash_fast_t), l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_priv->stake_lock_rwlock);

    if (!l_new_stake_lock_emission)
        debug_if(s_debug_more, L_ERROR, "Error: adding to hash-table. Be careful, there may be leaks");
    else if (PVT(a_ledger)->cached)
        s_ledger_stake_lock_cache_update(a_ledger, l_new_stake_lock_emission);

    return 0;
}

dap_chain_ledger_stake_lock_item_t *s_emissions_for_stake_lock_item_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash)
{
	dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_stake_lock_item_t *l_new_stake_lock_emission;
    pthread_rwlock_rdlock(&l_ledger_priv->stake_lock_rwlock);
    HASH_FIND(hh, l_ledger_priv->emissions_for_stake_lock, a_token_emission_hash, sizeof(dap_chain_hash_fast_t),
			  l_new_stake_lock_emission);
    pthread_rwlock_unlock(&l_ledger_priv->stake_lock_rwlock);
	return l_new_stake_lock_emission;
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
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);

    if ( dap_hash_fast_is_blank(a_tx_hash) )
        return NULL;

    dap_chain_ledger_tx_item_t *l_item;
    unsigned l_hash_value;
    HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item);
    if (l_item) {
        pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
        return l_item->cache_data.token_ticker;
    }
    dap_chain_ledger_tx_spent_item_t *l_spent_item;
    HASH_FIND_BYHASHVALUE(hh, l_ledger_priv->spent_items, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_spent_item);
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    return l_spent_item ? l_spent_item->cache_data.token_ticker : NULL;

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
        char *** a_tickers, size_t * a_tickers_size)
{
    if (a_addr == NULL){ // Get all tockens
        pthread_rwlock_rdlock(&PVT(a_ledger)->tokens_rwlock);
        size_t l_count = HASH_COUNT(PVT(a_ledger)->tokens);
        if (l_count && a_tickers){
            dap_chain_ledger_token_item_t * l_token_item, *l_tmp;
            char **l_tickers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            size_t i = 0;
            HASH_ITER(hh, PVT(a_ledger)->tokens, l_token_item, l_tmp) {
                l_tickers[i] = dap_strdup(l_token_item->ticker);
                i++;
            }
            *a_tickers = l_tickers;
        }
        pthread_rwlock_unlock(&PVT(a_ledger)->tokens_rwlock);
        if(a_tickers_size)
            *a_tickers_size = l_count;
    }else{ // Calc only tokens from address balance
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
            if(a_tickers)
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

    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_datum_tx_t *l_tx_ret = NULL;
    dap_chain_ledger_tx_item_t *l_tx_item;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
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

bool dap_chain_ledger_tx_spent_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash)
{
    dap_chain_ledger_tx_spent_item_t *l_tx_item;
    pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
    HASH_FIND(hh, PVT(a_ledger)->spent_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_item);
    pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
    return l_tx_item;
}

dap_hash_fast_t *dap_chain_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash)
{
    if(!a_ledger || !a_tx_hash || dap_hash_fast_is_blank(a_tx_hash))
        return NULL;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_item;
    unsigned l_hash_value;
    dap_chain_hash_fast_t *l_tx_hash = a_tx_hash;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    while (l_tx_hash) {
        HASH_VALUE(l_tx_hash, sizeof(*l_tx_hash), l_hash_value);
        HASH_FIND_BYHASHVALUE(hh, l_ledger_priv->ledger_items, l_tx_hash, sizeof(*l_tx_hash), l_hash_value, l_item);
        if (l_item) {
            int l_out_num = -1;
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
        HASH_FIND_BYHASHVALUE(hh, l_ledger_priv->spent_items, l_tx_hash, sizeof(*l_tx_hash), l_hash_value, l_spent_item);
        if (l_spent_item) {
            l_tx_hash = &l_spent_item->cache_data.tx_hash_spent_fast;
            if (dap_hash_fast_is_blank(l_tx_hash))
                break;          // We have no condional outpul with spent item
        } else {
            l_tx_hash = NULL;   // We can't find pointed hash in the ledger
            break;
        }
    }
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    if (l_tx_hash && !dap_hash_fast_is_blank(l_tx_hash))
        return l_tx_hash;
    return NULL;
}

/**
 * Check whether used 'out' items (local function)
 */
static bool dap_chain_ledger_item_is_used_out(dap_chain_ledger_tx_item_t *a_item, int a_idx_out, dap_chain_hash_fast_t *a_out_spender_hash)
{
    bool l_used_out = false;
    if (!a_item || !a_item->cache_data.n_outs) {
        return true;
    }
    if(a_idx_out >= MAX_OUT_ITEMS) {
        log_it(L_ERROR, "Index '%d' exeeds capacity of 'out' items %d", a_idx_out, MAX_OUT_ITEMS);
        return true;
    }

    if ((a_item->cache_data.n_outs_used > 0) && !dap_hash_fast_is_blank(&(a_item->cache_data.tx_hash_spent_fast[a_idx_out]))) {
        l_used_out = true;
        if (a_out_spender_hash)
            *a_out_spender_hash = a_item->cache_data.tx_hash_spent_fast[a_idx_out];
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

// Checking a new transaction before adding to the cache
int dap_chain_ledger_tx_cache_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash,
                                    bool a_from_threshold, dap_list_t **a_list_bound_items, dap_list_t **a_list_tx_out,  char **a_main_ticker)
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
            return -1;
        }
    }
    /*
    Steps of checking for current transaction tx2 and every previous transaction tx1:
    1. valid(tx2.dap_chain_datum_tx_sig.pkey)
    &&
    2. !is_used_out(tx1.dap_chain_datum_tx_out)
    &&
    3. tx1.output != tx2.bound_items.outputs.used
    &&
    4. tx1.dap_chain_datum_tx_out.addr.data.key == tx2.dap_chain_datum_tx_sig.pkey for unconditional output
    \\
    5a. tx1.dap_chain_datum_tx_sig.pkey == tx2.dap_chain_datum_tx_sig.pkey for conditional owner
    \\
    5b. tx1.dap_chain_datum_tx_out.condition == verify_svc_type(tx2) for conditional output
    &&
    6. sum(  find (tx2.input.tx_prev_hash).output[tx2.input_tx_prev_idx].value )  ==  sum (tx2.outputs.value) per token
    &&
    7. valid(fee)
    */

    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    if(!a_tx){
        log_it(L_DEBUG, "NULL transaction, check broken");
        return -1;
    }

    dap_list_t *l_list_bound_items = NULL;

	dap_list_t *l_list_tx_out = NULL;
	if (a_list_tx_out)
		*a_list_tx_out = l_list_tx_out;

    // sum of values in 'out' items from the previous transactions
    dap_chain_ledger_tokenizer_t *l_values_from_prev_tx = NULL, *l_values_from_cur_tx = NULL,
                                 *l_value_cur = NULL, *l_tmp = NULL, *l_res = NULL;
    char *l_token = NULL, *l_main_ticker = NULL;
    dap_chain_ledger_token_item_t * l_token_item = NULL;
    dap_chain_hash_fast_t *l_emission_hash = NULL;

    // check all previous transactions
    int l_err_num = 0;
    int l_prev_tx_count = 0;

    // 1. Verify signature in current transaction
    if (!a_from_threshold && dap_chain_datum_tx_verify_sign(a_tx) != 1)
        return -2;

    // ----------------------------------------------------------------
    // find all 'in' & conditional 'in' items in current transaction
    dap_list_t *l_list_in = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN_ALL,
                                                          &l_prev_tx_count);
    if (!l_list_in) {
        log_it(L_WARNING, "Tx check: no valid inputs found");
        return -22;
    }
    dap_chain_ledger_tx_bound_t *bound_item;
    dap_chain_hash_fast_t l_hash_pkey = {};
     // find all previous transactions
    dap_list_t *l_list_tmp = l_list_in;
    for (int l_list_tmp_num = 0; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_list_tmp_num++) {
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
        bound_item->tx_prev_hash = l_tx_prev_hash;

        bool l_is_blank = dap_hash_fast_is_blank(&l_tx_prev_hash);
        char l_tx_prev_hash_str[70]={[0]='\0'};
        if (l_is_blank){
            debug_if(s_debug_more && !a_from_threshold, L_DEBUG, "Tx check: blank prev hash");
            dap_snprintf(l_tx_prev_hash_str,sizeof( l_tx_prev_hash_str),"BLANK");
        }else{
            dap_chain_hash_fast_to_str(&l_tx_prev_hash,l_tx_prev_hash_str,sizeof(l_tx_prev_hash_str));
        }

        if (l_is_blank) {   // It's the first TX
            // if at least one blank hash is present, then all the hashes should be blank
            if (l_list_tmp_num > 1) {
                l_err_num = -3;
                log_it(L_WARNING, "Only one IN item allowed for base TX");
                break;
            }
            dap_chain_tx_token_t *l_tx_token = (dap_chain_tx_token_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL);
            if (!l_tx_token) {
                log_it(L_WARNING, "tx token item is mandatory fot base TX");
                l_err_num = -4;
                break;
            }
            l_token = l_tx_token->header.ticker;
            l_emission_hash = &l_tx_token->header.token_emission_hash;
            dap_chain_ledger_token_emission_item_t *l_emission_item = s_emission_item_find(a_ledger, l_token, l_emission_hash);
            dap_chain_ledger_stake_lock_item_t *stake_lock_emission = s_emissions_for_stake_lock_item_find(a_ledger, l_emission_hash);
			if (!l_emission_item && stake_lock_emission) {//check emission for STAKE_LOCK
				dap_hash_fast_t cur_tx_hash;
				dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &cur_tx_hash);
				if (!dap_hash_fast_is_blank(&stake_lock_emission->tx_used_out)) {
					if (!dap_hash_fast_compare(&cur_tx_hash, &stake_lock_emission->tx_used_out)) {
						debug_if(s_debug_more, L_WARNING, "stake_lock_emission already present in cache for tx_token [%s]", l_token);
					}
					else {
						debug_if(s_debug_more, L_WARNING, "stake_lock_emission is used out for tx_token [%s]", l_token);
					}
					l_err_num = -22;
					break;
				}
				dap_tsd_t *l_tsd;
				dap_chain_datum_token_t *l_datum_token = dap_chain_ledger_token_ticker_check(a_ledger, l_token);
				if (l_datum_token
				&&	(l_datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL || l_datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE)
				&&	l_datum_token->header_native_decl.tsd_total_size
				&&	NULL != (l_tsd = dap_tsd_find(l_datum_token->data_n_tsd, l_datum_token->header_native_decl.tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK))) {
					dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section = dap_tsd_get_scalar(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
					if (!dap_chain_ledger_token_ticker_check(a_ledger, l_tsd_section.ticker_token_from)) {
						debug_if(s_debug_more, L_WARNING, "tx_token [%s] no found", l_tsd_section.ticker_token_from);
						l_err_num = -23;
						break;
					}
//				int item_count = 0;
                    dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*)dap_chain_datum_tx_item_get(a_tx, 0, TX_ITEM_TYPE_OUT, 0);//TODO: ADD CHECK COUNT TX
					if (!l_tx_out) {
						debug_if(s_debug_more, L_WARNING, "Can't find OUT item for base TX with tx_token [%s]", l_tx_token->header.ticker);
						l_err_num = -24;
						break;
					}
					dap_chain_datum_tx_t *l_tx_stake_lock = dap_chain_ledger_tx_find_by_hash(a_ledger, l_emission_hash);
					if (!l_tx_stake_lock) {
						debug_if(s_debug_more, L_WARNING, "Not found stake_lock transaction");
						l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
						break;
					}
					dap_chain_tx_out_cond_t *l_tx_stake_lock_out_cond = (dap_chain_tx_out_cond_t*)dap_chain_datum_tx_item_get(l_tx_stake_lock, 0, TX_ITEM_TYPE_OUT_COND, 0);//TODO: ADD CHECK COUNT TX
					if (!l_tx_stake_lock_out_cond) {
						debug_if(s_debug_more, L_WARNING, "No OUT_COND to for tx_token [%s]", l_tx_token->header.ticker);
						l_err_num = -32;
						break;
					}
					if (l_tx_stake_lock_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
						debug_if(s_debug_more, L_WARNING, "OUT_COND is not stake_lock subtype to for tx_token [%s]", l_tx_token->header.ticker);
						l_err_num = -25;
						break;
					}
					uint256_t l_value_expected ={};
					if (MULT_256_COIN(l_tx_stake_lock_out_cond->header.value, l_tsd_section.emission_rate, &l_value_expected)!=0){
						if(s_debug_more){
							char * l_emission_rate_str = dap_chain_balance_print(l_tsd_section.emission_rate);
							char * l_locked_value_str = dap_chain_balance_print(l_tx_stake_lock_out_cond->header.value);
							log_it( L_WARNING, "Multiplication overflow for %s emission: locked value %s emission rate %s"
							, l_tx_token->header.ticker, l_locked_value_str, l_emission_rate_str);
							DAP_DEL_Z(l_emission_rate_str);
							DAP_DEL_Z(l_locked_value_str);
						}
						l_err_num = -26;
						break;
					}
                    l_token_item = NULL;
                    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
                    HASH_FIND_STR(l_ledger_priv->tokens, l_token, l_token_item);
                    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
                    if (!l_token_item){
                        if(s_debug_more)
                            log_it(L_WARNING, "No token item found for token %s", l_token);
                        l_err_num = -15;
                        break;
                    }
                    if (!IS_ZERO_256(l_token_item->total_supply) &&
                            compare256(l_token_item->current_supply, l_tx_out->header.value) < 0) {
                        char *l_balance = dap_chain_balance_print(l_token_item->current_supply);
                        char *l_value = dap_chain_balance_print(l_tx_out->header.value);
                        log_it(L_WARNING, "Token current supply %s lower, than emission value = %s",
                               l_balance, l_value);
                        DAP_DEL_Z(l_balance);
                        DAP_DEL_Z(l_value);
                        l_err_num = -30;
                        break;
                    }
					if (!EQUAL_256(l_value_expected, l_tx_out->header.value)) {
						char * l_value_expected_str = dap_chain_balance_print(l_value_expected);
						char * l_locked_value_str = dap_chain_balance_print(l_tx_out->header.value);

						debug_if(s_debug_more, L_WARNING, "Value %s not thats expected %s for [%s]",l_locked_value_str, l_value_expected_str,
								 l_tx_token->header.ticker);

						DAP_DEL_Z(l_value_expected_str);
						DAP_DEL_Z(l_locked_value_str);
						l_err_num = -34;
						break;
					}
					// check tiker
					const char *tx_tiker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, l_emission_hash);
					if (!tx_tiker) {
                        debug_if(s_debug_more, L_WARNING, "No ticker stake_lock to for tx_token [%s]", l_tx_token->header.ticker);
						l_err_num = -33;
						break;
					}
					if (strcmp(tx_tiker, l_tsd_section.ticker_token_from)) {
                        debug_if(s_debug_more, L_WARNING, "Tickers not equal for [%s]", l_tx_token->header.ticker);
						l_err_num = -35;
						break;
                    }
					debug_if(s_debug_more, L_NOTICE, "Check emission passed for tx_token [%s]", l_tx_token->header.ticker);
                    bound_item->tx_prev = l_tx_stake_lock;
                    bound_item->stake_lock_item = stake_lock_emission;
                    l_list_bound_items = dap_list_append(l_list_bound_items, bound_item);
                    break;

				} else {
					debug_if(s_debug_more, L_WARNING, "tx_token [%s] not valid for stake_lock transaction", l_token);
					l_err_num = -31;
					break;
				}
			}

			if (!l_emission_item) {
                debug_if(s_debug_more && !a_from_threshold, L_WARNING, "Emission for tx_token [%s] wasn't found", l_tx_token->header.ticker);
				l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION;
				break;
			}
            if (!dap_hash_fast_is_blank(&l_emission_item->tx_used_out)) {
                debug_if(s_debug_more, L_WARNING, "Emission for tx_token [%s] is already used", l_tx_token->header.ticker);
                l_err_num = -22;
                break;
            }
            dap_chain_datum_token_emission_t * l_token_emission = l_emission_item->datum_token_emission;
            int l_outs_count;
            dap_list_t *l_list_out = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT, &l_outs_count);
            dap_chain_tx_out_t *l_out = l_list_out ? (dap_chain_tx_out_t *)l_list_out->data : NULL;
            dap_list_free(l_list_out);
            if (l_outs_count != 1) {
                l_err_num = -23;
                log_it(L_WARNING, "Only one OUT item allowed for base TX");
                break;
            }
            if (!EQUAL_256(l_token_emission->hdr.value_256, l_out->header.value)) {
                l_err_num = -10;
                log_it(L_WARNING, "Output value of base TX must be equal emission value");
                break;
            }
            if (memcmp(&l_token_emission->hdr.address, &l_out->addr, sizeof(dap_chain_addr_t))) {
                l_err_num = -24;
                log_it(L_WARNING, "Output addr of base TX must be equal emission addr");
                break;
            }
            // Match the signature of the emission with the transaction
            /*if(!s_tx_match_sign(l_token_emission, a_tx)) {
                log_it(L_WARNING, "Base TX is not signed by the same certificate as the emission");
                l_err_num = -25;
                break;
            }*/ // Base TX can be unsigned so temporary disabled
            bound_item->item_emission = l_emission_item;
            l_list_bound_items = dap_list_append(l_list_bound_items, bound_item);
            break;
        }
        // Get previous transaction in the cache by hash
        dap_chain_ledger_tx_item_t *l_item_out = NULL;
        dap_chain_datum_tx_t *l_tx_prev =
                s_find_datum_tx_by_hash(a_ledger, &l_tx_prev_hash, &l_item_out); // dap_chain_datum_tx_t *l_tx_prev = (dap_chain_datum_tx_t*) dap_chain_node_datum_tx_cache_find(&tx_prev_hash);
        if(!l_tx_prev) { // Unchained transaction
            if (s_debug_more && !a_from_threshold)
                log_it(L_DEBUG, "No previous transaction was found for hash %s", l_tx_prev_hash_str);
            l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
            break;
        }
        bound_item->item_out = l_item_out;
        l_token = l_item_out->cache_data.token_ticker;
        if (s_debug_more && !a_from_threshold)
            log_it(L_INFO,"Previous transaction was found for hash %s",l_tx_prev_hash_str);
        bound_item->tx_prev = l_tx_prev;

        // 2. Check if out in previous transaction has spent
        int l_idx = (l_cond_type == TX_ITEM_TYPE_IN) ? l_tx_in->header.tx_out_prev_idx : l_tx_in_cond->header.tx_out_prev_idx;
        dap_hash_fast_t l_spender;
        if (dap_chain_ledger_item_is_used_out(l_item_out, l_idx, &l_spender)) {
            char l_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_spender, l_hash, sizeof(l_hash));
            log_it(L_INFO, "'Out' item of previous tx %s already spent by %s", l_tx_prev_hash_str, l_hash);
            l_err_num = -6;
            break;
        }

        uint256_t l_value;
        // Get list of all 'out' items from previous transaction
        dap_list_t *l_list_prev_out = dap_chain_datum_tx_items_get(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, NULL);
        // Get one 'out' item in previous transaction bound with current 'in' item
        void *l_tx_prev_out = dap_list_nth_data(l_list_prev_out, l_idx);
        dap_list_free(l_list_prev_out);
        if(!l_tx_prev_out) {
            debug_if(s_debug_more, L_ERROR, "No 'out' items in previous tx found at index %d, bound with current 'in'", l_idx);
            l_err_num = -8;
            break;
        }
        // 3. Compare out in previous transaction with currently used out
        for (dap_list_t *it = l_list_bound_items; it; it = it->next) {
            dap_chain_ledger_tx_bound_t *l_bound_tmp = it->data;
            if (l_tx_prev_out == l_bound_tmp->out.tx_prev_out) {
                debug_if(s_debug_more, L_ERROR, "Previous transaction output already used in current tx");
                l_err_num = -7;
                break;
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
                debug_if(s_debug_more, L_ERROR, "Unknown previous 'out' item type %d", l_type);
                l_err_num = -8;
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
                l_err_num = -9;
                break;
            }
        } else { // TX_ITEM_TYPE_IN_COND
            if(*(uint8_t *)l_tx_prev_out != TX_ITEM_TYPE_OUT_COND) {
                debug_if(s_debug_more, L_ERROR, "Tx previous item item has wrong type %d", *(uint8_t*)l_tx_prev_out);
                l_err_num = -8;
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

            dap_chain_tx_out_cond_t *l_tx_prev_out_cond = NULL;
            l_tx_prev_out_cond = (dap_chain_tx_out_cond_t *)l_tx_prev_out;
            if (l_tx_prev_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                l_main_ticker = l_token;
            bool l_owner = false;
            if (l_pkey_ser_size == l_prev_pkey_ser_size &&
                    !memcmp(l_prev_pkey_ser, l_pkey_ser, l_prev_pkey_ser_size)) {
                l_owner = true;
            }
            // 5b. Call verificator for conditional output
            dap_chain_ledger_verificator_t *l_verificator;
            int l_sub_tmp = l_tx_prev_out_cond->header.subtype;

            pthread_rwlock_rdlock(&s_verificators_rwlock);
            HASH_FIND_INT(s_verificators, &l_sub_tmp, l_verificator);
            pthread_rwlock_unlock(&s_verificators_rwlock);
            if (!l_verificator || !l_verificator->callback) {
                if(s_debug_more)
                    log_it(L_ERROR, "No verificator set for conditional output subtype %d", l_sub_tmp);
                l_err_num = -13;
                break;
            }
            if (l_verificator->callback(a_ledger, &l_tx_prev_hash, l_tx_prev_out_cond, a_tx, l_owner) == false) {
				if (l_sub_tmp == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
					l_err_num = DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
				} else {
					l_err_num = -14;
				}
                break;
            }
            // calculate sum of values from previous transactions
            bound_item->out.tx_prev_out_cond_256 = l_tx_prev_out_cond;
            l_value = l_tx_prev_out_cond->header.value;
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
        // calculate  from previous transactions per each token
        SUM_256_256(l_value_cur->sum, l_value, &l_value_cur->sum);

        l_list_bound_items = dap_list_append(l_list_bound_items, bound_item);
    }

    if (l_list_in)
        dap_list_free(l_list_in);

    if (l_err_num) {
        DAP_DELETE(bound_item);
        if ( l_list_bound_items )
            dap_list_free_full(l_list_bound_items, free);
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
            HASH_FIND_STR(l_values_from_cur_tx, PVT(a_ledger)->net->pub.native_ticker, l_value_cur);
            if (l_value_cur) {
                l_value_cur = l_value_cur->hh.next ? l_value_cur->hh.next : l_value_cur->hh.prev;
                l_main_ticker = l_value_cur->token_ticker;
            }
        }
    } else {
        l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
        if(l_token)
            dap_stpcpy(l_value_cur->token_ticker, l_token);
        if (!l_main_ticker)
            l_main_ticker = l_value_cur->token_ticker;
        HASH_ADD_STR(l_values_from_cur_tx, token_ticker, l_value_cur);
    }

    // find 'out' items
    dap_list_t *l_list_out = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
    uint256_t l_value = {}, l_fee_value = {}, l_fee_sum = {};
    dap_chain_addr_t l_fee_addr = {};
    bool l_fee_check = dap_chain_net_tx_get_fee(PVT(a_ledger)->net->pub.id, &l_fee_value, &l_fee_addr);

    int l_item_idx = 0;
    for (l_list_tmp = l_list_out; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_item_idx++) {
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
        dap_chain_addr_t l_tx_out_to={0};
        switch (l_type) {
        case TX_ITEM_TYPE_OUT_OLD: {
            dap_chain_tx_out_old_t *l_tx_out = (dap_chain_tx_out_old_t *)l_list_tmp->data;
            if (l_multichannel) { // token ticker is mandatory for multichannel transactions
                debug_if(s_debug_more, L_ERROR, "No token ticker for type TX_ITEM_TYPE_OUT_OLD");
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
                    debug_if(s_debug_more, L_ERROR, "No main ticker found");
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
            if (!l_multichannel) {
                debug_if(s_debug_more, L_ERROR, "Token ticker is deprecated for single-channel transactions");
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
                if (l_main_ticker)
                    l_token = l_main_ticker;
                else if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                    l_token = (char *)PVT(a_ledger)->net->pub.native_ticker;
                else {
                    log_it(L_WARNING, "No conditional output support for multichannel transaction");
                    l_err_num = -18;
                    break;
                }
            }
            l_value = l_tx_out->header.value;
            l_list_tx_out = dap_list_append(l_list_tx_out, l_tx_out);
        } break;
        default: { }
        }

        if (l_err_num) {
            break;
        }

        if (l_multichannel) {
            HASH_FIND_STR(l_values_from_cur_tx, l_token, l_value_cur);
            if (!l_value_cur) {
                l_value_cur = DAP_NEW_Z(dap_chain_ledger_tokenizer_t);
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

        if (l_fee_check && !memcmp(&l_tx_out_to, &l_fee_addr, sizeof(dap_chain_addr_t)) &&
                !dap_strcmp(l_value_cur->token_ticker, PVT(a_ledger)->net->pub.native_ticker)) {
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
                if(s_debug_more) {
                    char *l_balance = dap_chain_balance_to_coins(l_res ? l_res->sum : uint256_0);
                    char *l_balance_cur = dap_chain_balance_to_coins(l_value_cur->sum);
                    log_it(L_ERROR, "Sum of values of out items from current tx (%s) is not equal outs from previous tx (%s) for token %s",
                            l_balance, l_balance_cur, l_value_cur->token_ticker);
                    DAP_DELETE(l_balance);
                    DAP_DELETE(l_balance_cur);
                }
                l_err_num = -12;
                break;
            }
        }
    }

    // 7. Check the network fee
    if (l_fee_check && compare256(l_fee_sum, l_fee_value) == -1) {
        char *l_current_fee = dap_chain_balance_to_coins(l_fee_sum);
        char *l_expected_fee = dap_chain_balance_to_coins(l_fee_value);
        log_it(L_ERROR, "Fee value is invalid, expected %s pointed %s", l_expected_fee, l_current_fee);
        l_err_num = -55;
        DAP_DEL_Z(l_current_fee);
        DAP_DEL_Z(l_expected_fee);
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

    dap_hash_fast_t l_tx_hash;
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);
    int l_ret_check;
    if( (l_ret_check = dap_chain_ledger_tx_cache_check(a_ledger, a_tx, &l_tx_hash, false, NULL, NULL, NULL)) < 0) {
        debug_if(s_debug_more, L_DEBUG, "dap_chain_ledger_tx_add_check() tx not passed the check: code %d ", l_ret_check);
        return l_ret_check;
    }
    if(s_debug_more) {
        char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
        log_it ( L_INFO, "dap_chain_ledger_tx_add_check() check passed for tx %s", l_tx_hash_str);
    }
    return 0;
}

static int s_balance_cache_update(dap_ledger_t *a_ledger, dap_ledger_wallet_balance_t *a_balance)
{
    if (PVT(a_ledger)->cached) {
        char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
        if (!dap_chain_global_db_gr_set(a_balance->key, &a_balance->balance, sizeof(uint256_t), l_gdb_group)) {
            if(s_debug_more)
                log_it(L_WARNING, "Ledger cache mismatch");
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

void dap_chain_ledger_start_tps_count(dap_ledger_t *a_ledger)
{
    clock_gettime(CLOCK_REALTIME, &PVT(a_ledger)->tps_start_time);
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
        l_ledger_priv->tps_current_time.tv_sec = l_ledger_priv->tps_start_time.tv_sec;
        l_ledger_priv->tps_current_time.tv_nsec = l_ledger_priv->tps_start_time.tv_nsec;
        l_ledger_priv->tps_count = 0;
        l_ledger_priv->tps_timer = dap_timerfd_start(500, s_ledger_tps_callback, l_ledger_priv);
    }
    bool l_from_threshold = a_from_threshold;
    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
    int l_ret_check;
    char *l_main_token_ticker = NULL;
    if( (l_ret_check = dap_chain_ledger_tx_cache_check(a_ledger, a_tx, a_tx_hash, a_from_threshold,
                                                       &l_list_bound_items, &l_list_tx_out, &l_main_token_ticker)) < 0) {
        if (l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS ||
                l_ret_check == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION) {
            if (!l_from_threshold) {
                unsigned l_hash_value = 0;
                HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
                pthread_rwlock_rdlock(&l_ledger_priv->threshold_txs_rwlock);
                HASH_FIND_BYHASHVALUE(hh, l_ledger_priv->threshold_txs, a_tx_hash, sizeof(*a_tx_hash), l_hash_value, l_item_tmp);
                unsigned long long l_threshold_txs_count = HASH_COUNT(l_ledger_priv->threshold_txs);
                if (!l_item_tmp) {
                    if (l_threshold_txs_count >= s_threshold_txs_max) {
                        if(s_debug_more)
                            log_it(L_WARNING, "Threshold for tranactions is overfulled (%zu max), dropping down new data, added nothing",
                                       s_threshold_txs_max);
                    } else {
                        l_item_tmp = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
                        l_item_tmp->tx_hash_fast = *a_tx_hash;
                        l_item_tmp->tx = DAP_DUP_SIZE(a_tx, dap_chain_datum_tx_get_size(a_tx));
                        l_item_tmp->ts_added = dap_gdb_time_now();
                        HASH_ADD_BYHASHVALUE(hh, l_ledger_priv->threshold_txs, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_tmp);
                        if(s_debug_more)
                            log_it (L_DEBUG, "Tx %s added to threshold", l_tx_hash_str);
                    }
                }
                pthread_rwlock_unlock(&l_ledger_priv->threshold_txs_rwlock);
            }
        } else {
            if(s_debug_more)
                log_it (L_WARNING, "dap_chain_ledger_tx_add() tx %s not passed the check: code %d ",l_tx_hash_str, l_ret_check);
        }
        return l_ret_check;
    }
    if(s_debug_more)
        log_it ( L_DEBUG, "dap_chain_ledger_tx_add() check passed for tx %s",l_tx_hash_str);

    // Mark 'out' items in cache if they were used & delete previous transactions from cache if it need
    // find all bound pairs 'in' and 'out'
    dap_list_t *l_list_tmp = l_list_bound_items;
    size_t l_outs_used = dap_list_length(l_list_bound_items);
    size_t l_cache_size = sizeof(dap_store_obj_t) * (l_outs_used + 1);
    dap_store_obj_t *l_cache_used_outs = DAP_NEW_Z_SIZE(dap_store_obj_t, l_cache_size);
    char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
    char *l_cur_token_ticker = NULL;
    // Update balance: deducts

    for (int i = 1; l_list_tmp; i++) {
        dap_chain_ledger_tx_bound_t *bound_item = l_list_tmp->data;
        void *l_item_in = *(void **)&bound_item->in;
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_item_in;
        if (l_type == TX_ITEM_TYPE_IN) {
            dap_chain_tx_in_t *l_tx_in = bound_item->in.tx_cur_in;
            if (dap_hash_fast_is_blank(&l_tx_in->header.tx_prev_hash)) { // It's the emission behind
                // Find token ticker for emission
                dap_chain_tx_token_t * l_tx_token = (dap_chain_tx_token_t *) dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL);
                if (!l_tx_token) {
                    log_it(L_ERROR, "No token item with blank prev tx hash");
                    break;
                }
                if (bound_item->tx_prev) { // It's the stake lock emission
                    dap_chain_ledger_token_item_t *l_token_item = NULL;
                    pthread_rwlock_rdlock(&l_ledger_priv->tokens_rwlock);
                    HASH_FIND_STR(l_ledger_priv->tokens, l_main_token_ticker, l_token_item);
                    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
                    if (!l_token_item){
                        log_it(L_ERROR, "No token item found for token %s", l_main_token_ticker);
                        break;
                    }
                    if (!IS_ZERO_256(l_token_item->total_supply)) {
                        dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*)dap_chain_datum_tx_item_get(a_tx, 0, TX_ITEM_TYPE_OUT, 0);
                        SUBTRACT_256_256(l_token_item->current_supply, l_tx_out->header.value, &l_token_item->current_supply);
                        char *l_balance = dap_chain_balance_print(l_token_item->current_supply);
                        log_it(L_DEBUG, "New current supply %s for token %s", l_balance, l_token_item->ticker);
                        DAP_DEL_Z(l_balance);
                        if (PVT(a_ledger)->cached)
                            s_ledger_token_cache_update(a_ledger, l_token_item);
                    }
                    bound_item->stake_lock_item->tx_used_out = *a_tx_hash;
                    if (PVT(a_ledger)->cached)
                        // Mirror it in cache
                        s_ledger_stake_lock_cache_update(a_ledger, bound_item->stake_lock_item);
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
        }
        dap_chain_ledger_tx_item_t *l_prev_item_out = bound_item->item_out;
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
        } else { /* TX_ITEM_TYPE_IN_COND */
            // all balance deducts performed with previous conditional transaction
            dap_chain_tx_in_cond_t *l_tx_in_cond = bound_item->in.tx_cur_in_cond;
            /// Mark 'out' item in cache because it used
            l_tx_prev_out_used_idx = l_tx_in_cond->header.tx_out_prev_idx;
            dap_chain_tx_out_cond_t *l_cond = bound_item->out.tx_prev_out_cond_256;
            switch (l_cond->header.subtype) {
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE:
                l_cur_token_ticker = (char*)PVT(a_ledger)->net->pub.native_ticker;
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                if (l_cond->subtype.srv_stake_lock.flags & DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX) {
                    int l_tx_burning_prev_out_used_idx = 0;
                    /* For a lock with base tx, we should also mark burning tx out as used */
                    dap_chain_datum_tx_receipt_t *l_receipt = (dap_chain_datum_tx_receipt_t*)dap_chain_datum_tx_item_get(a_tx, 0, TX_ITEM_TYPE_RECEIPT, 0);
                    if (!l_receipt) {
                        log_it(L_ERROR, "Tx hash %s : no receipt found", l_tx_hash_str);
                        break;
                    }
                    dap_hash_fast_t *l_burning_hash = (dap_hash_fast_t*)l_receipt->exts_n_signs;
                    dap_chain_ledger_tx_item_t *l_burning_item_out = NULL;
                    dap_chain_datum_tx_t *l_tx_burning = s_find_datum_tx_by_hash(a_ledger, l_burning_hash, &l_burning_item_out);
                    dap_list_t *l_temp_list_out_items = dap_chain_datum_tx_items_get(l_tx_burning, TX_ITEM_TYPE_OUT_ALL, NULL);
                    for(dap_list_t *l_list_tmp = l_temp_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), ++l_tx_burning_prev_out_used_idx) {
                        dap_chain_tx_item_type_t l_type = *(uint8_t*)l_list_tmp->data;
                        if (l_type == TX_ITEM_TYPE_OUT) {
                            dap_chain_addr_t l_addr = ((dap_chain_tx_out_t*)l_list_tmp->data)->addr;
                            if (dap_chain_addr_is_blank(&l_addr)) {
                                l_burning_item_out->cache_data.tx_hash_spent_fast[l_tx_burning_prev_out_used_idx] = *a_tx_hash;
                                l_burning_item_out->cache_data.n_outs_used++;
                                debug_if(s_debug_more, L_INFO, "Mark burning tx 'out' item %d : %s", l_tx_burning_prev_out_used_idx, l_tx_hash_str);
                                break;
                            }
                        }
                    }
                    dap_list_free(l_temp_list_out_items);
                }
                break;
            }
            default:
                break;
            }

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



        // mirror it in the cache
        size_t l_tx_size = dap_chain_datum_tx_get_size(l_prev_item_out->tx);
        size_t l_tx_cache_sz = l_tx_size + sizeof(l_prev_item_out->cache_data);
        uint8_t *l_tx_cache = DAP_NEW_Z_SIZE(uint8_t, l_tx_cache_sz);
        memcpy(l_tx_cache, &l_prev_item_out->cache_data, sizeof(l_prev_item_out->cache_data));
        memcpy(l_tx_cache + sizeof(l_prev_item_out->cache_data), l_prev_item_out->tx, l_tx_size);
        char *l_tx_i_hash = dap_chain_hash_fast_to_str_new(&l_prev_item_out->tx_hash_fast);
        l_cache_used_outs[i] = (dap_store_obj_t) {
                .key        = l_tx_i_hash,
                .value      = l_tx_cache,
                .value_len  = l_tx_cache_sz,
                .group      = l_gdb_group
        };

        // delete previous transactions from cache because all out is used
        if(l_prev_item_out->cache_data.n_outs_used == l_prev_item_out->cache_data.n_outs) {
            dap_chain_hash_fast_t l_tx_prev_hash_to_del = bound_item->tx_prev_hash;
            // remove from memory ledger
            int res = dap_chain_ledger_tx_remove(a_ledger, &l_tx_prev_hash_to_del, a_tx->header.ts_created);
            if(res == -2) {
                if(s_debug_more) {
                    char * l_tx_prev_hash_str = dap_chain_hash_fast_to_str_new(&l_tx_prev_hash_to_del);
                    log_it(L_ERROR, "Can't delete previous transactions because hash=%s not found", l_tx_prev_hash_str);
                    DAP_DELETE(l_tx_prev_hash_str);
                }
                ret = -100;
                l_outs_used = i;
                goto FIN;
            }
            else if(res != 1) {
                if(s_debug_more) {
                    char * l_tx_prev_hash_str = dap_chain_hash_fast_to_str_new(&l_tx_prev_hash_to_del);
                    log_it(L_ERROR, "Can't delete previous transactions with hash=%s", l_tx_prev_hash_str);
                    DAP_DELETE(l_tx_prev_hash_str);
                }
                ret = -101;
                l_outs_used = i;
                goto FIN;
            }
        }
        // go to next previous transaction
        l_list_tmp = dap_list_next(l_list_tmp);
    }

    //Update balance : raise
    bool l_multichannel = false;
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

        dap_chain_addr_t *l_addr;
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
        char *l_addr_str = dap_chain_addr_to_str(l_addr);
        dap_ledger_wallet_balance_t *wallet_balance = NULL;
        char *l_wallet_balance_key = dap_strjoin(" ", l_addr_str, l_cur_token_ticker, (char*)NULL);
        if(s_debug_more) {
            char *l_balance = dap_chain_balance_print(l_value);
            log_it(L_DEBUG, "GOT %s to addr: %s", l_balance, l_wallet_balance_key);
            DAP_DELETE(l_balance);
        }
        pthread_rwlock_rdlock(&l_ledger_priv->balance_accounts_rwlock);
        HASH_FIND_STR(PVT(a_ledger)->balance_accounts, l_wallet_balance_key, wallet_balance);
        pthread_rwlock_unlock(&l_ledger_priv->balance_accounts_rwlock);
        if (wallet_balance) {
            //if(s_debug_more)
            //    log_it(L_DEBUG, "Balance item is present in cache");
            SUM_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            DAP_DELETE (l_wallet_balance_key);
            // Update the cache
            s_balance_cache_update(a_ledger, wallet_balance);
        } else {
            wallet_balance = DAP_NEW_Z(dap_ledger_wallet_balance_t);
            wallet_balance->key = l_wallet_balance_key;
            strcpy(wallet_balance->token_ticker, l_cur_token_ticker);
            SUM_256_256(wallet_balance->balance, l_value, &wallet_balance->balance);
            if(s_debug_more)
                log_it(L_DEBUG, "Create new balance item: %s %s", l_addr_str, l_cur_token_ticker);
            pthread_rwlock_wrlock(&l_ledger_priv->balance_accounts_rwlock);
            HASH_ADD_KEYPTR(hh, PVT(a_ledger)->balance_accounts, wallet_balance->key,
                            strlen(l_wallet_balance_key), wallet_balance);
            pthread_rwlock_unlock(&l_ledger_priv->balance_accounts_rwlock);
            // Add it to cache
            s_balance_cache_update(a_ledger, wallet_balance);
        }
        DAP_DELETE (l_addr_str);
    }

    // add transaction to the cache list
    dap_chain_ledger_tx_item_t *l_tx_item = DAP_NEW_Z(dap_chain_ledger_tx_item_t);
    l_tx_item->tx_hash_fast = *a_tx_hash;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    l_tx_item->tx = DAP_DUP_SIZE(a_tx, l_tx_size);
    l_tx_item->cache_data.ts_created = dap_time_now(); // Time of transasction added to ledge
    int l_outs_count = 0;
    dap_list_t *l_tist_tmp = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, &l_outs_count);
    l_tx_item->cache_data.n_outs = l_outs_count;
    // TODO: dump the UTXO in debug mode if need
    if(l_tist_tmp)
        dap_list_free(l_tist_tmp);
    dap_stpcpy(l_tx_item->cache_data.token_ticker, l_main_token_ticker);

    l_tx_item->cache_data.multichannel = l_multichannel;
    pthread_rwlock_wrlock(&l_ledger_priv->ledger_rwlock);
    l_tx_item->ts_added = dap_gdb_time_now();
    HASH_ADD_INORDER(hh, l_ledger_priv->ledger_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t),
                                 l_tx_item, s_sort_ledger_tx_item); // tx_hash_fast: name of key field
    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    // Callable callback
    for (dap_list_t *notifier = a_ledger->tx_add_notifiers; notifier != NULL; notifier = notifier->next) {
        dap_chain_ledger_tx_notifier_t *l_notify = (dap_chain_ledger_tx_notifier_t *)notifier->data;
        l_notify->callback(l_notify->arg, a_ledger, l_tx_item->tx);
    }
    // Count TPS
    clock_gettime(CLOCK_REALTIME, &l_ledger_priv->tps_end_time);
    l_ledger_priv->tps_count++;
    if (PVT(a_ledger)->cached) {
        // Add it to cache
        size_t l_tx_cache_sz = l_tx_size + sizeof(l_tx_item->cache_data);
        uint8_t *l_tx_cache = DAP_NEW_S_SIZE(uint8_t, l_tx_cache_sz);
        memcpy(l_tx_cache, &l_tx_item->cache_data, sizeof(l_tx_item->cache_data));
        memcpy(l_tx_cache + sizeof(l_tx_item->cache_data), a_tx, l_tx_size);
        l_cache_used_outs[0] = (dap_store_obj_t) {
                .key        = l_tx_hash_str,
                .value      = l_tx_cache,
                .value_len  = l_tx_cache_sz,
                .group      = l_gdb_group
        };
        // Apply it with single DB transaction
        if (dap_chain_global_db_driver_add(l_cache_used_outs, l_outs_used + 1)) {
            if(s_debug_more)
                log_it(L_WARNING, "Ledger cache mismatch");
        }
    }
    if (!a_from_threshold)
        s_threshold_txs_proc(a_ledger);
    ret = 1;
FIN:
    DAP_DEL_Z(l_main_token_ticker);
    if (l_list_bound_items)
        dap_list_free_full(l_list_bound_items, free);
    if (l_list_tx_out)
        dap_list_free(l_list_tx_out);
    for (size_t i = 1; i <= l_outs_used; i++) {
        DAP_DELETE(l_cache_used_outs[i].key);
        DAP_DELETE(l_cache_used_outs[i].value);
    }
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_cache_used_outs);
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
    if (PVT(a_ledger)->load_mode) {
        dap_chain_ledger_tx_item_t *l_tx_item;
        unsigned l_hash_value;
        HASH_VALUE(&l_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value);
        pthread_rwlock_rdlock(&PVT(a_ledger)->ledger_rwlock);
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->ledger_items, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_item);
        if (l_tx_item) {
            pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
            return 1;
        }
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->threshold_txs, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_item);
        if (l_tx_item) {
            pthread_rwlock_unlock(&PVT(a_ledger)->ledger_rwlock);
            return DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS;
        }
        dap_chain_ledger_tx_spent_item_t *l_tx_spent_item;
        HASH_FIND_BYHASHVALUE(hh, PVT(a_ledger)->spent_items, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_tx_spent_item);
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
int dap_chain_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, dap_time_t a_spent_time)
{
    if(!a_tx_hash)
        return -1;
    int l_ret = -1;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_item_tmp;
    unsigned l_hash_value;
    HASH_VALUE(a_tx_hash, sizeof(*a_tx_hash), l_hash_value);
    pthread_rwlock_wrlock(&l_ledger_priv->ledger_rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_priv->ledger_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_tmp);
    if(l_item_tmp != NULL) {
        HASH_DEL(l_ledger_priv->ledger_items, l_item_tmp);
        if (PVT(a_ledger)->cached) {
            // Remove it from cache
            char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
            char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(a_tx_hash);
            dap_chain_global_db_gr_del( l_tx_hash_str, l_gdb_group);
            DAP_DELETE(l_tx_hash_str);
            DAP_DELETE(l_gdb_group);
        }
        l_ret = 1;
        dap_chain_ledger_tx_spent_item_t *l_item_used;
        HASH_FIND_BYHASHVALUE(hh, l_ledger_priv->spent_items, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_used);
        if (!l_item_used) {   // Add it to spent items
            l_item_used = DAP_NEW_Z(dap_chain_ledger_tx_spent_item_t);
            l_item_used->tx_hash_fast = *a_tx_hash;
            l_item_used->cache_data.spent_time = a_spent_time;
            strncpy(l_item_used->cache_data.token_ticker, l_item_tmp->cache_data.token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
            int l_out_num = -1;
            dap_chain_datum_tx_out_cond_get(l_item_tmp->tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL, &l_out_num);
            if (l_out_num != -1 && l_out_num < MAX_OUT_ITEMS)
                l_item_used->cache_data.tx_hash_spent_fast = l_item_tmp->cache_data.tx_hash_spent_fast[l_out_num];
            HASH_ADD_BYHASHVALUE(hh, l_ledger_priv->spent_items, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_hash_value, l_item_used);
            if (PVT(a_ledger)->cached) {
                // Add it to cache
                char *l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
                char *l_tx_hash_str = dap_hash_fast_to_str_new(a_tx_hash);
                if (!dap_chain_global_db_gr_set(l_tx_hash_str, &l_item_used->cache_data, sizeof(l_item_used->cache_data), l_gdb_group)) {
                    if(s_debug_more)
                        log_it(L_WARNING, "Ledger cache mismatch");
                }
                DAP_DELETE(l_tx_hash_str);
                DAP_DELETE(l_gdb_group);
            }
        }
        // delete tx & its item
        DAP_DELETE(l_item_tmp->tx);
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
    pthread_rwlock_wrlock(&l_ledger_priv->threshold_emissions_rwlock);
    pthread_rwlock_wrlock(&l_ledger_priv->threshold_txs_rwlock);
    pthread_rwlock_wrlock(&l_ledger_priv->balance_accounts_rwlock);
    pthread_rwlock_wrlock(&l_ledger_priv->stake_lock_rwlock);

    /* Delete regular transactions */
    dap_chain_ledger_tx_item_t *l_item_current, *l_item_tmp;
    char *l_gdb_group;
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_priv->ledger_items, l_item_current);
        DAP_DELETE(l_item_current->tx);
        DAP_DEL_Z(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_TXS_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete spent transactions */
    dap_chain_ledger_tx_spent_item_t *l_spent_item_current, *l_spent_item_tmp;
    HASH_ITER(hh, l_ledger_priv->spent_items, l_spent_item_current, l_spent_item_tmp) {
        HASH_DEL(l_ledger_priv->spent_items, l_spent_item_current);
        DAP_DEL_Z(l_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_SPENT_TXS_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete balances */
    dap_ledger_wallet_balance_t *l_balance_current, *l_balance_tmp;
    HASH_ITER(hh, l_ledger_priv->balance_accounts, l_balance_current, l_balance_tmp) {
        HASH_DEL(l_ledger_priv->balance_accounts, l_balance_current);
        DAP_DELETE(l_balance_current->key);
        DAP_DELETE(l_balance_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_BALANCES_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete tokens and their emissions */
    dap_chain_ledger_token_item_t *l_token_current, *l_token_tmp;
    dap_chain_ledger_token_emission_item_t *l_emission_current, *l_emission_tmp;
    HASH_ITER(hh, l_ledger_priv->tokens, l_token_current, l_token_tmp) {
        HASH_DEL(l_ledger_priv->tokens, l_token_current);
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
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_EMISSIONS_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete stake-lock items */
    dap_chain_ledger_stake_lock_item_t *l_stake_item_current, *l_stake_item_tmp;
    HASH_ITER(hh, l_ledger_priv->emissions_for_stake_lock, l_stake_item_current, l_stake_item_tmp) {
        HASH_DEL(l_ledger_priv->emissions_for_stake_lock, l_stake_item_current);
        DAP_DELETE(l_stake_item_current);
    }
    if (!a_preserve_db) {
        l_gdb_group = dap_chain_ledger_get_gdb_group(a_ledger, DAP_CHAIN_LEDGER_STAKE_LOCK_STR);
        dap_chain_global_db_gr_del(NULL, l_gdb_group);
        DAP_DELETE(l_gdb_group);
    }

    /* Delete threshold emissions */
    HASH_ITER(hh, l_ledger_priv->threshold_emissions, l_emission_current, l_emission_tmp) {
        HASH_DEL(l_ledger_priv->threshold_emissions, l_emission_current);
        DAP_DELETE(l_emission_current->datum_token_emission);
        DAP_DELETE(l_emission_current);
    }
    /* Delete threshold transactions */
    HASH_ITER(hh, l_ledger_priv->threshold_txs, l_item_current, l_item_tmp) {
        HASH_DEL(l_ledger_priv->threshold_txs, l_item_current);
        DAP_DELETE(l_item_current->tx);
        DAP_DELETE(l_item_current);
    }

    l_ledger_priv->ledger_items         = NULL;
    l_ledger_priv->spent_items          = NULL;
    l_ledger_priv->balance_accounts     = NULL;
    l_ledger_priv->tokens               = NULL;
    l_ledger_priv->threshold_emissions  = NULL;
    l_ledger_priv->threshold_txs        = NULL;

    pthread_rwlock_unlock(&l_ledger_priv->ledger_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->tokens_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->threshold_emissions_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->threshold_txs_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->balance_accounts_rwlock);
    pthread_rwlock_unlock(&l_ledger_priv->stake_lock_rwlock);
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
bool dap_chain_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out, dap_chain_hash_fast_t *l_out_spndr_hash)
{
    dap_chain_ledger_tx_item_t *l_item_out = NULL;
    /* dap_chain_datum_tx_t *l_tx = */s_find_datum_tx_by_hash(a_ledger, a_tx_hash, &l_item_out);
    return dap_chain_ledger_item_is_used_out(l_item_out, a_idx_out, l_out_spndr_hash);
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
                        if(!dap_chain_ledger_item_is_used_out(l_iter_current, l_out_idx_tmp, NULL) &&
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
                        if(!dap_chain_ledger_item_is_used_out(l_iter_current, l_out_idx_tmp, NULL) &&
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
                        if(!dap_chain_ledger_item_is_used_out(l_iter_current, l_out_idx_tmp, NULL) &&
                                dap_chain_datum_tx_verify_sign(l_cur_tx)) {
                            SUM_256_256(balance, l_tx_out->header.value, &balance);
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
static dap_chain_ledger_tx_item_t* tx_item_find_by_addr(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                                                        const char * a_token, dap_chain_hash_fast_t *a_tx_first_hash)
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
    HASH_ITER(hh, l_ledger_priv->ledger_items , l_iter_current, l_item_tmp) {
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
 * @brief Get all transactions from the cache with the out_cond item
 * @param a_ledger
 * @param a_srv_uid
 * @return
 */
dap_list_t* dap_chain_ledger_tx_cache_find_out_cond_all(dap_ledger_t *a_ledger,dap_chain_net_srv_uid_t a_srv_uid)
{
    dap_list_t * l_ret = NULL;
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_ledger_tx_item_t *l_iter_current = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh, l_ledger_priv->ledger_items, l_iter_current, l_item_tmp) {
        dap_chain_datum_tx_t *l_tx = l_iter_current->tx;
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_COND, NULL);
        for (dap_list_t *it = l_list_out_items; it; it = it->next) {
            // Is present cond out
            dap_chain_tx_out_cond_t *l_tx_out_cond = it->data;
            if (l_tx_out_cond->header.srv_uid.uint64 == a_srv_uid.uint64) // is srv uid is same as we're searching for?
                l_ret = dap_list_append(l_ret,l_tx);
        }

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
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    dap_chain_ledger_tx_item_t *l_iter_current = NULL, *l_item_tmp = NULL;
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    int l_tx_out_cond_idx = -1;
    pthread_rwlock_rdlock(&l_ledger_priv->ledger_rwlock);
    HASH_ITER(hh, l_ledger_priv->ledger_items, l_iter_current, l_item_tmp) {
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
 * @return
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
                    if (!l_out->header.value || memcmp(a_addr_from, &l_out->addr, sizeof(dap_chain_addr_t))) {
                        continue;
                    }
                    l_value = GET_256_FROM_64(l_out->header.value);
                } break;
                case TX_ITEM_TYPE_OUT: {
                    dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_list_tmp->data;
                    if ( IS_ZERO_256(l_out->header.value) || memcmp(a_addr_from, &l_out->addr, sizeof(dap_chain_addr_t))) {
                        continue;
                    }
                    l_value = l_out->header.value;
                } break;
                case TX_ITEM_TYPE_OUT_EXT: {
                    dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
                    if (IS_ZERO_256(l_out_ext->header.value) || memcmp(a_addr_from, &l_out_ext->addr, sizeof(dap_chain_addr_t)) ||
                            strcmp((char *)a_token_ticker, l_out_ext->token)) {
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
                list_used_item_t *l_item = DAP_NEW_Z(list_used_item_t);
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
        dap_list_free_full(l_list_used_out, free);
        return NULL;
    }

    if (a_value_transfer) {
        *a_value_transfer = l_value_transfer;
    }
    return l_list_used_out;
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
                list_used_item_t *l_item = DAP_NEW(list_used_item_t);
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
        dap_list_free_full(l_list_used_out, free);
        return NULL;
    }

    if (a_value_transfer) {
        *a_value_transfer = l_value_transfer;
    }
    return l_list_used_out;
}

// Add new verificator callback with associated subtype. Returns 1 if callback replaced, overwise returns 0
int dap_chain_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype, dap_chain_ledger_verificator_callback_t a_callback, dap_chain_ledger_verificator_callback_out_t a_callback_added)
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
    l_new_verificator->callback_added = a_callback_added;
    pthread_rwlock_wrlock(&s_verificators_rwlock);
    HASH_ADD_INT(s_verificators, subtype, l_new_verificator);
    pthread_rwlock_unlock(&s_verificators_rwlock);
    return 0;
}


dap_list_t * dap_chain_ledger_get_txs(dap_ledger_t *a_ledger, size_t a_count, size_t a_page, bool reverse){
    dap_ledger_private_t *l_ledger_priv = PVT(a_ledger);
    size_t l_offset = a_count * (a_page - 1);
    size_t l_count = HASH_COUNT(l_ledger_priv->ledger_items);
    if (a_page < 2)
        l_offset = 0;
    if (l_offset > l_count){
        return NULL;
    }
    dap_list_t *l_list = NULL;
    size_t l_counter = 0;
    size_t l_end = l_offset + a_count;
    if (!l_ledger_priv->ledger_items) {
        return NULL;
    }
    if (reverse) {
        dap_chain_ledger_tx_item_t *l_ptr = l_ledger_priv->ledger_items->hh.tbl->tail->prev;
        if (!l_ptr)
            l_ptr = l_ledger_priv->ledger_items;
        else
            l_ptr = l_ptr->hh.next;
        for (dap_chain_ledger_tx_item_t *ptr = l_ptr; ptr != NULL && l_counter < l_end; ptr = ptr->hh.prev) {
            if (l_counter >= l_offset) {
                dap_chain_datum_tx_t *l_tx = ptr->tx;
                l_list = dap_list_append(l_list, l_tx);
            }
            l_counter++;
        }
    } else {
        dap_chain_ledger_tx_item_t *l_ptr = l_ledger_priv->ledger_items;
        for (dap_chain_ledger_tx_item_t *ptr = l_ptr; ptr != NULL && l_counter < l_end; ptr = ptr->hh.next) {
            if (l_counter >= l_offset) {
                dap_chain_datum_tx_t *l_tx = ptr->tx;
                l_list = dap_list_append(l_list, l_tx);
            }
            l_counter++;
        }
    }
    return l_list;
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
    a_ledger->tx_add_notifiers = dap_list_append(a_ledger->tx_add_notifiers, l_notifier);
}


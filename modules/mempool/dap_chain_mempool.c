/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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
#include <stddef.h>
#include <assert.h>
#include <memory.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
#include "dap_enc_base58.h"
#include "dap_enc_http.h"
#include "dap_http_status_code.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"  // For dap_chain_net_by_id
// REMOVED: dap_chain_node.h - dead include, not used
#include "dap_global_db.h"
#include "dap_global_db_cluster.h"
#include "dap_enc.h"
#include <dap_enc_http.h>
#include <dap_enc_key.h>
#include <dap_enc_ks.h>
#include "dap_chain_mempool.h"
#include "dap_config.h"

#include "dap_common.h"
#include "dap_list.h"
#include "dap_chain.h"
#include "dap_chain_net_core.h"  // All net API through core (no direct net dependency)
#include "dap_chain_net_types.h"  // For access to net->pub fields
#include "dap_chain_net.h"  // Headers OK (no CMake link dependency = no cycle)
// REMOVED target_link_libraries dependency on dap_chain_net in CMakeLists - that creates cycle
// But headers can be included safely for declarations
#include "dap_chain_net_tx.h"  // For dap_chain_net_tx_get_fee
#include "dap_chain_wallet.h"  // For dap_chain_wallet_get_list_tx_outs_with_val
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
// REMOVED: dap_chain_block_tx.h - deprecated wrapper functions removed to break mempool <-> blocks cycle
// REMOVED: dap_chain_wallet.h - dead include, not used
#include "dap_chain_ledger.h"  // Normal dependency: mempool (high) → ledger (mid)
#include "dap_chain_mempool_cli.h"

#define LOG_TAG "dap_chain_mempool"

extern int g_dap_global_db_debug_more;

static bool s_tx_create_massive_gdb_save_callback(dap_global_db_instance_t *a_dbi,
                                                  int a_rc, const char *a_group,
                                                  const size_t a_values_total, const size_t a_values_count,
                                                  dap_global_db_obj_t *a_values, void *a_arg);

/**
 * @brief Callback function for handling mempool record deletion by TTL
 * @details This callback is triggered when a mempool record expires due to TTL.
 *          It notifies all cluster subscribers about the deletion and then removes the record.
 * @param a_obj Store object being deleted (contains datum from mempool)
 * @param a_arg Custom argument (chain pointer)
 */
static void s_mempool_ttl_delete_callback(dap_store_obj_t *a_obj, void *a_arg)
{
    if (!a_obj) {
        log_it(L_WARNING, "Received NULL object in mempool TTL delete callback");
        return;
    }

    dap_chain_t *l_chain = (dap_chain_t *)a_arg;
    if (!l_chain) {
        log_it(L_WARNING, "Chain context is NULL in mempool TTL delete callback for group %s key %s", 
               a_obj->group, a_obj->key);
        dap_global_db_driver_delete(a_obj, 1);
        return;
    }

    // Get the mempool cluster to access notifiers
    dap_global_db_cluster_t *l_cluster = dap_chain_net_get_mempool_cluster(l_chain);
    if (!l_cluster) {
        log_it(L_WARNING, "Can't find mempool cluster for chain %s", l_chain->name);
        dap_global_db_driver_delete(a_obj, 1);
        return;
    }

    // Log the deletion event
    const char *l_datum_type_str = "unknown";
    if (a_obj->value && a_obj->value_len >= sizeof(dap_chain_datum_t)) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)a_obj->value;
        switch (l_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN:
            l_datum_type_str = "token";
            break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION:
            l_datum_type_str = "emission";
            break;
        case DAP_CHAIN_DATUM_TX:
            l_datum_type_str = "transaction";
            break;
        default:
            DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_datum_type_str);
        }
    }

    log_it(L_NOTICE, "Mempool TTL cleanup: removing %s datum with key %s from chain %s mempool group %s", 
           l_datum_type_str, a_obj->key, l_chain->name, a_obj->group);

    // Mark object as being deleted by TTL (set DEL flag for notifiers to recognize)
    // This allows notifiers to distinguish between normal operations and TTL deletions
    a_obj->flags |= DAP_GLOBAL_DB_RECORD_DEL;

    // IMPORTANT: Notify all cluster subscribers BEFORE actual deletion
    // This allows them to react to the deletion event (e.g., update caches, logs, etc.)
    if (l_cluster->notifiers) {
        debug_if(g_dap_global_db_debug_more, L_DEBUG, 
                 "Notifying cluster subscribers about TTL deletion of %s:%s", 
                 a_obj->group, a_obj->key);
        dap_global_db_cluster_notify(l_cluster, a_obj);
    }

    // Actually delete the record from GlobalDB
    dap_global_db_driver_delete(a_obj, 1);
}

/**
 * @brief Initialize mempool TTL delete callbacks for all chains
 * @details Registers del_callback for each chain's mempool cluster to handle TTL-based deletions
 * @return 0 if successful, negative error code otherwise
 */
int dap_chain_mempool_delete_callback_init()
{
    int l_registered_count = 0;
    
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        dap_chain_t *l_chain = NULL;
        
        // Iterate through all chains in the network
        DL_FOREACH(l_net->pub.chains, l_chain) {
            // Get the mempool cluster for this chain
            dap_global_db_cluster_t *l_cluster = dap_chain_net_get_mempool_cluster(l_chain);
            
            if (!l_cluster) {
                log_it(L_WARNING, "Can't find mempool cluster for chain %s in network %s", 
                       l_chain->name, l_net->pub.name);
                continue;
            }
            
            // Register the delete callback
            l_cluster->del_callback = s_mempool_ttl_delete_callback;
            l_cluster->del_arg = l_chain;
            
            log_it(L_INFO, "Registered mempool TTL delete callback for chain %s (network %s, group mask %s)", 
                   l_chain->name, l_net->pub.name, l_cluster->groups_mask);
            
            l_registered_count++;
        }
    }
    
    if (l_registered_count > 0) {
        log_it(L_NOTICE, "Mempool TTL delete callbacks initialized for %d chain(s)", l_registered_count);
        return 0;
    } else {
        log_it(L_WARNING, "No mempool TTL delete callbacks were registered");
        return -1;
    }
}

int dap_datum_mempool_init(void)
{
    dap_chain_mempool_delete_callback_init();
    
    // Register mempool CLI commands
    int l_cli_res = dap_chain_mempool_cli_init();
    if (l_cli_res != 0) {
        log_it(L_WARNING, "Failed to initialize mempool CLI commands: %d", l_cli_res);
    }
    
    return 0;
}

/**
 * @brief dap_chain_mempool_datum_add
 * @param a_datum
 * @return
 */
char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    dap_return_val_if_pass(!a_datum, NULL);

    dap_chain_hash_fast_t l_key_hash;
    dap_chain_datum_calc_hash(a_datum, &l_key_hash);
    char *l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    const char *l_key_str_out = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(&l_key_hash)
            : l_key_str;

    const char *l_type_str;
    switch (a_datum->header.type_id) {
    case DAP_CHAIN_DATUM_TOKEN:
        l_type_str = "token";
        break;
    case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
        size_t l_emission_size = a_datum->header.data_size;
        dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read((byte_t*)a_datum->data, &l_emission_size);
        uint64_t l_net_id = l_emission ? l_emission->hdr.address.net_id.uint64 : 0;
        DAP_DELETE(l_emission);
        if (l_net_id != a_chain->net_id.uint64) {
            log_it(L_WARNING, "Datum emission with hash %s NOT placed in mempool: wallet addr net ID %lu != %lu chain net ID",
                   l_key_str_out, l_net_id, a_chain->net_id.uint64);
            DAP_DELETE(l_key_str);
            return NULL;
        }
        l_type_str = "emission";
        break;
    }
    case DAP_CHAIN_DATUM_TX:
        l_type_str = "transaction";
        break;
    default:
        DAP_DATUM_TYPE_STR(a_datum->header.type_id, l_type_str);
    }

    char *l_gdb_group = dap_chain_mempool_group_new(a_chain);
    int l_res = dap_global_db_set_sync(l_gdb_group, l_key_str, a_datum, dap_chain_datum_size(a_datum), false);//, NULL, NULL);
    if (l_res == DAP_GLOBAL_DB_RC_SUCCESS)
        log_it(L_NOTICE, "Datum %s with hash %s was placed in mempool group %s", l_type_str, l_key_str_out, l_gdb_group);
    else
        log_it(L_WARNING, "Can't place datum %s with hash %s in mempool group %s", l_type_str, l_key_str_out, l_gdb_group);
    char *ret = (l_res == DAP_GLOBAL_DB_RC_SUCCESS) ? dap_strdup(l_key_str_out) : NULL;
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);
    return ret;
}

/**
 * @brief Create GDB group name for chain mempool
 * @param a_chain Chain
 * @return Group name (caller must free) or NULL
 */
char *dap_chain_mempool_group_new(dap_chain_t *a_chain)
{
    dap_chain_net_t *l_net = a_chain ? dap_chain_net_by_id(a_chain->net_id) : NULL;
    return l_net
            ? dap_chain_mempool_group_name(l_net->pub.gdb_groups_prefix, a_chain->name)
            : NULL;
}

static dap_datum_mempool_t *dap_datum_mempool_deserialize(uint8_t *a_datum_mempool_ser, size_t a_datum_mempool_ser_size)
{
    size_t shift_size = 0;
    dap_datum_mempool_t *datum_mempool = DAP_NEW_Z(dap_datum_mempool_t);
    if (!datum_mempool) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    datum_mempool->version = *(uint16_t*)(a_datum_mempool_ser + shift_size);
    shift_size += sizeof(uint16_t);
    datum_mempool->datum_count = *(uint16_t*)(a_datum_mempool_ser + shift_size);
    shift_size += sizeof(uint16_t);
    datum_mempool->data = DAP_NEW_Z_SIZE(dap_chain_datum_t*, datum_mempool->datum_count * sizeof(dap_chain_datum_t*));
    for (int i = 0; i < datum_mempool->datum_count; i++) {
        uint16_t size_one = *(uint16_t*)(a_datum_mempool_ser + shift_size);
        shift_size += sizeof(uint16_t);
        datum_mempool->data[i] = DAP_DUP((dap_chain_datum_t*)(a_datum_mempool_ser + shift_size));
        shift_size += size_one;
    }
    assert(shift_size == a_datum_mempool_ser_size);
    return datum_mempool;
}

static void dap_datum_mempool_clean(dap_datum_mempool_t *datum)
{
    if(!datum)
        return;
    for(int i = 0; i < datum->datum_count; i++) {
        DAP_DELETE(datum->data[i]);
    }
    DAP_DELETE(datum->data);
    datum->data = NULL;
}

static void dap_datum_mempool_free(dap_datum_mempool_t *datum)
{
    dap_datum_mempool_clean(datum);
    DAP_DELETE(datum);
}

static char* s_calc_datum_hash(const void *a_datum_str, size_t datum_size)
{
    dap_chain_hash_fast_t a_hash;
    dap_hash_fast(a_datum_str, datum_size, &a_hash);
    size_t a_str_max = (sizeof(a_hash.raw) + 1) * 2 + 2;
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);

    dap_chain_hash_fast_to_str(&a_hash, a_str, a_str_max);
    return a_str;
}

static void enc_http_reply_encode_new(struct dap_http_simple *a_http_simple, dap_enc_key_t *key,
        enc_http_delegate_t *a_http_delegate)
{
    if (key == NULL) {
        log_it(L_ERROR, "Can't find http key.");
        return;
    }
    if (a_http_delegate->response) {
        if (a_http_simple->reply)
            DAP_DELETE(a_http_simple->reply);

        size_t l_reply_size_max = dap_enc_code_out_size(a_http_delegate->key,
                a_http_delegate->response_size,
                DAP_ENC_DATA_TYPE_RAW);

        a_http_simple->reply = DAP_NEW_SIZE(void, l_reply_size_max);
        a_http_simple->reply_size = dap_enc_code(a_http_delegate->key,
                a_http_delegate->response, a_http_delegate->response_size,
                a_http_simple->reply, l_reply_size_max,
                DAP_ENC_DATA_TYPE_RAW);
    }
}

static void chain_mempool_proc(struct dap_http_simple *cl_st, void *arg)
{
    dap_http_status_code_t *return_code = (dap_http_status_code_t*)arg;
    dap_enc_key_t *l_enc_key = dap_enc_ks_find_http(cl_st->http_client);

    dap_http_header_t *hdr_session_close_id =
            (cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "SessionCloseAfterRequest") : NULL;
    dap_http_header_t *hdr_key_id =
            (hdr_session_close_id && cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "KeyID") : NULL;

    enc_http_delegate_t *l_enc_delegate = enc_http_request_decode(cl_st);
    if (l_enc_delegate) {
        char *suburl = l_enc_delegate->url_path;
        byte_t *l_request_data = l_enc_delegate->request_bytes;
        size_t l_request_size = l_enc_delegate->request_size;
        const char *l_gdb_datum_pool = dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool");
        if (l_request_data && l_request_size > 1) {
            uint8_t action = DAP_DATUM_MEMPOOL_NONE;
            if (l_enc_delegate->url_path_size > 0) {
                if (!strcmp(suburl, "add"))
                    action = DAP_DATUM_MEMPOOL_ADD;
                else if (!strcmp(suburl, "check"))
                    action = DAP_DATUM_MEMPOOL_CHECK;
                else if (!strcmp(suburl, "del"))
                    action = DAP_DATUM_MEMPOOL_DEL;
            }
            dap_datum_mempool_t *datum_mempool =
                    (action != DAP_DATUM_MEMPOOL_NONE) ?
                            dap_datum_mempool_deserialize((uint8_t*)l_request_data, (size_t)l_request_size) : NULL;
            if (datum_mempool) {
                dap_datum_mempool_free(datum_mempool);
                char *a_key = s_calc_datum_hash(l_request_data, (size_t)l_request_size);
                switch (action)
                {
                case DAP_DATUM_MEMPOOL_ADD:
                    if (dap_global_db_set_sync(l_gdb_datum_pool, a_key, l_request_data, l_request_size, false) == 0) {
                        *return_code = DAP_HTTP_STATUS_OK;
                    }
                    log_it(L_INFO, "Insert hash: key=%s result:%s", a_key,
                            (*return_code == DAP_HTTP_STATUS_OK) ? "OK" : "False!");
                    break;

                case DAP_DATUM_MEMPOOL_CHECK:
                    strcpy(cl_st->reply_mime, "text/text");
                    size_t l_datum_size = 0;
                    byte_t *l_datum = dap_global_db_get_sync(l_gdb_datum_pool, a_key, &l_datum_size, NULL, NULL);
                    if (l_datum) {
                        l_enc_delegate->response = strdup("1");
                        DAP_DEL_Z(l_datum);
                        log_it(L_INFO, "Check hash: key=%s result: Present", a_key);
                    }
                    else {
                        l_enc_delegate->response = strdup("0");
                        log_it(L_INFO, "Check hash: key=%s result: Absent", a_key);
                    }
                    l_enc_delegate->response_size = l_datum_size;
                    *return_code = DAP_HTTP_STATUS_OK;
                    enc_http_reply_encode_new(cl_st, l_enc_key, l_enc_delegate);
                    break;

                case DAP_DATUM_MEMPOOL_DEL:
                    strcpy(cl_st->reply_mime, "text/text");
                    if (dap_global_db_del_sync(l_gdb_datum_pool, a_key) == 0){
                        l_enc_delegate->response = dap_strdup("1");
                        log_it(L_INFO, "Delete hash: key=%s result: Ok", a_key);
                    } else {
                        l_enc_delegate->response = dap_strdup("0");
                        log_it(L_INFO, "Delete hash: key=%s result: False!", a_key);
                    }
                    *return_code = DAP_HTTP_STATUS_OK;
                    enc_http_reply_encode_new(cl_st, l_enc_key, l_enc_delegate);
                    break;

                default:
                    log_it(L_INFO, "Unknown request=%s! key=%s", (suburl) ? suburl : "-", a_key);
                    enc_http_delegate_delete(l_enc_delegate);
                    if (hdr_key_id)
                        dap_enc_ks_delete(hdr_key_id->value);
                    *return_code = DAP_HTTP_STATUS_BAD_REQUEST;
                    return;
                }
                DAP_DEL_Z(a_key);
            } else
                *return_code = DAP_HTTP_STATUS_BAD_REQUEST;
        } else
            *return_code = DAP_HTTP_STATUS_BAD_REQUEST;

        enc_http_delegate_delete(l_enc_delegate);
    } else
        *return_code = DAP_HTTP_STATUS_UNAUTHORIZED;

    if (hdr_session_close_id && !strcmp(hdr_session_close_id->value, "yes") && hdr_key_id)
        dap_enc_ks_delete(hdr_key_id->value);
}

void dap_chain_mempool_add_proc(dap_http_server_t *a_http_server, const char *a_url)
{
    dap_http_simple_proc_add(a_http_server, a_url, 4096, chain_mempool_proc);
}

/**
 * @brief Check if output is used in mempool
 * @param a_net Network
 * @param a_out_hash TX hash
 * @param a_out_idx Output index
 * @return true if used
 */
bool dap_chain_mempool_out_is_used(dap_chain_net_t *a_net, dap_hash_fast_t *a_out_hash, uint32_t a_out_idx)
{
    // Check if this UTXO is spent by any TX in mempool
    if (!a_net || !a_out_hash)
        return false;
    
    // Iterate through all chains in network
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        char *l_gdb_group = dap_chain_mempool_group_new(l_chain);
        if (!l_gdb_group)
            continue;
        
        // Get all datums from mempool
        size_t l_objs_count = 0;
        dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group, &l_objs_count);
        DAP_DELETE(l_gdb_group);
        
        // Check each TX in mempool
        for (size_t i = 0; i < l_objs_count; i++) {
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
            if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
                continue;
            
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
            
            // Check all inputs
            byte_t *l_item = NULL;
            size_t l_item_size = 0;
            TX_ITEM_ITER_TX(l_item, l_item_size, l_tx) {
                if (*l_item != TX_ITEM_TYPE_IN && *l_item != TX_ITEM_TYPE_IN_COND)
                    continue;
                
                dap_chain_tx_in_t *l_in = (dap_chain_tx_in_t *)l_item;
                if (dap_hash_fast_compare(&l_in->header.tx_prev_hash, a_out_hash) &&
                    l_in->header.tx_out_prev_idx == a_out_idx) {
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    return true;  // Found: output is spent
                }
            }
        }
        
        dap_global_db_objs_delete(l_objs, l_objs_count);
    }
    
    return false;  // Not found: output is unspent
}

/**
 * @brief Filter mempool datums
 * @param a_chain Chain
 * @param a_removed Output: number of removed datums
 */
void dap_chain_mempool_filter(dap_chain_t *a_chain, int *a_removed)
{
    if (!a_chain || !a_removed)
        return;
    
    *a_removed = 0;
    char *l_gdb_group = dap_chain_mempool_group_new(a_chain);
    if (!l_gdb_group)
        return;
    
    // Get all mempool datums
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group, &l_objs_count);
    
    // Filter logic: remove invalid/expired datums
    for (size_t i = 0; i < l_objs_count; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
        if (!l_datum)
            continue;
        
        // TODO: Add filtering criteria (e.g., expired TXs, invalid format)
        // For now, just count valid datums
        UNUSED(l_datum);
    }
    
    dap_global_db_objs_delete(l_objs, l_objs_count);
    DAP_DELETE(l_gdb_group);
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */

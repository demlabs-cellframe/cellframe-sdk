/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

 DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "utlist.h"

#include "dap_worker.h"
#include "dap_events.h"
#include "dap_proc_thread.h"
#include "dap_client_pvt.h"

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cell.h"

#include "dap_global_db_legacy.h"
#include "dap_global_db_pkt.h"
#include "dap_global_db_ch.h"

#include "dap_stream.h"
#include "dap_stream_pkt.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_chain_ch.h"
#include "dap_chain_ch_pkt.h"
#include "dap_stream_ch_gossip.h"

#define LOG_TAG "dap_chain_ch"

#define DAP_CHAIN_PKT_EXPECT_SIZE   DAP_STREAM_PKT_FRAGMENT_SIZE

enum sync_context_state {
    SYNC_STATE_IDLE,
    SYNC_STATE_READY,
    SYNC_STATE_BUSY,
    SYNC_STATE_OVER
};

struct sync_context {
    atomic_uint_fast64_t allowed_num;
    atomic_uint_fast16_t state;
    dap_chain_atom_iter_t *iter;
    dap_stream_node_addr_t addr;
    dap_chain_net_id_t net_id;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
    uint64_t num_last;
    dap_time_t last_activity;
};

typedef struct dap_chain_ch_hash_item {
    dap_hash_fast_t hash;
    uint32_t size;
    UT_hash_handle hh;
} dap_chain_ch_hash_item_t;

struct legacy_sync_context {
    dap_stream_worker_t *worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_stream_node_addr_t remote_addr;
    dap_chain_ch_pkt_hdr_t request_hdr;

    _Atomic(dap_chain_ch_state_t) state;
    dap_chain_ch_error_type_t last_error;

    bool is_type_of_gdb;
    union {
        struct {
            dap_chain_ch_hash_item_t *remote_atoms;     // Remote atoms
            dap_chain_atom_iter_t *atom_iter;           // Atom iterator
            uint64_t stats_request_atoms_processed;     // Atoms statictic
        };
        struct {
            dap_chain_ch_hash_item_t *remote_gdbs;      // Remote gdbs
            dap_global_db_legacy_list_t *db_list;       // DB iterator
            uint64_t stats_request_gdbs_processed;      // DB statictic
        };
    };

    dap_time_t last_activity;
    dap_chain_ch_state_t prev_state;
    size_t enqueued_data_size;
};

typedef struct dap_chain_ch {
    void *_inheritor;
    dap_timerfd_t *sync_timer;
    struct sync_context *sync_context;

    // Legacy section //
    dap_timerfd_t *activity_timer;
    uint32_t timer_shots;
    int sent_breaks;
    struct legacy_sync_context *legacy_sync_context;
} dap_chain_ch_t;

#define DAP_CHAIN_CH(a) ((dap_chain_ch_t *) ((a)->internal) )
#define DAP_STREAM_CH(a) ((dap_stream_ch_t *)((a)->_inheritor))

static void s_ch_chain_go_idle(dap_chain_ch_t *a_ch_chain);

static void s_stream_ch_new(dap_stream_ch_t *a_ch, void *a_arg);
static void s_stream_ch_delete(dap_stream_ch_t *a_ch, void *a_arg);
static bool s_stream_ch_packet_in(dap_stream_ch_t * a_ch, void *a_arg);
static void s_stream_ch_io_complete(dap_events_socket_t *a_es, void *a_arg);

static bool s_sync_in_chains_callback(void *a_arg);
static bool s_sync_out_chains_proc_callback(void *a_arg);
static bool s_gdb_in_pkt_proc_callback(void *a_arg);
static bool s_sync_out_gdb_proc_callback(void *a_arg);

static void s_stream_ch_chain_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size);

static void s_gossip_payload_callback(void *a_payload, size_t a_payload_size, dap_stream_node_addr_t a_sender_addr);
static bool s_chain_iter_callback(void *a_arg);
static bool s_chain_iter_delete_callback(void *a_arg);
static bool s_sync_timer_callback(void *a_arg);

static bool s_debug_more = false, s_debug_legacy = false;
static uint32_t s_sync_timeout = 30;
static uint32_t s_sync_packets_per_thread_call = 10;
static uint32_t s_sync_ack_window_size = 100; // atoms

// Legacy
static uint_fast16_t s_update_pack_size = 100; // Number of hashes packed into the one packet

#ifdef  DAP_SYS_DEBUG

enum    {MEMSTAT$K_STM_CH_CHAIN, MEMSTAT$K_NR};
static  dap_memstat_rec_t   s_memstat [MEMSTAT$K_NR] = {
    {.fac_len = sizeof(LOG_TAG) - 1, .fac_name = {LOG_TAG}, .alloc_sz = sizeof(dap_chain_ch_t)},
};

#endif

static const char *s_error_type_to_string(dap_chain_ch_error_type_t a_error)
{
    switch (a_error) {
    case DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS:
        return "SYNC_REQUEST_ALREADY_IN_PROCESS";
    case DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE:
        return "INCORRECT_SYNC_SEQUENCE";
    case DAP_CHAIN_CH_ERROR_SYNC_TIMEOUT:
        return "SYNCHRONIZATION TIMEOUT";
    case DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE:
        return "INVALID_PACKET_SIZE";
    case DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE:
        return "INVALID_LEGACY_PACKET_SIZE";
    case DAP_CHAIN_CH_ERROR_NET_INVALID_ID:
        return "INVALID_NET_ID";
    case DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND:
        return "CHAIN_NOT_FOUND";
    case DAP_CHAIN_CH_ERROR_ATOM_NOT_FOUND:
        return "ATOM_NOT_FOUND";
    case DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE:
        return "UNKNOWN_CHAIN_PACKET_TYPE";
    case DAP_CHAIN_CH_ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED:
        return "GLOBAL_DB_INTERNAL_SAVING_ERROR";
    case DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE:
        return "NET_IS_OFFLINE";
    case DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY:
        return "OUT_OF_MEMORY";
    case DAP_CHAIN_CH_ERROR_INTERNAL:
        return "INTERNAL_ERROR";
    default:
        return "UNKNOWN_ERROR";
    }
}

/**
 * @brief dap_chain_ch_init
 * @return
 */
int dap_chain_ch_init()
{
    log_it(L_NOTICE, "Chains exchange channel initialized");
    dap_stream_ch_proc_add(DAP_CHAIN_CH_ID, s_stream_ch_new, s_stream_ch_delete, s_stream_ch_packet_in, NULL);
    s_sync_timeout = dap_config_get_item_uint32_default(g_config, "chain", "sync_timeout", s_sync_timeout);
    s_sync_ack_window_size = dap_config_get_item_uint32_default(g_config, "chain", "sync_ack_window_size", s_sync_ack_window_size);
    s_sync_packets_per_thread_call = dap_config_get_item_int16_default(g_config, "chain", "pack_size", s_sync_packets_per_thread_call);
    s_debug_more = dap_config_get_item_bool_default(g_config, "chain", "debug_more", false);
    s_debug_legacy = dap_config_get_item_bool_default(g_config, "chain", "debug_legacy", false);
#ifdef  DAP_SYS_DEBUG
    for (int i = 0; i < MEMSTAT$K_NR; i++)
        dap_memstat_reg(&s_memstat[i]);
#endif
    return dap_stream_ch_gossip_callback_add(DAP_CHAIN_CH_ID, s_gossip_payload_callback);
}

/**
 * @brief dap_chain_ch_deinit
 */
void dap_chain_ch_deinit()
{

}

/**
 * @brief s_stream_ch_new
 * @param a_ch
 * @param arg
 */
void s_stream_ch_new(dap_stream_ch_t *a_ch, void *a_arg)
{
    UNUSED(a_arg);
    if (!(a_ch->internal = DAP_NEW_Z(dap_chain_ch_t))) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return;
    };
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    l_ch_chain->_inheritor = a_ch;

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM_CH_CHAIN].alloc_nr, 1);
#endif
    debug_if(s_debug_more, L_DEBUG, "[stm_ch_chain:%p] --- created chain:%p", a_ch, l_ch_chain);
}

/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
static void s_stream_ch_delete(dap_stream_ch_t *a_ch, void *a_arg)
{
    UNUSED(a_arg);
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    s_ch_chain_go_idle(l_ch_chain);
    debug_if(s_debug_more, L_DEBUG, "[stm_ch_chain:%p] --- deleted chain:%p", a_ch, l_ch_chain);
    DAP_DEL_Z(a_ch->internal);

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM_CH_CHAIN].free_nr, 1);
#endif
}

// *** Legacy support code *** //

/**
 * @brief dap_chain_ch_create_sync_request_gdb
 * @param a_ch_chain
 * @param a_net
 */
struct legacy_sync_context *s_legacy_sync_context_create(dap_chain_ch_pkt_t *a_chain_pkt, dap_stream_ch_t *a_ch)
{
    dap_chain_ch_t * l_ch_chain = DAP_CHAIN_CH(a_ch);
    dap_return_val_if_fail(l_ch_chain, NULL);

    struct legacy_sync_context *l_context;
    DAP_NEW_Z_RET_VAL(l_context, struct legacy_sync_context, NULL, NULL);

    *l_context = (struct legacy_sync_context) {
            .worker         = a_ch->stream_worker,
            .ch_uuid        = a_ch->uuid,
            .remote_addr    = *(dap_stream_node_addr_t *)a_chain_pkt->data,
            .request_hdr    = a_chain_pkt->hdr,
            .state          = DAP_CHAIN_CH_STATE_IDLE,
            .last_activity  = dap_time_now()
        };
    dap_stream_ch_uuid_t *l_uuid = DAP_DUP(&a_ch->uuid);
    if (!l_uuid) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        DAP_DELETE(l_context);
        return NULL;
    }
    l_ch_chain->sync_timer = dap_timerfd_start_on_worker(a_ch->stream_worker->worker, 1000, s_sync_timer_callback, l_uuid);
    a_ch->stream->esocket->callbacks.write_finished_callback = s_stream_ch_io_complete;
    a_ch->stream->esocket->callbacks.arg = l_context;
    if (l_context->worker->worker->_inheritor != a_ch->stream_worker)
        log_it(L_CRITICAL, "Corrupted stream worker %p", a_ch->stream_worker);
    return l_context;
}

/**
 * @brief s_stream_ch_chain_delete
 * @param a_ch_chain
 */
static void s_legacy_sync_context_delete(void *a_arg)
{
    struct legacy_sync_context *l_context = a_arg;
    dap_return_if_fail(l_context);

    dap_chain_ch_hash_item_t *l_hash_item, *l_tmp;

    if (l_context->is_type_of_gdb) {
        HASH_ITER(hh, l_context->remote_gdbs, l_hash_item, l_tmp) {
            // Clang bug at this, l_hash_item should change at every loop cycle
            HASH_DEL(l_context->remote_gdbs, l_hash_item);
            DAP_DELETE(l_hash_item);
        }
        l_context->remote_atoms = NULL;

        if (l_context->db_list)
            dap_global_db_legacy_list_delete(l_context->db_list);
    } else {
        HASH_ITER(hh, l_context->remote_atoms, l_hash_item, l_tmp) {
            // Clang bug at this, l_hash_item should change at every loop cycle
            HASH_DEL(l_context->remote_atoms, l_hash_item);
            DAP_DELETE(l_hash_item);
        }
        l_context->remote_gdbs = NULL;

        if (l_context->atom_iter)
            l_context->atom_iter->chain->callback_atom_iter_delete(l_context->atom_iter);
    }

    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(l_context->worker, l_context->ch_uuid);
    if (l_ch) {
        DAP_CHAIN_CH(l_ch)->legacy_sync_context = NULL;
        l_ch->stream->esocket->callbacks.write_finished_callback = NULL;
        l_ch->stream->esocket->callbacks.arg = NULL;
    }

    DAP_DELETE(l_context);
}

static bool s_sync_out_gdb_proc_callback(void *a_arg)
{
    struct legacy_sync_context *l_context = a_arg;
    dap_chain_ch_state_t l_cur_state = l_context->state;
    if (l_cur_state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB && l_cur_state != DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB) {
        // Illegal context
        assert(l_cur_state == DAP_CHAIN_CH_STATE_IDLE);
        goto context_delete;
    }
    dap_list_t *l_list_out = dap_global_db_legacy_list_get_multiple(l_context->db_list, s_update_pack_size);
    if (!l_list_out) {
        dap_chain_ch_sync_request_old_t l_payload = { .node_addr = g_node_addr };
        uint8_t l_type = l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB ? DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END
                                                                            : DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB;
        debug_if(s_debug_legacy, L_INFO, "Out: %s", dap_chain_ch_pkt_type_to_str(l_type));
        dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, l_type,
                                  l_context->request_hdr.net_id, l_context->request_hdr.chain_id, l_context->request_hdr.cell_id,
                                  &l_payload, sizeof(l_payload), DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        if (l_cur_state == DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB) {
            log_it(L_INFO, "Synchronized database: items synchronized %" DAP_UINT64_FORMAT_U " from %zu",
                                             l_context->stats_request_gdbs_processed, l_context->db_list->items_number);
            l_context->state = DAP_CHAIN_CH_STATE_IDLE;
            goto context_delete;
        }
        dap_global_db_legacy_list_rewind(l_context->db_list);
        if (atomic_compare_exchange_strong(&l_context->state, &l_cur_state, DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB_REMOTE))
            return false;
        goto context_delete;
    }

    void *l_data = NULL;
    size_t l_data_size = 0;
    uint8_t l_type = DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB;
    if (l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB) {
        l_type = DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB;
        l_data_size = dap_list_length(l_list_out) * sizeof(dap_chain_ch_update_element_t);
        l_data = DAP_NEW_Z_SIZE(dap_chain_ch_update_element_t, l_data_size);
        if (!l_data) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            l_context->state = DAP_CHAIN_CH_STATE_ERROR;
            goto context_delete;
        }
    }
    bool l_go_wait = false;
    size_t i = 0;
    for (dap_list_t *it = l_list_out; it; it = it->next, i++) {
        dap_global_db_pkt_old_t *l_pkt = it->data;
        if (l_context->db_list->items_rest)
            --l_context->db_list->items_rest;
        dap_hash_t l_pkt_hash;
        dap_hash_fast(l_pkt->data, l_pkt->data_size, &l_pkt_hash);
        if (l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB) {
            dap_chain_ch_update_element_t *l_hashes = l_data;
            l_hashes[i].hash = l_pkt_hash;
            l_hashes[i].size = l_pkt->data_size;
        } else { // l_cur_state == DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB
            dap_chain_ch_hash_item_t *l_hash_item = NULL;
            HASH_FIND(hh, l_context->remote_gdbs, &l_pkt_hash, sizeof(dap_hash_fast_t), l_hash_item);
            if (!l_hash_item) {
                dap_global_db_pkt_old_t *l_pkt_pack = l_data;
                size_t l_cur_size = l_pkt_pack ? l_pkt_pack->data_size : 0;
                if (l_cur_size + sizeof(dap_global_db_pkt_old_t) + l_pkt->data_size >= DAP_CHAIN_PKT_EXPECT_SIZE) {
                    l_context->enqueued_data_size += l_data_size;
                    if (!l_go_wait && l_context->enqueued_data_size > DAP_EVENTS_SOCKET_BUF_SIZE / 2) {
                        l_context->prev_state = l_cur_state;
                        l_go_wait = true;
                    }
                    dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, l_type,
                                              l_context->request_hdr.net_id, l_context->request_hdr.chain_id, l_context->request_hdr.cell_id,
                                              l_data, l_data_size, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
                    debug_if(s_debug_legacy, L_INFO, "Send one global_db packet len=%zu (rest=%zu/%zu items)", l_data_size,
                                                l_context->db_list->items_rest, l_context->db_list->items_number);
                    l_context->last_activity = dap_time_now();
                    DAP_DEL_Z(l_pkt_pack);
                    l_cur_size = 0;
                }
                l_pkt_pack = dap_global_db_pkt_pack_old(l_pkt_pack, l_pkt);
                if (!l_pkt_pack || l_cur_size == l_pkt_pack->data_size) {
                    log_it(L_CRITICAL, "%s", g_error_memory_alloc);
                    l_context->state = DAP_CHAIN_CH_STATE_ERROR;
                    goto context_delete;
                }
                l_context->stats_request_gdbs_processed++;
                l_data = l_pkt_pack;
                l_data_size = sizeof(dap_global_db_pkt_old_t) + l_pkt_pack->data_size;
            } /* else       // Over-extended debug
                debug_if(s_debug_legacy, L_DEBUG, "Skip GDB hash %s because its already present in remote GDB hash table",
                                                dap_hash_fast_to_str_static(&l_pkt_hash));
            */
        }
    }
    dap_list_free_full(l_list_out, NULL);

    if (l_data && l_data_size) {
        dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, l_type,
                                  l_context->request_hdr.net_id, l_context->request_hdr.chain_id, l_context->request_hdr.cell_id,
                                  l_data, l_data_size, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        if (l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB)
            debug_if(s_debug_legacy, L_INFO, "Out: %s, %zu records", dap_chain_ch_pkt_type_to_str(l_type), i);
        else
            debug_if(s_debug_legacy, L_INFO, "Send one global_db packet len=%zu (rest=%zu/%zu items)", l_data_size,
                                            l_context->db_list->items_rest, l_context->db_list->items_number);
        l_context->last_activity = dap_time_now();
        DAP_DELETE(l_data);
    } else if (l_context->last_activity + 3 < dap_time_now()) {
        l_context->last_activity = dap_time_now();
        debug_if(s_debug_more, L_INFO, "Send one GlobalDB no freeze packet");
        dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB_NO_FREEZE,
                                             l_context->request_hdr.net_id, l_context->request_hdr.chain_id,
                                             l_context->request_hdr.cell_id, NULL, 0, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
    }
    if (!l_go_wait)
        return true;
    if (atomic_compare_exchange_strong(&l_context->state, &l_cur_state, DAP_CHAIN_CH_STATE_WAITING))
        return false;
context_delete:
    dap_worker_exec_callback_on(l_context->worker->worker, s_legacy_sync_context_delete, l_context);
    return false;
}

struct record_processing_args {
    dap_stream_worker_t *worker;
    dap_stream_ch_uuid_t uuid;
    dap_chain_ch_pkt_hdr_t hdr;
    dap_global_db_pkt_old_t *pkt;
    bool new;
};

static bool s_gdb_in_pkt_proc_callback(void *a_arg)
{
    struct record_processing_args *l_args = a_arg;
    size_t l_objs_count = 0;
    dap_store_obj_t *l_objs = dap_global_db_pkt_deserialize_old(l_args->pkt, &l_objs_count);
    DAP_DELETE(l_args->pkt);
    if (!l_objs || !l_objs_count) {
        log_it(L_WARNING, "Deserialization of legacy global DB packet failed");
        DAP_DELETE(l_args);
        return false;
    }
    bool l_success = false;
    dap_stream_node_addr_t l_blank_addr = { .uint64 = 0 };
    for (uint32_t i = 0; i < l_objs_count; i++)
        if (!(l_success = dap_global_db_ch_check_store_obj(l_objs + i, &l_blank_addr)))
            break;
    if (l_args->new && l_objs_count == 1)
        l_objs[0].flags |= DAP_GLOBAL_DB_RECORD_NEW;
    if (l_success && dap_global_db_set_raw_sync(l_objs, l_objs_count)) {
        const char *l_err_str = s_error_type_to_string(DAP_CHAIN_CH_ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED);
        dap_chain_ch_pkt_t *l_chain_pkt = dap_chain_ch_pkt_new(l_args->hdr.net_id, l_args->hdr.chain_id, l_args->hdr.cell_id,
                                                               l_err_str, strlen(l_err_str), DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        dap_stream_ch_pkt_write_mt(l_args->worker, l_args->uuid, DAP_CHAIN_CH_PKT_TYPE_ERROR, l_chain_pkt, dap_chain_ch_pkt_get_size(l_chain_pkt));
        DAP_DELETE(l_chain_pkt);
    }
    dap_store_obj_free(l_objs, l_objs_count);
    DAP_DELETE(l_args);
    return false;
}

static bool s_sync_out_chains_proc_callback(void *a_arg)
{
    struct legacy_sync_context *l_context = a_arg;
    dap_chain_ch_state_t l_cur_state = l_context->state;
    if (l_cur_state != DAP_CHAIN_CH_STATE_UPDATE_CHAINS && l_cur_state != DAP_CHAIN_CH_STATE_SYNC_CHAINS) {
        // Illegal context
        assert(l_cur_state == DAP_CHAIN_CH_STATE_IDLE);
        goto context_delete;
    }

    dap_chain_ch_update_element_t *l_hashes = NULL;
    if (l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_CHAINS) {
        l_hashes = DAP_NEW_Z_SIZE(dap_chain_ch_update_element_t, s_update_pack_size * sizeof(dap_chain_ch_update_element_t));
        if (!l_hashes) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            l_context->state = DAP_CHAIN_CH_STATE_ERROR;
            goto context_delete;
        }
    }
    size_t l_data_size = 0;
    bool l_chain_end = false, l_go_wait = false;
    for (uint_fast16_t i = 0; i < s_update_pack_size; i++) {
        if (!l_context->atom_iter->cur || !l_context->atom_iter->cur_size) {
            l_chain_end = true;
            break;
        }
        if (l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_CHAINS) {
            l_hashes[i].hash = *l_context->atom_iter->cur_hash;
            l_hashes[i].size = l_context->atom_iter->cur_size;
            l_data_size += sizeof(dap_chain_ch_update_element_t);
        } else { // l_cur_state == DAP_CHAIN_CH_STATE_SYNC_CHAINS
            dap_chain_ch_hash_item_t *l_hash_item = NULL;
            HASH_FIND(hh, l_context->remote_atoms, l_context->atom_iter->cur_hash, sizeof(dap_hash_fast_t), l_hash_item);
            if (!l_hash_item) {
                l_context->enqueued_data_size += l_context->atom_iter->cur_size;
                if (l_context->enqueued_data_size > DAP_EVENTS_SOCKET_BUF_SIZE / 2) {
                    l_context->prev_state = l_cur_state;
                    l_go_wait = true;
                }
                dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, DAP_CHAIN_CH_PKT_TYPE_CHAIN_OLD,
                                          l_context->request_hdr.net_id, l_context->request_hdr.chain_id, l_context->request_hdr.cell_id,
                                          l_context->atom_iter->cur, l_context->atom_iter->cur_size, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
                debug_if(s_debug_legacy, L_INFO, "Out CHAIN pkt: atom hash %s (size %zd)", dap_hash_fast_to_str_static(l_context->atom_iter->cur_hash),
                                                                                           l_context->atom_iter->cur_size);
                l_context->last_activity = dap_time_now();
                l_context->stats_request_atoms_processed++;
            } /* else       // Over-extended debug
                debug_if(s_debug_legacy, L_DEBUG, "Skip atom hash %s because its already present in remote atoms hash table",
                                                dap_hash_fast_to_str_static(&l_context->atom_iter->cur_hash));
            */
        }
        l_context->atom_iter->chain->callback_atom_iter_get(l_context->atom_iter, DAP_CHAIN_ITER_OP_NEXT, NULL);
        if (l_go_wait)
            break;
    }

    if (l_hashes) {
        dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS,
                                  l_context->request_hdr.net_id, l_context->request_hdr.chain_id, l_context->request_hdr.cell_id,
                                  l_hashes, l_data_size, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        debug_if(s_debug_legacy, L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS, %zu records", l_data_size / sizeof(dap_chain_ch_update_element_t));
        DAP_DELETE(l_hashes);
    } else if (l_context->last_activity + 3 < dap_time_now()) {
        l_context->last_activity = dap_time_now();
        debug_if(s_debug_more, L_INFO, "Send one chain no freeze packet");
        dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, DAP_CHAIN_CH_PKT_TYPE_CHAINS_NO_FREEZE,
                                        l_context->request_hdr.net_id, l_context->request_hdr.chain_id,
                                        l_context->request_hdr.cell_id, NULL, 0, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
    }

    if (l_chain_end) {
        dap_chain_ch_sync_request_old_t l_payload = { .node_addr = g_node_addr };
        uint8_t l_type = l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_CHAINS ? DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END
                                                                         : DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS;
        debug_if(s_debug_legacy, L_INFO, "Out: %s", dap_chain_ch_pkt_type_to_str(l_type));
        dap_chain_ch_pkt_write_mt(l_context->worker, l_context->ch_uuid, l_type,
                                  l_context->request_hdr.net_id, l_context->request_hdr.chain_id, l_context->request_hdr.cell_id,
                                  &l_payload, sizeof(l_payload), DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        debug_if(l_cur_state == DAP_CHAIN_CH_STATE_UPDATE_CHAINS, L_INFO,
                    "Synchronized chain: items synchronized %" DAP_UINT64_FORMAT_U, l_context->stats_request_atoms_processed);
        if (l_cur_state == DAP_CHAIN_CH_STATE_SYNC_CHAINS) {
            l_context->state = DAP_CHAIN_CH_STATE_IDLE;
            goto context_delete;
        }
        l_context->atom_iter->chain->callback_atom_iter_get(l_context->atom_iter, DAP_CHAIN_ITER_OP_FIRST, NULL);
        if (atomic_compare_exchange_strong(&l_context->state, &l_cur_state, DAP_CHAIN_CH_STATE_SYNC_CHAINS_REMOTE))
            return false;
        goto context_delete;
    }
    if (!l_go_wait)
        return true;
    if (atomic_compare_exchange_strong(&l_context->state, &l_cur_state, DAP_CHAIN_CH_STATE_WAITING))
        return false;
context_delete:
    dap_worker_exec_callback_on(l_context->worker->worker, s_legacy_sync_context_delete, l_context);
    return false;
}

// *** End of legacy support code *** //


struct atom_processing_args {
    dap_stream_node_addr_t addr;
    bool ack_req;
    byte_t data[];
};

/**
 * @brief s_sync_in_chains_callback
 * @param a_thread dap_proc_thread_t
 * @param a_arg void
 * @return
 */
static bool s_sync_in_chains_callback(void *a_arg)
{
    assert(a_arg);
    struct atom_processing_args *l_args = a_arg;
    dap_chain_ch_pkt_t *l_chain_pkt = (dap_chain_ch_pkt_t *)l_args->data;
    if (!l_chain_pkt->hdr.data_size) {
        log_it(L_CRITICAL, "Proc thread received corrupted chain packet!");
        return false;
    }
    dap_chain_atom_ptr_t l_atom = (dap_chain_atom_ptr_t)l_chain_pkt->data;
    uint64_t l_atom_size = l_chain_pkt->hdr.data_size;
    dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
    if (!l_chain) {
        debug_if(s_debug_more, L_WARNING, "No chain found for DAP_CHAIN_CH_PKT_TYPE_CHAIN");
        DAP_DELETE(l_args);
        return false;
    }
    char *l_atom_hash_str = NULL;
    if (s_debug_more)
        dap_get_data_hash_str_static(l_atom, l_atom_size, l_atom_hash_str);
    dap_chain_atom_verify_res_t l_atom_add_res = l_chain->callback_atom_add(l_chain, l_atom, l_atom_size);
    bool l_ack_send = false;
    switch (l_atom_add_res) {
    case ATOM_PASS:
        debug_if(s_debug_more, L_WARNING, "Atom with hash %s for %s:%s not accepted (code ATOM_PASS, already present)",
                                                l_atom_hash_str, l_chain->net_name, l_chain->name);
        l_ack_send = true;
        break;
    case ATOM_MOVE_TO_THRESHOLD:
        debug_if(s_debug_more, L_INFO, "Thresholded atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
        break;
    case ATOM_ACCEPT:
        debug_if(s_debug_more, L_INFO, "Accepted atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
        if (dap_chain_atom_save(l_chain->cells, l_atom, l_atom_size, NULL) < 0)
            log_it(L_ERROR, "Can't save atom %s to the file", l_atom_hash_str);
        else
            l_ack_send = true;
        break;
    case ATOM_REJECT: {
        debug_if(s_debug_more, L_WARNING, "Atom with hash %s for %s:%s rejected", l_atom_hash_str, l_chain->net_name, l_chain->name);
        break;
    }
    default:
        log_it(L_CRITICAL, "Wtf is this ret code? %d", l_atom_add_res);
        break;
    }
    if (l_ack_send && l_args->ack_req) {
        uint64_t l_ack_num = (l_chain_pkt->hdr.num_hi << 16) | l_chain_pkt->hdr.num_lo;
        dap_chain_ch_pkt_t *l_pkt = dap_chain_ch_pkt_new(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                         &l_ack_num, sizeof(uint64_t), DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        dap_stream_ch_pkt_send_by_addr(&l_args->addr, DAP_CHAIN_CH_ID, DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK, l_pkt, dap_chain_ch_pkt_get_size(l_pkt));
        DAP_DELETE(l_pkt);
        debug_if(s_debug_more, L_DEBUG, "Out: CHAIN_ACK %s for net %s to destination " NODE_ADDR_FP_STR " with num %" DAP_UINT64_FORMAT_U,
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(l_args->addr),
                                l_ack_num);
    }
    DAP_DELETE(l_args);
    return false;
}

static void s_gossip_payload_callback(void *a_payload, size_t a_payload_size, dap_stream_node_addr_t a_sender_addr)
{
    assert(a_payload && a_payload_size);
    dap_chain_ch_pkt_t *l_chain_pkt = a_payload;
    if (a_payload_size <= sizeof(dap_chain_ch_pkt_t) ||
            a_payload_size != sizeof(dap_chain_ch_pkt_t) + l_chain_pkt->hdr.data_size) {
        log_it(L_WARNING, "Incorrect chain GOSSIP packet size");
        return;
    }
    struct atom_processing_args *l_args = DAP_NEW_SIZE(struct atom_processing_args, a_payload_size + sizeof(struct atom_processing_args));
    if (!l_args) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return;
    }
    l_args->addr = a_sender_addr;
    l_args->ack_req = false;
    memcpy(l_args->data, a_payload, a_payload_size);
    dap_proc_thread_callback_add(NULL, s_sync_in_chains_callback, l_args);
}

void dap_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id, dap_chain_ch_error_type_t a_error)
{
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    dap_return_if_fail(l_ch_chain);
    const char *l_err_str = s_error_type_to_string(a_error);
    dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_ERROR, a_net_id, a_chain_id, a_cell_id, l_err_str, strlen(l_err_str) + 1, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
    s_ch_chain_go_idle(l_ch_chain);
}

/**
 * @brief s_stream_ch_packet_in
 * @param a_ch
 * @param a_arg
 */
static bool s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    if (!l_ch_chain || l_ch_chain->_inheritor != a_ch) {
        log_it(L_ERROR, "No chain in channel, returning");
        return false;
    }
    dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    if (l_ch_pkt->hdr.data_size < sizeof(dap_chain_ch_pkt_t)) {
        log_it(L_ERROR, "Corrupted packet: too small size %u, smaller then header size %zu",
                                            l_ch_pkt->hdr.data_size, sizeof(dap_chain_ch_pkt_t));
        return false;
    }

    dap_chain_ch_pkt_t *l_chain_pkt = (dap_chain_ch_pkt_t *)l_ch_pkt->data;
    size_t l_chain_pkt_data_size = l_ch_pkt->hdr.data_size - sizeof(l_chain_pkt->hdr);

    if (!l_chain_pkt->hdr.version || l_chain_pkt->hdr.version > DAP_CHAIN_CH_PKT_VERSION_CURRENT) {
        debug_if(s_debug_more, L_ATT, "Unsupported protocol version %d, current version %d",
                 l_chain_pkt->hdr.version, DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        return false;
    }
    if (l_chain_pkt->hdr.version > DAP_CHAIN_CH_PKT_VERSION_LEGACY &&
                l_chain_pkt_data_size != l_chain_pkt->hdr.data_size) {
        log_it(L_WARNING, "Incorrect chain packet size %zu, expected %u",
                            l_chain_pkt_data_size, l_chain_pkt->hdr.data_size);
        return false;
    }

    switch (l_ch_pkt->hdr.type) {

    /* *** New synchronization protocol *** */

    case DAP_CHAIN_CH_PKT_TYPE_ERROR: {
        if (!l_chain_pkt_data_size || l_chain_pkt->data[l_chain_pkt_data_size - 1] != 0) {
            log_it(L_WARNING, "Incorrect format with data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            return false;
        }
        log_it(L_WARNING, "In: from remote addr %s chain id 0x%016" DAP_UINT64_FORMAT_x " got error on his side: '%s'",
               DAP_STREAM_CH(l_ch_chain)->stream->esocket->remote_addr_str,
               l_chain_pkt->hdr.chain_id.uint64, (char *)l_chain_pkt->data);
        s_ch_chain_go_idle(l_ch_chain);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN: {
        if (!l_chain_pkt_data_size) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_cluster_t *l_cluster = dap_cluster_find(dap_guuid_compose(l_chain_pkt->hdr.net_id.uint64, 0));
        if (!l_cluster) {
            log_it(L_WARNING, "Can't find cluster with ID 0x%" DAP_UINT64_FORMAT_X, l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_cluster_member_t *l_check = dap_cluster_member_find_unsafe(l_cluster, &a_ch->stream->node);
        if (!l_check) {
            log_it(L_WARNING, "Node with addr "NODE_ADDR_FP_STR" isn't a member of cluster %s",
                                        NODE_ADDR_FP_ARGS_S(a_ch->stream->node), l_cluster->mnemonim);
            return false;
        }
        struct atom_processing_args *l_args = DAP_NEW_SIZE(struct atom_processing_args, l_ch_pkt->hdr.data_size + sizeof(struct atom_processing_args));
        if (!l_args) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            break;
        }
        l_args->addr = a_ch->stream->node;
        l_args->ack_req = true;
        memcpy(l_args->data, l_chain_pkt, l_ch_pkt->hdr.data_size);
        if (s_debug_more) {
            char *l_atom_hash_str;
            dap_get_data_hash_str_static(l_chain_pkt->data, l_chain_pkt_data_size, l_atom_hash_str);
            log_it(L_INFO, "In: CHAIN pkt: atom hash %s (size %zd)", l_atom_hash_str, l_chain_pkt_data_size);
        }
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_in_chains_callback, l_args);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_sync_request_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_sync_request_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_chain_ch_sync_request_t *l_request = (dap_chain_ch_sync_request_t *)l_chain_pkt->data;
        if (s_debug_more)
            log_it(L_INFO, "In: CHAIN_REQ pkt: net 0x%016" DAP_UINT64_FORMAT_x " chain 0x%016" DAP_UINT64_FORMAT_x
                            " cell 0x%016" DAP_UINT64_FORMAT_x ", hash from %s, num from %" DAP_UINT64_FORMAT_U,
                            l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            dap_hash_fast_to_str_static(&l_request->hash_from), l_request->num_from);
        if (l_ch_chain->sync_context || l_ch_chain->legacy_sync_context) {
            log_it(L_WARNING, "Can't process CHAIN_REQ request cause already busy with synchronization");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
            break;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        if (!l_chain || l_chain->callback_load_from_gdb) {
            log_it(L_WARNING, "Not found valid chain with id 0x%016" DAP_UINT64_FORMAT_x " and net id 0x%016" DAP_UINT64_FORMAT_x,
                                                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND);
            break;
        }
        if (!dap_link_manager_get_net_condition(l_chain_pkt->hdr.net_id.uint64)) {
            log_it(L_WARNING, "Net id 0x%016" DAP_UINT64_FORMAT_x " is offline", l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE);
            break;
        }
        bool l_sync_from_begin = dap_hash_fast_is_blank(&l_request->hash_from);
        dap_chain_atom_iter_t *l_iter = l_chain->callback_atom_iter_create(l_chain, l_chain_pkt->hdr.cell_id, l_sync_from_begin
                                                                           ? NULL : &l_request->hash_from);
        if (!l_iter) {
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        if (l_sync_from_begin)
            l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, NULL);
        bool l_missed_hash = false;
        uint64_t l_last_num = l_chain->callback_count_atom(l_chain);
        if (l_iter->cur) {
            if (l_sync_from_begin ||
                    (l_request->num_from == l_iter->cur_num &&
                    l_last_num > l_iter->cur_num)) {
                dap_chain_ch_summary_t l_sum = { .num_cur = l_iter->cur_num, .num_last = l_last_num };
                dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY,
                                                l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                                l_chain_pkt->hdr.cell_id, &l_sum, sizeof(l_sum),
                                                DAP_CHAIN_CH_PKT_VERSION_CURRENT);
                debug_if(s_debug_more, L_DEBUG, "Out: CHAIN_SUMMARY %s for net %s to destination " NODE_ADDR_FP_STR,
                                                        l_chain->name, l_chain->net_name, NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
                struct sync_context *l_context = DAP_NEW_Z(struct sync_context);
                l_context->addr = a_ch->stream->node;
                l_context->iter = l_iter;
                l_context->net_id = l_chain_pkt->hdr.net_id;
                l_context->chain_id = l_chain_pkt->hdr.chain_id;
                l_context->cell_id = l_chain_pkt->hdr.cell_id;
                l_context->num_last = l_sum.num_last;
                l_context->last_activity = dap_time_now();
                atomic_store_explicit(&l_context->state, SYNC_STATE_READY, memory_order_relaxed);
                atomic_store(&l_context->allowed_num, l_sum.num_cur + s_sync_ack_window_size);
                dap_stream_ch_uuid_t *l_uuid = DAP_DUP(&a_ch->uuid);
                if (!l_uuid) {
                    log_it(L_CRITICAL, "%s", g_error_memory_alloc);
                    DAP_DELETE(l_context);
                    break;
                }
                l_ch_chain->sync_context = l_context;
                dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_chain_iter_callback, l_context);
                l_ch_chain->sync_timer = dap_timerfd_start_on_worker(a_ch->stream_worker->worker, 1000, s_sync_timer_callback, l_uuid);
                break;
            }
            if (l_request->num_from < l_iter->cur_num || l_last_num > l_iter->cur_num)
                l_missed_hash = true;
        } else if (!l_sync_from_begin && l_last_num >= l_request->num_from) {
            l_missed_hash = true;
            debug_if(s_debug_more, L_WARNING, "Requested atom with hash %s not found", dap_hash_fast_to_str_static(&l_request->hash_from));
        }
        if (l_missed_hash) {
            l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_LAST, NULL);
            dap_chain_ch_miss_info_t l_miss_info = { .missed_hash = l_request->hash_from,
                                                     .last_hash = *l_iter->cur_hash,
                                                     .last_num = l_iter->cur_num };
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS,
                                          l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                          l_chain_pkt->hdr.cell_id, &l_miss_info, sizeof(l_miss_info),
                                          DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            if (s_debug_more) {
                char l_last_hash_str[DAP_HASH_FAST_STR_SIZE];
                dap_hash_fast_to_str(&l_miss_info.last_hash, l_last_hash_str, DAP_HASH_FAST_STR_SIZE);
                log_it(L_INFO, "Out: CHAIN_MISS %s for net %s to source " NODE_ADDR_FP_STR
                                             " with hash missed %s, hash last %s and num last %" DAP_UINT64_FORMAT_U,
                        l_chain ? l_chain->name : "(null)",
                                    l_chain ? l_chain->net_name : "(null)",
                                                    NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                        dap_hash_fast_to_str_static(&l_miss_info.missed_hash),
                        l_last_hash_str,
                        l_miss_info.last_num);
            }
        } else {
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN,
                                          l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                          l_chain_pkt->hdr.cell_id, NULL, 0,
                                          DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            debug_if(s_debug_more, L_DEBUG, "Out: SYNCED_CHAIN %s for net %s to destination " NODE_ADDR_FP_STR,
                                    l_chain ? l_chain->name : "(null)",
                                                l_chain ? l_chain->net_name : "(null)",
                                                                NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
        }
        l_chain->callback_atom_iter_delete(l_iter);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_summary_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_summary_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        dap_chain_ch_summary_t *l_sum = (dap_chain_ch_summary_t *)l_chain_pkt->data;
        debug_if(s_debug_more, L_DEBUG, "In: CHAIN_SUMMARY of %s for net %s from source " NODE_ADDR_FP_STR
                                            " with %" DAP_UINT64_FORMAT_U " atoms to sync from %" DAP_UINT64_FORMAT_U " to %" DAP_UINT64_FORMAT_U,
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                                l_sum->num_last - l_sum->num_cur, l_sum->num_cur, l_sum->num_last);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK: {
        if (l_chain_pkt_data_size != sizeof(uint64_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(uint64_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        uint64_t l_ack_num = *(uint64_t *)l_chain_pkt->data;
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        debug_if(s_debug_more, L_DEBUG, "In: CHAIN_ACK %s for net %s from source " NODE_ADDR_FP_STR " with num %" DAP_UINT64_FORMAT_U,
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                                l_ack_num);
        struct sync_context *l_context = l_ch_chain->sync_context;
        if (!l_context) {
            log_it(L_WARNING, "CHAIN_ACK: No active sync context");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        if (l_context->num_last == l_ack_num) {
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN,
                                                l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                                l_chain_pkt->hdr.cell_id, NULL, 0,
                                                DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            s_ch_chain_go_idle(l_ch_chain);
            break;
        }
        l_context->last_activity = dap_time_now();
        if (atomic_load_explicit(&l_context->state, memory_order_relaxed) == SYNC_STATE_OVER)
            break;
        atomic_store_explicit(&l_context->allowed_num,
                              dap_min(l_ack_num + s_sync_ack_window_size, l_context->num_last),
                              memory_order_release);
        if (atomic_exchange(&l_context->state, SYNC_STATE_READY) == SYNC_STATE_IDLE)
            dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_chain_iter_callback, l_context);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN: {
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        log_it(L_INFO, "In: SYNCED_CHAIN %s for net %s from source " NODE_ADDR_FP_STR,
                    l_chain ? l_chain->name : "(null)",
                                l_chain ? l_chain->net_name : "(null)",
                                                NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_miss_info_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_miss_info_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        dap_chain_ch_miss_info_t *l_miss_info = (dap_chain_ch_miss_info_t *)l_chain_pkt->data;
        if (s_debug_more) {
            char l_last_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_miss_info->last_hash, l_last_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_INFO, "In: CHAIN_MISS %s for net %s from source " NODE_ADDR_FP_STR
                                         " with hash missed %s, hash last %s and num last %" DAP_UINT64_FORMAT_U,
                    l_chain ? l_chain->name : "(null)",
                                l_chain ? l_chain->net_name : "(null)",
                                                NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                    dap_hash_fast_to_str_static(&l_miss_info->missed_hash),
                    l_last_hash_str,
                    l_miss_info->last_num);
        }
        // Will be processed upper in net packet notifier callback
    } break;

    default:
        dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                            DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE);
        return false;

//    }
//}

    /* *** Legacy *** */

    /// --- GDB update ---
    // Request for gdbs list update
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_REQ: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_sync_request_old_t)) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        dap_cluster_t *l_net_cluster = dap_cluster_find(dap_guuid_compose(l_chain_pkt->hdr.net_id.uint64, 0));
        if (!l_net_cluster || !l_net_cluster->mnemonim) {
            log_it(L_WARNING, "Net id 0x%016" DAP_UINT64_FORMAT_x " not found", l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_NET_INVALID_ID);
            break;
        }
        if (!dap_link_manager_get_net_condition(l_chain_pkt->hdr.net_id.uint64)) {
            log_it(L_WARNING, "Net id 0x%016" DAP_UINT64_FORMAT_x " is offline", l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE);
            break;
        }
        if (l_ch_chain->sync_context || l_ch_chain->legacy_sync_context) {
            log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB request because its already busy with syncronization");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
            break;
        }
        dap_global_db_legacy_list_t *l_db_list = dap_global_db_legacy_list_start(l_net_cluster->mnemonim);
        if (!l_db_list) {
            log_it(L_ERROR, "Can't create legacy DB list");
            dap_global_db_legacy_list_delete(l_db_list);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                            DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        struct legacy_sync_context *l_context = s_legacy_sync_context_create(l_chain_pkt, a_ch);
        if (!l_context) {
            log_it(L_ERROR, "Can't create sychronization context");
            dap_global_db_legacy_list_delete(l_db_list);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                            DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        l_context->is_type_of_gdb = true;
        l_context->db_list = l_db_list;
        l_context->remote_addr = *(dap_stream_node_addr_t *)l_chain_pkt->data;
        l_context->request_hdr = l_chain_pkt->hdr;
        l_ch_chain->legacy_sync_context = l_context;
        l_context->state = DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB;
        debug_if(s_debug_legacy, L_DEBUG, "Sync out gdb proc, requested %" DAP_UINT64_FORMAT_U " records from address " NODE_ADDR_FP_STR " (unverified)",
                                                l_db_list->items_number, NODE_ADDR_FP_ARGS_S(l_context->remote_addr));
        log_it(L_INFO, "In: UPDATE_GLOBAL_DB_REQ pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                        l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
        debug_if(s_debug_legacy, L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START");
        dap_chain_ch_pkt_write_unsafe(DAP_STREAM_CH(l_ch_chain), DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START,
                                        l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                        l_chain_pkt->hdr.cell_id, &g_node_addr, sizeof(dap_chain_node_addr_t),
                                        DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_gdb_proc_callback, l_context);
    } break;

    // If requested - begin to recieve record's hashes
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START: {
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE) {
            log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_START packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In: UPDATE_GLOBAL_DB_START pkt net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                            l_context->request_hdr.net_id.uint64, l_context->request_hdr.chain_id.uint64, l_context->request_hdr.cell_id.uint64);
    } break;

    // Response with gdb element hashes and sizes
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB: {
        if (l_chain_pkt_data_size > sizeof(dap_chain_ch_update_element_t) * s_update_pack_size) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        debug_if(s_debug_legacy, L_INFO, "In: UPDATE_GLOBAL_DB pkt data_size=%zu", l_chain_pkt_data_size);
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE) {
            log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        l_context->last_activity = dap_time_now();

        for (dap_chain_ch_update_element_t *l_element = (dap_chain_ch_update_element_t *)l_chain_pkt->data;
                (size_t)((byte_t *)(l_element + 1) - l_chain_pkt->data) <= l_chain_pkt_data_size;
                l_element++) {
            dap_chain_ch_hash_item_t * l_hash_item = NULL;
            unsigned l_hash_item_hashv;
            HASH_VALUE(&l_element->hash, sizeof(l_element->hash), l_hash_item_hashv);
            HASH_FIND_BYHASHVALUE(hh, l_context->remote_gdbs, &l_element->hash, sizeof(l_element->hash),
                                  l_hash_item_hashv, l_hash_item);
            if (!l_hash_item) {
                l_hash_item = DAP_NEW_Z(dap_chain_ch_hash_item_t);
                if (!l_hash_item) {
                    log_it(L_CRITICAL, "%s", g_error_memory_alloc);
                    dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                            DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
                    break;
                }
                l_hash_item->hash = l_element->hash;
                l_hash_item->size = l_element->size;
                HASH_ADD_BYHASHVALUE(hh, l_context->remote_gdbs, hash, sizeof(l_hash_item->hash),
                                     l_hash_item_hashv, l_hash_item);
                //debug_if(s_debug_legacy, L_DEBUG, "In: Updated remote hash GDB list with %s", dap_chain_hash_fast_to_str_static(&l_hash_item->hash));
            }
        }
    } break;

    // End of response with GlobalDB hashes
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_sync_request_old_t)) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE) {
            log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_END packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In: UPDATE_GLOBAL_DB_END pkt with total count %d hashes", HASH_COUNT(l_context->remote_gdbs));
        l_context->state = DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB;
        debug_if(s_debug_legacy, L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB");
        dap_chain_ch_pkt_write_unsafe(DAP_STREAM_CH(l_ch_chain), DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB,
                l_context->request_hdr.net_id, l_context->request_hdr.chain_id,
                l_context->request_hdr.cell_id, &g_node_addr, sizeof(dap_chain_node_addr_t),
                DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_gdb_proc_callback, l_context);
    } break;

    // first packet of data with source node address
    case DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_node_addr_t)) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB_REMOTE) {
            log_it(L_WARNING, "Can't process FIRST_GLOBAL_DB packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In: FIRST_GLOBAL_DB data_size=%zu net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x
                        " from address "NODE_ADDR_FP_STR "(unverified)", l_chain_pkt_data_size, l_context->request_hdr.net_id.uint64,
                        l_context->request_hdr.chain_id.uint64, l_context->request_hdr.cell_id.uint64, NODE_ADDR_FP_ARGS_S(l_context->remote_addr));
    } break;

    // Dummy packet for freeze detection
    case DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB_NO_FREEZE: {
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB_REMOTE) {
            log_it(L_WARNING, "Can't process GLOBAL_DB_NO_FREEZE packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_DEBUG, "Global DB no freeze packet detected");
        l_context->last_activity = dap_time_now();
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB: {
        dap_global_db_pkt_old_t *l_pkt = (dap_global_db_pkt_old_t *)l_chain_pkt->data;
        if (l_chain_pkt_data_size < sizeof(dap_global_db_pkt_old_t) ||
                l_chain_pkt_data_size != sizeof(*l_pkt) + l_pkt->data_size) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (l_context && l_context->state != DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB_REMOTE) {
            log_it(L_WARNING, "Can't process GLOBAL_DB packet cause synchronization sequence violation");
            break;
        }
        if (l_context)
            l_context->last_activity = dap_time_now();
        debug_if(s_debug_legacy, L_INFO, "In: GLOBAL_DB_OLD data_size=%zu", l_chain_pkt_data_size);
        // get records and save it to global_db
        struct record_processing_args *l_args;
        DAP_NEW_Z_RET_VAL(l_args, struct record_processing_args, true, NULL);
        l_args->pkt = DAP_DUP_SIZE(l_pkt, l_chain_pkt_data_size);
        if (!l_args->pkt) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        l_args->worker = a_ch->stream_worker;
        l_args->uuid = a_ch->uuid;
        l_args->hdr = l_chain_pkt->hdr;
        l_args->new = !l_context && l_pkt->obj_count == 1;
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_gdb_in_pkt_proc_callback, l_args);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB: {
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB_REMOTE) {
            log_it(L_WARNING, "Can't process SYNCED_GLOBAL_DB packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In:  SYNCED_GLOBAL_DB: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                        l_context->request_hdr.net_id.uint64, l_context->request_hdr.chain_id.uint64, l_context->request_hdr.cell_id.uint64);
        // we haven't node client waitng, so reply to other side
        l_context->state = DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE;
        dap_chain_ch_sync_request_old_t l_request = { .node_addr = g_node_addr };
        debug_if(s_debug_legacy, L_INFO, "Out: UPDATE_GLOBAL_DB_REQ pkt");
        dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_REQ, l_context->request_hdr.net_id,
                                      l_context->request_hdr.chain_id, l_context->request_hdr.cell_id, &l_request, sizeof(l_request),
                                      DAP_CHAIN_CH_PKT_VERSION_LEGACY);
    } break;

    /// --- Chains update ---
    // Request for atoms list update
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_REQ: {
        if (l_chain_pkt_data_size) { // Expected packet with no data
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        if (!dap_link_manager_get_net_condition(l_chain_pkt->hdr.net_id.uint64)) {
            log_it(L_WARNING, "Net id 0x%016" DAP_UINT64_FORMAT_x " is offline", l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE);
            break;
        }
        if (l_ch_chain->sync_context || l_ch_chain->legacy_sync_context) {
            log_it(L_WARNING, "Can't process UPDATE_CHAINS request because its already busy with syncronization");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
            break;
        }
        dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        if (!l_chain) {
            log_it(L_WARNING, "Requested chain not found");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND);
            break;
        }
        dap_chain_atom_iter_t *l_atom_iter = l_chain->callback_atom_iter_create(l_chain, l_chain_pkt->hdr.cell_id, NULL);
        if (!l_atom_iter) {
            log_it(L_ERROR, "Can't create legacy atom iterator");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                            DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        struct legacy_sync_context *l_context = s_legacy_sync_context_create(l_chain_pkt, a_ch);
        if (!l_context) {
            log_it(L_ERROR, "Can't create sychronization context");
            l_chain->callback_atom_iter_delete(l_atom_iter);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                            DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        l_chain->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_FIRST, NULL);
        l_context->atom_iter = l_atom_iter;
        l_context->remote_addr = *(dap_stream_node_addr_t *)l_chain_pkt->data;
        l_context->request_hdr = l_chain_pkt->hdr;
        l_ch_chain->legacy_sync_context = l_context;
        l_context->state = DAP_CHAIN_CH_STATE_UPDATE_CHAINS;
        debug_if(s_debug_legacy, L_DEBUG, "Sync out chains proc, requested chain %s for net %s from address " NODE_ADDR_FP_STR " (unverified)",
                                                l_chain->name, l_chain->net_name, NODE_ADDR_FP_ARGS_S(l_context->remote_addr));
        debug_if(s_debug_legacy, L_INFO, "In: UPDATE_CHAINS_REQ pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                            l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
        debug_if(s_debug_legacy, L_INFO, "Out: UPDATE_CHAINS_START pkt: net %s chain %s cell 0x%016"DAP_UINT64_FORMAT_X, l_chain->name,
                                            l_chain->net_name, l_chain_pkt->hdr.cell_id.uint64);
        dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_START,
                                            l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                            l_chain_pkt->hdr.cell_id, NULL, 0,
                                            DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_chains_proc_callback, l_context);
    } break;

    // If requested - begin to send atom hashes
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_START: {
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE) {
            log_it(L_WARNING, "Can't process UPDATE_CHAINS_START packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In: UPDATE_CHAINS_START pkt net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                            l_context->request_hdr.net_id.uint64, l_context->request_hdr.chain_id.uint64, l_context->request_hdr.cell_id.uint64);
    } break;

    // Response with atom hashes and sizes
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS: {
        if (l_chain_pkt_data_size > sizeof(dap_chain_ch_update_element_t) * s_update_pack_size) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        debug_if(s_debug_legacy, L_INFO, "In: UPDATE_CHAINS pkt data_size=%zu", l_chain_pkt_data_size);
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE) {
            log_it(L_WARNING, "Can't process UPDATE_CHAINS packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_context->request_hdr.net_id,
                    l_context->request_hdr.chain_id, l_context->request_hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        l_context->last_activity = dap_time_now();

        unsigned int l_count_added = 0;
        unsigned int l_count_total = 0;
        for (dap_chain_ch_update_element_t *l_element = (dap_chain_ch_update_element_t *)l_chain_pkt->data;
                (size_t)((byte_t *)(l_element + 1) - l_chain_pkt->data) <= l_chain_pkt_data_size;
                l_element++) {
            dap_chain_ch_hash_item_t *l_hash_item = NULL;
            unsigned l_hash_item_hashv;
            HASH_VALUE(&l_element->hash, sizeof(l_element->hash), l_hash_item_hashv);
            HASH_FIND_BYHASHVALUE(hh, l_context->remote_atoms, &l_element->hash, sizeof(l_element->hash),
                                  l_hash_item_hashv, l_hash_item);
            if (!l_hash_item) {
                l_hash_item = DAP_NEW_Z(dap_chain_ch_hash_item_t);
                if (!l_hash_item) {
                    log_it(L_CRITICAL, "%s", g_error_memory_alloc);
                    dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                            DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
                    break;
                }
                l_hash_item->hash = l_element->hash;
                l_hash_item->size = l_element->size;
                HASH_ADD_BYHASHVALUE(hh, l_context->remote_atoms, hash, sizeof(l_hash_item->hash),
                                     l_hash_item_hashv, l_hash_item);
                l_count_added++;
                //debug_if(s_debug_legacy, L_DEBUG, "In: Updated remote hash GDB list with %s", dap_chain_hash_fast_to_str_static(&l_hash_item->hash));
            }
            l_count_total++;
        }
        debug_if(s_debug_legacy, L_INFO, "In: Added %u from %u remote atom hash in list", l_count_added, l_count_total);
    } break;

    // End of response with chain hashes
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_sync_request_old_t)) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE) {
            log_it(L_WARNING, "Can't process UPDATE_CHAINS_END packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In: UPDATE_CHAINS_END pkt with total count %d hashes", HASH_COUNT(l_context->remote_atoms));
        l_context->state = DAP_CHAIN_CH_STATE_SYNC_CHAINS;
        debug_if(s_debug_legacy, L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN");
        dap_chain_ch_pkt_write_unsafe(DAP_STREAM_CH(l_ch_chain), DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN,
                l_context->request_hdr.net_id, l_context->request_hdr.chain_id,
                l_context->request_hdr.cell_id, &g_node_addr, sizeof(dap_chain_node_addr_t),
                DAP_CHAIN_CH_PKT_VERSION_LEGACY);
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_chains_proc_callback, l_context);
    } break;

    // first packet of data with source node address (legacy, unverified)
    case DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_node_addr_t)) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_SYNC_CHAINS_REMOTE) {
            log_it(L_WARNING, "Can't process FIRST_CHAIN packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In: FIRST_CHAIN data_size=%zu net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x
                        " from address "NODE_ADDR_FP_STR "(unverified)", l_chain_pkt_data_size, l_context->request_hdr.net_id.uint64,
                        l_context->request_hdr.chain_id.uint64, l_context->request_hdr.cell_id.uint64, NODE_ADDR_FP_ARGS_S(l_context->remote_addr));
    } break;

    // Dummy packet for freeze detection
    case DAP_CHAIN_CH_PKT_TYPE_CHAINS_NO_FREEZE: {
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_SYNC_CHAINS_REMOTE) {
            log_it(L_WARNING, "Can't process CHAINS_NO_FREEZE packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_DEBUG, "Chains no freeze packet detected");
        l_context->last_activity = dap_time_now();
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_OLD: {
        if (!l_chain_pkt_data_size) {
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE);
            return false;
        }
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_SYNC_CHAINS_REMOTE) {
            log_it(L_WARNING, "Can't process FIRST_CHAIN packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In: CHAIN_OLD data_size=%zu", l_chain_pkt_data_size);
        struct atom_processing_args *l_args = DAP_NEW_Z_SIZE(struct atom_processing_args, l_ch_pkt->hdr.data_size + sizeof(struct atom_processing_args));
        if (!l_args) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        l_chain_pkt->hdr.data_size = l_chain_pkt_data_size;
        memcpy(l_args->data, l_chain_pkt, l_ch_pkt->hdr.data_size);
        if (s_debug_more) {
            char *l_atom_hash_str;
            dap_get_data_hash_str_static(l_chain_pkt->data, l_chain_pkt_data_size, l_atom_hash_str);
            log_it(L_INFO, "In: CHAIN_OLD pkt: atom hash %s (size %zd)", l_atom_hash_str, l_chain_pkt_data_size);
        }
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_in_chains_callback, l_args);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS: {
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (!l_context || l_context->state != DAP_CHAIN_CH_STATE_SYNC_CHAINS_REMOTE) {
            log_it(L_WARNING, "Can't process SYNCED_CHAINS packet cause synchronization sequence violation");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        debug_if(s_debug_legacy, L_INFO, "In:  SYNCED_CHAINS: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                        l_context->request_hdr.net_id.uint64, l_context->request_hdr.chain_id.uint64, l_context->request_hdr.cell_id.uint64);
        // we haven't node client waitng, so reply to other side
        l_context->state = DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE;
        debug_if(s_debug_legacy, L_INFO, "Out: UPDATE_CHAINS_REQ pkt");
        dap_chain_ch_sync_request_old_t l_request = { .node_addr = g_node_addr };
        dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_REQ, l_context->request_hdr.net_id,
                                      l_context->request_hdr.chain_id, l_context->request_hdr.cell_id, &l_request, sizeof(l_request),
                                      DAP_CHAIN_CH_PKT_VERSION_LEGACY);
    } break;

    }

    return true;
}

static bool s_sync_timer_callback(void *a_arg)
{
    dap_worker_t *l_worker = dap_worker_get_current();
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_worker), *(dap_stream_ch_uuid_t *)a_arg);
    if (!l_ch) {
        DAP_DELETE(a_arg);
        return false;
    }
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(l_ch);
    if (!l_ch_chain) {
        log_it(L_ERROR, "Channel without chain, dump it");
        DAP_DELETE(a_arg);
        return false;
    }

    bool l_timer_break = false;
    const char *l_err_str = s_error_type_to_string(DAP_CHAIN_CH_ERROR_SYNC_TIMEOUT);
    if (l_ch_chain->sync_context) {
        struct sync_context *l_context = l_ch_chain->sync_context;
        if (l_context->last_activity + s_sync_timeout <= dap_time_now()) {
            log_it(L_ERROR, "Sync timeout for node " NODE_ADDR_FP_STR " with net 0x%016" DAP_UINT64_FORMAT_x
                                " chain 0x%016" DAP_UINT64_FORMAT_x " cell 0x%016" DAP_UINT64_FORMAT_x,
                                            NODE_ADDR_FP_ARGS_S(l_context->addr), l_context->net_id.uint64,
                                            l_context->chain_id.uint64, l_context->cell_id.uint64);
            dap_chain_ch_pkt_write_unsafe(l_ch, DAP_CHAIN_CH_PKT_TYPE_ERROR, l_context->net_id,
                                          l_context->chain_id, l_context->cell_id, l_err_str, strlen(l_err_str) + 1,
                                          DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            l_timer_break = true;
        }
    } else if (l_ch_chain->legacy_sync_context) {
        struct legacy_sync_context *l_context = l_ch_chain->legacy_sync_context;
        if (l_context->last_activity + s_sync_timeout <= dap_time_now()) {
            log_it(L_ERROR, "Sync timeout for node " NODE_ADDR_FP_STR " (unverified) with net 0x%016" DAP_UINT64_FORMAT_x
                                " chain 0x%016" DAP_UINT64_FORMAT_x " cell 0x%016" DAP_UINT64_FORMAT_x,
                                            NODE_ADDR_FP_ARGS_S(l_context->remote_addr), l_context->request_hdr.net_id.uint64,
                                            l_context->request_hdr.chain_id.uint64, l_context->request_hdr.cell_id.uint64);
            dap_chain_ch_pkt_write_unsafe(l_ch, DAP_CHAIN_CH_PKT_TYPE_ERROR, l_context->request_hdr.net_id,
                                          l_context->request_hdr.chain_id, l_context->request_hdr.cell_id, l_err_str, strlen(l_err_str) + 1,
                                          DAP_CHAIN_CH_PKT_VERSION_LEGACY);
            l_timer_break = true;
        }
    } else
        l_timer_break = true;

    if (l_timer_break) {
        l_ch_chain->sync_timer = NULL;      // Preserve timer removing from s_ch_chain_go_idle()
        s_ch_chain_go_idle(l_ch_chain);
        DAP_DELETE(a_arg);
        return false;
    }
    return true;
}

static bool s_chain_iter_callback(void *a_arg)
{
    assert(a_arg);
    struct sync_context *l_context = a_arg;
    dap_chain_atom_iter_t *l_iter = l_context->iter;
    assert(l_iter);
    dap_chain_t *l_chain = l_iter->chain;
    if (atomic_exchange(&l_context->state, SYNC_STATE_BUSY) == SYNC_STATE_OVER) {
        atomic_store(&l_context->state, SYNC_STATE_OVER);
        return false;
    }
    size_t l_atom_size = l_iter->cur_size;
    dap_chain_atom_ptr_t l_atom = l_iter->cur;
    uint32_t l_cycles_count = 0;
    while (l_atom && l_atom_size) {
        if (l_iter->cur_num > atomic_load_explicit(&l_context->allowed_num, memory_order_acquire))
            break;
        dap_chain_ch_pkt_t *l_pkt = dap_chain_ch_pkt_new(l_context->net_id, l_context->chain_id, l_context->cell_id,
                                                         l_atom, l_atom_size, DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        // For master format binary complience
        l_pkt->hdr.num_lo = l_iter->cur_num & 0xFFFF;
        l_pkt->hdr.num_hi = (l_iter->cur_num >> 16) & 0xFF;
        dap_stream_ch_pkt_send_by_addr(&l_context->addr, DAP_CHAIN_CH_ID, DAP_CHAIN_CH_PKT_TYPE_CHAIN, l_pkt, dap_chain_ch_pkt_get_size(l_pkt));
        DAP_DELETE(l_pkt);
        debug_if(s_debug_more, L_DEBUG, "Out: CHAIN %s for net %s to destination " NODE_ADDR_FP_STR " with num %" DAP_UINT64_FORMAT_U
                                            " hash %s and size %zu",
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(l_context->addr),
                                l_iter->cur_num, dap_hash_fast_to_str_static(l_iter->cur_hash), l_iter->cur_size);
        l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size);
        if (!l_atom || !l_atom_size || l_iter->cur_num > l_context->num_last)
            break;
        if (atomic_exchange(&l_context->state, SYNC_STATE_BUSY) == SYNC_STATE_OVER) {
            atomic_store(&l_context->state, SYNC_STATE_OVER);
            return false;
        }
        if (++l_cycles_count >= s_sync_packets_per_thread_call)
            return true;
    }
    uint16_t l_state = l_atom && l_atom_size && l_iter->cur_num <= l_context->num_last
                ? SYNC_STATE_IDLE : SYNC_STATE_OVER;
    uint16_t l_prev_state = atomic_exchange(&l_context->state, l_state);
    if (l_prev_state == SYNC_STATE_OVER && l_state != SYNC_STATE_OVER)
        atomic_store(&l_context->state, SYNC_STATE_OVER);
    if (l_prev_state == SYNC_STATE_READY)   // Allowed num was changed since last state updating
        return true;
    return false;
}

static bool s_chain_iter_delete_callback(void *a_arg)
{
    struct sync_context *l_context = a_arg;
    assert(l_context->iter);
    l_context->iter->chain->callback_atom_iter_delete(l_context->iter);
    DAP_DELETE(l_context);
    return false;
}

/**
 * @brief s_ch_chain_go_idle
 * @param a_ch_chain
 */
static void s_ch_chain_go_idle(dap_chain_ch_t *a_ch_chain)
{
    debug_if(s_debug_more, L_INFO, "Going to chain's stream channel STATE_IDLE");

    // New protocol
    if (a_ch_chain->sync_context) {
        atomic_store(&((struct sync_context *)a_ch_chain->sync_context)->state, SYNC_STATE_OVER);
        dap_proc_thread_callback_add(DAP_STREAM_CH(a_ch_chain)->stream_worker->worker->proc_queue_input,
                                     s_chain_iter_delete_callback, a_ch_chain->sync_context);
        a_ch_chain->sync_context = NULL;
    }
    if (a_ch_chain->sync_timer) {
        dap_timerfd_delete_unsafe(a_ch_chain->sync_timer);
        a_ch_chain->sync_timer = NULL;
    }
//}
    // Legacy
    if (a_ch_chain->legacy_sync_context) {
        dap_chain_ch_state_t l_current_state = atomic_exchange(
                    &((struct legacy_sync_context *)a_ch_chain->legacy_sync_context)->state, DAP_CHAIN_CH_STATE_IDLE);
        if (l_current_state != DAP_CHAIN_CH_STATE_UPDATE_CHAINS &&
                l_current_state != DAP_CHAIN_CH_STATE_SYNC_CHAINS &&
                l_current_state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB &&
                l_current_state != DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB &&
                l_current_state != DAP_CHAIN_CH_STATE_IDLE &&
                l_current_state != DAP_CHAIN_CH_STATE_ERROR)
            // Context will not be removed from proc thread
            s_legacy_sync_context_delete(a_ch_chain->legacy_sync_context);
        a_ch_chain->legacy_sync_context = NULL;
    }
}

static void s_stream_ch_io_complete(dap_events_socket_t *a_es, void *a_arg)
{
    dap_return_if_fail(a_arg);
    dap_stream_t *l_stream = dap_stream_get_from_es(a_es);
    assert(l_stream);
    dap_stream_ch_t *l_ch = dap_stream_ch_by_id_unsafe(l_stream, DAP_CHAIN_CH_ID);
    assert(l_ch);
    struct legacy_sync_context *l_context = DAP_CHAIN_CH(l_ch)->legacy_sync_context;
    if (!l_context)
        return;
    dap_chain_ch_state_t l_expected = DAP_CHAIN_CH_STATE_WAITING;
    if (!atomic_compare_exchange_strong(&l_context->state, &l_expected, l_context->prev_state))
        return;
    if (l_context->prev_state == DAP_CHAIN_CH_STATE_UPDATE_CHAINS ||
            l_context->prev_state == DAP_CHAIN_CH_STATE_SYNC_CHAINS) {
        l_context->enqueued_data_size = 0;
        dap_proc_thread_callback_add(l_ch->stream_worker->worker->proc_queue_input, s_sync_out_chains_proc_callback, l_context);
    } else if (l_context->prev_state == DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB ||
                l_context->prev_state == DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB) {
        l_context->enqueued_data_size = 0;
        dap_proc_thread_callback_add(l_ch->stream_worker->worker->proc_queue_input, s_sync_out_gdb_proc_callback, l_context);
    } else
        log_it(L_ERROR, "Unexpected legacy sync context state %d", l_context->state);
}

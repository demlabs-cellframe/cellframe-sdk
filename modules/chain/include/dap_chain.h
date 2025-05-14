/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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
*/


#pragma once
#include <stdbool.h>
#include <pthread.h>
#include "dap_config.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"

#ifdef DAP_TPS_TEST
#define DAP_CHAIN_ATOM_MAX_SIZE (100 * 1024 * 1024)
#else
#define DAP_CHAIN_ATOM_MAX_SIZE (256 * 1024) // 256 KB
#endif

typedef struct dap_chain dap_chain_t;

typedef struct dap_chain_cell dap_chain_cell_t;

typedef struct dap_ledger dap_ledger_t;

// Atomic element
typedef const void * dap_chain_atom_ptr_t;

// Atomic element iterator
typedef struct dap_chain_atom_iter {
    dap_chain_t *chain;
    dap_chain_cell_id_t cell_id;
    void *cur_item;
    dap_chain_atom_ptr_t cur;
    size_t cur_size;
    dap_chain_hash_fast_t *cur_hash;
    uint64_t cur_num;
    dap_time_t cur_ts;
} dap_chain_atom_iter_t;

typedef struct dap_chain_datum_iter {
    dap_chain_t *chain;
    dap_chain_datum_t *cur;
    size_t cur_size;
    dap_chain_hash_fast_t *cur_hash;
    dap_chain_hash_fast_t *cur_atom_hash;
    uint32_t action;
    dap_chain_net_srv_uid_t uid;
    int ret_code;
    char *token_ticker;
    void *cur_item;
} dap_chain_datum_iter_t;

typedef enum dap_chain_atom_verify_res{
    ATOM_ACCEPT = 0, ATOM_PASS, ATOM_REJECT, ATOM_MOVE_TO_THRESHOLD, ATOM_FORK
} dap_chain_atom_verify_res_t;

static const char* const dap_chain_atom_verify_res_str[] = {
    [ATOM_ACCEPT]   = "accepted",
    [ATOM_PASS]     = "skipped",
    [ATOM_REJECT]   = "rejected",
    [ATOM_MOVE_TO_THRESHOLD] = "thresholded",
    [ATOM_FORK] = "forked"
};

typedef enum dap_chain_iter_op {
    DAP_CHAIN_ITER_OP_FIRST,
    DAP_CHAIN_ITER_OP_LAST,
    DAP_CHAIN_ITER_OP_NEXT,
    DAP_CHAIN_ITER_OP_PREV
} dap_chain_iter_op_t;

typedef dap_chain_t* (*dap_chain_callback_new_t)(void);

typedef void (*dap_chain_callback_t)(dap_chain_t *);
typedef int (*dap_chain_callback_new_cfg_t)(dap_chain_t *, dap_config_t *);
typedef void (*dap_chain_callback_ptr_t)(dap_chain_t *, void * );

typedef dap_chain_atom_verify_res_t (*dap_chain_callback_atom_t)(dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_hash_fast_t *a_atom_hash, bool a_atom_new);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_form_treshold_t)(dap_chain_t *, size_t *);
typedef json_object *(*dap_chain_callback_atom_to_json)(json_object **a_arr_out, dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, const char *a_hex_out_type);
typedef dap_chain_atom_verify_res_t (*dap_chain_callback_atom_verify_t)(dap_chain_t *, dap_chain_atom_ptr_t , size_t, dap_hash_fast_t*);
typedef size_t (*dap_chain_callback_atom_get_hdr_size_t)(void);

typedef dap_chain_atom_iter_t * (*dap_chain_callback_atom_iter_create_t)(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_get_t)(dap_chain_atom_iter_t *a_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_find_by_hash_t)(dap_chain_atom_iter_t *a_iter, dap_hash_fast_t *a_atom_hash, size_t *a_atom_size);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_get_by_num_t)(dap_chain_atom_iter_t *a_iter, uint64_t a_atom_num);
typedef void (*dap_chain_callback_atom_iter_delete_t)(dap_chain_atom_iter_t *);

typedef dap_chain_datum_iter_t * (*dap_chain_datum_callback_iter_create_t)(dap_chain_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_first_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_last_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_next_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_prev_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iters)(dap_chain_datum_iter_t *);
typedef void (*dap_chain_datum_callback_iter_delete_t)(dap_chain_datum_iter_t *);

typedef dap_chain_datum_t** (*dap_chain_callback_atom_get_datum_t)(dap_chain_atom_ptr_t, size_t, size_t * );
typedef dap_time_t (*dap_chain_callback_atom_get_timestamp_t)(dap_chain_atom_ptr_t);

typedef dap_chain_datum_t * (*dap_chain_callback_datum_find_by_hash_t)(dap_chain_t *, dap_chain_hash_fast_t *, dap_chain_hash_fast_t *, int *);

typedef dap_chain_atom_ptr_t (*dap_chain_callback_block_find_by_hash_t)(dap_chain_t * ,dap_chain_hash_fast_t *, size_t *);

typedef dap_chain_atom_ptr_t * (*dap_chain_callback_atom_iter_get_atoms_t)(dap_chain_atom_iter_t * ,size_t* ,size_t**);
typedef size_t (*dap_chain_callback_add_datums_t)(dap_chain_t * , dap_chain_datum_t **, size_t );

typedef void (*dap_chain_callback_notify_t)(void *a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, dap_chain_hash_fast_t *a_atom_hash,
                                            void *a_atom, size_t a_atom_size, dap_time_t a_atom_time); //change in chain happened
typedef void (*dap_chain_callback_datum_notify_t)(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_hash_fast_t *a_atom_hash, void *a_datum, 
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, dap_chain_net_srv_uid_t a_uid); //change in chain happened
typedef void (*dap_chain_callback_datum_removed_notify_t)(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum); //change in chain happened
typedef void (*dap_chain_callback_blockchain_timer_t)(dap_chain_t *a_chain, dap_time_t a_time, void *a_arg, bool a_reverse);
typedef uint64_t (*dap_chain_callback_get_count)(dap_chain_t *a_chain);
typedef dap_list_t *(*dap_chain_callback_get_list)(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);
typedef dap_list_t *(*dap_chain_callback_get_poa_certs)(dap_chain_t *a_chain, size_t *a_auth_certs_count, uint16_t *count_verify);
typedef void (*dap_chain_callback_load_from_gdb)(dap_chain_t *a_chain);
typedef uint256_t (*dap_chain_callback_calc_reward)(dap_chain_t *a_chain, dap_hash_fast_t *a_block_hash, dap_pkey_t *a_block_sign_pkey);

typedef enum dap_chain_type {
    CHAIN_TYPE_INVALID = -1,
    CHAIN_TYPE_TOKEN = 1,
    CHAIN_TYPE_EMISSION = 2,
    CHAIN_TYPE_TX = 3,
    CHAIN_TYPE_CA = 4,
    CHAIN_TYPE_SIGNER = 5,
    CHAIN_TYPE_DECREE = 7,
    CHAIN_TYPE_ANCHOR = 8,
    CHAIN_TYPE_MAX
} dap_chain_type_t;

// not rotate, use in state machine
typedef enum dap_chain_sync_state {
    CHAIN_SYNC_STATE_SYNCED = -1,  // chain was synced
    CHAIN_SYNC_STATE_IDLE = 0,  // do nothink
    CHAIN_SYNC_STATE_WAITING = 1,  // wait packet in
    CHAIN_SYNC_STATE_ERROR = 2 // have a error
} dap_chain_sync_state_t;

typedef struct dap_chain {
    pthread_rwlock_t rwlock; // Common rwlock for the whole structure

    dap_chain_id_t id;
    dap_chain_net_id_t net_id;
    uint16_t load_priority;
    char *name;
    char *net_name;
    bool is_datum_pool_proc;
    bool is_mapped;
    atomic_int load_progress; 
    // Nested cells (hashtab by cell_id)
    dap_chain_cell_t *cells;
    dap_chain_cell_id_t active_cell_id;
    dap_chain_cell_id_t forking_cell_id;

    uint16_t datum_types_count;
    dap_chain_type_t *datum_types;
    uint16_t default_datum_types_count;
    dap_chain_type_t *default_datum_types;
    uint16_t autoproc_datum_types_count;
    uint16_t *autoproc_datum_types;
    uint64_t atom_num_last;
    dap_time_t blockchain_time;

    dap_chain_sync_state_t  state;

    uint16_t authorized_nodes_count;
    dap_stream_node_addr_t *authorized_nodes_addrs;

    // To hold it in double-linked lists
    struct dap_chain * next;
    struct dap_chain * prev;

    pthread_rwlock_t cell_rwlock;

    dap_chain_callback_new_cfg_t callback_created;
    dap_chain_callback_t callback_delete;
    dap_chain_callback_t callback_purge;

    dap_chain_callback_atom_t callback_atom_add;
    dap_chain_callback_atom_form_treshold_t callback_atom_add_from_treshold;
    dap_chain_callback_atom_verify_t callback_atom_verify;

    dap_chain_callback_add_datums_t callback_add_datums;
    dap_chain_callback_atom_get_hdr_size_t callback_atom_get_hdr_static_size; // Get atom header's size

    dap_chain_callback_atom_get_datum_t callback_atom_get_datums;
    dap_chain_callback_atom_get_timestamp_t callback_atom_get_timestamp;

    dap_chain_callback_atom_iter_find_by_hash_t callback_atom_find_by_hash;
    dap_chain_callback_atom_iter_get_by_num_t callback_atom_get_by_num;
    dap_chain_callback_datum_find_by_hash_t callback_datum_find_by_hash;
    dap_chain_callback_atom_to_json callback_atom_dump_json;

    dap_chain_callback_block_find_by_hash_t callback_block_find_by_tx_hash;

    dap_chain_callback_atom_iter_create_t callback_atom_iter_create;
    dap_chain_callback_atom_iter_get_t callback_atom_iter_get;
    dap_chain_callback_atom_iter_delete_t callback_atom_iter_delete;
    // WRN: No iterator used or changed with it
    dap_chain_callback_atom_iter_get_atoms_t callback_atom_iter_get_links;

    dap_chain_callback_get_count callback_count_tx;
    dap_chain_callback_get_list callback_get_txs;
    dap_chain_callback_get_count callback_count_atom;
    dap_chain_callback_get_list callback_get_atoms;

    // Consensus specific callbacks
    dap_chain_callback_get_poa_certs callback_get_poa_certs;
    dap_chain_callback_calc_reward callback_calc_reward;
    dap_chain_callback_load_from_gdb callback_load_from_gdb;

    // Iterator callbacks
    dap_chain_datum_callback_iter_create_t callback_datum_iter_create;
    dap_chain_datum_callback_iter_get_first_t callback_datum_iter_get_first;
    dap_chain_datum_callback_iter_get_last_t callback_datum_iter_get_last;
    dap_chain_datum_callback_iter_get_next_t callback_datum_iter_get_next;
    dap_chain_datum_callback_iter_get_prev_t callback_datum_iter_get_prev;
    dap_chain_datum_callback_iter_delete_t callback_datum_iter_delete;

    dap_list_t *atom_notifiers;
    dap_list_t *datum_notifiers;
    dap_list_t *datum_removed_notifiers;
    dap_list_t *blockchain_timers;
    dap_list_t *atom_confirmed_notifiers;

    dap_config_t *config;

    void * _pvt; // private data
    void * _inheritor; // inheritor object
} dap_chain_t;

typedef struct dap_proc_thread dap_proc_thread_t;

typedef struct dap_chain_atom_notifier {
    dap_chain_callback_notify_t callback;
    dap_proc_thread_t *proc_thread;
    void *arg;
} dap_chain_atom_notifier_t;

typedef struct dap_chain_atom_confirmed_notifier {
    uint64_t block_notify_cnt;
    dap_chain_callback_notify_t callback;
    void *arg;
} dap_chain_atom_confirmed_notifier_t;

typedef struct dap_chain_pvt {
    char *cs_name, *file_storage_dir;
    bool cs_started, need_reorder;
} dap_chain_pvt_t;

#define DAP_CHAIN_PVT(a) ((dap_chain_pvt_t *)a->_pvt)

#define DAP_CHAIN(a) ( (dap_chain_t *) (a)->_inheritor)

DAP_STATIC_INLINE int dap_chain_id_parse(const char *a_id_str, dap_chain_id_t *a_id)
{
    uint64_t l_id;
    int res = dap_id_uint64_parse(a_id_str, &l_id);
    if (!res)
        a_id->uint64 = l_id;
    return res;
}

int dap_chain_init(void);
void dap_chain_deinit(void);

dap_chain_t *dap_chain_create(const char *a_chain_net_name, const char *a_chain_name, dap_chain_net_id_t a_chain_net_id, dap_chain_id_t a_chain_id);

int dap_chain_load_all (dap_chain_t * a_chain);
int dap_chain_save_all (dap_chain_t * a_chain);
bool dap_chain_has_file_store(dap_chain_t * a_chain);

//dap_chain_t * dap_chain_open(const char * a_file_storage,const char * a_file_cache);
void dap_chain_info_dump_log(dap_chain_t * a_chain);

dap_chain_t * dap_chain_find_by_id(dap_chain_net_id_t a_chain_net_id,dap_chain_id_t a_chain_id);
dap_chain_t *dap_chain_load_from_cfg(const char *a_chain_net_name, dap_chain_net_id_t a_chain_net_id, dap_config_t *a_cfg);

void dap_chain_delete(dap_chain_t * a_chain);
void dap_chain_add_callback_notify(dap_chain_t *a_chain, dap_chain_callback_notify_t a_callback, dap_proc_thread_t *a_thread, void *a_arg);
void dap_chain_add_callback_datum_index_notify(dap_chain_t *a_chain, dap_chain_callback_datum_notify_t a_callback, dap_proc_thread_t *a_thread, void *a_callback_arg);
void dap_chain_add_callback_datum_removed_from_index_notify(dap_chain_t *a_chain, dap_chain_callback_datum_removed_notify_t a_callback, dap_proc_thread_t *a_thread, void *a_callback_arg);
void dap_chain_atom_confirmed_notify_add(dap_chain_t *a_chain, dap_chain_callback_notify_t a_callback, void *a_arg, uint64_t a_conf_cnt);
int dap_chain_add_callback_timer(dap_chain_t *a_chain, dap_chain_callback_blockchain_timer_t a_callback, void *a_callback_arg);
void dap_chain_atom_notify(dap_chain_cell_t *a_chain_cell, dap_hash_fast_t *a_hash, const uint8_t *a_atom, size_t a_atom_size, dap_time_t a_atom_time);
void dap_chain_atom_remove_notify(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_time_t a_prev_atom_time);
void dap_chain_datum_notify(dap_chain_cell_t *a_chain_cell, dap_hash_fast_t *a_hash, dap_chain_hash_fast_t *a_atom_hash,
                            const uint8_t *a_datum, size_t a_datum_size, int a_ret_code, uint32_t a_action, dap_chain_net_srv_uid_t a_uid);
void dap_chain_datum_removed_notify(dap_chain_cell_t *a_chain_cell,  dap_hash_fast_t *a_hash, dap_chain_datum_t *a_datum);
void dap_chain_atom_add_from_threshold(dap_chain_t *a_chain);
dap_chain_atom_ptr_t dap_chain_get_atom_by_hash(dap_chain_t * a_chain, dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
bool dap_chain_get_atom_last_hash_num(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_atom_hash, uint64_t *a_atom_num);
DAP_STATIC_INLINE bool dap_chain_get_atom_last_hash(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_atom_hash)
{
    return dap_chain_get_atom_last_hash_num(a_chain, a_cell_id, a_atom_hash, NULL);
}
DAP_STATIC_INLINE dap_time_t dap_chain_get_blockhain_time(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id)
{
    return a_chain->blockchain_time;
}
ssize_t dap_chain_atom_save(dap_chain_cell_t *a_chain_cell, const uint8_t *a_atom, size_t a_atom_size, dap_hash_fast_t *a_new_atom_hash);
int dap_cert_chain_file_save(dap_chain_datum_t *datum, char *net_name);

const char *dap_chain_type_to_str(dap_chain_type_t a_chain_type);
const char *dap_chain_get_path(dap_chain_t *a_chain);
const char *dap_chain_get_cs_type(dap_chain_t *l_chain);

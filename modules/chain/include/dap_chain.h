/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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


#pragma once
#include <stdbool.h>
#include <pthread.h>
#include "dap_chain_global_db.h"
#include "dap_config.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"


typedef struct dap_chain dap_chain_t;

typedef struct dap_chain_cell dap_chain_cell_t;

typedef struct dap_ledger dap_ledger_t;

// Atomic element
typedef const void * dap_chain_atom_ptr_t;

// Atomic element iterator
typedef struct dap_chain_atom_iter{
    dap_chain_t * chain;
    dap_chain_atom_ptr_t cur;
    dap_chain_hash_fast_t *cur_hash;
    dap_chain_cell_id_t cell_id;
    bool with_treshold;
    bool found_in_treshold;
    size_t cur_size;
    void * cur_item;
    void * _inheritor;
} dap_chain_atom_iter_t;


typedef enum dap_chain_atom_verify_res{
    ATOM_ACCEPT = 0, ATOM_PASS, ATOM_REJECT, ATOM_MOVE_TO_THRESHOLD
} dap_chain_atom_verify_res_t;

static const char* const dap_chain_atom_verify_res_str[] = {
    [ATOM_ACCEPT]   = "accepted",
    [ATOM_PASS]     = "skipped",
    [ATOM_REJECT]   = "rejected",
    [ATOM_MOVE_TO_THRESHOLD] = "thresholded"
};

typedef dap_chain_t* (*dap_chain_callback_new_t)(void);

typedef void (*dap_chain_callback_t)(dap_chain_t *);
typedef int (*dap_chain_callback_new_cfg_t)(dap_chain_t*, dap_config_t *);
typedef void (*dap_chain_callback_ptr_t)(dap_chain_t *, void * );

typedef dap_chain_atom_verify_res_t (*dap_chain_callback_atom_t)(dap_chain_t *, dap_chain_atom_ptr_t, size_t );
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_form_treshold_t)(dap_chain_t *, size_t *);
typedef dap_chain_atom_verify_res_t (*dap_chain_callback_atom_verify_t)(dap_chain_t *, dap_chain_atom_ptr_t , size_t);
typedef size_t (*dap_chain_callback_atom_get_hdr_size_t)(void);

typedef dap_chain_atom_iter_t* (*dap_chain_callback_atom_iter_create_t)(dap_chain_t *, dap_chain_cell_id_t, bool);
typedef dap_chain_atom_iter_t* (*dap_chain_callback_atom_iter_create_from_t)(dap_chain_t * ,dap_chain_atom_ptr_t, size_t);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_get_first_t)(dap_chain_atom_iter_t * , size_t*);

typedef dap_hash_fast_t* (*dap_chain_callback_atom_iter_get_hash_t)(dap_chain_atom_iter_t *);
typedef const char* (*dap_chain_callback_atom_iter_get_hash_str_t)(dap_chain_atom_iter_t *);

typedef dap_chain_datum_t** (*dap_chain_callback_atom_get_datum_t)(dap_chain_atom_ptr_t, size_t, size_t * );
typedef dap_time_t (*dap_chain_callback_atom_get_timestamp_t)(dap_chain_atom_ptr_t);

typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_find_by_hash_t)(dap_chain_atom_iter_t * ,dap_chain_hash_fast_t *,size_t*);
typedef dap_chain_datum_tx_t* (*dap_chain_callback_tx_find_by_hash_t)(dap_chain_t * ,dap_chain_hash_fast_t *);

typedef dap_chain_atom_ptr_t * (*dap_chain_callback_atom_iter_get_atoms_t)(dap_chain_atom_iter_t * ,size_t* ,size_t**);

typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_get_next_t)(dap_chain_atom_iter_t *  ,size_t*);
typedef void (*dap_chain_callback_atom_iter_delete_t)(dap_chain_atom_iter_t *  );

typedef size_t (*dap_chain_callback_add_datums_t)(dap_chain_t * , dap_chain_datum_t **, size_t );

typedef void (*dap_chain_callback_notify_t)(void * a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, void* a_atom, size_t a_atom_size); //change in chain happened

typedef size_t(*dap_chain_callback_get_count)(dap_chain_t *a_chain);
typedef dap_list_t *(*dap_chain_callback_get_list)(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool reverse);

typedef enum dap_chain_type
{
    CHAIN_TYPE_FIRST,
    CHAIN_TYPE_TOKEN,
    CHAIN_TYPE_EMISSION,
    CHAIN_TYPE_TX,
    CHAIN_TYPE_CA,
    CHAIN_TYPE_SIGNER,
    CHAIN_TYPE_LAST
} dap_chain_type_t;

typedef struct dap_chain {
    pthread_rwlock_t rwlock; // Common rwlock for the whole structure

    dap_chain_id_t id;
    dap_chain_net_id_t net_id;
	uint16_t load_priority;
    char * name;
    char * net_name;
    dap_ledger_t * ledger; // If present - pointer to associated ledger
    bool is_datum_pool_proc;

    // Nested cells (hashtab by cell_id
    dap_chain_cell_t * cells;

    uint16_t datum_types_count;
    dap_chain_type_t *datum_types;
	uint16_t default_datum_types_count;
	dap_chain_type_t *default_datum_types;
    uint16_t autoproc_datum_types_count;
    uint16_t *autoproc_datum_types;

    // To hold it in double-linked lists
    struct dap_chain * next;
    struct dap_chain * prev;

    // read/write atoms rwlock
    pthread_rwlock_t atoms_rwlock;
    pthread_rwlock_t cell_rwlock;

    dap_chain_callback_new_cfg_t callback_created;
    dap_chain_callback_t callback_delete;
    dap_chain_callback_t callback_purge;

    dap_chain_callback_atom_t callback_atom_add;
    dap_chain_callback_atom_form_treshold_t callback_atom_add_from_treshold;
    dap_chain_callback_atom_verify_t callback_atom_verify;

    dap_chain_callback_add_datums_t callback_add_datums;

    dap_chain_callback_atom_get_hdr_size_t callback_atom_get_hdr_static_size; // Get atom header's size

    dap_chain_callback_atom_iter_create_t callback_atom_iter_create;
    dap_chain_callback_atom_iter_create_from_t callback_atom_iter_create_from;
    dap_chain_callback_atom_iter_get_first_t callback_atom_iter_get_first;

    dap_chain_callback_atom_get_datum_t callback_atom_get_datums;
    dap_chain_callback_atom_get_timestamp_t callback_atom_get_timestamp;

    dap_chain_callback_atom_iter_find_by_hash_t callback_atom_find_by_hash;
    dap_chain_callback_tx_find_by_hash_t callback_tx_find_by_hash;
    dap_chain_callback_atom_iter_get_next_t callback_atom_iter_get_next;
    dap_chain_callback_atom_iter_get_atoms_t callback_atom_iter_get_links;
    dap_chain_callback_atom_iter_get_atoms_t callback_atom_iter_get_lasts;
    dap_chain_callback_atom_iter_delete_t callback_atom_iter_delete;

    dap_chain_callback_get_count callback_count_tx;
    dap_chain_callback_get_list callback_get_txs;
    dap_chain_callback_get_count callback_count_atom;
    dap_chain_callback_get_list callback_get_atoms;

    dap_list_t * atom_notifiers;

    /*
    dap_chain_datum_callback_iter_create_t callback_datum_iter_create;
    dap_chain_datum_callback_iter_get_first_t callback_datum_iter_get_first;
    dap_chain_datum_callback_iter_get_first_t callback_datum_iter_get_next;
    dap_chain_datum_callback_iter_delete_t callback_datum_iter_delete;
*/
    void * _pvt; // private data
    void * _inheritor; // inheritor object
} dap_chain_t;

typedef struct dap_chain_gdb_notifier {
    dap_global_db_obj_callback_notify_t callback;
    void *cb_arg;
} dap_chain_gdb_notifier_t;

typedef struct dap_chain_atom_notifier {
    dap_chain_callback_notify_t callback;
    void *arg;
} dap_chain_atom_notifier_t;

#define DAP_CHAIN(a) ( (dap_chain_t *) (a)->_inheritor)

int dap_chain_init(void);
void dap_chain_deinit(void);

dap_chain_t* dap_chain_enum(void** a_item);
void dap_chain_enum_unlock(void);


dap_chain_t * dap_chain_create(dap_ledger_t* a_ledger,const char * a_chain_net_name, const char * a_chain_name, dap_chain_net_id_t a_chain_net_id, dap_chain_id_t a_chain_id );

int dap_chain_load_all (dap_chain_t * a_chain);
int dap_chain_save_all (dap_chain_t * a_chain);
bool dap_chain_has_file_store(dap_chain_t * a_chain);

//dap_chain_t * dap_chain_open(const char * a_file_storage,const char * a_file_cache);
void dap_chain_info_dump_log(dap_chain_t * a_chain);

dap_chain_t * dap_chain_find_by_id(dap_chain_net_id_t a_chain_net_id,dap_chain_id_t a_chain_id);
dap_chain_t * dap_chain_load_from_cfg(dap_ledger_t* a_ledger,const char * a_chain_net_name, dap_chain_net_id_t a_chain_net_id, const char * a_chain_cfg_name);

void dap_chain_delete(dap_chain_t * a_chain);
void dap_chain_add_callback_notify(dap_chain_t * a_chain, dap_chain_callback_notify_t a_callback, void * a_arg);
dap_chain_atom_ptr_t dap_chain_get_atom_by_hash(dap_chain_t * a_chain, dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
bool dap_chain_get_atom_last_hash(dap_chain_t *a_chain, dap_hash_fast_t *a_atom_hash, dap_chain_cell_id_t a_cel_id);
ssize_t dap_chain_atom_save(dap_chain_t *a_chain, const uint8_t *a_atom, size_t a_atom_size, dap_chain_cell_id_t a_cell_id);
void dap_chain_add_mempool_notify_callback(dap_chain_t *a_chain, dap_global_db_obj_callback_notify_t a_callback, void *a_cb_arg);
int dap_cert_chain_file_save(dap_chain_datum_t *datum, char *net_name);
int dap_chain_datum_unledgered_search_iter(dap_chain_datum_t*, dap_chain_t*);

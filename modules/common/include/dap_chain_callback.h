/**
 * @file dap_chain_callback.h
 * @brief Chain callback type definitions
 * 
 * All callback typedef declarations for chain module
 */

#pragma once

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_pkey.h"
#include "dap_time.h"
#include "dap_list.h"
#include "dap_json.h"

// Forward declarations
typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_datum dap_chain_datum_t;
typedef struct dap_chain_atom_iter dap_chain_atom_iter_t;
typedef struct dap_chain_datum_iter dap_chain_datum_iter_t;

// Atomic element
typedef const void * dap_chain_atom_ptr_t;

// Atom verification result
typedef enum dap_chain_atom_verify_res {
    ATOM_ACCEPT = 0,
    ATOM_REJECT = -1,
    ATOM_MOVE_TO_THRESHOLD = -2,
    ATOM_PASS = 1,
    ATOM_CORRUPTED = -3,
    ATOM_FORK = -4
} dap_chain_atom_verify_res_t;

// Iterator operation
typedef enum dap_chain_iter_op {
    DAP_CHAIN_ITER_OP_FIRST = 0,
    DAP_CHAIN_ITER_OP_NEXT = 1,
    DAP_CHAIN_ITER_OP_PREV = 2,
    DAP_CHAIN_ITER_OP_LAST = 3
} dap_chain_iter_op_t;

// Callback typedefs
typedef int (*dap_chain_callback_t)(dap_chain_t *);
typedef int (*dap_chain_callback_new_cfg_t)(dap_chain_t *, dap_config_t *);
typedef void (*dap_chain_callback_ptr_t)(dap_chain_t *, void * );

typedef dap_chain_atom_verify_res_t (*dap_chain_callback_atom_t)(dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_hash_fast_t *a_atom_hash, bool a_atom_new);
typedef unsigned (*dap_chain_callback_atoms_t)(dap_chain_t*);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_form_treshold_t)(dap_chain_t *, size_t *);
typedef dap_json_t *(*dap_chain_callback_atom_to_json)(dap_json_t **a_arr_out, dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, const char *a_hex_out_type, int a_version);
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

typedef void (*dap_chain_callback_notify_t)(void *a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, dap_chain_hash_fast_t *a_atom_hash, void *a_atom, size_t a_atom_size, dap_time_t a_atom_time);
typedef void (*dap_chain_callback_datum_notify_t)(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_hash_fast_t *a_atom_hash, void *a_datum, 
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, dap_chain_srv_uid_t a_uid);
typedef void (*dap_chain_callback_datum_removed_notify_t)(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum);
typedef void (*dap_chain_callback_blockchain_timer_t)(dap_chain_t *a_chain, dap_time_t a_time, void *a_arg, bool a_reverse);
typedef uint64_t (*dap_chain_callback_get_count)(dap_chain_t *a_chain);
typedef dap_list_t *(*dap_chain_callback_get_list)(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);
typedef dap_list_t *(*dap_chain_callback_get_poa_certs)(dap_chain_t *a_chain, size_t *a_auth_certs_count, uint16_t *count_verify);
typedef void (*dap_chain_callback_load_from_gdb)(dap_chain_t *a_chain);
typedef uint256_t (*dap_chain_callback_calc_reward)(dap_chain_t *a_chain, dap_hash_fast_t *a_block_hash, dap_pkey_t *a_block_sign_pkey);


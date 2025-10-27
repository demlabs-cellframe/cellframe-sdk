/**
 * @file dap_chain_callback.h
 * @brief Chain callback type definitions (non-atom callbacks)
 * 
 * Datum and general chain callback typedef declarations
 */

#pragma once

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_atom.h"  // Atom-related types
#include "dap_hash.h"
#include "dap_pkey.h"
#include "dap_time.h"
#include "dap_list.h"
#include "dap_json.h"
#include "dap_config.h"

// Forward declarations
typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_datum dap_chain_datum_t;
typedef struct dap_chain_datum_iter dap_chain_datum_iter_t;

// General callback typedefs
typedef int (*dap_chain_callback_t)(dap_chain_t *);
typedef int (*dap_chain_callback_new_cfg_t)(dap_chain_t *, dap_config_t *);
typedef void (*dap_chain_callback_ptr_t)(dap_chain_t *, void * );

// Atom callback to JSON
typedef dap_json_t *(*dap_chain_callback_atom_to_json)(dap_json_t **a_arr_out, dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, const char *a_hex_out_type, int a_version);

// Datum iterator callbacks
typedef dap_chain_datum_iter_t * (*dap_chain_datum_callback_iter_create_t)(dap_chain_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_first_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_last_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_next_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iter_get_prev_t)(dap_chain_datum_iter_t *);
typedef dap_chain_datum_t * (*dap_chain_datum_callback_iters)(dap_chain_datum_iter_t *);
typedef void (*dap_chain_datum_callback_iter_delete_t)(dap_chain_datum_iter_t *);

// Datum operations
typedef dap_chain_datum_t * (*dap_chain_callback_datum_find_by_hash_t)(dap_chain_t *, dap_chain_hash_fast_t *, dap_chain_hash_fast_t *, int *);
typedef size_t (*dap_chain_callback_add_datums_t)(dap_chain_t * , dap_chain_datum_t **, size_t );

// Notification callbacks
typedef void (*dap_chain_callback_datum_notify_t)(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_hash_fast_t *a_atom_hash, void *a_datum, 
                                    size_t a_datum_size, int a_ret_code, uint32_t a_action, dap_chain_srv_uid_t a_uid);
typedef void (*dap_chain_callback_datum_removed_notify_t)(void *a_arg, dap_chain_hash_fast_t *a_datum_hash, dap_chain_datum_t *a_datum);
typedef void (*dap_chain_callback_blockchain_timer_t)(dap_chain_t *a_chain, dap_time_t a_time, void *a_arg, bool a_reverse);

// General chain info callbacks
typedef uint64_t (*dap_chain_callback_get_count)(dap_chain_t *a_chain);
typedef dap_list_t *(*dap_chain_callback_get_list)(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);
typedef dap_list_t *(*dap_chain_callback_get_poa_certs)(dap_chain_t *a_chain, size_t *a_auth_certs_count, uint16_t *count_verify);
typedef void (*dap_chain_callback_load_from_gdb)(dap_chain_t *a_chain);
typedef uint256_t (*dap_chain_callback_calc_reward)(dap_chain_t *a_chain, dap_hash_fast_t *a_block_hash, dap_pkey_t *a_block_sign_pkey);

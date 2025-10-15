/**
 * @file dap_chain_atom.h
 * @brief Chain atom (block/event) definitions and types
 */

#pragma once

#include "dap_common.h"
#include "dap_time.h"
#include "dap_hash.h"

// Forward declarations
typedef struct dap_chain dap_chain_t;

// Atomic element pointer
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

// Helper function to get string representation of atom verify result
DAP_STATIC_INLINE const char* dap_chain_atom_verify_res_to_str(dap_chain_atom_verify_res_t a_res)
{
    switch(a_res) {
        case ATOM_ACCEPT: return "accepted";
        case ATOM_PASS: return "skipped";
        case ATOM_REJECT: return "rejected";
        case ATOM_MOVE_TO_THRESHOLD: return "thresholded";
        case ATOM_FORK: return "forked";
        case ATOM_CORRUPTED: return "corrupted";
        default: return "unknown";
    }
}

// Backward compatibility macro
#define dap_chain_atom_verify_res_str(res) dap_chain_atom_verify_res_to_str(res)

// Iterator operation
typedef enum dap_chain_iter_op {
    DAP_CHAIN_ITER_OP_FIRST = 0,
    DAP_CHAIN_ITER_OP_NEXT = 1,
    DAP_CHAIN_ITER_OP_PREV = 2,
    DAP_CHAIN_ITER_OP_LAST = 3
} dap_chain_iter_op_t;

// Atom iterator structure (forward declaration)
typedef struct dap_chain_atom_iter dap_chain_atom_iter_t;

// Atom-related callback typedefs
typedef dap_chain_atom_verify_res_t (*dap_chain_callback_atom_t)(dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_hash_fast_t *a_atom_hash, bool a_atom_new);
typedef unsigned (*dap_chain_callback_atoms_t)(dap_chain_t*);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_form_treshold_t)(dap_chain_t *, size_t *);
typedef dap_chain_atom_verify_res_t (*dap_chain_callback_atom_verify_t)(dap_chain_t *, dap_chain_atom_ptr_t , size_t, dap_hash_fast_t*);
typedef size_t (*dap_chain_callback_atom_get_hdr_size_t)(void);

typedef dap_chain_atom_iter_t * (*dap_chain_callback_atom_iter_create_t)(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_get_t)(dap_chain_atom_iter_t *a_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_find_by_hash_t)(dap_chain_atom_iter_t *a_iter, dap_hash_fast_t *a_atom_hash, size_t *a_atom_size);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_atom_iter_get_by_num_t)(dap_chain_atom_iter_t *a_iter, uint64_t a_atom_num);
typedef void (*dap_chain_callback_atom_iter_delete_t)(dap_chain_atom_iter_t *);

typedef dap_chain_atom_ptr_t * (*dap_chain_callback_atom_iter_get_atoms_t)(dap_chain_atom_iter_t * ,size_t* ,size_t**);
typedef dap_chain_atom_ptr_t (*dap_chain_callback_block_find_by_hash_t)(dap_chain_t * ,dap_chain_hash_fast_t *, size_t *);

// Forward declaration
typedef struct dap_chain_datum dap_chain_datum_t;

typedef dap_chain_datum_t** (*dap_chain_callback_atom_get_datum_t)(dap_chain_atom_ptr_t, size_t, size_t * );
typedef dap_time_t (*dap_chain_callback_atom_get_timestamp_t)(dap_chain_atom_ptr_t);

// Atom notification callback
typedef void (*dap_chain_callback_notify_t)(void *a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, dap_chain_hash_fast_t *a_atom_hash, void *a_atom, size_t a_atom_size, dap_time_t a_atom_time);


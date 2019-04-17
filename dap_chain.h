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
#include "dap_config.h"
#include "dap_chain_common.h"

#include "dap_chain_datum.h"

struct dap_chain;
typedef struct dap_chain dap_chain_t;

// Atomic element
typedef void * dap_chain_atom_t;

// Atomic element iterator
typedef struct dap_chain_atom_iter{
    dap_chain_t * chain;
    dap_chain_atom_t * cur;
} dap_chain_atom_iter_t;


typedef dap_chain_t* (*dap_chain_callback_new_t)(void);

typedef void (*dap_chain_callback_t)(dap_chain_t *);
typedef void (*dap_chain_callback_cfg_t)(dap_chain_t*, dap_config_t *);
typedef void (*dap_chain_callback_ptr_t)(dap_chain_t *, void * );

typedef int (*dap_chain_callback_atom_t)(dap_chain_t *, dap_chain_atom_t * );
typedef size_t (*dap_chain_callback_atom_get_hdr_size_t)();
typedef size_t (*dap_chain_callback_atom_hdr_get_size_t)(dap_chain_atom_t * );

typedef dap_chain_atom_iter_t* (*dap_chain_callback_atom_iter_create_t)(dap_chain_t * );
typedef dap_chain_atom_t* (*dap_chain_callback_atom_iter_get_first_t)(dap_chain_atom_iter_t * );
typedef dap_chain_atom_t* (*dap_chain_callback_atom_iter_get_next_t)(dap_chain_atom_iter_t *  );
typedef void (*dap_chain_callback_atom_iter_delete_t)(dap_chain_atom_iter_t *  );



typedef struct dap_chain{
    dap_chain_id_t id;
    dap_chain_net_id_t net_id;
    char * name;
    char * net_name;

    // To hold it in double-linked lists
    struct dap_chain * next;
    struct dap_chain * prev;

    dap_chain_callback_t callback_delete;

    dap_chain_callback_atom_t callback_atom_add;
    dap_chain_callback_atom_t callback_atom_verify;

    dap_chain_callback_atom_get_hdr_size_t callback_atom_get_hdr_size; // Get atom header's size
    dap_chain_callback_atom_hdr_get_size_t callback_atom_hdr_get_size; // Get atom's size from header

    dap_chain_callback_atom_iter_create_t callback_atom_iter_create;
    dap_chain_callback_atom_iter_get_first_t callback_atom_iter_get_first;
    dap_chain_callback_atom_iter_get_first_t callback_atom_iter_get_next;
    dap_chain_callback_atom_iter_delete_t callback_atom_iter_delete;

    dap_chain_datum_callback_iter_create_t callback_datum_iter_create;
    dap_chain_datum_callback_iter_get_first_t callback_datum_iter_get_first;
    dap_chain_datum_callback_iter_get_first_t callback_datum_iter_get_next;
    dap_chain_datum_callback_iter_delete_t callback_datum_iter_delete;

    void * _pvt; // private data
    void * _inheritor; // inheritor object
} dap_chain_t;

#define DAP_CHAIN(a) ( (dap_chain_t *) (a)->_inheritor)

int dap_chain_init();
void dap_chain_deinit();


dap_chain_t * dap_chain_create(const char * a_chain_net_name, const char * a_chain_name, dap_chain_net_id_t a_chain_net_id, dap_chain_id_t a_chain_id );

//dap_chain_t * dap_chain_open(const char * a_file_storage,const char * a_file_cache);
void dap_chain_info_dump_log(dap_chain_t * a_chain);

dap_chain_t * dap_chain_find_by_id(dap_chain_net_id_t a_chain_net_id,dap_chain_id_t a_chain_id);
dap_chain_t * dap_chain_load_from_cfg(const char * a_chain_net_name, dap_chain_net_id_t a_chain_net_id, const char * a_chain_cfg_name);

void dap_chain_delete(dap_chain_t * a_chain);




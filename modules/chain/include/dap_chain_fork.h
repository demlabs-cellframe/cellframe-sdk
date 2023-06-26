/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Cellframe Network: https://cellframe.net
 * Copyright  (c) 2023
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdint.h>
#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_chain.h"

typedef uint64_t dap_chain_fork_id_t;
typedef struct dap_chain_fork dap_chain_fork_t;

typedef void (*dap_chain_fork_callback_t)(dap_chain_fork_t* a_fork);

typedef struct dap_chain_fork {
    char * name;
    dap_chain_fork_id_t id;
    dap_chain_net_id_t net_id;
    dap_chain_id_t chain_id;
    dap_chain_fork_callback_t callback;
    uint64_t atom_number;

    void * hh_obj; // Pointer to HH object
    dap_chain_fork_t * next; // Next fork, NULL if not present
} dap_chain_fork_t;

dap_chain_fork_t * dap_chain_fork_get_current(dap_chain_net_id_t a_net_id);
dap_chain_fork_t * dap_chain_fork_get_last(dap_chain_net_id_t a_net_id);
dap_chain_fork_t * dap_chain_fork_get_coming(dap_chain_net_id_t a_net_id);

bool dap_chain_fork_check(dap_chain_fork_t * a_fork, uint64_t a_atom_number,  dap_chain_id_t a_chain_id);
dap_chain_fork_t * dap_chain_fork_add(dap_chain_net_id_t a_net_id, const char * a_name, uint64_t a_atom_number, dap_chain_id_t a_chain_id, dap_chain_fork_callback_t a_callback);

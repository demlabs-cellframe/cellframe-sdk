/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_chain_datum_decree.h"
#include "dap_list.h"
#include "dap_chain_net.h"

typedef struct decree_params {
    dap_list_t *pkeys;
    uint16_t num_of_owners;
    uint16_t min_num_of_owners;
}   dap_chain_net_decree_t;

int dap_chain_net_decree_init(dap_chain_net_t *a_net);
int dap_chain_net_decree_deinit(dap_chain_net_t *a_net);

void dap_chain_net_decree_purge(dap_chain_net_t *a_net);

int dap_chain_net_decree_apply(dap_hash_fast_t *a_decree_hash, dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain);
int dap_chain_net_decree_verify(dap_chain_net_t *a_net, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash);
int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_decree_hash);
int dap_chain_net_decree_reset_applied(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_decree_hash);


dap_chain_datum_decree_t *dap_chain_net_decree_get_by_hash(dap_hash_fast_t *a_hash, bool *is_applied);

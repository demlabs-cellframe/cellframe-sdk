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

typedef struct decree_params {
    dap_list_t *pkeys;
    uint256_t   num_of_owners;
    uint256_t   min_num_of_owners;
}   dap_chain_net_decree_t;

// Default values


int dap_chain_net_decree_init(dap_chain_net_t *a_net);
int dap_chain_net_decree_deinit(dap_chain_net_t *a_net);

int dap_chain_net_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain);
int dap_chain_net_decree_verify(dap_chain_datum_decree_t * a_decree, dap_chain_net_t *a_net, uint32_t *a_signs_count, uint32_t *a_signs_verify);

/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
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

#include "dap_chain_srv.h"
#include "dap_chain_datum.h"

typedef struct dap_chain_datum_service_state {
    byte_t nonce[DAP_CHAIN_DATUM_NONCE_SIZE];
    dap_chain_srv_uid_t srv_uid;
    uint32_t states_count;
    uint64_t state_size;
    byte_t states[];
} DAP_ALIGN_PACKED dap_chain_datum_service_state_t;

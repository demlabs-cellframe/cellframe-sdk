/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
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

#include "dap_chain_common.h"
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_time.h"
#include <stdint.h>

// Governance decree
typedef struct dap_chain_datum_decree{
    struct {
        dap_time_t ts_created;
        uint16_t type;
        union{
            dap_chain_net_srv_uid_t srv_id;
            dap_chain_net_id_t net_id;
            dap_chain_cell_id_t cell_id;
        };
        uint16_t action;
    } DAP_ALIGN_PACKED header;
    byte_t tsd_sections[];
} DAP_ALIGN_PACKED dap_chain_datum_decree_t;

#define DAP_CHAIN_DATUM_DECREE_TYPE_COMMON                  0x0001
#define DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE                 0x0002


// Create from scratch, reset all previous values
#define DAP_CHAIN_DATUM_DECREE_ACTION_CREATE                0x0001
#define DAP_CHAIN_DATUM_DECREE_ACTION_UPDATE                0x0002
#define DAP_CHAIN_DATUM_DECREE_ACTION_DELETE                0x0003


#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN                0x0001

/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
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
#include <stdio.h>
#include <stdint.h>
#include "dap_chain.h"
#include "dap_chain_cs.h"
#include "dap_chain_cell.h"
#include "dap_common.h"
/**
  * @struct dap_chain_pvt
  * @brief Internal blochain data, mostly aggregated
  *
  */
typedef struct dap_chain_pvt
{
    dap_chain_t * chain;
    char * file_storage_dir;
    char * cs_name;
    int celled;
    dap_list_t *mempool_notifires;
} dap_chain_pvt_t;

#define DAP_CHAIN_PVT(a) ((dap_chain_pvt_t *) a->_pvt  )

#define DAP_CHAIN_PVT_LOCAL(a) dap_chain_pvt_t * l_chain_pvt = DAP_CHAIN_PVT(a)

#define DAP_CHAIN_PVT_LOCAL_NEW(a) dap_chain_pvt_t * l_chain_pvt = DAP_NEW_Z(dap_chain_pvt_t); a->_pvt = l_chain_pvt

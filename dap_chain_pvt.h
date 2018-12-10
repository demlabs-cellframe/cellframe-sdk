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
#include "dap_common.h"
#include "dap_chain.h"

#define DAP_CHAIN_FILE_SIGNATURE 0xfa340bef153eba48
#define DAP_CHAIN_FILE_TYPE_RAW 0
#define DAP_CHAIN_FILE_TYPE_COMPRESSED 1
#define DAP_CHAIN_CHAIN_ID 0x123ULL
#define DAP_CHAIN_CHAIN_NET_ID 0x456ULL

typedef struct dap_chain_file_header
{
    uint64_t signature;
    uint32_t version;
    uint8_t type;
    uint64_t chain_id;
    uint64_t chain_net_id;
} dap_chain_file_header_t;

/**
  * @struct dap_chain_pvt
  * @brief Internal blochain data, mostly aggregated
  *
  */
typedef struct dap_chain_pvt
{
    FILE * file_cache_idx_blocks; /// @param file_cache @brief Index for blocks
    FILE * file_cache_idx_txs; /// @param file_cache @brief Index for cache
    FILE * file_cache; /// @param file_cache @brief Cache for raw blocks
    FILE * file_storage; /// @param file_cache @brief Cache for raw blocks
    uint8_t file_storage_type; /// @param file_storage_type  @brief Is file_storage is raw, compressed or smth else
} dap_chain_pvt_t;

#define DAP_CHAIN_PVT(a) ((dap_chain_pvt_t *) a->_internal  )

#define DAP_CHAIN_PVT_LOCAL(a) dap_chain_pvt_t * l_chain_pvt = DAP_CHAIN_PVT(a)

#define DAP_CHAIN_PVT_LOCAL_NEW(a) dap_chain_pvt_t * l_chain_pvt = DAP_NEW_Z(dap_chain_internal_t); a->_internal = l_chain_internal

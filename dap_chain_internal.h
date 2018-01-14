/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

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

typedef struct dap_chain_file_header
{
    uint64_t signature;
    uint32_t version;
    uint8_t type;
    uint32_t chain_id;
} dap_chain_file_header_t;

/**
  * @struct dap_chain_internal
  * @brief Internal blochain data, mostly aggregated
typedef struct dap_chain_internal
{
    FILE * file_cache_idx_blocks; /// @param file_cache @brief Index for blocks
    FILE * file_cache_idx_txs; /// @param file_cache @brief Index for cache
    FILE * file_cache; /// @param file_cache @brief Cache for raw blocks
    FILE * file_storage; /// @param file_cache @brief Cache for raw blocks
    uint8_t file_storage_type; /// @param file_storage_type  @brief Is file_storage is raw, compressed or smth else
} dap_chain_internal_t;

#define DAP_CHAIN_INTERNAL(a) ((dap_chain_internal_t *) a->_inheritor  )

#define DAP_CHAIN_INTERNAL_LOCAL(a) dap_chain_internal_t * l_chain_internal = DAP_CHAIN_INTERNAL(a)

#define DAP_CHAIN_INTERNAL_LOCAL_NEW(a) dap_chain_internal_t * l_chain_internal = DAP_NEW_Z(dap_chain_internal_t); a->_inheritor = l_chain_internal

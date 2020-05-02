/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include "dap_common.h"
#include "dap_chain_common.h"

/**
  * @struct dap_chain_datum_hashtree_roots_v1
  * @brief Hash tree roots for block, version 1
  */
typedef struct dap_chain_datum_hashtree_roots_v1{
    dap_chain_hash_fast_t main;
} DAP_ALIGN_PACKED dap_chain_block_roots_v1_t;

/**
  * @struct dap_chain_datum_hashtree_roots_v2
  * @brief Hash tree roots for block, version 2
  */
typedef struct dap_chain_datum_hashtree_roots_v2{
    dap_chain_hash_fast_t main;
    dap_chain_hash_fast_t txs;
} DAP_ALIGN_PACKED dap_chain_datum_hashtree_roots_v2_t;

typedef dap_chain_datum_hashtree_roots_v2_t dap_chain_datum_hashtree_roots_t;


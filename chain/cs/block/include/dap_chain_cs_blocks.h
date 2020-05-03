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

#include "dap_chain.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"

typedef struct dap_chain_cs_blocks
{
    dap_chain_t * chain;
    void * _pvt;
    void * _iheritor;
} dap_chain_cs_blocks_t;

typedef int (*dap_chain_blocks_block_callback_ptr_t)(dap_chain_cs_blocks_t *, dap_chain_block_t *);

int dap_chain_cs_blocks_init();
void dap_chain_cs_blocks_deinit();

dap_chain_block_cache_t* dap_chain_cs_blocks_allocate_next_block(dap_chain_cs_blocks_t * a_cs_blocks);
void dap_chain_cs_blocks_new(dap_chain_t * a_chain);

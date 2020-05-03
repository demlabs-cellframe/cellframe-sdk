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

#include "dap_common.h"
#include "dap_chain_cs_block_poa.h"
#include "dap_chain.h"
#include "dap_chain_cs_blocks.h"

#define LOG_TAG "dap_chain_cs_block_poa"

dap_chain_t *s_callback_chain_new();
void s_callback_delete(dap_chain_t * );
void s_callback_blocks(dap_chain_cs_blocks_t *, dap_chain_block_t * );

int dap_chain_cs_block_poa_init()
{
//    dap_chain_block_cs_add
    return 0;
}

void dap_chain_cs_block_poa_deinit()
{

}

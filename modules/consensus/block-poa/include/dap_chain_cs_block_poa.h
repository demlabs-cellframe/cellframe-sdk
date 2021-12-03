/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Limited https://demlabs.net
 * DAP SDK          https://gitlab.demlabs.net/dap/dap-sdk
 * Copyright  (c) 2017
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#pragma once
#include "dap_chain_cs_blocks.h"

typedef struct dap_chain_cs_block_poa
{
    dap_chain_t * chain;
    dap_chain_cs_blocks_t * blocks;
    void * _pvt;
    void * _inheritor;
} dap_chain_cs_block_poa_t;

#define DAP_CHAIN_CS_BLOCK_POA(a) ( (dap_chain_cs_block_poa_t *) (a)->_inheritor)


int dap_chain_cs_block_poa_init(void);
void dap_chain_cs_block_poa_deinit(void);
dap_cert_t **dap_chain_cs_block_poa_get_auth_certs(dap_chain_t *a_chain, size_t *a_auth_certs_count);

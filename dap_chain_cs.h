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
#define DAP_CHAIN_CS_TYPE_SIZE 2
typedef union dap_chain_cs_type{
    enum {
    DAP_CHAIN_CS_DAG_POA        =  0x0000,
    DAP_CHAIN_CS_BLOCK_POA      = 0xf000,
    DAP_CHAIN_CS_BLOCK_POW      = 0xf001 ,
    DAP_CHAIN_CS_DAG_HASHGRAPG  = 0x0100,
    DAP_CHAIN_CS_DAG_POH        = 0x0101,
    } enums: 16;
    uint8_t raw[DAP_CHAIN_CS_TYPE_SIZE];
}dap_chain_cs_type_t;

typedef void (*dap_chain_cs_callback_t)(dap_chain_t *);

int dap_chain_cs_init();
void dap_chain_cs_deinit();

void dap_chain_cs_add (const char * a_cs_str,  dap_chain_cs_callback_t a_callback_init);
int dap_chain_cs_create(dap_chain_t * a_chain, const char * a_chain_cs_type_str);

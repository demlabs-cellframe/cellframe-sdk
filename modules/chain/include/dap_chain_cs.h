/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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

typedef struct dap_chain_cs dap_chain_cs_t;

typedef struct dap_chain_cs{
    dap_chain_callback_new_t callback_init;
    dap_chain_cs_t * prev;
    dap_chain_cs_t * next;
} dap_chain_cs_t;

int dap_chain_cs_init(void);
void dap_chain_cs_deinit(void);

void dap_chain_cs_add (const char * a_cs_str,  dap_chain_callback_new_cfg_t a_callback_init);
int dap_chain_cs_create(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);

void dap_chain_cs_type_add (const char * a_cs_str,  dap_chain_callback_new_cfg_t a_callback_init);
int dap_chain_cs_type_create(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);

/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
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
#include "dap_chain_dag_event.h"
typedef struct dap_chain_dag
{
    dap_chain_t * chain;
    dap_chain_callback_new_t callback_new;
    dap_chain_callback_t callback_delete;
    dap_chain_dag_event_callback_ptr_t callback_event_input;

    void * _pvt;
    void * _inheritor;
} dap_chain_dag_t;

#define DAP_CHAIN_DAG(a) ( (dap_chain_dag_t *) (a)->_inheritor)

int dap_chain_dag_init();
void dap_chain_dag_deinit();

dap_chain_dag_t *dap_chain_dag_new(dap_chain_t * a_chain);
void dap_chain_dag_delete(dap_chain_dag_t * a_dag);


/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Limited https://demlabs.net
 * CellFrame SDK    https://cellframe.net
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "dap_chain_cs_dag.h"

typedef struct dap_chain_cs_dag_poa
{
    dap_chain_t * chain;
    dap_chain_cs_dag_t * dag;
    void * _pvt;
    void * _inheritor;
} dap_chain_cs_dag_poa_t;

#define DAP_CHAIN_CS_DAG_POA(a) ( (dap_chain_cs_dag_poa_t *) (a)->_inheritor)


int dap_chain_cs_dag_poa_init(void);
void dap_chain_cs_dag_poa_deinit(void);

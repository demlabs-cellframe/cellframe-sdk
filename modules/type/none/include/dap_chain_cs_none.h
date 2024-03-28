/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

 DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

typedef struct dap_nonconsensus {
    dap_chain_t *chain;
    void * _internal; // private data
    void * _inheritor; // inheritor object
} dap_nonconsensus_t;

#define DAP_NONCONSENSUS(a) ((a) ? (dap_nonconsensus_t *)(a)->_inheritor : NULL)

int dap_nonconsensus_init(void);
const char* dap_nonconsensus_get_group(dap_chain_t * a_chain);

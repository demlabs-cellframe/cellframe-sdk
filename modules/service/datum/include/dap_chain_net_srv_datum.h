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

#include "dap_common.h"
#include "dap_chain_net.h"

#define DAP_CHAIN_NET_SRV_DATUM_ID 0x5

int dap_chain_net_srv_datum_init();
void dap_chain_net_srv_datum_deinit();

uint8_t * dap_chain_net_srv_file_datum_data_read(char * a_path, size_t *a_data_size);
char* dap_chain_net_srv_datum_custom_add(dap_chain_t * a_chain, const uint8_t *a_data, size_t a_data_size);

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

#include <stdint.h>

#include "dap_chain_common.h"
#include "dap_enc_key.h"


/**
 * Make transfer transaction & insert to cache
 *
 * return 1 Ok, 0 Invalid signature, -1 Not found signature or other Error
 */
int dap_chain_datum_tx_ctrl_create_transfer(dap_enc_key_t *a_key_from,
        dap_chain_addr_t* a_addr_from, dap_chain_addr_t* a_addr_to, dap_chain_addr_t* a_addr_fee,
        uint64_t a_value, uint64_t a_value_fee);


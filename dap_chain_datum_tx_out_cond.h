/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include <stdint.h>
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"

/**
 * @struct dap_chain_tx_out
 * @brief Transaction item out_cond
 */
typedef struct dap_chain_tx_out_cond {
    struct {
        dap_chain_tx_item_type_t type :8; // Transaction item type
        uint64_t value; // Number of Datoshis ( DAP/10^9 ) to be reserver for service
        uint32_t pub_key_size; /// Public key size
        uint32_t cond_size; /// Condition parameters size
    } header;
    dap_chain_addr_t addr; // wallet address, whose owner can use the service
    uint8_t data[]; // serialized public key + condition parameters dap_chain_net_srv_abstract
}DAP_ALIGN_PACKED dap_chain_tx_out_cond_t;

uint8_t* dap_chain_datum_tx_out_cond_item_get_pkey(dap_chain_tx_out_cond_t *a_tx_out_cond, size_t *a_pkey_size_out);

uint8_t* dap_chain_datum_tx_out_cond_item_get_cond(dap_chain_tx_out_cond_t *a_tx_out_cond, size_t *a_cond_size_out);



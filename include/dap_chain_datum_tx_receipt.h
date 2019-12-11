/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
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
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <stdint.h>
#include "dap_chain_common.h"

/**
 * @struct dap_chain_tx_out
 * @brief Transaction item out_cond
 */
typedef struct dap_chain_datum_tx_receipt {
    dap_chain_tx_item_type_t type :8; // Transaction item type
    dap_chain_receipt_t receipt; // Receipt itself
    uint16_t size;
    byte_t signs[]; // Signatures, first from provider, second from client
}DAP_ALIGN_PACKED dap_chain_datum_tx_receipt_t;

dap_chain_datum_tx_receipt_t * dap_chain_datum_tx_receipt_create( dap_chain_net_srv_uid_t srv_uid,
                                                                  dap_chain_net_srv_price_unit_uid_t units_type,
                                                                    uint64_t units, uint64_t value_datoshi);
size_t dap_chain_datum_tx_receipt_sign_add(dap_chain_datum_tx_receipt_t * a_receipt, size_t a_receipt_size, dap_enc_key_t *a_key );
dap_sign_t* dap_chain_datum_tx_receipt_sign_get(dap_chain_datum_tx_receipt_t * l_receipt, size_t l_receipt_size , uint16_t sign_position);
uint16_t dap_chain_datum_tx_receipt_signs_count(dap_chain_datum_tx_receipt_t * l_receipt, size_t l_receipt_size);
static inline uint16_t dap_chain_datum_tx_receipt_get_size(const dap_chain_datum_tx_receipt_t * l_receipt)
{
    return l_receipt->size;
}


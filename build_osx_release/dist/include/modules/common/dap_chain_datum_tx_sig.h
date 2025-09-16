/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
  * @struct dap_chain_tx_sig
  * @brief Section with set of transaction signatures
  */
typedef struct dap_chain_tx_sig{
    struct {
        dap_chain_tx_item_type_t type; /// @param    type            @brief Transaction item type
        uint8_t version DAP_ALIGNED(1);
        uint32_t sig_size DAP_ALIGNED(4); /// Signature size
    } DAP_PACKED header; /// Only header's hash is used for verification
    uint8_t sig[]; /// @param sig @brief raw signature data
} DAP_PACKED dap_chain_tx_sig_t;

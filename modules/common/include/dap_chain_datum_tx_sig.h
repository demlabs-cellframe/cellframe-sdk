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
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"


/**
  * @struct dap_chain_tx_sig
  * @brief Section with set of transaction signatures
  */
typedef struct dap_chain_tx_sig{
    struct {
        dap_chain_tx_item_type_t type:8; /// @param    type            @brief Transaction item type
//        dap_sign_type_t sig_type; /// Signature type
        uint32_t sig_size; /// Signature size
    } header; /// Only header's hash is used for verification
    uint8_t sig[]; /// @param sig @brief raw signature data
} DAP_ALIGN_PACKED dap_chain_tx_sig_t;

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
#include "dap_math_ops.h"
#include "dap_chain_common.h"

/// End section, means all the rest of the block is empty
#define dap_chain_datum_END                 0x0000
/// Section with additional roots, for example transaction roots
#define dap_chain_datum_hashtree_roots 0x0001

/// Transaction header section
#define dap_chain_datum_TX                  0x0100

/// Transaction request section
#define dap_chain_datum_TX_REQUEST          0x0300

/// Smart contract: DVM code section
#define dap_chain_datum_DVM_CODE            0x0900
/// Smart contract: DVM code section
#define dap_chain_datum_DVM_DATA            0x0901

/// Smart contract: EVM code section
#define dap_chain_datum_EVM_CODE            0x0910

/// Smart contract: EVM data section
#define dap_chain_datum_EVM_DATA            0x0911

/// Pub key section, with sign and address
#define dap_chain_datum_PKEY                0x0c00


/// Coin
#define dap_chain_datum_COIN                0xf000

/**
  * @struct dap_chain_block_section
  * @brief section inside the block
  */

typedef struct dap_chain_datum{
    uint16_t type; // Section type
    uint8_t data[]; // data
} DAP_ALIGN_PACKED dap_chain_datum_t;



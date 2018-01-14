/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

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


/**
  * @struct dap_chain_block_section
  * @brief section inside the block
  */
#pragma once
#include <stdint.h>
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"


/// End section, means all the rest of the block is empty
#define DAP_CHAIN_SECTION_END                 0x0000

/// Transaction header section
#define DAP_CHAIN_SECTION_TX                  0x0100

/// Transaction request section
#define DAP_CHAIN_SECTION_TX_REQUEST          0x0300

/// Smart contract: DVM code section
#define DAP_CHAIN_SECTION_DVM_CODE            0x0900
/// Smart contract: DVM code section
#define DAP_CHAIN_SECTION_DVM_DATA            0x0901

/// Smart contract: EVM code section
#define DAP_CHAIN_SECTION_EVM_CODE            0x0910

/// Smart contract: EVM data section
#define DAP_CHAIN_SECTION_EVM_CODE            0x0911

/// Pub key section, with sign and address
#define DAP_CHAIN_SECTION_PKEY                0x0c00

/// Section with additional roots, for example transaction roots
#define DAP_CHAIN_SECTION_ROOTS 0xf000

/// Coin
#define DAP_CHAIN_SECTION_COIN                0xffff




typedef struct dap_chain_block_section{
    uint16_t type; // Section type
    uint8_t data[]; // data
} DAP_ALIGN_PACKED dap_chain_block_section_t;

inline uint32_t

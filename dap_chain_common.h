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

#define DAP_CHAIN_HASH_SIZE 64

typedef union dap_chain_hash{
    uint8_t data[DAP_CHAIN_HASH_SIZE];
} dap_chain_hash_t;


typedef union dap_chain_sig_type{
    enum {
        SIG_TYPE_NEWHOPE = 0x0000,
        SIG_TYPE_MULTI = 0xffff ///  @brief Has inside subset of different signatures and sign composed with all of them

    } type: 16;
    uint16_t raw;
} dap_chain_sig_type_t;


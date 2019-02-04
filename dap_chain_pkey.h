/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
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

#include <stdint.h>
#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"

static dap_chain_pkey_t m_dap_chain_pkey_null; // For sizeof nothing more

dap_chain_pkey_t *dap_chain_pkey_from_enc_key(dap_enc_key_t *a_key);
static inline size_t dap_chain_pkey_from_enc_key_output_calc(dap_enc_key_t *a_key)
{
    return sizeof(m_dap_chain_pkey_null.header)+ a_key->pub_key_data_size;
}

int dap_chain_pkey_from_enc_key_output(dap_enc_key_t *a_key, void * a_output);

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
#include "dap_chain_common.h"
typedef struct dap_chain_wallet{
    void * _internal;
    void * _inheritor;
} dap_chain_wallet_t;

dap_chain_wallet_t * dap_chain_wallet_open(const char * a_file_name, dap_chain_sig_type_t a_sig_type); // Creates new one if not found
void dap_chain_wallet_close( dap_chain_wallet_t * a_wallet);

int dap_chain_wallet_get_pkey( dap_chain_wallet_t * a_wallet,uint32_t a_pkey_idx, void * a_pkey, size_t a_pkey_size_max);

int dap_chain_wallet_sign( dap_chain_wallet_t * a_wallet,uint32_t a_pkey_idx, const void * a_data, size_t a_data_size, void * a_sign, size_t a_sign_size_max);


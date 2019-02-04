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
#include "dap_enc_key.h"
#include "dap_chain_pkey.h"
#include "dap_chain_sign.h"
#include "dap_chain_net.h"

typedef struct dap_chain_wallet{
    char * name;
    void * _internal;
    void * _inheritor;
} dap_chain_wallet_t;


int dap_chain_wallet_init();
void dap_chain_wallet_deinit();

dap_chain_wallet_t * dap_chain_wallet_create(const char * a_wallet_name, const char * a_wallets_path, dap_chain_net_id_t a_net_id,
                                             dap_chain_sign_type_t a_sig_type); // Creates new one if not found
dap_chain_wallet_t * dap_chain_wallet_open_file(const char * a_file_name);
dap_chain_wallet_t * dap_chain_wallet_open(const char * a_wallet_name, const char * a_wallets_path);
int dap_chain_wallet_save(dap_chain_wallet_t * a_wallet);

void dap_chain_wallet_close( dap_chain_wallet_t * a_wallet);

size_t dap_chain_wallet_get_certs_number( dap_chain_wallet_t * a_wallet);
dap_chain_pkey_t * dap_chain_wallet_get_pkey( dap_chain_wallet_t * a_wallet,uint32_t a_key_idx);
dap_enc_key_t * dap_chain_wallet_get_key( dap_chain_wallet_t * a_wallet,uint32_t a_key_idx);

int dap_chain_wallet_save_file( dap_chain_wallet_t * a_wallet);

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
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_enc_key.h"
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_cert.h"


/* @RRL: #6131 */
#define DAP_WALLET$SZ_NAME  64                                              /* Maximum length of the wallet's name */
#define DAP_WALLET$SZ_PASS  64                                              /* Maximum length of the wallet's password */

#define DAP_WALLET$M_FL_PROTECTED        (1 << 0)                           /* Wallet is password protected */
#define DAP_WALLET$M_FL_ACTIVE           (1 << 1)                           /* Has been activated (has been open with password) */

typedef struct dap_chain_wallet{
    char        name[ DAP_WALLET$SZ_NAME + 1 ];                             /* Human readable name of BMF Wallet */
    uint64_t    flags;                                                      /* See DAP_WALLET$M_FL_* constants */
    void        *_internal;
    void        *_inheritor;
} dap_chain_wallet_t;


int dap_chain_wallet_init();
void dap_chain_wallet_deinit(void);

const char* dap_chain_wallet_get_path(dap_config_t * a_config);

/* @RRL: #6131 - Password protected BMF Wallet */
dap_chain_wallet_t * dap_chain_wallet_create_with_seed(const char * a_wallet_name, const char * a_wallets_path,
        dap_sign_type_t a_sig_type, const void* a_seed, size_t a_seed_size, const char *a_pass);

dap_chain_wallet_t * dap_chain_wallet_create_with_pass(const char * a_wallet_name, const char * a_wallets_path,
        const void* a_pass, size_t a_pass_sz);


dap_chain_wallet_t  *dap_chain_wallet_create(const char * a_wallet_name, const char * a_wallets_path, dap_sign_type_t a_sig_type, const char *a_pass); // Creates new one if not found
dap_chain_wallet_t  *dap_chain_wallet_open_file(const char * a_file_name, const char *a_pass);
dap_chain_wallet_t *dap_chain_wallet_open(const char * a_wallet_name, const char * a_wallets_path);
dap_chain_wallet_t *dap_chain_wallet_open_ext(const char * a_wallet_name, const char * a_wallets_path, const char *pass);
int dap_chain_wallet_save(dap_chain_wallet_t * a_wallet, const char *a_pass);

void dap_chain_wallet_close( dap_chain_wallet_t * a_wallet);

dap_chain_addr_t * dap_cert_to_addr(dap_cert_t * a_cert, dap_chain_net_id_t a_net_id);

dap_chain_addr_t* dap_chain_wallet_get_addr(dap_chain_wallet_t * a_wallet, dap_chain_net_id_t a_net_id);
size_t dap_chain_wallet_get_certs_number( dap_chain_wallet_t * a_wallet);
dap_pkey_t * dap_chain_wallet_get_pkey( dap_chain_wallet_t * a_wallet,uint32_t a_key_idx);
dap_enc_key_t * dap_chain_wallet_get_key( dap_chain_wallet_t * a_wallet,uint32_t a_key_idx);

uint256_t dap_chain_wallet_get_balance(dap_chain_wallet_t *a_wallet, dap_chain_net_id_t a_net_id, const char *a_token_ticker);

int dap_chain_wallet_save_file( dap_chain_wallet_t * a_wallet);

int dap_chain_wallet_activate   (const char *a_name, ssize_t a_name_len, const char *a_pass, ssize_t a_pass_len, unsigned a_ttl);
int dap_chain_wallet_deactivate   (const char *a_name, ssize_t a_name_len);

const char* dap_chain_wallet_check_bliss_sign(dap_chain_wallet_t *a_wallet);
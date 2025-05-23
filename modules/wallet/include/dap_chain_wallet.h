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
#include "dap_config.h"
#include "dap_chain_common.h"
#include "dap_enc_key.h"
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_cert.h"
#include "dap_chain_ledger.h"

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

typedef void (*dap_chain_wallet_opened_callback_t)(dap_chain_wallet_t *a_wallet, void *a_arg);
#ifdef __cplusplus
extern "C" {
#endif

int dap_chain_wallet_init();
void dap_chain_wallet_deinit(void);

const char* dap_chain_wallet_get_path(dap_config_t * a_config);

/* @RRL: #6131 - Password protected BMF Wallet */

dap_chain_wallet_t * dap_chain_wallet_create_with_seed_multi(const char * a_wallet_name, const char * a_wallets_path,
        const dap_sign_type_t *a_sig_types, size_t a_sig_count, const void* a_seed, size_t a_seed_size, const char *a_pass);

DAP_STATIC_INLINE dap_chain_wallet_t * dap_chain_wallet_create_with_seed(const char * a_wallet_name, const char * a_wallets_path,
        dap_sign_type_t a_sig_type, const void* a_seed, size_t a_seed_size, const char *a_pass) {
                return dap_chain_wallet_create_with_seed_multi(a_wallet_name, a_wallets_path, &a_sig_type, 1, a_seed, a_seed_size, a_pass);
        }

dap_chain_wallet_t * dap_chain_wallet_create_with_pass(const char * a_wallet_name, const char * a_wallets_path,
        const void* a_pass, size_t a_pass_sz);

dap_chain_wallet_t  *dap_chain_wallet_create(const char * a_wallet_name, const char * a_wallets_path, dap_sign_type_t a_sig_type, const char *a_pass); // Creates new one if not found
dap_chain_wallet_t  *dap_chain_wallet_open_file(const char * a_file_name, const char *a_pass, unsigned int *a_out_stat);
dap_chain_wallet_t *dap_chain_wallet_open(const char * a_wallet_name, const char * a_wallets_path, unsigned int * a_out_stat);
dap_chain_wallet_t *dap_chain_wallet_open_ext(const char * a_wallet_name, const char * a_wallets_path, const char *pass);
int dap_chain_wallet_save(dap_chain_wallet_t * a_wallet, const char *a_pass);

void dap_chain_wallet_close(dap_chain_wallet_t *a_wallet);

dap_chain_addr_t *dap_cert_to_addr(dap_cert_t **a_certs, size_t a_count, size_t a_key_start_index, dap_chain_net_id_t a_net_id);

dap_chain_addr_t* dap_chain_wallet_get_addr(dap_chain_wallet_t * a_wallet, dap_chain_net_id_t a_net_id);
size_t dap_chain_wallet_get_certs_number( dap_chain_wallet_t * a_wallet);
dap_pkey_t * dap_chain_wallet_get_pkey( dap_chain_wallet_t * a_wallet,uint32_t a_key_idx);
dap_enc_key_t *dap_chain_wallet_get_key(dap_chain_wallet_t *a_wallet, uint32_t a_key_idx);

uint256_t dap_chain_wallet_get_balance(dap_chain_wallet_t *a_wallet, dap_chain_net_id_t a_net_id, const char *a_token_ticker);

int dap_chain_wallet_save_file( dap_chain_wallet_t * a_wallet);

int dap_chain_wallet_activate   (const char *a_name, ssize_t a_name_len, const char *a_path, const char *a_pass, ssize_t a_pass_len, unsigned a_ttl);
int dap_chain_wallet_deactivate   (const char *a_name, ssize_t a_name_len);

const char* dap_chain_wallet_check_sign(dap_chain_wallet_t *a_wallet);
const char *dap_chain_wallet_addr_cache_get_name(dap_chain_addr_t *a_addr);
json_object *dap_chain_wallet_info_to_json(const char *a_name, const char *a_path);

int dap_chain_wallet_get_pkey_hash(dap_chain_wallet_t *a_wallet, dap_hash_fast_t *a_out_hash);

int dap_chain_wallet_add_wallet_opened_notify(dap_chain_wallet_opened_callback_t a_callback, void *a_arg);
int dap_chain_wallet_add_wallet_created_notify(dap_chain_wallet_opened_callback_t a_callback, void *a_arg);
dap_list_t* dap_chain_wallet_get_local_addr();

int dap_chain_wallet_get_pkey_hash(dap_chain_wallet_t *a_wallet, dap_hash_fast_t *a_out_hash);
char *dap_chain_wallet_get_pkey_str(dap_chain_wallet_t *a_wallet, const char *a_str_type);
#ifdef __cplusplus
}
#endif

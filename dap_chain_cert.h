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

#include "dap_chain_common.h"
#include "dap_chain_sign.h"
#include "dap_chain_pkey.h"

#include "dap_enc.h"
#include "dap_enc_key.h"

#define DAP_CHAIN_CERT_ITEM_NAME_MAX 40

typedef struct dap_chain_cert {
    dap_enc_key_t * key_private;
    char name[DAP_CHAIN_CERT_ITEM_NAME_MAX];
    void * _pvt;
    char * metadata;
} dap_chain_cert_t;

int dap_chain_cert_init();


dap_chain_cert_t * dap_chain_cert_new(const char * a_name);

dap_chain_cert_t * dap_chain_cert_generate(const char * a_cert_name,const char * a_file_path,dap_enc_key_type_t a_key_type );

dap_chain_cert_t * dap_chain_cert_generate_mem(const char * a_cert_name,
                                               dap_enc_key_type_t a_key_type );

dap_chain_addr_t * dap_chain_cert_to_addr(dap_chain_cert_t * a_cert, dap_chain_net_id_t a_net_id);

dap_chain_cert_t * dap_chain_cert_add_file(const char * a_cert_name,const char *a_file_path);
void dap_chain_cert_add_folder(const char* a_cert_name_prefix,const char *a_folder_path);
void dap_chain_cert_dump(dap_chain_cert_t * a_cert);
dap_chain_pkey_t * dap_chain_cert_to_pkey(dap_chain_cert_t * a_cert);

dap_chain_cert_t * dap_chain_cert_find_by_name(const char * a_cert_name);

dap_chain_sign_t * dap_chain_cert_sign(dap_chain_cert_t * a_cert, const void * a_data, size_t a_data_size, size_t a_output_size_wished );

size_t dap_chain_cert_sign_output_size(dap_chain_cert_t * a_cert, size_t a_size_wished);


int dap_chain_cert_sign_output(dap_chain_cert_t * a_cert, const void * a_data, size_t a_data_size
                                        , void * a_output , size_t a_output_size);


int dap_chain_cert_add_cert_sign(dap_chain_cert_t * a_cert, dap_chain_cert_t * a_cert_signer);

size_t dap_chain_cert_count_cert_sign(dap_chain_cert_t * a_cert);

void dap_chain_cert_deinit();

void dap_chain_cert_delete(dap_chain_cert_t * a_cert);
void dap_chain_cert_delete_by_name(const char * a_cert_name);

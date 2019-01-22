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
#include "dap_chain_sign.h"
#include "dap_chain_pkey.h"
#include "dap_enc.h"
#include "dap_enc_key.h"


typedef struct dap_chain_cert {
    dap_enc_key_t * key_private;
    void * _pvt;
} dap_chain_cert_t;

int dap_chain_cert_init();


dap_chain_cert_t * dap_chain_cert_generate(const char * a_cert_name,const char * a_file_path,dap_enc_key_type_t a_key_type );

dap_chain_cert_t * dap_chain_cert_add_file(const char * a_cert_name,const char *a_file_path);
void dap_chain_cert_add_folder(const char* a_cert_name_prefix,const char *a_folder_path);
void dap_chain_cert_dump(dap_chain_cert_t * a_cert);

void dap_chain_cert_deinit();

void dap_chain_cert_delete(const char * a_cert_name);

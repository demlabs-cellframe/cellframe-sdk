/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ENC_KS_H_
#define _ENC_KS_H_
#include <time.h>
#include <pthread.h>
#include "uthash.h"
#include "dap_enc_key.h"
#include "stdbool.h"
#include "dap_hash.h"

#define DAP_ENC_KS_KEY_ID_SIZE 33
struct dap_http_client;
typedef struct dap_enc_key dap_enc_key_t;
typedef struct dap_enc_ks_key{
    char id[DAP_ENC_KS_KEY_ID_SIZE];
    dap_enc_key_t *key;
    time_t time_created;
    pthread_mutex_t mutex;
    uint8_t *acl_list;
	uint8_t *acl_bugreport;
    UT_hash_handle hh; // makes this structure hashable with UTHASH library
} dap_enc_ks_key_t;

void dap_enc_ks_deinit();

dap_enc_ks_key_t * dap_enc_ks_find(const char * v_id);
dap_enc_key_t * dap_enc_ks_find_http(struct dap_http_client * http);

dap_enc_ks_key_t * dap_enc_ks_new();
dap_enc_ks_key_t * dap_enc_ks_add(struct dap_enc_key * key);

bool dap_enc_ks_save_in_storage(dap_enc_ks_key_t* key);
void dap_enc_ks_delete(const char *id);

#endif

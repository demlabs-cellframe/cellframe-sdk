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
struct dap_http_client;

struct enc_key;
typedef struct enc_ks_key{
    char id[33];
    struct enc_key *key;
    time_t time_created;
    pthread_mutex_t mutex;
    UT_hash_handle hh; // makes this structure hashable with UTHASH library
} enc_ks_key_t;

extern int enc_ks_init();
extern void enc_ks_deinit();

extern enc_ks_key_t * enc_ks_find(const char * v_id);
extern struct enc_key * enc_ks_find_http(struct dap_http_client * http);

//extern enc_ks_key_t * enc_ks_new();
extern enc_ks_key_t * enc_ks_add(struct enc_key * key);
extern void enc_ks_delete(const char *id);

#endif

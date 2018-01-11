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

#include "uthash.h"
#include "common.h"

#include "dap_http_client.h"
#include "dap_http_header.h"

#include "enc.h"
#include "enc_ks.h"
#include "enc_key.h"

#define LOG_TAG "enc_ks"

enc_ks_key_t * ks=NULL;

int enc_ks_init()
{
    return 0;
}

void _enc_key_free(enc_ks_key_t **ptr);

void enc_ks_deinit()
{
    if (ks) {
        enc_ks_key_t *cur_item, *tmp;
        HASH_ITER(hh, ks, cur_item, tmp) {
            HASH_DEL(ks, cur_item);
            _enc_key_free(&cur_item);
        }
    }
}

enc_ks_key_t * enc_ks_find(const char * v_id)
{
    enc_ks_key_t * ret=NULL;
    HASH_FIND_STR(ks,v_id,ret);
    return ret;
}

enc_key_t * enc_ks_find_http(struct dap_http_client * http)
{
    dap_http_header_t * hdr_key_id=dap_http_header_find(http->in_headers,"KeyID");
    if(hdr_key_id){
        enc_ks_key_t * ks_key=enc_ks_find(hdr_key_id->value);
        if(ks_key)
            return ks_key->key;
        else{
            //log_it(WARNING, "Not found keyID");
            return NULL;
        }
    }else{
        log_it(WARNING, "No KeyID in HTTP headers");
        return NULL;
    }
}


/*enc_ks_key_t * enc_ks_new()
{
    enc_ks_key_t * ret = DAP_NEW_Z(enc_ks_key_t);
    ret->key=enc_key_new()
    int i;
    for(i=0;i<sizeof(ret->id)-1;i++)
        ret->id[i]=65+rand()%25;
    HASH_ADD_STR(ks,id,ret);
    return ret;
}*/

enc_ks_key_t * enc_ks_add(struct enc_key * key)
{
    enc_ks_key_t * ret = DAP_NEW_Z(enc_ks_key_t);
    ret->key=key;
    pthread_mutex_init(&ret->mutex,NULL);
    int i;
    for(i=0;i<sizeof(ret->id)-1;i++)
        ret->id[i]=65+rand()%25;
    HASH_ADD_STR(ks,id,ret);
    return ret;
}

void enc_ks_delete(const char *id)
{
    enc_ks_key_t *delItem = enc_ks_find(id);
    if (delItem) {
        HASH_DEL (ks, delItem);
        _enc_key_free(&delItem);
    }
}

void _enc_key_free(enc_ks_key_t **ptr)
{
    if (*ptr){
        if((*ptr)->key)
            enc_key_delete((*ptr)->key);
        free (*ptr);
        //*ptr = NULL; //not need
    }
}

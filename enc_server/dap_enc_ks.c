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
#include "dap_common.h"

#include "../http_server/http_client/dap_http_client.h"
#include "../http_server/http_client/dap_http_header.h"

#include "dap_enc.h"
#include "dap_enc_ks.h"
#include "dap_enc_key.h"
#include "dap_memcached.h"

#define LOG_TAG "enc_ks"

static dap_enc_ks_key_t * _ks = NULL;
static bool _memcache_enable = false;

int dap_enc_ks_init(bool memcache_backup_enable)
{
    if(memcache_backup_enable) {
        if(dap_memcache_is_enable()) {
            _memcache_enable = true;
        } else {
            log_it(L_ERROR, "Can't init memcache backup. Memcache module is not activated.");
            return -1;
        }
    }
    return 0;
}

void _enc_key_free(dap_enc_ks_key_t **ptr);

void dap_enc_ks_deinit()
{
    if (_ks) {
        dap_enc_ks_key_t *cur_item, *tmp;
        HASH_ITER(hh, _ks, cur_item, tmp) {
            HASH_DEL(_ks, cur_item);
            _enc_key_free(&cur_item);
        }
    }
}

inline static void _gen_session_id(char id_buf[DAP_ENC_KS_KEY_ID_SIZE])
{
    for(short i = 0; i < DAP_ENC_KS_KEY_ID_SIZE; i++)
        id_buf[i] = 65 + rand() % 25;
}

void _save_key_in_storge(dap_enc_ks_key_t *key)
{
    HASH_ADD_STR(_ks,id,key);
    if(_memcache_enable) {
        dap_enc_key_serealize_t* serealize_key = dap_enc_key_serealize(key->key);
        dap_memcache_put(key->id, serealize_key, sizeof (dap_enc_key_serealize_t), 0);
        free(serealize_key);
    }
}


dap_enc_ks_key_t * dap_enc_ks_find(const char * v_id)
{
    dap_enc_ks_key_t * ret = NULL;
    HASH_FIND_STR(_ks,v_id,ret);
    if(ret == NULL) {
        if(_memcache_enable) {
            void* key_buf;
            size_t val_length;
            bool find = dap_memcache_get(v_id, &val_length, (void**)&key_buf);
            if(find) {
                if(val_length != sizeof (dap_enc_key_serealize_t)) {
                    log_it(L_WARNING, "Data can be broken");
                }
                dap_enc_key_t* key = dap_enc_key_deserealize(key_buf, val_length);
                ret = DAP_NEW_Z(dap_enc_ks_key_t);
                strncpy(ret->id, v_id, DAP_ENC_KS_KEY_ID_SIZE);
                pthread_mutex_init(&ret->mutex,NULL);
                ret->key = key;
                HASH_ADD_STR(_ks,id,ret);
                free(key_buf);
                return ret;
            }
        }
        log_it(L_WARNING, "Key not found");
    }
    return ret;
}

dap_enc_key_t * dap_enc_ks_find_http(struct dap_http_client * http)
{
    dap_http_header_t * hdr_key_id=dap_http_header_find(http->in_headers,"KeyID");

    if(hdr_key_id){
        
        dap_enc_ks_key_t * ks_key=dap_enc_ks_find(hdr_key_id->value);
        if(ks_key)
            return ks_key->key;
        else{
            log_it(L_WARNING, "Not found keyID %s in storage", hdr_key_id->value);
            return NULL;
        }
    }else{
        log_it(L_WARNING, "No KeyID in HTTP headers");
        return NULL;
    }
}

dap_enc_ks_key_t * dap_enc_ks_new()
{
    dap_enc_ks_key_t * ret = DAP_NEW_Z(dap_enc_ks_key_t);
    _gen_session_id(ret->id);
    pthread_mutex_init(&ret->mutex,NULL);
    return ret;
}

bool dap_enc_ks_save_in_storage(dap_enc_ks_key_t* key)
{
    if(dap_enc_ks_find(key->id) != NULL) {
        log_it(L_WARNING, "key is already saved in storage");
        return false;
    }
    _save_key_in_storge(key);
    return true;
}

dap_enc_ks_key_t * dap_enc_ks_add(struct dap_enc_key * key)
{
    dap_enc_ks_key_t * ret = DAP_NEW_Z(dap_enc_ks_key_t);
    ret->key = key;
    pthread_mutex_init(&ret->mutex, NULL);
    _gen_session_id(ret->id);
    dap_enc_ks_save_in_storage(ret);
    return ret;
}

void dap_enc_ks_delete(const char *id)
{
    dap_enc_ks_key_t *delItem = dap_enc_ks_find(id);
    if (delItem) {
        HASH_DEL (_ks, delItem);
        if(_memcache_enable && dap_memcache_delete(id) == false) {
            log_it(L_WARNING, "Cant delete key from memcache. Not found");
        }
        _enc_key_free(&delItem);
        return;
    }
    log_it(L_WARNING, "Can't delete key by id: %s. Key not found", id);
}

void _enc_key_free(dap_enc_ks_key_t **ptr)
{
    if (*ptr){
        if((*ptr)->key)
            dap_enc_key_delete((*ptr)->key);
        free (*ptr);
        //*ptr = NULL; //not need
    }
}

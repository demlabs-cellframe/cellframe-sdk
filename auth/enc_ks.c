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
    enc_ks_key_t * ret = CALLOC(enc_ks_key_t);
    ret->key=enc_key_new()
    int i;
    for(i=0;i<sizeof(ret->id)-1;i++)
        ret->id[i]=65+rand()%25;
    HASH_ADD_STR(ks,id,ret);
    return ret;
}*/

enc_ks_key_t * enc_ks_add(struct enc_key * key)
{
    enc_ks_key_t * ret = CALLOC(enc_ks_key_t);
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

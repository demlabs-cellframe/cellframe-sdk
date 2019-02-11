#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
//#include <dap_http_simple.h>
//#include <http_status_code.h>
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
//#include "dap_enc_http.h"
#include "dap_enc_http.h"
//#include "dap_http.h"
#include "http_status_code.h"
#include "dap_chain_common.h"
#include "dap_chain_node.h"//#include "dap_chain_global_db.h"
#include "dap_enc.h"
#include <dap_enc_http.h>
#include <dap_enc_key.h>
#include <dap_enc_ks.h>
#include "dap_chain_mempool.h"

#define LOG_TAG "MEMPOOL"

uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool, size_t *size)
{
    size_t a_request_size = 2 * sizeof(uint16_t), shift_size = 0;
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        a_request_size += _dap_chain_datum_data_size(datum_mempool->data[i]) + sizeof(uint16_t);
    }
    uint8_t *a_request = DAP_NEW_SIZE(uint8_t, a_request_size);
    memcpy(a_request + shift_size, &(datum_mempool->version), sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    memcpy(a_request + shift_size, &(datum_mempool->datum_count), sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        size_t size_one = _dap_chain_datum_data_size(datum_mempool->data[i]);
        memcpy(a_request + shift_size, &size_one, sizeof(uint16_t));
        shift_size += sizeof(uint16_t);
        memcpy(a_request + shift_size, datum_mempool->data[i], size_one);
        shift_size += size_one;
    }
    assert(shift_size == a_request_size);
    if(size)
        *size = a_request_size;
    return a_request;
}

dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *datum_mempool_str_in, size_t datum_mempool_size)
{
    size_t shift_size = 0;
    uint8_t *datum_mempool_str = DAP_NEW_Z_SIZE(uint8_t, datum_mempool_size / 2 + 1);
    datum_mempool_size = hex2bin(datum_mempool_str, datum_mempool_str_in, datum_mempool_size) / 2;
    dap_datum_mempool_t *datum_mempool = DAP_NEW_Z(dap_datum_mempool_t);
    memcpy(&(datum_mempool->version), datum_mempool_str + shift_size, sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    memcpy(&(datum_mempool->datum_count), datum_mempool_str + shift_size, sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    datum_mempool->data = DAP_NEW_Z_SIZE(dap_chain_datum_t*, datum_mempool->datum_count * sizeof(dap_chain_datum_t*));
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        size_t size_one = 0;
        memcpy(&size_one, datum_mempool_str + shift_size, sizeof(uint16_t));
        shift_size += sizeof(uint16_t);
        datum_mempool->data[i] = (dap_chain_datum_t*) DAP_NEW_Z_SIZE(uint8_t, size_one);
        memcpy(datum_mempool->data[i], datum_mempool_str + shift_size, size_one);
        shift_size += size_one;
        datum_mempool->data[i];
    }
    assert(shift_size == datum_mempool_size);
    DAP_DELETE(datum_mempool_str);
    return datum_mempool;
}

void dap_datum_mempool_clean(dap_datum_mempool_t *datum)
{
    if(!datum)
        return;
    for(int i = 0; i < datum->datum_count; i++) {
        DAP_DELETE(datum->data[i]);
    }
    DAP_DELETE(datum->data);
    datum->data = NULL;
}

void dap_datum_mempool_free(dap_datum_mempool_t *datum)
{
    dap_datum_mempool_clean(datum);
    DAP_DELETE(datum);
}

/**
 *
 */
static char* calc_datum_hash(const char *datum_str, size_t datum_size)
{
    dap_chain_hash_t a_hash;
    dap_hash((char*) datum_str, datum_size, a_hash.raw, sizeof(a_hash.raw), DAP_HASH_TYPE_SLOW_0);
    size_t a_str_max = (sizeof(a_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
    size_t hash_len = dap_chain_hash_to_str(&a_hash, a_str, a_str_max);
    if(!hash_len) {
        DAP_DELETE(a_str);
        return NULL ;
    }
    return a_str;
}

static void enc_http_reply_encode_new(struct dap_http_simple *a_http_simple, dap_enc_key_t * key,
        enc_http_delegate_t * a_http_delegate)
{
    //dap_enc_key_t * key = dap_enc_ks_find_http(a_http_simple->http);
    if(key == NULL) {
        log_it(L_ERROR, "Can't find http key.");
        return;
    }
    if(a_http_delegate->response) {

        if(a_http_simple->reply)
            free(a_http_simple->reply);

        size_t l_reply_size_max = dap_enc_code_out_size(a_http_delegate->key,
                a_http_delegate->response_size,
                DAP_ENC_DATA_TYPE_RAW);

        a_http_simple->reply = DAP_NEW_SIZE(void, l_reply_size_max);
        a_http_simple->reply_size = dap_enc_code(a_http_delegate->key,
                a_http_delegate->response, a_http_delegate->response_size,
                a_http_simple->reply, l_reply_size_max,
                DAP_ENC_DATA_TYPE_RAW);

        /*/ decode test
         size_t l_response_dec_size_max = a_http_simple->reply_size ? a_http_simple->reply_size * 2 + 16 : 0;
         char * l_response_dec = a_http_simple->reply_size ? DAP_NEW_Z_SIZE(char, l_response_dec_size_max) : NULL;
         size_t l_response_dec_size = 0;
         if(a_http_simple->reply_size)
         l_response_dec_size = dap_enc_decode(a_http_delegate->key,
         a_http_simple->reply, a_http_simple->reply_size,
         l_response_dec, l_response_dec_size_max,
         DAP_ENC_DATA_TYPE_RAW);
         l_response_dec_size_max = 0;*/
    }

}

/**
 * @brief
 * @param cl_st HTTP server instance
 * @param arg for return code
 */
void chain_mempool_proc(struct dap_http_simple *cl_st, void * arg)
{
    http_status_code_t * return_code = (http_status_code_t*) arg;
    // save key while it alive, i.e. still exist
    dap_enc_key_t *key = dap_enc_ks_find_http(cl_st->http);
    //dap_enc_key_serealize_t *key_ser = dap_enc_key_serealize(key_tmp);
    //dap_enc_key_t *key = dap_enc_key_deserealize(key_ser, sizeof(dap_enc_key_serealize_t));

    // read header
    dap_http_header_t *hdr_session_close_id =
            (cl_st->http) ? dap_http_header_find(cl_st->http->in_headers, "SessionCloseAfterRequest") : NULL;
    dap_http_header_t *hdr_key_id =
            (hdr_session_close_id && cl_st->http) ? dap_http_header_find(cl_st->http->in_headers, "KeyID") : NULL;

    enc_http_delegate_t *dg = enc_http_request_decode(cl_st);
    if(dg) {
        char *suburl = dg->url_path;
        char *request_str = dg->request_str;
        int request_size = dg->request_size;
        printf("!!***!!! chain_mempool_proc arg=%d suburl=%s str=%s len=%d\n", arg, suburl, request_str, request_size);
        if(request_str && request_size > 1) {
            //  find what to do
            uint8_t action = DAP_DATUM_MEMPOOL_NONE;    //*(uint8_t*) request_str;
            if(dg->url_path_size > 0) {
                if(!strcmp(suburl, "add"))
                    action = DAP_DATUM_MEMPOOL_ADD;
                else if(!strcmp(suburl, "check"))
                    action = DAP_DATUM_MEMPOOL_CHECK;
                else if(!strcmp(suburl, "del"))
                    action = DAP_DATUM_MEMPOOL_DEL;
            }
            dap_datum_mempool_t *datum_mempool =
                    (action != DAP_DATUM_MEMPOOL_NONE) ?
                            dap_datum_mempool_deserialize(request_str, (size_t) request_size) : NULL;
            if(datum_mempool)
            {
                dap_datum_mempool_free(datum_mempool);
                char *a_key = calc_datum_hash(request_str, (size_t) request_size);
                char *a_value;
                switch (action)
                {
                case DAP_DATUM_MEMPOOL_ADD: // add datum in base
                    a_value = DAP_NEW_Z_SIZE(char, request_size * 2);
                    bin2hex((char*) a_value, (const unsigned char*) request_str, request_size);
                    if(dap_chain_global_db_set(a_key, a_value)) {
                        *return_code = Http_Status_OK;
                    }
                    log_it(L_INFO, "Insert hash: key=%s result:%s", a_key,
                            (*return_code == Http_Status_OK) ? "OK" : "False!");
                    DAP_DELETE(a_value);
                    break;

                case DAP_DATUM_MEMPOOL_CHECK: // check datum in base

                    strcpy(cl_st->reply_mime, "text/text");
                    char *str = dap_chain_global_db_get(a_key);
                    if(str) {
                        dg->response = strdup("1");
                        DAP_DELETE(str);
                        log_it(L_INFO, "Check hash: key=%s result: Present", a_key);
                    }
                    else
                    {
                        dg->response = strdup("0");
                        log_it(L_INFO, "Check hash: key=%s result: Absent", a_key);
                    }
                    dg->response_size = strlen(dg->response);
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, key, dg);
                    break;

                case DAP_DATUM_MEMPOOL_DEL: // delete datum in base
                    strcpy(cl_st->reply_mime, "text/text");
                    if(dap_chain_global_db_del(a_key)) {
                        dg->response = strdup("1");
                        DAP_DELETE(str);
                        log_it(L_INFO, "Delete hash: key=%s result: Ok", a_key);
                    }
                    else
                    {
                        dg->response = strdup("0");
                        log_it(L_INFO, "Delete hash: key=%s result: False!", a_key);
                    }
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, key, dg);
                    break;

                default: // unsupported command
                    log_it(L_INFO, "Unknown request=%s! key=%s", (suburl) ? suburl : "-", a_key);
                    DAP_DELETE(a_key);
                    enc_http_delegate_delete(dg);
                    if(key)
                        dap_enc_key_delete(key);
                    return;
                }
                DAP_DELETE(a_key);
            }
            else
                *return_code = Http_Status_BadRequest;
        }
        else
            *return_code = Http_Status_BadRequest;
        enc_http_delegate_delete(dg);
    }
    else {
        *return_code = Http_Status_Unauthorized;
    }
    if(hdr_session_close_id && hdr_session_close_id->value && !strcmp(hdr_session_close_id->value, "yes")) {
        // close session
        if(hdr_key_id && hdr_key_id->value) {
            dap_enc_ks_delete(hdr_key_id->value);
        }
    }
}

/**
 * @brief chain_mempool_add_proc
 * @param sh HTTP server instance
 * @param url URL string
 */
void dap_chain_mempool_add_proc(struct dap_http * sh, const char * url)
{
    dap_http_simple_proc_add(sh, url, 4096, chain_mempool_proc);
}

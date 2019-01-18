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
#include "dap_chain_global_db.h"
#include "dap_chain_mempool.h"

#define FILE_MEMPOOL_DB "1.db" // TODO get from settings

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
    datum_mempool->data = DAP_NEW_Z_SIZE(dap_chain_datum_t*, datum_mempool->datum_count);
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
}

void dap_datum_mempool_free(dap_datum_mempool_t *datum)
{
    dap_datum_mempool_clean(datum);
    DAP_DELETE(datum);
}

/**
 *
 */
char* calc_datum_hash(const char *datum_str, size_t datum_size)
{
    dap_chain_hash_t a_hash;
    dap_hash((char*) datum_str, datum_size, a_hash.raw, sizeof(a_hash.raw), DAP_HASH_TYPE_SLOW_0);
    size_t a_str_max = sizeof(a_hash.raw) * 2;
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);
    size_t hash_len = dap_chain_hash_to_str(&a_hash, a_str, a_str_max);
    if(hash_len) {
        DAP_DELETE(a_str);
        return NULL;
    }
    return a_str;
}

/**
 * Convert binary data to binhex encoded data.
 *
 * out output buffer, must be twice the number of bytes to encode.
 * len is the size of the data in the in[] buffer to encode.
 * return the number of bytes encoded, or -1 on error.
 */
int bin2hex(char *out, const unsigned char *in, int len)
{
    int ct = len;
    static char hex[] = "0123456789ABCDEF";
    if(!in || !out || len < 0)
        return -1;
    // hexadecimal lookup table
    while(ct-- > 0)
    {
        *out++ = hex[*in >> 4];
        *out++ = hex[*in++ & 0x0F];
    }
    return len;
}

/**
 * Convert binhex encoded data to binary data
 *
 * len is the size of the data in the in[] buffer to decode, and must be even.
 * out outputbuffer must be at least half of "len" in size.
 * The buffers in[] and out[] can be the same to allow in-place decoding.
 * return the number of bytes encoded, or -1 on error.
 */
int hex2bin(char *out, const unsigned char *in, int len)
{
    // '0'-'9' = 0x30-0x39
    // 'a'-'f' = 0x61-0x66
    // 'A'-'F' = 0x41-0x46
    int ct = len;
    if(!in || !out || len < 0 || len & 1)
        return -1;
    while(ct > 0)
    {
        char ch1 = ((*in >= 'a') ? (*in++ - 'a' + 10) : ((*in >= 'A') ? (*in++ - 'A' + 10) : (*in++ - '0'))) << 4;
        char ch2 = ((*in >= 'a') ? (*in++ - 'a' + 10) : ((*in >= 'A') ? (*in++ - 'A' + 10) : (*in++ - '0'))); // ((*in >= 'A') ? (*in++ - 'A' + 10) : (*in++ - '0'));
        *out++ = ch1 + ch2;
        ct -= 2;
    }
    return len;
}

/**
 * @brief
 * @param cl_st HTTP server instance
 * @param arg for return code
 */
void chain_mempool_proc(struct dap_http_simple *cl_st, void * arg)
{
    http_status_code_t * return_code = (http_status_code_t*) arg;
    enc_http_delegate_t *dg = enc_http_request_decode(cl_st);
    if(dg) {
        char *url = dg->url_path;
        char *request_str = dg->request_str;
        int request_size = dg->request_size;
        printf("!!***!!! chain_mempool_proc arg=%d url=%s str=%s len=%d\n", arg, url, request_str, request_size);
        if(request_str && request_size > 0) {
            dap_datum_mempool_t *datum_mempool = dap_datum_mempool_deserialize(request_str, (size_t) request_size);
            if(datum_mempool)
            {
                dap_datum_mempool_free(datum_mempool);
                char *a_key = calc_datum_hash(request_str, (size_t) request_size);
                char *a_value = DAP_NEW_Z_SIZE(char, request_size * 2);
                bin2hex((char*) a_value, (const unsigned char*) request_str, request_size);
                if(dap_chain_global_db_set(a_key, a_value)) {
                    *return_code = Http_Status_OK;
                    DAP_DELETE(a_key);
                    DAP_DELETE(a_value);
                    return;
                }
                DAP_DELETE(a_key);
                DAP_DELETE(a_value);
            }
            else
                *return_code = Http_Status_InternalServerError;
        }
        else
            *return_code = Http_Status_BadRequest;
    }
    else {
        *return_code = Http_Status_Unauthorized;
    }
}

/**
 * @brief chain_mempool_add_proc
 * @param sh HTTP server instance
 * @param url URL string
 */
void dap_chain_mempool_add_proc(struct dap_http * sh, const char * url)
{
    dap_chain_global_db_init(FILE_MEMPOOL_DB);
    dap_http_simple_proc_add(sh, url, 4096, chain_mempool_proc);
}

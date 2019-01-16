#include <stdio.h>
#include "dap_common.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
//#include "dap_enc_http.h"
#include "dap_enc_http.h"
//#include "dap_http.h"
#include "http_status_code.h"
#include "dap_chain_global_db.h"
#include "dap_chain_mempool.h"

#define FILE_MEMPOOL_DB "1.db" // TODO get from settings


void dap_datum_mempool_clean(dap_datum_mempool_t *datum)
{
    if(!datum)
        return;
    for(int i = 0; i < datum->datum_count; i++){
        DAP_DELETE(datum->data[i]);
    }
}

void dap_datum_mempool_free(dap_datum_mempool_t *datum)
{
    dap_datum_mempool_clean(datum);
    DAP_DELETE(datum);
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
            dap_datum_mempool_t *mempool = (dap_datum_mempool_t*)request_str;
            const char *a_key = "";//TODO hash(mempool)
            const char *a_value = "";// TODO mempool;
            if(dap_chain_global_db_set(a_key, a_value))
                *return_code = Http_Status_OK;
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

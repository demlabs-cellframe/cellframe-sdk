#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utlist.h"

#include "common.h"

#include "dap_client.h"
#include "dap_http_client.h"
#include "../db_http/dap_http_simple.h"

#include "db_http.h"
#include "db_auth.h"


#include "enc_http.h"

#define LOG_TAG "db_http"

#define LAST_USE_KEY(key) ((rsa_key_t*)key->internal)->last_time_use_key

void db_http_proc(dap_http_simple_t * cl_st, void * arg );

int db_http_init()
{
    log_it(NOTICE, "Init content manager");
    return 0;
}

void db_http_deinit()
{
    log_it(NOTICE, "Deinit content manager");
}


void db_http_add_proc(struct dap_http * sh, const char * url)
{
    dap_http_simple_proc_add(sh,url,1000000,db_http_proc);
}

/**
 * @brief content_proc Process content list request
 * @param sh HTTP simple client instance
 * @param arg Return if ok
 */
void db_http_proc(dap_http_simple_t * cl_st, void * arg )
{
    bool *isOk= (bool*)arg;
    enc_http_delegate_t * dg;
    strcpy(cl_st->reply_mime,"application/octet-stream");

    dg=enc_http_request_decode(cl_st);
    if(dg){
        dg->isOk=true;
        if(strcmp(dg->url_path,"auth")==0){
            db_auth_http_proc(dg,NULL);
        }
        else if (strcmp(dg->url_path,"TestRsaKey")==0) {
            enc_http_reply_f(dg,"TestRsaKey Request");
        }
        else {
            if(dg->url_path)
                log_it(ERROR,"Wrong DB request %s",dg->url_path);
            else
                log_it(ERROR,"Wrong DB request: nothing after / ");
            dg->isOk=false;
        }
        *isOk=dg->isOk;
        enc_http_reply_encode(cl_st,dg);
        enc_http_delegate_delete(dg);
    }else{
        *isOk=false;
        log_it(WARNING,"No KeyID in the request");
    }
}


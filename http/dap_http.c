#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <netdb.h>

#include "common.h"
#include "dap_client.h"
#include "dap_server.h"

#include "dap_http.h"
#include "dap_http_header.h"
#include "dap_http_client.h"


#define LOG_TAG "http"


/**
 * @brief dap_http_init // Init HTTP module
 * @return Zero if ok others if not
 */
int dap_http_init()
{
    if(dap_http_header_init()!=0){ // Init submodule for headers manipulations
        log_it(CRITICAL,"Can't init HTTP headers processing submodule");
        return -1;
    }
    if(dap_http_client_init()!=0){ // Init submodule for HTTP client event processing
        log_it(CRITICAL,"Can't init HTTP client submodule");
        return -2;
    }
    log_it(NOTICE,"Initialized HTTP server module");
    return 0;
}

/**
 * @brief dap_http_deinit Deinit HTTP module
 */
void dap_http_deinit()
{
    dap_http_header_deinit();
    dap_http_client_deinit();
}



/**
 * @brief dap_server_http_init Init HTTP server
 * @param sh Server instance
 * @return 0 if ok lesser number if error
 */
int dap_http_new(dap_server_t *sh, const char * server_name)
{
    sh->internal= calloc(1,sizeof(dap_http_t));

    dap_http_t *shttp = DAP_HTTP(sh);

    shttp->server=sh;
    strncpy(shttp->server_name,server_name,sizeof(shttp->server_name)-1);

    sh->client_new_callback=dap_http_client_new;
    sh->client_delete_callback=dap_http_client_delete;
    sh->client_read_callback=dap_http_client_read;
    sh->client_write_callback=dap_http_client_write;
    sh->client_error_callback=dap_http_client_error;

    return 0;
}

/**
 * @brief dap_http_delete Clear dap_http structure in the internal data field of dap_server_t instance
 * @param sh Server's instance
 * @param arg Non-used argument
 */
void dap_http_delete(dap_server_t *sh,void * arg)
{
    (void) arg;
    (void) sh;
    dap_http_t * shttp=DAP_HTTP(sh);
    dap_http_url_proc_t * up, * tmp;

    HASH_ITER(hh, shttp->url_proc , up, tmp) {
        HASH_DEL(shttp->url_proc, up);
        if(up->internal)
            free(up->internal);
        free(up);
    }

}


/**
 * @brief dap_http_add_proc  Add custom procesor for the HTTP server
 * @param sh                Server's instance
 * @param url_path          Part of URL to be processed
 * @param read_callback     Callback for read in DATA state
 * @param write_callback    Callback for write in DATA state
 * @param error_callback    Callback for error processing
 */
void dap_http_add_proc(dap_http_t * sh, const char * url_path, void * internal
                      ,dap_http_client_callback_t new_callback
                      ,dap_http_client_callback_t delete_callback
                      ,dap_http_client_callback_t headers_read_callback
                      ,dap_http_client_callback_t headers_write_callback
                      ,dap_http_client_callback_t data_read_callback
                      ,dap_http_client_callback_t data_write_callback
                      ,dap_http_client_callback_t error_callback

                      )
{
    dap_http_url_proc_t * up= (dap_http_url_proc_t*) calloc(1,sizeof(dap_http_url_proc_t));
    strncpy(up->url,url_path,sizeof(up->url));
    up->new_callback=new_callback;
    up->delete_callback=delete_callback;
    up->data_read_callback=data_read_callback;
    up->data_write_callback=data_write_callback;
    up->headers_read_callback=headers_read_callback;
    up->headers_write_callback=headers_write_callback;
    up->error_callback=error_callback;
    up->internal=internal;
    HASH_ADD_STR(sh->url_proc,url,up);
    log_it(DEBUG,"Added URL processor for '%s' path",up->url);
}



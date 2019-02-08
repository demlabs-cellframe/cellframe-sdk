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

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
#include "dap_enc_key.h"
#include "dap_http_user_agent.h"
#include "../enc_server/dap_enc_ks.h"
#include "../enc_server/dap_enc_http.h"
#include "http_status_code.h"
#include <ev.h>
#include <sys/queue.h>
#include <utlist.h>

#define LOG_TAG "dap_http_simple"

void dap_http_simple_headers_read(dap_http_client_t * cl_ht, void * arg );
void dap_http_simple_data_write(dap_http_client_t * a_http_client,void * a_arg);
void dap_http_simple_data_read(dap_http_client_t * cl_ht,void * arg);
void* dap_http_simple_proc(dap_http_simple_t * cl_sh);

static void* loop_http_simple_proc(void *arg);
static void async_control_proc (EV_P_ ev_async *w, int revents);
static void queue_http_request_put(dap_http_simple_t * cl_sh);

typedef struct dap_http_simple_url_proc {
    dap_http_simple_callback_t proc_callback;
    size_t reply_size_max;
} dap_http_simple_url_proc_t;

typedef struct tailq_entry {
    dap_http_simple_t * cl_sh;
    TAILQ_ENTRY(tailq_entry) entries;
} tailq_entry_t;
TAILQ_HEAD(, tailq_entry) tailq_head;


typedef struct user_agents_item {
    dap_http_user_agent_ptr_t user_agent;
    /* This is instead of "struct foo *next" */
    struct user_agents_item* next;
} user_agents_item_t;

user_agents_item_t *user_agents_list = NULL;

#define DAP_HTTP_SIMPLE_URL_PROC(a) ((dap_http_simple_url_proc_t*) (a)->_inheritor)

static struct ev_loop* http_simple_loop;
static ev_async async_watcher_http_simple;
static pthread_mutex_t mutex_on_queue_http_response = PTHREAD_MUTEX_INITIALIZER;

// uint64_t s_TTL_session_key=3600;

int dap_http_simple_module_init()
{
    pthread_mutex_init(&mutex_on_queue_http_response, NULL);
    http_simple_loop = ev_loop_new(0);

    TAILQ_INIT(&tailq_head);

    pthread_t thread;
    ev_async_init(&async_watcher_http_simple, async_control_proc);
    ev_async_start(http_simple_loop, &async_watcher_http_simple);
    pthread_create(&thread, NULL, loop_http_simple_proc, NULL);

    return 0;
}


static void async_control_proc (EV_P_ ev_async *w, int revents)
{
    pthread_mutex_lock(&mutex_on_queue_http_response);

    tailq_entry_t* item;
    while (item = TAILQ_FIRST(&tailq_head)) {
        dap_http_simple_proc(item->cl_sh);
        TAILQ_REMOVE(&tailq_head, item, entries);
        free(item);
    }

    pthread_mutex_unlock(&mutex_on_queue_http_response);
}

static void* loop_http_simple_proc(void *arg)
{
    log_it(L_NOTICE, "Start loop http simple thread");
    ev_loop(http_simple_loop, 0);
    return NULL;
}


/**
 * @brief dap_http_simple_proc_add Add simple HTTP processor
 * @param sh HTTP server instance
 * @param url_path URL path
 * @param cb Callback for data processing
 */
void dap_http_simple_proc_add(dap_http_t *sh, const char * url_path, size_t reply_size_max, dap_http_simple_callback_t cb)
{
    dap_http_simple_url_proc_t * shs_up = DAP_NEW_Z(dap_http_simple_url_proc_t);
    shs_up->proc_callback=cb;
    shs_up->reply_size_max=reply_size_max;
    dap_http_add_proc(sh,url_path
                     ,shs_up, // Internal structure
                     NULL,NULL, // Contrustor, Destructor
                     dap_http_simple_headers_read,NULL, // Headers read,write
                     dap_http_simple_data_read, dap_http_simple_data_write, // Data read, write
                     NULL); // errror
}


static void _free_user_agents_list()
{
    user_agents_item_t *elt, *tmp;
    LL_FOREACH_SAFE(user_agents_list,elt,tmp) {
        LL_DELETE(user_agents_list, elt);
        dap_http_user_agent_delete(elt->user_agent);
        free(elt);
    }
}

static bool _is_user_agent_supported(const char* user_agent)
{
    bool result = false;

    dap_http_user_agent_ptr_t find_agent =
            dap_http_user_agent_new_from_str(user_agent);
    if(find_agent == NULL) {
        return false;
    }
    const char* find_agent_name = dap_http_user_agent_get_name(find_agent);

    user_agents_item_t * elt;
    LL_FOREACH(user_agents_list,elt) {
        const char* user_agent_name =
            dap_http_user_agent_get_name(elt->user_agent);

        if(strcmp(find_agent_name, user_agent_name) == 0) {
            if(dap_http_user_agent_versions_compare(find_agent, elt->user_agent) >= 0) {
                result = true;
                goto END;
            } else {
                result = false;
                goto END;
            }
        }
    }

END:
    dap_http_user_agent_delete(find_agent);
    return result;
}

bool dap_http_simple_set_supported_user_agents(const char *user_agents, ...)
{
    va_list argptr;
    va_start( argptr, user_agents );

    const char* str = user_agents;
    while (str != NULL)
    {
        dap_http_user_agent_ptr_t user_agent = dap_http_user_agent_new_from_str(str);
        if(user_agent == NULL) {
            log_it(L_ERROR, "Can't parse user agent string");
            _free_user_agents_list();
            return NULL;
        }
        user_agents_item_t * item = calloc(1, sizeof (user_agents_item_t));
        item->user_agent = user_agent;
        LL_APPEND(user_agents_list, item);

        log_it( L_DEBUG, "%s", str );
        str = va_arg( argptr, const char* );
    }
    va_end(argptr);
    return true;
}

/**
 * @brief dap_http_simple_proc Execute procession callback and switch to write state
 * @param cl_sh HTTP simple client instance
 */
void* dap_http_simple_proc(dap_http_simple_t * cl_sh)
{
    log_it(L_DEBUG, "dap http simple proc");
    http_status_code_t return_code = (http_status_code_t)0;
//    bool key_is_expiried = false;

//    dap_enc_key_t * key = dap_enc_ks_find_http(cl_sh->http);
//    if(key){
//        if( key->last_used_timestamp && ( (time(NULL) - key->last_used_timestamp  )
//                                          > s_TTL_session_key ) ) {

//            enc_http_delegate_t * dg = enc_http_request_decode(cl_sh);

//            if( dg == NULL ) {
//                log_it(L_ERROR, "dg is NULL");
//                return NULL;
//            }

//            log_it(L_WARNING, "Key has been expiried");
//            strcpy(cl_sh->reply_mime,"text/plain");
//            enc_http_reply_f(dg,"Key has been expiried");
//            enc_http_reply_encode(cl_sh,dg);
//            enc_http_delegate_delete(dg);
//            key_is_expiried = true;
//        } else{
//            key->last_used_timestamp = time(NULL);
//        }
//    }

//    if ( !key_is_expiried )

    DAP_HTTP_SIMPLE_URL_PROC(cl_sh->http->proc)->proc_callback(cl_sh,&return_code);

    if(return_code) {
        log_it(L_DEBUG, "Request was processed well");
        cl_sh->http->reply_status_code = (uint16_t)return_code;
        if(cl_sh->reply_size != 0) {
            cl_sh->http->out_content_length=cl_sh->reply_size;
            strcpy(cl_sh->http->out_content_type, cl_sh->reply_mime);
        }
    }else{
        log_it(L_ERROR, "Request was processed with ERROR");
        cl_sh->http->reply_status_code = Http_Status_InternalServerError;
    }
    dap_client_remote_ready_to_read(cl_sh->http->client,false);
    cl_sh->http->state_write=DAP_HTTP_CLIENT_STATE_NONE;

    dap_client_remote_ready_to_write(cl_sh->http->client,true);
    cl_sh->http->state_write=DAP_HTTP_CLIENT_STATE_START;

    return NULL;
}

/**
 * @brief dap_http_simple_headers_read Prepare reply on request
 * @param cl_ht
 * @param arg
 */
void dap_http_simple_headers_read(dap_http_client_t * cl_ht, void * arg )
{
    cl_ht->_inheritor = DAP_NEW_Z(dap_http_simple_t);

    DAP_HTTP_SIMPLE(cl_ht)->http = cl_ht;
    DAP_HTTP_SIMPLE(cl_ht)->reply_size_max = DAP_HTTP_SIMPLE_URL_PROC( cl_ht->proc )->reply_size_max;
    DAP_HTTP_SIMPLE(cl_ht)->reply = calloc(1,DAP_HTTP_SIMPLE(cl_ht)->reply_size_max);

    if(cl_ht->in_content_length)
    {
        if(cl_ht->in_content_length< DAP_HTTP_SIMPLE_REQUEST_MAX)
            DAP_HTTP_SIMPLE(cl_ht)->request = calloc(1,cl_ht->in_content_length+1);
        else
            log_it(L_ERROR, "Too big content-length %u in request", cl_ht->in_content_length);
    }
    else
    {
        log_it(L_DEBUG,"No data section, execution proc callback");
        queue_http_request_put(DAP_HTTP_SIMPLE(cl_ht));
    }
}

void dap_http_simple_data_read(dap_http_client_t * cl_ht,void * arg)
{
    int *ret= (int*) arg;

    dap_http_simple_t * shs = DAP_HTTP_SIMPLE(cl_ht);
    size_t bytes_to_read=(cl_ht->client->buf_in_size+shs->request_size)< cl_ht->in_content_length?
                            cl_ht->client->buf_in_size:
                            (cl_ht->in_content_length-shs->request_size);
    if(bytes_to_read)
    {
        memcpy(shs->request+shs->request_size,cl_ht->client->buf_in,bytes_to_read);
        shs->request_size+=bytes_to_read;
    }
    if(shs->request_size >=cl_ht->in_content_length)
    {
       // bool isOK=true;
        log_it(L_DEBUG,"Data collected");
        queue_http_request_put(shs);
    }
    *ret=cl_ht->client->buf_in_size;
}


/**
 * @brief dap_http_simple_data_write
 * @param a_http_client
 * @param a_arg
 */
void dap_http_simple_data_write(dap_http_client_t * a_http_client,void * a_arg)
{
    (void) a_arg;
    dap_http_simple_t * cl_st = DAP_HTTP_SIMPLE(a_http_client);

    if ( cl_st->reply ) {
        cl_st->reply_sent += dap_client_remote_write(a_http_client->client,
                                              cl_st->reply + cl_st->reply_sent,
                                              a_http_client->out_content_length - cl_st->reply_sent);

        if(cl_st->reply_sent>=a_http_client->out_content_length) {
            log_it(L_INFO, "All the reply (%u) is sent out",a_http_client->out_content_length);
            //cl_ht->client->signal_close=cl_ht->keep_alive;
            a_http_client->client->signal_close=true;
            //dap_client_ready_to_write(cl_ht->client,false);
        }

        free(cl_st->reply);
    }else{
        a_http_client->client->signal_close=true;
        log_it(L_WARNING,"No reply to write, close connection");
    }
}

/**
 * @brief dap_http_simple_reply Add data to the reply buffer
 * @param shs HTTP simple client instance
 * @param data
 * @param data_size
 */
size_t dap_http_simple_reply(dap_http_simple_t * shs, void * data, size_t data_size)
{
    size_t wb = (data_size> (shs->reply_size_max - shs->reply_size) )? (shs->reply_size_max - shs->reply_size):data_size;
    memcpy(shs->reply + shs->reply_size, data, wb);
    shs->reply_size += wb;
    return wb;
}

/**
 * @brief dap_http_simple_reply_f
 * @param shs
 * @param data
 */
size_t dap_http_simple_reply_f(dap_http_simple_t * shs, const char * data, ...)
{
    char buf[4096];
    va_list ap;
    int vret;
    va_start(ap,data);
    vret = vsnprintf(buf, sizeof(buf)-1, data, ap);
    va_end(ap);
    if(vret > 0)
        return dap_http_simple_reply(shs, buf, vret);
    else
        return 0;
}

inline void queue_http_request_put(dap_http_simple_t *cl_sh)
{
    pthread_mutex_lock(&mutex_on_queue_http_response);
    tailq_entry_t * item = malloc (sizeof(tailq_entry_t));
    item->cl_sh = cl_sh;
    TAILQ_INSERT_TAIL(&tailq_head, item, entries);
    pthread_mutex_unlock(&mutex_on_queue_http_response);

    ev_async_send(http_simple_loop, &async_watcher_http_simple);
}

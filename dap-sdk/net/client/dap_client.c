#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_http_client.h"
#include "dap_client.h"
#include "dap_client_pvt.h"
#include "dap_client_http.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_worker.h"

#define LOG_TAG "dap_client"

// FSM realization: thats callback executes after the every stage is done
// and have to select the next one stage
static void s_stage_fsm_operator_unsafe(dap_client_t *, void *);
static void s_stage_done_delete(dap_client_t * a_client, void * a_arg);

/**
 * @brief dap_client_init
 * @return
 */
int dap_client_init()
{
    static bool s_is_first_time=true;
    if (s_is_first_time ) {
        int err = 0;
        log_it(L_INFO, "Init DAP client module");
        dap_http_client_init();
        err = dap_client_http_init();
        if (err)
            return err;
        dap_client_pvt_init();
        s_is_first_time = false;
    }
    return 0;

}

/**
 * @brief dap_client_deinit
 */
void dap_client_deinit()
{
    dap_client_pvt_deinit();
    dap_http_client_deinit();
    log_it(L_INFO, "Deinit DAP client module");
}

/**
 * @brief dap_client_new
 * @param a_stage_status_callback
 * @param a_stage_status_error_callback
 * @return
 */
dap_client_t * dap_client_new(dap_events_t * a_events, dap_client_callback_t a_stage_status_callback
                              ,dap_client_callback_t a_stage_status_error_callback )
{
    // ALLOC MEM FOR dap_client
    dap_client_t *l_client = DAP_NEW_Z(dap_client_t);
    if (!l_client)
        goto MEM_ALLOC_ERR;

    pthread_mutex_init(&l_client->mutex, NULL);

    l_client->_internal  = DAP_NEW_Z(dap_client_pvt_t);
    if (!l_client->_internal)
        goto MEM_ALLOC_ERR;

    // CONSTRUCT dap_client object
    DAP_CLIENT_PVT(l_client)->client = l_client;
    DAP_CLIENT_PVT(l_client)->events = a_events;
    DAP_CLIENT_PVT(l_client)->stage_status_callback = a_stage_status_callback;
    DAP_CLIENT_PVT(l_client)->stage_status_error_callback = a_stage_status_error_callback;
    DAP_CLIENT_PVT(l_client)->worker = dap_events_worker_get_auto();

    dap_client_pvt_new(DAP_CLIENT_PVT(l_client) );

    return l_client;

MEM_ALLOC_ERR:
    log_it(L_ERROR, "dap_client_new can not allocate memory");
    if (l_client)
        if(l_client->_internal)
            DAP_DELETE(l_client->_internal);

    if (l_client)
        DAP_DELETE (l_client);
    return NULL;
}

/**
 * @brief dap_client_set_uplink
 * @param a_client
 * @param a_addr
 * @param a_port
 */
void dap_client_set_uplink_unsafe(dap_client_t * a_client,const char* a_addr, uint16_t a_port)
{
    if(a_addr == NULL){
        log_it(L_ERROR,"Address is NULL for dap_client_set_uplink");
        return;
    }
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_set_uplink");
        return;
    }
    DAP_DEL_Z(DAP_CLIENT_PVT(a_client)->uplink_addr);
    DAP_CLIENT_PVT(a_client)->uplink_addr = strdup(a_addr);
    DAP_CLIENT_PVT(a_client)->uplink_port = a_port;
}

/**
 * @brief dap_client_get_uplink_addr
 * @param a_client
 * @return
 */
const char* dap_client_get_uplink_addr_unsafe(dap_client_t * a_client)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_uplink");
        return NULL;
    }
    const char * l_ret = DAP_CLIENT_PVT(a_client)->uplink_addr;
    return l_ret;
}

/**
 * @brief dap_client_set_active_channels
 * @param a_client
 * @param a_active_channels
 */
void dap_client_set_active_channels_unsafe (dap_client_t * a_client, const char * a_active_channels)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_set_active_channels");
        return;
    }

    if ( DAP_CLIENT_PVT(a_client)->active_channels )
        DAP_DELETE(DAP_CLIENT_PVT(a_client)->active_channels );
    DAP_CLIENT_PVT(a_client)->active_channels =  a_active_channels? dap_strdup( a_active_channels) : NULL;
}

/**
 * @brief dap_client_get_uplink_port
 * @param a_client
 * @return
 */
uint16_t dap_client_get_uplink_port_unsafe(dap_client_t * a_client)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_uplink_port");
        return 0;
    }

    return DAP_CLIENT_PVT(a_client)->uplink_port;
}

void dap_client_set_auth_cert_unsafe(dap_client_t * a_client, dap_cert_t *a_cert)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_set_auth_cert");
        return;
    }

    DAP_CLIENT_PVT(a_client)->auth_cert = a_cert;
}

/**
 * @brief s_client_delete
 * @param a_client
 */
void dap_client_delete_unsafe(dap_client_t * a_client)
{
    if ( DAP_CLIENT_PVT(a_client)->refs_count ==0 ){
        dap_client_pvt_delete( DAP_CLIENT_PVT(a_client) );
        pthread_mutex_destroy(&a_client->mutex);
        DAP_DEL_Z(a_client)
    } else
        DAP_CLIENT_PVT(a_client)->is_to_delete = true;
}

/**
 * @brief s_stage_begin_before_delete
 * @param a_client
 * @param a_arg
 */
static void s_stage_done_delete(dap_client_t * a_client, void * a_arg)
{
    (void) a_arg;
    pthread_mutex_destroy(&a_client->mutex);
}


struct go_stage_arg{
    bool flag_delete_after;// Delete after stage achievement
    dap_client_pvt_t *client_pvt;
    dap_client_stage_t stage_target;
    dap_client_callback_t stage_end_callback;
};

/**
 * @brief s_go_stage_on_client_worker_unsafe
 * @param a_worker
 * @param a_arg
 */
static void s_go_stage_on_client_worker_unsafe(dap_worker_t * a_worker,void * a_arg)
{
    (void) a_worker;
    assert(a_arg);
    dap_client_stage_t l_stage_target = ((struct go_stage_arg*) a_arg)->stage_target;
    dap_client_callback_t l_stage_end_callback= ((struct go_stage_arg*) a_arg)->stage_end_callback;
    dap_client_pvt_t * l_client_pvt = ((struct go_stage_arg*) a_arg)->client_pvt;
    dap_client_t * l_client = ((struct go_stage_arg*) a_arg)->client_pvt->client;
    bool l_flag_delete_after = ((struct go_stage_arg *) a_arg)->flag_delete_after ;// Delete after stage achievement
    DAP_DELETE(a_arg);

    l_client_pvt->is_to_delete = l_flag_delete_after;
    if ( l_client==NULL){
        log_it(L_WARNING,"Client is NULL, why? Refs %u", l_client_pvt->refs_count);
        if ( l_client_pvt->refs_count ==0 ){
            dap_client_pvt_delete( l_client_pvt );
        } else
            l_client_pvt->is_to_delete = true;
        return;
    }

    dap_client_stage_t l_cur_stage = l_client_pvt->stage;
    dap_client_stage_status_t l_cur_stage_status= l_client_pvt->stage_status;
    if (l_stage_target == l_cur_stage){
        switch ( l_cur_stage_status) {
            case STAGE_STATUS_DONE:
                log_it(L_DEBUG, "Already have target state %s", dap_client_stage_str(l_stage_target));
                if (l_stage_end_callback) {
                    l_stage_end_callback(l_client_pvt->client, NULL);
                }
            break;
            case STAGE_STATUS_ERROR:
                log_it(L_DEBUG, "Already moving target state %s, but status is error (%s)", dap_client_stage_str(l_stage_target),
                       dap_client_get_error_str( l_client_pvt->client) );
            break;
            case STAGE_STATUS_IN_PROGRESS:
                log_it(L_DEBUG, "Already moving target state %s", dap_client_stage_str(l_stage_target));
            break;
            default:
                log_it(L_WARNING, "Unprocessed stage status %s for go to stage %s scheme ",  dap_client_stage_str(l_stage_target),
                       dap_client_stage_status_str( l_cur_stage_status));
        }
        l_client_pvt->refs_count--;
        dap_client_delete_unsafe(l_client_pvt->client);
        return;
    }
    log_it(L_DEBUG, "Start transitions chain for client %p -> %p from %s to %s", l_client_pvt, l_client_pvt->client, dap_client_stage_str(l_cur_stage ) , dap_client_stage_str(l_stage_target));
    l_client_pvt->stage_target = l_stage_target;
    l_client_pvt->stage_target_done_callback = l_stage_end_callback;
    if (l_stage_target < l_cur_stage) {
        dap_client_pvt_stage_transaction_begin(l_client_pvt, STAGE_BEGIN, NULL);
    }
    l_cur_stage = l_client_pvt->stage;
    l_cur_stage_status= l_client_pvt->stage_status;
    if (l_stage_target != l_cur_stage ){ // Going to stages downstairs
        switch(l_cur_stage_status ){
            case STAGE_STATUS_ABORTING:
                log_it(L_ERROR, "Already aborting the stage %s"
                        , dap_client_stage_str(l_cur_stage));
            break;
            case STAGE_STATUS_IN_PROGRESS:{
                log_it(L_WARNING, "Status progress the stage %s"
                        , dap_client_stage_str(l_cur_stage));
            }break;
            case STAGE_STATUS_DONE:
            case STAGE_STATUS_ERROR:
            default: {
                dap_client_pvt_stage_transaction_begin(l_client_pvt,
                                                       l_cur_stage + 1,
                                                       s_stage_fsm_operator_unsafe);
            }
        }
    }
    l_client_pvt->refs_count--;
    if ( l_client_pvt->is_to_delete )
        dap_client_delete_unsafe(l_client);

}
/**
 * @brief dap_client_go_stage
 * @param a_client
 * @param a_stage_end
 */
void dap_client_go_stage(dap_client_t * a_client, dap_client_stage_t a_stage_target, dap_client_callback_t a_stage_end_callback)
{
    // ----- check parameters -----
    if(NULL == a_client) {
        log_it(L_ERROR, "dap_client_go_stage, a_client == NULL");
        return;
    }
    if(NULL == a_stage_end_callback) {
        log_it(L_ERROR, "dap_client_go_stage, a_stage_end_callback == NULL");
        return;
    }
    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client);

    assert(l_client_pvt);

    struct go_stage_arg *l_stage_arg = DAP_NEW_Z(struct go_stage_arg); if (! l_stage_arg) return;
    l_stage_arg->stage_end_callback = a_stage_end_callback;
    l_stage_arg->stage_target = a_stage_target;
    l_stage_arg->client_pvt = l_client_pvt;
    dap_worker_exec_callback_on(l_client_pvt->worker, s_go_stage_on_client_worker_unsafe, l_stage_arg);
}

/**
 * @brief dap_client_go_delete
 * @param a_client
 */
void dap_client_delete_mt(dap_client_t * a_client)
{
    assert(a_client);
    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client);
    assert(l_client_pvt);

    struct go_stage_arg *l_stage_arg = DAP_NEW(struct go_stage_arg); if (! l_stage_arg) return;
    l_stage_arg->stage_end_callback  = s_stage_done_delete ;
    l_stage_arg->stage_target = STAGE_BEGIN ;
    l_stage_arg->client_pvt = l_client_pvt;
    l_stage_arg->flag_delete_after = true;
    dap_worker_exec_callback_on(l_client_pvt->worker, s_go_stage_on_client_worker_unsafe, l_stage_arg);
}


/**
 * @brief s_stage_fsm_operator_unsafe
 * @param a_client
 * @param a_arg
 */
static void s_stage_fsm_operator_unsafe(dap_client_t * a_client, void * a_arg)
{
    UNUSED(a_arg);
    assert(a_client);
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    assert(l_client_internal);

    if ( l_client_internal->is_to_delete ){ // If we're switched once to delete and smbd else switched to another state - we restore target
        l_client_internal->stage_target = STAGE_BEGIN;
        l_client_internal->stage_target_done_callback = s_stage_done_delete;
    }

    if (l_client_internal->stage_target == l_client_internal->stage){
        log_it(L_WARNING, "FSM Op: current stage %s is same as target one, nothing to do",
              dap_client_stage_str( l_client_internal->stage ) );
        l_client_internal->stage_status_done_callback = NULL;

        return;
    }

    int step = (l_client_internal->stage_target > l_client_internal->stage)?1:-1;
    dap_client_stage_t l_stage_next = l_client_internal->stage+step;
    log_it(L_NOTICE, "FSM Op: current stage %s, go to %s (target %s)"
           ,dap_client_stage_str(l_client_internal->stage), dap_client_stage_str(l_stage_next)
           ,dap_client_stage_str(l_client_internal->stage_target));
    dap_client_pvt_stage_transaction_begin(l_client_internal,
                                                l_stage_next, s_stage_fsm_operator_unsafe
                                                );

}


/**
 * @brief dap_client_request_enc
 * @param a_client
 * @param a_path
 * @param a_suburl
 * @param a_query
 * @param a_request
 * @param a_request_size
 * @param a_response_proc
 * @param a_response_error
 */
void dap_client_request_enc_unsafe(dap_client_t * a_client, const char * a_path, const char * a_suburl,const char* a_query, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error )
{
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    dap_client_pvt_request_enc(l_client_internal, a_path, a_suburl, a_query,a_request,a_request_size, a_response_proc,a_response_error);
}

void dap_client_request_unsafe(dap_client_t * a_client, const char * a_full_path, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error )
{
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    dap_client_pvt_request(l_client_internal, a_full_path, a_request, a_request_size, a_response_proc, a_response_error);
}

/**
 * @brief dap_client_error_str
 * @param a_client_error
 * @return
 */
const char * dap_client_error_str(dap_client_error_t a_client_error)
{
    switch(a_client_error){
        case ERROR_OUT_OF_MEMORY: return "OUT_OF_MEMORY";
        case ERROR_ENC_NO_KEY: return "ENC_NO_KEY";
        case ERROR_ENC_WRONG_KEY: return "ENC_WRONG_KEY";
        case ERROR_ENC_SESSION_CLOSED:  return "ENC_SESSION_CLOSED";
        case ERROR_STREAM_RESPONSE_WRONG: return "STREAM_RESPONSE_WRONG";
        case ERROR_STREAM_RESPONSE_TIMEOUT: return "STREAM_RESPONSE_TIMEOUT";
        case ERROR_STREAM_FREEZED: return "STREAM_FREEZED";
        case ERROR_STREAM_CTL_ERROR: return "STREAM_CTL_ERROR";
        case ERROR_STREAM_CTL_ERROR_AUTH: return "STREAM_CTL_ERROR_AUTH";
        case ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT: return "STREAM_CTL_ERROR_RESPONSE_FORMAT";
        case ERROR_NETWORK_CONNECTION_TIMEOUT: return "NETWORK_CONNECTION_TIMEOUT";
        default : return "UNDEFINED";
    }
}

/**
 * @brief dap_client_get_error_str
 * @param a_client
 * @return
 */
const char * dap_client_get_error_str(dap_client_t * a_client)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_error_str");
        return NULL;
    }
    return dap_client_error_str( DAP_CLIENT_PVT(a_client)->last_error );
}
/**
 * @brief dap_client_get_stage
 * @param a_client
 * @return
 */
dap_client_stage_t dap_client_get_stage(dap_client_t * a_client)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_stage");
        return -1;
    }
    return DAP_CLIENT_PVT(a_client)->stage;
}

/**
 * @brief dap_client_get_stage_status_str
 * @param a_client
 * @return
 */
const char * dap_client_get_stage_status_str(dap_client_t *a_client){
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_stage_status_str");
        return NULL;
    }
    return dap_client_stage_status_str(DAP_CLIENT_PVT(a_client)->stage_status);
}

/**
 * @brief dap_client_stage_status_str
 * @param a_stage_status
 * @return
 */
const char * dap_client_stage_status_str(dap_client_stage_status_t a_stage_status)
{
    switch(a_stage_status){
        case STAGE_STATUS_NONE: return "NONE";
        case STAGE_STATUS_IN_PROGRESS: return "IN_PROGRESS";
        case STAGE_STATUS_ERROR: return "ERROR";
        case STAGE_STATUS_DONE: return "DONE";
        default: return "UNDEFINED";
    }
}

/**
 * @brief dap_client_get_stage_str
 * @param a_client
 * @return
 */
const char * dap_client_get_stage_str(dap_client_t *a_client)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_stage_str");
        return NULL;
    }
    return dap_client_stage_str(DAP_CLIENT_PVT(a_client)->stage);
}

/**
 * @brief dap_client_stage_str
 * @param a_stage
 * @return
 */
const char * dap_client_stage_str(dap_client_stage_t a_stage)
{
    switch(a_stage){
        case STAGE_BEGIN: return "BEGIN";
        case STAGE_ENC_INIT: return "ENC";
        case STAGE_STREAM_CTL: return "STREAM_CTL";
        case STAGE_STREAM_SESSION: return "STREAM_SESSION";
        case STAGE_STREAM_CONNECTED: return "STREAM_CONNECTED";
        case STAGE_STREAM_STREAMING: return "STREAM";
        case STAGE_STREAM_ABORT: return "ABORT";
        default: return "UNDEFINED";
    }
}
/**
 * @brief dap_client_get_stage_status
 * @param a_client
 * @return
 */
dap_client_stage_status_t dap_client_get_stage_status(dap_client_t * a_client)
{
    return (a_client && DAP_CLIENT_PVT(a_client)) ? DAP_CLIENT_PVT(a_client)->stage_status : STAGE_STATUS_NONE;
}

/**
 * @brief dap_client_get_key_stream
 * @param a_client
 * @return
 */
dap_enc_key_t * dap_client_get_key_stream(dap_client_t * a_client){
    return (a_client && DAP_CLIENT_PVT(a_client)) ? DAP_CLIENT_PVT(a_client)->stream_key : NULL;
}


/**
 * @brief dap_client_get_stream
 * @param a_client
 * @return
 */
dap_stream_t * dap_client_get_stream(dap_client_t * a_client)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_stream");
        return NULL;
    }

    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    return (l_client_internal) ? l_client_internal->stream : NULL;
}

/**
 * @brief dap_client_get_stream_worker
 * @param a_client
 * @return
 */
dap_stream_worker_t * dap_client_get_stream_worker(dap_client_t * a_client)
{
    if(a_client == NULL){
        log_it(L_ERROR,"Client is NULL for dap_client_get_stream_worker");
        return NULL;
    }
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    return (l_client_internal) ? l_client_internal->stream_worker : NULL;

}

dap_stream_ch_t * dap_client_get_stream_ch_unsafe(dap_client_t * a_client, uint8_t a_ch_id)
{
    dap_stream_ch_t * l_ch = NULL;
    dap_client_pvt_t * l_client_internal = a_client ? DAP_CLIENT_PVT(a_client) : NULL;
    if(l_client_internal && l_client_internal->stream && l_client_internal->stream_es)
        for(size_t i = 0; i < l_client_internal->stream->channel_count; i++) {
            if(l_client_internal->stream->channel[i]->proc->id == a_ch_id) {
                l_ch = l_client_internal->stream->channel[i];
                break;
            }
        }
    return l_ch;
}

/**
 * @brief dap_client_get_stream_id
 * @param a_client
 * @return
 */
const char * dap_client_get_stream_id(dap_client_t * a_client)
{
    if(!(a_client || !DAP_CLIENT_PVT(a_client)))
        return NULL;
    return DAP_CLIENT_PVT(a_client)->stream_id;
}

/**
 * @brief dap_client_get_is_always_reconnect
 * @param a_client
 * @return
 */
bool dap_client_get_is_always_reconnect(dap_client_t * a_client)
{
    assert(a_client);
    return DAP_CLIENT_PVT(a_client)->is_always_reconnect;
}

/**
 * @brief dap_client_set_is_always_reconnect
 * @param a_client
 * @param a_value
 */
void dap_client_set_is_always_reconnect(dap_client_t * a_client, bool a_value)
{
    assert(a_client);
    DAP_CLIENT_PVT(a_client)->is_always_reconnect = a_value;
}

/**
 * @brief dap_client_from_esocket
 * @param a_esocket
 * @return
 */
dap_client_t * dap_client_from_esocket(dap_events_socket_t * a_esocket)
{
   dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t *) a_esocket->_inheritor;
   return l_client_pvt?l_client_pvt->client: NULL;
}

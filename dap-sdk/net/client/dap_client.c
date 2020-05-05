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
#include "dap_stream_ch_proc.h"

#define LOG_TAG "dap_client"

// FSM realization: thats callback executes after the every stage is done
// and have to select the next one stage
void m_stage_fsm_operator(dap_client_t *, void *);

/**
 * @brief dap_client_init
 * @return
 */
int dap_client_init()
{
    static bool s_is_first_time=true;
    if (s_is_first_time ){
        log_it(L_INFO, "Init DAP client module");
        dap_http_client_init();
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


    dap_client_pvt_new(DAP_CLIENT_PVT(l_client) );

    return l_client;

MEM_ALLOC_ERR:
    log_it(L_ERROR, "dap_client_new can not allocate memory");
    if (l_client)
        if(l_client->_internal)
            free(l_client->_internal);

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
void dap_client_set_uplink(dap_client_t * a_client,const char* a_addr, uint16_t a_port)
{
    if(a_addr == NULL){
        log_it(L_ERROR,"Address is NULL");
        return;
    }
    DAP_CLIENT_PVT(a_client)->uplink_addr = strdup(a_addr);
    DAP_CLIENT_PVT(a_client)->uplink_port = a_port;
}

/**
 * @brief dap_client_get_uplink_addr
 * @param a_client
 * @return
 */
const char* dap_client_get_uplink_addr(dap_client_t * a_client)
{
    return DAP_CLIENT_PVT(a_client)->uplink_addr;
}

/**
 * @brief dap_client_set_active_channels
 * @param a_client
 * @param a_active_channels
 */
void dap_client_set_active_channels (dap_client_t * a_client, const char * a_active_channels)
{
    if ( DAP_CLIENT_PVT(a_client)->active_channels )
        DAP_DELETE(DAP_CLIENT_PVT(a_client)->active_channels );
    DAP_CLIENT_PVT(a_client)->active_channels = dap_strdup( a_active_channels);
}


/**
 * @brief dap_client_get_uplink_port
 * @param a_client
 * @return
 */
uint16_t dap_client_get_uplink_port(dap_client_t * a_client)
{
    return DAP_CLIENT_PVT(a_client)->uplink_port;
}


/**
 * @brief dap_client_reset
 * @param a_client
 */
void dap_client_reset(dap_client_t * a_client)
{
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);

    if(l_client_internal->session_key){
        dap_enc_key_delete(l_client_internal->session_key);
        l_client_internal->session_key = NULL;

    }
    if(l_client_internal->session_key_id){
        DAP_DELETE(l_client_internal->session_key_id);
        l_client_internal->session_key_id = NULL;
    }
    if ( l_client_internal->stream_key ){
        dap_enc_key_delete(l_client_internal->stream_key );
        l_client_internal->stream_key = NULL;
    }
    l_client_internal->stream_es = NULL;

    l_client_internal->stage = STAGE_BEGIN;
    l_client_internal->stage_status = STAGE_STATUS_DONE ;
    l_client_internal->stage_target = STAGE_BEGIN ;
}


/**
 * @brief dap_client_delete
 * @param a_client
 */
void dap_client_delete(dap_client_t * a_client)
{
    if(!a_client)
        return;

    pthread_mutex_lock(&a_client->mutex);

    //dap_client_disconnect(a_client);
    //dap_client_reset(a_client);

    //dap_client_pvt_t *l_client_pvt = DAP_CLIENT_PVT(a_client);
    // reset l_client_pvt (before removal)
    //memset(l_client_pvt, 0, sizeof(dap_client_pvt_t));
    //a_client->_internal = NULL;

    dap_client_pvt_delete(DAP_CLIENT_PVT(a_client));
    //a_client->_internal = NULL;

    //pthread_mutex_t *l_mutex = &a_client->mutex;
    //memset(a_client, 0, sizeof(dap_client_t));
    //pthread_mutex_unlock(l_mutex);
    pthread_mutex_unlock(&a_client->mutex);
    // a_client will be deleted in dap_events_socket_delete() -> free( a_es->_inheritor );
    //DAP_DELETE(a_client);
    DAP_DELETE(a_client);
    a_client = NULL;
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
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);

    l_client_internal->stage_target = a_stage_target;
    l_client_internal->stage_target_done_callback = a_stage_end_callback;
    if(a_stage_target != l_client_internal->stage ){ // Going to stages downstairs
        switch(l_client_internal->stage_status ){
            case STAGE_STATUS_ABORTING:
                log_it(L_ERROR, "Already aborting the stage %s"
                        , dap_client_stage_str(l_client_internal->stage));
            break;
            case STAGE_STATUS_IN_PROGRESS:{
                log_it(L_WARNING, "Status progress the stage %s"
                        , dap_client_stage_str(l_client_internal->stage));
            }break;
            case STAGE_STATUS_DONE:
            case STAGE_STATUS_ERROR:
            default: {
                log_it(L_DEBUG, "Start transitions chain to %s"
                       ,dap_client_stage_str(l_client_internal->stage_target) );
                int step = (a_stage_target > l_client_internal->stage)?1:-1;
                dap_client_pvt_stage_transaction_begin(l_client_internal,
                                                            l_client_internal->stage+step,
                                                            m_stage_fsm_operator
                                                            );
            }
        }
    }else{  // Same stage
        log_it(L_ERROR,"We're already on stage %s",dap_client_stage_str(a_stage_target));
    }
}

/**
 * @brief m_stage_fsm_operator
 * @param a_client
 * @param a_arg
 */
void m_stage_fsm_operator(dap_client_t * a_client, void * a_arg)
{
    UNUSED(a_arg);
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    if(!l_client_internal){
        log_it(L_ERROR, "FSM Op: l_client_internal is NULL!");
        return;
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
                                                l_stage_next, m_stage_fsm_operator
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
void dap_client_request_enc(dap_client_t * a_client, const char * a_path, const char * a_suburl,const char* a_query, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error )
{
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    dap_client_pvt_request_enc(l_client_internal, a_path, a_suburl, a_query,a_request,a_request_size, a_response_proc,a_response_error);
}

void dap_client_request(dap_client_t * a_client, const char * a_full_path, void * a_request, size_t a_request_size,
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
        case ERROR_ENC_NO_KEY: return "ENC_NO_KEY";
        case ERROR_ENC_WRONG_KEY: return "ENC_WRONG_KEY";
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
   return dap_client_error_str( DAP_CLIENT_PVT(a_client)->last_error );
}
/**
 * @brief dap_client_get_stage
 * @param a_client
 * @return
 */
dap_client_stage_t dap_client_get_stage(dap_client_t * a_client)
{
    return DAP_CLIENT_PVT(a_client)->stage;
}

/**
 * @brief dap_client_get_stage_status_str
 * @param a_client
 * @return
 */
const char * dap_client_get_stage_status_str(dap_client_t *a_client){
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
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    return (l_client_internal) ? l_client_internal->stream : NULL;
}

dap_stream_ch_t * dap_client_get_stream_ch(dap_client_t * a_client, uint8_t a_ch_id)
{
    dap_stream_ch_t * l_ch = NULL;
    dap_client_pvt_t * l_client_internal = a_client ? DAP_CLIENT_PVT(a_client) : NULL;
    if(l_client_internal && l_client_internal->stream)
        for(int i = 0; i < l_client_internal->stream->channel_count; i++) {
            dap_stream_ch_proc_t *l_ch_id = l_client_internal->stream->channel[i]->proc;
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

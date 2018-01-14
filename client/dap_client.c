#include <string.h>

#include "dap_common.h"

#include "../http/dap_http_client.h"

#include "dap_client.h"
#include "dap_client_internal.h"

#define LOG_TAG "dap_client"

/**
 * @brief dap_client_init
 * @return
 */
int dap_client_init()
{
    log_it(L_INFO, "Init DAP client module");
    dap_http_client_init();
    dap_client_internal_init();
    return 0;
}

/**
 * @brief dap_client_deinit
 */
void dap_client_deinit()
{
    dap_client_internal_deinit();
    dap_http_client_deinit();
    log_it(L_INFO, "Deinit DAP client module");
}

/**
 * @brief dap_client_new
 * @param a_stage_status_callback
 * @param a_stage_status_error_callback
 * @return
 */
dap_client_t * dap_client_new(dap_client_callback_t a_stage_status_callback
                              ,dap_client_callback_t a_stage_status_error_callback )
{
    // ALLOC MEM FOR dap_client
    dap_client_t *l_client = DAP_NEW_Z(dap_client_t);
    if (!l_client)
        goto MEM_ALLOC_ERR;

    l_client->_internal  = DAP_NEW_Z(dap_client_internal_t);
    if (!l_client->_internal)
        goto MEM_ALLOC_ERR;

    // CONSTRUCT dap_client object
    DAP_CLIENT_INTERNAL(l_client)->client = l_client;
    DAP_CLIENT_INTERNAL(l_client)->stage_status_callback = a_stage_status_callback;
    DAP_CLIENT_INTERNAL(l_client)->stage_status_error_callback = a_stage_status_error_callback;

    dap_client_internal_new(DAP_CLIENT_INTERNAL(l_client) );

    return l_client;

MEM_ALLOC_ERR:
    log_it(L_ERROR, "dap_client_new can not allocate memory");
    if (l_client)
        if(l_client->_internal)
            free(l_client->_internal);

    if (l_client)
        free (l_client);

}

/**
 * @brief dap_client_delete
 * @param a_client
 */
void dap_client_delete(dap_client_t * a_client)
{
    dap_client_internal_delete(DAP_CLIENT_INTERNAL(a_client));
    free(a_client);
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
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);

    l_client_internal->stage_target = a_stage_target;

    if(a_stage_target != l_client_internal->stage ){ // Going to stages downstairs
        switch(l_client_internal->stage_status ){
            case DAP_CLIENT_STAGE_STATUS_ABORTING:
                log_it(L_ERROR, "Already aborting the stage %s"
                        , dap_client_stage_str(l_client_internal->stage));
            break;
            case DAP_CLIENT_STAGE_STATUS_IN_PROGRESS:{
                log_it(L_WARNING, "Aborting the stage %s"
                        , dap_client_stage_str(l_client_internal->stage));
            }break;
            case DAP_CLIENT_STAGE_STATUS_DONE:
            case DAP_CLIENT_STAGE_STATUS_ERROR:
            default: {
                log_it(L_DEBUG, "Start transitions chain to %");
                int step = (a_stage_target > l_client_internal->stage)?1:-1;
                dap_client_internal_stage_transaction_begin(l_client_internal,l_client_internal->stage+step,a_stage_end_callback);
            }
        }
    }else{  // Same stage
        log_it(L_ERROR,"We're already on stage %s",dap_client_stage_str(a_stage_target));
    }
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
    dap_client_internal_t * l_client_internal = DAP_CLIENT_INTERNAL(a_client);
    dap_client_internal_request_enc(l_client_internal, a_path, a_suburl, a_query,a_request,a_request_size, a_response_proc,a_response_error);
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
    DAP_CLIENT_INTERNAL(a_client)->uplink_addr = strdup(a_addr);
    DAP_CLIENT_INTERNAL(a_client)->uplink_port = a_port;
}

/**
 * @brief dap_client_set_credentials
 * @param a_client
 * @param a_user
 * @param a_password
 */
void dap_client_set_credentials(dap_client_t * a_client,const char* a_user, const char * a_password)
{
    if(a_user == NULL){
        log_it(L_ERROR,"Username is NULL");
        return;
    }
    if(a_password == NULL){
        log_it(L_ERROR,"Password is NULL");
        return;
    }
    DAP_CLIENT_INTERNAL(a_client)->uplink_user = strdup(a_user);
}


/**
 * @brief dap_client_error_str
 * @param a_client_error
 * @return
 */
const char * dap_client_error_str(dap_client_error_t a_client_error)
{
    switch(a_client_error){
        case DAP_CLIENT_ERROR_ENC_NO_KEY: return "ENC_NO_KEY";
        case DAP_CLIENT_ERROR_ENC_WRONG_KEY: return "ENC_WRONG_KEY";
        case DAP_CLIENT_ERROR_AUTH_WRONG_COOKIE: return "AUTH_WRONG_COOKIE";
        case DAP_CLIENT_ERROR_AUTH_WRONG_CREDENTIALS: return "AUTH_WRONG_CREDENTIALS";
        case DAP_CLIENT_ERROR_NETWORK_CONNECTION_TIMEOUT: return "NETWORK_CONNECTION_TIMEOUT";
        case DAP_CLIENT_ERROR_NETWORK_CONNECTION_REFUSE: return "NETWORK_CONNECTION_REFUSE";
        case DAP_CLIENT_ERROR_NETWORK_DISCONNECTED: return "NETWORK_DISCONNECTED";
        case DAP_CLIENT_ERROR_STREAM_RESPONSE_WRONG: return "STREAM_RESPONSE_WRONG";
        case DAP_CLIENT_ERROR_STREAM_RESPONSE_TIMEOUT: return "STREAM_RESPONSE_TIMEOUT";
        case DAP_CLIENT_ERROR_STREAM_FREEZED: return "STREAM_FREEZED";
        case DAP_CLIENT_ERROR_LICENSE: return "LICENSE_ERROR";
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
   return dap_client_error_str( DAP_CLIENT_INTERNAL(a_client)->last_error );
}
/**
 * @brief dap_client_get_stage
 * @param a_client
 * @return
 */
dap_client_stage_t dap_client_get_stage(dap_client_t * a_client)
{
    return DAP_CLIENT_INTERNAL(a_client)->stage;
}

/**
 * @brief dap_client_get_stage_status_str
 * @param a_client
 * @return
 */
const char * dap_client_get_stage_status_str(dap_client_t *a_client){
    return dap_client_stage_status_str(DAP_CLIENT_INTERNAL(a_client)->stage_status);
}

/**
 * @brief dap_client_stage_status_str
 * @param a_stage_status
 * @return
 */
const char * dap_client_stage_status_str(dap_client_stage_status_t a_stage_status)
{
    switch(a_stage_status){
        case DAP_CLIENT_STAGE_STATUS_NONE: return "NONE";
        case DAP_CLIENT_STAGE_STATUS_IN_PROGRESS: return "IN_PROGRESS";
        case DAP_CLIENT_STAGE_STATUS_ERROR: return "ERROR";
        case DAP_CLIENT_STAGE_STATUS_DONE: return "DONE";
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
    return dap_client_stage_str(DAP_CLIENT_INTERNAL(a_client)->stage);
}

/**
 * @brief dap_client_stage_str
 * @param a_stage
 * @return
 */
const char * dap_client_stage_str(dap_client_stage_t a_stage)
{
    switch(a_stage){
        case DAP_CLIENT_STAGE_BEGIN: return "BEGIN";
        case DAP_CLIENT_STAGE_ENC: return "ENC";
        case DAP_CLIENT_STAGE_AUTH: return "AUTH";
        case DAP_CLIENT_STAGE_STREAM_CTL: return "STREAM_CTL";
        case DAP_CLIENT_STAGE_STREAM: return "STREAM";
        case DAP_CLIENT_STAGE_NETCONF: return "NETCONF";
        case DAP_CLIENT_STAGE_TUNNEL: return "TUNNEL";
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
    return DAP_CLIENT_INTERNAL(a_client)->stage_status;
}


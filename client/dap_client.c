#include <stddef.h>
#include "common.h"

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
    return 0;
}

/**
 * @brief dap_client_deinit
 */
void dap_client_deinit()
{
    log_it(L_INFO, "Deinit DAP client module");
}

/**
 * @brief dap_client_new
 * @param a_stage_status_callback
 * @return
 */
dap_client_t * dap_client_new(dap_client_callback_t a_stage_status_callback)
{

}

/**
 * @brief dap_client_delete
 * @param a_client
 */
void dap_client_delete(dap_client_t * a_client)
{

}

/**
 * @brief dap_client_go_stage
 * @param a_client
 * @param a_stage_end
 */
void dap_client_go_stage(dap_client_t * a_client, dap_client_stage_t a_stage_end,
                         dap_client_callback_t a_stage_end_callback)
{

}

/**
 * @brief dap_client_session_request
 * @param a_client
 * @param a_path
 * @param a_request
 * @param a_request_size
 * @param a_response_proc
 */
void dap_client_session_request(dap_client_t * a_client, const char * a_path, void * a_request, size_t a_request_size,
                                dap_client_callback_t a_response_proc)
{

}

/**
 * @brief dap_client_set_uplink
 * @param a_client
 * @param a_addr
 * @param a_port
 */
void dap_client_set_uplink(dap_client_t * a_client,const char* a_addr, uint16_t a_port)
{

}

/**
 * @brief dap_client_set_credentials
 * @param a_client
 * @param a_user
 * @param a_password
 */
void dap_client_set_credentials(dap_client_t * a_client,const char* a_user, const char * a_password)
{

}


/**
 * @brief dap_client_error_str
 * @param a_client_error
 * @return
 */
const char * dap_client_error_str(sap_client_error_t a_client_error)
{
    switch(a_client_error){
        case DAP_CLIENT_ERROR_ENC_NO_KEY: return "ENC_NO_KEY";
        case DAP_CLIENT_ERROR_ENC_WRONG_KEY: return "ENC_WRONG_KEY";
        case DAP_CLIENT_ERROR_AUTH_WRONG_COOKIE: return "AUTH_WRONG_COOKIE";
        case DAP_CLIENT_ERROR_AUTH_WRONG_CREDENTIALS: return "AUTH_WRONG_CREDENTIALS";
        case DAP_CLIENT_ERROR_NETWORK_CONNECTION_TIMEOUT: return "NETWORK_CONNECTION_TIMEOUT";
        case DAP_CLIENT_ERROR_NETWORK_CONNECTION_REFUSE: return "NETWORK_CONNECTION_REFUSE";
        case DAP_CLIENT_ERROR_NETWORK_DISCONNECTED: return "NETWORK_DISCONNECTED";
        default : return "UNDEFINED";
    }
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
const char * dap_client_get_stage_status_str(dap_client_t *a_client)
{
    switch(DAP_CLIENT_INTERNAL(a_client)->stage_status){
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
const char * dap_client_get_stage_str(dap_client_t * a_client)
{
    switch(DAP_CLIENT_INTERNAL(a_client)->stage){
        case DAP_CLIENT_STAGE_BEGIN: return "BEGIN";
        case DAP_CLIENT_STAGE_ENC: return "ENC";
        case DAP_CLIENT_STAGE_AUTH: return "AUTH";
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

#include "common.h"

#include "sap_client.h"
#include "sap_client_internal.h"

#define LOG_TAG "sap_client"

/**
 * @brief sap_client_init
 * @return
 */
int sap_client_init()
{
    log_it(L_INFO, "Init SAP client module");
    return 0;
}

/**
 * @brief sap_client_deinit
 */
void sap_client_deinit()
{
    log_it(L_INFO, "Deinit SAP client module");
}

/**
 * @brief sap_client_new
 * @param a_stage_status_callback
 * @return
 */
sap_client_t * sap_client_new(sap_client_callback_t a_stage_status_callback)
{

}

/**
 * @brief sap_client_delete
 * @param a_client
 */
void sap_client_delete(sap_client_t * a_client)
{

}

/**
 * @brief sap_client_go_stage
 * @param a_client
 * @param a_stage_end
 */
void sap_client_go_stage(sap_client_t * a_client, sap_client_stage_t a_stage_end, sap_client_callback_t a_stage_end_callback)
{

}

/**
 * @brief sap_client_session_request
 * @param a_client
 * @param a_path
 * @param a_request
 * @param a_request_size
 * @param a_response_proc
 */
void sap_client_session_request(sap_client_t * a_client, const char * a_path, void * a_request, size_t a_request_size,
                                sap_client_callback_t a_response_proc)
{

}

/**
 * @brief sap_client_set_uplink
 * @param a_client
 * @param a_addr
 * @param a_port
 */
void sap_client_set_uplink(sap_client_t * a_client,const char* a_addr, uint16_t a_port)
{

}

/**
 * @brief sap_client_set_credentials
 * @param a_client
 * @param a_user
 * @param a_password
 */
void sap_client_set_credentials(sap_client_t * a_client,const char* a_user, const char * a_password)
{

}


/**
 * @brief sap_client_error_str
 * @param a_client_error
 * @return
 */
const char * sap_client_error_str(sap_client_error_t a_client_error)
{
    switch(a_client_error){
        case SAP_CLIENT_ERROR_ENC_NO_KEY: return "ENC_NO_KEY";
        case SAP_CLIENT_ERROR_ENC_WRONG_KEY: return "ENC_WRONG_KEY";
        case SAP_CLIENT_ERROR_AUTH_WRONG_COOKIE: return "AUTH_WRONG_COOKIE";
        case SAP_CLIENT_ERROR_AUTH_WRONG_CREDENTIALS: return "AUTH_WRONG_CREDENTIALS";
        case SAP_CLIENT_ERROR_NETWORK_CONNECTION_TIMEOUT: return "NETWORK_CONNECTION_TIMEOUT";
        case SAP_CLIENT_ERROR_NETWORK_CONNECTION_REFUSE: return "NETWORK_CONNECTION_REFUSE";
        case SAP_CLIENT_ERROR_NETWORK_DISCONNECTED: return "NETWORK_DISCONNECTED";
        case SAP_CLIENT_ERROR_STREAM_RESPONSE_WRONG: return "STREAM_RESPONSE_WRONG";
        case SAP_CLIENT_ERROR_STREAM_RESPONSE_TIMEOUT: return "STREAM_RESPONSE_TIMEOUT";
        case SAP_CLIENT_ERROR_STREAM_FREEZED: return "STREAM_FREEZED";
        case SAP_CLIENT_ERROR_LICENSE: return "LICENSE_ERROR";
        default : return "UNDEFINED";
    }
}

/**
 * @brief sap_client_get_stage
 * @param a_client
 * @return
 */
sap_client_stage_t sap_client_get_stage(sap_client_t * a_client)
{
    return SAP_CLIENT_INTERNAL(a_client)->stage;
}

/**
 * @brief sap_client_get_stage_status_str
 * @param a_client
 * @return
 */
const char * sap_client_get_stage_status_str(sap_client_t *a_client)
{
    switch(SAP_CLIENT_INTERNAL(a_client)->stage_status){
        case SAP_CLIENT_STAGE_STATUS_NONE: return "NONE";
        case SAP_CLIENT_STAGE_STATUS_IN_PROGRESS: return "IN_PROGRESS";
        case SAP_CLIENT_STAGE_STATUS_ERROR: return "ERROR";
        case SAP_CLIENT_STAGE_STATUS_DONE: return "DONE";
        default: return "UNDEFINED";
    }
}

/**
 * @brief sap_client_get_stage_str
 * @param a_client
 * @return
 */
const char * sap_client_get_stage_str(sap_client_t * a_client)
{
    switch(SAP_CLIENT_INTERNAL(a_client)->stage){
        case SAP_CLIENT_STAGE_BEGIN: return "BEGIN";
        case SAP_CLIENT_STAGE_ENC: return "ENC";
        case SAP_CLIENT_STAGE_AUTH: return "AUTH";
        case SAP_CLIENT_STAGE_STREAM_CTL: return "STREAM_CTL";
        case SAP_CLIENT_STAGE_STREAM: return "STREAM";
        case SAP_CLIENT_STAGE_NETCONF: return "NETCONF";
        case SAP_CLIENT_STAGE_TUNNEL: return "TUNNEL";
        default: return "UNDEFINED";
    }
}
/**
 * @brief sap_client_get_stage_status
 * @param a_client
 * @return
 */
sap_client_stage_status_t sap_client_get_stage_status(sap_client_t * a_client)
{
    return SAP_CLIENT_INTERNAL(a_client)->stage_status;
}

#ifndef _DAP_CLIENT_H_
#define _DAP_CLIENT_H_

#include <stdint.h>
#include <stddef.h>

/**
 * @brief The dap_client_stage enum. Top level of client's state machine
 **/
typedef enum dap_client_stage {
    DAP_CLIENT_STAGE_BEGIN=0,
    DAP_CLIENT_STAGE_ENC=1,
    DAP_CLIENT_STAGE_AUTH=2,
} dap_client_stage_t;

typedef enum dap_client_stage_status {
    DAP_CLIENT_STAGE_STATUS_NONE=0,
    // Enc init stage
    DAP_CLIENT_STAGE_STATUS_IN_PROGRESS,
    DAP_CLIENT_STAGE_STATUS_ERROR,
    DAP_CLIENT_STAGE_STATUS_DONE,
} dap_client_stage_status_t;

typedef enum dap_client_error {
    DAP_CLIENT_ERROR_UNDEFINED = 0,
    DAP_CLIENT_ERROR_ENC_NO_KEY,
    DAP_CLIENT_ERROR_ENC_WRONG_KEY,
    DAP_CLIENT_ERROR_AUTH_WRONG_COOKIE,
    DAP_CLIENT_ERROR_AUTH_WRONG_CREDENTIALS,
    DAP_CLIENT_ERROR_NETWORK_CONNECTION_TIMEOUT,
    DAP_CLIENT_ERROR_NETWORK_CONNECTION_REFUSE,
    DAP_CLIENT_ERROR_NETWORK_DISCONNECTED,
} dap_client_error_t;


/**
 * @brief The dap_client struct
 */
typedef struct dap_client{
    void * _internal;
    void * _inheritor;
} dap_client_t;

typedef void (*dap_client_callback_t) (dap_client_t *, void*);

#ifdef __cplusplus
extern "C" {
#endif

int dap_client_init();
void dap_client_deinit();

dap_client_t * dap_client_new(dap_client_callback_t a_stage_status_callback);
void dap_client_delete(dap_client_t * a_client);

void dap_client_set_uplink(dap_client_t * a_client,const char* a_addr, uint16_t a_port);
void dap_client_go_stage(dap_client_t * a_client, dap_client_stage_t a_stage_end, dap_client_callback_t a_stage_end_callback);

void dap_client_set_credentials(dap_client_t * a_client,const char* a_user, const char * a_password);

void dap_client_enc_request(dap_client_t * a_client, const char * a_path, void * a_request, size_t a_request_size,
                                dap_client_callback_t a_response_proc);

const char * dap_client_get_stage_str(dap_client_t * a_client);
const char * dap_client_get_stage_status_str(dap_client_t * a_client);
const char * dap_client_error_str(dap_client_error_t a_client_error);
dap_client_stage_t dap_client_get_stage(dap_client_t * a_client);
dap_client_stage_status_t dap_client_get_stage_status(dap_client_t * a_client);

#ifdef __cplusplus
}
#endif

#endif

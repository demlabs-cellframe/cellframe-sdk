#ifndef _SAP_CLIENT_INTERNAL_H_
#define _SAP_CLIENT_INTERNAL_H_

#include "dap_client.h"

typedef struct dap_client_remote dap_client_remote_t;
typedef struct dap_enc_key dap_enc_key_t;

typedef struct dap_client_remote_internal
{
    dap_client_t * client;
    dap_client_remote_t * es;

    dap_enc_key_t * session_key;

    dap_client_stage_t stage;
    dap_client_stage_status_t stage_status;

    dap_client_callback_t stage_status_callback;
} dap_client_internal_t;

#define DAP_CLIENT_INTERNAL(a) ((dap_client_internal_t*) a->_internal )
#endif

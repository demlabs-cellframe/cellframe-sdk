#ifndef _DAP_CLIENT_INTERNAL_H_
#define _DAP_CLIENT_INTERNAL_H_

#include <stdbool.h>
#include <stdint.h>
#include "dap_client.h"

typedef struct dap_events_socket_t dap_events_socket_t;
typedef struct dap_enc_key dap_enc_key_t;
typedef struct dap_http_client dap_http_client_t;

typedef struct dap_client_internal
{
    dap_client_t * client;

    dap_http_client_t * http_client;

    dap_events_socket_t * es_stream;

    dap_enc_key_t * session_key;
    dap_enc_key_t * stream_key;
    char stream_id[25];

    char  * session_key_id;
    char * auth_cookie;

    char  * uplink_addr;
    uint16_t uplink_port;
    char  * uplink_user;
    char  * uplink_password;

    uint32_t uplink_protocol_version;

    char * last_parsed_node;


    dap_client_stage_t stage_target;
    dap_client_callback_t stage_target_done_callback;

    dap_client_stage_t stage;
    dap_client_stage_status_t stage_status;
    dap_client_error_t last_error;

    dap_client_callback_t stage_status_callback;

    dap_client_callback_t stage_status_done_callback;
    dap_client_callback_t stage_status_error_callback;

    bool is_encrypted;
    dap_client_callback_data_size_t request_response_callback;
    dap_client_callback_int_t request_error_callback;
} dap_client_internal_t;

#define DAP_CLIENT_INTERNAL(a) ((dap_client_internal_t*) a->_internal )


int dap_client_internal_init();
void dap_client_internal_deinit();

void dap_client_internal_stage_transaction_begin(dap_client_internal_t * dap_client_internal_t, dap_client_stage_t a_stage_next,
                                                 dap_client_callback_t a_done_callback);

void dap_client_internal_request(dap_client_internal_t * a_client_internal, const char * a_path, void * a_request,
                    size_t a_request_size,  dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error);

void dap_client_internal_request_enc(dap_client_internal_t * a_client_internal, const char * a_path, const char * a_sub_url,
                                     const char * a_query, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_error_proc);

void dap_client_internal_new(dap_client_internal_t * a_client_internal);
void dap_client_internal_delete(dap_client_internal_t * a_client_internal);

#endif

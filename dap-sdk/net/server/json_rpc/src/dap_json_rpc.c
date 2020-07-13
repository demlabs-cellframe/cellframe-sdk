#include "dap_json_rpc.h"

static bool init_module = false;

//void _dap_json_rpc_http_new_callback(dap_http_t *a_http, void *s_args);
//void _dap_json_rpc_http_delete_callback(dap_http_t *a_http, void *s_args);
void _dap_json_rpc_http_headers_read_callback(dap_http_client_t *a_http_client, void *a_args);
void _dap_json_rpc_http_headers_write_callback(dap_http_client_t *a_http_client, void *a_args);
void _dap_json_rpc_http_data_read_callback(dap_http_client_t *a_http_client, void *a_args);
void _dap_json_rpc_http_data_write_callback(dap_http_client_t *a_http_client, void *a_args);
//void _dap_json_rpc_http_error_callback(dap_http_t *a_http, void *s_args);
//dap_http_client_callback_t new_callback
//                      ,dap_http_client_callback_t delete_callback
//                      ,dap_http_client_callback_t headers_read_callback
//                      ,dap_http_client_callback_t headers_write_callback
//                      ,dap_http_client_callback_t data_read_callback
//                      ,dap_http_client_callback_t data_write_callback
//                      ,dap_http_client_callback_t error_callback

int dap_json_rpc_init(){
    init_module = true;
    return 0;
}

void dap_json_rpc_deinit(){
    //
}

void _dap_json_rpc_http_headers_read_callback(dap_http_client_t *a_http_client, void *a_args){
    (void) a_args;
    if (dap_strcmp(a_http_client->action, "POST") == 0){
        if(dap_strcmp(a_http_client->in_content_type, "application/json") == 0){
            a_http_client->reply_status_code = 200;
        } else {
            a_http_client->reply_status_code = 404;
            strcpy(a_http_client->reply_reason_phrase, "The request must be have content type: applicaton/json.");
        }
    } else {
        a_http_client->reply_status_code = 404;
        strcpy(a_http_client->reply_reason_phrase, "The request must be executed using the POST method.");
    }
}
void _dap_json_rpc_http_headers_write_callback(dap_http_client_t *a_http_client, void *a_args){
    if (a_http_client->reply_status_code == 200){
        dap_http_out_header_add(a_http_client,"Content-Type","application/json");
        dap_http_out_header_add(a_http_client,"Connnection","keep-alive");
        dap_http_out_header_add(a_http_client,"Cache-Control","no-cache");
        a_http_client->state_read=DAP_HTTP_CLIENT_STATE_DATA;
        dap_client_remote_ready_to_read(a_http_client->client,true);
    }
}
void _dap_json_rpc_http_data_read_callback(dap_http_client_t *a_http_client, void *a_args){
    (void) a_args;
    char *l_reading_data = DAP_NEW_SIZE(char, a_http_client->in_content_length);
    memcpy(l_reading_data, a_http_client->client->buf_in, a_http_client->in_content_length);
    dap_json_rpc_request_t *l_request = dap_json_rpc_request_from_json(l_reading_data);
    dap_json_rpc_request_handler(l_request, a_http_client->client);
}
void _dap_json_rpc_http_data_write_callback(dap_http_client_t *a_http_client, void *a_args){

}

void dap_json_rpc_add_proc_http(struct dap_http *sh, const char *URL){
    dap_http_add_proc(sh, URL, NULL,
                      NULL,
                      NULL,
                      _dap_json_rpc_http_headers_read_callback,
                      _dap_json_rpc_http_headers_write_callback,
                      _dap_json_rpc_http_data_read_callback,
                      _dap_json_rpc_http_headers_write_callback,
                      NULL);
    //dap_http_add_proc(sh, URL, )
}

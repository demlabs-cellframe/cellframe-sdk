#include "dap_json_rpc.h"

#define LOG_TAG "dap_json_rpc_rpc"

static bool init_module = false;

void _dap_json_rpc_http_headers_read_callback(dap_http_client_t *a_http_client, void *a_args);
void _dap_json_rpc_http_headers_write_callback(dap_http_client_t *a_http_client, void *a_args);
void _dap_json_rpc_http_data_read_callback(dap_http_client_t *a_http_client, void *a_args);
void _dap_json_rpc_http_data_write_callback(dap_http_client_t *a_http_client, void *a_args);

int dap_json_rpc_init(){
    init_module = true;
    return 0;
}

void dap_json_rpc_deinit(){
    //
}

//void _dap_json_rpc_http_headers_read_callback(dap_http_client_t *a_http_client, void *a_args){
//    (void) a_args;
//    if (dap_strcmp(a_http_client->action, "POST") == 0){
//        if(dap_strcmp(a_http_client->in_content_type, "application/json") == 0){
//            a_http_client->reply_status_code = 200;
//        } else {
//            a_http_client->reply_status_code = 404;
//            strcpy(a_http_client->reply_reason_phrase, "The request must be have content type: applicaton/json.");
//        }
//    } else {
//        a_http_client->reply_status_code = 404;
//        strcpy(a_http_client->reply_reason_phrase, "The request must be executed using the POST method.");
//    }
//}
//void _dap_json_rpc_http_headers_write_callback(dap_http_client_t *a_http_client, void *a_args){
//    if (a_http_client->reply_status_code == 200){
//        dap_http_out_header_add(a_http_client,"Content-Type","application/json");
//        dap_http_out_header_add(a_http_client,"Cache-Control","no-cache");
//        a_http_client->keep_alive = false;
//        dap_client_remote_ready_to_read(a_http_client->client,true);
//    }
//    a_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
//}
//void _dap_json_rpc_http_data_read_callback(dap_http_client_t *a_http_client, void *a_args){
//    (void) a_args;
//    char *l_reading_data = DAP_NEW_SIZE(char, a_http_client->in_content_length + 1);
//    l_reading_data[a_http_client->in_content_length] = '\0';
//    memcpy(l_reading_data, a_http_client->client->buf_in, a_http_client->in_content_length);
//    dap_json_rpc_request_t *l_request = dap_json_rpc_request_from_json(l_reading_data);
//    if (l_request){
//        dap_json_rpc_request_handler(l_request, a_http_client->client);
//        a_http_client->state_read=DAP_HTTP_CLIENT_STATE_NONE;
//        a_http_client->state_write=DAP_HTTP_CLIENT_STATE_DATA;
//    } else {
//        a_http_client->reply_status_code = 404;
//        strcpy(a_http_client->reply_reason_phrase, dap_strdup("Can't parse JSON"));
//    }
//}
//void _dap_json_rpc_http_data_write_callback(dap_http_client_t *a_http_client, void *a_args){

//}

void _json_rpc_http_proc(struct dap_http_simple *a_client, void *a_arg){
    log_it(L_DEBUG, "Proc json_rpc request");
    http_status_code_t *l_http_code = (http_status_code_t*)a_arg;
    dap_json_rpc_request_t *l_request = dap_json_rpc_request_from_json(a_client->request);
    if (l_request){
        dap_json_rpc_request_handler(l_request, a_client);
    } else {
        *l_http_code = Http_Status_NotFound;
    }
    *l_http_code = Http_Status_OK;
}

void dap_json_rpc_add_proc_http(struct dap_http *sh, const char *URL){
    dap_http_simple_proc_add(sh, URL, 140000, _json_rpc_http_proc);
//    dap_http_add_proc(sh, URL, NULL,
//                      NULL,
//                      NULL,
//                      _dap_json_rpc_http_headers_read_callback,
//                      _dap_json_rpc_http_headers_write_callback,
//                      _dap_json_rpc_http_data_read_callback,
//                      _dap_json_rpc_http_headers_write_callback,
//                      NULL);
    dap_json_rpc_request_init(URL);
}

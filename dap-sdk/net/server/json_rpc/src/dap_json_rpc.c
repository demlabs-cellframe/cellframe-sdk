#include "dap_json_rpc.h"

#define LOG_TAG "dap_json_rpc_rpc"

static bool init_module = false;

int dap_json_rpc_init()
{
    init_module = true;
    return 0;
}

void dap_json_rpc_deinit()
{
    //
}

void _json_rpc_http_proc(struct dap_http_simple *a_client, void *a_arg)
{
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

void dap_json_rpc_add_proc_http(struct dap_http *sh, const char *URL)
{
    dap_http_simple_proc_add(sh, URL, 140000, _json_rpc_http_proc);
    dap_json_rpc_request_init(URL);
}

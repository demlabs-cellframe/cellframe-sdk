
#include "dap_client_pool.h"

#define LOG_TAG "dap_client_pool"

// Single-linked peers list
struct dap_client_list{
    dap_client_t * item;
    char * id;
    struct dap_client_list * next;
};


void s_stage_status_callback(dap_client_t * a_client, void* a_arg);
void s_stage_status_error_callback(dap_client_t * a_client, void* a_arg);

dap_events_t * s_events = NULL;
/**
 * @brief dap_client_pool_init
 * @param a_events
 * @return
 */
int dap_client_pool_init(dap_events_t * a_events)
{
    s_events = a_events;
    return 0;
}

void dap_client_pool_deinit()
{
}

/**
 * @brief dap_client_pool_new
 * @param a_client_id
 * @return
 */
dap_client_t * dap_client_pool_new(const char * a_client_id)
{
    dap_client_t * l_client = dap_client_new(s_events, s_stage_status_callback
                                  , s_stage_status_error_callback );
    return  l_client;
}

void s_stage_status_callback(dap_client_t * a_client, void* a_arg)
{

}

void s_stage_status_error_callback(dap_client_t * a_client, void* a_arg)
{

}

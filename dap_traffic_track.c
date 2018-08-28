#include "dap_traffic_track.h"
#include "dap_common.h"

#define LOG_TAG "dap_traffic_track"

static dap_traffic_callback_t callback = NULL;
static dap_server_client_t * server_clients;
static ev_timer timeout_watcher;
static struct ev_loop *loop;

static void timeout_cb()
{
    if(callback != NULL) {
        callback(NULL, NULL);
        return;
    }
    log_it(L_WARNING, "Callback is NULL!");
}

void dap_traffic_track_init(dap_server_client_t * clients,
                            time_t timeout)
{
    server_clients = clients;
    timeout_watcher.repeat = timeout;
    loop = EV_DEFAULT;
    ev_init(&timeout_watcher, timeout_cb);
    ev_timer_again (loop, &timeout_watcher);
    log_it(L_NOTICE, "Initialized traffic track module");
}

void dap_traffic_track_deinit()
{
    ev_timer_stop(loop, &timeout_watcher);
    log_it(L_NOTICE, "Deinitialized traffic track module");
}

void dap_traffic_set_callback(dap_traffic_callback_t cb)
{
   callback = cb;
}

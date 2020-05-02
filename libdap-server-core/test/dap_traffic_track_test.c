#include "dap_traffic_track_test.h"
#include <unistd.h>
#include <ev.h>
#include <math.h>
#if 0

static struct ev_loop *loop;

static struct moc_dap_clients_remote {
  dap_client_remote_t ** clients;
    size_t count;
} moc_dap_clients_remote;

static dap_server_t * _dap_server;

// false == test failed
static bool is_callback_result_success = false;

static void success_callback(dap_server_t* server)
{
    dap_pass_msg("Call success_callback");
    pthread_mutex_lock(&_dap_server->mutex_on_hash);
    size_t cnt = HASH_COUNT(server->clients);
    pthread_mutex_unlock(&_dap_server->mutex_on_hash);
    dap_assert(cnt == moc_dap_clients_remote.count, "Dap server amount clients");
    is_callback_result_success = true;
}

static void test_callback() {
    time_t timeout_sucess = 1;
    dap_traffic_track_init(_dap_server, timeout_sucess);
    dap_traffic_callback_set(success_callback);

    loop = EV_DEFAULT;
    ev_run(loop, EVRUN_ONCE);

    usleep(10000); // wait for callback
    dap_assert(is_callback_result_success, "Callback_result");
    dap_traffic_callback_stop();
}


void init_test_case() {
    _dap_server = DAP_NEW_Z(dap_server_t);
    moc_dap_clients_remote.count = 111;
    moc_dap_clients_remote.clients = calloc(moc_dap_clients_remote.count,
                                            sizeof(dap_client_remote_t *));
    for(size_t i = 0, j = 0; (i < moc_dap_clients_remote.count) && (j = i + 1); i++) {
        moc_dap_clients_remote.clients[i] =
            dap_client_remote_create(_dap_server, j, NULL);
    }
}

void cleanup_test_case() {
    for(size_t i = 0; i < moc_dap_clients_remote.count; i++)
      dap_client_remote_remove(moc_dap_clients_remote.clients[i], _dap_server);
    ev_loop_destroy(loop);
    DAP_DELETE(moc_dap_clients_remote.clients);
    DAP_DELETE(_dap_server);
}


void dap_traffic_track_tests_run(void) {
    dap_print_module_name("traffic_track");
    init_test_case();
    test_callback();
    cleanup_test_case();
}
#endif

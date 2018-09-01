#include "dap_traffic_track_test.h"
#include <ev.h>
#include <math.h>

static struct ev_loop *loop;

static struct moc_dap_server_clients {
    dap_server_client_t ** clients;
    size_t count;
} moc_dap_server_clients;
static dap_server_t * _dap_server;

static void success_callback(dap_traffic_track_result_t res[], size_t result_length) {
    dap_assert(result_length == moc_dap_server_clients.count, "dap server amount clients");

    for(size_t i = 0, j = 0; (i < result_length) && (j = i + 1); i++) {
        dap_assert_PIF(rint(res[i].download_speed_mbs) == (j * 8), "Calculate download traffic speed");
        dap_assert_PIF(rint(res[i].upload_speed_mbs) == (j * 8), "Calculate upload traffic speed");
    }
    ev_break (EV_A_ EVBREAK_ONE);
}

_Noreturn static void error_callback() {
    dap_fail("Error callback call, success_callback has no been called");
}

static void test_callback() {
    time_t timeout_sucess = 1;
    loop = EV_DEFAULT;
    /* timeout sucess_callback must be 1 for sucess calculating result*/
    dap_traffic_track_init(_dap_server, timeout_sucess);
    dap_traffic_set_callback(success_callback);

    /* Add error watcher*/
    static ev_timer timeout_error_watcher;
    ev_init(&timeout_error_watcher, error_callback);
    ev_timer_init (&timeout_error_watcher, error_callback, timeout_sucess * 2, 0.);
    ev_timer_start (loop, &timeout_error_watcher);
    ev_run (loop, 0);
}


void init_test_case() {
    _dap_server = DAP_NEW_Z(dap_server_t);
    moc_dap_server_clients.count = 111;
    moc_dap_server_clients.clients = calloc(moc_dap_server_clients.count,
                                            sizeof(dap_server_client_t *));
    for(size_t i = 0, j = 0; (i < moc_dap_server_clients.count) && (j = i + 1); i++) {
        moc_dap_server_clients.clients[i] = dap_client_create(_dap_server, j, NULL);
        moc_dap_server_clients.clients[i]->upload_stat.buf_size_total = j * 1000000;
        moc_dap_server_clients.clients[i]->download_stat.buf_size_total = j * 1000000;
    }
}

void cleanup_test_case() {
    for(size_t i = 0; i < moc_dap_server_clients.count; i++)
        dap_client_remove(moc_dap_server_clients.clients[i], _dap_server);
    ev_loop_destroy(loop);
    DAP_DELETE(moc_dap_server_clients.clients);
    DAP_DELETE(_dap_server);
}


void dap_traffic_track_tests_run(void) {
    dap_print_module_name("traffic_track");
    init_test_case();
    test_callback();
    cleanup_test_case();
}

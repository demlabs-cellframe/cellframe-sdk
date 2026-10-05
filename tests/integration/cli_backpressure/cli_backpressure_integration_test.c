/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2026
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file cli_backpressure_integration_test.c
 * @brief Integration tests for the CLI/RPC dead-client check and backpressure
 *        gate that cli_backpressure_unit_test.c cannot reach, because both
 *        mechanisms are wired into s_cli_cmd_schedule() (dap_cli_server.c),
 *        which only ever runs against a real dap_events_socket_t produced by
 *        a real listening dap_server_t - not against dap_cli_cmd_exec()
 *        called directly in-process (the pattern used by the other CLI
 *        integration tests in this tree, which test command *logic*, not
 *        the socket/backpressure layer itself).
 * @details Runs a real dap_cli_server_init()'d server on a unix-domain
 *          socket and drives it with plain POSIX socket clients, mirroring
 *          the wire format dap_app_cli_net.c/dap_app_cli_post_command() use
 *          in production (an HTTP-ish POST with a Content-Length header and
 *          a JSON-RPC body).
 *
 *          Test 1 (control): a normal request over a live socket gets a
 *          real "200 OK" HTTP reply - establishes the harness actually
 *          works end-to-end before testing the interesting edge cases.
 *
 *          Test 2 (dead-client check, deterministic): dap_cli_server_client_
 *          is_alive()/s_cli_live_client_check() is a point-in-time check
 *          made once, right before a command starts running - it is NOT
 *          cooperative cancellation and does not abort a command already in
 *          flight (see the doc comment on s_cli_live_client_check() in
 *          dap_cli_server.c). This test proves exactly that documented
 *          boundary deterministically: a blocking command is confirmed
 *          dispatched (so the alive-check already passed), the client is
 *          then closed while the command is still blocked inside its
 *          handler, and the command is confirmed to run to completion
 *          anyway. (The opposite scenario - client closes before the
 *          command thread's alive-check runs - is a genuine race between
 *          the worker's epoll loop and the freshly spawned pthread even in
 *          production; asserting a specific winner would make this test
 *          flaky, so it is intentionally not attempted here.)
 *
 *          Test 3 (backpressure, real 429 over a live socket): with
 *          max_inflight configured to a small number, that many blocking
 *          commands are dispatched to saturate the regular inflight
 *          counter, and one more connection is confirmed to receive a real
 *          "HTTP/1.1 429 Too Many Requests" response on the wire - the
 *          actual client-visible behavior, complementing
 *          cli_backpressure_unit_test.c's direct acquire/release checks.
 *
 *          Tests 4-5: GET /health readiness probe and a command turning its
 *          reply into 503 + Retry-After.
 *
 *          Test 6: a streamed listing plus an error object added after
 *          streaming started arrives as one well-formed JSON-RPC body, over
 *          several rounds on the reused executor threads.
 *
 *          Test 7: a reply larger than the esocket output cap makes the
 *          server drop the connection right away, instead of leaving the
 *          client waiting for the inactivity timeout.
 *
 *          The per-/16 rate limiter (s_cli_rate_limit_check) is out of
 *          scope here too: it explicitly bypasses loopback and unix-socket
 *          callers (see its doc comment in dap_cli_server.c), so exercising
 *          it for real would require a non-loopback source address, which
 *          is not practical to fake portably in a CI sandbox.
 * @date 2026-09-24
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#ifndef DAP_OS_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#endif

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"
#include "dap_cli_server.h"
#include "dap_events_socket.h"
#include "dap_json_rpc_errors.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"

#define LOG_TAG "cli_backpressure_integration_test"

static char s_sock_path[512];

// --- Slow, blocking test command --------------------------------------
// Registered once; every test that needs a command dispatch thread to sit
// blocked (so we can deterministically observe/control "still running")
// sends this. s_slow_release gates it; reset between tests via
// s_slow_reset().
static _Atomic int s_slow_started = 0;
static _Atomic int s_slow_completed = 0;
static pthread_mutex_t s_slow_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_slow_cond = PTHREAD_COND_INITIALIZER;
static bool s_slow_release = false;

static void s_slow_reset(void)
{
    atomic_store(&s_slow_started, 0);
    atomic_store(&s_slow_completed, 0);
    pthread_mutex_lock(&s_slow_mutex);
    s_slow_release = false;
    pthread_mutex_unlock(&s_slow_mutex);
}

static int s_cmd_slow(int argc, char **argv, void **a_str_reply, int a_version)
{
    (void)argc; (void)argv; (void)a_version;
    atomic_fetch_add(&s_slow_started, 1);
    pthread_mutex_lock(&s_slow_mutex);
    while (!s_slow_release)
        pthread_cond_wait(&s_slow_cond, &s_slow_mutex);
    pthread_mutex_unlock(&s_slow_mutex);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "slow-done");
    atomic_fetch_add(&s_slow_completed, 1);
    return 0;
}

static void s_slow_release_all(void)
{
    pthread_mutex_lock(&s_slow_mutex);
    s_slow_release = true;
    pthread_cond_broadcast(&s_slow_cond);
    pthread_mutex_unlock(&s_slow_mutex);
}

// Command that reports its dependency as not ready yet (503 + Retry-After)
static int s_cmd_warming(int argc, char **argv, void **a_str_reply, int a_version)
{
    (void)argc; (void)argv; (void)a_version;
    dap_cli_cmd_reply_set_unavailable(7);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "index warming");
    return -1;
}

// Streamed listing (dap_cli_cmd_reply_stream_begin_nested) with an error
// object added after the rows: the reply is assembled from detached
// dap_string buffers on the executor thread.
#define CLI_BP_IT_STREAM_ROWS 300
static int s_cmd_stream(int argc, char **argv, void **a_reply, int a_version)
{
    (void)argc; (void)argv; (void)a_version;
    json_object **l_arr = (json_object **)a_reply;
    dap_cli_cmd_reply_stream_begin_nested();
    for (int i = 0; i < CLI_BP_IT_STREAM_ROWS; i++) {
        json_object *l_row = json_object_new_object();
        json_object_object_add(l_row, "n", json_object_new_int(i));
        dap_cli_cmd_reply_add(l_arr, l_row);
    }
    dap_cli_cmd_reply_stream_nested_end();
    json_object *l_tail = json_object_new_object();
    json_object_object_add(l_tail, "rows", json_object_new_int(CLI_BP_IT_STREAM_ROWS));
    dap_cli_cmd_reply_add(l_arr, l_tail);
    dap_json_rpc_error_add(*l_arr, 77, "stream-tail-error");
    return 0;
}

// Reply far larger than the esocket output cap set in s_setup()
#define CLI_BP_IT_BUF_OUT_MAX (256 * 1024)
static int s_cmd_huge(int argc, char **argv, void **a_str_reply, int a_version)
{
    (void)argc; (void)argv; (void)a_version;
    size_t l_size = CLI_BP_IT_BUF_OUT_MAX * 4;
    char *l_text = DAP_NEW_SIZE(char, l_size + 1);
    if (!l_text)
        return -1;
    memset(l_text, 'x', l_size);
    l_text[l_size] = '\0';
    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_text);
    DAP_DELETE(l_text);
    return 0;
}

static _Atomic bool s_ready = false;

static bool s_ready_cb(char *a_reason, size_t a_reason_size)
{
    if (atomic_load(&s_ready))
        return true;
    snprintf(a_reason, a_reason_size, "test \"net\" syncing");   // quote must be escaped by the server
    return false;
}

// Bounded poll: returns true once *a_var >= a_target, false on timeout.
static bool s_wait_at_least(_Atomic int *a_var, int a_target, int a_timeout_ms)
{
    int l_waited = 0;
    while (atomic_load(a_var) < a_target && l_waited < a_timeout_ms) {
        usleep(10 * 1000);
        l_waited += 10;
    }
    return atomic_load(a_var) >= a_target;
}

// --- Minimal raw-socket JSON-RPC client, mirroring the wire format
// dap_app_cli_post_command() uses against the real unix-socket CLI port ---
static int s_client_connect(void)
{
    int l_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (l_fd < 0)
        return -1;
    struct sockaddr_un l_addr = { .sun_family = AF_UNIX };
    dap_strncpy(l_addr.sun_path, s_sock_path, sizeof(l_addr.sun_path) - 1);
    // The listener is bound+listen()'d synchronously inside
    // dap_cli_server_init() -> dap_server_listen_addr_add(), so the kernel
    // backlog already accepts connections by the time setup() returns;
    // still retry briefly in case of any scheduling jitter in CI.
    for (int i = 0; i < 50; ++i) {
        if (connect(l_fd, (struct sockaddr*)&l_addr, sizeof(l_addr)) == 0)
            return l_fd;
        usleep(10 * 1000);
    }
    close(l_fd);
    return -1;
}

static bool s_client_send_request(int a_fd, const char *a_method)
{
    char l_body[256];
    int l_body_len = snprintf(l_body, sizeof(l_body), "{\"id\":1,\"method\":\"%s\",\"params\":[[]]}", a_method);
    char l_req[512];
    int l_req_len = snprintf(l_req, sizeof(l_req),
        "POST /connect HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/text\r\nContent-Length: %d\r\n\r\n%s",
        l_body_len, l_body);
    return send(a_fd, l_req, (size_t)l_req_len, 0) == l_req_len;
}

// Reads until EOF or a_timeout_ms elapses, NUL-terminates into a_out.
static void s_client_read_response(int a_fd, char *a_out, size_t a_out_size, int a_timeout_ms)
{
    struct timeval l_tv = { .tv_sec = a_timeout_ms / 1000, .tv_usec = (a_timeout_ms % 1000) * 1000 };
    setsockopt(a_fd, SOL_SOCKET, SO_RCVTIMEO, &l_tv, sizeof(l_tv));
    size_t l_off = 0;
    while (l_off + 1 < a_out_size) {
        ssize_t l_n = recv(a_fd, a_out + l_off, a_out_size - 1 - l_off, 0);
        if (l_n <= 0)
            break;
        l_off += (size_t)l_n;
    }
    a_out[l_off] = '\0';
}

// --- Setup / teardown ----------------------------------------------------
static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    log_it(L_NOTICE, "=== CLI Backpressure/Dead-Client Integration Tests Setup ===");

    const char *l_tmp = test_get_temp_dir();
    char l_config_dir_buf[512], l_gdb_buf[512], l_certs_buf[512], l_wallets_buf[512];
    snprintf(l_config_dir_buf, sizeof(l_config_dir_buf), "%s%ccli_bp_it_config", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_gdb_buf, sizeof(l_gdb_buf), "%s%ccli_bp_it_gdb", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_certs_buf, sizeof(l_certs_buf), "%s%ccli_bp_it_certs", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_wallets_buf, sizeof(l_wallets_buf), "%s%ccli_bp_it_wallets", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(s_sock_path, sizeof(s_sock_path), "%s%ccli_bp_it.sock", l_tmp, DAP_DIR_SEPARATOR);

    dap_rm_rf(l_gdb_buf);
    dap_rm_rf(l_certs_buf);
    dap_rm_rf(l_wallets_buf);
    dap_rm_rf(l_config_dir_buf);
    remove(s_sock_path);

    dap_mkdir_with_parents(l_config_dir_buf);
    dap_mkdir_with_parents(l_certs_buf);
    dap_mkdir_with_parents(l_wallets_buf);

    // listen-path (DAP_CFG_PARAM_SOCK_PATH) is the real config key
    // dap_server_new()/dap_server_listen_addr_add() consult to open an
    // actual AF_UNIX listener - NOT "listen_unix_socket_path", which the
    // other CLI integration tests in this tree set but which dap_server.c
    // never reads, so those tests never open a real socket at all (they
    // only ever call dap_cli_cmd_exec() in-process). We need a real
    // listener here since the whole point is to exercise the live-esocket
    // code path.
    char l_config_content[4096];
    snprintf(l_config_content, sizeof(l_config_content),
        "[general]\n"
        "debug=true\n"
        "[cli-server]\n"
        "enabled=true\n"
        "debug_more=true\n"
        "version=1\n"
        "listen-path=[%s]\n"
        "max_inflight=2\n"
        "max_inflight_heavy=4\n"
        "[global_db]\n"
        "driver=mdbx\n"
        "path=%s\n"
        "[resources]\n"
        "ca_folders=%s\n"
        "wallets_path=%s\n",
        s_sock_path, l_gdb_buf, l_certs_buf, l_wallets_buf);

    char l_config_path[1024];
    snprintf(l_config_path, sizeof(l_config_path), "%s%ctest.cfg", l_config_dir_buf, DAP_DIR_SEPARATOR);
    FILE *l_config_file = fopen(l_config_path, "w");
    dap_assert_PIF(l_config_file != NULL, "Config file created");
    fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
    fclose(l_config_file);

    int l_env_init_res = test_env_init(l_config_dir_buf, l_gdb_buf);
    dap_assert(l_env_init_res == 0, "Test environment initialization");

    int l_cli_init_res = dap_cli_server_init(false, "cli-server");
    dap_assert(l_cli_init_res == 0, "CLI server initialization with a real unix-socket listener");

    dap_cli_cmd_t *l_slow_cmd = dap_cli_server_cmd_add("cli_bp_it_slow_cmd", s_cmd_slow, NULL,
                                                        "test slow/blocking command", "test slow/blocking command (extended)");
    dap_assert_PIF(l_slow_cmd != NULL, "Slow test command registered");
    dap_assert_PIF(dap_cli_server_cmd_add("cli_bp_it_warming_cmd", s_cmd_warming, NULL, "test 503 command", "test 503 command") != NULL,
                   "Warming test command registered");
    // Both names are in the JSON-reply command list, so the executor hands the
    // handler a json_object** reply array, as for real streaming commands.
    dap_assert_PIF(dap_cli_server_cmd_add("block", s_cmd_stream, NULL, "test streamed reply", "test streamed reply") != NULL,
                   "Streaming test command registered");
    dap_assert_PIF(dap_cli_server_cmd_add("cli_bp_it_huge_cmd", s_cmd_huge, NULL, "test huge reply", "test huge reply") != NULL,
                   "Huge-reply test command registered");
    dap_events_socket_set_buf_out_max(CLI_BP_IT_BUF_OUT_MAX);

    log_it(L_NOTICE, "Test environment initialized (real CLI server on %s)", s_sock_path);
}

static void s_teardown(void)
{
    log_it(L_DEBUG, "Starting teardown...");
    dap_events_socket_set_buf_out_max(DAP_EVENTS_SOCKET_BUF_LIMIT * 8);
    dap_cli_server_deinit();
    test_env_deinit();
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();

    const char *l_tmp = test_get_temp_dir();
    char l_config_dir_buf[512], l_gdb_buf[512], l_certs_buf[512], l_wallets_buf[512];
    snprintf(l_config_dir_buf, sizeof(l_config_dir_buf), "%s%ccli_bp_it_config", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_gdb_buf, sizeof(l_gdb_buf), "%s%ccli_bp_it_gdb", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_certs_buf, sizeof(l_certs_buf), "%s%ccli_bp_it_certs", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_wallets_buf, sizeof(l_wallets_buf), "%s%ccli_bp_it_wallets", l_tmp, DAP_DIR_SEPARATOR);
    dap_rm_rf(l_config_dir_buf);
    dap_rm_rf(l_gdb_buf);
    dap_rm_rf(l_certs_buf);
    dap_rm_rf(l_wallets_buf);
    remove(s_sock_path);
    log_it(L_NOTICE, "Teardown complete");
}

// --- Test 1: control - a normal request over the real socket succeeds ---
static void s_test_control_request_succeeds(void)
{
    dap_print_module_name("Integration Test 1: control request over real unix socket");
    s_slow_reset();

    int l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects to the real CLI unix socket");
    dap_assert_PIF(s_client_send_request(l_fd, "cli_bp_it_slow_cmd"), "Request sent");

    dap_assert_PIF(s_wait_at_least(&s_slow_started, 1, 2000),
                   "Command dispatched and started running (alive-check passed for a connected client)");
    s_slow_release_all();

    char l_resp[2048];
    s_client_read_response(l_fd, l_resp, sizeof(l_resp), 2000);
    close(l_fd);

    dap_assert_PIF(strstr(l_resp, "HTTP/1.1 200") != NULL, "Real HTTP 200 OK reply received over the live socket");
    dap_assert_PIF(s_wait_at_least(&s_slow_completed, 1, 2000), "Command completed");

    dap_pass_msg("Control request test passed");
}

// --- Test 2: dead-client check only guards dispatch, not in-flight work -
static void s_test_mid_flight_disconnect_does_not_abort(void)
{
    dap_print_module_name("Integration Test 2: dead-client check does not cancel in-flight command");
    s_slow_reset();

    int l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects");
    dap_assert_PIF(s_client_send_request(l_fd, "cli_bp_it_slow_cmd"), "Request sent");

    // Confirm the command was actually dispatched (its alive-check already
    // ran and passed, since the client is still connected at this point) -
    // this establishes we are testing the documented "already in flight"
    // case, not racing the dispatch itself.
    dap_assert_PIF(s_wait_at_least(&s_slow_started, 1, 2000),
                   "Command dispatched while client is still connected");

    // Now disconnect while the command is still blocked inside its handler.
    close(l_fd);
    // Give the framework's worker loop a moment to actually process the
    // peer close and run s_cli_cmd_delete()/s_cli_live_client_remove() -
    // irrelevant to the outcome here (the check already happened and
    // passed), but keeps the scenario realistic.
    usleep(200 * 1000);

    s_slow_release_all();
    dap_assert_PIF(s_wait_at_least(&s_slow_completed, 1, 2000),
                   "Command ran to completion despite the client having disconnected mid-flight "
                   "(point-in-time check, not cooperative cancellation - matches the documented "
                   "behavior of dap_cli_server_client_is_alive()/s_cli_live_client_check())");

    dap_pass_msg("Mid-flight disconnect test passed");
}

// --- Test 3: backpressure sends a real 429 over the live socket ---------
static void s_test_backpressure_returns_real_429(void)
{
    dap_print_module_name("Integration Test 3: saturated inflight cap returns real HTTP 429");
    s_slow_reset();

    // max_inflight=2 (see s_setup()'s config) - saturate it with two
    // blocking commands, each held open on its own connection.
    int l_fd1 = s_client_connect(), l_fd2 = s_client_connect();
    dap_assert_PIF(l_fd1 >= 0 && l_fd2 >= 0, "Two connections established");
    dap_assert_PIF(s_client_send_request(l_fd1, "cli_bp_it_slow_cmd"), "Request 1 sent");
    dap_assert_PIF(s_client_send_request(l_fd2, "cli_bp_it_slow_cmd"), "Request 2 sent");
    dap_assert_PIF(s_wait_at_least(&s_slow_started, 2, 2000),
                   "Both commands dispatched, regular inflight counter now saturated at max_inflight=2");

    // A third connection must be rejected with a real 429 on the wire -
    // the client-visible behavior the unit test (direct acquire/release
    // calls, no socket) cannot observe.
    int l_fd3 = s_client_connect();
    dap_assert_PIF(l_fd3 >= 0, "Third connection established");
    dap_assert_PIF(s_client_send_request(l_fd3, "cli_bp_it_slow_cmd"), "Request 3 sent");

    char l_resp3[512];
    s_client_read_response(l_fd3, l_resp3, sizeof(l_resp3), 2000);
    close(l_fd3);
    dap_assert_PIF(strstr(l_resp3, "HTTP/1.1 429") != NULL,
                   "Third request over the live socket is refused with a real 429 Too Many Requests");

    // Rejection must not have touched the counter for the two in-flight
    // commands - releasing them now must let both finish normally.
    s_slow_release_all();
    dap_assert_PIF(s_wait_at_least(&s_slow_completed, 2, 2000),
                   "Both originally-dispatched commands still complete normally after the 429");

    char l_resp1[2048], l_resp2[2048];
    s_client_read_response(l_fd1, l_resp1, sizeof(l_resp1), 2000);
    s_client_read_response(l_fd2, l_resp2, sizeof(l_resp2), 2000);
    close(l_fd1);
    close(l_fd2);
    dap_assert_PIF(strstr(l_resp1, "HTTP/1.1 200") != NULL, "Connection 1 got its real 200 OK reply");
    dap_assert_PIF(strstr(l_resp2, "HTTP/1.1 200") != NULL, "Connection 2 got its real 200 OK reply");

    dap_pass_msg("Backpressure real-429 test passed");
}

// --- Test 4: GET /health readiness probe -------------------------------
static void s_test_health_probe(void)
{
    dap_print_module_name("Integration Test 4: GET /health readiness probe");
    static const char c_probe[] = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    char l_resp[1024];

    // No callback registered: always ready
    int l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects");
    dap_assert_PIF(send(l_fd, c_probe, sizeof(c_probe) - 1, 0) == (ssize_t)(sizeof(c_probe) - 1), "Probe sent");
    s_client_read_response(l_fd, l_resp, sizeof(l_resp), 2000);
    close(l_fd);
    dap_assert_PIF(strstr(l_resp, "HTTP/1.1 200") && strstr(l_resp, "\"status\":\"ok\""),
                   "Probe without readiness callback answers 200 ok");
    dap_assert_PIF(strstr(l_resp, "\"max_inflight\":2"), "Probe reports the inflight limits");

    // Not ready: 503 + Retry-After, reason with a quote is sanitized
    dap_cli_server_ready_callback_set(s_ready_cb);
    l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects");
    dap_assert_PIF(send(l_fd, c_probe, sizeof(c_probe) - 1, 0) == (ssize_t)(sizeof(c_probe) - 1), "Probe sent");
    s_client_read_response(l_fd, l_resp, sizeof(l_resp), 2000);
    close(l_fd);
    dap_assert_PIF(strstr(l_resp, "HTTP/1.1 503") && strstr(l_resp, "Retry-After:"),
                   "Probe of a not-ready node answers 503 with Retry-After");
    dap_assert_PIF(strstr(l_resp, "\"status\":\"unavailable\"") && strstr(l_resp, "test  net  syncing"),
                   "503 body carries the sanitized reason");

    // Ready again
    atomic_store(&s_ready, true);
    l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects");
    dap_assert_PIF(send(l_fd, c_probe, sizeof(c_probe) - 1, 0) == (ssize_t)(sizeof(c_probe) - 1), "Probe sent");
    s_client_read_response(l_fd, l_resp, sizeof(l_resp), 2000);
    close(l_fd);
    dap_assert_PIF(strstr(l_resp, "HTTP/1.1 200"), "Probe of a ready node answers 200");
    dap_cli_server_ready_callback_set(NULL);

    dap_pass_msg("Health probe test passed");
}

// --- Test 5: a command can turn its reply into 503 ----------------------
static void s_test_command_unavailable_reply(void)
{
    dap_print_module_name("Integration Test 5: command reply as 503 + Retry-After");
    char l_resp[2048];
    int l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects");
    dap_assert_PIF(s_client_send_request(l_fd, "cli_bp_it_warming_cmd"), "Request sent");
    s_client_read_response(l_fd, l_resp, sizeof(l_resp), 2000);
    close(l_fd);
    dap_assert_PIF(strstr(l_resp, "HTTP/1.1 503 Service Unavailable") && strstr(l_resp, "Retry-After: 7"),
                   "Command that reported unavailable gets 503 with its Retry-After");
    dap_assert_PIF(strstr(l_resp, "index warming"), "JSON-RPC body is still delivered with the 503");

    // The flag is per-command: the next request on the (reused) executor
    // threads must be a plain 200 again.
    s_slow_reset();
    s_slow_release_all();
    for (int i = 0; i < 4; i++) {
        l_fd = s_client_connect();
        dap_assert_PIF(l_fd >= 0, "Client connects");
        dap_assert_PIF(s_client_send_request(l_fd, "cli_bp_it_slow_cmd"), "Request sent");
        s_client_read_response(l_fd, l_resp, sizeof(l_resp), 2000);
        close(l_fd);
        dap_assert_PIF(strstr(l_resp, "HTTP/1.1 200"), "Following command on a reused executor thread is 200 again");
    }
    dap_pass_msg("Command 503 reply test passed");
}

// --- Test 6: streamed reply arrives whole and well-formed ---------------
static void s_test_streamed_reply(void)
{
    dap_print_module_name("Integration Test 6: streamed reply with trailing error object");
    size_t l_resp_size = 64 * 1024;
    char *l_resp = DAP_NEW_Z_SIZE(char, l_resp_size);
    dap_assert_PIF(l_resp, "Response buffer allocated");
    // Several rounds on the reused executor threads: the thread-local stream
    // state must be fully reset after every command.
    for (int l_round = 0; l_round < 3; l_round++) {
        int l_fd = s_client_connect();
        dap_assert_PIF(l_fd >= 0, "Client connects");
        dap_assert_PIF(s_client_send_request(l_fd, "block"), "Request sent");
        s_client_read_response(l_fd, l_resp, l_resp_size, 2000);
        close(l_fd);
        dap_assert_PIF(strstr(l_resp, "HTTP/1.1 200"), "Streamed reply is a 200");
        char *l_body = strstr(l_resp, "\r\n\r\n");
        dap_assert_PIF(l_body, "Reply has a body");
        json_object *l_jobj = json_tokener_parse(l_body + 4);
        dap_assert_PIF(l_jobj, "Streamed body is valid JSON");
        json_object *l_result = NULL;
        dap_assert_PIF(json_object_object_get_ex(l_jobj, "result", &l_result) && json_object_is_type(l_result, json_type_array),
                       "Body carries the result array");
        // [ {errors}, [rows...], {rows} ]: the error added after the stream
        // started is prepended, the listing stays one nested element
        dap_assert_PIF(json_object_array_length(l_result) == 3, "Error entry, listing and tail are all present");
        json_object *l_errors = NULL;
        dap_assert_PIF(json_object_object_get_ex(json_object_array_get_idx(l_result, 0), "errors", &l_errors),
                       "Error object added after streaming started survives");
        json_object *l_rows = json_object_array_get_idx(l_result, 1);
        dap_assert_PIF(json_object_is_type(l_rows, json_type_array)
                       && json_object_array_length(l_rows) == CLI_BP_IT_STREAM_ROWS, "Every streamed row arrives");
        json_object *l_last = json_object_array_get_idx(l_rows, CLI_BP_IT_STREAM_ROWS - 1), *l_n = NULL;
        dap_assert_PIF(json_object_object_get_ex(l_last, "n", &l_n) && json_object_get_int(l_n) == CLI_BP_IT_STREAM_ROWS - 1,
                       "Rows keep their order");
        json_object_put(l_jobj);
    }
    DAP_DELETE(l_resp);
    dap_pass_msg("Streamed reply test passed");
}

// --- Test 7: a reply over the output cap disconnects the client ---------
static void s_test_reply_over_output_cap(void)
{
    dap_print_module_name("Integration Test 7: reply larger than the esocket output cap");
    int l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects");
    dap_assert_PIF(s_client_send_request(l_fd, "cli_bp_it_huge_cmd"), "Request sent");
    // The client neither reads nor closes: only the server can end this
    // exchange, and it must do so well before the 60 s inactivity timeout.
    struct timeval l_tv = { .tv_sec = 5 };
    setsockopt(l_fd, SOL_SOCKET, SO_RCVTIMEO, &l_tv, sizeof(l_tv));
    char l_buf[4096];
    ssize_t l_total = 0, l_n;
    errno = 0;
    while ((l_n = recv(l_fd, l_buf, sizeof(l_buf), 0)) > 0)
        l_total += l_n;
    bool l_timed_out = l_n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    close(l_fd);
    dap_assert_PIF(!l_timed_out, "Server closes the connection instead of leaving the client hanging");
    dap_assert_PIF(l_total == 0, "No truncated reply is passed off as a complete one");

    // The refusal is per connection: an ordinary request right after it works.
    s_slow_reset();
    s_slow_release_all();
    char l_resp[2048];
    l_fd = s_client_connect();
    dap_assert_PIF(l_fd >= 0, "Client connects");
    dap_assert_PIF(s_client_send_request(l_fd, "cli_bp_it_slow_cmd"), "Request sent");
    s_client_read_response(l_fd, l_resp, sizeof(l_resp), 2000);
    close(l_fd);
    dap_assert_PIF(strstr(l_resp, "HTTP/1.1 200"), "Next request is served normally");
    dap_pass_msg("Output cap test passed");
}

int main(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);

    printf("CLI Backpressure/Dead-Client Integration Tests starting...\n"); fflush(stdout);
    dap_print_module_name("CLI Backpressure/Dead-Client Integration Tests");

    s_setup();

    s_test_control_request_succeeds();
    s_test_mid_flight_disconnect_does_not_abort();
    s_test_backpressure_returns_real_429();
    s_test_health_probe();
    s_test_command_unavailable_reply();
    s_test_streamed_reply();
    s_test_reply_over_output_cap();

    s_teardown();

    printf("All CLI backpressure/dead-client integration tests passed (7 tests)!\n"); fflush(stdout);
    return 0;
}

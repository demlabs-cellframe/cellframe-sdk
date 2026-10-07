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
 * @file rpc_service_unit_test.c
 * @brief Unit tests for the standalone plain-HTTP JSON-RPC service ([rpc-server]).
 * @details The service itself needs a listening socket, but every decision it makes about a
 *          request is a pure function, and those are what this test covers:
 *           - dap_json_rpc_method_is_public(): which command a restricted (non-loopback) caller
 *             of the endpoint is allowed to run, per the configured public list;
 *           - dap_cli_server_addr_is_loopback(): the loopback classification both the CLI port
 *             and the RPC service use to decide whether a caller is trusted with the full
 *             command set (IPv4 and IPv6 forms, unix sockets, single addresses);
 *           - dap_cli_server_cmd_list_json(): the command index the service answers a bare GET
 *             with - registered commands with their doc and their public/private flag;
 *           - dap_cli_server_ready_check(): readiness with no callback registered (which is the
 *             case in this test process) must not misreport the node as unready.
 */

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <stdint.h>

#include "dap_common.h"
#include "dap_test.h"
#include "dap_strfuncs.h"
#include "dap_cli_server.h"
#include "dap_json_rpc.h"

#define TEST_CMD_PUBLIC  "rpc_service_test_public_cmd"
#define TEST_CMD_PRIVATE "rpc_service_test_private_cmd"

static int s_stub_cmd_func(int a_argc, char **a_argv, void **a_reply, int a_version)
{
    (void)a_argc; (void)a_argv; (void)a_reply; (void)a_version;
    return 0;
}

/* The public/private decision: exact membership in the configured list, nothing else. */
static void s_test_method_visibility(void)
{
    static const char *l_public[] = { "version", "net", "node", NULL };

    dap_assert(dap_json_rpc_method_is_public("version", l_public),
               "A listed command is public");
    dap_assert(dap_json_rpc_method_is_public("net", l_public),
               "Every command of the list is public, not just the first");
    dap_assert(!dap_json_rpc_method_is_public("mempool", l_public),
               "A command outside the list is not public");

    // Not even a prefix or a subcommand form may slip through.
    dap_assert(!dap_json_rpc_method_is_public("ver", l_public),
               "A prefix of a public command is not public");
    dap_assert(!dap_json_rpc_method_is_public("net_bridge", l_public),
               "A command whose name starts like a public one is not public");

    dap_assert(!dap_json_rpc_method_is_public("version", NULL),
               "Without a public list nothing is public");
    static const char *l_empty[] = { NULL };
    dap_assert(!dap_json_rpc_method_is_public("version", l_empty),
               "An empty public list exposes nothing");
    dap_assert(!dap_json_rpc_method_is_public(NULL, l_public),
               "A request without a method name is never public (malformed JSON path)");
    dap_assert(!dap_json_rpc_method_is_public("", l_public),
               "An empty method name is never public");

    dap_pass_msg("HTTP RPC method visibility test passed");
}

/* Loopback classification, shared by the CLI port and the RPC service. */
static void s_test_loopback_detection(void)
{
    struct sockaddr_storage l_addr = { 0 };

    dap_assert(!dap_cli_server_addr_is_loopback(NULL),
               "A missing peer address is not loopback");

    struct sockaddr_in *l_in = (struct sockaddr_in *)&l_addr;
    l_addr.ss_family = AF_INET;
    l_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dap_assert(dap_cli_server_addr_is_loopback(&l_addr), "127.0.0.1 is loopback");
    l_in->sin_addr.s_addr = htonl(0x7F050505);              // 127.5.5.5
    dap_assert(!dap_cli_server_addr_is_loopback(&l_addr),
               "Only 127.0.0.1 is trusted, not every 127.0.0.0/8 neighbour (as on the CLI port)");
    l_in->sin_addr.s_addr = htonl(0x0A000001);              // 10.0.0.1
    dap_assert(!dap_cli_server_addr_is_loopback(&l_addr), "A public IPv4 address is not loopback");
    l_in->sin_addr.s_addr = htonl(0xAC100002);              // 172.16.0.2
    dap_assert(!dap_cli_server_addr_is_loopback(&l_addr),
               "A private RFC1918 address is still not loopback (proxies land here)");

#ifdef AF_INET6
    memset(&l_addr, 0, sizeof(l_addr));
    struct sockaddr_in6 *l_in6 = (struct sockaddr_in6 *)&l_addr;
    l_addr.ss_family = AF_INET6;
    l_in6->sin6_addr = in6addr_loopback;
    dap_assert(dap_cli_server_addr_is_loopback(&l_addr), "::1 is loopback");
    // 2001:db8::1, written out instead of inet_pton() so the test needs no resolver header
    // (and stays portable to the Windows test run).
    static const uint8_t l_public_v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0x01 };
    memcpy(&l_in6->sin6_addr, l_public_v6, sizeof(l_public_v6));
    dap_assert(!dap_cli_server_addr_is_loopback(&l_addr), "A public IPv6 address is not loopback");
#else
    memset(&l_addr, 0, sizeof(l_addr));
#endif
    l_addr.ss_family = AF_UNIX;
    dap_assert(!dap_cli_server_addr_is_loopback(&l_addr),
               "Unix sockets are not loopback (the CLI trusts them by family)");

    dap_pass_msg("HTTP RPC loopback detection test passed");
}

/* Looks the command up in the index and returns its "public" flag, or -1 when absent. */
static int s_index_flag_of(const char *a_index, const char *a_cmd)
{
    json_object *l_arr = json_tokener_parse(a_index);
    int l_ret = -1;
    if (l_arr && json_object_is_type(l_arr, json_type_array)) {
        size_t l_n = json_object_array_length(l_arr);
        for (size_t i = 0; i < l_n; ++i) {
            json_object *l_obj = json_object_array_get_idx(l_arr, i);
            json_object *l_name = NULL, *l_public = NULL;
            if (json_object_object_get_ex(l_obj, "name", &l_name) && l_name &&
                !strcmp(json_object_get_string(l_name), a_cmd) &&
                json_object_object_get_ex(l_obj, "public", &l_public) && l_public) {
                l_ret = json_object_get_boolean(l_public) ? 1 : 0;
                break;
            }
        }
    }
    json_object_put(l_arr);
    return l_ret;
}

/* The command index a bare GET answers with: names, docs and the public flag. */
static void s_test_command_index(void)
{
    dap_assert_PIF(dap_cli_server_cmd_add(TEST_CMD_PUBLIC, s_stub_cmd_func, NULL,
                                          "public test command", NULL) != NULL,
                   "Public test command registers");
    dap_assert_PIF(dap_cli_server_cmd_add(TEST_CMD_PRIVATE, s_stub_cmd_func, NULL,
                                          "private test command", NULL) != NULL,
                   "Private test command registers");

    static const char *l_public[] = { TEST_CMD_PUBLIC, NULL };
    char *l_index = dap_cli_server_cmd_list_json(l_public, false);
    dap_assert_PIF(l_index != NULL, "Command index is produced");
    dap_assert(s_index_flag_of(l_index, TEST_CMD_PUBLIC) == 1,
               "A command from the public list is flagged public in the index");
    dap_assert(s_index_flag_of(l_index, TEST_CMD_PRIVATE) == 0,
               "A command outside the list is flagged private in the index");
    dap_assert(strstr(l_index, "public test command") != NULL,
               "The index carries the command documentation");
    DAP_DELETE(l_index);

    // An endpoint that runs everything reports everything as public.
    l_index = dap_cli_server_cmd_list_json(NULL, true);
    dap_assert_PIF(l_index != NULL, "Command index is produced for a public endpoint");
    dap_assert(s_index_flag_of(l_index, TEST_CMD_PRIVATE) == 1,
               "On a public endpoint every command is flagged public");
    DAP_DELETE(l_index);

    // A restricted endpoint without a list exposes nothing.
    l_index = dap_cli_server_cmd_list_json(NULL, false);
    dap_assert_PIF(l_index != NULL, "Command index is produced for a restricted endpoint");
    dap_assert(s_index_flag_of(l_index, TEST_CMD_PUBLIC) == 0,
               "Without a public list even a known command is flagged private");
    DAP_DELETE(l_index);

    dap_pass_msg("HTTP RPC command index test passed");
}

static void s_test_ready_default(void)
{
    char l_reason[128];
    dap_assert(dap_cli_server_ready_check(l_reason, sizeof(l_reason)),
               "With no readiness callback registered the node reports ready");
    dap_assert(l_reason[0] == '\0', "No reason is reported when ready");
    dap_pass_msg("HTTP RPC readiness default test passed");
}

int main(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);

    printf("HTTP RPC Service Unit Tests starting...\n"); fflush(stdout);
    dap_print_module_name("HTTP RPC Service Unit Tests");

    s_test_method_visibility();
    s_test_loopback_detection();
    s_test_command_index();
    s_test_ready_default();

    printf("All HTTP RPC service unit tests passed (4 tests)!\n"); fflush(stdout);

    return 0;
}

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
 * @file rpc_executor_bench.c
 * @brief Microbenchmark of the shared command executor (the CLI-server stage).
 * @details Measures the full executor round trip for a trivial command: one JSON parse
 *          (since the single-parse pass the entry points hand the tree down, this bench
 *          goes through the raw-string wrapper, i.e. parse + dispatch + execute +
 *          response envelope), at 20k iterations. Registered as a ctest target with the
 *          "bench" label so it runs in CI and keeps a regression signal on the executor
 *          overhead (the review pass of 2026-10-09 established the baseline: the executor
 *          accounts for well under 1 ms of a request, this bench pins the exact figure).
 *          Not an assertion test: it prints per-request cost and always passes, unless the
 *          executor is outright broken.
 */

#include <stdio.h>
#include <time.h>

#include "dap_common.h"
#include "dap_cli_server.h"
#include "dap_test.h"
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#define BENCH_ITERS 20000

int main(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_ERROR);
    dap_print_module_name("RPC executor microbenchmark");

    // Trivial command: the measurement is the executor overhead itself (parse + hash find +
    // dispatch + serialize), the command body is a constant string.
    static const char c_req[] = "{\"method\":\"version\",\"params\":[\"version\"],\"id\":1}";
    char l_req[sizeof(c_req)];
    memcpy(l_req, c_req, sizeof(c_req));

    // Warmup + sanity: one pass must produce a valid response.
    char *l_warm = dap_cli_cmd_exec(l_req);
    if (!l_warm) {
        fprintf(stderr, "executor returned NULL for a trivial command\n");
        return -1;
    }
    bool l_ok = strstr(l_warm, "version") != NULL;
    free(l_warm);
    if (!l_ok) {
        fprintf(stderr, "executor response does not mention 'version'\n");
        return -1;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        char *l_resp = dap_cli_cmd_exec(l_req);
        if (l_resp)
            free(l_resp);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double l_ns = (double)((t1.tv_sec - t0.tv_sec) * 1000000000ll + (t1.tv_nsec - t0.tv_nsec));
    double l_us_per_req = l_ns / 1000.0 / BENCH_ITERS;
    printf("executor: %.1f us/request over %d iterations (%.0f req/s/thread)\n",
           l_us_per_req, BENCH_ITERS, 1e6 / l_us_per_req);
    return 0;
}

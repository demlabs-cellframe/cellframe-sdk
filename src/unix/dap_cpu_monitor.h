/*
 * Authors:
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

// For C++
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CPU_COUNT 64

#include <stdlib.h>

typedef struct dap_cpu {
    unsigned ncpu; // number of cpu core
    float load; // percent of load
    size_t total_time;
    size_t idle_time;
} dap_cpu_t;

typedef struct dap_cpu_stats
{
    unsigned cpu_cores_count;
    dap_cpu_t cpu_summary; // average statistic for all cpu
    dap_cpu_t cpus[MAX_CPU_COUNT]; // list of cpu with stat
} dap_cpu_stats_t;

/**
 * @brief dap_cpu_monitor_init Monitor CPU initialization
 * @return
 */
int dap_cpu_monitor_init(void);

/**
 * @brief dap_cpu_monitor_deinit Monitor CPU deinitialization
 */
void dap_cpu_monitor_deinit(void);

/**
 * @brief dap_cpu_get_stats Getting processor information
 * @return
 */
dap_cpu_stats_t dap_cpu_get_stats(void);

#ifdef __cplusplus
}
#endif

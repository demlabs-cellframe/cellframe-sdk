/*
 Copyright (c) 2017-2019 (c) Project "DeM Labs Inc" https://gitlab.demlabs.net/cellframe
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
//#include <winnt.h>
#include <winternl.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "dap_cpu_monitor.h"
#include "dap_common.h"

#define LOG_TAG "dap_cpu_monitor"

//static FILE * _proc_stat = NULL;
static dap_cpu_stats_t _cpu_stats = {0};

static dap_cpu_t _cpu_old_stats[MAX_CPU_COUNT] = {};
static dap_cpu_t _cpu_summary_old = {0};

typedef struct proc_stat_line
{
    /* http://man7.org/linux/man-pages/man5/proc.5.html */
    char cpu[10];
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
    uint64_t guest;
    uint64_t guest_nice;
    uint64_t total; // summary all parameters
} proc_stat_line_t;

int dap_cpu_monitor_init()
{
  SYSTEM_INFO si;

  GetSystemInfo( &si );
  _cpu_stats.cpu_cores_count = si.dwNumberOfProcessors;

  log_it( L_DEBUG, "dap_cpu_monitor_init(): Cpu core count: %d", _cpu_stats.cpu_cores_count );

  dap_cpu_get_stats( ); // init prev parameters

  return 0;
}

void dap_cpu_monitor_deinit()
{

}
/*
static void _deserealize_proc_stat(char *line, proc_stat_line_t *stat)
{
    sscanf(line,"%s %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu",
           stat->cpu, &stat->user, &stat->nice, &stat->system, &stat->idle,
           &stat->iowait, &stat->irq, &stat->softirq, &stat->steal,
           &stat->guest, &stat->guest_nice);

    stat->total = stat->user + stat->system + stat->idle +
            stat->iowait + stat->irq + stat->softirq +
            stat->steal + stat->guest + stat->guest_nice;
}
*/
static float _calculate_load( uint64_t idle_time, uint64_t prev_idle_time,
                      uint64_t total_time, uint64_t prev_total_time ) {
  return ( 1 - (1.0 * idle_time - prev_idle_time) / (total_time - prev_total_time) ) * 100.0;
}

dap_cpu_stats_t dap_cpu_get_stats()
{
  FILETIME idleTime, kernelTime, userTime;
  GetSystemTimes( &idleTime, &kernelTime, &userTime );

  #define WINNT_FILETIME_TO_UINT64(t) (((uint64_t)(t.dwHighDateTime)<<32) | (uint64_t)(t.dwLowDateTime))
  _cpu_stats.cpu_summary.idle_time  = WINNT_FILETIME_TO_UINT64(idleTime);
  _cpu_stats.cpu_summary.total_time = WINNT_FILETIME_TO_UINT64(kernelTime) + WINNT_FILETIME_TO_UINT64(userTime);

  /*********************************************/

  SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION pinfo[64];
  ULONG outsize = 0;
  uint32_t ntstatus_error = 0;

  /*ntstatus_error = NtQuerySystemInformation( SystemProcessorPerformanceInformation, &pinfo,
                              sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * 64, &outsize );*/ // ! ! ! Legacy method, must be replaced

  if ( ntstatus_error ) {
    log_it(L_ERROR, "NtQuerySystemInformation returned an error %u", ntstatus_error );
    return (dap_cpu_stats_t){0};
  }

  if ( outsize < sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * _cpu_stats.cpu_cores_count ) {
    log_it(L_WARNING, "NtQuerySystemInformation: data size less than expected");
  }

  for( uint32_t i = 0; i < _cpu_stats.cpu_cores_count; i++ ) {

    _cpu_stats.cpus[i].idle_time = pinfo[i].IdleTime.QuadPart;
    _cpu_stats.cpus[i].total_time = pinfo[i].KernelTime.QuadPart + pinfo[i].UserTime.QuadPart;
    _cpu_stats.cpus[i].ncpu = i;

    _cpu_stats.cpus[i].load = _calculate_load(_cpu_stats.cpus[i].idle_time,
                                                  _cpu_old_stats[i].idle_time,
                                                  _cpu_stats.cpus[i].total_time,
                                                  _cpu_old_stats[i].total_time);

       // log_it(L_WARNING, "CPU %d %f", i, _cpu_stats.cpus[i].load);
  }

  _cpu_stats.cpu_summary.load = _calculate_load(_cpu_stats.cpu_summary.idle_time,
                    _cpu_summary_old.idle_time,
                    _cpu_stats.cpu_summary.total_time,
                    _cpu_summary_old.total_time);

  //  log_it(L_WARNING, "%f", _cpu_stats.cpu_summary.load);

  memcpy(&_cpu_summary_old, &_cpu_stats.cpu_summary, sizeof (dap_cpu_t));

  memcpy(_cpu_old_stats, _cpu_stats.cpus,
           sizeof (dap_cpu_t) * _cpu_stats.cpu_cores_count);

  return _cpu_stats;
}

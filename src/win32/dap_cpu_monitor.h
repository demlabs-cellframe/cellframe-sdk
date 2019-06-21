#pragma once

#define MAX_CPU_COUNT 64

typedef struct dap_cpu {
    uint32_t ncpu; // number of cpu core
    float load; // percent of load
    uint64_t total_time;
    uint64_t idle_time;
} dap_cpu_t;

typedef struct dap_cpu_stats
{
    uint32_t cpu_cores_count;
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

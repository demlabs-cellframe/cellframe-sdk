#include "dap_cpu_monitor.h"
#include "dap_common.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define LOG_TAG "dap_cpu_monitor"

static FILE * _proc_stat = NULL;
static dap_cpu_stats_t _cpu_stats = {0};
static dap_cpu_t _cpu_old_stats[MAX_CPU_COUNT] = {0};
static dap_cpu_t _cpu_summary_old = {0};

typedef struct proc_stat_line
{
    /* http://man7.org/linux/man-pages/man5/proc.5.html */
    char cpu[10];
    size_t user;
    size_t nice;
    size_t system;
    size_t idle;
    size_t iowait;
    size_t irq;
    size_t softirq;
    size_t steal;
    size_t guest;
    size_t guest_nice;
    size_t total; // summary all parameters
} proc_stat_line_t;

int dap_cpu_monitor_init()
{
    _cpu_stats.cpu_cores_count = (unsigned) sysconf(_SC_NPROCESSORS_ONLN);

    log_it(L_DEBUG, "Cpu core count: %d", _cpu_stats.cpu_cores_count);

    dap_cpu_get_stats(); // init prev parameters

    return 0;
}

void dap_cpu_monitor_deinit()
{

}

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

static float _calculate_load(size_t idle_time, size_t prev_idle_time,
                      size_t total_time, size_t prev_total_time)
{
    return (1 - (1.0*idle_time -prev_idle_time) /
            (total_time - prev_total_time)) * 100.0;
}

dap_cpu_stats_t dap_cpu_get_stats()
{
    _proc_stat = fopen("/proc/stat", "r");

    if(_proc_stat == NULL){
        log_it(L_ERROR, "Сan't open /proc/stat file");
        return (dap_cpu_stats_t){0};
    }

    char *line = NULL;
    proc_stat_line_t stat = {0};

    /** get summary cpu stat **/
    size_t mem_size;
    getline(&line, &mem_size, _proc_stat);
    _deserealize_proc_stat(line, &stat);

    _cpu_stats.cpu_summary.idle_time = stat.idle;
    _cpu_stats.cpu_summary.total_time = stat.total;
    /*********************************************/

    for(unsigned i = 0; i < _cpu_stats.cpu_cores_count; i++) {
        getline(&line, &mem_size, _proc_stat);
        _deserealize_proc_stat(line, &stat);
        _cpu_stats.cpus[i].idle_time = stat.idle;
        _cpu_stats.cpus[i].total_time = stat.total;
        _cpu_stats.cpus[i].ncpu = i;

        _cpu_stats.cpus[i].load = _calculate_load(_cpu_stats.cpus[i].idle_time,
                                                  _cpu_old_stats[i].idle_time,
                                                  _cpu_stats.cpus[i].total_time,
                                                  _cpu_old_stats[i].total_time);
    }

    _cpu_stats.cpu_summary.load = _calculate_load(_cpu_stats.cpu_summary.idle_time,
                    _cpu_summary_old.idle_time,
                    _cpu_stats.cpu_summary.total_time,
                    _cpu_summary_old.total_time);

    memcpy(&_cpu_summary_old, &_cpu_stats.cpu_summary, sizeof (dap_cpu_t));

    memcpy(_cpu_old_stats, _cpu_stats.cpus,
           sizeof (dap_cpu_t) * _cpu_stats.cpu_cores_count);

    fclose(_proc_stat);

    return _cpu_stats;
}

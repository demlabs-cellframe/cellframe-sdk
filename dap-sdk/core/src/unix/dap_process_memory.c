#include "dap_process_memory.h"
#include "dap_common.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_TAG "dap_process_mem"

#define MAX_LINE_LENGTH 128

static size_t _parse_size_line(char *line) {
    // This assumes that a digit will be found and the line ends in " Kb".
    size_t i = strlen(line);
    const char *p = line;
    while (*p < '0' || *p > '9') p++;
    line[i - 3] = '\0';
    i = (size_t)atol(p);
    return i;
}

static dap_process_memory_t _get_process_memory(const char* proc_file_path)
{
    FILE *file = fopen(proc_file_path, "r");

    if(file == NULL) {
        log_it(L_WARNING, "Cant open proc file");
        return (dap_process_memory_t){0,0};
    }

    char line[MAX_LINE_LENGTH];
    dap_process_memory_t proc_mem = {0};

    while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
        if (strncmp(line, "VmSize:", 7) == 0) {
            proc_mem.vsz = _parse_size_line(line);
        }

        if (strncmp(line, "VmRSS:", 6) == 0) {
            proc_mem.rss = _parse_size_line(line);
        }

        if (proc_mem.rss != 0 && proc_mem.vsz != 0)
            break;
    }

    fclose(file);

    if(proc_mem.vsz == 0 || proc_mem.rss == 0)
        log_it(L_WARNING, "Getting memory statistics failed");

    return proc_mem;
}

dap_process_memory_t get_proc_mem_current(void)
{
    return _get_process_memory("/proc/self/status");
}

dap_process_memory_t get_proc_mem_by_pid(pid_t pid)
{
    char buf[126] = {0};
    sprintf(buf, "/proc/%d/status", pid);
    return _get_process_memory(buf);
}

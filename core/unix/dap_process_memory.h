#include <stdint.h>
#include <sys/types.h>


typedef struct dap_process_memory {
    size_t vsz; // virtual memory (kb)
    size_t rss; // physical memory (kb)
} dap_process_memory_t;


/**
 * @brief get_proc_mem_current
 * @return
 */
dap_process_memory_t get_proc_mem_current(void);

/**
 * @brief get_proc_mem_by_pid
 * @param pid
 * @return
 */
dap_process_memory_t get_proc_mem_by_pid(pid_t pid);

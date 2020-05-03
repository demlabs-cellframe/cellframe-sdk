
//#include <stdint.h>
//#include <sys/types.h>


typedef struct dap_process_memory {
    size_t vsz; // virtual memory (kb)
    size_t rss; // physical memory (kb)
} dap_process_memory_t;


/**
 * @brief get_proc_mem_current Get information about the amount of RAM consumed for the current process
 * @return
 */
dap_process_memory_t get_proc_mem_current(void);

/**
 * @brief get_proc_mem_by_pid Obtain information about the amount of RAM consumed for a particular process
 * @param[in] pid PID
 * @return
 */
dap_process_memory_t get_proc_mem_by_pid( uint32_t pid );

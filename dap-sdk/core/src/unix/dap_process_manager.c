#ifdef DAP_OS_UNIX
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>

#include "dap_process_manager.h"
#include "dap_common.h"

#undef LOG_TAG
#define LOG_TAG "dap_process_manager"

/**
 * @brief is_process_running Check whether the process is running
 * @param[in] pid PID
 * @return
 */
bool is_process_running(pid_t pid) {
    return kill(pid, 0) == 0;
}

/**
 * @brief save_process_pid_in_file Saves process pid into file by file_path
 * @param[in] file_path File path
 * @return Execution result
 *
 * Saves process pid into file by file_path.
 * If file exists he will be overwritten
 */
bool save_process_pid_in_file(const char* file_path) {
    FILE * fpid = fopen(file_path, "w");
    if (fpid == NULL) {
        log_it(L_ERROR, "Cant create/open file by path %s",file_path);
        return false;
    }
    fprintf(fpid, "%d", getpid());
    fclose(fpid);
    return true;
}

/**
 * @brief get_pid_from_file File must consist only PID. Return 0 if file is clear.
 * @param[in] file_path File path
 * @return Execution result
 */
pid_t get_pid_from_file(const char* file_path) {
    FILE * fpid = fopen(file_path, "r");
    if (fpid == NULL) {
        log_it(L_ERROR, "Cant create/open file by path %s",file_path);
        return false;
    }

    pid_t f_pid = 0;
    fscanf(fpid, "%d", &f_pid);
    fclose(fpid);

    return f_pid;
}

/**
 * @brief daemonize_process Demonizes current process and exit from program
 * @return
 */
bool daemonize_process() {
    return daemon(1,1) == 0;
}

/**
 * @brief kill_process Sends SIGKILL to process
 * @param[in] pid
 * @return
 */
bool kill_process(pid_t pid) {
    if (!is_process_running(pid)) {
        return false;
    }
    return kill(pid, SIGKILL) == 0;
}

#endif

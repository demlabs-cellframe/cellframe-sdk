#ifdef __linux__
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>

#include "dap_process_manager.h"
#include "../dap_common.h"

#undef LOG_TAG
#define LOG_TAG "dap_process_manager"

bool is_process_running(pid_t pid) {
    return kill(pid, 0) == 0;
}

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

bool daemonize_process() {
    return daemon(1,1) == 0;
}

bool kill_process(pid_t pid) {
    if (!is_process_running(pid)) {
        return false;
    }
    return kill(pid, SIGKILL) == 0;
}

#endif

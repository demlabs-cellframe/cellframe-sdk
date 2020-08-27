#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_hw.h"

int _get_system_data_solid(char** repl, const char * a_cmd)
{
    int ret = 0;
    for (int i = 0; i < 5; i++){
        ret = exec_with_ret(repl, a_cmd);
        if (strcmp(*repl, "") || 4 == i)
            break;
        free(*repl);
    }
    return ret;
}

char *dap_cpu_info() {
    char *ret = NULL;
    _get_system_data_solid(&ret, "system_profiler SPHardwareDataType | awk '/Serial/ {print $4}'");
    return ret;
}

char *dap_get_motherboard_id() {
    char *ret = NULL;
    _get_system_data_solid(&ret, "system_profiler SPHardwareDataType |grep 'Hardware UUID' | awk '{ print $3;}'");
    return ret;
}

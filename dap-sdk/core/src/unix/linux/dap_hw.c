#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_hw.h"

#define SYSFS_BOARD_SERIAL_PATH "/sys/class/dmi/id/product_uuid"

char *dap_get_motherboard_id() {
    FILE * f = fopen(SYSFS_BOARD_SERIAL_PATH, "r");
    const size_t ret_size = 37;
    char * ret = calloc(1, ret_size + 1);
    if(f) {
        fgets(ret, ret_size, f);
        fclose(f);
    }
    return ret;
}

__attribute__((always_inline))
inline void cpuid(u_int *eax, u_int *ebx, u_int *ecx, u_int *edx)
{
    asm volatile
            (
                "cpuid"
                : "=a" (*eax),
                  "=b" (*ebx),
                  "=c" (*ecx),
                  "=d" (*edx)
                : "0" (*eax), "2" (*ecx)
            );
}

char *dap_cpu_info() {
    u_int eax, ebx, ecx, edx;
    char *buf = (char *)malloc(512);
    memset(buf, 0, 512);
    sprintf(buf, "CPU_model=");
    eax = 0x80000000;
    cpuid(&eax, &ebx, &ecx, &edx);
    int offset = strlen(buf);
    memcpy(buf + offset, &ebx, 4);
    memcpy(buf + offset + 4, &edx, 4);
    memcpy(buf + offset + 8, &ecx, 4);
    eax = 0x80000002;
    offset = strlen(buf);
    for (u_int i = 0x80000002; i <= 0x80000004; ++i, eax = i, offset = strlen(buf)) {
        cpuid(&eax, &ebx, &ecx, &edx);
        sprintf(buf + offset, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
                eax & 0xFF, (eax >> 8) & 0xFF, (eax >> 16) & 0xFF, (eax >> 24) & 0xFF,
                ebx & 0xFF, (ebx >> 8) & 0xFF, (ebx >> 16) & 0xFF, (ebx >> 24) & 0xFF,
                ecx & 0xFF, (ecx >> 8) & 0xFF, (ecx >> 16) & 0xFF, (ecx >> 24) & 0xFF,
                edx & 0xFF, (edx >> 8) & 0xFF, (edx >> 16) & 0xFF, (edx >> 24) & 0xFF);
    }
    offset = strlen(buf);
    eax = 0x1;
    cpuid(&eax, &ebx, &ecx, &edx);
    if (((eax >> 8) & 0xF) == 0xF) {
        sprintf(buf + offset, "Family %d Model %d Stepping %d",
                ((eax >> 8) & 0xFF) + ((eax >> 20) & 0xFF),
                ((eax >> 4) & 0xF) + (((eax >> 16) << 4) & 0xF), eax & 0xF);
    }
    else {
        sprintf(buf + offset, "Family %d Model %d Stepping %d",
            (eax >> 8) & 0xFF, (eax >> 4) & 0xFF, eax & 0xFF);
    }
    return buf;
}


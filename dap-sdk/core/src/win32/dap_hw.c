#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <winsock2.h>
#include <winuser.h>
#include <iphlpapi.h>
#include <cpuid.h>
#include "dap_hw.h"

#define _CRT_SECURE_NO_WARNINGS
#define MBSIZE 1024

#include <versionhelpers.h>

#define PERR(bSuccess, msg) { if(!(bSuccess)) printf("%s: Error (%d) from %s on line %d\n", __FILE__, GetLastError(), msg, __LINE__); }

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
RET:
    return buf;
}

PRAW_SMBIOS_DATA GetSmbiosData() {
    UINT bufferSize = 0;
    PRAW_SMBIOS_DATA smbios = NULL;
    bufferSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (bufferSize) {
        smbios = (PRAW_SMBIOS_DATA)malloc(bufferSize);
        bufferSize = GetSystemFirmwareTable('RSMB', 0, (PVOID)smbios, bufferSize);
    }
    return smbios;
}

PSMBIOS_HEADER GetNextStructure(PRAW_SMBIOS_DATA smbios, PSMBIOS_HEADER previous) {
    if (smbios == NULL)
        return NULL;
    if (previous == NULL)
        return (PSMBIOS_HEADER)(&smbios->SMBIOSTableData[0]);
    for (PBYTE c = ((PBYTE)previous) + previous->Length; ; c++) {
        if ('\0' == *c && '\0' == *(c + 1)) {
            if ((c + 2) < ((PBYTE)smbios->SMBIOSTableData + smbios->Length))
                return (PSMBIOS_HEADER)(c + 2);
            else
                goto RET;
        }
    }
RET:
    return NULL;
}

PSMBIOS_HEADER GetNextStructureOfType(PRAW_SMBIOS_DATA smbios,PSMBIOS_HEADER previous, DWORD type)
{
    PSMBIOS_HEADER next = previous;
    while (NULL != (next = GetNextStructure(smbios,next))) {
        if (type == next->Type)
            return next;
    }

    return NULL;
}

PSMBIOS_HEADER GetStructureByHandle(PRAW_SMBIOS_DATA smbios,WORD handle)
{
    PSMBIOS_HEADER header = NULL;

    while (NULL != (header = GetNextStructure(smbios,header)))
        if (handle == header->Handle)
            return header;
    return NULL;
}

char *GetSmbiosString(PSMBIOS_HEADER table, BYTE index)
{
    char *ret = NULL;
    if (index == 0)
        goto RET;
    char *c;
    DWORD i;
    for (i = 1, c = (char *)table + table->Length; *c != '\0'; c += strlen(c) + 1, i++) {
        if (i == index) {
            ret = (char *)malloc(strlen(c)+3);
            memset(ret, 0, strlen(c)+3);
            strcpy(ret, c);
            goto RET;
        }
    }
RET:
    return ret;
}

char *GetBiosString(PRAW_SMBIOS_DATA smbios, DWORD type, DWORD offset) {
    PSMBIOS_HEADER head = NULL;
    PBYTE cursor = NULL;
    char *ret = NULL;
    head = GetNextStructureOfType(smbios, head, type);
    if (head == NULL) {
       goto RET;
    }
    cursor = ((PBYTE)head + offset);
    ret = GetSmbiosString(head, *cursor);
RET:
    return ret;
}

char *dap_get_motherboard_id() {
    PRAW_SMBIOS_DATA data = GetSmbiosData();
    char *ret = GetBiosString(data, SMBIOS_TABLE_BASEBOARD, 7);
    strcat(ret, "  ");
    free(data);
    return ret;
}


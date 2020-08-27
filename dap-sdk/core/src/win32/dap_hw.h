#ifndef DAP_HW_H
#define DAP_HW_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

char *dap_get_motherboard_id();
char *dap_cpu_info();

#define SMBIOS_TABLE_BIOS              0
#define SMBIOS_TABLE_SYSTEM            1
#define SMBIOS_TABLE_BASEBOARD         2
#define SMBIOS_TABLE_CHASSIS           3
#define SMBIOS_TABLE_PROCESSOR         4
#define SMBIOS_TABLE_MEMCTRL           5
#define SMBIOS_TABLE_MEMMODULES        6
#define SMBIOS_TABLE_PORTS             8
#define SMBIOS_TABLE_SLOTS             9
#define SMBIOS_TABLE_OEM_STRINGS       11
#define SMBIOS_TABLE_SYS_CFG_OPTIONS   12
#define SMBIOS_TABLE_MEM_ARRAY         16
#define SMBIOS_TABLE_MEM_DEVICE        17
#define SMBIOS_TABLE_END_OF_TABLE      127

typedef struct _RawSMBIOSData {
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Length;
    BYTE    SMBIOSTableData[1];
} RAW_SMBIOS_DATA, *PRAW_SMBIOS_DATA;

typedef struct _SMBIOSHeader {
    BYTE Type;
    BYTE Length;
    WORD Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _SMBIOSNode {
    WCHAR *Name;
    struct _SMBIOSNodeAttrLink *Attributes;
    struct _SMBIOSNode *Parent;
    struct _SMBIOSNodeLink *Children;
    int Flags;
} SMBIOS_NODE, * PSMBIOS_NODE;

typedef struct _SMBIOSNodeLink {
    struct _SMBIOSNode *LinkedNode;
} SMBIOS_ODE_LINK, *PSMBIOS_NODE_LINK;

typedef struct _SMBIOSNodeAttr {
    WCHAR *Key;
    WCHAR *Value;
    int Flags;
} SMBIOS_NODE_ATTR, *PSMBIOS_NODE_ATTR;

typedef struct _SMBIOSNodeAttrLink {
    struct _SMBIOSNodeAttr *LinkedAttribute;
} SMBIOS_NODE_ATTR_LINK, *PSMBIOS_NODE_ATTR_LINK;

#ifdef __cplusplus
}
#endif

#endif // DAP_HW_H

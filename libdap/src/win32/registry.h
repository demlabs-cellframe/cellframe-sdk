#ifndef REGISTRY_H
#define REGISTRY_H

#include <stdio.h>
#include <windows.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

wchar_t* readRegKey(HKEY hKey, LPCWSTR regSubKey, LPCWSTR val);
wchar_t* getTapGUID();
wchar_t* getTapName();
wchar_t* getUserSID(LPCWSTR homePath);
wchar_t* shGetUsrPath();

wchar_t*    regWGetUsrPath();
char*       regGetUsrPath();

#ifdef __cplusplus
}
#endif

#endif

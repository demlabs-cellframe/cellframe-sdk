#ifndef REGISTRY_H
#define REGISTRY_H

#include <stdio.h>
#include <windows.h>
#include <tchar.h>

wchar_t* readRegKey(HKEY hKey, LPCWSTR regSubKey, LPCWSTR val);
wchar_t* getTapGUID();
wchar_t* getTapName();
wchar_t* getUserSID(LPCWSTR homePath);

char* regGetUsrPath();

#endif

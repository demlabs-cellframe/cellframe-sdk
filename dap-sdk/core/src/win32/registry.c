#include "registry.h"
#include <shlobj.h>

wchar_t* readRegKey(HKEY hKey, LPCWSTR regSubKey, LPCWSTR val) {
    wchar_t *wret = (wchar_t*)malloc(MAX_PATH);
    DWORD dwSize = MAX_PATH;
    LSTATUS err = RegGetValueW(hKey, regSubKey, val, RRF_RT_REG_SZ, NULL, (void*)wret, &dwSize);
    if (err == ERROR_SUCCESS) {
        return wret;
    } else {
        free(wret);
        return NULL;
    }
}

char* regGetUsrPath() {
    static char path[MAX_PATH] = {'\0'};
    if (strlen(path) > 3) { return path; }
    HKEY hKey;
    const char keyPath[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
    LSTATUS err = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                 keyPath,
                                 0, KEY_READ, &hKey );
    if (err != ERROR_SUCCESS) { return NULL; }
    DWORD len = MAX_PATH;
    err = RegGetValueA(hKey, NULL, "Common Documents", RRF_RT_REG_SZ, NULL, (void*)path, &len);
    RegCloseKey(hKey);
    return path;
}

wchar_t* regWGetUsrPath() {
    static wchar_t path[MAX_PATH] = {'\0'};
    if (wcslen(path) > 3) { return path; }
    HKEY hKey;
    const char keyPath[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
    LSTATUS err = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                 keyPath,
                                 0, KEY_READ, &hKey );
    if (err != ERROR_SUCCESS) { return NULL; }
    DWORD len = MAX_PATH;
    err = RegGetValueW(hKey, NULL, L"Common Documents", RRF_RT_REG_SZ, NULL, (void*)path, &len);
    RegCloseKey(hKey);
    return path;
}

wchar_t* getTapGUID() {
    static wchar_t guid[MAX_PATH] = {};
    if (wcslen(guid) > 2) { return guid; }

    const wchar_t keyPath[] = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    HKEY baseKey;
    LSTATUS err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0
                  ,KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY | KEY_READ
                  ,&baseKey);
    if (err != ERROR_SUCCESS) { return NULL; }
    DWORD index;
    for (index = 0; ; ++index) {
        wchar_t hKey[MAX_PATH];
        DWORD len = MAX_PATH;
        if (RegEnumKeyExW(baseKey, index, hKey, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        wchar_t *tmp = readRegKey(baseKey, hKey, L"ComponentId");
        if (tmp && wcscmp(tmp, L"tap0901") == 0) {
            wchar_t *tmp2 = readRegKey(baseKey, hKey, L"NetCfgInstanceId");
            wcscpy(guid, tmp2);
            free(tmp);
            free(tmp2);
            return guid;
        }
        if (tmp) free(tmp);
    }
    return NULL;
}

wchar_t* getTapName() {
    static wchar_t name[MAX_PATH] = {};
    if (wcslen(name) > 2) return name;

    wchar_t *guid = getTapGUID();
    if (guid == NULL) return NULL;
    wchar_t keyPath[MAX_PATH] = L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    wcscat(keyPath, L"\\");
    wcscat(keyPath, guid);

    HKEY baseKey;
    LSTATUS err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0
                  ,KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY | KEY_READ
                  ,&baseKey);
    if (err != ERROR_SUCCESS) { return NULL; }
    DWORD index;
    for (index = 0; ; ++index) {
        wchar_t hKey[MAX_PATH];
        DWORD len = MAX_PATH;
        if (RegEnumKeyExW(baseKey, index, hKey, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        wchar_t *tmp = readRegKey(baseKey, hKey, L"Name");
        if (tmp) {
            wcscpy(name, tmp);
            free(tmp);
            return name;
        }
    }
    return NULL;
}

wchar_t* getUserSID(LPCWSTR homePath) {
    static wchar_t sid[MAX_PATH] = {};
    if (wcslen(sid) > 2) return sid;

    const wchar_t keyPath[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    HKEY baseKey;
    LSTATUS err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0
                  ,KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY | KEY_READ
                  ,&baseKey);
    if (err != ERROR_SUCCESS) { return NULL; }
    DWORD index;
    for (index = 0; ; ++index) {
        wchar_t hKey[MAX_PATH];
        DWORD len = MAX_PATH;
        if (RegEnumKeyExW(baseKey, index, hKey, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        wchar_t *tmp = readRegKey(baseKey, hKey, L"ProfileImagePath");
        if (tmp && wcscmp(tmp, homePath) == 0) {
            wcscpy(sid, hKey);
            free(tmp);
            return sid;
        }
        if (tmp) free(tmp);
    }
    return NULL;
}

wchar_t* shGetUsrPath(){
    static WCHAR path[MAX_PATH];
    memset(path, L'\0', MAX_PATH * sizeof(WCHAR));
    SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path);
    return path;
}

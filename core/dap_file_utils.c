/*
 * Authors:
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#if (OS_TARGET == OS_MACOS)
    #include <stdio.h>
#else
    #include <malloc.h>
#endif
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"

/**
 * Check the directory path for unsupported symbols
 *
 * @string
 * @return true, if the directory path contains only ASCII symbols
 */
bool dap_valid_ascii_symbols(const char *a_string)
{
    if(!a_string)
        return true;
    for(size_t i = 0; i < strlen(a_string); i++) {
        if((uint8_t) a_string[i] > 0x7f)
            return false;
    }
    return true;
}

/**
 * Check the directory for exists
 *
 * @dir_path directory pathname
 * @return true, if the file is a directory
 */
bool dap_dir_test(const char * a_dir_path)
{
    if(!a_dir_path)
        return false;
#ifdef _WIN32
    int attr = GetFileAttributesA(a_dir_path);
    if(attr != -1 && (attr & FILE_ATTRIBUTE_DIRECTORY))
        return true;
#else
    struct stat st;
    if (!stat(a_dir_path, &st)) {
        if (S_ISDIR(st.st_mode))
        return true;
    }
#endif
    return false;
}

/**
 * Create a new directory with intermediate sub-directories
 *
 * @dir_path new directory pathname
 * @return 0, if the directory was created or already exist, else -1
 */
int dap_mkdir_with_parents(const char *a_dir_path)
{

    char *path, *p;
    // validation of a pointer
    if(a_dir_path == NULL || a_dir_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    path = strdup(a_dir_path);
    // skip the root component if it is present, i.e. the "/" in Unix or "C:\" in Windows
#ifdef _WIN32
    if(((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
            && (path[1] == ':') && DAP_IS_DIR_SEPARATOR(path[2])) {
        p = path + 3;
    }
#else
        if (DAP_IS_DIR_SEPARATOR(path[0])) {
            p = path + 1;
        }
#endif
        else
        p = path;

    do {
        while(*p && !DAP_IS_DIR_SEPARATOR(*p))
            p++;

        if(!*p)
            p = NULL;
        else
            *p = '\0';

        if(!dap_dir_test(path)) {
#ifdef _WIN32
            int result = mkdir(path);
#else
            int result = mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
            if(result == -1) {
                free(path);
                errno = ENOTDIR;
                return -1;
            }
        }
        if(p) {
            *p++ = DAP_DIR_SEPARATOR;
            while(*p && DAP_IS_DIR_SEPARATOR(*p))
                p++;
        }
    } while(p);

    free(path);
    return 0;
}

/**
 * dap_path_get_basename:
 * @a_file_name: the name of the file
 *
 * Gets the last component of the filename.
 *
 * If @a_file_name ends with a directory separator it gets the component
 * before the last slash. If @a_file_name consists only of directory
 * separators (and on Windows, possibly a drive letter), a single
 * separator is returned. If @a_file_name is empty, it gets ".".
 *
 * Returns: a newly allocated string containing the last
 *    component of the filename
 */
char* dap_path_get_basename(const char *a_file_name)
{
    ssize_t l_base;
    ssize_t l_last_nonslash;
    const char *l_retval;

    dap_return_val_if_fail(a_file_name != NULL, NULL);

    if(a_file_name[0] == '\0')
        return dap_strdup(".");

    l_last_nonslash = strlen(a_file_name) - 1;

    while(l_last_nonslash >= 0 && DAP_IS_DIR_SEPARATOR(a_file_name[l_last_nonslash]))
        l_last_nonslash--;

    if(l_last_nonslash == -1)
        // string only containing slashes
        return dap_strdup(DAP_DIR_SEPARATOR_S);

#ifdef _WIN32
    if (l_last_nonslash == 1 &&
            dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':')
    // string only containing slashes and a drive
    return dap_strdup (DAP_DIR_SEPARATOR_S);
#endif
    l_base = l_last_nonslash;

    while(l_base >= 0 && !DAP_IS_DIR_SEPARATOR(a_file_name[l_base]))
        l_base--;

#ifdef _WIN32
    if (l_base == -1 &&
            dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':')
    l_base = 1;
#endif

    //size_t l_len = l_last_nonslash - l_base;
    l_retval = a_file_name + l_base + 1;

    return dap_strdup(l_retval);
}

/**
 * dap_path_is_absolute:
 * @a_file_name: a file name
 *
 * Returns true if the given @a_file_name is an absolute file name.
 * Note that this is a somewhat vague concept on Windows.
 *
 * On POSIX systems, an absolute file name is well-defined. It always
 * starts from the single root directory. For example "/usr/local".
 *
 * On Windows, the concepts of current drive and drive-specific
 * current directory introduce vagueness. This function interprets as
 * an absolute file name one that either begins with a directory
 * separator such as "\Users\tml" or begins with the root on a drive,
 * for example "C:\Windows". The first case also includes UNC paths
 * such as "\\myserver\docs\foo". In all cases, either slashes or
 * backslashes are accepted.
 *
 * Returns: true if @a_file_name is absolute
 */
bool dap_path_is_absolute(const char *a_file_name)
{
    dap_return_val_if_fail(a_file_name != NULL, false);

    if(DAP_IS_DIR_SEPARATOR(a_file_name[0]))
        return true;

#ifdef _WIN32
    /* Recognize drive letter on native Windows */
    if (dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':' && DAP_IS_DIR_SEPARATOR (a_file_name[2]))
    return true;
#endif

    return false;
}

/**
 * dap_path_get_dirname:
 * @a_file_name: the name of the file
 *
 * Gets the directory components of a file name.
 *
 * If the file name has no directory components "." is returned.
 * The returned string should be freed when no longer needed.
 *
 * Returns: the directory components of the file
 */
char* dap_path_get_dirname(const char *a_file_name)
{
    char *l_base;
    size_t l_len;

    dap_return_val_if_fail(a_file_name != NULL, NULL);

    l_base = strrchr(a_file_name, DAP_DIR_SEPARATOR);

#ifdef _WIN32
    {
        char *l_q;
        l_q = strrchr (a_file_name, '/');
        if (l_base == NULL || (l_q != NULL && l_q > l_base))
        l_base = l_q;
    }
#endif

    if(!l_base)
    {
#ifdef _WIN32
        if (dap_ascii_isalpha(a_file_name[0]) && a_file_name[1] == ':')
        {
            char l_drive_colon_dot[4];

            l_drive_colon_dot[0] = a_file_name[0];
            l_drive_colon_dot[1] = ':';
            l_drive_colon_dot[2] = '.';
            l_drive_colon_dot[3] = '\0';

            return dap_strdup (l_drive_colon_dot);
        }
#endif
        return dap_strdup(".");
    }

    while(l_base > a_file_name && DAP_IS_DIR_SEPARATOR(*l_base))
        l_base--;

#ifdef _WIN32
    /* base points to the char before the last slash.
     *
     * In case file_name is the root of a drive (X:\) or a child of the
     * root of a drive (X:\foo), include the slash.
     *
     * In case file_name is the root share of an UNC path
     * (\\server\share), add a slash, returning \\server\share\ .
     *
     * In case file_name is a direct child of a share in an UNC path
     * (\\server\share\foo), include the slash after the share name,
     * returning \\server\share\ .
     */
    if (l_base == a_file_name + 1 &&
            dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':')
    l_base++;
    else if (DAP_IS_DIR_SEPARATOR (a_file_name[0]) &&
            DAP_IS_DIR_SEPARATOR (a_file_name[1]) &&
            a_file_name[2] &&
            !DAP_IS_DIR_SEPARATOR (a_file_name[2]) &&
            l_base >= a_file_name + 2)
    {
        const char *l_p = a_file_name + 2;
        while (*l_p && !DAP_IS_DIR_SEPARATOR (*l_p))
        l_p++;
        if (l_p == l_base + 1)
        {
            l_len = (uint32_t) strlen (a_file_name) + 1;
            l_base = DAP_NEW_SIZE (char, l_len + 1);
            strcpy (l_base, a_file_name);
            l_base[l_len-1] = DAP_DIR_SEPARATOR;
            l_base[l_len] = 0;
            return l_base;
        }
        if (DAP_IS_DIR_SEPARATOR (*l_p))
        {
            l_p++;
            while (*l_p && !DAP_IS_DIR_SEPARATOR (*l_p))
            l_p++;
            if (l_p == l_base + 1)
            l_base++;
        }
    }
#endif

    l_len = (uint32_t) 1 + l_base - a_file_name;
    l_base = DAP_NEW_SIZE(char, l_len + 1);
    memmove(l_base, a_file_name, l_len);
    l_base[l_len] = 0;

    return l_base;
}

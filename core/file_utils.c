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
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>
#include "file_utils.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define DIR_SEPARATOR '\\'
#else
#define DIR_SEPARATOR '/'
#endif
#define IS_DIR_SEPARATOR(c) ((c) == DIR_SEPARATOR || (c) == '/')

/**
 * Check the directory path for unsupported symbols
 *
 * @string
 * @return true, if the directory path contains only ASCII symbols
 */
bool valid_ascii_symbols(const char *string)
{
    if(!string)
        return true;
    for(size_t i = 0; i < strlen(string); i++) {
        if((uint8_t) string[i] > 0x7f)
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
bool dir_test(const char * dir_path)
{
    if(!dir_path)
        return false;
#ifdef _WIN32
    int attr = GetFileAttributesA(dir_path);
    if(attr != -1 && (attr & FILE_ATTRIBUTE_DIRECTORY))
        return true;
#else
    struct stat st;
    if (!stat(dir_path, &st)) {
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
int mkdir_with_parents(const char *dir_path)
{

    char *path, *p;
    // validation of a pointer
    if(dir_path == NULL || dir_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    path = strdup(dir_path);
    // skip the root component if it is present, i.e. the "/" in Unix or "C:\" in Windows
#ifdef _WIN32
    if(((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
            && (path[1] == ':') && IS_DIR_SEPARATOR(path[2])) {
        p = path + 3;
    }
#else
        if (IS_DIR_SEPARATOR(path[0])) {
            p = path + 1;
        }
#endif
        else
        p = path;

    do {
        while(*p && !IS_DIR_SEPARATOR(*p))
            p++;

        if(!*p)
            p = NULL;
        else
            *p = '\0';

        if(!dir_test(path)) {
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
            *p++ = DIR_SEPARATOR;
            while(*p && IS_DIR_SEPARATOR(*p))
                p++;
        }
    } while(p);

    free(path);
    return 0;
}


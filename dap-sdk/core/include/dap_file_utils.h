/*
 * Authors:
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
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
#include <stdbool.h>
#include "utlist.h"
#include <dirent.h>

#ifndef _DAP_FILE_UTILS_H_
#define _DAP_FILE_UTILS_H_

#ifdef _WIN32

#include <windows.h>

/* On Win32, the canonical directory separator is the backslash, and
 * the search path separator is the semicolon. Note that also the
 * (forward) slash works as directory separator.
 */
#define DAP_DIR_SEPARATOR '\\'
#define DAP_DIR_SEPARATOR_S "\\"
#define DAP_IS_DIR_SEPARATOR(c) ((c) == DAP_DIR_SEPARATOR || (c) == '/')
#define DAP_SEARCHPATH_SEPARATOR ';'
#define DAP_SEARCHPATH_SEPARATOR_S ";"

#else

#ifndef O_BINARY
# define O_BINARY 0
#endif
#define DAP_DIR_SEPARATOR '/'
#define DAP_DIR_SEPARATOR_S "/"
#define DAP_IS_DIR_SEPARATOR(c) ((c) == DAP_DIR_SEPARATOR)
#define DAP_SEARCHPATH_SEPARATOR ':'
#define DAP_SEARCHPATH_SEPARATOR_S ":"

#endif

typedef struct dap_list_name_directories{
    char *name_directory;
    struct dap_list_name_directories *next;
}dap_list_name_directories_t;

/**
 * Check the directory path for unsupported symbols
 *
 * @dir_path directory pathname
 * @return true, if the directory path contains only ASCII symbols
 */
#ifdef __cplusplus
extern "C" {
#endif

bool dap_valid_ascii_symbols(const char *a_dir_path);

/**
 * Check the file for exists
 *
 * @a_file_path filename pathname
 * @return true, if file exists
 */
bool dap_file_test(const char * a_file_path);

/**
 * Check the directory for exists
 *
 * @a_dir_path directory pathname
 * @return true, if the file is a directory
 */
bool dap_dir_test(const char * a_dir_path);

/**
 * Create a new directory with intermediate sub-directories
 *
 * @dir_path new directory pathname
 * @return 0, if the directory was created or already exist, else -1
 */
int dap_mkdir_with_parents(const char *a_dir_path);


char* dap_path_get_basename(const char *a_file_name);
bool  dap_path_is_absolute(const char *a_file_name);
char* dap_path_get_dirname(const char *a_file_name);
const char* dap_path_get_ext(const char *a_filename);

/**
 * Get list of subdirectories
 *
 * @a_path_name directory path.
 * @return dap_list_t type variable that contains a list of subdirectories.
 */
dap_list_name_directories_t *dap_get_subs(const char *a_path_name);


/*
 * Reads an entire file into allocated memory, with error checking.
 */
bool dap_file_get_contents(const char *filename, char **contents, size_t *length);

#ifdef __cplusplus
}
#endif

#endif // _FILE_UTILS_H_

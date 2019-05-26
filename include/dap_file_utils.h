/*
 * Authors:
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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

#ifndef _DAP_FILE_UTILS_H_
#define _DAP_FILE_UTILS_H_

#ifdef _WIN32

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

#define DAP_DIR_SEPARATOR '/'
#define DAP_DIR_SEPARATOR_S "/"
#define DAP_IS_DIR_SEPARATOR(c) ((c) == DAP_DIR_SEPARATOR)
#define DAP_SEARCHPATH_SEPARATOR ':'
#define DAP_SEARCHPATH_SEPARATOR_S ":"

#endif

/**
 * Check the directory path for unsupported symbols
 *
 * @dir_path directory pathname
 * @return true, if the directory path contains only ASCII symbols
 */
bool dap_valid_ascii_symbols(const char *a_dir_path);

/**
 * Check the directory for exists
 *
 * @dir_path directory pathname
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

#endif // _FILE_UTILS_H_

/*
 * Authors:
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://gitlab.demlabs.net/cellframe
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
 * @brief dap_file_simple_test
 * test if file presented without specific file system attributic
 * 
 * @param a_file_path 
 * @return true 
 * @return false 
 */
bool dap_file_simple_test(const char * a_file_path);

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

/*
 * Creates a path from a series of elements using @separator as the
 * separator between elements. At the boundary between two elements,
 * any trailing occurrences of separator in the first element, or
 * leading occurrences of separator in the second element are removed
 * and exactly one copy of the separator is inserted.
 *
 * @separator: (type filename): a string used to separator the elements of the path.
 * @first_element: (type filename): the first element in the path
 * @...: remaining elements in path, terminated by %NULL
 *
 * Returns: (type filename) (transfer full): a newly-allocated string that
 *     must be freed with DAP_DELETE().
 */
char* dap_build_path(const char *separator, const char *first_element, ...);

/*
 * Creates a filename from a series of elements using the correct
 * separator for filenames.
 *
 * @first_element: (type filename): the first element in the path
 * @...: remaining elements in path, terminated by %NULL
 *
 * Returns: (type filename) (transfer full): a newly-allocated string that must be freed with DAP_DELETE().
 */
char *dap_build_filename (const char *first_element, ...);

/*
 * Gets the canonical file name from @filename. All triple slashes are turned into
 * single slashes, and all `..` and `.`s resolved against @relative_to.
 *
 * @filename: (type filename): the name of the file
 * @relative_to: (type filename) (nullable): the relative directory, or %NULL to use the current working directory
 *
 * Returns: (type filename) (transfer full): a newly allocated string with the canonical file path
 */
char* dap_canonicalize_filename(const char *filename, const char *relative_to);

/*
 * Gets the current directory
 * Returns: (type filename) (transfer full): the current directory
 */
char* dap_get_current_dir(void);

/**
 * rm_rf
 *
 * A fairly naive `rm -rf` implementation
 */
void dap_rm_rf(const char *path);

#ifdef DAP_BUILD_WITH_ZIP
/*
 * Pack a directory to zip file
 *
 * @a_inputdir: input dir
 * @a_output_filename: output zip file path
 *
 * Returns: True, if successfully
 */
bool dap_zip_directory(const char *a_inputdir, const char * a_output_filename);
#endif

/*
 * Pack a directory to tar file
 *
 * @a_inputdir: input dir
 * @a_output_filename: output tar file path
 *
 * Returns: True, if successfully
 */
bool dap_tar_directory(const char *a_inputdir, const char *a_output_tar_filename);


#ifdef __cplusplus
}
#endif

#endif // _FILE_UTILS_H_

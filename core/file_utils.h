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

#include <stdbool.h>

#ifndef _FILE_UTILS_H_
#define _FILE_UTILS_H_

/**
 * Check the directory path for unsupported symbols
 *
 * @dir_path directory pathname
 * @return true, if the directory path contains only ASCII symbols
 */
bool valid_ascii_symbols(const char *dir_path);

/**
 * Check the directory for exists
 *
 * @dir_path directory pathname
 * @return true, if the file is a directory
 */
bool dir_test(const char * dir_path);

/**
 * Create a new directory with intermediate sub-directories
 *
 * @dir_path new directory pathname
 * @return 0, if the directory was created or already exist, else -1
 */
int mkdir_with_parents(const char *dir_path);

#endif // _FILE_UTILS_H_

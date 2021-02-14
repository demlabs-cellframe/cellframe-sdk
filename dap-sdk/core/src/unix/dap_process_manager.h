/*
 * Authors:
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe
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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DAP_OS_UNIX

#include <stdbool.h>
#include <unistd.h>

/* Saves process pid into file by file_path.
 * If file exists he will be overwritten */
extern bool save_process_pid_in_file(const char* file_path);

/* File must consist only PID. Return 0 if file is clear. */
extern pid_t get_pid_from_file(const char* file_path);

/* Return true if process running */
extern bool is_process_running(pid_t pid);

/* Demonizes current process and exit from program */
extern bool daemonize_process(void);

/* Sends SIGKILL to process */
extern bool kill_process(pid_t pid);

#endif

#ifdef __cplusplus
}
#endif

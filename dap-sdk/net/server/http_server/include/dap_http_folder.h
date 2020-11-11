/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2017
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DAP_HTTP_FOLDER_H_
#define _DAP_HTTP_FOLDER_H_

#pragma once

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>
#include <magic.h>

#include "dap_common.h"
//#include "dap_events_socket.h"
#include "dap_http.h"
#include "dap_http_client.h"
#include "http_status_code.h"


struct dap_http;

#ifdef __cplusplus
extern "C" {
#endif

int dap_http_folder_init(void);
void dap_http_folder_deinit(void);

int dap_http_folder_add(struct dap_http *sh, const char * url_path, const char * local_path); // Add folder for reading to the HTTP server

#ifdef __cplusplus
}
#endif

#endif

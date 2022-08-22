/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include "dap_app_cli.h"
#include "dap_events_socket.h"

#define DAP_CLI_HTTP_RESPONSE_SIZE_MAX 65536
#define DAP_CLI_HTTP_TIMEOUT 10  // seconds
#define DAP_CLI_ERROR_FORMAT    -1
#define DAP_CLI_ERROR_TIMEOUT   -2
#define DAP_CLI_ERROR_SOCKET    -3
#define DAP_CLI_ERROR_INCOMPLETE -4

// connection description
typedef uint64_t dap_app_cli_connect_param_t;

/**
 * Connect to node unix socket server
 *
 * return struct connect_param if connect established, else NULL
 */
dap_app_cli_connect_param_t* dap_app_cli_connect(const char * a_socket_path);

/**
 * Send request to kelvin-node
 *
 * return 0 if OK, else error code
 */
int dap_app_cli_post_command(dap_app_cli_connect_param_t *socket, dap_app_cli_cmd_state_t *cmd);

int dap_app_cli_disconnect(dap_app_cli_connect_param_t *socket);

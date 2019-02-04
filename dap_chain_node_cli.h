/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

__BEGIN_DECLS
#include "dap_common.h"
#include "dap_config.h"

#define UNIX_SOCKET_FILE "/opt/kelvin-node/var/run/node_cli.sock"
//#define UNIX_SOCKET_FILE "/var/run/node_cli.sock"

typedef int cmdfunc_t(int argc, const char ** argv, char **str_reply);

typedef struct {
    char *name; /* User printable name of the function. */
    cmdfunc_t *func; /* Function to call to do the job. */
    char *doc; /* Documentation for this function.  */
} COMMAND;

/**
 *  Look up NAME as the name of a command, and return a pointer to that
 *  command.  Return a NULL pointer if NAME isn't a command name.
 */
const COMMAND* find_command(const char *name);

/**
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 */
int dap_chain_node_cli_init(dap_config_t * g_config);

/**
 * Deinitialization of the server side
 */
void dap_chain_node_cli_delete(void);

__END_DECLS

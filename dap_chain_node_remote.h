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

#include <stdbool.h>

#include "dap_chain_node_cli_connect.h"

/**
 * Add new established connection in the list
 */
bool chain_node_client_list_add(chain_node_client_t *client);

/**
 * Delete established connection from the list
 */
bool chain_node_client_list_del(chain_node_client_t *client);

/**
 * Get one established connection
 *
 * n - the position of the established connection, counting from 0
 *
 * return client, or NULL if the position is off the end of the list
 */
chain_node_client_t* chain_node_client_list_get_item(int n);

/**
 * Get the number of established connections
 */
int chain_node_client_list_count(void);

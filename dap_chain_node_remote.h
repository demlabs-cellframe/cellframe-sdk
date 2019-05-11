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

#include "dap_chain_node.h"
#include "dap_chain_node_client.h"

/**
 * Add new established connection to the list
 *
 * return 0 OK, -1 error, -2 already present
 */
int dap_chain_node_client_list_add(dap_chain_node_addr_t *address, dap_chain_node_client_t *client);

/**
 * Delete established connection from the list
 *
 * return 0 OK, -1 error, -2 address not found
 */
int chain_node_client_list_del(dap_chain_node_addr_t *address);

/**
 * Delete all established connection from the list
 */
void chain_node_client_list_del_all(void);

/**
 * Get present established connection by address
 *
 * return client, or NULL if the connection not found in the list
 */
const dap_chain_node_client_t* chain_node_client_find(dap_chain_node_addr_t *address);

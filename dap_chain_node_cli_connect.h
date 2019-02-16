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

#include <pthread.h>
#include <stdbool.h>

#include "dap_client.h"
#include "dap_chain_node.h"

// connection states
enum {
    NODE_CLIENT_STATE_ERROR = -1,
    NODE_CLIENT_STATE_INIT,
    NODE_CLIENT_STATE_CONNECT,
    NODE_CLIENT_STATE_CONNECTED,
    NODE_CLIENT_STATE_SEND,
    NODE_CLIENT_STATE_SENDED,
    NODE_CLIENT_STATE_END
};

// state for a client connection
typedef struct chain_node_client {
    int state;
    dap_client_t *a_client;
    dap_events_t *a_events;
    pthread_cond_t wait_cond;
    pthread_mutex_t wait_mutex;
} chain_node_client_t;


int chain_node_client_init(void);

void chain_node_client_deinit();

/**
 * Create connection to server
 *
 * return a connection handle, or NULL, if an error
 */
chain_node_client_t* chain_node_client_connect(dap_chain_node_info_t *node_info);

/**
 * Close connection to server, delete chain_node_client_t *client
 */
void chain_node_client_close(chain_node_client_t *client);

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample NODE_CLIENT_STATE_CONNECT or NODE_CLIENT_STATE_SENDED
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int chain_node_client_wait(chain_node_client_t *client, int waited_state, int timeout_ms);


/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
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

#include "uthash.h"
#include "dap_client.h"
#include "dap_chain_node.h"

// connection states
typedef enum dap_chain_node_client_state {
    NODE_CLIENT_STATE_ERROR = -1,
    NODE_CLIENT_STATE_DISCONNECTED = 0,
    NODE_CLIENT_STATE_GET_NODE_ADDR = 1,
    NODE_CLIENT_STATE_NODE_ADDR_LEASED = 2,
    NODE_CLIENT_STATE_PING = 3,
    NODE_CLIENT_STATE_PONG = 4,
    NODE_CLIENT_STATE_CONNECT = 5,
    NODE_CLIENT_STATE_CONNECTED = 100,
    //NODE_CLIENT_STATE_SEND,
    //NODE_CLIENT_STATE_SENDED,
    NODE_CLIENT_STATE_SYNC_GDB = 101,
    NODE_CLIENT_STATE_SYNC_CHAINS = 102,
    NODE_CLIENT_STATE_SYNCED = 103
} dap_chain_node_client_state_t;

typedef struct dap_chain_node_client dap_chain_node_client_t;

typedef void (*dap_chain_node_client_callback_t)(dap_chain_node_client_t *, void*);

// state for a client connection
typedef struct dap_chain_node_client {
    dap_chain_node_client_state_t state;
    dap_chain_cell_id_t cell_id;
    dap_client_t *client;
    dap_events_t *events;
    char last_error[128];

    dap_chain_node_client_callback_t callback_connected;
    #ifndef _WIN32
    pthread_cond_t wait_cond;
    #else
    HANDLE wait_cond;
#endif
    pthread_mutex_t wait_mutex;

    // For hash indexing
    UT_hash_handle hh;
    dap_chain_node_addr_t remote_node_addr;
    struct in_addr remote_ipv4;
    struct in6_addr remote_ipv6;

    bool keep_connection;
} dap_chain_node_client_t;
#define DAP_CHAIN_NODE_CLIENT(a) ( (dap_chain_node_client_t *) (a)->_inheritor )

int dap_chain_node_client_init(void);

void dap_chain_node_client_deinit(void);

dap_chain_node_client_t* dap_chain_client_connect(dap_chain_node_info_t *a_node_info, dap_client_stage_t a_stage_target,
        const char *a_active_channels);
/**
 * Create handshake to server
 *
 * return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_node_client_connect(dap_chain_node_info_t *node_info);

/**
 * Close connection to server, delete chain_node_client_t *client
 */
void dap_chain_node_client_close(dap_chain_node_client_t *client);

/**
 * Send stream request to server
 */
int dap_chain_node_client_send_ch_pkt(dap_chain_node_client_t *a_client, uint8_t a_ch_id, uint8_t a_type,
        const void *a_buf, size_t a_buf_size);

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample NODE_CLIENT_STATE_CONNECT or NODE_CLIENT_STATE_SENDED
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int dap_chain_node_client_wait(dap_chain_node_client_t *a_client, int a_waited_state, int a_timeout_ms);

int dap_chain_node_client_set_callbacks(dap_client_t *a_client, uint8_t a_ch_id);


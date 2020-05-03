/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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

#include <pthread.h>
#include <stdbool.h>
#include "dap_client.h"
#include "dap_chain_mempool.h"

// connection states
enum {
    CLIENT_MEMPOOL_ERROR = -1,
    CLIENT_MEMPOOL_INIT,
    CLIENT_MEMPOOL_CONNECT,
    CLIENT_MEMPOOL_CONNECTED,
    CLIENT_MEMPOOL_SEND,
    CLIENT_MEMPOOL_SENDED,
    CLIENT_MEMPOOL_END
};

// state for a client connection with mempool
typedef struct client_mempool {
    int state;
    dap_events_t *a_events;
    dap_client_t *a_client;
    pthread_cond_t wait_cond;
    pthread_mutex_t wait_mutex;
    struct readed_data{
        uint8_t *data;
        int data_len;
    }read_data_t;
} client_mempool_t;

int client_mempool_init(void);
void client_mempool_deinit();

client_mempool_t* client_mempool_connect(const char *addr);
void client_mempool_close(client_mempool_t *mempool);

/**
 * timeout_ms timeout in milliseconds
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int client_mempool_wait(client_mempool_t *mempool, int waited_state, int timeout_ms);

/**
 * get read data from server
 */
uint8_t* client_mempool_read(client_mempool_t *mempool, int *data_len);

/**
 * datum add in mempool
 */
int client_mempool_send_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool);
/**
 * datum check in mempool
 */
int client_mempool_check_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool);
/**
 * datum delete from mempool
 */
int client_mempool_del_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool);

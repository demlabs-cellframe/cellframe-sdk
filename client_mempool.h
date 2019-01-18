#pragma once

#include <pthread.h>
#include "dap_client.h"
#include "dap_chain_mempool.h"

// connection states
enum {
    CLIENT_MEMPOOL_ERROR = -1, CLIENT_MEMPOOL_INIT, CLIENT_MEMPOOL_CONNECT, CLIENT_MEMPOOL_CONNECTED, CLIENT_MEMPOOL_SENDED, CLIENT_MEMPOOL_END
};

// state for a client connection with mempool
typedef struct client_mempool_t {
    int state;
    dap_events_t *a_events;
    dap_client_t *a_client;
    pthread_cond_t wait_cond;
    pthread_mutex_t wait_mutex;
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


int client_mempool_send_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool);

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <assert.h>
#include <errno.h>
#include "dap_common.h"

#include "dap_client_pvt.h"
#include "dap_http_client_simple.h"
#include "client_mempool.h"

// connection states
enum {
    ERROR = -1, INIT, CONNECT, CONNECTED, SENDED, END
};

int dap_http_client_simple_wait();

static void stage_status_callback(dap_client_t *a_client, void *a_arg)
{
    printf("* stage_status_callback client=%x data=%x\n", a_client, a_arg);
}

static void stage_status_error_callback(dap_client_t *a_client, void *a_arg)
{
    printf("* tage_status_error_callback client=%x data=%x\n", a_client, a_arg);
}

void a_response_proc(dap_client_t *a_client, void *str, size_t str_len)
{
    printf("a* _response_proc a_client=%x str=%x str_len=%d\n", a_client, str, str_len);
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = SENDED;
        pthread_cond_signal(&mempool->wait_cond);
        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

void a_response_error(dap_client_t *a_client, int val)
{
    printf("* a_response_error a_client=%x val=%d\n", a_client, val);
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = ERROR;
        pthread_cond_signal(&mempool->wait_cond);
        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

// callback for the end of handshake
static void a_stage_end_callback(dap_client_t *a_client, void *a_arg)
{
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = CONNECTED;
        pthread_cond_signal(&mempool->wait_cond);
        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

int client_mempool_init(void)
{
    int res = dap_client_init();
    res = dap_http_client_simple_init();
    return res;
}

void client_mempool_deinit()
{
    dap_http_client_simple_deinit();
    dap_client_deinit();
}

client_mempool_t* client_mempool_connect(const char *addr)
{
    if(!addr || strlen(addr) < 1)
        return NULL;
    client_mempool_t *mempool = DAP_NEW_Z(client_mempool_t);
    mempool->state = INIT;
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&mempool->wait_cond, &attr);
    pthread_mutex_init(&mempool->wait_mutex, NULL);
    mempool->a_events = dap_events_new();
    mempool->a_client = dap_client_new(mempool->a_events, stage_status_callback, stage_status_error_callback);
    mempool->a_client->_inheritor = mempool;
    dap_client_pvt_t *l_client_internal = DAP_CLIENT_PVT(mempool->a_client);

    l_client_internal->uplink_addr = strdup(addr);
    l_client_internal->uplink_port = 8079; // TODO read from kelvin-node.cfg [server][listen_port_tcp]
    dap_client_stage_t a_stage_target = STAGE_ENC_INIT;

    mempool->state = CONNECT;
    // Handshake
    dap_client_go_stage(mempool->a_client, a_stage_target, a_stage_end_callback);
    return mempool;
}

/**
 * timeout_ms timeout in milliseconds
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int client_mempool_wait(client_mempool_t *mempool, int timeout_ms)
{
    int ret = -1;
    if(!mempool)
        return -1;
    pthread_mutex_lock(&mempool->wait_mutex);
    struct timespec to;
    clock_gettime(CLOCK_MONOTONIC, &to);
    int64_t nsec_new = to.tv_nsec + timeout_ms * 1000000ll;
    // if the new number of nanoseconds is more than a second
    if(nsec_new > (long) 1e9) {
        to.tv_sec += nsec_new / (long) 1e9;
        to.tv_nsec = nsec_new % (long) 1e9;
    }
    else
        to.tv_nsec = (long) nsec_new;
    int wait = pthread_cond_timedwait(&mempool->wait_cond, &mempool->wait_mutex, &to);
    if(wait == 0) //0
        ret = 1;
    else if(wait == ETIMEDOUT) // 110 260
        ret = 0;
    pthread_mutex_unlock(&mempool->wait_mutex);
    return ret;
}

void client_mempool_close(client_mempool_t *mempool)
{
    if(mempool)
    {
        dap_client_pvt_t *l_client_internal = DAP_CLIENT_PVT(mempool->a_client);
        DAP_DELETE(l_client_internal->uplink_addr);
        dap_client_delete(mempool->a_client);
        dap_events_delete(mempool->a_events);
        pthread_cond_destroy(&mempool->wait_cond);
        pthread_mutex_destroy(&mempool->wait_mutex);
        DAP_DELETE(mempool);
    }
}

int client_mempool_send_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum)
{
    /*
     void *a_request = "123";
     size_t a_request_size = 3*/
    const char * a_path = "mempool";
    const char *a_suburl = "mempool"; //"enc_init";
    const char* a_query = "";
    size_t a_request_size = 0, shift_size = 0;
    for(int i = 0; i < datum->datum_count; i++) {
        a_request_size += _dap_chain_datum_data_size(datum->data[i]);
    }
    uint8_t *a_request = DAP_NEW_SIZE(uint8_t, a_request_size);
    for(int i = 0; i < datum->datum_count; i++) {
        memcpy(a_request + shift_size, datum->data[i], _dap_chain_datum_data_size(datum->data[i]));
    }
    dap_client_request_enc(mempool->a_client, a_path, a_suburl, a_query, a_request, a_request_size,
            a_response_proc, a_response_error);
    DAP_DELETE(a_request);
    return 1;
}

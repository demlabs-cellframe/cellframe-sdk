#include <stdio.h>
#include <string.h>
#include <time.h>

#include <assert.h>
#include <errno.h>
#include "dap_common.h"

#include "dap_client_pvt.h"
#include "dap_http_client_simple.h"
#include "client_mempool.h"

// callback for dap_client_new() in client_mempool_connect()
static void stage_status_callback(dap_client_t *a_client, void *a_arg)
{
    printf("* stage_status_callback client=%x data=%x\n", a_client, a_arg);
}
// callback for dap_client_new() in client_mempool_connect()
static void stage_status_error_callback(dap_client_t *a_client, void *a_arg)
{
    printf("* tage_status_error_callback client=%x data=%x\n", a_client, a_arg);
}

// callback for dap_client_request_enc() in client_mempool_send_datum()
static void a_response_proc(dap_client_t *a_client, void *str, size_t str_len)
{
    printf("a* _response_proc a_client=%x str=%s str_len=%d\n", a_client, str, str_len);
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        if(str_len > 0) {
            mempool->read_data_t.data = DAP_NEW_Z_SIZE(uint8_t, str_len + 1);
            if(mempool->read_data_t.data) {
                memcpy(mempool->read_data_t.data, str, str_len);
                mempool->read_data_t.data_len = str_len;
            }
        }
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = CLIENT_MEMPOOL_SENDED;
        pthread_cond_signal(&mempool->wait_cond);
        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

// callback for dap_client_request_enc() in client_mempool_send_datum()
static void a_response_error(dap_client_t *a_client, int val)
{
    printf("* a_response_error a_client=%x val=%d\n", a_client, val);
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = CLIENT_MEMPOOL_ERROR;
        pthread_cond_signal(&mempool->wait_cond);
        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

// callback for the end of handshake in dap_client_go_stage() / client_mempool_connect()
static void a_stage_end_callback(dap_client_t *a_client, void *a_arg)
{
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = CLIENT_MEMPOOL_CONNECTED;
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
    mempool->state = CLIENT_MEMPOOL_INIT;
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

    mempool->state = CLIENT_MEMPOOL_CONNECT;
    // Handshake
    dap_client_go_stage(mempool->a_client, a_stage_target, a_stage_end_callback);
    return mempool;
}

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample CLIENT_MEMPOOL_CONNECTED or CLIENT_MEMPOOL_SENDED
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int client_mempool_wait(client_mempool_t *mempool, int waited_state, int timeout_ms)
{
    int ret = -1;
    if(!mempool)
        return -1;
    pthread_mutex_lock(&mempool->wait_mutex);
// have waited
    if(mempool->state == waited_state) {
        pthread_mutex_unlock(&mempool->wait_mutex);
        return 1;
    }
// prepare for signal waiting
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
// signal waiting
    int wait = pthread_cond_timedwait(&mempool->wait_cond, &mempool->wait_mutex, &to);
    if(wait == 0) //0
        ret = 1;
    else if(wait == ETIMEDOUT) // 110 260
        ret = 0;
    pthread_mutex_unlock(&mempool->wait_mutex);
    return ret;
}

/**
 * get read data from server
 */
uint8_t* client_mempool_read(client_mempool_t *mempool, int *data_len)
{
    if(mempool && mempool->read_data_t.data_len > 0) {

        uint8_t*data = DAP_NEW_Z_SIZE(uint8_t, mempool->read_data_t.data_len + 1);
        if(mempool->read_data_t.data) {
            memcpy(data, mempool->read_data_t.data, mempool->read_data_t.data_len);
            if(data_len)
                *data_len = mempool->read_data_t.data_len;
            return data;
        }
    }
    return NULL;
}

void client_mempool_close(client_mempool_t *mempool)
{
    if(mempool) {
        // TODO send last request for dehandshake with "SessionCloseAfterRequest=true"
        // ...
        dap_client_pvt_t *l_client_internal = DAP_CLIENT_PVT(mempool->a_client);
        DAP_DELETE(l_client_internal->uplink_addr);
        dap_client_delete(mempool->a_client);
        dap_events_delete(mempool->a_events);
        DAP_DELETE(mempool->read_data_t.data);
        pthread_cond_destroy(&mempool->wait_cond);
        pthread_mutex_destroy(&mempool->wait_mutex);
        DAP_DELETE(mempool);
    }
}

// set new state and delete previous read data
static void client_mempool_reset(client_mempool_t *mempool, int new_state)
{
    if(!mempool)
        return;
    pthread_mutex_lock(&mempool->wait_mutex);
    mempool->read_data_t.data_len = 0;
    DAP_DELETE(mempool->read_data_t.data);
    mempool->read_data_t.data = NULL;
    mempool->state = new_state;
    pthread_mutex_unlock(&mempool->wait_mutex);
}

// send request to server
static int client_mempool_send_request(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool, uint8_t action)
{
    if(!mempool || !datum_mempool || mempool->state < CLIENT_MEMPOOL_CONNECTED)
        return -1;
    const char * a_path = "mempool";
    const char *a_suburl = "mempool"; //"enc_init";
    const char* a_query = "";
    size_t a_request_size = 0;
    uint8_t *a_request = dap_datum_mempool_serialize(datum_mempool, &a_request_size);
    uint8_t *a_request_out = DAP_NEW_Z_SIZE(uint8_t, a_request_size * 2 + 1); // a_request + 1 byte for type action
    *((uint8_t*) a_request_out) = action;
    bin2hex(a_request_out + 1, a_request, a_request_size);
    client_mempool_reset(mempool, CLIENT_MEMPOOL_SEND);
    dap_client_request_enc(mempool->a_client, a_path, a_suburl, a_query, a_request_out, a_request_size * 2 + 1,
            a_response_proc, a_response_error);
    DAP_DELETE(a_request);
    DAP_DELETE(a_request_out);
    return 1;
}

/**
 * datum add in mempool
 *
 * return -1 not connected or error, 1 send packet OK
 */
int client_mempool_send_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool)
{
    return client_mempool_send_request(mempool, datum_mempool, DAP_DATUM_MEMPOOL_ADD);
}

/**
 * datum check in mempool
 *
 * return -1 not connected or error, 1 send packet OK
 */
int client_mempool_check_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool)
{
    return client_mempool_send_request(mempool, datum_mempool, DAP_DATUM_MEMPOOL_CHECK);
}

/**
 * datum delete from mempool
 *
 * return -1 not connected or error, 1 send packet OK
 */
int client_mempool_del_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool)
{
    return client_mempool_send_request(mempool, datum_mempool, DAP_DATUM_MEMPOOL_DEL);
}

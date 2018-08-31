#include "dap_traffic_track.h"
#include "dap_common.h"

#define LOG_TAG "dap_traffic_track"
#define BITS_IN_BYTE 8

static dap_traffic_callback_t callback = NULL;
static dap_server_t * _dap_server;
static ev_timer _timeout_watcher;
static struct ev_loop *loop;

/**
 * @brief calculate_mbits_speed
 * @param count_bytes
 * @details timeout we gots from _timeout_watcher.repeat
 * @return mbit/second speed
 */
static double calculate_mbits_speed(size_t count_bytes) {
    size_t bits_per_second = (count_bytes / (size_t)_timeout_watcher.repeat) * BITS_IN_BYTE;
//    log_it(L_DEBUG, "TIMEOUT: %d, bits_per_second: %d mbits: %f",
//           (size_t)_timeout_watcher.repeat, bits_per_second, bits_per_second / 1000000.0);
    return bits_per_second / 1000000.0; // convert to mbits
}

static void timeout_cb()
{
    pthread_mutex_lock(&_dap_server->mutex_on_hash);

    dap_server_client_t *dap_cur, *tmp;
    HASH_ITER(hh,_dap_server->clients,dap_cur,tmp) {
        dap_cur->upload_stat.speed_mbs =
                calculate_mbits_speed(dap_cur->upload_stat.buf_size_total -
                                      dap_cur->upload_stat.buf_size_total_old);
        dap_cur->upload_stat.buf_size_total_old = dap_cur->upload_stat.buf_size_total;

        dap_cur->download_stat.speed_mbs =
                calculate_mbits_speed(dap_cur->download_stat.buf_size_total -
                                      dap_cur->download_stat.buf_size_total_old);
        dap_cur->download_stat.buf_size_total_old = dap_cur->download_stat.buf_size_total;

//        log_it(L_DEBUG, "upload_mbs: %f download_mbs: %f", dap_cur->upload_stat.speed_mbs,
//               dap_cur->download_stat.speed_mbs);
    }

    pthread_mutex_unlock(&_dap_server->mutex_on_hash);

    if(callback != NULL) {
        callback(NULL, 0);
        return;
    }
}

void dap_traffic_track_init(dap_server_t * server,
                            time_t timeout)
{
    _dap_server = server;
    _timeout_watcher.repeat = timeout;
    loop = EV_DEFAULT;
    ev_init(&_timeout_watcher, timeout_cb);
    ev_timer_again (loop, &_timeout_watcher);
    log_it(L_NOTICE, "Initialized traffic track module");
}

void dap_traffic_track_deinit()
{
    ev_timer_stop(loop, &_timeout_watcher);
    log_it(L_NOTICE, "Deinitialized traffic track module");
}

void dap_traffic_set_callback(dap_traffic_callback_t cb)
{
   callback = cb;
}

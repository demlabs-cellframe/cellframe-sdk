#include "dap_traffic_track.h"
#include "dap_common.h"

#define LOG_TAG "dap_traffic_track"
#define BYTES_IN_MB 1048576.0

static dap_traffic_callback_t callback = NULL;
static dap_server_t * _dap_server;
static ev_timer _timeout_watcher;
static struct ev_loop *loop;

/**
 * @brief calculate_mbs_speed
 * @param count_bytes
 * @details timeout we gots from _timeout_watcher.repeat
 * @return mbs speed
 */
static double calculate_mbs_speed(size_t count_bytes) {
    size_t bytes_per_sec = count_bytes / (size_t)_timeout_watcher.repeat;
    log_it(L_DEBUG, "TIMEOUT: %d, bytes_per_sec: %d",
           (size_t)_timeout_watcher.repeat, bytes_per_sec);
    return bytes_per_sec / BYTES_IN_MB;
}

static void timeout_cb()
{
    pthread_mutex_lock(&_dap_server->mutex_on_hash);

    dap_server_client_t *dap_cur, *tmp;
    HASH_ITER(hh,_dap_server->clients,dap_cur,tmp) {
        log_it(L_DEBUG, "hash iter socket: %d buf_in_total_new: %d, buf_in_total_old: %d",
               dap_cur->socket, dap_cur->buf_in_size_total, dap_cur->buf_in_size_total_old);

        dap_cur->upload_speed_bytes =
                calculate_mbs_speed(dap_cur->buf_in_size_total - dap_cur->buf_in_size_total_old);
        dap_cur->buf_in_size_total_old = dap_cur->buf_in_size_total;

        dap_cur->download_speed_bytes =
                calculate_mbs_speed(dap_cur->buf_out_size_total - dap_cur->buf_out_size_total_old);
        dap_cur->buf_out_size_total_old = dap_cur->buf_out_size_total;

        log_it(L_DEBUG, "upload_mbs: %f, download_mbs: %f", dap_cur->upload_speed_bytes, dap_cur->download_speed_bytes);

    }

    pthread_mutex_unlock(&_dap_server->mutex_on_hash);

//    if(callback != NULL) {
//        callback(NULL, 0);
//        return;
//    }
//    log_it(L_WARNING, "Callback is NULL!");
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

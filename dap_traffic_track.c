#include "dap_traffic_track.h"
#include "dap_common.h"

#define LOG_TAG "dap_traffic_track"
#define BITS_IN_BYTE 8
#define ALLOC_STEP 100

static dap_traffic_callback_t callback = NULL;
static dap_server_t * _dap_server;
static ev_timer _timeout_watcher;
static struct ev_loop *loop;

static struct callback_result {
    dap_traffic_track_result_t * res;
    size_t allocated_counter;
} _callback_result;

/**
 * @brief calculate_mbits_speed
 * @param count_bytes
 * @details timeout we gots from _timeout_watcher.repeat
 * @return mbit/second speed
 */
static double _calculate_mbits_speed(size_t count_bytes)
{
    size_t bits_per_second = (count_bytes / (size_t)_timeout_watcher.repeat) * BITS_IN_BYTE;
    //    log_it(L_DEBUG, "TIMEOUT: %d, bits_per_second: %d mbits: %f",
    //           (size_t)_timeout_watcher.repeat, bits_per_second, bits_per_second / 1000000.0);
    return bits_per_second / 1000000.0; // convert to mbits
}


static void _realloc_callback_result(size_t count_users)
{
    // rounding to multiple ALLOC_STEP
    size_t new_size = (count_users + ALLOC_STEP) - (count_users % ALLOC_STEP);

    _callback_result.res = (dap_traffic_track_result_t *) realloc
            (_callback_result.res, new_size * sizeof(dap_traffic_track_result_t));
    _callback_result.allocated_counter = new_size;

    log_it(L_DEBUG, "Reallocated memory for _callback_result to: %d", _callback_result.allocated_counter);
}

static void _timeout_cb()
{
    pthread_mutex_lock(&_dap_server->mutex_on_hash);

    size_t count_users = HASH_COUNT(_dap_server->clients);

    if(_callback_result.allocated_counter < count_users ||
            _callback_result.allocated_counter - ALLOC_STEP > count_users) {
        _realloc_callback_result(count_users);
    }

    if(count_users) {
        size_t idx = 0;
        dap_server_client_t *dap_cur, *tmp;
        HASH_ITER(hh, _dap_server->clients, dap_cur,tmp) {

            dap_cur->upload_stat.speed_mbs =
                    _calculate_mbits_speed(dap_cur->upload_stat.buf_size_total -
                                          dap_cur->upload_stat.buf_size_total_old);
            dap_cur->upload_stat.buf_size_total_old = dap_cur->upload_stat.buf_size_total;

            dap_cur->download_stat.speed_mbs =
                    _calculate_mbits_speed(dap_cur->download_stat.buf_size_total -
                                          dap_cur->download_stat.buf_size_total_old);

            dap_cur->download_stat.buf_size_total_old = dap_cur->download_stat.buf_size_total;

            //        log_it(L_DEBUG, "upload_mbs: %f download_mbs: %f", dap_cur->upload_stat.speed_mbs,
            //               dap_cur->download_stat.speed_mbs);
            strcpy(_callback_result.res[idx].client_id, dap_cur->id);
            _callback_result.res[idx].upload_speed_mbs = dap_cur->upload_stat.speed_mbs;
            _callback_result.res[idx].download_speed_mbs = dap_cur->download_stat.speed_mbs;
            idx++;
        }
    }

    pthread_mutex_unlock(&_dap_server->mutex_on_hash);

    if(callback != NULL) {
        callback(_callback_result.res, count_users);
    }
}

void dap_traffic_track_init(dap_server_t * server,
                            time_t timeout)
{
    _callback_result.allocated_counter = ALLOC_STEP;
    _callback_result.res = calloc(_callback_result.allocated_counter, sizeof (dap_traffic_track_result_t));

    _dap_server = server;
    _timeout_watcher.repeat = timeout;
    loop = EV_DEFAULT;
    ev_init(&_timeout_watcher, _timeout_cb);
    ev_timer_again (loop, &_timeout_watcher);
    log_it(L_NOTICE, "Initialized traffic track module");
}

void dap_traffic_track_deinit()
{
    _callback_result.allocated_counter = 0;
    free(_callback_result.res);
    ev_timer_stop(loop, &_timeout_watcher);
    ev_loop_destroy(loop);
    log_it(L_NOTICE, "Deinitialized traffic track module");
}

void dap_traffic_set_callback(dap_traffic_callback_t cb)
{
    callback = cb;
}

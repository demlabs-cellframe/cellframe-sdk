#include "dap_traffic_track.h"
#include "dap_common.h"

#include <pthread.h>

#define LOG_TAG "dap_traffic_track"
#define BITS_IN_BYTE 8
#define ALLOC_STEP 100

static dap_traffic_callback_t _callback = NULL;
static dap_server_t * _dap_server;
static ev_timer _timeout_watcher;
static struct ev_loop *loop;
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _cond = PTHREAD_COND_INITIALIZER;
static pthread_t worker_thread;
static bool _stop_worker_signal = false;

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

void* _worker_run(void * a)
{
    (void)a;
    pthread_mutex_lock(&_mutex);
    while (true) {
        pthread_cond_wait(&_cond, &_mutex);
        if(_stop_worker_signal) {
            log_it(L_INFO, "Dap traffic track worker stopped");
            _stop_worker_signal = false;
            break;
        }
        _callback(_dap_server);
    }
    pthread_mutex_unlock(&_mutex);
    pthread_exit(NULL);
}

void _worker_start()
{
    pthread_mutex_init(&_mutex, NULL);
    pthread_cond_init(&_cond, NULL);
    pthread_create(&worker_thread, NULL, _worker_run, NULL);
}

void _worker_stop()
{
    pthread_mutex_lock(&_mutex);
    _stop_worker_signal = true;
    pthread_cond_signal(&_cond);
    pthread_mutex_unlock(&_mutex);

    // wait for exit worker_thread
    pthread_join(worker_thread, NULL);

    pthread_mutex_destroy(&_mutex);
    pthread_cond_destroy(&_cond);
    _callback = NULL;
}

static void _timeout_cb()
{
    pthread_mutex_lock(&_dap_server->mutex_on_hash);

    size_t count_users = HASH_COUNT(_dap_server->clients);

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

            idx++;
        }
    }

    pthread_mutex_unlock(&_dap_server->mutex_on_hash);

    if(_callback != NULL) {
        pthread_mutex_lock(&_mutex);
        pthread_cond_signal(&_cond);
        pthread_mutex_unlock(&_mutex);
    }
}

void dap_traffic_track_init(dap_server_t * server,
                            time_t timeout)
{
    _dap_server = server;
    _timeout_watcher.repeat = timeout;
    loop = EV_DEFAULT;
    ev_init(&_timeout_watcher, _timeout_cb);
    ev_timer_again (loop, &_timeout_watcher);
    log_it(L_NOTICE, "Initialized traffic track module");
}

void dap_traffic_track_deinit()
{
    if(_callback != NULL)
        _worker_stop();

    ev_timer_stop(loop, &_timeout_watcher);
    ev_loop_destroy(loop);
    log_it(L_NOTICE, "Deinitialized traffic track module");
}

void dap_traffic_callback_stop() {
    if(_callback == NULL) {
        log_it(L_WARNING, "worker not running");
        return;
    }
    _worker_stop();
}

void dap_traffic_callback_set(dap_traffic_callback_t cb)
{
    if(_callback == NULL) {
        _callback = cb;
        _worker_start();
        return;
    }

    log_it(L_WARNING, "Callback already setted");
}

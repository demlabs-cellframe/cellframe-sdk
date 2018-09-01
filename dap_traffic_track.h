#ifndef _TRAFFIC_TRACK_H_
#define _TRAFFIC_TRACK_H_
#include "dap_server_client.h"
#include "dap_server.h"

typedef struct dap_traffic_track_result {
    dap_server_client_id client_id;
    double download_speed_mbs;
    double upload_speed_mbs;
} dap_traffic_track_result_t;

typedef void (*dap_traffic_callback_t) (dap_traffic_track_result_t[], size_t result_length); // Callback for specific server's operations

/**
 * @brief dap_traffic_track_init
 * @param clients
 * @param timeout callback
 */
void dap_traffic_track_init(dap_server_t * server,
                            time_t timeout);

/**
 * @brief dap_traffic_track_deinit
 */
void dap_traffic_track_deinit(void);

/**
 * @brief dap_traffic_add_callback
 */
void dap_traffic_set_callback(dap_traffic_callback_t);
#endif

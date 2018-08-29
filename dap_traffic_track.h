#ifndef _TRAFFIC_TRACK_H_
#define _TRAFFIC_TRACK_H_
#include "dap_server_client.h"
#include "dap_server.h"

typedef void (*dap_traffic_callback_t) (struct dap_traffic_info *, size_t count_info); // Callback for specific server's operations

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

#pragma once

#include <stdbool.h>
#include <time.h>

// Set last timestamp for remote node
bool dap_db_log_set_last_timestamp_remote(uint64_t a_node_addr, time_t a_timestamp);
// Get last timestamp for remote node
time_t dap_db_log_get_last_timestamp_remote(uint64_t a_node_addr);


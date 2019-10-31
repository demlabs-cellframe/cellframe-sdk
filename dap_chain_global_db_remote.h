#pragma once

#include <stdbool.h>
#include <time.h>

#include "dap_chain_common.h"
// Set addr for current node
bool dap_db_set_cur_node_addr(uint64_t a_address, char *a_net_name);
bool dap_db_set_cur_node_addr_exp(uint64_t a_address, char *a_net_name );
uint64_t dap_db_get_cur_node_addr(char *a_net_name);

// Set last id for remote node
bool dap_db_log_set_last_id_remote(uint64_t a_node_addr, uint64_t a_id);
// Get last id for remote node
uint64_t dap_db_log_get_last_id_remote(uint64_t a_node_addr);

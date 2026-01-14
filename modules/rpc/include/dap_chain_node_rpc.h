/*
#pragma once
 * Authors:
 * Pavel Uhanov <pavel.uhanov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

// REMOVED: dap_chain_node.h - creates cycle (rpc is low-level, node is in net)
// REMOVED: cmd include from header - breaks layering (net is low-level, cmd is high-level)
// Functions using cmd types should be in cmd module, not net
#ifdef DAP_OS_LINUX
#include <sys/sysinfo.h>
#else
#include "dap_config.h"
#include "dap_chain_node_types.h"  // Base node types from net/core (no cycle!)


// REMOVED: cmd statistics structures moved to cmd module
// net module should NOT track cmd-specific statistics - breaks layering
// Moved to: modules/cmd/include/dap_chain_node_cli_cmd.h

typedef struct dap_chain_node_rpc_states_info {
   uint32_t version;
   dap_stream_node_addr_t address;
   uint32_t location;
   uint32_t links_count;
   uint32_t cli_thread_count;
   struct sysinfo system_info;
   // REMOVED: dap_chain_node_rpc_cmd_states_info_t cmd_info - moved to cmd module
} DAP_ALIGN_PACKED dap_chain_node_rpc_states_info_t;

 void dap_chain_node_rpc_init(dap_config_t *a_cfg);
 void dap_chain_node_rpc_deinit();
 int dap_chain_node_rpc_info_save(dap_chain_node_info_t *a_node_info, bool a_force);
 int dap_chain_node_rpc_info_del(dap_stream_node_addr_t a_addr);
 dap_json_t *dap_chain_node_rpc_list();
 dap_chain_node_rpc_states_info_t *dap_chain_node_rpc_get_states_sort(size_t *a_count);
 bool dap_chain_node_rpc_is_my_node_authorized();
 bool dap_chain_node_rpc_is_balancer();
 bool dap_chain_node_rpc_is_root();
 dap_json_t *dap_chain_node_rpc_states_info_read(dap_stream_node_addr_t a_addr);

 DAP_STATIC_INLINE size_t dap_chain_node_rpc_get_states_info_size(dap_chain_node_rpc_states_info_t *a_info)
 {
    return a_info ? sizeof(dap_chain_node_rpc_states_info_t) : 0;
 }
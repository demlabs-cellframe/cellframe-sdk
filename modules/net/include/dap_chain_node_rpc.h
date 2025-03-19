/*
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
#include <sys/sysinfo.h>
#include "dap_chain_node.h"
#include "dap_config.h"

 typedef struct dap_chain_node_rpc_states_info {
    uint32_t version;
    dap_chain_node_addr_t address;
    uint32_t location;
    uint32_t links_count;
    uint32_t cli_thread_count;
    struct sysinfo sysinfo;
    uint32_t cmd_data_size;
    uint8_t cmd_data[];
} DAP_ALIGN_PACKED dap_chain_node_rpc_states_info_t;

 void dap_chain_node_rpc_init(dap_config_t *a_cfg);
 bool dap_chain_node_rpc_is_my_node_authorized();
 int dap_chain_node_rpc_info_save(dap_chain_node_info_t *a_node_info);
 dap_string_t *dap_chain_node_rpc_list();

 DAP_STATIC_INLINE size_t dap_chain_node_rpc_get_states_info_size(dap_chain_node_rpc_states_info_t *a_info)
 {
    return a_info ? sizeof(dap_chain_node_rpc_states_info_t) + a_info->cmd_data_size : 0;
 }
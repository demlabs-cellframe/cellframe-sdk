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

#include "dap_chain_node.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_config.h"

#ifndef WIN32
#include <sys/sysinfo.h>
#else
struct sysinfo {  // temporary added to read
	__kernel_long_t uptime;		/* Seconds since boot */
	__kernel_ulong_t loads[3];	/* 1, 5, and 15 minute load averages */
	__kernel_ulong_t totalram;	/* Total usable main memory size */
	__kernel_ulong_t freeram;	/* Available memory size */
	__kernel_ulong_t sharedram;	/* Amount of shared memory */
	__kernel_ulong_t bufferram;	/* Memory used by buffers */
	__kernel_ulong_t totalswap;	/* Total swap space size */
	__kernel_ulong_t freeswap;	/* swap space still available */
	__u16 procs;		   	/* Number of current processes */
	__u16 pad;		   	/* Explicit padding for m68k */
	__kernel_ulong_t totalhigh;	/* Total high memory size */
	__kernel_ulong_t freehigh;	/* Available high memory size */
	__u32 mem_unit;			/* Memory unit size in bytes */
	char _f[20-2*sizeof(__kernel_ulong_t)-sizeof(__u32)];	/* Padding: libc5 uses this.. */
};
#endif

typedef struct dap_chain_node_rpc_cmd_states_info {
   int16_t count;
   int64_t time_stat[DAP_CHAIN_NODE_CLI_CMD_ID_TOTAL];
} DAP_ALIGN_PACKED dap_chain_node_rpc_cmd_states_info_t;

typedef struct dap_chain_node_rpc_states_info {
   uint32_t version;
   dap_chain_node_addr_t address;
   uint32_t location;
   uint32_t links_count;
   uint32_t cli_thread_count;
   struct sysinfo sysinfo;
   dap_chain_node_rpc_cmd_states_info_t cmd_info;
} DAP_ALIGN_PACKED dap_chain_node_rpc_states_info_t;

 void dap_chain_node_rpc_init(dap_config_t *a_cfg);
 void dap_chain_node_rpc_deinit();
 int dap_chain_node_rpc_info_save(dap_chain_node_info_t *a_node_info);
 dap_string_t *dap_chain_node_rpc_list();
 dap_chain_node_rpc_states_info_t *dap_chain_node_rpc_get_states_sort(size_t *a_count);
 bool dap_chain_node_rpc_is_my_node_authorized();
 bool dap_chain_node_rpc_is_balancer_node();

 DAP_STATIC_INLINE size_t dap_chain_node_rpc_get_states_info_size(dap_chain_node_rpc_states_info_t *a_info)
 {
    return a_info ? sizeof(dap_chain_node_rpc_states_info_t) : 0;
 }
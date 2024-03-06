/*
 * Authors:
 * Dmitriy A. Gerasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#pragma once

#include <limits.h>
#include "dap_common.h"
#include "dap_list.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_stream.h"
#include "dap_chain_common.h"
#include "dap_global_db.h"
#include "dap_chain.h"

typedef struct dap_chain_net dap_chain_net_t;

typedef struct dap_chain_node_info {
    dap_chain_node_addr_t address;
    dap_chain_cell_id_t cell_id;
    char alias[64];
    uint16_t ext_port;
    uint8_t ext_host_len;
    char ext_host[];
} DAP_ALIGN_PACKED dap_chain_node_info_t;

typedef struct dap_chain_node_states_info {
    dap_chain_node_addr_t address;
    uint64_t atoms_count;
    uint32_t links_count;
    dap_chain_node_addr_t links_addrs[];
} DAP_ALIGN_PACKED dap_chain_node_states_info_t;

typedef dap_stream_node_addr_t dap_chain_node_addr_t;
#define dap_chain_node_addr_str_check dap_stream_node_addr_str_check
#define dap_chain_node_addr_from_str dap_stream_node_addr_from_str
#define dap_chain_node_addr_is_blank dap_stream_node_addr_is_blank

/**
 * Calculate size of struct dap_chain_node_info_t
 */
DAP_STATIC_INLINE size_t dap_chain_node_info_get_size(dap_chain_node_info_t *a_node_info)
{
    return !a_node_info ? 0 : sizeof(dap_chain_node_info_t) + a_node_info->ext_host_len + 1;
}

/**
 * Compare addresses of two dap_chain_node_info_t structures
 *
 * @return True if addresses are equal, otherwise false
 */
bool dap_chain_node_info_addr_match(dap_chain_node_info_t *node_info1, dap_chain_node_info_t *node_info2);

/**
 * Compare two struct dap_chain_node_info_t
 */
bool dap_chain_node_info_match(dap_chain_node_info_t *node_info1, dap_chain_node_info_t *node_info2);

/**
 * Serialize dap_chain_node_info_t
 * size[out] - length of output string
 * return data or NULL if error
 */
//uint8_t* dap_chain_node_info_serialize(dap_chain_node_info_t *node_info, size_t *size);

dap_chain_node_addr_t * dap_chain_node_alias_find(dap_chain_net_t * l_net,const char *alias);
bool dap_chain_node_alias_register(dap_chain_net_t *a_net, const char *a_alias, dap_chain_node_addr_t *a_addr);
bool dap_chain_node_alias_delete(dap_chain_net_t * l_net,const char *alias);

int dap_chain_node_info_save(dap_chain_net_t * l_net,dap_chain_node_info_t *node_info);
int dap_chain_node_info_del(dap_chain_net_t * l_net,dap_chain_node_info_t *node_info);
dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_net_t *l_net, dap_chain_node_addr_t *address);

inline static char *dap_chain_node_addr_to_str_static(dap_chain_node_addr_t *a_address)
{
    static _Thread_local char s_buf[23] = { '\0' };
    dap_snprintf(s_buf, sizeof(s_buf), NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(a_address));
    return s_buf;
}

bool dap_chain_node_mempool_need_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum);
bool dap_chain_node_mempool_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_datum_hash_str);
void dap_chain_node_mempool_process_all(dap_chain_t *a_chain, bool a_force);
bool dap_chain_node_mempool_autoproc_init();
inline static void dap_chain_node_mempool_autoproc_deinit() {}
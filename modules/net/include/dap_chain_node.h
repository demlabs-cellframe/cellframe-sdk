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
    struct {
        dap_chain_node_addr_t address;
        dap_chain_cell_id_t cell_id;
        struct in_addr ext_addr_v4;
        struct in6_addr ext_addr_v6;
        uint16_t ext_port; // Port thats node listening
    } DAP_ALIGN_PACKED hdr;
    struct {
        uint64_t atoms_count; /* truncated alias len */
        uint32_t links_number;
        byte_t other_info_for_future[240];
    } DAP_ALIGN_PACKED info;
    uint16_t alias_len;
    byte_t alias[];
} DAP_ALIGN_PACKED dap_chain_node_info_t;

typedef dap_stream_node_addr_t dap_chain_node_addr_t;
#define dap_chain_node_addr_str_check dap_stream_node_addr_str_check
#define dap_chain_node_addr_from_str dap_stream_node_addr_from_str
#define dap_chain_node_addr_not_null dap_stream_node_addr_not_null

/**
 * Calculate size of struct dap_chain_node_info_t
 */
DAP_STATIC_INLINE size_t dap_chain_node_info_get_size(dap_chain_node_info_t *a_node_info)
{
    if (!a_node_info)
        return 0;
    return (sizeof(dap_chain_node_info_t) + a_node_info->alias_len);
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
dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_net_t * l_net, dap_chain_node_addr_t *address);

inline static char *dap_chain_node_addr_to_hash_str(dap_chain_node_addr_t *a_address)
{
    return dap_strdup_printf(NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(a_address));
}

bool dap_chain_node_mempool_need_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum);
bool dap_chain_node_mempool_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_datum_hash_str);
void dap_chain_node_mempool_process_all(dap_chain_t *a_chain, bool a_force);
bool dap_chain_node_mempool_autoproc_init();
inline static void dap_chain_node_mempool_autoproc_deinit() {}

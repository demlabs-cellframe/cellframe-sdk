/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_global_db.h"

/**
  *  Node Declaration request
  *
  */

#define DAP_CHAIN_NODE_DECL_REQ_INFO_SIZE 32
typedef struct dap_chain_node_delc_req{
    dap_chain_node_addr_t node_address;
    uint64_t create_ts;
    union{
        uint8_t raw[DAP_CHAIN_NODE_DECL_REQ_INFO_SIZE];
        char str[DAP_CHAIN_NODE_DECL_REQ_INFO_SIZE];
    } info;
} DAP_ALIGN_PACKED dap_chain_decl_req_t;

/**
  * @struct dap_chain_node decl
  * @details New node declaration
  *
  */
#define DAP_CHAIN_NODE_DECL_ACCEPT_INFO_SIZE 32
typedef struct dap_chain_node_decl{
    dap_chain_decl_req_t request;
    uint64_t accept_ts;
    struct in_addr accept_addr_v4;
    struct in6_addr accept_addr_v6;
    union{
        uint8_t raw[DAP_CHAIN_NODE_DECL_ACCEPT_INFO_SIZE];
        char str[DAP_CHAIN_NODE_DECL_ACCEPT_INFO_SIZE];
    } accept_info;
} DAP_ALIGN_PACKED dap_chain_node_decl_t;

typedef struct dap_chain_node_info
{
    struct {
        dap_chain_node_addr_t address;
        dap_chain_cell_id_t cell_id;
        uint32_t links_number;
        struct in_addr ext_addr_v4;
        struct in6_addr ext_addr_v6;
        uint16_t ext_port; // Port thats node listening
        char alias[256];
    } DAP_ALIGN_PACKED hdr;
    dap_chain_node_addr_t links[]; // dap_chain_addr_t
} DAP_ALIGN_PACKED dap_chain_node_info_t;

typedef struct dap_chain_node_publ{
    dap_chain_hash_fast_t decl_hash;
    dap_chain_node_info_t node_info;
} DAP_ALIGN_PACKED dap_chain_node_publ_t;

/**
 * Calculate size of struct dap_chain_node_info_t
 */
size_t dap_chain_node_info_get_size(dap_chain_node_info_t *node_info);

/**
 * Serialize dap_chain_node_info_t
 * size[out] - length of output string
 * return data or NULL if error
 */
//uint8_t* dap_chain_node_info_serialize(dap_chain_node_info_t *node_info, size_t *size);

/**
 * Deserialize dap_chain_node_info_t
 * size[in] - length of input string
 * return data or NULL if error
 */
//dap_chain_node_info_t* dap_chain_node_info_deserialize(uint8_t *node_info_str, size_t size);

/**
 * Generate node addr by shard id
 */
dap_chain_node_addr_t* dap_chain_node_gen_addr(dap_chain_cell_id_t *shard_id);

/**
 * Check the validity of the node address by shard id
 */
bool dap_chain_node_check_addr(dap_chain_node_addr_t *addr, dap_chain_cell_id_t *shard_id);

dap_chain_node_addr_t * dap_chain_node_alias_find(const char *alias);
bool dap_chain_node_alias_register(const char *alias, dap_chain_node_addr_t *addr);
bool dap_chain_node_alias_delete(const char *alias);

int dap_chain_node_info_save(dap_chain_node_info_t *node_info);
dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_node_addr_t *address);

inline static char* dap_chain_node_addr_to_hash_str(dap_chain_node_addr_t *address)
{
    char *a_key = dap_chain_global_db_hash((const uint8_t*) address, sizeof(dap_chain_node_addr_t));
    return a_key;
}



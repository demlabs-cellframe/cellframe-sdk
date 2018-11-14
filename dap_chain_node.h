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

#include <sys/socket.h>
#include <netinet/in.h>

#include "dap_common.h"
#include "dap_chain_common.h"

/**
  * @struct Node address
  *
  */
typedef union dap_chain_node_addr{
    uint64_t uint64;
    uint8_t raw[sizeof(uint64_t)];  // Access to selected octects
} dap_chain_node_addr_t;

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
        dap_chain_shard_id_t shard_id;
        uint32_t uplinks_number;
        struct in_addr ext_addr_v4;
        struct in6_addr ext_addr_v6;
    } DAP_ALIGN_PACKED hdr;
    dap_chain_addr_t uplinks[];
} DAP_ALIGN_PACKED dap_chain_node_info_t;

typedef struct dap_chain_node_publ{
    dap_chain_hash_fast_t decl_hash;
    dap_chain_node_info_t node_info;
} DAP_ALIGN_PACKED dap_chain_node_publ_t;

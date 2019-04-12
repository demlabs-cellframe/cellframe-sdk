/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

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

#include "dap_chain_node_ctl.h"
#include "dap_chain_net_srv_common.h"

//Classes of services
enum {
    SERV_CLASS_ONCE = 1, // one-time service
    SERV_CLASS_PERMANENT = 2
};

//Types of services
enum {
    SERV_ID_VPN = 1,
};

typedef struct dap_chain_net_srv
{
    dap_chain_node_ctl_t * node;
    dap_chain_net_srv_uid_t uid; // Unique ID for service.

    void * _internal;
    void * _inhertor;
} dap_chain_net_srv_t;

typedef struct dap_chain_net_srv_abstract
{
    uint64_t proposal_id; // id trade proposal. Must be unique to the node.

    uint8_t class; //Class of service
    uint8_t type_id; //Type of service
    union {
        struct {
            int bandwith;
            int abuse_resistant;
            int limit_bytes;
        } vpn;
        struct {
            int value;
        } other_srv;
    } proposal_params;

    uint64_t price; //  service price, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
    uint8_t price_units; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    char decription[128];
} DAP_ALIGN_PACKED dap_chain_net_srv_abstract_t;

int dap_chain_net_srv_init();
void dap_chain_net_srv_deinit();

void dap_chain_net_srv_add(dap_chain_net_srv_t * a_srv);
dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid);
const size_t dap_chain_net_srv_count();
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list();


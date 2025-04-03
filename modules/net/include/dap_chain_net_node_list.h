/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Roman Padenkov <roman.padenkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2023
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_http_simple.h"
#include "dap_chain_net.h"

#define DAP_NODE_LIST_URI_HASH "node_list_hash"


struct node_link_request {
    dap_chain_node_info_t *link_info;
    dap_chain_net_t *net;
#ifdef DAP_OS_WINDOWS
    CONDITION_VARIABLE wait_cond;
    CRITICAL_SECTION wait_crit_sec;
#else
    pthread_cond_t wait_cond;
    pthread_mutex_t wait_mutex;
#endif
    int response;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief dap_chain_net_node_list_get_gdb_group
* @param a_net
* @return
*/
DAP_STATIC_INLINE char* dap_chain_net_node_list_get_gdb_group(dap_chain_net_t * a_net)
{
    return a_net ? dap_strdup_printf("%s.service.orders",a_net->pub.gdb_groups_prefix) : NULL;
}

void dap_chain_net_node_check_http_issue_link(dap_http_simple_t *a_http_simple, void *a_arg);
int dap_chain_net_node_list_request(dap_chain_net_t *a_net, uint16_t a_port, bool a_sync, char a_cmd);
dap_chain_node_info_t* dap_chain_node_list_ip_check(dap_chain_node_info_t *a_node_info, dap_chain_net_t *a_net);
int dap_chain_net_node_list_init();

#ifdef __cplusplus
}
#endif
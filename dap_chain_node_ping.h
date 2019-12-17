/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
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

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <windows.h>
#endif
#include <pthread.h>

// start sending ping
int start_node_ping(pthread_t *a_thread, struct in_addr a_addr, int a_port, int a_count);

// wait for ending ping within timeout_ms milliseconds
int wait_node_ping(pthread_t l_thread, int timeout_ms);


// background thread for testing connect to the nodes
int dap_chain_node_ping_background_start(dap_chain_net_t *a_net, dap_list_t *a_node_list);
int dap_chain_node_ping_background_stop(void);
int dap_chain_node_ping_background_status(void);

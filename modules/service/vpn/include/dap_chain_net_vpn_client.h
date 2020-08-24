/*
 * Authors:
 *
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2019
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

#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv_vpn.h"

typedef enum dap_chain_net_vpn_client_status_enum{
    VPN_CLIENT_STATUS_NOT_STARTED=0,
    VPN_CLIENT_STATUS_STARTED,
    VPN_CLIENT_STATUS_STOPPED,
    VPN_CLIENT_STATUS_CONN_LOST,
} dap_chain_net_vpn_client_status_t;


dap_stream_ch_t* dap_chain_net_vpn_client_get_stream_ch(void);
dap_stream_worker_t* dap_chain_net_vpn_client_get_stream_worker(void);

int dap_chain_net_vpn_client_update(dap_chain_net_t *a_net, const char *a_wallet_name, const char *a_str_token, uint64_t a_value_datoshi);
int dap_chain_net_vpn_client_get_wallet_info(dap_chain_net_t *a_net, char **a_wallet_name, char **a_str_token, uint64_t *a_value_datoshi);

char *dap_chain_net_vpn_client_check_result(dap_chain_net_t *a_net, const char* a_hash_out_type);
int dap_chain_net_vpn_client_check(dap_chain_net_t *a_net, const char *a_ipv4_str, const char *a_ipv6_str, int a_port, size_t a_data_size_to_send, size_t a_data_size_to_recv, int a_timeout_test_ms);

int dap_chain_net_vpn_client_start(dap_chain_net_t *a_net, const char *a_ipv4_str, const char *a_ipv6_str, int a_port);
int dap_chain_net_vpn_client_stop(void);
dap_chain_net_vpn_client_status_t dap_chain_net_vpn_client_status(void);

int dap_chain_net_vpn_client_init(dap_config_t * g_config);
void dap_chain_net_vpn_client_deinit();


void dap_chain_net_vpn_client_pkt_out(dap_stream_ch_t* a_ch);
void dap_chain_net_vpn_client_pkt_in(dap_stream_ch_t* a_ch, dap_stream_ch_pkt_t* a_pkt);

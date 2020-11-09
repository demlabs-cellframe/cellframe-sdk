/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
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
#include "dap_chain_net_srv_vpn.h"

int dap_chain_net_vpn_client_tun_init(const char *a_ipv4_gw_str);
dap_events_socket_t* dap_chain_net_vpn_client_tun_get_esock(void);
int dap_chain_net_vpn_client_tun_create(const char *a_ipv4_addr_str, const char *a_ipv4_gw_str);
int dap_chain_net_vpn_client_tun_delete(void);
int dap_chain_net_vpn_client_tun_status(void);

int ch_sf_tun_addr_leased(dap_chain_net_srv_ch_vpn_t * a_sf, ch_vpn_pkt_t * a_pkt, size_t a_pkt_data_size);
void ch_sf_tun_client_send(dap_chain_net_srv_ch_vpn_t * ch_sf, void * pkt_data, size_t pkt_data_size);

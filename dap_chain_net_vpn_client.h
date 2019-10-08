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

int dap_chain_net_vpn_client_start(dap_chain_net_t *a_net, const char *a_ipv4_str, const char *a_ipv6_str, int a_port);
int dap_chain_net_vpn_client_stop(void);
int dap_chain_net_vpn_client_status(void);

int dap_chain_net_vpn_client_init(dap_config_t * g_config);
void dap_chain_net_vpn_client_deinit();

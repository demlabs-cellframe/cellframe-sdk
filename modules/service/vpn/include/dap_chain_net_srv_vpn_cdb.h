/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
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
#include "dap_http.h"
#include "dap_enc_http.h"
#include "dap_config.h"

#define DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX "srv.vpn"

extern dap_config_t * g_dap_config_cdb;

int dap_chain_net_srv_vpn_cdb_init(dap_http_t * a_http);
void dap_chain_net_srv_vpn_cdb_deinit();
void dap_chain_net_srv_vpn_cdb_auth_after(enc_http_delegate_t* a_delegate, const char * a_login, const char * a_pkey_b64 );

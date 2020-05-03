/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2020
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

int dap_chain_net_srv_vpn_cdb_auth_init (const char * a_domain, bool a_is_registration_open);
void dap_chain_net_srv_vpn_cdb_auth_deinit();

void dap_chain_net_srv_vpn_cdb_auth_add_proc(dap_http_t * a_http, const char * a_url);
void dap_chain_net_srv_vpn_cdb_auth_set_callback(dap_enc_http_callback_t a_callback_success);
int dap_chain_net_srv_vpn_cdb_auth_cli_cmd (    const char *a_user_str,int a_arg_index, int a_argc, char ** a_argv, char **a_str_reply);

int dap_chain_net_srv_vpn_cdb_auth_check(const char * a_login, const char * a_password);

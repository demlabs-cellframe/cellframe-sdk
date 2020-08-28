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

typedef struct dap_serial_key {
    struct {
        char serial[20];
        time_t activated; // if set, then serial is activated
        // if zero then time no expired
        union{
            time_t expired;
            int64_t license_length;// in sec
        };
        int32_t pkey_type;// dap_enc_key_type_t pkey type
        size_t ext_size;
    }DAP_ALIGN_PACKED header;
    uint8_t ext[];// pkey here
}DAP_ALIGN_PACKED dap_serial_key_t;

size_t dap_serial_key_len(dap_serial_key_t *a_serial_key);
dap_serial_key_t* dap_chain_net_srv_vpn_cdb_auth_get_serial_param(const char *a_serial_str, const char **a_group_out);

int dap_chain_net_srv_vpn_cdb_auth_init (const char * a_domain, const char * a_mode, bool a_is_registration_open);
void dap_chain_net_srv_vpn_cdb_auth_deinit();

void dap_chain_net_srv_vpn_cdb_auth_add_proc(dap_http_t * a_http, const char * a_url);
void dap_chain_net_srv_vpn_cdb_auth_set_callback(dap_enc_http_callback_t a_callback_success);
int dap_chain_net_srv_vpn_cdb_auth_cli_cmd_serial(const char *a_serial_str, int a_arg_index, int a_argc, char ** a_argv, char **a_str_reply);
int dap_chain_net_srv_vpn_cdb_auth_cli_cmd_user(const char *a_user_str, int a_arg_index, int a_argc, char ** a_argv, char **a_str_reply);

int dap_chain_net_srv_vpn_cdb_auth_check_login(const char * a_login, const char * a_password);
int dap_chain_net_srv_vpn_cdb_auth_activate_serial(const char * a_serial_raw, const char * a_serial, const char * a_sign, const char * a_pkey);
int dap_chain_net_srv_vpn_cdb_auth_check_serial(const char * a_serial, const char * a_pkey);

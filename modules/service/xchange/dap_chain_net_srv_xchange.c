/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
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


#include "dap_chain_common.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_xchange.h"

static int s_cli_srv_xchange(int argc, char ** argv, void *arg_func, char **str_reply);
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);



/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_xchange_init()
{
        dap_chain_node_cli_cmd_item_create ("srv_xchange", s_cli_srv_xchange, NULL, "eXchange service commands",
        "srv_xchange purchase <oreder hash>"
        "srv_xchange price create -net <net name> -token_sell <token ticker> -token_buy <token ticker> -rate <value> -wallet <name>\n"
            "\tCreate a new price with rate value = token_sell : token_buy\n"
        "srv_xchange price remove <number>\n"
             "\tRemove price with specified number\n"
        "srv_xchange price list\n"
             "\tList all active prices"

        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, s_callback_requested, s_callback_response_success,
                                                           s_callback_response_error, s_callback_receipt_next_success);
        dap_chain_net_srv_xchange_t* l_srv_xchange  = DAP_NEW_Z(dap_chain_net_srv_xchange_t);
        l_srv->_inhertor = l_srv_xchange;
        l_srv_xchange->enabled = false;
        return 0;
}

static int s_cli_srv_xchange(int argc, char ** argv, void *arg_func, char **str_reply)
{
    return 0;
}

static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

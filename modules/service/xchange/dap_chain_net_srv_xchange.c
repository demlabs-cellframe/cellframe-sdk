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
#include "dap_chain_net_srv_xchange.h"

static int s_cli_srv_xchange(int a_argc, char **a_argv, void *a_arg_func, char **a_str_reply);
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);

static dap_chain_net_srv_xchange_t *s_srv_xchange;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_xchange_init()
{
        dap_chain_node_cli_cmd_item_create ("srv_xchange", s_cli_srv_xchange, NULL, "eXchange service commands",
        "srv_xchange price create -net <net name> -token_sell <token ticker> -token_buy <token ticker> -rate <value> -wallet <name>\n"
            "\tCreate a new price with rate value = token_sell : token_buy\n"
        "srv_xchange price remove -token_pair <concatenated token ticker>\n"
             "\tRemove price with specified concatenated ticker\n"
        "srv_xchange price list\n"
             "\tList all active prices\n"
        "srv_xchange price update -token_pair <concatenated token ticker> {-rate <value> | -wallet <name>}\n"
             "\tUpdate price with specified concatenated ticker\n"
        "srv_xchange purchase <order hash> -net <net name>\n"
             "\tExchange tokens with specified order\n"
        "srv_xchange enable\n"
             "\tEnable eXchange service\n"
        "srv_xchange disable\n"
             "\tDisable eXchange service\n"
        );
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, s_callback_requested, s_callback_response_success,
                                                           s_callback_response_error, s_callback_receipt_next_success);
        s_srv_xchange  = DAP_NEW_Z(dap_chain_net_srv_xchange_t);
        l_srv->_inhertor = s_srv_xchange;
        s_srv_xchange->enabled = false;
        return 0;
}

void dap_chain_net_srv_xchange_deinit()
{
    dap_chain_net_srv_del(s_srv_xchange->parent);
    DAP_DELETE(s_srv_xchange);
}

static int s_cli_srv_xchange_price(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_CREATE, CMD_REMOVE, CMD_LIST, CMD_UPDATE
    };
    int l_cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "create", NULL)) {
        l_cmd_num = CMD_CREATE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "remove", NULL)) {
        l_cmd_num = CMD_REMOVE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "list", NULL)) {
        l_cmd_num = CMD_LIST;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "update", NULL)) {
        l_cmd_num = CMD_UPDATE;
    }
    switch (l_cmd_num) {
        case CMD_CREATE: {
            dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
            //TODO fill the price
            HASH_ADD_STR(s_srv_xchange->pricelist, token_pair, l_price);
        } break;
        case CMD_REMOVE:
        case CMD_UPDATE: {
            const char *l_token_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, ++a_arg_index, a_argc, "-token_pair", &l_token_str);
            if (!l_token_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -token_pair",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -1;
            }
            dap_chain_net_srv_xchange_price_t *l_price = NULL;
            HASH_FIND_STR(s_srv_xchange->pricelist, l_token_str, l_price);
            if (l_price) {
                if (l_cmd_num == CMD_REMOVE) {
                    HASH_DEL(s_srv_xchange->pricelist, l_price);
                } else {
                    //TODO update price
                }
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Token pair %s not found", l_token_str);
                return -1;
            }
        } break;
        case CMD_LIST: {
            dap_chain_net_srv_xchange_price_t *l_price = NULL, *l_tmp;
            HASH_ITER(hh, s_srv_xchange->pricelist, l_price, l_tmp) {
                *a_str_reply = dap_strdup_printf("%s\t%d\t%s\t%s\n", l_price->token_pair, l_price->rate,
                                                 l_price->net->pub.name, l_price->wallet->name);
            }
            if (!l_price) {
                 dap_chain_node_cli_set_reply_text(a_str_reply, "Pricelist is empty");
            }
        } break;
        default: {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Subcommand %s not recognized", a_argv[a_arg_index]);
            return -1;
        }
    }
    return 0;
}

static int s_cli_srv_xchange(int a_argc, char **a_argv, void *a_arg_func, char **a_str_reply)
{
    UNUSED(a_arg_func);
    enum {
        CMD_NONE, CMD_PRICE, CMD_PURCHASE, CMD_ENABLE, CMD_DISABLE
    };
    int arg_index = 1;
    int l_cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "price", NULL)) {
        l_cmd_num = CMD_PRICE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "purchase", NULL)) {
        l_cmd_num = CMD_PURCHASE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "enable", NULL)) {
        l_cmd_num = CMD_ENABLE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "disable", NULL)) {
        l_cmd_num = CMD_DISABLE;
    }
    switch (l_cmd_num) {
        case CMD_PRICE:
            return s_cli_srv_xchange_price(a_argc, a_argv, arg_index, a_str_reply);
        case CMD_PURCHASE: {
            const char *l_net_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, ++arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -net");
                return -1;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -1;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, a_argv[arg_index]);
            if (l_order) {
                //TODO purchase it
            }
        } break;
        case CMD_ENABLE: {
            s_srv_xchange->enabled = true;
        } break;
        case CMD_DISABLE: {
            s_srv_xchange->enabled = false;
        } break;
        default: {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[arg_index]);
            return -1;
        }
    }
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

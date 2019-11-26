/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "dap_common.h"
#include "dap_config.h"

#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_order.h"

#include "dap_http.h"
#include "dap_http_simple.h"
#include "http_status_code.h"

#include "dap_chain_net_srv_vpn_cdb_server_list.h"

#define LOG_TAG "dap_chain_net_srv_vpn_cdb_server_list"


static size_t s_cdb_net_count = 0;
static dap_chain_net_t ** s_cdb_net = NULL;
static void s_http_simple_proc(dap_http_simple_t *a_http_simple, void *a_arg);

int dap_chain_net_srv_vpn_cdb_server_list_init()
{
    char **l_cdb_networks;
    uint16_t l_cdb_networks_count = 0;
    log_it(L_NOTICE,"Initialized Server List Module");
    l_cdb_networks = dap_config_get_array_str( g_config, "cdb", "servers_list_networks", &l_cdb_networks_count );

    if ( l_cdb_networks_count ){
        s_cdb_net = DAP_NEW_Z_SIZE(dap_chain_net_t*, sizeof (dap_chain_net_t*)* l_cdb_networks_count );
        s_cdb_net_count = l_cdb_networks_count;
        for ( size_t i = 0; i < l_cdb_networks_count ; i++) {
            s_cdb_net[i] = dap_chain_net_by_name( l_cdb_networks[i] );
            if ( s_cdb_net[i] )
                log_it( L_INFO, "Added \"%s\" network for server list fetchs", l_cdb_networks[i]);
            else
                log_it( L_WARNING, "Can't find \"%s\" network to add to server list fetchs", l_cdb_networks[i]);
        }
    } else
        log_it( L_WARNING, "No chain networks listed in config");

    return 0;
}

void dap_chain_net_srv_vpn_cdb_server_list_deinit(void)
{
}


static void s_http_simple_proc(dap_http_simple_t *a_http_simple, void *a_arg)
{
    http_status_code_t * l_ret_code = (http_status_code_t*)a_arg;
    dap_string_t *l_reply_str = dap_string_new("[\n");


    log_it(L_DEBUG, "Have %zd chain networks for cdb lists", s_cdb_net_count );

    for ( size_t i = 0; i < s_cdb_net_count ; i++ ) {
        dap_chain_net_t * l_net = s_cdb_net[i];
        if ( l_net ) {
            dap_chain_net_srv_order_t * l_orders = NULL;
            size_t l_orders_count = 0;
            dap_chain_net_srv_price_unit_uid_t l_unit_uid = {{0}};
            dap_chain_net_srv_uid_t l_srv_uid = { .uint64 =DAP_CHAIN_NET_SRV_VPN_ID };
            dap_chain_net_srv_order_find_all_by( l_net, SERV_DIR_SELL,  l_srv_uid, SERV_CLASS_PERMANENT ,l_unit_uid ,
                                                 NULL,0,0, &l_orders, &l_orders_count );
            log_it(L_DEBUG, "Found %zd orders in \"%s\" network", l_orders_count, l_net->pub.name );

            for ( size_t j = 0; j < l_orders_count ; j++ ) {
                dap_chain_node_info_t * l_node_info = dap_chain_node_info_read( l_net, &l_orders[j].node_addr );
                if ( l_node_info ){
                    char l_node_ext_ipv4_str[INET_ADDRSTRLEN]={0};
                    char l_node_ext_ipv6_str[INET6_ADDRSTRLEN]={0};
                    if (l_node_info->hdr.ext_addr_v4.s_addr)
                        inet_ntop(AF_INET,&l_node_info->hdr.ext_addr_v4,l_node_ext_ipv4_str,sizeof(l_node_ext_ipv4_str));
                    if (  *((uint128_t *) l_node_info->hdr.ext_addr_v6.__in6_u.__u6_addr8 ) )
                        inet_ntop(AF_INET6,&l_node_info->hdr.ext_addr_v6,l_node_ext_ipv6_str,sizeof(l_node_ext_ipv6_str));
                    dap_string_append_printf( l_reply_str, "    {\n");

                    dap_string_append_printf( l_reply_str, "        \"Location\":\"NETHERLANDS\",\n");
                    dap_string_append_printf( l_reply_str, "        \"ChainNet\":\"%s\",\n",l_net->pub.name );
                    dap_string_append_printf( l_reply_str, "        \"Name\":\"%s.Cell-%lu.%zd\",\n",l_net->pub.name, l_node_info->hdr.cell_id.uint64, j);
                    if ( l_node_ext_ipv4_str[0] )
                        dap_string_append_printf( l_reply_str,"        \"Address\":\"%s\",\n",l_node_ext_ipv4_str);
                    if ( l_node_ext_ipv6_str[0] )
                        dap_string_append_printf( l_reply_str, "        \"Address6\":\"%s\",\n",l_node_ext_ipv6_str);
                    dap_string_append_printf( l_reply_str, "        \"Port\":%hu,\n",l_node_info->hdr.ext_port?l_node_info->hdr.ext_port:80);
                    dap_string_append_printf( l_reply_str, "        \"Ext\":\"%s\",\n",l_orders[j].ext);
                    dap_string_append_printf( l_reply_str, "        \"Price\":%lu,\n",l_orders[j].price);
                    dap_string_append_printf( l_reply_str, "        \"PriceUnits\":%u,\n",l_orders[j].price_unit.uint32);
                    dap_string_append_printf( l_reply_str, "        \"PriceToken\":\"%s\"\n",l_orders[j].price_ticker);
                    if ( j != l_orders_count-1)
                        dap_string_append_printf( l_reply_str, "    },\n");
                    else
                        dap_string_append_printf( l_reply_str, "    }\n");

                }else
                    log_it( L_WARNING, "Order %zd in \"%s\" network issued by node without ext_ipv4 field",j,l_net->pub.name);
            }
        }
    }
    dap_string_append_printf( l_reply_str, "]\n\n");
    dap_http_simple_reply( a_http_simple, l_reply_str->str, l_reply_str->len );
    dap_string_free(l_reply_str, true);
    //log_it(L_DEBUG,"Reply in buffer: %s", a_http_simple->reply_str );
    *l_ret_code = Http_Status_OK;

}

/**
 * @brief dap_chain_net_srv_vpn_cdb_server_list_add_proc
 * @param sh
 * @param url
 */
void dap_chain_net_srv_vpn_cdb_server_list_add_proc(dap_http_t *a_http, const char *a_url)
{
    dap_http_simple_proc_add(a_http,a_url,100000,s_http_simple_proc);
}

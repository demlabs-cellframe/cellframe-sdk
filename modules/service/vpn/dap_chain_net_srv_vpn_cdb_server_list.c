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
#include <stdlib.h>
#include <stdint.h>
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
#include "dap_chain_net_srv_geoip.h"

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


/**
 * @brief order_info_print
 * @param a_server_location for server name, NULL not used
 * @param a_node_number for server name, <0 not use
 */
static int order_info_print(dap_string_t *a_reply_str, dap_chain_net_t * a_net, dap_chain_net_srv_order_t * a_order, const char *a_server_name, int a_node_number)
{
    dap_chain_node_info_t * l_node_info = dap_chain_node_info_read(a_net, &a_order->node_addr);
    if(l_node_info) {
        char l_node_ext_ipv4_str[INET_ADDRSTRLEN] = { 0 };
        char l_node_ext_ipv6_str[INET6_ADDRSTRLEN] = { 0 };
        if(l_node_info->hdr.ext_addr_v4.s_addr)
            inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_ext_ipv4_str, sizeof(l_node_ext_ipv4_str));
        if(*((uint128_t *) l_node_info->hdr.ext_addr_v6.s6_addr))
            inet_ntop(AF_INET6, &l_node_info->hdr.ext_addr_v6, l_node_ext_ipv6_str, sizeof(l_node_ext_ipv6_str));

        uint8_t l_continent_num = 0;
        char *l_region = NULL;
        dap_chain_net_srv_order_get_continent_region(a_order, &l_continent_num, &l_region);
        const char *l_continent_str = dap_chain_net_srv_order_continent_to_str(l_continent_num);
        // ext_out in hex view
        char *l_ext_out = a_order->ext_size ? DAP_NEW_Z_SIZE(char, a_order->ext_size * 2 + 1) : NULL;
        dap_bin2hex(l_ext_out, a_order->ext, a_order->ext_size);

        dap_string_append_printf(a_reply_str, "    {\n");
        dap_string_append_printf(a_reply_str, "        \"Location\":\"%s\",\n", l_region ? l_region : "None"); //NETHERLANDS
                //l_continent_str ? l_continent_str : "None", l_region ? l_region : "None");


        dap_string_append_printf(a_reply_str, "        \"ChainNet\":\"%s\",\n", a_net->pub.name);
        //dap_string_append_printf(a_reply_str, "        \"Name\":\"%s.Cell-%lu.%zd\",\n", a_net->pub.name, l_node_info->hdr.cell_id.uint64, 0);
        if(a_server_name)
            dap_string_append_printf(a_reply_str, "        \"Name\":\"%s\",\n", a_server_name);
        else
            dap_string_append_printf(a_reply_str, "        \"Name\":\"%s.%s.%zd\",\n", l_continent_str ? l_continent_str : "", l_region ? l_region : "", a_node_number + 1);
            //dap_string_append_printf(a_reply_str, "        \"Name\":\"%s.%s.Cell-%lu.%zd\",\n", l_continent_str ? l_continent_str : "", l_region ? l_region : "", l_node_info->hdr.cell_id.uint64, a_node_number + 1);
        if(l_node_ext_ipv4_str[0])
            dap_string_append_printf(a_reply_str, "        \"Address\":\"%s\",\n", l_node_ext_ipv4_str);
        if(l_node_ext_ipv6_str[0])
            dap_string_append_printf(a_reply_str, "        \"Address6\":\"%s\",\n", l_node_ext_ipv6_str);
        dap_string_append_printf(a_reply_str, "        \"Port\":%hu,\n", l_node_info->hdr.ext_port ? l_node_info->hdr.ext_port : 80);

        //dap_string_append_printf(a_reply_str, "        \"Ext\":\"%s-%s\",\n", l_continent_str ? l_continent_str : "", l_region ? l_region : "");
        if(l_ext_out)
            dap_string_append_printf(a_reply_str, "        \"Ext\":\"0x%s\",\n", l_ext_out);
        else
            dap_string_append_printf(a_reply_str, "        \"Ext\":\"0x0\",\n");
        dap_string_append_printf(a_reply_str, "        \"Price\":%lu,\n", a_order->price);
        dap_string_append_printf(a_reply_str, "        \"PriceUnits\":%u,\n", a_order->price_unit.uint32);
        dap_string_append_printf(a_reply_str, "        \"PriceToken\":\"%s\"\n", a_order->price_ticker);
        dap_string_append_printf(a_reply_str, "    }");
        DAP_DELETE(l_region);
        DAP_DELETE(l_ext_out);


    } else{
        log_it(L_WARNING, "Order in \"%s\" network issued by node without ext_ipv4 field", a_net->pub.name);
        return -1;
    }
    return 0;
}


static void s_http_simple_proc(dap_http_simple_t *a_http_simple, void *a_arg)
{
    http_status_code_t * l_ret_code = (http_status_code_t*)a_arg;
    dap_string_t *l_reply_str = dap_string_new("[\n");


    char *l_client_ip = a_http_simple->http->client->s_ip;//"77.222.110.44"
    geoip_info_t *l_geoip_info = chain_net_geoip_get_ip_info(l_client_ip);

    log_it(L_DEBUG, "Have %zd chain networks for cdb lists", s_cdb_net_count );

    for ( size_t i = 0; i < s_cdb_net_count ; i++ ) {
        dap_chain_net_t * l_net = s_cdb_net[i];
        if ( l_net ) {
            dap_chain_net_srv_order_t * l_orders = NULL;
            size_t l_orders_num = 0;
            dap_chain_net_srv_price_unit_uid_t l_unit_uid = {{0}};
            dap_chain_net_srv_uid_t l_srv_uid = { .uint64 =DAP_CHAIN_NET_SRV_VPN_ID };
            dap_chain_net_srv_order_find_all_by( l_net, SERV_DIR_SELL,  l_srv_uid, l_unit_uid ,
                                                 NULL,0,0, &l_orders, &l_orders_num );
            log_it(L_DEBUG, "Found %zd orders in \"%s\" network", l_orders_num, l_net->pub.name );


            // find the shift for each node
            dap_chain_net_srv_order_t *l_orders_pos[l_orders_num];
            size_t l_orders_size = 0;
            for(size_t j = 0; j < l_orders_num; j++) {
                l_orders_pos[j] = (dap_chain_net_srv_order_t*) ((char*) l_orders + l_orders_size);
                l_orders_size += dap_chain_net_srv_order_get_size(l_orders_pos[j]);
            }


            // list of node numbers
            size_t l_continents_count = dap_chain_net_srv_order_continents_count(); //int *l_node_numbering = DAP_NEW_Z_SIZE(int, l_orders_num * sizeof(int));
            // list of the number of nodes in each continent
            int l_continents_numbers[l_continents_count]; //int *l_continents_numbers = DAP_NEW_Z_SIZE(int, l_continents_count * sizeof(int));
            int l_node_numbering[l_continents_count][l_orders_num];
            // init arrays
            for(size_t m1 = 0; m1 < l_continents_count; m1++) {
                l_continents_numbers[m1] = 0;
                for(size_t m2 = 0; m2 < l_orders_num; m2++)
                    l_node_numbering[m1][m2] = -1;
            }

            // node numbering
            size_t l_orders_used_num = 0;
            {
                // filling l_continents_numbers and l_node_numbering
                for(size_t j = 0; j < l_orders_num; j++) {
                    dap_chain_net_srv_order_t *l_order = l_orders_pos[j];
                    uint8_t l_continent_num;
                    if(!dap_chain_net_srv_order_get_continent_region(l_order, &l_continent_num, NULL))
                        continue;
                    l_node_numbering[l_continent_num][j] = l_continents_numbers[l_continent_num]++;
                    l_orders_used_num++;
                }
                // shuffle nodes for each continent
                for(size_t m1 = 0; m1 < l_continents_count; m1++) {
                    int l_cont_num = l_continents_numbers[m1];
                    if(l_cont_num <= 1)
                        continue;
                    // number of shuffles
                    int l_shuffle_num = rand() % (l_cont_num + 1);
                    for(size_t l_sh = 0; l_sh <= l_shuffle_num; l_sh++) {
                        size_t l_pos1 = 0;
                        size_t l_pos2 = 0;
                        while(l_pos1 == l_pos2) {
                            l_pos1 = rand() % l_cont_num;
                            l_pos2 = rand() % l_cont_num;
                        }
                        for(size_t m2 = 0; m2 < l_orders_num; m2++) {
                            if(l_node_numbering[m1][m2] == l_pos1)
                                l_node_numbering[m1][m2] = l_pos2;
                            else if(l_node_numbering[m1][m2] == l_pos2)
                                l_node_numbering[m1][m2] = l_pos1;
                        }
                    }
                }
            }

            int8_t l_client_continent = l_geoip_info ? dap_chain_net_srv_order_continent_to_num(l_geoip_info->continent) : 0;
            // random node on client's continent
			if (l_client_continent) {
				int l_count = 0;
				while (l_orders_num > 0) {
					size_t k = rand() % l_continents_numbers[l_client_continent];
					dap_chain_net_srv_order_t *l_order = l_orders_pos[k];
					const char *country_code = dap_chain_net_srv_order_get_country_code(l_order);
					if (country_code) {
						// only for other countries
						if (dap_strcmp(l_geoip_info->country_code, country_code)){
							if (!order_info_print(l_reply_str, l_net, l_order, "Auto", -1)) {
								dap_string_append_printf(l_reply_str, ",\n");
								break;
							}
						}
					}
					if (l_count > 20)
						break;
					l_count++;
				}

			}
			// random node for the whole world
			else {
				int l_count = 0;
				while(l_orders_num > 0) {
					// first random node
					size_t k = rand() % l_orders_num;
					dap_chain_net_srv_order_t *l_order = l_orders_pos[k];
					if(!order_info_print(l_reply_str, l_net, l_order, "Auto", -1)){
						dap_string_append_printf(l_reply_str, ",\n");
						break;
					}
					if (l_count>20)
						break;
					l_count++;
				}
            }
            // random nodes for continents
            int l_count = 0;
            for(size_t l_c = 0; l_c < l_continents_count; l_c++) {
                while(l_continents_numbers[l_c] > 0) {
                    // random node for continent
                    size_t k = rand() % l_continents_numbers[l_c];
                    size_t l_node_pos = -1;
                    for(size_t j2 = 0; j2 <= l_orders_num; j2++) {
                        if(k == l_node_numbering[l_c][j2]) {
                            l_node_pos = j2;
                            break;
                        }
                    }
                    if(l_node_pos == -1)
                        break;
                    dap_chain_net_srv_order_t *l_order = l_orders_pos[l_node_pos];
                    char *l_server_name = dap_strdup_printf("%s", dap_chain_net_srv_order_continent_to_str(l_c));
                    if(!order_info_print(l_reply_str, l_net, l_order, l_server_name, -1)) {
                        dap_string_append_printf(l_reply_str, ",\n");
                        DAP_DELETE(l_server_name);
                        break;
                    }
                    else
                        DAP_DELETE(l_server_name);
                    if(l_count > 20)
                        break;
                    l_count++;
                }
            }
            size_t l_num_print_nodes = 0;
            for(size_t l_c = 0; l_c < l_continents_count; l_c++) {
                // print all nodes for continent
                for(size_t l_n = 0; l_n < l_continents_numbers[l_c]; l_n++) {
                    // since the nodes are shuffled, look for the desired node index
                    for(size_t l_o = 0; l_o < l_orders_num; l_o++) {
                        if(l_node_numbering[l_c][l_o] != l_n)
                            continue;
                        dap_chain_net_srv_order_t *l_order = l_orders_pos[l_o];
                        if(!order_info_print(l_reply_str, l_net, l_order, NULL, l_n)) {
                            //if(l_o != l_orders_num - 1)
                            l_num_print_nodes++;
                            if(l_num_print_nodes < l_orders_used_num)
                                dap_string_append_printf(l_reply_str, ",\n");
                            else
                                dap_string_append_printf(l_reply_str, "\n");
                        }
                        break;
                    }
                }
            }
        }
    }
    DAP_DELETE(l_geoip_info);
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

/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.        https://demlabs.net
 * CellFrame            https://cellframe.net
 * Sources              https://gitlab.demlabs.net/cellframe
 * Cellframe CDB lib    https://gitlab.demlabs.net/dap.support/cellframe-node-cdb-lib
 * Copyrighted by Demlabs Limited, 2020
 * All rights reserved.
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

#include <json-c/json.h>
#include <json-c/json_object.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_timerfd.h"
#include "dap_list.h"
#include "uthash.h"

#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_srv_geoip.h"
#include "dap_chain_net_vpn_client.h"

#include "dap_http.h"
#include "dap_http_simple.h"
#include "http_status_code.h"

#include "dap_chain_net_srv_vpn_cdb.h"
#include "dap_chain_net_srv_vpn_cdb_server_list.h"

#define LOG_TAG "dap_chain_net_srv_vpn_cdb_server_list"

typedef struct dap_chain_net_srv_order_static
{
    uint8_t continent;
    const char *region;
    const char *net_str;
    const char *order_name;
    uint64_t node_addr_uint64;
    const char *ipv4_str;
    const char *ipv6_str;
    uint16_t port;
    const char *ext_str;
    size_t ext_size;
    const char *price_ticker;
    int price_unit;
    uint64_t price;
    json_object *obj;
} dap_chain_net_srv_order_static_t;


// Exceptions for countries - first element: target country, rest elements: countries for ordering "auto", last element "", and then another target country, etc.
static char *s_orders_exclusion[] = {"India", "Hong Kong", "",
                                     "China", "India", "Hong Kong", ""
                                    };
//static char *s_orders_exclusion[] = {"China", "India", "Hong Kong", "" };



static size_t s_cdb_net_count = 0;
static dap_chain_net_t ** s_cdb_net = NULL;
static bool *s_orders_use = NULL;
static bool s_debug_more = false;
static size_t s_orders_use_total;

static bool s_server_list_static_auto=true;
static bool s_server_list_static_no_shuffle= true;
static time_t s_server_list_cache_expire = 3600;

static dap_http_url_proc_t * s_url_proc = NULL;

static void s_http_simple_proc(dap_http_simple_t *a_http_simple, void *a_arg);

typedef struct dap_chain_net_item {
    dap_chain_node_addr_t node_addr;
    bool is_available;
    UT_hash_handle hh;
} dap_order_state_t;

dap_order_state_t *s_order_state = NULL;

static dap_order_state_t* find_order_state(dap_chain_node_addr_t a_node_addr)
{
    dap_order_state_t *l_order_state = NULL;

    HASH_FIND(hh, s_order_state, &a_node_addr, sizeof(dap_chain_node_addr_t), l_order_state);
    if(l_order_state){
        int gsdg=532;
    }
    return l_order_state;
}

int get_order_state(dap_chain_node_addr_t a_node_addr)
{
    dap_order_state_t *l_order_state = find_order_state(a_node_addr);
    if(!l_order_state)
        return -1;
    // if order off-line
    if(l_order_state->is_available)
        return 1;
    // if order on-line
    return 0;
}

static void save_order_state(dap_chain_node_addr_t a_node_addr, bool a_is_available)
{
    dap_order_state_t *l_order_state = find_order_state(a_node_addr);
    // node_addr already in the hash?
    if(!l_order_state) {
        l_order_state = DAP_NEW_Z(dap_order_state_t);
        l_order_state->node_addr.uint64 = a_node_addr.uint64;
        HASH_ADD(hh, s_order_state, node_addr, sizeof(dap_chain_node_addr_t), l_order_state);
    }
    l_order_state->is_available = a_is_available;
}

static void delete_order_state(dap_order_state_t *l_order_state)
{
    HASH_DELETE(hh, s_order_state, l_order_state);
    DAP_DELETE(l_order_state);
}

static bool callback_check_orders(void *a_arg)
{
    log_it(L_DEBUG, "callback_check_orders");
    static int l_current_run = 0;
    int l_multiplicity = DAP_POINTER_TO_INT(a_arg);
    // default timeout 10ms
    int l_timeout_test_ms = dap_config_get_item_int32_default( g_config,"cdb", "servers_list_check_timeout", 20) * 1000;// read settings
    size_t l_orders_num_total = 0;
    // read all orders
    for(size_t i = 0; i < s_cdb_net_count; i++) {
        dap_chain_net_t * l_net = s_cdb_net[i];
        if(l_net) {
            dap_chain_net_srv_order_t * l_orders = NULL;
            size_t l_orders_num = 0;
            dap_chain_net_srv_price_unit_uid_t l_unit_uid = { { 0 } };
            dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
            dap_chain_net_srv_order_find_all_by(l_net, SERV_DIR_SELL, l_srv_uid, l_unit_uid,
            NULL, 0, 0, &l_orders, &l_orders_num);
            log_it(L_DEBUG, "Found %zd orders in \"%s\" network", l_orders_num, l_net->pub.name);
            //l_orders_num_total += l_orders_num;

            // find the shift for each node
            dap_chain_net_srv_order_t *l_orders_pos[l_orders_num];
            size_t l_orders_size = 0;
            for(size_t j = 0; j < l_orders_num; j++) {
                l_orders_pos[j] = (dap_chain_net_srv_order_t*) ((char*) l_orders + l_orders_size);
                l_orders_size += dap_chain_net_srv_order_get_size(l_orders_pos[j]);
            }

            //check active orders
            for(size_t j = 0; j < l_orders_num; j++) {

                dap_chain_net_srv_order_t *l_orders = l_orders_pos[j];
                dap_order_state_t *l_order_state = find_order_state(l_orders->node_addr);
                // filter of unavailable orders
                if(l_order_state){
                    // run check for unavailable orders only every l_multiplicity time
                    if(!l_order_state->is_available && (l_current_run % (l_multiplicity ? l_multiplicity : 1)))
                        continue;
                }
                // get ip from node addr
                dap_chain_node_info_t *l_node_info = dap_chain_node_info_read(l_net, &(l_orders->node_addr));
                if(!l_node_info){
                    log_it(L_NOTICE,"Node addr "NODE_ADDR_FP_STR" not found in base", &l_orders->node_addr);
                    continue;
                }
                char l_node_ext_ipv4_str[INET_ADDRSTRLEN] = { 0 };
                //char l_node_ext_ipv4_str[INET_ADDRSTRLEN] = "192.168.100.93";
                char l_node_ext_ipv6_str[INET6_ADDRSTRLEN] = { 0 };
                if(l_node_info->hdr.ext_addr_v4.s_addr)
                    inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_ext_ipv4_str,
                            sizeof(l_node_ext_ipv4_str));
                if(*((uint128_t *) l_node_info->hdr.ext_addr_v6.s6_addr))
                    inet_ntop(AF_INET6, &l_node_info->hdr.ext_addr_v6, l_node_ext_ipv6_str,
                            sizeof(l_node_ext_ipv6_str));
                size_t l_data_size_to_send = 10240*2;
                size_t l_data_size_to_recv = 0;
                // check send speed
                int l_res1 = dap_chain_net_vpn_client_check(l_net, l_node_ext_ipv4_str, l_node_ext_ipv6_str, l_node_info->hdr.ext_port,
                        l_data_size_to_send, l_data_size_to_recv, l_timeout_test_ms);
                int l_res2 = -1;
                if(l_res1 == 0) {
                    size_t l_data_size_to_send = 0;
                    size_t l_data_size_to_recv = 10240*2;
                    // check recv speed
                    l_res2 = dap_chain_net_vpn_client_check(l_net, l_node_ext_ipv4_str, l_node_ext_ipv6_str, l_node_info->hdr.ext_port, l_data_size_to_send, l_data_size_to_recv, l_timeout_test_ms);
                    //s_orders_use[i] = false;
                }
                // save availability of order
                save_order_state(l_orders->node_addr, !l_res1 || !l_res2);
            }
            if (l_orders)
                DAP_DELETE(l_orders);
        }
    }
    l_current_run++;
    // repeat callback
    if(l_multiplicity)
        return true;
    // no repeat callback
    return false;
}

int dap_chain_net_srv_vpn_cdb_server_list_init()
{
    char **l_cdb_networks;
    uint16_t l_cdb_networks_count = 0;
    log_it(L_NOTICE,"Initialized Server List Module");
    l_cdb_networks = dap_config_get_array_str( g_dap_config_cdb, "cdb", "servers_list_networks", &l_cdb_networks_count );
    s_debug_more = dap_config_get_item_bool_default( g_dap_config_cdb, "cdb", "debug_more", s_debug_more );
    s_server_list_cache_expire = dap_config_get_item_int32_default(g_dap_config_cdb, "cdb","cache_expire", s_server_list_cache_expire);
    s_server_list_static_auto = dap_config_get_item_bool_default( g_dap_config_cdb, "cdb", "server_list_static_auto", s_server_list_static_auto );
    s_server_list_static_no_shuffle = dap_config_get_item_bool_default( g_dap_config_cdb,"cdb", "server_list_static_no_shuffle", s_server_list_static_no_shuffle);// read settings
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
        dap_string_append_printf(a_reply_str, "        \"PriceToken\":\"%s\",\n", a_order->price_ticker);
        // order state
        {
            dap_order_state_t *l_order_state = find_order_state(a_order->node_addr);
            // if order is not tested
            if(!l_order_state)
                dap_string_append_printf(a_reply_str, "        \"State\":\"unknown\"\n");
            // if order off-line
            else if(l_order_state->is_available)
                dap_string_append_printf(a_reply_str, "        \"State\":\"available\"\n");
            // if order on-line
            else
                dap_string_append_printf(a_reply_str, "        \"State\":\"not available\"\n");
        }
        dap_string_append_printf(a_reply_str, "    }");
        DAP_DELETE(l_region);
        DAP_DELETE(l_ext_out);


    } else{
        log_it(L_WARNING, "Order in \"%s\" network issued by node without ext_ipv4 field", a_net->pub.name);
        return -1;
    }
    return 0;
}

static void s_http_simple_proc_default(dap_http_simple_t *a_http_simple, void *a_arg)
{
    http_status_code_t * l_ret_code = (http_status_code_t*)a_arg;
    dap_string_t *l_reply_str = dap_string_new("[\n");

    char *l_client_ip = a_http_simple->http_client->esocket->hostaddr;//"64.225.61.216"
    //char *l_client_ip = "122.75.117.129";// china
    geoip_info_t *l_geoip_info = chain_net_geoip_get_ip_info(l_client_ip);

    if(s_debug_more)
        log_it(L_DEBUG, "Have %zd chain networks for cdb lists", s_cdb_net_count );

    for ( int i = 0; i < s_cdb_net_count ; i++ ) {
        dap_chain_net_t * l_net = s_cdb_net[i];
        if ( l_net ) {
            dap_chain_net_srv_order_t * l_orders = NULL;
            size_t l_orders_num = 0;
            dap_chain_net_srv_price_unit_uid_t l_unit_uid = {{0}};
            dap_chain_net_srv_uid_t l_srv_uid = { .uint64 =DAP_CHAIN_NET_SRV_VPN_ID };
            dap_chain_net_srv_order_find_all_by( l_net, SERV_DIR_SELL,  l_srv_uid, l_unit_uid ,
                                                 NULL,0,0, &l_orders, &l_orders_num );
            if(s_debug_more)
                log_it(L_DEBUG, "Found %zd orders in \"%s\" network", l_orders_num, l_net->pub.name );


            // find the shift for each node
            dap_chain_net_srv_order_t *l_orders_pos[l_orders_num];
            int l_orders_available[l_orders_num];
            size_t l_orders_size = 0;
            for(int j = 0; j < l_orders_num; j++) {
                l_orders_pos[j] = (dap_chain_net_srv_order_t*) ((char*) l_orders + l_orders_size);
                l_orders_size += dap_chain_net_srv_order_get_size(l_orders_pos[j]);
            }


            // list of node numbers
            int l_continents_count = dap_chain_net_srv_order_continents_count(); //int *l_node_numbering = DAP_NEW_Z_SIZE(int, l_orders_num * sizeof(int));
            // list of the number of nodes in each continent
            int l_continents_numbers[l_continents_count]; //int *l_continents_numbers = DAP_NEW_Z_SIZE(int, l_continents_count * sizeof(int));
            int l_node_numbering[l_continents_count][l_orders_num];
            // init arrays
            for(int m1 = 0; m1 < l_continents_count; m1++) {
                l_continents_numbers[m1] = 0;
                for(int m2 = 0; m2 < l_orders_num; m2++)
                    l_node_numbering[m1][m2] = -1;
            }

            // node numbering
            int l_orders_used_num = 0;
            {
                // filling l_continents_numbers and l_node_numbering
                for(int j = 0; j < l_orders_num; j++) {
                    dap_chain_net_srv_order_t *l_order = l_orders_pos[j];
                    // get order availability
                    dap_order_state_t *l_order_state = find_order_state(l_order->node_addr);
                    if(l_order_state){
                        // if order on-line or off-line
                        l_orders_available[j] = l_order_state->is_available;
                    }
                    else
                        l_orders_available[j] = -1;
                    if(l_orders_available[j] == 0)
                        continue;
                    uint8_t l_continent_num;
                    if(!dap_chain_net_srv_order_get_continent_region(l_order, &l_continent_num, NULL))
                        continue;
                    l_node_numbering[l_continent_num][j] = l_continents_numbers[l_continent_num]++;
                    l_orders_used_num++;
                }
                // shuffle nodes for each continent
                for(int m1 = 0; m1 < l_continents_count; m1++) {
                    int l_cont_num = l_continents_numbers[m1];
                    if(l_cont_num <= 1)
                        continue;
                    // number of shuffles
                    int l_shuffle_num = rand() % (l_cont_num + 1);
                    for(int l_sh = 0; l_sh <= l_shuffle_num; l_sh++) {
                        int l_pos1 = 0;
                        int l_pos2 = 0;
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
            bool l_is_auto_order = false;
            // rule for countries - exclusion
            if(l_geoip_info) {
                for(size_t l_reg = 0; l_reg < sizeof(s_orders_exclusion) / sizeof(char*); l_reg++) {
                    if(!dap_strcmp(s_orders_exclusion[l_reg], l_geoip_info->country_name)) {
                        l_reg++;
                        dap_list_t *l_list_reg = NULL;
                        for(size_t j = 0; j < l_orders_num; j++) {
                            dap_chain_net_srv_order_t *l_order = l_orders_pos[j];
                            size_t l_region_size = l_order->ext_size - sizeof(uint8_t) - 1;
                            char *l_region = (char*) l_order->ext + 1 + sizeof(uint8_t);
                            for(size_t l_reg2 = l_reg; l_reg2 < sizeof(s_orders_exclusion) / sizeof(char*); l_reg2++) {
                                if(!dap_strlen(s_orders_exclusion[l_reg2])){
                                    if(j == l_orders_num - 1)
                                        l_reg = l_reg2;
                                    break;
                                }
                                if(l_region_size > 0 &&
                                        !dap_strncmp(s_orders_exclusion[l_reg2], l_region, l_region_size))
                                    l_list_reg = dap_list_prepend(l_list_reg, l_order);
                            }

                        }
                        size_t l_num_reg = dap_list_length(l_list_reg);
                        // random node from selected counties
                        if(l_num_reg > 0) {
                            size_t k = rand() % l_num_reg;
                            dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t*) dap_list_nth_data(
                                    l_list_reg,
                                    k);
                            if(!order_info_print(l_reply_str, l_net, l_order, "Auto", -1)) {
                                dap_string_append_printf(l_reply_str, ",\n");
                                l_is_auto_order = true;
                            }
                        }
                        break;
                    }
                    else {
                        for(; l_reg < sizeof(s_orders_exclusion) / sizeof(char*); l_reg++) {
                            if(!dap_strlen(s_orders_exclusion[l_reg]))
                                break;
                        }
                    }
                }
            }
            // random node on client's continent
            if(!l_is_auto_order && l_client_continent > 0 && l_continents_numbers[l_client_continent] > 1) {
                int l_count = 0;
                while(l_orders_num > 0) {
                    size_t k = rand() % l_continents_numbers[l_client_continent];
                    int l_node_pos = -1;
                    for(size_t j2 = 0; j2 <= l_orders_num; j2++) {
                        if(k == l_node_numbering[l_client_continent][j2]) {
                            l_node_pos = j2;
                            break;
                        }
                    }
                    if(l_node_pos == -1) {
                        // random node for the whole world
                        l_node_pos = rand() % l_orders_num;
                    }
                    dap_chain_net_srv_order_t *l_order = l_orders_pos[l_node_pos];
                    const char *country_code = dap_chain_net_srv_order_get_country_code(l_order);
                    if(country_code) {
                        // only for other countries
                        if(dap_strcmp(l_geoip_info->country_code, country_code)) {
                            if(!order_info_print(l_reply_str, l_net, l_order, "Auto", -1)) {
                                dap_string_append_printf(l_reply_str, ",\n");
                                break;
                            }
                        }
                    }
                    if(l_count > 200)
                        break;
                    l_count++;
                }

            }
            // random node for the whole world
			else if(!l_is_auto_order) {
				int l_count = 0;
				while(l_orders_num > 0) {
					// first random node
					size_t k = rand() % l_orders_num;
                    if(l_orders_available[k] != 0) {
                        dap_chain_net_srv_order_t *l_order = l_orders_pos[k];
                        if(!order_info_print(l_reply_str, l_net, l_order, "Auto", -1)) {
                            dap_string_append_printf(l_reply_str, ",\n");
                            break;
                        }
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
                    int l_node_pos = -1;
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

            for(size_t l_c = 0; l_c < l_continents_count; l_c++) {
                // print all nodes for continent
                for(size_t l_n = 0; l_n < l_continents_numbers[l_c]; l_n++) {
                    // since the nodes are shuffled, look for the desired node index
                    for(size_t l_o = 0; l_o < l_orders_num; l_o++) {
                        if(l_node_numbering[l_c][l_o] != l_n)
                            continue;
                        dap_chain_net_srv_order_t *l_order = l_orders_pos[l_o];
                        if(!order_info_print(l_reply_str, l_net, l_order, NULL, l_n)) {
                            dap_string_append_printf(l_reply_str, ",\n");
                        }
                        break;
                    }
                }
            }
        }else
            log_it(L_ERROR,"No network in list!");
    }
    DAP_DELETE(l_geoip_info);
    //delete trailing comma if exists
    if(l_reply_str->str[l_reply_str->len - 2] == ','){
        dap_string_truncate(l_reply_str, l_reply_str->len - 2);
        dap_string_append_printf(l_reply_str, "\n");
    }

    dap_string_append_printf( l_reply_str, "]\n\n");
    dap_http_simple_reply( a_http_simple, l_reply_str->str, l_reply_str->len );
    strcpy( a_http_simple->reply_mime, "application/json" );
    dap_string_free(l_reply_str, true);
    if(s_debug_more)
        log_it(L_DEBUG,"Reply in buffer: %s", a_http_simple->reply_str );
    *l_ret_code = Http_Status_OK;
    dap_http_simple_make_cache_from_reply(a_http_simple,time(NULL)+s_server_list_cache_expire);
}

static void s_http_simple_proc(dap_http_simple_t *a_http_simple, void *a_arg)
{
    http_status_code_t * l_ret_code = (http_status_code_t*) a_arg;
    dap_string_t *l_reply_str = dap_string_new(NULL);



    char *l_client_ip = a_http_simple->http_client->esocket->hostaddr; //"64.225.61.216"
    //char *l_client_ip = "122.75.117.129";// china
    geoip_info_t *l_geoip_info = chain_net_geoip_get_ip_info(l_client_ip);

    // how many static nodelist processing
    int l_net_processing_num = 0;
    log_it(L_DEBUG, "Have %zd chain networks for cdb lists", s_cdb_net_count);
    for(size_t i = 0; i < s_cdb_net_count; i++) {
        dap_chain_net_t * l_net = s_cdb_net[i];
        if(l_net) {
            //dap_chain_net_srv_order_t * l_orders = NULL;
            //size_t l_orders_num = 0;
            //dap_chain_net_srv_price_unit_uid_t l_unit_uid = { { 0 } };
            //dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
            //dap_chain_net_srv_order_find_all_by(l_net, SERV_DIR_SELL, l_srv_uid, l_unit_uid,
            //NULL, 0, 0, &l_orders, &l_orders_num);
            //log_it(L_DEBUG, "Found %zd orders in \"%s\" network", l_orders_num, l_net->pub.name);

            // get static nodelist
            size_t l_static_nodelist_size = 0;
            uint8_t *l_static_nodelist = dap_chain_global_db_gr_get(dap_strdup(l_net->pub.name), &l_static_nodelist_size, "cdb.static_nodelist");
            if (!l_static_nodelist && s_server_list_static_auto)
                dap_chain_net_srv_vpn_cdb_server_list_static_create(l_net);

            // try to fetch again
            l_static_nodelist = dap_chain_global_db_gr_get(dap_strdup(l_net->pub.name), &l_static_nodelist_size, "cdb.static_nodelist");

            if(!l_static_nodelist)
                continue;

            // use only static part
            if(s_server_list_static_no_shuffle){
                // parse static nodelist in json format
                struct json_object *l_jobj_arr = json_tokener_parse((char*) l_static_nodelist);
                // added static part
                const char* json_str = json_object_to_json_string(l_jobj_arr);
                dap_string_append(l_reply_str, json_str);

                if(l_static_nodelist)
                    l_net_processing_num++;
                DAP_DELETE(l_static_nodelist);
                json_object_put(l_jobj_arr);
                continue;
            }


            // orders list
            size_t l_static_orders_num = 0;
            dap_chain_net_srv_order_static_t * l_static_orders = NULL;

            struct json_object *l_jobj_arr_new = json_object_new_array();
            // parse static nodelist in json format
            struct json_object *l_jobj_arr = json_tokener_parse((char*)l_static_nodelist);
            if(json_object_is_type(l_jobj_arr, json_type_array)) {
                // form l_static_orders
                l_static_orders_num = json_object_array_length(l_jobj_arr);
                l_static_orders = DAP_NEW_Z_SIZE(dap_chain_net_srv_order_static_t, sizeof(dap_chain_net_srv_order_static_t) * l_static_orders_num);
                for(int i = 0; i < (int) l_static_orders_num; i++) {
                    json_object *l_one_news = json_object_array_get_idx(l_jobj_arr, i);
                    // parse json_object to dap_chain_net_srv_order_static_t
                    if(json_object_is_type(l_one_news, json_type_object)) {
                        const char *str;
                        struct json_object *l_obj;
                        dap_chain_net_srv_order_static_t *l_order = l_static_orders + i;
                        l_obj = json_object_object_get(l_one_news, "Location");
                        if(l_obj)
                            l_order->region = json_object_get_string(l_obj);
                        l_obj = json_object_object_get(l_one_news, "ChainNet");
                        if(l_obj)
                            l_order->net_str = json_object_get_string(l_obj);
                        l_obj = json_object_object_get(l_one_news, "Name");
                        if(l_obj){
                            l_order->order_name = json_object_get_string(l_obj);
                            // parse order_name to get continent (for example "Europe.Germany.2" -> "Europe")
                            const char *l_dot = dap_strstr_len(l_order->order_name, -1, ".");
                            if(l_dot){
                                char *l_continent_str = dap_strdup(l_order->order_name);
                                l_continent_str[l_dot-l_order->order_name]= '\0';
                                l_order->continent = dap_chain_net_srv_order_continent_to_num(l_continent_str);
                            }
                        }
                        l_obj = json_object_object_get(l_one_news, "Address");
                        if(l_obj)
                            l_order->ipv4_str = json_object_get_string(l_obj);
                        l_obj = json_object_object_get(l_one_news, "Address");
                        if(l_obj)
                            l_order->ipv6_str = json_object_get_string(l_obj);
                        l_obj = json_object_object_get(l_one_news, "Port");
                        if(l_obj)
                            l_order->port = json_object_get_int(l_obj);
                        l_obj = json_object_object_get(l_one_news, "Ext");
                        if(l_obj){
                            l_order->ext_str = json_object_get_string(l_obj);
                            l_order->ext_size = dap_strlen(l_order->ext_str);
                        }
                        l_obj = json_object_object_get(l_one_news, "Price");
                        if(l_obj)
                            l_order->price = json_object_get_int64(l_obj);
                        l_obj = json_object_object_get(l_one_news, "PriceUnits");
                        if(l_obj)
                            l_order->price_unit = json_object_get_int(l_obj);
                        l_obj = json_object_object_get(l_one_news, "PriceToken");
                        if(l_obj)
                            l_order->price_ticker = json_object_get_string(l_obj);
                        l_obj = json_object_object_get(l_one_news, "NodeAddress");
                        if(l_obj)
                            l_order->node_addr_uint64 = (uint64_t)json_object_get_int64(l_obj);
                        l_order->obj = l_one_news;
                    }
                }

                // added dynamic part
                {
                    // list of node numbers
                    size_t l_continents_count = dap_chain_net_srv_order_continents_count();
                    // list of the number of nodes in each continent
                    int l_continents_numbers[l_continents_count]; //int *l_continents_numbers = DAP_NEW_Z_SIZE(int, l_continents_count * sizeof(int));
                    int l_node_numbering[l_continents_count][l_static_orders_num];
                    // init arrays
                    for(size_t m1 = 0; m1 < l_continents_count; m1++) {
                        l_continents_numbers[m1] = 0;
                        for(size_t m2 = 0; m2 < l_static_orders_num; m2++)
                            l_node_numbering[m1][m2] = -1;
                    }

                    int l_orders_available[l_static_orders_num];
                    // filling l_continents_numbers and l_node_numbering
                    for(size_t j = 0; j < l_static_orders_num; j++) {
                        dap_chain_net_srv_order_static_t *l_order_static = l_static_orders + j;
                        // get order availability
                        dap_chain_node_addr_t l_node_addr;
                        l_node_addr.uint64 = l_order_static->node_addr_uint64;
                        dap_order_state_t *l_order_state = find_order_state(l_node_addr);
                        if(l_order_state) {
                            // if order on-line or off-line
                            l_orders_available[j] = l_order_state->is_available;
                        }
                        else
                            l_orders_available[j] = -1;
                        if(l_orders_available[j] == 0)
                            continue;
                        uint8_t l_continent_num = l_order_static->continent;
                        if(!l_continent_num)//dap_chain_net_srv_order_static_get_continent_region(l_order_static, &l_continent_num, NULL))
                            continue;
                        l_node_numbering[l_continent_num][j] = l_continents_numbers[l_continent_num]++;
                    }

                    // get client continent by client ip
                    char *l_client_ip = a_http_simple->http_client->esocket->hostaddr;//"64.225.61.216"
                    //char *l_client_ip = "122.75.117.129";// china
                    geoip_info_t *l_geoip_info = chain_net_geoip_get_ip_info(l_client_ip);
                    int8_t l_client_continent = l_geoip_info ? dap_chain_net_srv_order_continent_to_num(l_geoip_info->continent) : 0;

                    bool l_is_auto_order = false;
                    // rule for countries - exclusion
                    if(l_geoip_info) {
                        for(size_t l_reg = 0; l_reg < sizeof(s_orders_exclusion) / sizeof(char*); l_reg++) {
                            if(!dap_strcmp(s_orders_exclusion[l_reg], l_geoip_info->country_name)) {
                                l_reg++;
                                dap_list_t *l_list_reg = NULL;
                                for(size_t j = 0; j < l_static_orders_num; j++) {
                                    dap_chain_net_srv_order_static_t *l_order_static = l_static_orders + j;
                                    const char *l_region = l_order_static->region;
                                    size_t l_region_size = dap_strlen(l_order_static->region);
                                    for(size_t l_reg2 = l_reg; l_reg2 < sizeof(s_orders_exclusion) / sizeof(char*);
                                            l_reg2++) {
                                        if(!dap_strlen(s_orders_exclusion[l_reg2])) {
                                            if(j == l_static_orders_num - 1)
                                                l_reg = l_reg2;
                                            break;
                                        }
                                        if(l_region_size > 0 &&
                                                !dap_strncmp(s_orders_exclusion[l_reg2], l_region, l_region_size))
                                            l_list_reg = dap_list_prepend(l_list_reg, l_order_static);
                                    }

                                }
                                size_t l_num_reg = dap_list_length(l_list_reg);
                                // random node from selected counties
                                if(l_num_reg > 0) {
                                    size_t k = rand() % l_num_reg;
                                    dap_chain_net_srv_order_static_t *l_order_static =
                                            (dap_chain_net_srv_order_static_t*) dap_list_nth_data(l_list_reg, k);
                                    // create deep copy of order
                                    const char* json_one_str = json_object_to_json_string(l_order_static->obj);
                                    struct json_object *l_jobj = json_tokener_parse(json_one_str);
                                    json_object_object_add(l_jobj, "Name", json_object_new_string("Auto"));
                                    // added new json object for continent
                                    json_object_array_add(l_jobj_arr_new, l_jobj);
                                    l_is_auto_order = true;
                                }
                                break;
                            }
                            else {
                                for(; l_reg < sizeof(s_orders_exclusion) / sizeof(char*); l_reg++) {
                                    if(!dap_strlen(s_orders_exclusion[l_reg]))
                                        break;
                                }
                            }
                        }
                    }

                    // node 'auto' -> random node on client's continent
                    if(!l_is_auto_order && l_client_continent > 0 && l_continents_numbers[l_client_continent] > 1) {
                        int l_count = 0;
                        while(l_static_orders_num > 0) {
                            size_t k = rand() % l_continents_numbers[l_client_continent];
                            int l_node_pos = -1;
                            for(size_t j2 = 0; j2 <= l_static_orders_num; j2++) {
                                if(k == l_node_numbering[l_client_continent][j2]) {
                                    l_node_pos = j2;
                                    break;
                                }
                            }
                            if(l_node_pos == -1) {
                                // random node for the whole world
                                l_node_pos = rand() % l_static_orders_num;
                            }
                            dap_chain_net_srv_order_static_t *l_order_static = l_static_orders + l_node_pos;
                            const char *country_code_str = dap_chain_net_srv_order_continent_to_str(l_order_static->continent);
                            if(country_code_str) {
                                // only for other countries
                                if(dap_strcmp(l_geoip_info->country_code, country_code_str)) {

                                    // create deep copy of order
                                    const char* json_one_str = json_object_to_json_string(l_order_static->obj);
                                    struct json_object *l_jobj = json_tokener_parse(json_one_str);
                                    json_object_object_add(l_jobj, "Name", json_object_new_string("Auto"));
                                    // added new json object for continent
                                    json_object_array_add(l_jobj_arr_new, l_jobj);
                                    break;
                                }
                            }
                            if(l_count > 200)
                                break;
                            l_count++;
                        }

                    }
                    // random node for the whole world
                    else if(!l_is_auto_order) {
                        int l_count = 0;
                        while(l_static_orders_num > 0) {
                            // first random node
                            size_t k = rand() % l_static_orders_num;
                            if(l_orders_available[k] != 0) {
                                dap_chain_net_srv_order_static_t *l_order_static = l_static_orders + k;
                                // create deep copy of order
                                const char* json_one_str = json_object_to_json_string(l_order_static->obj);
                                struct json_object *l_jobj = json_tokener_parse(json_one_str);
                                json_object_object_add(l_jobj, "Name", json_object_new_string("Auto"));
                                // added new json object for continent
                                json_object_array_add(l_jobj_arr_new, l_jobj);
                                break;
                            }
                            if(l_count > 20)
                                break;
                            l_count++;
                        }
                    }

                    // random nodes for continents
                    for(size_t l_c = 0; l_c < l_continents_count; l_c++) {
                        while(l_continents_numbers[l_c] > 0) {
                            // random node for continent
                            size_t k = rand() % l_continents_numbers[l_c];
                            int l_node_pos = -1;
                            for(size_t j2 = 0; j2 <= l_static_orders_num; j2++) {
                                if(k == l_node_numbering[l_c][j2]) {
                                    l_node_pos = j2;
                                    break;
                                }
                            }
                            if(l_node_pos == -1)
                                break;
                            //dap_chain_net_srv_order_t *l_order = l_static_orders[l_node_pos];
                            dap_chain_net_srv_order_static_t *l_order = l_static_orders + l_node_pos;
                            char *l_server_name = dap_strdup_printf("%s", dap_chain_net_srv_order_continent_to_str(l_c));
                            // create deep copy of order
                            const char* json_one_str = json_object_to_json_string(l_order->obj);
                            struct json_object *l_jobj = json_tokener_parse(json_one_str);
                            json_object_object_add(l_jobj, "Name", json_object_new_string(l_server_name));
                            // added new json object for continent
                            json_object_array_add(l_jobj_arr_new, l_jobj);
                            DAP_DELETE(l_server_name);
                            break;
                        }
                    }
                }

                // copy static part to common list
                for(int i = 0; i < (int) json_object_array_length(l_jobj_arr); i++) {
                    json_object *l_one_news = json_object_array_get_idx(l_jobj_arr, i);
                    if(!l_one_news)
                        continue;
                    json_object_array_add(l_jobj_arr_new, l_one_news);
                }

                //added order state to all orders
                {
                    size_t l_all_orders_num = json_object_array_length(l_jobj_arr_new);
                    for(int i = 0; i < (int) l_all_orders_num; i++) {
                        json_object *l_one_news = json_object_array_get_idx(l_jobj_arr_new, i);
                        json_object *l_obj = json_object_object_get(l_one_news, "NodeAddress");
                        if(!l_obj)
                            continue;
                        uint64_t l_node_addr_uint64 = (uint64_t) json_object_get_int64(l_obj);
                        // get order availability
                        dap_chain_node_addr_t l_node_addr;
                        l_node_addr.uint64 = l_node_addr_uint64;
                        dap_order_state_t *l_order_state = find_order_state(l_node_addr);
                        if(l_order_state) {
                            // if order on-line or off-line
                            if(l_order_state->is_available)
                                json_object_object_add(l_one_news, "State", json_object_new_string("available"));
                            // if order on-line
                            else
                                json_object_object_add(l_one_news, "State", json_object_new_string("not available"));
                        }
                        else
                            json_object_object_add(l_one_news, "State", json_object_new_string("unknown"));
                    }
                }
            }

            // added static+dinamic part
            const char* json_str = json_object_to_json_string(l_jobj_arr_new);
            dap_string_append(l_reply_str, json_str);

            if(l_static_nodelist)
                l_net_processing_num++;
            DAP_DELETE(l_static_nodelist);
            json_object_put(l_jobj_arr);
            json_object_put(l_jobj_arr_new);
        }
    }
    // if static node lists not found
    if(!l_net_processing_num){
        s_http_simple_proc_default(a_http_simple, a_arg);
        return;
    }


    dap_http_simple_reply( a_http_simple, l_reply_str->str, l_reply_str->len );
    strcpy(a_http_simple->reply_mime, "application/json");
    dap_string_free(l_reply_str, true);
    *l_ret_code = Http_Status_OK;
    dap_http_simple_make_cache_from_reply(a_http_simple,time(NULL)+ s_server_list_cache_expire);
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_server_list_static_create
 * @param sh
 * @param url
 */
int dap_chain_net_srv_vpn_cdb_server_list_static_create(dap_chain_net_t *a_net)
{
    if(!a_net) {
        return -1;
    }
    // main json object - array [{...},{...},{...}]
    struct json_object *l_jarr = json_object_new_array();

    dap_chain_net_srv_order_t * l_orders = NULL;
    size_t l_orders_num = 0;
    dap_chain_net_srv_price_unit_uid_t l_unit_uid = { { 0 } };
    //dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = 0x0000000000000001 };
    dap_chain_net_srv_order_find_all_by(a_net, SERV_DIR_SELL, l_srv_uid, l_unit_uid, NULL, 0, 0, &l_orders, &l_orders_num);
    log_it(L_DEBUG, "Found %zd orders in \"%s\" network", l_orders_num, a_net->pub.name);


    // find the shift for each node
    dap_chain_net_srv_order_t *l_orders_pos[l_orders_num];
    int l_orders_available[l_orders_num];
    size_t l_orders_size = 0;
    for(size_t j = 0; j < l_orders_num; j++) {
        l_orders_pos[j] = (dap_chain_net_srv_order_t*) ((char*) l_orders + l_orders_size);
        l_orders_size += dap_chain_net_srv_order_get_size(l_orders_pos[j]);
    }

    // list of node numbers
    size_t l_continents_count = dap_chain_net_srv_order_continents_count();
    // list of the number of nodes in each continent
    int l_continents_numbers[l_continents_count];
    int l_node_numbering[l_continents_count][l_orders_num];
    // init arrays
    for(size_t m1 = 0; m1 < l_continents_count; m1++) {
        l_continents_numbers[m1] = 0;
        for(size_t m2 = 0; m2 < l_orders_num; m2++)
            l_node_numbering[m1][m2] = -1;
    }

    // node numbering
    size_t l_orders_used_num = 0;
    // filling l_continents_numbers and l_node_numbering
    for(size_t j = 0; j < l_orders_num; j++) {
        dap_chain_net_srv_order_t *l_order = l_orders_pos[j];
        // get order availability
        /*            dap_order_state_t *l_order_state = find_order_state(l_order->node_addr);
         if(l_order_state) {
         // if order on-line or off-line
         l_orders_available[j] = l_order_state->is_available;
         }
         else
         l_orders_available[j] = -1;
         if(l_orders_available[j] == 0)
         continue;*/
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
        size_t l_shuffle_num = rand() % (l_cont_num + 1);
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

    for(size_t l_c = 0; l_c < l_continents_count; l_c++) {
        // print all nodes for continent
        for(size_t l_n = 0; l_n < l_continents_numbers[l_c]; l_n++) {
            // since the nodes are shuffled, look for the desired node index
            for(size_t l_o = 0; l_o < l_orders_num; l_o++) {
                if(l_node_numbering[l_c][l_o] != l_n)
                    continue;
                dap_chain_net_srv_order_t *l_order = l_orders_pos[l_o];

                dap_chain_node_info_t * l_node_info = dap_chain_node_info_read(a_net, &l_order->node_addr);
                if(!l_node_info)
                    continue;
                uint8_t l_continent_num = 0;
                char *l_region = NULL;
                dap_chain_net_srv_order_get_continent_region(l_order, &l_continent_num, &l_region);
                const char *l_continent_str = dap_chain_net_srv_order_continent_to_str(l_continent_num);
                // ext_out in hex view
                char *l_ext_out = l_order->ext_size ? DAP_NEW_Z_SIZE(char, l_order->ext_size * 2 + 1) : NULL;
                dap_bin2hex(l_ext_out, l_order->ext, l_order->ext_size);
                // Order name
                char *l_order_name = dap_strdup_printf("%s.%s.%llu", l_continent_str ? l_continent_str : "", l_region ? l_region : "",  l_n + 1);
                // ip addresses
                char l_node_ext_ipv4_str[INET_ADDRSTRLEN] = { 0 };
                char l_node_ext_ipv6_str[INET6_ADDRSTRLEN] = { 0 };
                if(l_node_info->hdr.ext_addr_v4.s_addr)
                    inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_ext_ipv4_str, sizeof(l_node_ext_ipv4_str));
                if(*((uint128_t *) l_node_info->hdr.ext_addr_v6.s6_addr))
                    inet_ntop(AF_INET6, &l_node_info->hdr.ext_addr_v6, l_node_ext_ipv6_str,
                            sizeof(l_node_ext_ipv6_str));
                // ext
                char *l_ext_out_str = dap_strdup_printf("0x%s", l_ext_out);


                struct json_object *l_jobj = json_object_new_object();
                json_object_array_add(l_jarr, l_jobj);
                json_object_object_add(l_jobj, "Location", json_object_new_string(l_region ? l_region : "None"));
                json_object_object_add(l_jobj, "ChainNet", json_object_new_string(a_net->pub.name));
                json_object_object_add(l_jobj, "Name", json_object_new_string(l_order_name));
                if(l_node_ext_ipv4_str[0])
                    json_object_object_add(l_jobj, "Address", json_object_new_string(l_node_ext_ipv4_str));
                if(l_node_ext_ipv6_str[0])
                    json_object_object_add(l_jobj, "Address6", json_object_new_string(l_node_ext_ipv6_str));
                json_object_object_add(l_jobj, "Port", json_object_new_int(l_node_info->hdr.ext_port ? l_node_info->hdr.ext_port : 8079));
                json_object_object_add(l_jobj, "Ext", json_object_new_string(l_ext_out_str));
                json_object_object_add(l_jobj, "Price", json_object_new_int64(l_order->price));
                json_object_object_add(l_jobj, "PriceUnits", json_object_new_int(l_order->price_unit.uint32));
                json_object_object_add(l_jobj, "PriceToken", json_object_new_string(l_order->price_ticker));
                json_object_object_add(l_jobj, "NodeAddress", json_object_new_int64((int64_t)l_order->node_addr.uint64));
                // order state
                /*{
                    dap_order_state_t *l_order_state = find_order_state(l_order->node_addr);
                    // if order is not tested
                    if(!l_order_state)
                        json_object_object_add(l_jobj, "State", json_object_new_string("unknown"));
                    // if order off-line
                    else if(l_order_state->is_available)
                        json_object_object_add(l_jobj, "State", json_object_new_string("available"));
                    // if order on-line
                    else
                        json_object_object_add(l_jobj, "State", json_object_new_string("not available"));
                }*/

                DAP_DELETE(l_region);
                DAP_DELETE(l_ext_out);
                DAP_DELETE(l_order_name);
                DAP_DELETE(l_ext_out_str);
                break;
            }
        }
    }

    // get json string
    const char* l_json_str = json_object_to_json_string(l_jarr);
    int l_ret = 0;
    // save to db
    if(l_json_str) {
        size_t l_orders_count = 0;
        if(!dap_chain_global_db_gr_set(dap_strdup(a_net->pub.name), (void*) l_json_str, dap_strlen(l_json_str),
                "cdb.static_nodelist")) {
            log_it(L_DEBUG, "Error save static nodelist, %llu orders in \"%s\" network", l_orders_num, a_net->pub.name);
            l_ret = -2;
        }
        else {
            log_it(L_DEBUG, "Static nodelist saved successfully, %llu orders, \"%s\" network", l_orders_num,
                    a_net->pub.name);
        }
    }
    else {
        log_it(L_DEBUG, "Error create static nodelist, %llu orders in \"%s\" network", l_orders_num, a_net->pub.name);
        l_ret = -3;
    }
    //...
    // free all json objects
    json_object_put(l_jarr);
    return l_ret;
}



/**
 * @brief dap_chain_net_srv_vpn_cdb_server_list_static_delete
 * @param sh
 * @param url
 */

int dap_chain_net_srv_vpn_cdb_server_list_static_delete(dap_chain_net_t *a_net)
{
    if(!a_net) {
        return -1;
    }
    // delete from db
    char * lgroup_str = dap_chain_net_srv_order_get_nodelist_group(a_net);
    size_t l_orders_count = 0;
    size_t l_static_nodelist_size = 0;
    // check static nodelist
    uint8_t *l_static_nodelist = dap_chain_global_db_gr_get(dap_strdup(a_net->pub.name), &l_static_nodelist_size, "cdb.static_nodelist");
    if(!l_static_nodelist)
        return 1;
    else
        DAP_DELETE(l_static_nodelist);
    // delete static nodelist
    if(!dap_chain_global_db_gr_del(a_net->pub.name, "cdb.static_nodelist")) {
        log_it(L_DEBUG, "Error delete static nodelist for \"%s\" network", a_net->pub.name);
        DAP_DELETE(lgroup_str);
        return -2;
    }
    else {
        log_it(L_DEBUG, "Static nodelist deleted successfully, \"%s\" network", a_net->pub.name);
    }
    DAP_DELETE(lgroup_str);
    return 0;
}

int dap_chain_net_srv_vpn_cdb_server_list_check_orders(dap_chain_net_t * a_net)
{
    int l_multiplicity = 0;// no repeat callback
    // run callback now and only one time
    dap_timerfd_t *s_timerfd_check_orders = dap_timerfd_start(1, &callback_check_orders, DAP_INT_TO_POINTER(l_multiplicity));
    return 0;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_server_list_add_proc
 * @param sh
 * @param url
 */
void dap_chain_net_srv_vpn_cdb_server_list_add_proc(dap_http_t *a_http, const char *a_url)
{
    s_url_proc = dap_http_simple_proc_add(a_http,a_url,100000,s_http_simple_proc_default);
    // added check of orders
    if(dap_config_get_item_bool_default(g_config, "cdb", "servers_list_check", true)) {
        int64_t l_timeout_ms = 0; // period between orders checks
        int64_t l_timeout2_ms = 0; // period between checks for unavailable servers
        uint16_t l_array_length = 0;
        char **l_servers_list_check_periods_sec = dap_config_get_array_str(g_config, "cdb", "servers_list_check_periods", &l_array_length);
        if(l_array_length > 0)
            l_timeout_ms = strtoul(l_servers_list_check_periods_sec[0], NULL, 10) * 1000;
        if(l_array_length > 1)
            l_timeout2_ms = strtoul(l_servers_list_check_periods_sec[1], NULL, 10) * 1000;
        // set default values ​​if necessary
        if(!l_timeout_ms)
            l_timeout_ms = 3600;// * 1000;
        if(!l_timeout2_ms)
            l_timeout2_ms = 12 * 3600;// * 1000;
        int l_multiplicity = l_timeout2_ms / l_timeout_ms;
        if(l_multiplicity < 1)
            l_multiplicity = 1;

        // add timer with l_timeout_ms millisecond timeout for check orders
        dap_timerfd_t *s_timerfd_check_orders = dap_timerfd_start(l_timeout_ms, &callback_check_orders,
                                                                  DAP_INT_TO_POINTER(l_multiplicity));
    }

}

/**
 * @brief dap_chain_net_srv_vpn_cdb_server_list_cache_reset
 */
void dap_chain_net_srv_vpn_cdb_server_list_cache_reset(void)
{
    if(s_url_proc){
        pthread_rwlock_wrlock(&s_url_proc->cache_rwlock);
        dap_http_cache_delete(s_url_proc->cache);
        s_url_proc->cache = NULL;
        pthread_rwlock_unlock(&s_url_proc->cache_rwlock);
    }
}

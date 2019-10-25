/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
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
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <wepoll.h>
#endif

#include <pthread.h>


#include "uthash.h"
#include "utlist.h"
#include "dap_list.h"
#include "dap_string.h"

#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_order.h"

#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "chain_net_srv"

static size_t m_uid_count;
static dap_chain_net_srv_uid_t * m_uid;

typedef struct service_list {
    dap_chain_net_srv_uid_t uid;
    dap_chain_net_srv_t * srv;
    UT_hash_handle hh;
} service_list_t;

// list of active services
static service_list_t *s_srv_list = NULL;
// for separate access to s_srv_list
static pthread_mutex_t s_srv_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_cli_net_srv( int argc, char **argv, char **a_str_reply);
/**
 * @brief dap_chain_net_srv_init
 * @return
 */
int dap_chain_net_srv_init(void)
{
    m_uid = NULL;
    m_uid_count = 0;
    if( dap_chain_net_srv_order_init() != 0 )
        return -1;

    dap_chain_node_cli_cmd_item_create ("net_srv", s_cli_net_srv, "Network services managment",
        "net_srv -net <chain net name> order list [-srv_uid <Service UID>] [-srv_class <Service Class>]\n"
        "\tOrders list, all or by UID and/or class\n"
        "net_srv -net <chain net name> order delete -id <Proposal ID>\n"
        "\tOrder delete\n"
        "net_srv -net <chain net name> order create -srv_uid <Service UID> -srv_class <Service Class> -price <Price>\\\n"
        "        -price_unit <Price Unit> -node_addr <Node Address> -tx_cond <TX Cond Hash> \\\n"
        "        [-expires <Unix time when expires>]\\\n"
        "\tOrder create\n" );

    return 0;
}

/**
 * @brief dap_chain_net_srv_deinit
 */
void dap_chain_net_srv_deinit(void)
{
    // TODO Stop all services

    dap_chain_net_srv_del_all();
}


/**
 * @brief s_cli_net_srv
 * @param argc
 * @param argv
 * @param a_str_reply
 * @return
 */
static int s_cli_net_srv( int argc, char **argv, char **a_str_reply)
{
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    int ret = dap_chain_node_cli_cmd_values_parse_net_chain( &arg_index, argc, argv, a_str_reply, NULL, &l_net );
    if ( l_net ) {
        char * l_orders_group = dap_chain_net_srv_order_get_gdb_group( l_net );

        dap_string_t *l_string_ret = dap_string_new("");
        const char *l_order_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "order", &l_order_str);
        if ( strcmp( l_order_str, "list" ) == 0 ){
            dap_string_append(l_string_ret,"Orders:\n");

            // Select with specified service uid
            const char *l_srv_uid_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);

            // Select with specified service class
            const char *l_srv_class_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-srv_class", &l_srv_class_str);
        } else if( strcmp( l_order_str, "create" ) == 0 ){
            const char* l_srv_uid_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);

            const char* l_srv_class_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-srv_class", &l_srv_class_str);

            const char* l_node_addr_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-node_addr", &l_node_addr_str);

            const char*  l_tx_cond_hash_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-tx_cond", &l_tx_cond_hash_str);

            const char*  l_price_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price", &l_price_str);

            const char*  l_price_unit_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price_unit", &l_price_unit_str);

            const char*  l_comments = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-comments", &l_comments);

            if ( l_srv_uid_str && l_srv_class_str && l_node_addr_str && l_tx_cond_hash_str && l_price_str ) {
                dap_chain_net_srv_uid_t l_srv_uid={{0}};
                dap_chain_net_srv_class_t l_srv_class= SERV_CLASS_UNDEFINED;
                dap_chain_node_addr_t l_node_addr={0};
                dap_chain_hash_fast_t l_tx_cond_hash={{0}};
                uint128_t l_price=0;
                dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};

                l_srv_uid.uint128 = (uint128_t) atoll( l_srv_uid_str);
                l_srv_class = (dap_chain_net_srv_class_t) atoi( l_srv_class_str );
                dap_chain_node_addr_from_str( &l_node_addr, l_node_addr_str );
                dap_chain_str_to_hash_fast (l_tx_cond_hash_str, &l_tx_cond_hash);
                l_price = (uint128_t) atoll ( l_price_str );
                l_price_unit.uint32 = (uint32_t) atol ( l_price_unit_str );

                char * l_order_new_hash_str = dap_chain_net_srv_order_create (
                            l_net, l_srv_uid, l_srv_class, l_node_addr,l_tx_cond_hash, l_price, l_price_unit, l_comments);
                if (l_order_new_hash_str)
                    dap_string_append_printf( l_string_ret, "Created order %s\n", l_order_new_hash_str);
                else{
                    dap_string_append_printf( l_string_ret, "Error! Can't created order\n");
                    ret = -4;
                }
            } else {
                dap_string_append_printf( l_string_ret, "Missed some required params\n");
                ret=-5;
            }
        } else {
            dap_string_append_printf( l_string_ret, "Unknown subcommand \n");
            ret=-3;
        }
        dap_chain_node_cli_set_reply_text(a_str_reply, l_string_ret->str);
        dap_string_free(l_string_ret, true);
    }

    return ret;
}

/**
 * @brief dap_chain_net_srv_add
 * @param a_srv
 */
void dap_chain_net_srv_add(dap_chain_net_srv_t * a_srv)
{
    service_list_t *l_sdata = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &(a_srv->uid), sizeof(a_srv->uid), l_sdata);
    if(l_sdata == NULL) {
        l_sdata = DAP_NEW_Z(service_list_t);
        memcpy(&l_sdata->uid, &a_srv->uid, sizeof(dap_chain_net_srv_uid_t));
        l_sdata->srv = DAP_NEW(dap_chain_net_srv_t);
        memcpy(&l_sdata->srv, a_srv, sizeof(dap_chain_net_srv_t));
        HASH_ADD(hh, s_srv_list, uid, sizeof(a_srv->uid), l_sdata);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_del
 * @param a_srv
 */
void dap_chain_net_srv_del(dap_chain_net_srv_t * a_srv)
{
    service_list_t *l_sdata;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, a_srv, sizeof(dap_chain_net_srv_uid_t), l_sdata);
    if(l_sdata) {
        DAP_DELETE(l_sdata);
        HASH_DEL(s_srv_list, l_sdata);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_del_all
 * @param a_srv
 */
void dap_chain_net_srv_del_all(void)
{
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        DAP_DELETE(l_sdata);
        HASH_DEL(s_srv_list, l_sdata);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_get
 * @param a_uid
 * @return
 */
dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t *a_uid)
{
    service_list_t *l_sdata = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &a_uid, sizeof(dap_chain_net_srv_uid_t), l_sdata);
    pthread_mutex_unlock(&s_srv_list_mutex);
    return (l_sdata) ? l_sdata->srv : NULL;
}

/**
 * @brief dap_chain_net_srv_count
 * @return
 */
 size_t dap_chain_net_srv_count(void)
{
    size_t l_count = 0;
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        l_count++;
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_count;
}

/**
 * @brief dap_chain_net_srv_list
 * @return
 */
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void)
{
    static dap_chain_net_srv_uid_t *l_srv_uids = NULL;
    static size_t l_count_last = 0;
    size_t l_count_cur = 0;
    dap_list_t *l_list = NULL;
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    // count the number of services and save them in list
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        l_list = dap_list_append(l_list, l_sdata);
        l_count_cur++;
    }
    // fill the output array
    if(l_count_cur > 0) {
        if(l_count_cur != l_count_last) {
            DAP_DELETE(l_srv_uids);
            l_srv_uids = DAP_NEW_SIZE(dap_chain_net_srv_uid_t, sizeof(dap_chain_net_srv_uid_t) * l_count_cur);
        }
        for(size_t i = 0; i < l_count_cur; i++) {
            service_list_t *l_sdata = l_list->data;
            memcpy(l_srv_uids + i, &l_sdata->uid, sizeof(dap_chain_net_srv_uid_t));
        }
    }
    // save new number of services
    l_count_last = l_count_cur;
    pthread_mutex_unlock(&s_srv_list_mutex);
    dap_list_free(l_list);
    return l_srv_uids;
}


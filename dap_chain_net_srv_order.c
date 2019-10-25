/*
 * Authors:
 * Dmitrii Gerasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe https://cellframe.net
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

#include "dap_chain_net_srv_order.h"

#include "dap_hash.h"
#include "dap_chain_global_db.h"

#define LOG_TAG "dap_chain_net_srv_order"


/**
 * @brief dap_chain_net_srv_order_init
 * @return
 */
int dap_chain_net_srv_order_init(void)
{

    return 0;
}

/**
 * @brief dap_chain_net_srv_order_deinit
 */
void dap_chain_net_srv_order_deinit()
{

}

char* dap_chain_net_srv_order_create(
        dap_chain_net_t * a_net,
        dap_chain_net_srv_uid_t a_srv_uid, // Service UID
        dap_chain_net_srv_class_t a_srv_class, //Class of service (once or permanent)
        dap_chain_node_addr_t a_node_addr, // Node address that servs the order (if present)
        dap_chain_hash_fast_t a_tx_cond_hash, // Hash index of conditioned transaction attached with order
        uint64_t a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        const char * a_comments
        )
{
    if (a_net) {
        dap_chain_net_srv_order_t *l_order = DAP_NEW_Z(dap_chain_net_srv_order_t);
        dap_chain_hash_fast_t* l_order_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
        l_order->version = 1;
        l_order->srv_uid = a_srv_uid;
        l_order->srv_class = a_srv_class;
        l_order->node_addr.uint64 = a_node_addr.uint64;
        memcpy(&l_order->tx_cond_hash, &a_tx_cond_hash, DAP_CHAIN_HASH_FAST_SIZE);
        l_order->price = a_price;
        l_order->price_unit = a_price_unit;
        if ( a_comments)
            strncpy(l_order->comments, a_comments, sizeof ( l_order->comments)-1 );

        dap_hash_fast( l_order, sizeof ( *l_order), l_order_hash );
        char * l_order_hash_str = dap_chain_hash_fast_to_str_new( l_order_hash );
        char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
        if ( !dap_chain_global_db_gr_set(l_order_hash_str, l_order, sizeof (*l_order), l_gdb_group_str ) ){
            DAP_DELETE( l_order );
            DAP_DELETE( l_order_hash );
            DAP_DELETE( l_order_hash_str );
            DAP_DELETE( l_gdb_group_str );
            return NULL;
        }
        DAP_DELETE( l_order_hash );
        DAP_DELETE( l_order_hash_str );
        DAP_DELETE( l_order );
        DAP_DELETE( l_gdb_group_str );
        return  l_order_hash_str;
    }else
        return NULL;
}

/**
 * @brief dap_chain_net_srv_order_find_by_hash
 * @param a_net
 * @param a_hash
 * @return
 */
dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_hash)
{
    dap_chain_net_srv_order_t * l_order = NULL;
    if ( a_net && a_hash ){
        char * l_order_hash_str = dap_chain_hash_fast_to_str_new(a_hash );
        char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
        size_t l_order_size =0;
        l_order = (dap_chain_net_srv_order_t *) dap_chain_global_db_gr_get(l_order_hash_str, &l_order_size, l_gdb_group_str );
        if (l_order_size != sizeof (dap_chain_net_srv_order_t) ){
            log_it( L_ERROR, "Found wrong size order");
            DAP_DELETE( l_order );
            DAP_DELETE( l_order_hash_str );
            DAP_DELETE( l_gdb_group_str );
            return NULL;
        }
        DAP_DELETE( l_order_hash_str );
        DAP_DELETE( l_gdb_group_str );
    }
    return l_order;
}

int dap_chain_net_srv_order_find_all_by(dap_chain_net_t * a_net, dap_chain_net_srv_uid_t a_srv_uid, dap_chain_net_srv_class_t a_srv_class,
                                        dap_chain_net_srv_price_unit_uid_t a_price_unit, uint64_t a_price_min, uint64_t a_price_max,
                                        dap_chain_net_srv_order_t ** a_output_orders, size_t * a_output_orders_count)
{
    if ( a_net && a_output_orders && a_output_orders_count ){
        char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
        size_t l_orders_count = 0;
        dap_global_db_obj_t * l_orders = dap_chain_global_db_gr_load(l_gdb_group_str,&l_orders_count);

        bool l_order_pass_first=true;
        size_t l_order_passed_index;
lb_order_pass:
        l_order_passed_index =0;
        for (int i; i< l_orders_count; i++){
            dap_chain_net_srv_order_t * l_order = (dap_chain_net_srv_order_t *) l_orders[i].value;
            // Check srv uid
            if ( a_srv_uid.uint128)
                if ( l_order->srv_uid.uint128 != a_srv_uid.uint128 )
                    continue;
            // Check srv class
            if ( a_srv_class != SERV_CLASS_UNDEFINED )
                if ( l_order->srv_class != a_srv_class )
                    continue;
            // check price unit
            if ( a_price_unit.uint32 )
                if ( a_price_unit.uint32 != l_order->price_unit.uint32 )
                    continue;
            // Check price minimum
            if ( a_price_min )
                if ( l_order->price < a_price_min )
                    continue;
            // Check price maximum
            if ( a_price_max )
                if ( l_order->price > a_price_max )
                    continue;
            if( !l_order_pass_first ){
                memcpy(a_output_orders[l_order_passed_index], l_order, sizeof (dap_chain_net_srv_order_t));
            }
            l_order_passed_index++;
        }
        // Dirty goto usage ho ho ho
        if (l_order_pass_first) {
            l_order_pass_first = false;
            *a_output_orders_count = l_order_passed_index;
            *a_output_orders = DAP_NEW_Z_SIZE(dap_chain_net_srv_order_t, sizeof (dap_chain_net_srv_order_t)*l_order_passed_index );
            goto lb_order_pass;
        }
        // If we here - its the second pass through

        dap_chain_global_db_objs_delete(l_orders, l_orders_count);
        DAP_DELETE( l_gdb_group_str);
        return 0;
    }
    return -1;
}

/**
 * @brief dap_chain_net_srv_order_delete_by_hash_str
 * @param a_net
 * @param a_hash_str
 * @return
 */
int dap_chain_net_srv_order_delete_by_hash_str(dap_chain_net_t * a_net, const char * a_hash_str )
{
    int ret = -2;
    if ( a_net && a_hash_str  ){
        char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
        ret = dap_chain_global_db_gr_del( a_hash_str, l_gdb_group_str ) ? 0 : -1;
        DAP_DELETE( l_gdb_group_str );
    }
    return ret;
}


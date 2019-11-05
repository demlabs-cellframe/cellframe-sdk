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
        dap_chain_net_srv_order_direction_t a_direction,
        dap_chain_net_srv_uid_t a_srv_uid, // Service UID
        dap_chain_net_srv_class_t a_srv_class, //Class of service (once or permanent)
        dap_chain_node_addr_t a_node_addr, // Node address that servs the order (if present)
        dap_chain_hash_fast_t a_tx_cond_hash, // Hash index of conditioned transaction attached with order
        uint64_t a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        dap_chain_time_t a_expires, // TS when the service expires
        const char * a_ext
        )
{
    if (a_net) {
        dap_chain_net_srv_order_t *l_order = DAP_NEW_Z(dap_chain_net_srv_order_t);
        dap_chain_hash_fast_t* l_order_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
        l_order->version = 1;
        l_order->srv_uid = a_srv_uid;
        l_order->ts_created = (dap_chain_time_t) time(NULL);
        l_order->srv_class = a_srv_class;
        l_order->node_addr.uint64 = a_node_addr.uint64;
        memcpy(&l_order->tx_cond_hash, &a_tx_cond_hash, DAP_CHAIN_HASH_FAST_SIZE);
        l_order->price = a_price;
        l_order->price_unit = a_price_unit;
        strncpy(l_order->price_ticker, a_price_ticker,sizeof(l_order->price_ticker)-1);
        if ( a_ext)
            strncpy(l_order->ext, a_ext, sizeof ( l_order->ext)-1 );

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
        DAP_DELETE( l_order );
        DAP_DELETE( l_gdb_group_str );
        return  l_order_hash_str;
    }else
        return NULL;
}

/**
 * @brief dap_chain_net_srv_order_find_by_hash_str
 * @param a_net
 * @param a_hash_str
 * @return
 */
dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_hash_str(dap_chain_net_t * a_net, const char * a_hash_str)
{
    dap_chain_net_srv_order_t * l_order = NULL;
    if ( a_net && a_hash_str ){
        char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
        size_t l_order_size =0;
        l_order = (dap_chain_net_srv_order_t *) dap_chain_global_db_gr_get(a_hash_str, &l_order_size, l_gdb_group_str );
        if (l_order_size != sizeof (dap_chain_net_srv_order_t) ){
            log_it( L_ERROR, "Found wrong size order");
            DAP_DELETE( l_order );
            DAP_DELETE( l_gdb_group_str );
            return NULL;
        }
        DAP_DELETE( l_gdb_group_str );
    }
    return l_order;
}

/**
 * @brief dap_chain_net_srv_order_find_all_by
 * @param a_net
 * @param a_srv_uid
 * @param a_srv_class
 * @param a_price_unit
 * @param a_price_min
 * @param a_price_max
 * @param a_output_orders
 * @param a_output_orders_count
 * @return
 */
int dap_chain_net_srv_order_find_all_by(dap_chain_net_t * a_net,const dap_chain_net_srv_order_direction_t a_direction,
                                        const dap_chain_net_srv_uid_t a_srv_uid,const dap_chain_net_srv_class_t a_srv_class,
                                        const dap_chain_net_srv_price_unit_uid_t a_price_unit,const char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                        const uint64_t a_price_min, const uint64_t a_price_max,
                                        dap_chain_net_srv_order_t ** a_output_orders, size_t * a_output_orders_count)
{
    if ( a_net && a_output_orders && a_output_orders_count ){
        char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
        size_t l_orders_count = 0;
        dap_global_db_obj_t * l_orders = dap_chain_global_db_gr_load(l_gdb_group_str,&l_orders_count);
        log_it( L_DEBUG ,"Loaded %zd orders", l_orders_count);
        bool l_order_pass_first=true;
        size_t l_order_passed_index;
lb_order_pass:
        l_order_passed_index =0;
        for (size_t i=0; i< l_orders_count; i++){
            dap_chain_net_srv_order_t * l_order = (dap_chain_net_srv_order_t *) l_orders[i].value;
            // Check direction
            if (a_direction != SERV_DIR_UNDEFINED )
                if ( l_order->direction != a_direction )
                    continue;

            // Check srv uid
            if ( a_srv_uid.uint64 )
                if ( l_order->srv_uid.uint64 != a_srv_uid.uint64 )
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
            // Check ticker
            if ( a_price_ticker )
                if ( strcmp( l_order->price_ticker, a_price_ticker) != 0 )
                    continue;
            if( !l_order_pass_first ){
                memcpy(a_output_orders[l_order_passed_index], l_order, sizeof (dap_chain_net_srv_order_t));
            }else
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

/**
 * @brief dap_chain_net_srv_order_dump_to_string
 * @param a_orders
 * @param a_str_out
 */
void dap_chain_net_srv_order_dump_to_string(dap_chain_net_srv_order_t *a_order,dap_string_t * a_str_out)
{
    if (a_order && a_str_out ){
        dap_chain_hash_fast_t l_hash;
        char l_hash_str[DAP_CHAIN_HASH_FAST_SIZE * 2 + 4];
        dap_hash_fast(a_order,sizeof (*a_order),&l_hash );
        dap_chain_hash_fast_to_str(&l_hash,l_hash_str,sizeof(l_hash_str)-1);
        dap_string_append_printf(a_str_out, "== Order %s ==\n", l_hash_str);
        dap_string_append_printf(a_str_out, "  version:          %u\n", a_order->version );

        switch ( a_order->direction) {
            case SERV_DIR_UNDEFINED: dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_UNDEFINED\n" ); break;
            case SERV_DIR_SELL: dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_SELL\n" ); break;
            case SERV_DIR_BUY: dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_BUY\n" ); break;
        }

        switch ( a_order->srv_class) {
            case SERV_CLASS_ONCE: dap_string_append_printf(a_str_out, "  srv_class:        SERV_CLASS_ONCE\n" ); break;;
            case SERV_CLASS_PERMANENT: dap_string_append_printf(a_str_out, "  srv_class:        SERV_CLASS_PERMANENT\n" ); break;
            case SERV_CLASS_UNDEFINED: dap_string_append_printf(a_str_out, "  srv_class:        SERV_CLASS_UNDEFINED\n" ); break;
            //default: dap_string_append_printf(a_str_out, "  srv_class:        UNKNOWN\n" );
        }
        dap_string_append_printf(a_str_out, "  srv_uid:          0x%016llX\n", a_order->srv_uid.uint64 );
        dap_string_append_printf(a_str_out, "  price:            \u00a0%.3Lf (%llu)\n", dap_chain_balance_to_coins(a_order->price) , a_order->price);
        if( a_order->price_unit.uint32 )
            dap_string_append_printf(a_str_out, "  price_unit:       0x%016llX\n", dap_chain_net_srv_price_unit_uid_to_str(a_order->price_unit) );
        if ( a_order->node_addr.uint64)
            dap_string_append_printf(a_str_out, "  node_addr:        "NODE_ADDR_FP_STR"\n", NODE_ADDR_FP_ARGS_S(a_order->node_addr) );

        dap_chain_hash_fast_to_str(&a_order->tx_cond_hash,l_hash_str,sizeof(l_hash_str)-1);
        dap_string_append_printf(a_str_out, "  tx_cond_hash:          %s\n", l_hash_str );
        dap_string_append_printf(a_str_out, "  ext:          \"%s\"\n", a_order->ext );
    }
}

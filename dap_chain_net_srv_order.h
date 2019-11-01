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

#pragma once
#include "dap_common.h"
#include "dap_string.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv_common.h"

typedef struct dap_chain_net_srv_order
{
    uint16_t version;
    dap_chain_net_srv_uid_t srv_uid; // Service UID
    dap_chain_net_srv_class_t srv_class:8; //Class of service (once or permanent)
    dap_chain_node_addr_t node_addr; // Node address that servs the order (if present)
    dap_chain_hash_fast_t tx_cond_hash; // Hash index of conditioned transaction attached with order
    uint64_t price; //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
    dap_chain_net_srv_price_unit_uid_t price_unit; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    dap_chain_time_t ts_created;
    dap_chain_time_t ts_expires;
    char ext[128];
} dap_chain_net_srv_order_t;

// Init/deinit should be call only if private
int dap_chain_net_srv_order_init(void);
void dap_chain_net_srv_order_deinit(void);

dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_hash_str(dap_chain_net_t * a_net, const char * a_hash_str);

DAP_STATIC_INLINE dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_hash)
{
    if ( a_net && a_hash ){
        char l_hash_str[DAP_CHAIN_HASH_FAST_SIZE * 2 + 4];
        dap_chain_hash_fast_to_str(a_hash,l_hash_str,sizeof(l_hash_str)-1);
        return  dap_chain_net_srv_order_find_by_hash_str(a_net, l_hash_str );
    }
}

int dap_chain_net_srv_order_find_all_by(dap_chain_net_t * a_net,dap_chain_net_srv_uid_t a_srv_uid, dap_chain_net_srv_class_t a_srv_class,
                                        dap_chain_net_srv_price_unit_uid_t a_price_unit, uint64_t a_price_min, uint64_t a_price_max,
                                        dap_chain_net_srv_order_t ** a_output_orders, size_t * a_output_orders_count);
int dap_chain_net_srv_order_delete_by_hash_str( dap_chain_net_t * a_net,const char * a_hash_str );

/**
 * @brief dap_chain_net_srv_order_delete_by_hash
 * @param a_net
 * @param a_hash
 * @return
 */
DAP_STATIC_INLINE int dap_chain_net_srv_order_delete_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_hash )
{
    char l_hash_str[DAP_CHAIN_HASH_FAST_SIZE * 2 + 4];
    dap_chain_hash_fast_to_str(a_hash,l_hash_str,sizeof(l_hash_str)-1);
    return dap_chain_net_srv_order_delete_by_hash_str ( a_net, l_hash_str);
}

char* dap_chain_net_srv_order_create(
        dap_chain_net_t * a_net,
        dap_chain_net_srv_uid_t a_srv_uid, // Service UID
        dap_chain_net_srv_class_t a_srv_class, //Class of service (once or permanent)
        dap_chain_node_addr_t a_node_addr, // Node address that servs the order (if present)
        dap_chain_hash_fast_t a_tx_cond_hash, // Hash index of conditioned transaction attached with order
        uint64_t a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        dap_chain_time_t a_expires, // TS when the service expires
        const char * a_comments
        );

void dap_chain_net_srv_order_dump_to_string(dap_chain_net_srv_order_t *a_order,dap_string_t * a_str_out);

/**
* @brief dap_chain_net_srv_order_get_gdb_group_mempool
* @param l_chain
* @return
*/
DAP_STATIC_INLINE char * dap_chain_net_srv_order_get_gdb_group(dap_chain_net_t * a_net)
{
   if ( a_net ) {
       const char c_srv_order_group_str[]="srv_order";
       return dap_strdup_printf("%s-%s",a_net->pub.gdb_groups_prefix,c_srv_order_group_str);
   }
   return NULL;
}

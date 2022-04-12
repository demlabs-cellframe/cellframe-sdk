/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
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
#include "dap_chain_net.h"
#include "dap_common.h"
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_net_srv.h"

typedef struct dap_chain_net_srv_order_old
{
    uint16_t version;
    dap_chain_net_srv_uid_t srv_uid; // Service UID
    byte_t padding; // some padding
    dap_chain_net_srv_order_direction_t direction; // Order direction - SELL or PURCHASE
    dap_chain_node_addr_t node_addr; // Node address that servs the order (if present)
    dap_chain_hash_fast_t tx_cond_hash; // Hash index of conditioned transaction attached with order
    dap_chain_net_srv_price_unit_uid_t price_unit; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    dap_chain_time_t ts_created;
    dap_chain_time_t ts_expires;
    uint64_t price; //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
    char price_ticker[DAP_CHAIN_TICKER_SIZE_MAX]; // Token ticker to pay for service
    //uint8_t continent;
    //char region[32];
    uint32_t ext_size;
    uint8_t ext[];
} DAP_ALIGN_PACKED dap_chain_net_srv_order_old_t;

typedef struct dap_chain_net_srv_order
{
    uint16_t version;
    dap_chain_net_srv_uid_t srv_uid; // Service UID
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    byte_t padding[8];
#endif
    dap_chain_net_srv_order_direction_t direction; // Order direction - SELL or PURCHASE
    byte_t padding_dir[3];
    dap_chain_node_addr_t node_addr; // Node address that servs the order (if present)
    dap_chain_hash_fast_t tx_cond_hash; // Hash index of conditioned transaction attached with order
    dap_chain_net_srv_price_unit_uid_t price_unit; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    dap_chain_time_t ts_created;
    dap_chain_time_t ts_expires;
    uint256_t price; //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
    char price_ticker[DAP_CHAIN_TICKER_SIZE_MAX]; // Token ticker to pay for service
    uint32_t ext_size;
    byte_t free_space[128];  // for future changes
    uint8_t ext_n_sign[];
} DAP_ALIGN_PACKED dap_chain_net_srv_order_t;

// Init/deinit should be call only if private
int dap_chain_net_srv_order_init(void);
void dap_chain_net_srv_order_deinit(void);

size_t dap_chain_net_srv_order_get_size(dap_chain_net_srv_order_t *a_order);
dap_chain_net_srv_order_t *dap_chain_net_srv_order_read(byte_t *a_order, size_t a_order_size);

bool dap_chain_net_srv_order_set_continent_region(dap_chain_net_srv_order_t **a_order, uint8_t a_continent_num, const char *a_region);
bool dap_chain_net_srv_order_get_continent_region(dap_chain_net_srv_order_t *a_order, uint8_t *a_continent_num, char **a_region);

const char* dap_chain_net_srv_order_get_country_code(dap_chain_net_srv_order_t *a_order);
size_t dap_chain_net_srv_order_continents_count(void);
const char* dap_chain_net_srv_order_continent_to_str(int8_t a_num);
int8_t dap_chain_net_srv_order_continent_to_num(const char *l_continent_str);

dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_hash_str(dap_chain_net_t * a_net, const char * a_hash_str);

DAP_STATIC_INLINE dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_hash)
{
    if ( a_net && a_hash ){
        char l_hash_str[DAP_CHAIN_HASH_FAST_SIZE * 2 + 4];
        dap_chain_hash_fast_to_str(a_hash,l_hash_str,sizeof(l_hash_str)-1);
        return  dap_chain_net_srv_order_find_by_hash_str(a_net, l_hash_str );
    }
    return NULL;
}

int dap_chain_net_srv_order_find_all_by(dap_chain_net_t * a_net, const dap_chain_net_srv_order_direction_t a_direction, const dap_chain_net_srv_uid_t a_srv_uid,
                                        const dap_chain_net_srv_price_unit_uid_t a_price_unit, const char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX], const uint256_t a_price_min, const uint256_t a_price_max,
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

char *dap_chain_net_srv_order_create(dap_chain_net_t * a_net,
        dap_chain_net_srv_order_direction_t a_direction,
        dap_chain_net_srv_uid_t a_srv_uid, // Service UID
        dap_chain_node_addr_t a_node_addr, // Node address that servs the order (if present)
        dap_chain_hash_fast_t a_tx_cond_hash, // Hash index of conditioned transaction attached with order
        uint256_t a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        const char a_price_ticker[],
        dap_chain_time_t a_expires, // TS when the service expires
        const uint8_t *a_ext,
        uint32_t a_ext_size,
        const char *a_region,
        int8_t a_continent_num,
        dap_enc_key_t *a_key
        );

dap_chain_net_srv_order_t *dap_chain_net_srv_order_compose(
        dap_chain_net_t *a_net,
        dap_chain_net_srv_order_direction_t a_direction,
        dap_chain_net_srv_uid_t a_srv_uid, // Service UID
        dap_chain_node_addr_t a_node_addr, // Node address that servs the order (if present)
        dap_chain_hash_fast_t a_tx_cond_hash, // Hash index of conditioned transaction attached with order
        uint256_t a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        const char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        dap_chain_time_t a_expires, // TS when the service expires
        const uint8_t *a_ext,
        uint32_t a_ext_size,
        const char *a_region,
        int8_t a_continent_num,
        dap_enc_key_t *a_key
        );

char *dap_chain_net_srv_order_save(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_order);
void dap_chain_net_srv_order_dump_to_string(dap_chain_net_srv_order_t *a_order,dap_string_t * a_str_out, const char *a_hash_out_type);
void dap_chain_net_srv_order_add_notify_callback(dap_chain_net_t *a_net, dap_global_db_obj_callback_notify_t a_callback, void *a_cb_arg);
/**
* @brief dap_chain_net_srv_order_get_gdb_group_mempool
* @param l_chain
* @return
*/
DAP_STATIC_INLINE char * dap_chain_net_srv_order_get_gdb_group(dap_chain_net_t * a_net)
{
   if ( a_net ) {
       const char c_srv_order_group_str[]="service.orders";
       return dap_strdup_printf("%s.%s",a_net->pub.gdb_groups_prefix,c_srv_order_group_str);
   }
   return NULL;
}

/**
* @brief dap_chain_net_srv_order_get_gdb_group_mempool
* @param l_chain
* @return
*/
DAP_STATIC_INLINE char * dap_chain_net_srv_order_get_nodelist_group(dap_chain_net_t * a_net)
{
   if ( a_net ) {
       const char c_srv_order_group_str[]="service.orders.static_nodelist";
       return dap_strdup_printf("%s.%s",a_net->pub.gdb_groups_prefix,c_srv_order_group_str);
   }
   return NULL;
}

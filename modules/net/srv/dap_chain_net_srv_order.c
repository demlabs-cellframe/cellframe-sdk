/*
 * Authors:
 * Dmitrii Gerasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe https://cellframe.net
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

 DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#include <stdio.h>
#include <strings.h>

#include "dap_chain_net_srv_order.h"
#include "dap_hash.h"
#include "dap_enc_base58.h"
#include "dap_global_db.h"
#include "dap_chain_net_srv_countries.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"

#define LOG_TAG "dap_chain_net_srv_order"

/*
Continent codes :
AF : Africa			geonameId=6255146
AS : Asia			geonameId=6255147
EU : Europe			geonameId=6255148
NA : North America		geonameId=6255149
OC : Oceania			geonameId=6255151
SA : South America		geonameId=6255150
AN : Antarctica			geonameId=6255152
 */

char *s_server_continents[]={
        "None",
        "Africa",
        "Europe",
        "North America",
        "South America",
        "Southeast Asia",
        "Asia",
        //"Near East",
        "Oceania",
        "Antarctica"
 };

struct dap_order_notify {
    dap_chain_net_t *net;
    dap_store_obj_callback_notify_t callback;
    void *cb_arg;
};

/**
 * @brief dap_chain_net_srv_order_init
 * @return
 */
int dap_chain_net_srv_order_init()
{
    return 0;
}

/**
 * @brief dap_chain_net_srv_order_deinit
 */
void dap_chain_net_srv_order_deinit()
{

}

size_t dap_chain_net_srv_order_get_size(dap_chain_net_srv_order_t *a_order)
{
    if (!a_order)
        return 0;
    size_t l_sign_size = 0;
    if (a_order->version == 3) {
        dap_sign_t *l_sign = (dap_sign_t *)(a_order->ext_n_sign + a_order->ext_size);
        if (l_sign->header.type.type == SIG_TYPE_NULL)
            l_sign_size = sizeof(dap_sign_type_t);
        else
            l_sign_size = dap_sign_get_size(l_sign);
        return sizeof(dap_chain_net_srv_order_t) + a_order->ext_size + l_sign_size;
    }
    dap_chain_net_srv_order_old_t *l_order = (dap_chain_net_srv_order_old_t *)a_order;
    if(l_order->version == 2) {
        dap_sign_t *l_sign = (dap_sign_t *)&l_order->ext[l_order->ext_size];
        if (l_sign->header.type.type == SIG_TYPE_NULL)
            l_sign_size = sizeof(dap_sign_type_t);
        else
            l_sign_size = dap_sign_get_size(l_sign);
    }
    return sizeof(dap_chain_net_srv_order_old_t) + l_order->ext_size + l_sign_size;
}

/**
 * @brief dap_chain_net_srv_order_get_region_continent
 * @param a_continent_num [in]
 * @param a_region [in]
 */
bool dap_chain_net_srv_order_set_continent_region(dap_chain_net_srv_order_t **a_order, uint8_t a_continent_num, const char *a_region)
{
    dap_chain_net_srv_order_t *l_order = *a_order;
    if(!l_order || (!a_continent_num && !a_region))
        return false;
    uint8_t l_continent_num_prev = 0;
    char *l_region_prev = NULL;
    dap_chain_net_srv_order_get_continent_region(*a_order, &l_continent_num_prev, &l_region_prev);
    uint32_t l_ext_size = 1 + sizeof(uint8_t);
    if(a_region)
        l_ext_size += strlen(a_region) + 1;
    else if(l_region_prev)
        l_ext_size += strlen(l_region_prev) + 1;

    l_order = DAP_REALLOC(l_order, sizeof(dap_chain_net_srv_order_t) + l_ext_size);
    l_order->ext_n_sign[0] =0x52;
    if(a_continent_num > 0)
        memcpy(l_order->ext_n_sign + 1, &a_continent_num, sizeof(uint8_t));
    else
        memcpy(l_order->ext_n_sign + 1, &l_continent_num_prev, sizeof(uint8_t));
    if(a_region)
        memcpy(l_order->ext_n_sign + 1 + sizeof(uint8_t), a_region, strlen(a_region) + 1);
    else if(l_region_prev)
        memcpy(l_order->ext_n_sign + 1 + sizeof(uint8_t), l_region_prev, strlen(l_region_prev) + 1);
    //sprintf(l_order->ext, "\52%d-%s", a_continent_num, a_region);
    l_order->ext_size = l_ext_size;
    *a_order = l_order;
    DAP_DELETE(l_region_prev);
    return true;
}

/**
 * @brief dap_chain_net_srv_order_get_region_continent
 * @param a_continent_num [out]
 * @param a_region [out]
 */
bool dap_chain_net_srv_order_get_continent_region(dap_chain_net_srv_order_t *a_order_static, uint8_t *a_continent_num, char **a_region)
{
    if(!a_order_static || !a_order_static->ext_size || a_order_static->ext_n_sign[0]!=0x52)
        return false;
    if(a_continent_num) {
       if((uint8_t)a_order_static->ext_n_sign[1]!=0xff)
           memcpy(a_continent_num, a_order_static->ext_n_sign + 1, sizeof(uint8_t));
        else
           a_continent_num = 0;
    }
    if(a_region) {
        size_t l_size = a_order_static->ext_size - sizeof(uint8_t) - 1;
        if(l_size > 0) {
            *a_region = DAP_NEW_SIZE(char, l_size);
            if (!a_region) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
                return false;
            }
            memcpy(*a_region, a_order_static->ext_n_sign + 1 + sizeof(uint8_t), l_size);
        }
        else
            *a_region = NULL;
    }
    return true;
}

/**
 * @brief dap_chain_net_srv_order_get_country_code
 * @param a_order
 */
const char* dap_chain_net_srv_order_get_country_code(dap_chain_net_srv_order_t *a_order)
{
    char *l_region = NULL;
    if (!dap_chain_net_srv_order_get_continent_region(a_order, NULL, &l_region))
        return NULL;
    int l_countries = sizeof(s_server_countries)/sizeof(char*);
    for (int i = 0; i < l_countries; i+=4) {
        if(l_region && (!strcasecmp(l_region, s_server_countries[i+1]) || !strcasecmp(l_region, s_server_countries[i+2]))){
            const char *l_country_code = s_server_countries[i];
            DAP_DELETE(l_region);
            return l_country_code;
        }
    }
    DAP_DELETE(l_region);
    return NULL;
}

/**
 * @brief dap_chain_net_srv_order_continents_count
 */
size_t dap_chain_net_srv_order_continents_count(void)
{
    size_t l_count = sizeof(s_server_continents) / sizeof(char*);
    return l_count;
}

/**
 * @brief dap_chain_net_srv_order_get_continent_str
 */
const char* dap_chain_net_srv_order_continent_to_str(int8_t a_num)
{
    int8_t l_count = dap_chain_net_srv_order_continents_count();
    if(a_num >= l_count)
        return NULL;
    return s_server_continents[a_num];
}

/**
 * @brief dap_chain_net_srv_order_get_continent_num
 */
int8_t dap_chain_net_srv_order_continent_to_num(const char *a_continent_str)
{
    int8_t l_count = dap_chain_net_srv_order_continents_count();
    // convert to to upper case
    char *l_continent_str = dap_strup(a_continent_str, -1);
    for(int8_t i = 1; i < l_count; i++) {
        // convert to to upper case
        char *l_server_continents = dap_strup(s_server_continents[i], -1);
        // compare strings in upper case
        if(!dap_strcmp(l_continent_str, l_server_continents)) {
            DAP_DELETE(l_server_continents);
            DAP_DELETE(l_continent_str);
            return i;
        }
        DAP_DELETE(l_server_continents);
    }
    DAP_DELETE(l_continent_str);
    // none
    return 0;
}

char * dap_chain_net_srv_order_create(
        dap_chain_net_t * a_net,
        dap_chain_net_srv_order_direction_t a_direction,
        dap_chain_net_srv_uid_t a_srv_uid, // Service UID
        dap_chain_node_addr_t a_node_addr, // Node address that servs the order (if present)
        dap_chain_hash_fast_t a_tx_cond_hash, // Hash index of conditioned transaction attached with order
        uint256_t *a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        const char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        dap_time_t a_expires, // TS when the service expires
        const uint8_t *a_ext,
        uint32_t a_ext_size,
        uint64_t a_units,
        const char *a_region,
        int8_t a_continent_num,
        dap_enc_key_t *a_key
        )
{
    dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_compose(a_net, a_direction, a_srv_uid, a_node_addr, a_tx_cond_hash, a_price,
                                                                         a_price_unit, a_price_ticker, a_expires, a_ext, a_ext_size, a_units,
                                                                         a_region, a_continent_num, a_key);
    if (!l_order)
        return NULL;
    char *l_ret = dap_chain_net_srv_order_save(a_net, l_order, false);
    DAP_DELETE(l_order);
    return l_ret;
}

dap_chain_net_srv_order_t *dap_chain_net_srv_order_compose(dap_chain_net_t *a_net,
        dap_chain_net_srv_order_direction_t a_direction,
        dap_chain_net_srv_uid_t a_srv_uid, // Service UID
        dap_chain_node_addr_t a_node_addr, // Node address that servs the order (if present)
        dap_chain_hash_fast_t a_tx_cond_hash, // Hash index of conditioned transaction attached with order
        uint256_t *a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        const char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        dap_time_t a_expires, // TS when the service expires
        const uint8_t *a_ext,
        uint32_t a_ext_size,
        uint64_t a_units,
        const char *a_region,
        int8_t a_continent_num,
        dap_enc_key_t *a_key
        )
{
    UNUSED(a_expires);
     // Order must have network & sign
    if (!a_net) {
        log_it(L_WARNING, "Order mast have a network");
        return NULL;
    }
    if (!a_key) {
        log_it(L_WARNING, "The key with which the order should be signed is not specified.");
        return NULL;
    }
    dap_chain_net_srv_order_t *l_order;
    if (a_ext_size) {
        l_order = (dap_chain_net_srv_order_t *)DAP_NEW_Z_SIZE(void, sizeof(dap_chain_net_srv_order_t) + a_ext_size);
        if (!l_order) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            return NULL;
        }
        memcpy(l_order->ext_n_sign, a_ext, a_ext_size);
        l_order->ext_size = a_ext_size;
    }
    else {
        l_order = DAP_NEW_Z(dap_chain_net_srv_order_t);
        if (!l_order) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            return NULL;
        }
        dap_chain_net_srv_order_set_continent_region(&l_order, a_continent_num, a_region);
    }

    l_order->version = 3;
    l_order->srv_uid = a_srv_uid;
    l_order->direction = a_direction;
    l_order->ts_created = dap_time_now();

    if ( a_node_addr.uint64)
        l_order->node_addr.uint64 = a_node_addr.uint64;

    l_order->tx_cond_hash = a_tx_cond_hash;
    l_order->price = *a_price;
    l_order->price_unit.uint32 = a_price_unit.uint32;

    if ( a_price_ticker)
        strncpy(l_order->price_ticker, a_price_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_order->units = a_units;
    dap_sign_t *l_sign = dap_sign_create(a_key, l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size, 0);
    if (!l_sign) {
        DAP_DELETE(l_order);
        return NULL;
    }
    size_t l_sign_size = dap_sign_get_size(l_sign); // sign data
    l_order = DAP_REALLOC(l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size + l_sign_size);
    memcpy(l_order->ext_n_sign + l_order->ext_size, l_sign, l_sign_size);
    return l_order;
}

/**
 * @brief dap_chain_net_srv_order_update
 * @param a_net
 * @param a_order
 * @return
 */
char *dap_chain_net_srv_order_save(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_order, bool a_common)
{
    if (!a_net || !a_order)
        return NULL;
    dap_chain_hash_fast_t l_order_hash;
    size_t l_order_size = dap_chain_net_srv_order_get_size(a_order);
    dap_hash_fast(a_order, l_order_size, &l_order_hash);
    const char *l_order_hash_str = dap_chain_hash_fast_to_str_static(&l_order_hash);
    char *l_gdb_group_str = a_common ? dap_chain_net_srv_order_get_common_group(a_net)
                                     : dap_chain_net_srv_order_get_gdb_group(a_net);
    if (!l_gdb_group_str)
        return NULL;
    int l_rc = dap_global_db_set_sync(l_gdb_group_str, l_order_hash_str, a_order, l_order_size, false);
    DAP_DELETE(l_gdb_group_str);
    return l_rc == DAP_GLOBAL_DB_RC_SUCCESS ? dap_strdup(l_order_hash_str) : NULL;
}

dap_chain_net_srv_order_t *dap_chain_net_srv_order_read(byte_t *a_order, size_t a_order_size)
{
    if (NULL == a_order) {
        log_it(L_ERROR, "Argumets are NULL for dap_chain_net_srv_order_read");
        return NULL;
    }
    dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)a_order;
    size_t l_order_size = dap_chain_net_srv_order_get_size((dap_chain_net_srv_order_t *)a_order);
    if (l_order->version > 3 || l_order->direction > SERV_DIR_SELL || l_order_size != a_order_size)
        return NULL;
    if (l_order->version == 3)
        return DAP_DUP_SIZE(a_order, l_order_size);
    dap_chain_net_srv_order_old_t *l_old = (dap_chain_net_srv_order_old_t *)a_order;
    size_t l_ret_size = dap_chain_net_srv_order_get_size((dap_chain_net_srv_order_t *)l_old) +
                            sizeof(dap_chain_net_srv_order_t) - sizeof(dap_chain_net_srv_order_old_t);
    if (l_old->version == 1)
        l_ret_size += sizeof(dap_sign_type_t);
    dap_chain_net_srv_order_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_net_srv_order_t, l_ret_size);
    l_ret->version = 3;
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    l_ret->srv_uid.uint64 = l_old->srv_uid.uint64;
#else
    l_ret->srv_uid.uint128 = dap_chain_uint128_from(l_old->srv_uid.uint64);
#endif
    l_ret->direction = l_old->direction;
    l_ret->node_addr.uint64 = l_old->node_addr.uint64;
    l_ret->tx_cond_hash = l_old->tx_cond_hash;
    l_ret->price_unit.uint32 = l_old->price_unit.uint32;
    l_ret->ts_created = l_old->ts_created;
    l_ret->ts_expires = l_old->ts_expires;
    l_ret->price = dap_chain_uint256_from(l_old->price);
    strncpy(l_ret->price_ticker, l_old->price_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    l_ret->ext_size = l_old->ext_size;
    memcpy(l_ret->ext_n_sign, l_old->ext, l_old->ext_size);
    dap_sign_t *l_sign = (dap_sign_t *)&l_old->ext[l_old->ext_size];
    size_t l_sign_size = l_old->version == 1 ? 0 : dap_sign_get_size(l_sign);
    if (l_sign_size)
        memcpy(l_ret->ext_n_sign + l_ret->ext_size, l_sign, l_sign_size);
    else
        ((dap_sign_type_t *)(l_ret->ext_n_sign + l_ret->ext_size))->type = SIG_TYPE_NULL;
    return l_ret;
}


/**
 * @brief dap_chain_net_srv_order_find_by_hash_str
 * @param a_net
 * @param a_hash_str
 * @return
 */
dap_chain_net_srv_order_t *dap_chain_net_srv_order_find_by_hash_str(dap_chain_net_t *a_net, const char *a_hash_str)
{
    dap_chain_net_srv_order_t *l_order = NULL;
    for (int i = 0; a_net && a_hash_str && i < 2; i++) {
        char *l_gdb_group_str = i ? dap_chain_net_srv_order_get_gdb_group(a_net)
                                  : dap_chain_net_srv_order_get_common_group(a_net);
        size_t l_order_size = 0;
        byte_t *l_gdb_order = dap_global_db_get_sync(l_gdb_group_str, a_hash_str, &l_order_size, NULL, NULL);
        DAP_DELETE(l_gdb_group_str);
        if (!l_gdb_order)
            continue;
        // check order size
        size_t l_expected_size = dap_chain_net_srv_order_get_size((dap_chain_net_srv_order_t *)l_gdb_order);
        if (l_order_size != l_expected_size) {
            log_it(L_ERROR, "Found wrong size order %zu, expected %zu", l_order_size, l_expected_size);
            DAP_DELETE(l_gdb_order);
            return NULL;
        }
        l_order = dap_chain_net_srv_order_read(l_gdb_order, l_order_size);
        if (!l_order || (l_order->ts_expires &&  l_order->ts_expires < dap_time_now())){
            DAP_DEL_Z(l_order);
            DAP_DELETE(l_gdb_order);
            continue;
        }
        DAP_DELETE(l_gdb_order);
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
                                        const dap_chain_net_srv_uid_t a_srv_uid,
                                        const dap_chain_net_srv_price_unit_uid_t a_price_unit,const char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                        const uint256_t a_price_min, const uint256_t a_price_max,
                                        dap_list_t** a_output_orders, size_t * a_output_orders_count)
{
    if (!a_net || !a_output_orders || !a_output_orders_count)
        return -1;
    size_t l_orders_size = 0, l_output_orders_count = 0;
    *a_output_orders = NULL;

    dap_list_t* l_out_list = NULL;

    for (int i = 0; i < 2; i++) {
        char *l_gdb_group_str = i ? dap_chain_net_srv_order_get_gdb_group(a_net)
                                  : dap_chain_net_srv_order_get_common_group(a_net);
        size_t l_orders_count = 0;
        dap_global_db_obj_t *l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
        log_it( L_DEBUG, "Loaded %zu orders", l_orders_count);
        dap_chain_net_srv_order_t *l_order = NULL;
        for (size_t i = 0; i < l_orders_count; i++) {
            l_order = dap_chain_net_srv_order_read(l_orders[i].value, l_orders[i].value_len);
            if (!l_order) {
                dap_global_db_del_sync(l_gdb_group_str, l_orders[i].key);
                continue; // order is corrupted
            }
            if (l_order->ts_expires && l_order->ts_expires < dap_time_now()){
                DAP_DEL_Z(l_order);
                continue;
            }

            dap_chain_hash_fast_t l_hash, l_hash_gdb;
            dap_hash_fast(l_orders[i].value, l_orders[i].value_len, &l_hash);
            dap_chain_hash_fast_from_str(l_orders[i].key, &l_hash_gdb);
            if (memcmp(&l_hash, &l_hash_gdb, sizeof(dap_chain_hash_fast_t))) {
                dap_global_db_del_sync(l_gdb_group_str, l_orders[i].key);
                DAP_DEL_Z(l_order);
                continue; // order is corrupted
            }
            // Check direction
            if (a_direction != SERV_DIR_UNDEFINED && l_order->direction != a_direction){
                DAP_DEL_Z(l_order);
                continue;
            }
            // Check srv uid
            if (a_srv_uid.uint64 && l_order->srv_uid.uint64 != a_srv_uid.uint64){
                DAP_DEL_Z(l_order);
                continue;
            }
            // check price unit
            if (a_price_unit.uint32 && a_price_unit.uint32 != l_order->price_unit.uint32){
                DAP_DEL_Z(l_order);
                continue;
            }
            // Check price minimum
            if (!IS_ZERO_256(a_price_min) && compare256(l_order->price, a_price_min) == -1){
                DAP_DEL_Z(l_order);
                continue;
            }
            // Check price maximum
            if (!IS_ZERO_256(a_price_max) && compare256(l_order->price, a_price_max) == 1){
                DAP_DEL_Z(l_order);
                continue;
            }
            // Check ticker
            if (a_price_ticker && strcmp( l_order->price_ticker, a_price_ticker)){
                DAP_DEL_Z(l_order);
                continue;
            }
            size_t l_order_mem_size = dap_chain_net_srv_order_get_size(l_order);
            dap_chain_net_srv_order_t *l_output_order = DAP_DUP_SIZE(l_order, l_order_mem_size);
            DAP_DEL_Z(l_order);
            l_out_list = dap_list_append(l_out_list, l_output_order);
            l_output_orders_count++;
        }
        dap_global_db_objs_delete(l_orders, l_orders_count);
        DAP_DELETE(l_gdb_group_str);
    }
    *a_output_orders_count = l_output_orders_count;
    *a_output_orders = l_out_list;
    return 0;
}

/**
 * @brief dap_chain_net_srv_order_delete_by_hash_str
 * @param a_net
 * @param a_hash_str
 * @return
 */
int dap_chain_net_srv_order_delete_by_hash_str_sync(dap_chain_net_t *a_net, const char *a_hash_str, dap_enc_key_t *a_key)
{
    int l_ret = -2;
    if(a_key){
        return l_ret;
    }

    dap_chain_net_srv_order_t *l_order = NULL;
    for (int i = 0; a_net && a_hash_str && i < 2; i++) {
        char *l_gdb_group_str = i ? dap_chain_net_srv_order_get_gdb_group(a_net)
                                  : dap_chain_net_srv_order_get_common_group(a_net);

        size_t l_order_size = 0;
        byte_t *l_gdb_order = dap_global_db_get_sync(l_gdb_group_str, a_hash_str, &l_order_size, NULL, NULL);
        if (!l_gdb_order){
            DAP_DELETE(l_gdb_group_str);
            continue;
        }
            
        // check order size
        size_t l_expected_size = dap_chain_net_srv_order_get_size((dap_chain_net_srv_order_t *)l_gdb_order);
        if (l_order_size != l_expected_size) {
            log_it(L_ERROR, "Found wrong size order %zu, expected %zu", l_order_size, l_expected_size);
            DAP_DELETE(l_gdb_order);
            DAP_DELETE(l_gdb_group_str);
            return -1;
        }
        l_order = dap_chain_net_srv_order_read(l_gdb_order, l_order_size);
        if (l_order->ts_expires && l_order->ts_expires < dap_time_now()){
            DAP_DEL_Z(l_order);
            DAP_DELETE(l_gdb_order);
            DAP_DELETE(l_gdb_group_str);
            continue;
        }
        DAP_DELETE(l_gdb_order);

        
        dap_pkey_t *l_pkey_new = dap_pkey_from_enc_key(a_key);
        if(!l_pkey_new){
            DAP_DEL_Z(l_order);
            DAP_DELETE(l_gdb_order);
            DAP_DELETE(l_gdb_group_str);
            continue;
        }


        if (dap_pkey_compare_with_sign(l_pkey_new, (dap_sign_t*)(l_order->ext_n_sign + l_order->ext_size))){
            log_it(L_ERROR, "Pkeys in cert and order sign doesn't match");
            DAP_DEL_Z(l_order);
            DAP_DELETE(l_gdb_order);
            DAP_DELETE(l_gdb_group_str);
            continue;
        }

        l_order = DAP_REALLOC(l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size);

        l_order->ts_expires = dap_time_now();

        dap_sign_t *l_sign = dap_sign_create(a_key, l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size, 0);
        if (!l_sign) {
            DAP_DEL_Z(l_order);
            DAP_DELETE(l_gdb_order);
            DAP_DELETE(l_gdb_group_str);
            continue;
        }
        size_t l_sign_size = dap_sign_get_size(l_sign); // sign data
        l_order = DAP_REALLOC(l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size + l_sign_size);
        memcpy(l_order->ext_n_sign + l_order->ext_size, l_sign, l_sign_size);

        int l_ret = dap_global_db_set_sync(l_gdb_group_str, a_hash_str, l_order, l_order_size, false);
        DAP_DELETE(l_gdb_group_str);
    }
    return l_ret;
}

/**
 * @brief dap_chain_net_srv_order_dump_to_string
 * @param a_orders
 * @param a_str_out
 */
void dap_chain_net_srv_order_dump_to_string(dap_chain_net_srv_order_t *a_order,dap_string_t * a_str_out, const char *a_hash_out_type, const char *a_native_ticker)
{
    if (a_order && a_str_out ){
        dap_chain_hash_fast_t l_hash;
        dap_hash_fast(a_order, dap_chain_net_srv_order_get_size(a_order), &l_hash);
        const char *l_hash_str = dap_strcmp(a_hash_out_type,"hex")
                ? dap_enc_base58_encode_hash_to_str_static(&l_hash)
                : dap_chain_hash_fast_to_str_static(&l_hash);

        dap_string_append_printf(a_str_out, "== Order %s ==\n", l_hash_str);
        dap_string_append_printf(a_str_out, "  version:          %u\n", a_order->version );

        switch ( a_order->direction) {
        case SERV_DIR_UNDEFINED:    dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_UNDEFINED\n" );   break;
        case SERV_DIR_SELL:         dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_SELL\n" );        break;
        case SERV_DIR_BUY:          dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_BUY\n" );         break;
        }
        char buf_time[DAP_TIME_STR_SIZE];
        dap_time_to_str_rfc822(buf_time, DAP_TIME_STR_SIZE, a_order->ts_created);
        dap_string_append_printf(a_str_out, "  created:          %s\n", buf_time);
        dap_string_append_printf(a_str_out, "  srv_uid:          0x%016"DAP_UINT64_FORMAT_X"\n", a_order->srv_uid.uint64 );
        
        char *l_balance_coins, *l_balance = dap_uint256_to_char(a_order->price, &l_balance_coins);
        dap_string_append_printf(a_str_out, "  price:            %s (%s)\n", l_balance_coins, l_balance);
        dap_string_append_printf(a_str_out, "  price_token:      %s\n",  (*a_order->price_ticker) ? a_order->price_ticker: a_native_ticker);
        dap_string_append_printf(a_str_out, "  units:            %zu\n", a_order->units);
        if( a_order->price_unit.uint32 )
            dap_string_append_printf(a_str_out, "  price_unit:       %s\n", dap_chain_net_srv_price_unit_uid_to_str(a_order->price_unit) );
        if ( a_order->node_addr.uint64)
            dap_string_append_printf(a_str_out, "  node_addr:        "NODE_ADDR_FP_STR"\n", NODE_ADDR_FP_ARGS_S(a_order->node_addr) );

        char *l_region = NULL;
        uint8_t l_continent_num = 0;
        const char *l_continent_str = NULL;
        if(dap_chain_net_srv_order_get_continent_region(a_order, &l_continent_num, &l_region))
            l_continent_str = dap_chain_net_srv_order_continent_to_str(l_continent_num);
        dap_string_append_printf(a_str_out, "  node_location:    %s - %s\n", l_continent_str ? l_continent_str : "None" , l_region ? l_region : "None");
        DAP_DELETE(l_region);

        l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(&a_order->tx_cond_hash)
                : dap_chain_hash_fast_to_str_static(&a_order->tx_cond_hash);
        dap_string_append_printf(a_str_out, "  tx_cond_hash:     %s\n", l_hash_str );
        char *l_ext_out = a_order->ext_size ? DAP_NEW_Z_SIZE(char, a_order->ext_size * 2 + 1) : NULL;
        if(l_ext_out) {
            dap_bin2hex(l_ext_out, a_order->ext_n_sign, a_order->ext_size);
            dap_string_append_printf(a_str_out, "  ext:              0x%s\n", l_ext_out);
        }
        else
            dap_string_append_printf(a_str_out, "  ext:              0x0\n");
        dap_sign_t *l_sign = (dap_sign_t*)((byte_t*)a_order->ext_n_sign + a_order->ext_size);
        dap_hash_fast_t l_sign_pkey = {0};
        dap_sign_get_pkey_hash(l_sign, &l_sign_pkey);
        const char *l_sign_pkey_hash_str = dap_hash_fast_to_str_static(&l_sign_pkey);
        dap_string_append_printf(a_str_out, "  pkey:             %s\n", l_sign_pkey_hash_str);
        DAP_DELETE(l_ext_out);
    }
}

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

static dap_list_t *s_order_notify_callbacks = NULL;
static void s_srv_order_callback_notify(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg);


static dap_timerfd_t *s_timer_order_check_decree_sign = NULL;
static void s_srv_order_check_decree_sign_timer() {
    uint32_t l_unverified_orders_lifetime = dap_config_get_item_uint32_default(g_config, "srv", "unverified_orders_lifetime", 21600);
    dap_time_t l_time_cut_off = dap_time_now();
    l_time_cut_off -= l_unverified_orders_lifetime; // 6 Hours;
    uint16_t l_net_count = 0;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        if (dap_chain_net_get_role(l_net_list[i]).enums == NODE_ROLE_MASTER) {
            char *l_order_group = dap_chain_net_srv_order_get_gdb_group(l_net_list[i]);
            size_t l_order_count = 0;
            dap_global_db_obj_t *l_orders = dap_global_db_get_all_sync(l_order_group, &l_order_count);
            for (size_t j = 0; j < l_order_count; j++) {
                dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *) (l_orders[j].value);
                if (!l_order)
                    continue;
                if (l_order->ts_created < l_time_cut_off) {
                    dap_sign_t *l_sign = (dap_sign_t *) (l_order->ext_n_sign + l_order->ext_size);
                    dap_hash_fast_t l_sign_pkey_hash = {0};
                    dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                    dap_chain_addr_t l_signed_addr = {0};
                    dap_chain_addr_fill(&l_signed_addr, l_sign->header.type, &l_sign_pkey_hash, l_net_list[i]->pub.id);
                    if (!dap_chain_net_srv_stake_key_delegated(&l_signed_addr)) {
                        char *l_pkey_hash_str = dap_hash_fast_to_str_new(&l_sign_pkey_hash);
                        log_it(L_NOTICE, "Order %s signed by the non-delegated public key %s. Order deleted",
                               l_orders[j].key,
                               l_pkey_hash_str);
                        DAP_DELETE(l_pkey_hash_str);
                        dap_global_db_del(l_order_group, l_orders[j].key, NULL, NULL);
                    }
                }
            }
            dap_global_db_objs_delete(l_orders, l_order_count);
            DAP_DELETE(l_order_group);
        }
    }
    DAP_DELETE(l_net_list);
}

/**
 * @brief dap_chain_net_srv_order_init
 * @return
 */
int dap_chain_net_srv_order_init()
{
    uint16_t l_net_count = 0;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        dap_chain_net_add_gdb_notify_callback(l_net_list[i], s_srv_order_callback_notify, l_net_list[i]);
    }
    //geoip_info_t *l_ipinfo = chain_net_geoip_get_ip_info("8.8.8.8");
    if (!dap_config_get_item_bool_default(g_config, "srv", "allow_unverified_orders", true)) {
        uint32_t l_unverified_orders_lifetime = dap_config_get_item_uint32_default(g_config, "srv", "unverified_orders_lifetime", 21600); // 6 Hours
        s_timer_order_check_decree_sign = dap_interval_timer_create(l_unverified_orders_lifetime * 1000,
                                                                    (dap_timer_callback_t)s_srv_order_check_decree_sign_timer,
                                                                    NULL);
    } else {
        log_it(L_DEBUG, "A mode is enabled that disables verification that the signature was put by "
                        "the node by the validator.");
    }
    DAP_DELETE(l_net_list);
    return 0;
}

/**
 * @brief dap_chain_net_srv_order_deinit
 */
void dap_chain_net_srv_order_deinit()
{
    dap_list_free_full(s_order_notify_callbacks, NULL);
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
        log_it(L_CRITICAL, "Memory allocation error");
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
            log_it(L_CRITICAL, "Memory allocation error");
            return NULL;
        }
        memcpy(l_order->ext_n_sign, a_ext, a_ext_size);
        l_order->ext_size = a_ext_size;
    }
    else {
        l_order = DAP_NEW_Z(dap_chain_net_srv_order_t);
        if (!l_order) {
            log_it(L_CRITICAL, "Memory allocation error");
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
    char *l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_order_hash);
    if (!l_order_hash_str)
        return NULL;
    char *l_gdb_group_str = a_common ? dap_chain_net_srv_order_get_common_group(a_net)
                                     : dap_chain_net_srv_order_get_gdb_group(a_net);
    if (!l_gdb_group_str)
        return NULL;
    int l_rc = dap_global_db_set_sync(l_gdb_group_str, l_order_hash_str, a_order, l_order_size, true);
    DAP_DELETE(l_gdb_group_str);
    if (l_rc != DAP_GLOBAL_DB_RC_SUCCESS)
        DAP_DEL_Z(l_order_hash_str);
    return l_order_hash_str;
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
int dap_chain_net_srv_order_delete_by_hash_str_sync(dap_chain_net_t *a_net, const char *a_hash_str)
{
    int l_ret = -2;
    bool l_is_found = false;
    for (int i = 0; a_net && a_hash_str && i < 2; i++) {
        char *l_gdb_group_str = i ? dap_chain_net_srv_order_get_gdb_group(a_net)
                                  : dap_chain_net_srv_order_get_common_group(a_net);

        size_t l_order_size = 0;
        byte_t *l_gdb_order = dap_global_db_get_sync(l_gdb_group_str, a_hash_str, &l_order_size, NULL, NULL);
        if (!l_gdb_order){
            log_it(L_NOTICE, "Record with key %s not found in group %s  ", a_hash_str, l_gdb_group_str);
            DAP_DELETE(l_gdb_group_str);
            continue;
        }
        l_is_found = true;    
        // check order size
        size_t l_expected_size = dap_chain_net_srv_order_get_size((dap_chain_net_srv_order_t *)l_gdb_order);
        if (l_order_size != l_expected_size) {
            log_it(L_ERROR, "Found wrong size order %zu, expected %zu", l_order_size, l_expected_size);
            DAP_DELETE(l_gdb_order);
            DAP_DELETE(l_gdb_group_str);
            return -1;
        }

        char *l_removed_orders_group_str = dap_chain_net_srv_order_removed_get_gdb_group(a_net);
        l_ret = dap_global_db_set_sync(l_removed_orders_group_str, a_hash_str, NULL, 0, true);

        dap_global_db_del_sync(l_gdb_group_str, a_hash_str);

        DAP_DELETE(l_gdb_group_str);
        DAP_DELETE(l_removed_orders_group_str);
    }

    return l_is_found ? l_ret: -3;
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
        char *l_hash_str = dap_strcmp(a_hash_out_type,"hex")
                ? dap_enc_base58_encode_hash_to_str(&l_hash)
                : dap_chain_hash_fast_to_str_new(&l_hash);

        dap_string_append_printf(a_str_out, "== Order %s ==\n", l_hash_str);
        dap_string_append_printf(a_str_out, "  version:          %u\n", a_order->version );

        switch ( a_order->direction) {
        case SERV_DIR_UNDEFINED:    dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_UNDEFINED\n" );   break;
        case SERV_DIR_SELL:         dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_SELL\n" );        break;
        case SERV_DIR_BUY:          dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_BUY\n" );         break;
        }
        char buf_time[50];
        dap_time_to_str_rfc822(buf_time, 50, a_order->ts_created);
        dap_string_append_printf(a_str_out, "  created:          %s\n", buf_time);

        dap_string_append_printf(a_str_out, "  srv_uid:          0x%016"DAP_UINT64_FORMAT_X"\n", a_order->srv_uid.uint64 );
        char *l_balance_coins = dap_chain_balance_to_coins(a_order->price);
        char *l_balance = dap_chain_balance_print(a_order->price);
        dap_string_append_printf(a_str_out, "  price:            %s (%s)\n", l_balance_coins, l_balance);
        DAP_DELETE(l_balance_coins);
        DAP_DELETE(l_balance);
        dap_string_append_printf(a_str_out, "  price_token:      %s\n", (*a_order->price_ticker) ? a_order->price_ticker : a_native_ticker);
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
        DAP_DELETE(l_hash_str);

        l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str(&a_order->tx_cond_hash)
                : dap_chain_hash_fast_to_str_new(&a_order->tx_cond_hash);
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
        char *l_sign_pkey_hash_str = dap_hash_fast_to_str_new(&l_sign_pkey);
        dap_string_append_printf(a_str_out, "  pkey:             %s\n", l_sign_pkey_hash_str);
        DAP_DELETE(l_sign_pkey_hash_str);
        // order state
/*        {
            int l_order_state = get_order_state(a_order->node_addr);
            // if order is not tested
            if(l_order_state == -1)
                dap_string_append_printf(a_str_out, "        \"State\":\"unknown\"\n");
            // if order off-line
            else if(l_order_state == 1)
                dap_string_append_printf(a_str_out, "        \"State\":\"available\"\n");
            // if order on-line
            else
                dap_string_append_printf(a_str_out, "        \"State\":\"not available\"\n");
        }*/
        DAP_DELETE(l_hash_str);
        DAP_DELETE(l_ext_out);
    }
}

static void s_srv_order_callback_notify(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg)
{
    if (!a_arg || !a_obj || !a_obj->key)
        return;
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    dap_global_db_context_t * l_gdb_context = dap_global_db_context_current();
    if (!l_gdb_context) {
        log_it(L_ATT, "[!] GDB context not found in LTS");
        l_gdb_context = a_context;
    }
    assert(l_net);
    assert(l_gdb_context);

    char *l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);

    if (!dap_strcmp(a_obj->group, l_gdb_group_str)) {
        char *l_gdb_removed_orders_group_str = dap_chain_net_srv_order_removed_get_gdb_group(l_net);
        dap_store_obj_t *l_gdb_order = dap_global_db_get_raw_sync(l_gdb_removed_orders_group_str, a_obj->key);
        if (l_gdb_order){
            dap_global_db_driver_delete(a_obj, 1);
            return;
        }


        for (dap_list_t *it = s_order_notify_callbacks; it; it = it->next) {
            struct dap_order_notify *l_notifier = (struct dap_order_notify *)it->data;
            if ((l_notifier->net == NULL || l_notifier->net == l_net) &&
                        l_notifier->callback) {
                l_notifier->callback(a_context, a_obj, l_notifier->cb_arg);
            }
        }
        bool l_allow_unsigned_orders = dap_config_get_item_bool_default(g_config, "srv", "allow_unsigned_orders", false);
        if (a_obj->value && a_obj->type == DAP_DB$K_OPTYPE_ADD) {
            dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)a_obj->value;
            if (sizeof(dap_chain_net_srv_order_t) + l_order->ext_size > a_obj->value_len) {
                log_it(L_ERROR, "Order is broken, size mismatch (%zu > %zu)",
                       sizeof(dap_chain_net_srv_order_t) + l_order->ext_size,
                       a_obj->value_len);
                dap_global_db_del_unsafe(l_gdb_context, a_obj->group, a_obj->key);
            } else if (l_order->version != 3) {
                log_it(L_NOTICE, "Order %s removed version != 3.", a_obj->key);
                dap_global_db_del_unsafe(l_gdb_context, a_obj->group, a_obj->key);
            } else {
                if (l_allow_unsigned_orders) {
                    log_it(L_DEBUG, "The mode that disables verification of the order signature is enabled.");
                } else {
                    dap_sign_t *l_sign = (dap_sign_t *) (l_order->ext_n_sign + l_order->ext_size);
                    size_t l_max_size = a_obj->value_len - sizeof(dap_chain_net_srv_order_t) - l_order->ext_size;
                    int l_verify = dap_sign_verify_all(l_sign, l_max_size, l_order,
                                                       sizeof(dap_chain_net_srv_order_t) + l_order->ext_size);
                    if (l_verify) {
                        log_it(L_ERROR, "Order unverified, err %d", l_verify);
                        dap_global_db_del_unsafe(l_gdb_context, a_obj->group, a_obj->key);
                    }
                }
            }
        }
    }

    DAP_DELETE(l_gdb_group_str);
}

void dap_chain_net_srv_order_add_notify_callback(dap_chain_net_t *a_net, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    struct dap_order_notify *l_notifier = DAP_NEW(struct dap_order_notify);
    if (!l_notifier) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_notifier->net = a_net;
    l_notifier->callback = a_callback;
    l_notifier->cb_arg = a_cb_arg;
    s_order_notify_callbacks = dap_list_append(s_order_notify_callbacks, l_notifier);
}

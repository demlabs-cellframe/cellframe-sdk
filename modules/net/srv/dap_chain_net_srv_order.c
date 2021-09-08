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

#include <stdio.h>
#include <strings.h>

#include "dap_chain_net_srv_order.h"

#include "dap_hash.h"
#include "dap_enc_base58.h"
#include "dap_chain_global_db.h"
#include "dap_chain_net_srv_countries.h"
#if DAP_SRV_STAKE_USED
#include "dap_chain_net_srv_stake.h"
#else
static bool dap_chain_net_srv_stake_key_delegated() { return false; }
#endif
//#include "dap_chain_net_srv_geoip.h"

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

static void s_srv_order_callback_notify(void *a_arg, const char a_op_code, const char *a_group,
                                   const char *a_key, const void *a_value, const size_t a_value_len);

/**
 * @brief dap_chain_net_srv_order_init
 * @return
 */
int dap_chain_net_srv_order_init(void)
{
    dap_chain_net_set_srv_callback_notify(s_srv_order_callback_notify);
	//geoip_info_t *l_ipinfo = chain_net_geoip_get_ip_info("8.8.8.8");
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
    if (a_order->version > 1) {
        dap_sign_t *l_sign = (dap_sign_t *)&a_order->ext[a_order->ext_size];
        l_sign_size = dap_sign_get_size(l_sign);
    }
    return sizeof(dap_chain_net_srv_order_t) + a_order->ext_size + l_sign_size;
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
    l_order->ext[0] =0x52;
    if(a_continent_num > 0)
        memcpy(l_order->ext + 1, &a_continent_num, sizeof(uint8_t));
    else
        memcpy(l_order->ext + 1, &l_continent_num_prev, sizeof(uint8_t));
    if(a_region)
        memcpy(l_order->ext + 1 + sizeof(uint8_t), a_region, strlen(a_region) + 1);
    else if(l_region_prev)
        memcpy(l_order->ext + 1 + sizeof(uint8_t), l_region_prev, strlen(l_region_prev) + 1);
    //dap_sprintf(l_order->ext, "\52%d-%s", a_continent_num, a_region);
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
    if(!a_order_static || !a_order_static->ext_size || a_order_static->ext[0]!=0x52)
        return false;
    if(a_continent_num) {
       if((uint8_t)a_order_static->ext[1]!=0xff)
           memcpy(a_continent_num, a_order_static->ext + 1, sizeof(uint8_t));
        else
           a_continent_num = 0;
    }
    if(a_region) {
        size_t l_size = a_order_static->ext_size - sizeof(uint8_t) - 1;
        if(l_size > 0) {
            *a_region = DAP_NEW_SIZE(char, l_size);
            memcpy(*a_region, a_order_static->ext + 1 + sizeof(uint8_t), l_size);
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
        uint64_t a_price, //  service price in datoshi, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
        dap_chain_net_srv_price_unit_uid_t a_price_unit, // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
        const char a_price_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        dap_chain_time_t a_expires, // TS when the service expires
        const uint8_t *a_ext,
        uint32_t a_ext_size,
        const char *a_region,
        int8_t a_continent_num,
        dap_enc_key_t *a_key
        )
{
    UNUSED(a_expires);
    if (a_net) {
        dap_chain_net_srv_order_t *l_order;
        if (a_ext_size) {
            l_order = (dap_chain_net_srv_order_t *)DAP_NEW_Z_SIZE(void, sizeof(dap_chain_net_srv_order_t) + a_ext_size);
            memcpy(l_order->ext, a_ext, a_ext_size);
            l_order->ext_size = a_ext_size;
        }
        else {
            l_order = DAP_NEW_Z(dap_chain_net_srv_order_t);
            dap_chain_net_srv_order_set_continent_region(&l_order, a_continent_num, a_region);
        }

        dap_chain_hash_fast_t l_order_hash;
        l_order->version = a_key ? 2 : 1;
        l_order->srv_uid = a_srv_uid;
        l_order->direction = a_direction;
        l_order->ts_created = (dap_chain_time_t) time(NULL);


        if ( a_node_addr.uint64)
            l_order->node_addr.uint64 = a_node_addr.uint64;

        memcpy(&l_order->tx_cond_hash, &a_tx_cond_hash, DAP_CHAIN_HASH_FAST_SIZE);
        l_order->price = a_price;
        l_order->price_unit.uint32 = a_price_unit.uint32;

        if ( a_price_ticker)
            strncpy(l_order->price_ticker, a_price_ticker,sizeof(l_order->price_ticker)-1);
        if (a_key) {
            dap_sign_t *l_sign = dap_sign_create(a_key, l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size, 0);
            if (!l_sign) {
                return NULL;
            }
            size_t l_sign_size = dap_sign_get_size(l_sign); // sign data
            l_order = DAP_REALLOC(l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size + l_sign_size);
            memcpy(&l_order->ext[l_order->ext_size], l_sign, l_sign_size);
            DAP_DELETE(l_sign);
        }
        size_t l_order_size = dap_chain_net_srv_order_get_size(l_order);
        dap_hash_fast( l_order, l_order_size, &l_order_hash );
        char * l_order_hash_str = dap_chain_hash_fast_to_str_new( &l_order_hash );
        char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
        if ( !dap_chain_global_db_gr_set( dap_strdup(l_order_hash_str), l_order, l_order_size, l_gdb_group_str ) ){
            DAP_DELETE( l_order );
            DAP_DELETE( l_gdb_group_str );
            return NULL;
        }
        DAP_DELETE( l_gdb_group_str );
        return  l_order_hash_str;
    }else
        return NULL;
}

/**
 * @brief dap_chain_net_srv_order_update
 * @param a_net
 * @param a_order
 * @return
 */
int dap_chain_net_srv_order_save(dap_chain_net_t * a_net, dap_chain_net_srv_order_t *a_order)
{
    if (!a_net || !a_order)
        return -1;

    dap_chain_hash_fast_t l_order_hash;
    size_t l_order_size = dap_chain_net_srv_order_get_size(a_order);
    dap_hash_fast( a_order, l_order_size, &l_order_hash );
    char * l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_order_hash);
    char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group( a_net);
    if ( !dap_chain_global_db_gr_set(l_order_hash_str, a_order, l_order_size, l_gdb_group_str ) ){
        DAP_DELETE( l_gdb_group_str );
        return -1;
    }
    DAP_DELETE( l_gdb_group_str );
    return 0;
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
        // check order size
        if(l_order_size != dap_chain_net_srv_order_get_size(l_order)) {
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
                                        const dap_chain_net_srv_uid_t a_srv_uid,
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
        size_t l_order_passed_index = 0;
        size_t l_orders_size = 0;
lb_order_pass:
        l_order_passed_index = 0;
        l_orders_size = 0;
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
                size_t l_order_size = dap_chain_net_srv_order_get_size(l_order);
                memcpy((char*)*a_output_orders + l_orders_size, l_order, l_order_size);
                l_orders_size += l_order_size;
            }
            else
                // calc size of all orders
                l_orders_size += dap_chain_net_srv_order_get_size(l_order);
            l_order_passed_index++;

        }
        // Dirty goto usage ho ho ho
        if (l_order_pass_first) {
            l_order_pass_first = false;
            *a_output_orders_count = l_order_passed_index;
            if(l_orders_size)
                *a_output_orders = DAP_NEW_Z_SIZE(dap_chain_net_srv_order_t, l_orders_size);
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
        char * l_hash_str = strdup( a_hash_str );
        ret = dap_chain_global_db_gr_del( l_hash_str, l_gdb_group_str ) ? 0 : -1;
        DAP_DELETE( l_gdb_group_str );
    }
    return ret;
}

/**
 * @brief dap_chain_net_srv_order_dump_to_string
 * @param a_orders
 * @param a_str_out
 */
void dap_chain_net_srv_order_dump_to_string(dap_chain_net_srv_order_t *a_order,dap_string_t * a_str_out, const char *a_hash_out_type)
{
    if (a_order && a_str_out ){
        dap_chain_hash_fast_t l_hash;
        char *l_hash_str;//[DAP_CHAIN_HASH_FAST_SIZE * 2 + 4];
        dap_hash_fast(a_order, dap_chain_net_srv_order_get_size(a_order), &l_hash);
        //dap_chain_hash_fast_to_str(&l_hash,l_hash_str,sizeof(l_hash_str)-1);
        if(!dap_strcmp(a_hash_out_type,"hex"))
            l_hash_str = dap_chain_hash_fast_to_str_new(&l_hash);
        else
            l_hash_str = dap_enc_base58_encode_hash_to_str(&l_hash);

        dap_string_append_printf(a_str_out, "== Order %s ==\n", l_hash_str);
        dap_string_append_printf(a_str_out, "  version:          %u\n", a_order->version );

        switch ( a_order->direction) {
            case SERV_DIR_UNDEFINED: dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_UNDEFINED\n" ); break;
            case SERV_DIR_SELL: dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_SELL\n" ); break;
            case SERV_DIR_BUY: dap_string_append_printf(a_str_out, "  direction:        SERV_DIR_BUY\n" ); break;
        }

        dap_string_append_printf(a_str_out, "  srv_uid:          0x%016llX\n", a_order->srv_uid.uint64 );
        dap_string_append_printf(a_str_out, "  price:           \xA0""%.7Lf (%"DAP_UINT64_FORMAT_U")\n", dap_chain_datoshi_to_coins(a_order->price) , a_order->price);
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

        if(!dap_strcmp(a_hash_out_type, "hex"))
            l_hash_str = dap_chain_hash_fast_to_str_new(&a_order->tx_cond_hash);
        else
            l_hash_str = dap_enc_base58_encode_hash_to_str(&a_order->tx_cond_hash);
        //dap_chain_hash_fast_to_str(&a_order->tx_cond_hash,l_hash_str, sizeof(l_hash_str)-1);
        dap_string_append_printf(a_str_out, "  tx_cond_hash:     %s\n", l_hash_str );
        char *l_ext_out = a_order->ext_size ? DAP_NEW_Z_SIZE(char, a_order->ext_size * 2 + 1) : NULL;
        dap_bin2hex(l_ext_out, a_order->ext, a_order->ext_size);
        if(l_ext_out)
            dap_string_append_printf(a_str_out, "  ext:              0x%s\n", l_ext_out);
        else
            dap_string_append_printf(a_str_out, "  ext:              0x0\n");
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

static void s_srv_order_callback_notify(void *a_arg, const char a_op_code, const char *a_group,
                                   const char *a_key, const void *a_value, const size_t a_value_len)
{
    UNUSED(a_value_len);
    if (!a_arg || !a_value || a_op_code != 'a' || !dap_config_get_item_bool_default(g_config, "srv", "order_signed_only", false)) {
        return;
    }
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    char *l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);
    if (!strcmp(a_group, l_gdb_group_str)) {
        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)a_value;
        if (l_order->version != 2) {
            dap_chain_global_db_gr_del(dap_strdup(a_key), a_group);
        } else {
            dap_sign_t *l_sign = (dap_sign_t *)&l_order->ext[l_order->ext_size];
            if (!dap_sign_verify(l_sign, l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size)) {
                dap_chain_global_db_gr_del(dap_strdup(a_key), a_group);
                DAP_DELETE(l_gdb_group_str);
                return;
            }
            dap_chain_hash_fast_t l_pkey_hash;
            if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash)) {
                dap_chain_global_db_gr_del(dap_strdup(a_key), a_group);
                DAP_DELETE(l_gdb_group_str);
                return;
            }
            dap_chain_addr_t l_addr = {};
            dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, l_net->pub.id);
            uint128_t l_balance = dap_chain_ledger_calc_balance(l_net->pub.ledger, &l_addr, l_order->price_ticker);
            uint64_t l_solvency = dap_chain_uint128_to(l_balance);
            if (l_solvency < l_order->price && !dap_chain_net_srv_stake_key_delegated(&l_addr)) {
                dap_chain_global_db_gr_del(dap_strdup(a_key), a_group);
            }
        }
        DAP_DELETE(l_gdb_group_str);
    }
}

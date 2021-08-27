/*
 * Authors:
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2020
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
#include <stddef.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_client_http.h"
#include "dap_chain_net_srv_geoip.h"
#include "libmaxminddb/maxminddb.h"

#define LOG_TAG "chain_net_srv_geoip"
#define LOCALE_DEFAULT  "en"


static char *s_geoip_db_file_path = NULL; // share/geoip/GeoLite2-City.mmdb

/**
 * @brief m_request_response
 * @param a_response
 * @param a_response_size
 * @param a_obj
 */
static void m_request_getip_response(void * a_response, size_t a_response_size, void * a_obj)
{
    char *l_addr = (char *) a_obj;
    //printf("m_request_getip_response %s\n", a_response);
}

static void m_request_getip_request_error(int a_err_code, void *a_obj)
{
    char *l_addr = (char *) a_obj;
    //printf("m_request_getip_request_error %s\n", l_addr);
}

geoip_info_t *chain_net_geoip_get_ip_info_by_web(const char *a_ip_str)
{
    // https://geoip.maxmind.com/geoip/v2.1/insights/<ip>
	// https://geoip.maxmind.com/geoip/v2.1/city/<ip>
    char *l_path = dap_strdup_printf("geoip/v2.1/insights/%s", a_ip_str);
    //104.16.38.47:443
    // geoip.maxmind.com
    char l_out[40];
    //Account/User ID        288651
    //License key
    // https://dev.maxmind.com/geoip/geoip2/web-services/
    const char *user_id = "288651";
    const char *license_key = "1JGvRmd3Ux1kcBkb";
    char *l_auth = dap_strdup_printf("%s:%s", user_id, license_key);
    size_t l_out_len = dap_enc_base64_encode(l_auth, strlen(l_auth), l_out, DAP_ENC_DATA_TYPE_B64);
    size_t l_size_req = l_out_len > 0 ? l_out_len + 32 : 0;
    char * l_custom = l_out_len > 0 ? DAP_NEW_S_SIZE(char, l_size_req) : NULL;
    int l_offset = l_out_len ? dap_snprintf(l_custom, l_size_req, "Authorization: Basic %s\r\n", l_out) : 0;
    //finish up https request
    dap_client_http_request_custom(NULL,"geoip.maxmind.com", 443, "GET", "application/json", l_path, NULL,
            0, NULL, m_request_getip_response, m_request_getip_request_error, NULL, l_custom, true);
    return NULL;
}

/*
 * Get value from mmdb by 2 strings
 */
static int mmdb_get_value_double2(MMDB_lookup_result_s *a_result, const char *a_one, const char *a_two, double *a_out_double)
{
	if (!a_out_double || !a_result || !a_result->found_entry)
		return -1;
	MMDB_entry_data_s entry_data;
	int l_status = MMDB_get_value(&a_result->entry, &entry_data, a_one, a_two, NULL);
	if (MMDB_SUCCESS != l_status) {
		log_it(L_DEBUG, "False get_value [%s->%s] with errcode=%d", a_one, a_two, l_status);
		return -2;
	}
	if (entry_data.has_data) {
		if (a_out_double && entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
			//memcpy(a_out_double, &entry_data.double_value, entry_data.data_size);
			*a_out_double = entry_data.double_value;
		} else
			log_it(L_DEBUG,
					"error value [%s->%s] has size=%d(>0) type=%d(%d)",
					a_one, a_two, entry_data.data_size,
					entry_data.type, MMDB_DATA_TYPE_DOUBLE);
	}
	else
		return -3;
	return 0;
}

/*
 * Get value from mmdb by 2 strings
 */
static int mmdb_get_value_str2(MMDB_lookup_result_s *a_result, const char *a_one, const char *a_two, char *a_out_str, size_t a_out_str_size)
{
	if (!a_out_str || !a_result || !a_result->found_entry)
		return -1;
	MMDB_entry_data_s entry_data;
	int l_status = MMDB_get_value(&a_result->entry, &entry_data, a_one, a_two, NULL);
	if (MMDB_SUCCESS != l_status) {
		log_it(L_DEBUG, "False get_value [%s->%s] with errcode=%d", a_one, a_two, l_status);
		return -2;
	}
	if (entry_data.has_data) {
		if (entry_data.data_size > 0 && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
			size_t l_size = min(a_out_str_size-1, entry_data.data_size);
			strncpy(a_out_str, entry_data.utf8_string, l_size);
			a_out_str[l_size] = 0;
		} else
			log_it(L_DEBUG,
					"error value [%s->%s] has size=%d(>0) type=%d(%d)",
					a_one, a_two, entry_data.data_size,
					entry_data.type, MMDB_DATA_TYPE_UTF8_STRING);
	}
	else
		return -3;
	return 0;
}

/*
 * Get value from mmdb by 3 strings
 */
static int mmdb_get_value_str3(MMDB_lookup_result_s *a_result, const char *a_one, const char *a_two, const char *a_three, char *a_out_str, size_t a_out_str_size)
{
	if (!a_out_str || !a_result || !a_result->found_entry)
		return -1;
	MMDB_entry_data_s entry_data;
	int l_status = MMDB_get_value(&a_result->entry, &entry_data, a_one, a_two, a_three, NULL);
	if (MMDB_SUCCESS != l_status) {
		log_it(L_DEBUG, "False get_value [%s->%s->%s] with errcode=%d", a_one, a_two, a_three, l_status);
		return -2;
	}
	if (entry_data.has_data) {
		if (entry_data.data_size > 0 && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
			size_t l_size = min(a_out_str_size-1, entry_data.data_size);
			strncpy(a_out_str, entry_data.utf8_string, l_size);
			a_out_str[l_size] = 0;
		} else
			log_it(L_DEBUG,
					"error value [%s->%s->%s] has size=%d(>0) type=%d(%d)",
					a_one, a_two, a_three, entry_data.data_size,
					entry_data.type, MMDB_DATA_TYPE_UTF8_STRING);
	}
	else
		return -3;
	return 0;
}

geoip_info_t *chain_net_geoip_get_ip_info_by_local_db(const char *a_ip_str, const char *a_locale)
{
	// https://geoip.maxmind.com/geoip/v2.1/city/178.7.88.55
	// https://maxmind.github.io/libmaxminddb/
    //char *l_file_db_name = dap_strdup_printf("%s/share/geoip/GeoLite2-City.mmdb", g_sys_dir_path);
    if(!dap_file_test(s_geoip_db_file_path)) {
        //DAP_DELETE(l_file_db_name);
        return NULL ;
    }
    MMDB_s mmdb;
    int l_status = MMDB_open(s_geoip_db_file_path, MMDB_MODE_MMAP, &mmdb);
    if(MMDB_SUCCESS != l_status) {
        log_it(L_WARNING, "geoip file %s opened with errcode=%d", s_geoip_db_file_path, l_status);
        return NULL ;
    }
    //DAP_DELETE(l_file_db_name);

	geoip_info_t *l_ret = DAP_NEW_Z(geoip_info_t);

	int gai_error, mmdb_error;
	MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, a_ip_str, &gai_error, &mmdb_error);
	if (0 != gai_error || MMDB_SUCCESS != mmdb_error) {
		log_it(L_WARNING, "no lookup ip=%s with errcode=%d", a_ip_str, l_status);
	}

	// continent
	if (mmdb_get_value_str3(&result, "continent", "names", a_locale, l_ret->continent, sizeof(l_ret->continent))) {
		if (mmdb_get_value_str3(&result, "continent", "names", LOCALE_DEFAULT, l_ret->continent, sizeof(l_ret->continent))) {
			MMDB_close(&mmdb);
			DAP_FREE(l_ret);
			return NULL;
		}
	}
	// country
	if (mmdb_get_value_str3(&result, "country", "names", a_locale, l_ret->country_name, sizeof(l_ret->country_name))) {
		if (mmdb_get_value_str3(&result, "country", "names", LOCALE_DEFAULT, l_ret->country_name, sizeof(l_ret->country_name))) {
			MMDB_close(&mmdb);
			DAP_FREE(l_ret);
			return NULL;
		}
	}
	// all the country names http://download.geonames.org/export/dump/countryInfo.txt
	if (mmdb_get_value_str2(&result, "country", "iso_code", l_ret->country_code, sizeof(l_ret->country_code))) {
		MMDB_close(&mmdb);
		DAP_FREE(l_ret);
		return NULL;
	}
	// city
	/*if (mmdb_get_value_str3(&result, "city", "names", a_locale, l_ret->city_name, sizeof(l_ret->city_name))) {
		if (mmdb_get_value_str3(&result, "city", "names", LOCALE_DEFAULT, l_ret->city_name, sizeof(l_ret->city_name))) {
			MMDB_close(&mmdb);
			DAP_FREE(l_ret);
			return NULL;
		}
	}*/

	//location
	if (mmdb_get_value_double2(&result, "location", "latitude", &l_ret->latitude)) {
		MMDB_close(&mmdb);
		DAP_FREE(l_ret);
		return NULL;
	}
	if (mmdb_get_value_double2(&result, "location", "longitude", &l_ret->longitude)) {
		MMDB_close(&mmdb);
		DAP_FREE(l_ret);
		return NULL;
	}

	// IP
	/*if (mmdb_get_value_str2(&result, "traits", "ip_address", l_ret->ip_str, sizeof(l_ret->ip_str))) {
		MMDB_close(&mmdb);
		DAP_FREE(l_ret);
		return NULL;
	}*/
	int a = sizeof(l_ret->ip_str);
	size_t l_size = min(dap_strlen(a_ip_str), sizeof(l_ret->ip_str));
	l_ret->ip_str[l_size] = 0;
	strncpy(l_ret->ip_str, a_ip_str, l_size);

	MMDB_close(&mmdb);
	return l_ret;
}

geoip_info_t *chain_net_geoip_get_ip_info(const char *a_ip_str)
{
    return chain_net_geoip_get_ip_info_by_local_db(a_ip_str, "en");
    //return chain_net_geoip_get_ip_info_by_web(a_ip_str);
}


int chain_net_geoip_init(dap_config_t *a_config)
{
    s_geoip_db_file_path = dap_strdup_printf("%s/%s", g_sys_dir_path,
            dap_config_get_item_str(g_config, "resources", "geoip_db_path"));
    if(!dap_file_test(s_geoip_db_file_path)) {
        log_it(L_ERROR, "No exists geoip db file %s", s_geoip_db_file_path);
        DAP_DELETE(s_geoip_db_file_path);
        s_geoip_db_file_path = NULL;
        return -1;
    }
    MMDB_s mmdb;
    int l_status = MMDB_open(s_geoip_db_file_path, MMDB_MODE_MMAP, &mmdb);
    if(MMDB_SUCCESS != l_status) {
        log_it(L_WARNING, "geoip file %s opened with errcode=%d", s_geoip_db_file_path, l_status);
        DAP_DELETE(s_geoip_db_file_path);
        s_geoip_db_file_path = NULL;
        return -2;
    }
    return 0;
}

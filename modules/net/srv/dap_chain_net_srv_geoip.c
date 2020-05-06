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

/**
 * @brief m_request_response
 * @param a_response
 * @param a_response_size
 * @param a_obj
 */
static void m_request_getip_response(void * a_response, size_t a_response_size, void * a_obj)
{
    char *l_addr = (char *) a_obj;
    printf("m_request_getip_response %s\n", a_response);
}

static void m_request_getip_request_error(int a_err_code, void *a_obj)
{
    char *l_addr = (char *) a_obj;
    printf("m_request_getip_request_error %s\n", l_addr);
}

geoip_info_t *chain_net_geoip_get_ip_info_by_web(const char *a_ip_str)
{
    // https://geoip.maxmind.com/geoip/v2.1/insights/%s
    char *l_path = dap_strdup_printf("/geoip/v2.1/insights/%s", a_ip_str);
    //104.16.38.47:443
    // geoip.maxmind.com
    char l_out[40];
    //Account/User ID        288651
    //License key
    // https://dev.maxmind.com/geoip/geoip2/web-services/
    const char *user_id = "288651";
    const char *license_key = "1JGvRmd3Ux1kcBkb";
    char *l_auth = dap_strdup_printf("%s:%s", user_id, license_key);
    size_t l_out_len = dap_enc_base64_encode(l_auth, strlen(l_auth), &l_out, DAP_ENC_DATA_TYPE_B64);
    char * l_custom = l_out_len > 0 ? dap_strdup_printf("Authorization: Basic %s", l_out) : NULL;
    size_t l_custom_count = 1;
    // todo
    dap_client_http_request_custom("geoip.maxmind.com", 443, "GET", "application/json", l_path, NULL,
            0, NULL, m_request_getip_response, m_request_getip_request_error, NULL, l_custom, l_custom_count);
    return NULL ;
}

geoip_info_t *chain_net_geoip_get_ip_info_by_local_db(const char *a_ip_str)
{
    char *l_file_db_name = dap_strdup_printf("%s/share/geoip/GeoLite2-City.mmdb", g_sys_dir_path);
    if(!dap_file_test(l_file_db_name)) {
        DAP_DELETE(l_file_db_name);
        return NULL ;
    }
    MMDB_s mmdb;
    int l_status = MMDB_open(l_file_db_name, MMDB_MODE_MMAP, &mmdb);
    if(MMDB_SUCCESS != l_status) {
        log_it(L_WARNING, "geoip file %s opened with errcode=%d", l_file_db_name, l_status);
        return NULL ;
    }
    DAP_DELETE(l_file_db_name);

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result =
            MMDB_lookup_string(&mmdb, a_ip_str, &gai_error, &mmdb_error);
    if(0 != gai_error || MMDB_SUCCESS != mmdb_error) {
        log_it(L_WARNING, "no lookup ip=%s with errcode=%d", a_ip_str, l_status);
    }

    if(result.found_entry) {
        MMDB_entry_data_s entry_data;
        l_status = MMDB_get_value(&result.entry, &entry_data, "names", "en", NULL);
        if(MMDB_SUCCESS != l_status) {
            log_it(L_DEBUG, "no get_value with errcode=%d", l_status);
        }
        if(entry_data.has_data) {
            ;
        }
    }

    MMDB_close(&mmdb);
    return NULL ;
}

geoip_info_t *chain_net_geoip_get_ip_info(const char *a_ip_str)
{
    return chain_net_geoip_get_ip_info_by_local_db(a_ip_str);
    //return chain_net_geoip_get_ip_info_by_web(a_ip_str);
}

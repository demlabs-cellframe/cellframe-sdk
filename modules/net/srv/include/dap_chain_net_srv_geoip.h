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

#include "dap_config.h"

typedef struct geoip_info {

    char ip_str[20];
    char continent[60];
    char country_name[64];
    char country_code[3];// iso_code, all the country names http://download.geonames.org/export/dump/countryInfo.txt
    char city_name[64];
    double latitude;
    double longitude;

} geoip_info_t;

geoip_info_t *chain_net_geoip_get_ip_info(const char *a_ip_str);

int chain_net_geoip_init(dap_config_t *a_config);

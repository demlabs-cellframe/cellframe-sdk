/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe
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

#ifndef _DAP_CONFIG_H_
#define _DAP_CONFIG_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dap_config{
    void * _internal;
} dap_config_t;

int dap_config_init(const char * a_configs_path);
void dap_config_deinit();
dap_config_t * dap_config_open(const char * a_name);
void dap_config_close(dap_config_t * a_config);

const char * dap_config_path();

uint16_t dap_config_get_item_uint16(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
uint16_t dap_config_get_item_uint16_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, uint16_t a_default);

int16_t dap_config_get_item_int16(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
int16_t dap_config_get_item_int16_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, int16_t a_default);

uint32_t dap_config_get_item_uint32(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
uint32_t dap_config_get_item_uint32_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, uint32_t a_default);

int32_t dap_config_get_item_int32(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
int32_t dap_config_get_item_int32_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, int32_t a_default);

int64_t dap_config_get_item_int64(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
int64_t dap_config_get_item_int64_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, int64_t a_default);

uint64_t dap_config_get_item_uint64(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
uint64_t dap_config_get_item_uint64_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, uint64_t a_default);

const char * dap_config_get_item_str(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
const char * dap_config_get_item_str_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, const char * a_value_default);
char** dap_config_get_array_str(dap_config_t * a_config, const char * a_section_path,
                                      const char * a_item_name, uint16_t * array_length);

bool dap_config_get_item_bool(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
bool dap_config_get_item_bool_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, bool a_default);

double dap_config_get_item_double(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
double dap_config_get_item_double_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, double a_default);

extern dap_config_t * g_config;


#ifdef __cplusplus
}
#endif


#endif

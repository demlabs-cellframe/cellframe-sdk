/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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

typedef int (*dap_module_callback_init_t)(void * arg0, ...);
typedef void (*dap_module_callback_deinit_t)(void);

typedef struct dap_module {
    const char * name;
    unsigned int version;
    const char * dependensies[];
} dap_module_t;

#define DAP_MODULE_ARGS_MAX  10
typedef struct dap_module_args {
    const char * name;
    const char * args[DAP_MODULE_ARGS_MAX]; // ARGS could me not more than DAP_MODULE_ARGS_MAX define
} dap_module_args_t;

int dap_module_add(const char * a_name, unsigned int a_version, const char * a_dependensies,
                   dap_module_callback_init_t a_init_callback, dap_module_args_t a_init_args[],
                   dap_module_callback_deinit_t a_deinit_callback );

int dap_module_init_all(void);
void dap_module_deinit_all(void);

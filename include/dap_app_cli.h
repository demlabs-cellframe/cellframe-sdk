/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include <stdint.h>
#include <stddef.h>

// command description
typedef struct dap_app_cli_cmd_state {
    char *cmd_name;
    char **cmd_param;
    int cmd_param_count;
    int ret_code;
    // for reply
    char *cmd_res;
    size_t cmd_res_len;
    size_t cmd_res_cur;
} dap_app_cli_cmd_state_t;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Clear and delete memory of structure cmd_state
 */
void dap_app_cli_free_cmd_state(dap_app_cli_cmd_state_t *cmd);

int dap_app_cli_main(const char * a_app_name, const char * a_socket_path, int argc, char **argv);

#ifdef __cplusplus
}
#endif

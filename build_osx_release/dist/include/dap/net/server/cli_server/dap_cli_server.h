/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe  https://cellframe.net
 * Copyright  (c) 2019-2022
 * All rights reserved.

 This file is part of Cellframe SDK

 Cellframe SDK is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Cellframe SDK is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_events_socket.h"
#include "dap_common.h"
#include "dap_config.h"
#include "uthash.h"

typedef int (*dap_cli_server_cmd_callback_ex_t)(int argc, char ** argv, void *arg_func, void **a_str_reply);
typedef int (*dap_cli_server_cmd_callback_t)(int argc, char ** argv, void **a_str_reply);

typedef void (*dap_cli_server_override_log_cmd_callback_t)(const char*);

typedef struct dap_cli_server_cmd_override{
    /* use it if you want to prevent logging of some sensetive data */
    dap_cli_server_override_log_cmd_callback_t log_cmd_call;
} dap_cli_server_cmd_override_t;

typedef struct dap_cli_cmd{
    char name[32]; /* User printable name of the function. */
    union {
        dap_cli_server_cmd_callback_t func; /* Function to call to do the job. */
        dap_cli_server_cmd_callback_ex_t func_ex; /* Function with additional arg to call to do the job. */
    };
    void *arg_func; /* additional argument of function*/
    char *doc; /* Documentation for this function.  */
    char *doc_ex; /* Full documentation for this function.  */
    dap_cli_server_cmd_override_t overrides; /* Used to change default behaviour */
    UT_hash_handle hh;
} dap_cli_cmd_t;

typedef struct dap_cli_cmd_aliases{
    char alias[32];
    char addition[32];
    dap_cli_cmd_t *standard_command;
    UT_hash_handle hh;
} dap_cli_cmd_aliases_t;


int dap_cli_server_init(bool a_debug_more, const char *a_cfg_section);
void dap_cli_server_deinit();

void dap_cli_server_cmd_add(const char * a_name, dap_cli_server_cmd_callback_t a_func, const char *a_doc, const char *a_doc_ex);
DAP_PRINTF_ATTR(2, 3) void dap_cli_server_cmd_set_reply_text(void **a_str_reply, const char *str, ...);
int dap_cli_server_cmd_find_option_val( char** argv, int arg_start, int arg_end, const char *opt_name, const char **opt_value);
int dap_cli_server_cmd_check_option( char** argv, int arg_start, int arg_end, const char *opt_name);
void dap_cli_server_cmd_apply_overrides(const char * a_name, const dap_cli_server_cmd_override_t a_overrides);

dap_cli_cmd_t* dap_cli_server_cmd_get_first();
dap_cli_cmd_t* dap_cli_server_cmd_find(const char *a_name);

void dap_cli_server_alias_add(const char *a_alias, const char *a_pre_cmd, dap_cli_cmd_t *a_cmd);
dap_cli_cmd_t *dap_cli_server_cmd_find_by_alias(const char *a_cli, char **a_append, char **a_ncmd);

//for json
int json_commands(const char * a_name);
char *dap_cli_cmd_exec(char *a_req_str);

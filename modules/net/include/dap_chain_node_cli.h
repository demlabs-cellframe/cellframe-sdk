/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe  https://cellframe.net
 * Copyright  (c) 2019-2021
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

typedef int cmdfunc_ex_t(int argc, char ** argv, void *arg_func, char **str_reply);
typedef int cmdfunc_t(int argc, char ** argv, char **str_reply);

typedef void cmd_item_func_override_log_cmd_call(const char*);

typedef struct dap_chain_node_cmd_item_func_overrides{
    /* use it if you want to prevent logging of some sensetive data */
    cmd_item_func_override_log_cmd_call * log_cmd_call;
} dap_chain_node_cmd_item_func_overrides_t;

typedef struct dap_chain_node_cmd_item{
    char name[32]; /* User printable name of the function. */
    union {
        cmdfunc_t *func; /* Function to call to do the job. */
        cmdfunc_ex_t *func_ex; /* Function with additional arg to call to do the job. */
    };
    void *arg_func; /* additional argument of function*/
    char *doc; /* Documentation for this function.  */
    char *doc_ex; /* Full documentation for this function.  */
    dap_chain_node_cmd_item_func_overrides_t overrides; /* Used to change default behaviour */
    UT_hash_handle hh;
} dap_chain_node_cmd_item_t;


// Read from socket
long s_recv(SOCKET sd, unsigned char *buf, size_t bufsize, int timeout);

/**
 *  Look up NAME as the name of a command, and return a pointer to that
 *  command.  Return a NULL pointer if NAME isn't a command name.
 */
dap_chain_node_cmd_item_t* dap_chain_node_cli_cmd_get_first();
dap_chain_node_cmd_item_t* dap_chain_node_cli_cmd_find(const char *a_name);
void dap_chain_node_cli_cmd_item_create_ex(const char * a_name, cmdfunc_ex_t *a_func, void *a_arg_func, const char *a_doc, const char *a_doc_ex);
DAP_STATIC_INLINE void dap_chain_node_cli_cmd_item_create(const char * a_name, cmdfunc_t *a_func, const char *a_doc, const char *a_doc_ex)
{
    dap_chain_node_cli_cmd_item_create_ex(a_name, (cmdfunc_ex_t *)(void *)a_func, NULL, a_doc, a_doc_ex);
}
void dap_chain_node_cli_cmd_item_apply_overrides(const char * a_name, const dap_chain_node_cmd_item_func_overrides_t * a_overrides);

void dap_chain_node_cli_set_reply_text(char **str_reply, const char *str, ...);

int dap_chain_node_cli_find_option_val( char** argv, int arg_start, int arg_end, const char *opt_name, const char **opt_value);
int dap_chain_node_cli_check_option( char** argv, int arg_start, int arg_end, const char *opt_name);


/**
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 */
int dap_chain_node_cli_init(dap_config_t * g_config);

/**
 * Deinitialization of the server side
 */
void dap_chain_node_cli_delete(void);

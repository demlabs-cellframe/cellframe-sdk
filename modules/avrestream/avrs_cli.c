/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of AVReStream

 AVReStream is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 AVReStream is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any AVReStream based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <dap_string.h>
#include <dap_cli_server.h>

#include "avrs_session.h"
#include "avrs_cluster.h"
#include "avrs_content.h"
#include "avrs_balancer.h"

#include "avrs_cli.h"
#include "dap_strfuncs.h"

#define LOG_TAG "avrs_cli"
static int s_cli_callback(int a_argc, char **a_argv, char **a_str_reply);

static int s_cli_callback_help(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply);
static int s_cli_callback_cluster(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply);
static int s_cli_callback_content(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply);
static int s_cli_callback_session(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply);
static int s_cli_callback_route(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply);
static int s_cli_callback_balance(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply);
static int s_cli_callback_service(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply);

/**
 * @brief avrs_cli_init
 * @return
 */
int avrs_cli_init()
{
    dap_cli_server_cmd_add("avrestream", s_cli_callback, "AVReStream service",
               "AVReStream service :\n"
               );
    return 0;
}

/**
 * @brief avrs_cli_deinit
 */
void avrs_cli_deinit()
{

}

/**
 * @brief s_command_handler
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
static int s_cli_callback(int a_argc, char **a_argv, char **a_str_reply)
{
    enum {
        CMD_HELP,
        CMD_VERSION,
        CMD_CLUSTER,
        CMD_CONTENT,
        CMD_SESSION,
        CMD_ROUTE,
        CMD_BALANCE,
        CMD_SERVICE
    } l_cmd = CMD_HELP;
    int				l_arg_index = 1;
    int l_retcode = 0 ;
    dap_string_t* l_reply = dap_string_new(NULL);
    const char * l_cmd_arg = NULL;

    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "cluster", &l_cmd_arg))
        l_cmd = CMD_CLUSTER;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "content", &l_cmd_arg))
        l_cmd = CMD_CONTENT;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "session", &l_cmd_arg))
        l_cmd = CMD_SESSION;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "route", &l_cmd_arg))
        l_cmd = CMD_ROUTE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "balance", &l_cmd_arg))
        l_cmd = CMD_BALANCE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "service", &l_cmd_arg))
        l_cmd = CMD_SERVICE;

    switch (l_cmd) {
        case CMD_CLUSTER: l_retcode = s_cli_callback_cluster(a_argc, a_argv, l_arg_index + 1, l_cmd_arg, l_reply); break;
        case CMD_CONTENT: l_retcode = s_cli_callback_content(a_argc, a_argv, l_arg_index + 1, l_cmd_arg, l_reply); break;
        case CMD_SESSION: l_retcode = s_cli_callback_session(a_argc, a_argv, l_arg_index + 1, l_cmd_arg, l_reply); break;
        case CMD_ROUTE:   l_retcode = s_cli_callback_route(a_argc, a_argv, l_arg_index + 1, l_cmd_arg, l_reply); break;
        case CMD_BALANCE: l_retcode = s_cli_callback_balance(a_argc, a_argv, l_arg_index + 1, l_cmd_arg, l_reply); break;
        case CMD_SERVICE: l_retcode = s_cli_callback_service(a_argc, a_argv, l_arg_index + 1, l_cmd_arg, l_reply); break;
        case CMD_HELP:
        default:          l_retcode = s_cli_callback_help(a_argc, a_argv, l_arg_index + 1, l_cmd_arg, l_reply);
    }

    dap_cli_server_cmd_set_reply_text(a_str_reply, l_reply->str);
    dap_string_free(l_reply, true);

    return l_retcode;
}

/**
 * @brief s_cli_callback_help
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_cmd_arg
 * @param a_reply
 * @return
 */
static int s_cli_callback_help(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply)
{
    int l_ret = 0;
    const char c_cmd_list[]="help, version, cluster, session, content, route, balance";
    if( a_cmd_arg == NULL){
        dap_string_append_printf(a_reply,
                             "AVReStream plugin CLI interface. Usage: avrs <subcommand> [<subcommand arguments>]\n"
                             "Subcommands: %s", c_cmd_list
                             );
    } else if ( dap_strcmp( a_cmd_arg, "" ) == 0 ){
    } else{
        dap_string_append_printf(a_reply,
                             "Subcommand \"%s\" is not recognized. Proper subcommands: %s", a_cmd_arg, c_cmd_list
                             );
        l_ret = -1;
    }
    return l_ret;
}

/**
 * @brief s_cli_callback_cluster
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_cmd_arg
 * @param a_reply
 * @return
 */
static int s_cli_callback_cluster( int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply)
{
    return 0;
}

/**
 * @brief s_cli_callback_content
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_cmd_arg
 * @param a_reply
 * @return
 */
static int s_cli_callback_content(int a_argc, char** a_argv, int a_arg_index,const char * a_cmd_arg, dap_string_t* a_reply)
{
    return 0;
}

/**
 * @brief s_cli_callback_session
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_cmd_arg
 * @param a_reply
 * @return
 */
static int s_cli_callback_session(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply)
{
    return 0;
}

/**
 * @brief s_cli_callback_route
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_cmd_arg
 * @param a_reply
 * @return
 */
static int s_cli_callback_route(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply)
{
    return 0;
}

/**
 * @brief s_cli_callback_balance
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_cmd_arg
 * @param a_reply
 * @return
 */
static int s_cli_callback_balance(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply)
{
    return 0;
}

/**
 * @brief s_cli_callback_service
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_cmd_arg
 * @param a_reply
 * @return
 */
static int s_cli_callback_service(int a_argc, char** a_argv, int a_arg_index, const char * a_cmd_arg, dap_string_t* a_reply)
{
    return 0;
}

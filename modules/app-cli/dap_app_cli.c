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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "dap_client.h"
#include "dap_common.h"
#include "dap_file_utils.h"
#include "dap_strfuncs.h"
#include "dap_chain_node_cli.h"
#include "dap_app_cli.h"
#include "dap_app_cli_net.h"
#include "dap_app_cli_shell.h"


#ifdef _WIN32
#include "registry.h"
#endif


/**
 * split string to argc and argv
 */
static char** split_word(char *line, int *argc)
{
    if(!line)
    {
        if(argc)
            *argc = 0;
        return NULL ;
    }
    char **argv = calloc(sizeof(char*), strlen(line));
    int n = 0;
    char *s, *start = line;
    size_t len = strlen(line);
    for(s = line; s <= line + len; s++) {
        if(whitespace(*s)) {
            *s = '\0';
            argv[n] = start;
            s++;
            // miss spaces
            for(; whitespace(*s); s++)
                ;
            start = s;
            n++;
        }
    }
    // last param
    if(len) {
        argv[n] = start;
        n++;
    }
    if(argc)
        *argc = n;
    return argv;
}

/*
 * Execute a command line.
 */
int execute_line(dap_app_cli_connect_param_t *cparam, char *line)
{
    register int i;
    dap_chain_node_cmd_item_t *command;
    char *word;

    /* Isolate the command word. */
    i = 0;
    while(line[i] && whitespace(line[i]))
        i++;
    word = line + i;

    int argc = 0;
    char **argv = split_word(word, &argc);

    // Call the function
    if(argc > 0) {
        dap_app_cli_cmd_state_t cmd;
        memset(&cmd, 0, sizeof(dap_app_cli_cmd_state_t));
        cmd.cmd_name = (char *) argv[0];
        cmd.cmd_param_count = argc - 1;
        if(cmd.cmd_param_count > 0)
            cmd.cmd_param = (char**) (argv + 1);
        // Send command
        int res = dap_app_cli_post_command(cparam, &cmd);
        return res;
    }
    fprintf(stderr, "No command\n");
    return -1;
}

/**
 * Clear and delete memory of structure cmd_state
 */
void dap_app_cli_free_cmd_state(dap_app_cli_cmd_state_t *cmd) {
    if(!cmd->cmd_param)
        return;
    for(int i = 0; i < cmd->cmd_param_count; i++)
            {
        DAP_DELETE(cmd->cmd_param[i]);
    }
    DAP_DELETE(cmd->cmd_res);
    DAP_DELETE(cmd);
}

/**
 *  Read and execute commands until EOF is reached.  This assumes that
 *  the input source has already been initialized.
 */
int shell_reader_loop(dap_app_cli_connect_param_t *cparam)
{
    char *line, *s;

    rl_initialize(); /* Bind our completer. */
    int done = 0;
    // Loop reading and executing lines until the user quits.
    for(; done == 0;) {
        // Read a line of input
        line = rl_readline("> ");

        if(!line)
            break;

        /* Remove leading and trailing whitespace from the line.
         Then, if there is anything left, add it to the history list
         and execute it. */
        s = rl_stripwhite(line);

        if(*s)
        {
            add_history(s);
            execute_line(cparam, s);
        }

        DAP_DELETE(line);
    }

    return 0;
}


/**
 * @brief dap_app_cli_main
 * @param argc
 * @param argv
 * @return
 */
int dap_app_cli_main(const char * a_app_name, const char * a_socket_path, int a_argc, char **a_argv)
{
    dap_set_appname(a_app_name);
    if (dap_common_init(dap_get_appname(), NULL,NULL) != 0) {
        printf("Fatal Error: Can't init common functions module");
        return -2;
    }

    dap_log_level_set(L_CRITICAL);
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
    // connect to node
    dap_app_cli_connect_param_t *cparam = dap_app_cli_connect( a_socket_path );
    if(!cparam)
    {
        printf("Can't connect to %s on socket %s\n",dap_get_appname(), a_socket_path);
        exit(-1);
    }

    if(a_argc > 1){
        // Call the function
        dap_app_cli_cmd_state_t cmd;
        memset(&cmd, 0, sizeof(dap_app_cli_cmd_state_t));
        cmd.cmd_name = strdup(a_argv[1]);
        cmd.cmd_param_count = a_argc - 2;
        if(cmd.cmd_param_count > 0)
            cmd.cmd_param = (char**) (a_argv + 2);
        // Send command
        int res = dap_app_cli_post_command(cparam, &cmd);
        dap_app_cli_disconnect(cparam);
#ifdef _WIN32
        WSACleanup();
#endif
        return res;
    }else{
        // command not found, start interactive shell
        shell_reader_loop(cparam);
        dap_app_cli_disconnect(cparam);
    }
#ifdef _WIN32
        WSACleanup();
#endif
    return 0;
}


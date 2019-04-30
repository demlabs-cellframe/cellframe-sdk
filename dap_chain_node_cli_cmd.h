/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

#include "dap_chain_node.h"
#include "dap_chain_node_cli.h"

/**
 * Find in base addr by alias
 *
 * return addr, NULL if not found
 */
dap_chain_node_addr_t* get_name_by_alias(const char *alias);

/**
 *  Look up NAME as the name of a command, and return a pointer to that
 *  command.  Return a NULL pointer if NAME isn't a command name.
 */
const COMMAND* find_command(const char *name);


/**
 * global_db command
 */
int com_global_db(int argc, const char ** argv, char **str_reply);

/**
 * Node command
 */
int com_node(int argc, const char ** argv, char **str_reply);

/**
 * Traceroute command
 *
 * return 0 OK, -1 Err
 */
int com_traceroute(int argc, const char** argv, char **str_reply);

/**
 * Tracepath command
 *
 * return 0 OK, -1 Err
 */
int com_tracepath(int argc, const char** argv, char **str_reply);

/**
 * Ping command
 *
 * return 0 OK, -1 Err
 */
int com_ping(int argc, const char** argv, char **str_reply);

/**
 * Help command
 */
int com_help(int argc, const char ** argv, char **str_reply);


int com_token_declare ( int argc, const char ** argv, char ** str_reply);

int com_token_emit (int argc, const char ** argv, char ** str_reply);


/**
 * com_tx_create command
 *
 * Wallet info
 */
int com_tx_wallet(int argc, const char ** argv, char **str_reply);

/**
 * com_tx_create command
 *
 * Create transaction
 */
int com_tx_create(int argc, const char ** argv, char **str_reply);
int com_tx_cond_create(int argc, const char ** argv, char **str_reply);

/**
 * tx_verify command
 *
 * Verifing transaction
 */
int com_tx_verify(int argc, const char ** argv, char **str_reply);

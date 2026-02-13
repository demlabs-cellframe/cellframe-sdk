/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 */

#include <stdio.h>
#include <string.h>
#define _XOPEN_SOURCE
#define __USE_XOPEN
#include <time.h>
#include <errno.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_net_cli.h"
#include "dap_chain_net.h"
#include "dap_chain_net_core.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_tx.h"                // tx module exports include/
#include "dap_chain_net_srv.h"               // srv/base exports include/
#include "dap_chain_net_cli_error_codes.h"  // Error codes registration
#include "dap_chain_net_node_list.h"         // For dap_chain_node_list_ip_check, dap_chain_net_node_list_request
#include "dap_chain_node_rpc.h"              // For dap_chain_node_rpc_* functions
#include "dap_chain_node_sync_client.h"      // For dap_chain_node_sync_handshake
#include "dap_chain_datum.h"                 // For dap_chain_datum_create
#include "dap_chain_mempool.h"               // For dap_chain_mempool_datum_add
#include "dap_chain_srv.h"                   // For dap_chain_srv_get_fees
#include "dap_chain_net_balancer.h"          // For dap_chain_net_balancer_get_node_str
#include "dap_http_ban_list_client.h"        // For dap_http_ban_list_client_dump
#include "dap_link_manager.h"                // For dap_link_manager_* functions
#include "dap_cli_server.h"
#include "dap_json_rpc.h"
#include "dap_json_rpc_request.h"       // For dap_json_rpc_request_t, dap_json_rpc_request_send
#include "dap_json_rpc_params.h"        // For dap_json_rpc_params_t
#include "dap_json_rpc_response.h"      // For dap_json_rpc_response_get_new_id
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_chain_datum_anchor.h"     // For dap_chain_datum_anchor_t
#include "dap_chain_datum_decree.h"     // For dap_chain_datum_decree_t
#include "dap_cert.h"                   // For dap_cert_t, dap_cert_parse_str_list
#include "dap_enc_base58.h"             // For base58 encoding functions
#include "dap_tsd.h"                    // For dap_tsd_t, dap_tsd_create
#include "dap_cpu_monitor.h"            // For dap_cpu_get_stats, dap_cpu_monitor_init
#include "utlist.h"

#define LOG_TAG "dap_chain_net_cli"

// Forward declarations
// Forward declarations for legacy static functions
static dap_tsd_t *s_chain_node_cli_com_node_create_tsd_addr_json(char **a_argv, int a_arg_start, int a_argc,
                                                                   dap_json_t *a_json_arr_reply, const char *a_cmd_name);
static dap_json_t *s_net_sync_status(dap_chain_net_t *a_net, int a_version);

static int com_node(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_net(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_help(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_version(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_print_log(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_exit(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_remove(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_decree(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_exec_cmd(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_cli_stats(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);
static int s_print_for_help(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt);
static int s_print_for_print_log(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt);
static dap_chain_datum_anchor_t *s_sign_anchor_in_cycle(dap_cert_t **a_certs, dap_chain_datum_anchor_t *a_datum_anchor,
                                                         size_t a_certs_count, size_t *a_total_sign_count);

/**
 * @brief s_net_sync_status - Creates JSON object with network sync status information
 * @param a_net Network object
 * @param a_version API version
 * @return dap_json_t* JSON object with sync status per chain
 */
static dap_json_t *s_net_sync_status(dap_chain_net_t *a_net, int a_version)
{
    (void)a_version;
    if (!a_net)
        return NULL;

    dap_json_t *l_jobj_chains = dap_json_object_new();
    if (!l_jobj_chains)
        return NULL;

    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        if (!l_chain)
            continue;

        dap_json_t *l_jobj_chain = dap_json_object_new();
        if (!l_jobj_chain)
            continue;

        // Chain sync status
        const char *l_status_str = "unknown";
        switch (l_chain->state) {
            case CHAIN_SYNC_STATE_IDLE:
                l_status_str = "idle";
                break;
            case CHAIN_SYNC_STATE_WAITING:
                l_status_str = "sync in process";
                break;
            case CHAIN_SYNC_STATE_SYNCED:
                l_status_str = "synced";
                break;
            default:
                l_status_str = "unknown";
                break;
        }
        dap_json_object_add_string(l_jobj_chain, "status", l_status_str);

        // Current atom count (blocks or events)
        uint64_t l_current = 0;
        if (l_chain->callback_count_atom) {
            l_current = l_chain->callback_count_atom(l_chain);
        }
        dap_json_object_add_object(l_jobj_chain, "current", dap_json_object_new_uint64(l_current));

        // Total atoms in network (from last sync info)
        uint64_t l_total = l_chain->atom_num_last;
        dap_json_object_add_object(l_jobj_chain, "in_network", dap_json_object_new_uint64(l_total));

        // Sync percentage
        if (l_total > 0) {
            double l_percent = (double)l_current / (double)l_total * 100.0;
            if (l_percent > 100.0)
                l_percent = 100.0;
            char l_percent_str[32];
            snprintf(l_percent_str, sizeof(l_percent_str), "%.2f%%", l_percent);
            dap_json_object_add_string(l_jobj_chain, "percent", l_percent_str);
        } else {
            dap_json_object_add_string(l_jobj_chain, "percent", "N/A");
        }

        // Chain type info
        const char *l_cs_type = dap_chain_get_cs_type(l_chain);
        dap_json_object_add_string(l_jobj_chain, "type", l_cs_type ? l_cs_type : "unknown");

        // Add chain to chains object
        dap_json_object_add_object(l_jobj_chains, l_chain->name, l_jobj_chain);
    }

    return l_jobj_chains;
}

/**
 * @brief s_chain_node_cli_com_node_create_tsd_addr_json - Creates TSD item from address parameters
 * @param a_argv Arguments array
 * @param a_arg_start Start index for parsing
 * @param a_argc Total argument count
 * @param a_json_arr_reply JSON reply array for errors
 * @param a_cmd_name Command name for error messages
 * @return dap_tsd_t* Created TSD item or NULL on error
 */
static dap_tsd_t *s_chain_node_cli_com_node_create_tsd_addr_json(char **a_argv, int a_arg_start, int a_argc,
                                                                   dap_json_t *a_json_arr_reply, const char *a_cmd_name)
{
    // Find -addr parameter
    const char *l_addr_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_start, a_argc, "-addr", &l_addr_str);
    
    if (!l_addr_str) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, 
                              "%s requires -addr parameter", a_cmd_name);
        return NULL;
    }

    // Parse address
    dap_chain_node_addr_t l_node_addr = {};
    if (dap_chain_node_addr_from_str(&l_node_addr, l_addr_str) != 0) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,
                              "Invalid node address format: %s", l_addr_str);
        return NULL;
    }

    // Create TSD item with address
    size_t l_tsd_size = sizeof(dap_tsd_t) + sizeof(dap_chain_node_addr_t);
    dap_tsd_t *l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_tsd_size);
    if (!l_tsd) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,
                              "Memory allocation failed for TSD");
        return NULL;
    }

    l_tsd->type = 0; // TSD type for node address
    l_tsd->size = sizeof(dap_chain_node_addr_t);
    memcpy(l_tsd->data, &l_node_addr, sizeof(dap_chain_node_addr_t));

    return l_tsd;
}

// REMOVED: int com_net() forward declaration - legacy CLI handler

// Helper function to list nodes with full reply  
// Implementation based on dap_chain_node_rpc_list logic
static int s_node_info_list_with_reply(dap_chain_net_t *a_net, dap_chain_node_addr_t *a_node_addr,
                                       bool a_is_full, const char *a_alias, dap_json_t *a_json_arr_reply)
{
    // Get nodes from global_db - use gdb_nodes which is the same group where node add saves
    // This is "<prefix>.nodes.list" (e.g., "stagenet.nodes.list")
    size_t l_nodes_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_net->pub.gdb_nodes, &l_nodes_count);

    if (!l_nodes_count || !l_objs) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR,
                              "No nodes found in network");
        return -DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR;
    }

    size_t l_count = 0;  // Counter for matched nodes
    for (size_t i = 0; i < l_nodes_count; i++) {
        dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t *)l_objs[i].value;
        if (!l_node_info || dap_chain_node_addr_is_blank(&l_node_info->address))
            continue;

        // Filter by address if specified
        if (a_node_addr && !dap_chain_node_addr_is_blank(a_node_addr)) {
            if (memcmp(&l_node_info->address, a_node_addr, sizeof(dap_chain_node_addr_t)) != 0)
                continue;
        }

        // Filter by alias if specified
        if (a_alias && *a_alias) {
            if (strcmp(l_node_info->alias, a_alias) != 0)  // alias is array, always non-NULL
                continue;
        }

        // Build JSON object for this node
        dap_json_t *l_json_node = dap_json_object_new();
        if (!l_json_node)
            continue;

        // Add node address (using NODE_ADDR_FP_STR format like rpc_list does)
        char *l_addr_str = dap_strdup_printf(NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_node_info->address));
        dap_json_object_add_string(l_json_node, "address", l_addr_str);
        DAP_DELETE(l_addr_str);

        // Add alias if exists (alias is array, check for empty string)
        if (*l_node_info->alias)
            dap_json_object_add_string(l_json_node, "alias", l_node_info->alias);

        // Add host/port info (ext_host is array, check for empty string)
        if (*l_node_info->ext_host)
            dap_json_object_add_string(l_json_node, "IPv4", l_node_info->ext_host);
        dap_json_object_add_uint64(l_json_node, "port", l_node_info->ext_port);

        // Add full info if requested
        if (a_is_full) {
            char l_ts[DAP_TIME_STR_SIZE] = {'\0'};
            dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), l_objs[i].timestamp);
            dap_json_object_add_string(l_json_node, "timestamp", l_ts);
        }

        dap_json_array_add(a_json_arr_reply, l_json_node);
        l_count++;
    }

    dap_global_db_objs_delete(l_objs, l_nodes_count);

    if (l_count == 0) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR,
                              "No nodes match the specified criteria");
        return -DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR;
    }

    return 0;
}

int com_node(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    enum {
        CMD_NONE, CMD_ADD, CMD_DEL, CMD_ALIAS, CMD_HANDSHAKE, CMD_CONNECT, CMD_LIST, CMD_DUMP, CMD_CONNECTIONS, CMD_BALANCER,
        CMD_BAN, CMD_UNBAN, CMD_BANLIST, CMD_ADD_RPC, CMD_LIST_RPC, CMD_DUMP_RPC, CMD_DEL_RPC
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "add", NULL)) {
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-rpc", NULL))
            cmd_num = CMD_ADD_RPC;
        else
            cmd_num = CMD_ADD;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "del", NULL)) {
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-rpc", NULL))
            cmd_num = CMD_DEL_RPC;
        else
            cmd_num = CMD_DEL;
    } // find  add parameter ('alias' or 'handshake')
    else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "handshake", NULL)) {
        cmd_num = CMD_HANDSHAKE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "connect", NULL)) {
        cmd_num = CMD_CONNECT;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "alias", NULL)) {
        cmd_num = CMD_ALIAS;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "list", NULL)) {
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-rpc", NULL))
            cmd_num = CMD_LIST_RPC;
        else
            cmd_num = CMD_LIST;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "dump", NULL)) {
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-rpc", NULL))
            cmd_num = CMD_DUMP_RPC;
        else
            cmd_num = CMD_DUMP;
    }
    else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "connections", NULL)) {
        cmd_num = CMD_CONNECTIONS;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index+1), "ban", NULL)) {
        cmd_num = CMD_BAN;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index+1), "unban", NULL)) {
        cmd_num = CMD_UNBAN;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index+1), "banlist", NULL)) {
        cmd_num = CMD_BANLIST;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "balancer", NULL)){
        cmd_num = CMD_BALANCER;
    }
    arg_index++;
    if(cmd_num == CMD_NONE) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_COMMAND_NOT_RECOGNIZED_ERR,
            "command %s not recognized", a_argv[1]);
        return -DAP_CHAIN_NODE_CLI_COM_NODE_COMMAND_NOT_RECOGNIZED_ERR;
    }
    const char *l_addr_str = NULL, *l_port_str = NULL, *alias_str = NULL;
    const char *l_cell_str = NULL, *l_link_str = NULL, *l_hostname = NULL;

    // find net
    dap_chain_net_t *l_net = NULL;

    int l_net_parse_val = dap_chain_net_parse_net_chain(a_json_arr_reply, &arg_index, a_argc, a_argv, NULL, &l_net, CHAIN_TYPE_INVALID);
    if(l_net_parse_val) {
        if (cmd_num != CMD_BANLIST && cmd_num != CMD_ADD_RPC && cmd_num != CMD_LIST_RPC && cmd_num != CMD_CONNECTIONS && cmd_num != CMD_DUMP && cmd_num != CMD_DUMP_RPC && cmd_num != CMD_DEL_RPC) {
            dap_json_rpc_error_add(a_json_arr_reply, l_net_parse_val, "Request parsing error (code: %d)", l_net_parse_val);
            return l_net_parse_val;
        }
        dap_json_array_del_idx(a_json_arr_reply, 0, 1);
    }

    // find addr, alias
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-port", &l_port_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-alias", &alias_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cell", &l_cell_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-host", &l_hostname);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-link", &l_link_str);

    // struct to write to the global db
    dap_chain_node_addr_t l_node_addr = {}, l_link;
    uint32_t l_info_size = l_hostname 
        ? sizeof(dap_chain_node_info_t) + dap_strlen(l_hostname) + 1
        : sizeof(dap_chain_node_info_t);
    dap_chain_node_info_t *l_node_info = DAP_NEW_STACK_SIZE(dap_chain_node_info_t, l_info_size);
    memset(l_node_info, 0, l_info_size);;
    //TODO need to rework with new node info / alias /links concept

    if (l_addr_str) {
        if (dap_chain_node_addr_from_str(&l_node_info->address, l_addr_str)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_NODE_ADDR_ERR,
                "Can't parse node address %s", l_addr_str);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_NODE_ADDR_ERR;
        }
    }
    if (l_port_str) {
        dap_digit_from_string(l_port_str, &l_node_info->ext_port, sizeof(uint16_t));
        if (!l_node_info->ext_port) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_HOST_PORT_ERR,
                "Can't parse host port %s", l_port_str);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_HOST_PORT_ERR;
        }
    }
    if (l_cell_str) {
        dap_digit_from_string(l_cell_str, l_node_info->cell_id.raw, sizeof(l_node_info->cell_id.raw)); //DAP_CHAIN_CELL_ID_SIZE);
    }
    if (l_link_str) {   // TODO
        if(dap_chain_node_addr_from_str(&l_link, l_link_str) != 0) {
            dap_digit_from_string(l_link_str, l_link.raw, sizeof(l_link.raw));
        }
    }
    switch (cmd_num) {

    case CMD_ADD: {
        int l_res = -10;
        uint16_t l_port = 0;
        if (l_addr_str || l_hostname) {
            if (!dap_chain_net_is_my_node_authorized(l_net)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR,
                    "You have no access rights");
                return l_res;
            }
            // We're in authorized list, add directly
            struct sockaddr_storage l_verifier = { };
            if ( 0 > dap_net_parse_config_address(l_hostname, l_node_info->ext_host, &l_port, &l_verifier, NULL) ) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PARSE_HOST_STRING_ERR,
                    "Can't parse host string %s", l_hostname);
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PARSE_HOST_STRING_ERR;
            }
            if ( !l_node_info->ext_port && !(l_node_info->ext_port = l_port) ) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR,
                                       "Unspecified port");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR;
            }

            l_node_info->ext_host_len = dap_strlen(l_node_info->ext_host);

            dap_chain_node_info_t* l_check_node_info = dap_chain_node_list_ip_check(l_node_info, l_net);
            if (l_check_node_info) {
                log_it(L_INFO, "Replace existed node with same ip %s address %s -> %s", l_check_node_info->ext_host,
                                         dap_stream_node_addr_to_str_static(l_check_node_info->address), dap_stream_node_addr_to_str_static(l_node_info->address));
                dap_chain_node_info_del(l_net, l_check_node_info);
            }

            l_res = dap_chain_node_info_save(l_net, l_node_info);

            if (l_res) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_ADDED_NOT_ERR,
                                       "Can't add node %s, error %d", l_addr_str, l_res);
            } else {
                dap_json_t *json_obj_out = dap_json_object_new();
                if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                dap_json_object_add_string(json_obj_out, "successfully_added_node", l_addr_str);
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return l_res;
        }
        // Synchronous request, wait for reply
        if ( !(l_port = l_node_info->ext_port) 
             && !(l_port = dap_chain_net_get_my_node_info(l_net)->ext_port)
             && !(l_port = dap_config_get_item_int16(g_config, "server", DAP_CFG_PARAM_LEGACY_PORT)) )
        {
            if ( dap_config_get_item_bool_default(g_config, "server", "enabled", false) ) {
                const char **l_listening = dap_config_get_array_str(g_config, "server", DAP_CFG_PARAM_LISTEN_ADDRS, NULL);
                if ( l_listening && dap_net_parse_config_address(*l_listening, NULL, &l_port, NULL, NULL) < 0 ) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_INVALID_SERVER_ERR,
                                       "Invalid server IP address, check [server] section in cellframe-node.cfg");
                    return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_INVALID_SERVER_ERR;
                }
            }
            if (!l_port) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR,
                                       "Unspecified port");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR;
            } 
        }
        dap_json_t *json_obj_out = NULL;
        switch ( l_res = dap_chain_net_node_list_request(l_net, l_port, true, 'a') )
        {
            case 1:
                json_obj_out = dap_json_object_new();
                if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                dap_json_object_add_string(json_obj_out, "status", "Successfully added");
                dap_json_array_add(a_json_arr_reply, json_obj_out);
                 return DAP_CHAIN_NODE_CLI_COM_NODE_OK;
            case 2: dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_NO_SERVER_ERR,
                                                                                                "No server");break;
            case 3: dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_DIDNT_ADD_ADDRESS_ERR,
                                                                "Didn't add your address node to node list");break;
            case 4: dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_CALCULATE_HASH_ERR,
                                                                       "Can't calculate hash for your addr");break;
            case 5: dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_DO_HANDSHAKE_ERR,
                                                                         "Can't do handshake for your node");break;
            case 6: dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_ALREADY_EXISTS_ERR,
                                                                                  "The node already exists");break;
            case 7: dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PROCESS_NODE_LIST_ERR,
                                                                     "Can't process node list HTTP request");break;
            default:dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PROCESS_REQUEST_ERR,
                                                                   "Can't process request, error %d", l_res);break;
            return l_res;
        }
    }

    case CMD_ADD_RPC: {
        int l_res = -10;
        uint16_t l_port = 0;
        if (!l_addr_str || !l_hostname) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_FIND_ARGS_ERR,
                "Requires -addr and -host args");;
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_FIND_ARGS_ERR;
        }
        if (!dap_chain_node_rpc_is_root()) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR,
                "Your rpc role is not root");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR;
        }
        if (!dap_chain_node_rpc_is_my_node_authorized()) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR,
                "You have no access rights");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR;
        }
        // We're in authorized list, add directly
        struct sockaddr_storage l_verifier = { };
        if ( 0 > dap_net_parse_config_address(l_hostname, l_node_info->ext_host, &l_port, &l_verifier, NULL) ) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PARSE_HOST_STRING_ERR,
                "Can't parse host string %s", l_hostname);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PARSE_HOST_STRING_ERR;
        }
        if ( !l_node_info->ext_port && !(l_node_info->ext_port = l_port) ) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR,
                                   "Unspecified port");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR;
        }

        l_node_info->ext_host_len = dap_strlen(l_node_info->ext_host);
        l_res = dap_chain_node_rpc_info_save(l_node_info, dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-force", NULL));
        if (l_res) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_ADDED_NOT_ERR,
                                   "Can't add node %s, error %d", l_addr_str, l_res);
        } else {
            dap_json_t* json_obj_out = dap_json_object_new();
            if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
            dap_json_object_add_string(json_obj_out, "successfully_added_node", l_addr_str);
            dap_json_array_add(a_json_arr_reply, json_obj_out);
        }
        return l_res;
    }

    case CMD_DEL: {
        // handler of command 'node del'
        if (l_addr_str) {
            if (!dap_chain_net_is_my_node_authorized(l_net)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_DELL_NO_ACCESS_RIGHTS_ERR,
                                        "You have no access rights");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_DELL_NO_ACCESS_RIGHTS_ERR;
            }
            int l_res = dap_chain_node_info_del(l_net, l_node_info);
            if (l_res)
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_DELL_CANT_DEL_NODE_ERR,
                                        "Can't delete node %s, error %d", l_addr_str, l_res);
            else {
                dap_json_t *json_obj_out = dap_json_object_new();
                if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                dap_json_object_add_string(json_obj_out, "successfully_deleted_node", l_addr_str);
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return l_res;
        }
        // Synchronous request, wait for reply
        int l_res = dap_chain_net_node_list_request(l_net, 0, true, 'r');
        dap_json_t *json_obj_out = NULL;
        switch (l_res) {
            case 8: 
                json_obj_out = dap_json_object_new();
                if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                dap_json_object_add_string(json_obj_out, "status", "Successfully deleted");
                dap_json_array_add(a_json_arr_reply, json_obj_out); 
            return DAP_CHAIN_NODE_CLI_COM_NODE_OK;
            default: dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_DELL_CANT_PROCESS_REQUEST_ERR,
                                       "Can't process request, error %d", l_res);
            return l_res;
        }
    }

    case CMD_DEL_RPC: {
        int l_res = -10;
        uint16_t l_port = 0;
        if (!l_addr_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_FIND_ARGS_ERR,
                "Requires -addr arg");;
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_FIND_ARGS_ERR;
        }
        if (!dap_chain_node_rpc_is_root()) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR,
                "Your rpc role is not root");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR;
        }
        if (!dap_chain_node_rpc_is_my_node_authorized()) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR,
                "You have no access rights");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR;
        }
        l_res = dap_chain_node_rpc_info_del(l_node_info->address);
        if (l_res){
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_DELL_CANT_DEL_NODE_ERR,
                                        "Can't delete node %s, error %d", l_addr_str, l_res);
        } else {
            dap_json_t *json_obj_out = dap_json_object_new();
            if (!json_obj_out)
                return DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
            dap_json_object_add_string(json_obj_out, "successfully_deleted_node", l_addr_str);
            dap_json_array_add(a_json_arr_reply, json_obj_out);
        }
        return l_res;
    }

    case CMD_LIST:{
        // handler of command 'node dump'
        bool l_is_full = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-full", NULL);
        return s_node_info_list_with_reply(l_net, &l_node_addr, l_is_full, alias_str, a_json_arr_reply);
    }
    case CMD_LIST_RPC: {
        dap_json_t *json_obj_out = dap_chain_node_rpc_list();
        if (!json_obj_out) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR, "No records\n");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR;
        }
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        return 0;
    }
    case CMD_DUMP: {
        dap_json_t *json_obj_out = dap_json_object_new();
        if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        dap_string_t *l_string_reply = dap_chain_node_states_info_read(l_net, l_node_info->address);
        dap_json_object_add_string(json_obj_out, "status_dump", l_string_reply->str);
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        dap_string_free(l_string_reply, true);
        return 0;
    }
    case CMD_DUMP_RPC: {
        dap_json_t *json_obj_out = dap_chain_node_rpc_states_info_read(l_node_info->address);
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        return 0;
    }
        // add alias
    case CMD_ALIAS:
        if(alias_str) {
            if(l_addr_str) {
                // add alias
                if(!dap_chain_node_alias_register(l_net, alias_str, &l_node_addr))
                    log_it(L_WARNING, "can't save alias %s", alias_str);
                else {
                    dap_json_t *json_obj_out = dap_json_object_new();
                    if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                    dap_json_object_add_string(json_obj_out, "status_alias", "alias mapped successfully");
                    dap_json_array_add(a_json_arr_reply, json_obj_out);
                }
            }
            else {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ADDR_NOT_FOUND_ERR,
                                                                "alias can't be mapped because -addr is not found");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ADDR_NOT_FOUND_ERR;
            }
        }
        else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ALIAS_NOT_FOUND_ERR,
                "alias can't be mapped because -alias is not found");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ALIAS_NOT_FOUND_ERR;
        }

        break;
        // make connect
    case CMD_CONNECT:
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECT_NOT_IMPLEMENTED_ERR,
                                                                                        "Not implemented yet");
         break;
#if 0
        // get address from alias if addr not defined
        if(alias_str && !l_node_addr.uint64) {
            dap_chain_node_addr_t *address_tmp = dap_chain_node_alias_find(l_net, alias_str);
            if(address_tmp) {
                l_node_addr = *address_tmp;
                DAP_DELETE(address_tmp);
            }
            else {
                dap_json_rpc_error_add(a_json_arr_reply, -1, "no address found by alias");
                return -1;
            }
        }
        // for auto mode
        int l_is_auto = 0;
        // list of dap_chain_node_addr_t struct
        unsigned int l_nodes_count = 0;
        dap_list_t *l_node_list = NULL;
        dap_chain_node_addr_t *l_remote_node_addr = NULL;
        if(!l_node_addr.uint64) {
            // check whether auto mode
            l_is_auto = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "auto", NULL);
            if(!l_is_auto) {
                dap_json_rpc_error_add(a_json_arr_reply, -1, "addr not found");
                return -1;
            }
            // if auto mode, then looking for the node address

            // get cur node links
            bool a_is_only_cur_cell = false;
            // TODO rewrite this command totally
            // dap_list_t *l_node_link_list = dap_chain_net_get_link_node_list(l_net, a_is_only_cur_cell);
            // get all nodes list if no links
            l_node_list = dap_chain_net_get_node_list(l_net);
            // select random node from the list
            l_nodes_count = dap_list_length(l_node_list);
            if(l_nodes_count > 0) {
                unsigned int l_node_pos = rand() % l_nodes_count;
                dap_list_t *l_tmp = dap_list_nth(l_node_list, l_node_pos);
                l_remote_node_addr = l_tmp->data;
                l_node_addr.uint64 = l_remote_node_addr->uint64;
            }

            if(!l_node_addr.uint64) {
                dap_json_rpc_error_add(a_json_arr_reply, -1, "no node is available");
                return -1;
            }
        }
        dap_chain_node_info_t *l_remote_node_info;
        dap_chain_node_client_t *l_node_client;
        int res;
        do {
            // Fixed: use existing dap_chain_node_info_read instead of non-existent node_info_read_and_reply
            l_remote_node_info = dap_chain_node_info_read(l_net, &l_node_addr);
            if(!l_remote_node_info) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR,
                                       "Node info not found for specified address");
                return -1;
            }
            // start connect
            l_node_client = dap_chain_node_client_connect_default_channels(l_net,l_remote_node_info);
            if(!l_node_client) {
                dap_json_rpc_error_add(a_json_arr_reply, -1, "can't connect");
                DAP_DELETE(l_remote_node_info);
                return -1;
            }
            // wait connected
            int timeout_ms = 7000; // 7 sec = 7000 ms
            res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
            // select new node addr
            if(l_is_auto && res){
                if(l_remote_node_addr && l_nodes_count>1){
                    l_nodes_count--;
                    l_node_list = dap_list_remove(l_node_list, l_remote_node_addr);
                    DAP_DELETE(l_remote_node_addr);
                    unsigned int l_node_pos = rand() % l_nodes_count;
                    dap_list_t *l_tmp = dap_list_nth(l_node_list, l_node_pos);
                    l_remote_node_addr = l_tmp->data;
                    l_node_addr.uint64 = l_remote_node_addr->uint64;

                    // clean client struct
                    dap_chain_node_client_close(l_node_client);
                    DAP_DELETE(l_remote_node_info);
                    //return -1;
                    continue;
                }
            }
            break;
        }
        while(1);
        // for auto mode only
        if(l_is_auto) {
            //start background thread for testing connect to the nodes
            dap_chain_node_ping_background_start(l_net, l_node_list);
            dap_list_free_full(l_node_list, NULL);
        }



        if(res) {
            dap_json_rpc_error_add(a_json_arr_reply, -1, "no response from remote node(s)");
            log_it(L_WARNING, "No response from remote node(s): err code %d", res);
            // clean client struct
            dap_chain_node_client_close(l_node_client);
            //DAP_DELETE(l_remote_node_info);
            return -1;
        }
        log_it(L_NOTICE, "Stream connection established");

        dap_chain_ch_sync_request_old_old_t l_sync_request = {};
        dap_stream_ch_t *l_ch_chain = dap_client_get_stream_ch_unsafe(l_node_client->client, DAP_CHAIN_CH_ID);
        // fill begin id
        l_sync_request.id_start = 1;
        // fill current node address
        l_sync_request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);

        log_it(L_INFO, "Requested GLOBAL_DB syncronizatoin, %"DAP_UINT64_FORMAT_U":%"DAP_UINT64_FORMAT_U" period",
                                                        l_sync_request.id_start, l_sync_request.id_end);
        if(0 == dap_chain_ch_pkt_write_unsafe(l_ch_chain, DAP_CHAIN_CH_PKT_TYPE_SYNC_GLOBAL_DB,
                l_net->pub.id.uint64, 0, 0, &l_sync_request,
                sizeof(l_sync_request))) {
            dap_json_rpc_error_add(a_json_arr_reply, -1, "Error: Can't send sync chains request");
            // clean client struct
            dap_chain_node_client_close(l_node_client);
            DAP_DELETE(l_remote_node_info);
            return -1;
        }
        dap_stream_ch_set_ready_to_write_unsafe(l_ch_chain, true);
        // wait for finishing of request
        int timeout_ms = 420000; // 7 min = 420 sec = 420 000 ms
        // TODO add progress info to console
        res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);
        if(res < 0) {
            dap_json_rpc_error_add(a_json_arr_reply, -1, "Error: can't sync with node "NODE_ADDR_FP_STR,
                                            NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
            dap_chain_node_client_close(l_node_client);
            DAP_DELETE(l_remote_node_info);
            log_it(L_WARNING, "Gdb synced err -2");
            return -2;

        }
        // flush global_db
        dap_global_db_flush_sync();
        log_it(L_INFO, "Gdb synced Ok");

        // Requesting chains
        dap_chain_t *l_chain = NULL;
        DL_FOREACH(l_net->pub.chains, l_chain)
        {
            // reset state NODE_CLIENT_STATE_SYNCED
            dap_chain_node_client_reset(l_node_client);
            // send request
            dap_chain_ch_sync_request_old_old_t l_sync_request = {};
            if(0 == dap_chain_ch_pkt_write_unsafe(l_ch_chain, DAP_CHAIN_CH_PKT_TYPE_SYNC_CHAINS,
                    l_net->pub.id.uint64, l_chain->id.uint64, l_remote_node_info->hdr.cell_id.uint64, &l_sync_request,
                    sizeof(l_sync_request))) {
                dap_json_rpc_error_add(a_json_arr_reply, -1, "Error: Can't send sync chains request");
                // clean client struct
                dap_chain_node_client_close(l_node_client);
                DAP_DELETE(l_remote_node_info);
                log_it(L_INFO, "Chain '%s' synced error: Can't send sync chains request", l_chain->name);
                return -3;
            }
            log_it(L_NOTICE, "Requested syncronization for chain \"%s\"", l_chain->name);
            dap_stream_ch_set_ready_to_write_unsafe(l_ch_chain, true);

            // wait for finishing of request
            timeout_ms = 120000; // 2 min = 120 sec = 120 000 ms
            // TODO add progress info to console
            res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);
            if(res < 0) {
                log_it(L_ERROR, "Error: Can't sync chain %s", l_chain->name);
            }
        }
        log_it(L_INFO, "Chains and gdb are synced");
        DAP_DELETE(l_remote_node_info);
        //dap_client_disconnect(l_node_client->client);
        //l_node_client->client = NULL;
        dap_chain_node_client_close(l_node_client);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Node sync completed: Chains and gdb are synced");
        return 0;

    }
#endif
        // make handshake
    case CMD_HANDSHAKE: {
        // get address from alias if addr not defined
        if (alias_str && !l_node_addr.uint64) {
            dap_chain_node_addr_t *address_tmp = dap_chain_node_alias_find(l_net, alias_str);
            if (address_tmp) {
                l_node_addr = *address_tmp;
                DAP_DELETE(address_tmp);
            } else {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR,
                                       "No address found by alias");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR;
            }
        }
        l_node_addr = l_node_info->address;
        if (!l_node_addr.uint64) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR,
                                   "Addr not found");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR;
        }

        // Fixed: use existing dap_chain_node_info_read instead of non-existent node_info_read_and_reply
        dap_chain_node_info_t *node_info = dap_chain_node_info_read(l_net, &l_node_addr);
        if (!node_info) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR,
                                   "Node info not found for specified address");
            return -6;
        }
        
        int timeout_ms = 5000;
        int res = dap_chain_node_sync_handshake(l_net, node_info, "CN", timeout_ms);
        DAP_DELETE(node_info);
        
        if (res != DAP_SYNC_ERROR_NONE) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_RESPONSE_ERR,
                                   "No response from node: %s", dap_chain_node_sync_error_str(res));
            return -DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_RESPONSE_ERR;
        }
        
        dap_json_t *json_obj_out = dap_json_object_new();
        if (!json_obj_out) 
            return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        dap_json_object_add_string(json_obj_out, "status_handshake", "Connection established");
        dap_json_array_add(a_json_arr_reply, json_obj_out);
    } break;

    case CMD_CONNECTIONS: {

        if (l_net) {
            dap_cluster_t *l_links_cluster = dap_cluster_by_mnemonim(l_net->pub.name);
            if (!l_links_cluster) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_NOT_FOUND_LINKS_ERR,
                                            "Not found links cluster for net %s", l_net->pub.name);
                break;
            }
            dap_json_t *l_jobj_links = dap_cluster_get_links_info_json(l_links_cluster);
            dap_json_array_add(a_json_arr_reply, l_jobj_links);
        } else {
            const char *l_guuid_str = NULL;
            dap_cluster_t *l_cluster = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cluster", &l_guuid_str);
            if (l_guuid_str) {
                bool l_success = false;
                dap_guuid_t l_guuid = dap_guuid_from_hex_str(l_guuid_str, &l_success);
                if (!l_success) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_CANT_PARSE_CLUSTER_ERR,
                                                    "Can't parse cluster guid %s", l_guuid_str);
                    break;
                }
                l_cluster = dap_cluster_find(l_guuid);
                
                if (!l_cluster) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_NOT_FOUND_CLUSTER_ID_ERR,
                                                    "Not found cluster with ID %s", l_guuid_str);
                    break;
                }
            }
            dap_json_t *l_jobj_links = dap_cluster_get_links_info_json(l_cluster);
            dap_json_array_add(a_json_arr_reply, l_jobj_links);
        }
    } break;

    case  CMD_BAN: {
        dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
        if(!l_chain) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_NETWORK_DOESNOT_SUPPORT_ERR,
                                        "Network %s does not support decrees.", l_net->pub.name);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_NETWORK_DOESNOT_SUPPORT_ERR;
        }
        const char * l_hash_out_type = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
        if(!l_hash_out_type)
            l_hash_out_type = "hex";
        if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_INVALID_PARAMETER_ERR,
                                        "invalid parameter -H, valid values: -H <hex | base58>");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_INVALID_PARAMETER_ERR;
        }
        const char *l_certs_str = NULL;
        size_t l_certs_count = 0;
        dap_cert_t **l_certs = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_REQUIRES_PARAMETER_ERR,
                                        "ban create requires parameter '-certs'");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_REQUIRES_PARAMETER_ERR;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
        if(!l_certs_count) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_LEAST_ONE_VALID_CERT_ERR,
                                        "decree create command request at least one valid certificate to sign the decree");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_LEAST_ONE_VALID_CERT_ERR;
        }
        dap_chain_datum_decree_t *l_decree = NULL;
        dap_tsd_t *l_addr_tsd = s_chain_node_cli_com_node_create_tsd_addr_json(a_argv, arg_index, a_argc, a_json_arr_reply, "bun");
        if (!l_addr_tsd) {
            return -112;
        }
        l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + dap_tsd_size(l_addr_tsd));
        l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
        l_decree->header.ts_created = dap_time_now();
        l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
        l_decree->header.common_decree_params.net_id = l_net->pub.id;
        l_decree->header.common_decree_params.chain_id = l_chain->id;
        l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(l_net);
        l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN;
        l_decree->header.data_size = dap_tsd_size(l_addr_tsd);
        l_decree->header.signs_size = 0;
        memcpy(l_decree->data_n_signs, l_addr_tsd, dap_tsd_size(l_addr_tsd));
        size_t l_total_signs_success = 0;
        l_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_decree, l_certs_count, &l_total_signs_success);
        if (!l_decree || !l_total_signs_success) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_DECREE_CREATION_FAILED_ERR,
                                            "Decree creation failed. Successful count of certificate signing is 0");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_DECREE_CREATION_FAILED_ERR;
        }
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, l_decree,
                                                            sizeof(*l_decree) + l_decree->header.data_size +
                                                            l_decree->header.signs_size);
        DAP_DELETE(l_decree);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        dap_json_t *json_obj_out = dap_json_object_new();
        if (!json_obj_out)
            return DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        dap_json_object_add_object(json_obj_out, "datum_placed_status", l_key_str_out ? dap_json_object_new_string(l_key_str_out) :
                                                                                    dap_json_object_new_string("not placed"));
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        DAP_DELETE(l_key_str_out);
    } break;

    case CMD_UNBAN: {
        dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
        if(!l_chain) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_NETWORK_DOES_NOT_SUPPORT_ERR,
                                            "Network %s does not support decrees.", l_net->pub.name);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_NETWORK_DOES_NOT_SUPPORT_ERR;
        }
        const char * l_hash_out_type = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
        if(!l_hash_out_type)
            l_hash_out_type = "hex";
        if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_INVALID_PRAMETER_ERR,
                                        "invalid parameter -H, valid values: -H <hex | base58>");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_INVALID_PRAMETER_ERR;
        }
        const char *l_certs_str = NULL;
        size_t l_certs_count = 0;
        dap_cert_t **l_certs = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_REQUIRES_PARAMETER_CERT_ERR,
                                        "ban create requires parameter '-certs'");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_REQUIRES_PARAMETER_CERT_ERR;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
        if(!l_certs_count) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_LEAST_ONE_VALID_CERT_ERR,
                                        "decree create command request at least one valid certificate to sign the decree");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_LEAST_ONE_VALID_CERT_ERR;
        }
        dap_chain_datum_decree_t *l_decree = NULL;
        dap_tsd_t *l_addr_tsd = s_chain_node_cli_com_node_create_tsd_addr_json(a_argv, arg_index, a_argc, a_json_arr_reply, "unbun");
        if (!l_addr_tsd) {
            return -112;
        }
        l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + dap_tsd_size(l_addr_tsd));
        l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
        l_decree->header.ts_created = dap_time_now();
        l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
        l_decree->header.common_decree_params.net_id = l_net->pub.id;
        l_decree->header.common_decree_params.chain_id = l_chain->id;
        l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(l_net);
        l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN;
        l_decree->header.data_size = dap_tsd_size(l_addr_tsd);
        l_decree->header.signs_size = 0;
        memcpy(l_decree->data_n_signs, l_addr_tsd, dap_tsd_size(l_addr_tsd));
        size_t l_total_signs_success = 0;
        l_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_decree, l_certs_count, &l_total_signs_success);
        if (!l_decree || !l_total_signs_success) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_DECREE_CREATION_FAILED_ERR,
                                                    "Decree creation failed. Successful count of certificate signing is 0");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_DECREE_CREATION_FAILED_ERR;
        }
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, l_decree,
                                                            sizeof(*l_decree) + l_decree->header.data_size +
                                                            l_decree->header.signs_size);
        DAP_DELETE(l_decree);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        dap_json_t *json_obj_out = dap_json_object_new();
        if (!json_obj_out) return dap_json_object_free(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        dap_json_object_add_object(json_obj_out, "datum_placed_status", l_key_str_out ? dap_json_object_new_string(l_key_str_out) :
                                                                                    dap_json_object_new_string("not placed"));
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        DAP_DELETE(l_key_str_out);
    } break;

    case CMD_BANLIST: {
        dap_json_t *json_obj_out = dap_http_ban_list_client_dump(NULL);
        dap_json_array_add(a_json_arr_reply, json_obj_out);
    } break;

    case CMD_BALANCER: {
        //balancer link list
        dap_json_t *l_links_list = dap_chain_net_balancer_get_node_str(l_net);
        dap_json_array_add(a_json_arr_reply, l_links_list);
    } break;

    default:
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNRECOGNISED_SUB_ERR,
                                    "Unrecognized subcommand '%s'", arg_index < a_argc ? a_argv[arg_index] : "(null)");
        break;
    }
    return 0;
}

/**
 * @brief s_print_for_help - Format help output as a table
 * @param a_json_input JSON input from command handler
 * @param a_json_output JSON output for CLI
 * @param a_cmd_param Command parameters
 * @param a_cmd_cnt Parameter count
 * @return 0 on success, -1 to use raw JSON
 */
static int s_print_for_help(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt)
{
    (void)a_cmd_param;
    (void)a_cmd_cnt;
    dap_return_val_if_pass(!a_json_input || !a_json_output, -1);
    
    // Always use table mode for help output
    if (dap_json_get_type(a_json_input) != DAP_JSON_TYPE_ARRAY)
        return -1;
    
    int l_arr_len = dap_json_array_length(a_json_input);
    if (l_arr_len <= 0)
        return -1;
    
    dap_json_t *l_json_obj = dap_json_array_get_idx(a_json_input, 0);
    if (!l_json_obj)
        return -1;
    
    dap_string_t *l_str = dap_string_new("\n");
    
    // Check if this is a single command help or list of all commands
    dap_json_t *l_commands = NULL;
    dap_json_t *l_usage = NULL;
    
    if (dap_json_object_get_ex(l_json_obj, "commands", &l_commands)) {
        // List of all commands - display as table (sorted alphabetically)
        int l_cmd_count = dap_json_array_length(l_commands);
        
        // Build array of command names and descriptions for sorting
        typedef struct {
            const char *name;
            const char *desc;
        } cmd_entry_t;
        
        cmd_entry_t *l_entries = DAP_NEW_Z_COUNT(cmd_entry_t, l_cmd_count);
        if (!l_entries) {
            dap_string_free(l_str, true);
            return -1;
        }
        
        int l_valid_count = 0;
        for (int i = 0; i < l_cmd_count; i++) {
            dap_json_t *l_cmd_obj = dap_json_array_get_idx(l_commands, i);
            if (!l_cmd_obj)
                continue;
            
            dap_json_t *l_name = NULL, *l_desc = NULL;
            dap_json_object_get_ex(l_cmd_obj, "name", &l_name);
            dap_json_object_get_ex(l_cmd_obj, "description", &l_desc);
            
            l_entries[l_valid_count].name = l_name ? dap_json_get_string(l_name) : "(unknown)";
            l_entries[l_valid_count].desc = l_desc ? dap_json_get_string(l_desc) : "(no description)";
            l_valid_count++;
        }
        
        // Sort entries alphabetically by name (simple bubble sort for small lists)
        for (int i = 0; i < l_valid_count - 1; i++) {
            for (int j = 0; j < l_valid_count - i - 1; j++) {
                if (strcmp(l_entries[j].name, l_entries[j + 1].name) > 0) {
                    cmd_entry_t l_tmp = l_entries[j];
                    l_entries[j] = l_entries[j + 1];
                    l_entries[j + 1] = l_tmp;
                }
            }
        }
        
        // Output sorted table
        dap_string_append(l_str, "________________________________________________________________________________\n");
        dap_string_append_printf(l_str, " %-20s | %-55s |\n", "Command", "Description");
        dap_string_append(l_str, "______________________|_________________________________________________________|\n");
        
        for (int i = 0; i < l_valid_count; i++) {
            const char *l_desc_str = l_entries[i].desc;
            
            // Truncate description if too long
            char l_desc_buf[56];
            if (strlen(l_desc_str) > 55) {
                strncpy(l_desc_buf, l_desc_str, 52);
                l_desc_buf[52] = '.';
                l_desc_buf[53] = '.';
                l_desc_buf[54] = '.';
                l_desc_buf[55] = '\0';
                l_desc_str = l_desc_buf;
            }
            
            dap_string_append_printf(l_str, " %-20s | %-55s |\n", l_entries[i].name, l_desc_str);
        }
        
        DAP_DELETE(l_entries);
        
        dap_string_append(l_str, "______________________|_________________________________________________________|\n");
        dap_string_append_printf(l_str, "\n\tTotal commands: %d\n", l_valid_count);
        dap_string_append(l_str, "\tUse 'help <command>' for detailed usage information.\n");
    } else if (dap_json_object_get_ex(l_json_obj, "usage", &l_usage)) {
        // Single command help
        dap_json_t *l_cmd_name = NULL, *l_desc = NULL;
        dap_json_object_get_ex(l_json_obj, "command", &l_cmd_name);
        dap_json_object_get_ex(l_json_obj, "description", &l_desc);
        
        dap_string_append(l_str, "________________________________________________________________________________\n");
        if (l_cmd_name)
            dap_string_append_printf(l_str, "Command: %s\n", dap_json_get_string(l_cmd_name));
        if (l_desc)
            dap_string_append_printf(l_str, "Description: %s\n", dap_json_get_string(l_desc));
        dap_string_append(l_str, "________________________________________________________________________________\n");
        dap_string_append(l_str, "Usage:\n");
        dap_string_append_printf(l_str, "%s\n", dap_json_get_string(l_usage));
    } else {
        // Unknown format, return raw JSON
        dap_string_free(l_str, true);
        return -1;
    }
    
    dap_json_t *l_json_result = dap_json_object_new();
    dap_json_object_add_string(l_json_result, "output", l_str->str);
    dap_json_array_add(a_json_output, l_json_result);
    dap_string_free(l_str, true);
    return 0;
}

/**
 * @brief s_cli_help - Display help for commands
 * @param argc argument count
 * @param argv arguments
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success
 */
static int s_cli_help(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void)a_version;
    dap_json_t *l_jobj_return = dap_json_object_new();
    if (!l_jobj_return) {
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return -1;
    }

    // Find the first non-flag argument (command name to get help for)
    const char *l_cmd_name = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i] && argv[i][0] != '-') {
            l_cmd_name = argv[i];
            break;
        }
    }

    if (l_cmd_name) {
        // Help for specific command
        dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find(l_cmd_name);
        if (l_cmd) {
            dap_json_object_add_string(l_jobj_return, "command", l_cmd->name);
            dap_json_object_add_string(l_jobj_return, "description", l_cmd->doc ? l_cmd->doc : "(undocumented)");
            dap_json_object_add_string(l_jobj_return, "usage", l_cmd->doc_ex ? l_cmd->doc_ex : "(no usage info)");
            dap_json_array_add(a_json_arr_reply, l_jobj_return);
            return 0;
        } else {
            dap_json_object_free(l_jobj_return);
            dap_json_rpc_error_add(a_json_arr_reply, -1, "Command '%s' not recognized", l_cmd_name);
            return -1;
        }
    } else {
        // List all commands
        dap_json_t *l_jobj_commands = dap_json_array_new();
        if (!l_jobj_commands) {
            dap_json_object_free(l_jobj_return);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return -1;
        }

        dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_get_first();
        while (l_cmd) {
            dap_json_t *l_jobj_cmd = dap_json_object_new();
            if (l_jobj_cmd) {
                dap_json_object_add_string(l_jobj_cmd, "name", l_cmd->name);
                dap_json_object_add_string(l_jobj_cmd, "description", l_cmd->doc ? l_cmd->doc : "(undocumented)");
                dap_json_array_add(l_jobj_commands, l_jobj_cmd);
            }
            l_cmd = (dap_cli_cmd_t *)l_cmd->hh.next;
        }

        dap_json_object_add_object(l_jobj_return, "commands", l_jobj_commands);
        dap_json_array_add(a_json_arr_reply, l_jobj_return);
        return 0;
    }
}

/**
 * @brief s_cli_version - Display version information
 * @param argc argument count
 * @param argv arguments
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success
 */
static int s_cli_version(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void)argc;
    (void)argv;
    (void)a_version;
    
    dap_json_t *l_jobj_return = dap_json_object_new();
    if (!l_jobj_return) {
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return -1;
    }

#ifdef DAP_VERSION
    dap_json_object_add_string(l_jobj_return, "version", DAP_VERSION);
#else
    dap_json_object_add_string(l_jobj_return, "version", "unknown");
#endif

#ifdef CELLFRAME_SDK_VERSION
    dap_json_object_add_string(l_jobj_return, "sdk_version", CELLFRAME_SDK_VERSION);
#endif

#ifdef BUILD_HASH
    dap_json_object_add_string(l_jobj_return, "build_hash", BUILD_HASH);
#endif

#ifdef BUILD_TS
    dap_json_object_add_string(l_jobj_return, "build_date", BUILD_TS);
#endif

    dap_json_array_add(a_json_arr_reply, l_jobj_return);
    return 0;
}

/**
 * @brief s_cli_print_log - Print log entries from the log file
 * @param argc argument count
 * @param argv arguments
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success
 */
static int s_cli_print_log(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void)a_version;
    int l_arg_index = 1;
    const char *l_str_ts_after = NULL;
    const char *l_str_limit = NULL;
    int64_t l_ts_after = 0;
    long l_limit = 0;
    
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "ts_after", &l_str_ts_after);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "limit", &l_str_limit);

    l_ts_after = l_str_ts_after ? strtoll(l_str_ts_after, NULL, 10) : -1;
    l_limit = l_str_limit ? strtol(l_str_limit, NULL, 10) : -1;

    if (l_ts_after < 0 || !l_str_ts_after) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_TS_AFTER,
                               "requires valid parameter 'ts_after'");
        return -DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_TS_AFTER;
    }
    if (l_limit <= 0) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_LIMIT,
                               "requires valid parameter 'limit'");
        return -DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_LIMIT;
    }

    // Get log file path from config
    const char *l_log_file = dap_config_get_item_str(g_config, "general", "log_file");
    if (!l_log_file) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_NO_FILE,
                               "Log file path not configured");
        return -DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_NO_FILE;
    }

    // Get logs from file
    char *l_str_ret = dap_log_get_item(l_log_file, (time_t)l_ts_after, (int)l_limit);
    if (!l_str_ret) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_NO_LOGS,
                               "No logs found for the specified time range");
        return -DAP_CHAIN_NET_CLI_ERROR_PRINT_LOG_NO_LOGS;
    }

    dap_json_t *l_jobj_return = dap_json_object_new();
    if (!l_jobj_return) {
        DAP_DELETE(l_str_ret);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return -1;
    }

    dap_json_object_add_int64(l_jobj_return, "ts_after", l_ts_after);
    dap_json_object_add_int64(l_jobj_return, "limit", l_limit);
    dap_json_object_add_string(l_jobj_return, "log_file", l_log_file);
    dap_json_object_add_string(l_jobj_return, "logs", l_str_ret);
    dap_json_array_add(a_json_arr_reply, l_jobj_return);
    
    DAP_DELETE(l_str_ret);
    return 0;
}

/**
 * @brief s_print_for_print_log - Format print_log output
 * @param a_json_input JSON input from command handler
 * @param a_json_output JSON output for CLI
 * @param a_cmd_param Command parameters
 * @param a_cmd_cnt Parameter count
 * @return 0 on success, -1 to use raw JSON
 */
static int s_print_for_print_log(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt)
{
    (void)a_cmd_param;
    (void)a_cmd_cnt;
    dap_return_val_if_pass(!a_json_input || !a_json_output, -1);
    
    if (dap_json_get_type(a_json_input) != DAP_JSON_TYPE_ARRAY)
        return -1;
    
    int l_arr_len = dap_json_array_length(a_json_input);
    if (l_arr_len <= 0)
        return -1;
    
    dap_json_t *l_json_obj = dap_json_array_get_idx(a_json_input, 0);
    if (!l_json_obj)
        return -1;
    
    dap_json_t *l_logs = NULL;
    if (!dap_json_object_get_ex(l_json_obj, "logs", &l_logs))
        return -1;
    
    const char *l_logs_str = dap_json_get_string(l_logs);
    if (!l_logs_str)
        return -1;
    
    dap_string_t *l_str = dap_string_new("\n");
    
    // Get metadata
    dap_json_t *l_ts_after = NULL, *l_limit = NULL, *l_log_file = NULL;
    dap_json_object_get_ex(l_json_obj, "ts_after", &l_ts_after);
    dap_json_object_get_ex(l_json_obj, "limit", &l_limit);
    dap_json_object_get_ex(l_json_obj, "log_file", &l_log_file);
    
    dap_string_append(l_str, "================================================================================\n");
    if (l_log_file)
        dap_string_append_printf(l_str, "Log file: %s\n", dap_json_get_string(l_log_file));
    if (l_ts_after)
        dap_string_append_printf(l_str, "From timestamp: %" DAP_INT64_FORMAT "\n", dap_json_get_int64(l_ts_after));
    if (l_limit)
        dap_string_append_printf(l_str, "Limit: %" DAP_INT64_FORMAT " lines\n", dap_json_get_int64(l_limit));
    dap_string_append(l_str, "================================================================================\n");
    dap_string_append(l_str, l_logs_str);
    dap_string_append(l_str, "\n================================================================================\n");
    
    dap_json_t *l_json_result = dap_json_object_new();
    dap_json_object_add_string(l_json_result, "output", l_str->str);
    dap_json_array_add(a_json_output, l_json_result);
    dap_string_free(l_str, true);
    return 0;
}

/**
 * @brief s_cli_exit - Stop application and exit
 * @param argc argument count
 * @param argv arguments
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success (never returns)
 */
static int s_cli_exit(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void)argc;
    (void)argv;
    (void)a_json_arr_reply;
    (void)a_version;
    
    log_it(L_NOTICE, "Exit command received, stopping node...");
    exit(0);
    return 0;
}

/**
 * @brief Helper function to stop all networks
 * @return List of networks that were stopped (need to be restarted later)
 */
static dap_list_t *s_go_all_nets_offline(void)
{
    dap_list_t *l_net_returns = NULL;
    for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
        if (dap_chain_net_stop(it))
            l_net_returns = dap_list_append(l_net_returns, it);
    }
    return l_net_returns;
}

/**
 * @brief Private structure for storing network nodes list
 */
typedef struct s_pvt_net_nodes_list {
    dap_chain_net_t *net;
    dap_global_db_obj_t *group_nodes;
    size_t count_nodes;
} s_pvt_net_nodes_list_t;

/**
 * @brief s_cli_remove - Delete chain files or global database
 * @param argc argument count
 * @param argv arguments
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, error code otherwise
 */
static int s_cli_remove(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void)a_version;
    
    const char *l_gdb_path = NULL;
    const char *l_net_str = NULL;
    dap_chain_net_t *l_net = NULL;
    int l_all = 0;
    
    // Error and success flags
    uint8_t l_error = 0;
    uint8_t l_successful = 0;
    
    // Error codes
    enum {
        GDB_FAIL_PATH       = 0x01,
        CHAINS_FAIL_PATH    = 0x02,
        COMMAND_NOT_CORRECT = 0x04,
        NET_NOT_VALID       = 0x08
    };
    
    // Success codes
    enum {
        REMOVED_GDB    = 0x01,
        REMOVED_CHAINS = 0x02
    };
    
    // Check paths from config file
    if (dap_cli_server_cmd_check_option(argv, 1, argc, "-gdb") >= 0
        && (NULL == (l_gdb_path = dap_config_get_item_str(g_config, "global_db", "path")))) {
        l_error |= GDB_FAIL_PATH;
    }
    
    dap_list_t *l_net_returns = NULL;
    
    // Perform GDB deletion
    if (l_gdb_path) {
        l_net_returns = s_go_all_nets_offline();
        dap_list_t *l_gdb_nodes_list = NULL;
        
        // Save nodes list for each network
        for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
            s_pvt_net_nodes_list_t *l_gdb_groups = DAP_NEW_Z(s_pvt_net_nodes_list_t);
            if (!l_gdb_groups) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_list_free(l_net_returns);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return -1;
            }
            l_gdb_groups->net = it;
            l_gdb_groups->group_nodes = dap_global_db_get_all_sync(l_gdb_groups->net->pub.gdb_nodes, &l_gdb_groups->count_nodes);
            l_gdb_nodes_list = dap_list_append(l_gdb_nodes_list, l_gdb_groups);
        }
        
        // Erase all GDB groups
        dap_list_t *l_group_list = dap_global_db_driver_get_groups_by_mask("*");
        for (dap_list_t *l_list = l_group_list; l_list; l_list = dap_list_next(l_list)) {
            dap_global_db_erase_table_sync((const char *)(l_list->data));
        }
        dap_list_free_full(l_group_list, NULL);
        
        // Restore GDB version
        uint32_t l_version = DAP_GLOBAL_DB_VERSION;
        if (dap_global_db_set_sync(DAP_GLOBAL_DB_LOCAL_GENERAL, "gdb_version", &l_version, sizeof(l_version), false))
            log_it(L_ERROR, "Can't add information about gdb_version");
        
        // Restore nodes list for each network
        for (dap_list_t *ptr = l_gdb_nodes_list; ptr; ptr = dap_list_next(ptr)) {
            s_pvt_net_nodes_list_t *l_tmp = (s_pvt_net_nodes_list_t *)ptr->data;
            for (size_t i = 0; i < l_tmp->count_nodes; i++) {
                dap_global_db_obj_t l_obj = l_tmp->group_nodes[i];
                dap_global_db_set_sync(l_tmp->net->pub.gdb_nodes, l_obj.key, l_obj.value, l_obj.value_len, false);
            }
            dap_global_db_objs_delete(l_tmp->group_nodes, l_tmp->count_nodes);
        }
        dap_list_free_full(l_gdb_nodes_list, NULL);
        
        if (!l_error)
            l_successful |= REMOVED_GDB;
    }
    
    // Perform chains deletion
    if (dap_cli_server_cmd_check_option(argv, 1, argc, "-chains") >= 0) {
        dap_cli_server_cmd_find_option_val(argv, 1, argc, "-net", &l_net_str);
        l_all = dap_cli_server_cmd_check_option(argv, 1, argc, "-all");
        
        if (NULL == l_net_str && l_all >= 0) {
            // Remove all chains
            if (NULL == l_gdb_path)
                l_net_returns = s_go_all_nets_offline();
            for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
                dap_chain_net_purge(it);
            }
            if (!l_error)
                l_successful |= REMOVED_CHAINS;
        } else if (NULL != l_net_str && l_all < 0) {
            // Remove specific network chains
            if (NULL != (l_net = dap_chain_net_by_name(l_net_str))) {
                if (NULL == l_gdb_path && dap_chain_net_stop(l_net))
                    l_net_returns = dap_list_append(l_net_returns, l_net);
                dap_chain_net_purge(l_net);
                if (!l_error)
                    l_successful |= REMOVED_CHAINS;
            } else {
                l_error |= NET_NOT_VALID;
            }
        } else {
            l_error |= COMMAND_NOT_CORRECT;
        }
    }
    
    // Handle errors and generate response
    if (l_error & GDB_FAIL_PATH || l_error & CHAINS_FAIL_PATH) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_REMOVE_PATH,
            "The node configuration file does not specify the path to the database and/or chains.\n"
            "Please check the cellframe-node.cfg file in the [resources] item for subitems:\n"
            "dap_global_db_path=<PATH>\n"
            "dap_chains_path=<PATH>");
    } else if (l_error & COMMAND_NOT_CORRECT) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_REMOVE_CMD,
            "You need to make a decision whether to remove all chains or a chain from a specific network.\n"
            "You cannot use two keys '-net' and '-all' at the same time.\n"
            "Be careful, the '-all' option will delete ALL CHAINS and won't ask you for permission!");
    } else if (l_error & NET_NOT_VALID) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_REMOVE_NET,
            "The specified network was not found.\n"
            "The list of available networks can be viewed using the command: 'net list'");
    } else if (l_successful) {
        dap_json_t *l_jobj_return = dap_json_object_new();
        const char *l_status_str = (l_successful & REMOVED_GDB && l_successful & REMOVED_CHAINS) ? "gdb, chains" :
                                   (l_successful & REMOVED_GDB) ? "gdb" :
                                   (l_successful & REMOVED_CHAINS) ? "chains" : "";
        dap_json_object_add_string(l_jobj_return, "status", "success");
        dap_json_object_add_string(l_jobj_return, "removed", l_status_str);
        dap_json_array_add(a_json_arr_reply, l_jobj_return);
    } else {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_REMOVE_NOTHING,
            "Nothing to delete. Check if the command is correct.\n"
            "Use flags: -gdb or/and -chains [-net <net_name> | -all]\n"
            "Be careful, the '-all' option will delete ALL CHAINS and won't ask you for permission!");
    }
    
    // Restart networks that were stopped
    for (dap_list_t *it = l_net_returns; it; it = it->next)
        dap_chain_net_start((dap_chain_net_t *)it->data);
    dap_list_free(l_net_returns);
    
    return l_error;
}

/**
 * @brief Sign anchor datum in cycle with multiple certificates
 * @param a_certs Array of certificates to sign with
 * @param a_datum_anchor Anchor datum to sign
 * @param a_certs_count Number of certificates
 * @param a_total_sign_count Output: number of successful signatures
 * @return dap_chain_datum_anchor_t* Signed anchor or NULL on failure
 */
static dap_chain_datum_anchor_t *s_sign_anchor_in_cycle(dap_cert_t **a_certs, dap_chain_datum_anchor_t *a_datum_anchor,
                                                         size_t a_certs_count, size_t *a_total_sign_count)
{
    size_t l_cur_sign_offset = a_datum_anchor->header.data_size + a_datum_anchor->header.signs_size;
    size_t l_total_signs_size = a_datum_anchor->header.signs_size, l_total_sign_count = 0;

    for (size_t i = 0; i < a_certs_count; i++) {
        dap_sign_t *l_sign = dap_cert_sign(a_certs[i], a_datum_anchor, 
                                           sizeof(dap_chain_datum_anchor_t) + a_datum_anchor->header.data_size);

        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            dap_chain_datum_anchor_t *l_new_anchor = DAP_REALLOC(a_datum_anchor, 
                sizeof(dap_chain_datum_anchor_t) + l_cur_sign_offset + l_sign_size);
            if (!l_new_anchor) {
                DAP_DELETE(l_sign);
                log_it(L_ERROR, "Memory allocation failed for anchor realloc");
                return a_datum_anchor;
            }
            a_datum_anchor = l_new_anchor;
            memcpy((byte_t*)a_datum_anchor->data_n_sign + l_cur_sign_offset, l_sign, l_sign_size);
            l_total_signs_size += l_sign_size;
            l_cur_sign_offset += l_sign_size;
            a_datum_anchor->header.signs_size = l_total_signs_size;
            DAP_DELETE(l_sign);
            log_it(L_DEBUG, "<-- Anchor signed with '%s'", a_certs[i]->name);
            l_total_sign_count++;
        }
    }

    if (a_total_sign_count)
        *a_total_sign_count = l_total_sign_count;
    return a_datum_anchor;
}

// Decree command enums
enum {
    DECREE_CMD_NONE = 0,
    DECREE_CMD_CREATE,
    DECREE_CMD_SIGN,
    DECREE_CMD_ANCHOR
    // Note: DECREE_CMD_FIND and DECREE_CMD_INFO require dap_chain_net_decree_get_by_hash 
    // and dap_chain_net_get_net_decree which are not implemented yet
};

enum {
    DECREE_TYPE_NONE = 0,
    DECREE_TYPE_COMMON,
    DECREE_TYPE_SERVICE
};

enum {
    DECREE_SUBTYPE_NONE = 0,
    DECREE_SUBTYPE_FEE,
    DECREE_SUBTYPE_OWNERS,
    DECREE_SUBTYPE_MIN_OWNERS
};

/**
 * @brief CLI command handler for decree operations
 * @param argc Argument count
 * @param argv Argument values
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, negative error code on failure
 * 
 * Supported subcommands:
 *   create common - Create common decree (fee, owners, min_owners)
 *   sign          - Sign existing decree in mempool
 *   anchor        - Create anchor for decree
 * 
 * Note: 'find' and 'info' subcommands are not implemented yet as they require
 * dap_chain_net_decree_get_by_hash and dap_chain_net_get_net_decree functions.
 */
static int s_cli_decree(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void)a_version;
    
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;
    const char *l_certs_str = NULL;
    const char *l_decree_chain_str = NULL;
    const char *l_hash_out_type = NULL;
    
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    dap_chain_t *l_decree_chain = NULL;
    dap_cert_t **l_certs = NULL;
    size_t l_certs_count = 0;
    
    // Get hash output type
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_INVALID_HASH_TYPE,
            "Invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NET_CLI_ERROR_DECREE_INVALID_HASH_TYPE;
    }
    
    // Get network
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_NET_REQUIRED,
            "Command requires parameter '-net'");
        return -DAP_CHAIN_NET_CLI_ERROR_DECREE_NET_REQUIRED;
    }
    l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_NET_NOT_FOUND,
            "Network '%s' not found", l_net_str);
        return -DAP_CHAIN_NET_CLI_ERROR_DECREE_NET_NOT_FOUND;
    }
    
    // Determine subcommand
    int l_cmd = DECREE_CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "create", NULL))
        l_cmd = DECREE_CMD_CREATE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "sign", NULL))
        l_cmd = DECREE_CMD_SIGN;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "anchor", NULL))
        l_cmd = DECREE_CMD_ANCHOR;
    
    // Parse certificates for commands that need them
    if (l_cmd != DECREE_CMD_NONE) {
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CERTS_REQUIRED,
                "Decree command requires parameter '-certs'");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CERTS_REQUIRED;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
        if (!l_certs_count) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CERTS_INVALID,
                "At least one valid certificate is required to sign the decree");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CERTS_INVALID;
        }
    }
    
    switch (l_cmd) {
    case DECREE_CMD_CREATE: {
        int l_type = DECREE_TYPE_NONE;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "common", NULL))
            l_type = DECREE_TYPE_COMMON;
        else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "service", NULL))
            l_type = DECREE_TYPE_SERVICE;
        
        dap_chain_datum_decree_t *l_datum_decree = NULL;
        
        if (l_type == DECREE_TYPE_COMMON) {
            // Get chain for decree storage
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
            if (l_chain_str) {
                l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
                if (!l_chain) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NOT_FOUND,
                        "Invalid '-chain' parameter '%s', not found in net %s", l_chain_str, l_net_str);
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NOT_FOUND;
                }
                if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NO_SUPPORT,
                        "Chain '%s' doesn't support decree", l_chain->name);
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NO_SUPPORT;
                }
            } else {
                l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
                if (!l_chain) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_NO_DECREE_CHAIN,
                        "Can't find chain with decree support in network '%s'", l_net_str);
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_NO_DECREE_CHAIN;
                }
            }
            
            // Get decree_chain (chain the decree applies to)
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-decree_chain", &l_decree_chain_str);
            if (l_decree_chain_str) {
                l_decree_chain = dap_chain_net_get_chain_by_name(l_net, l_decree_chain_str);
                if (!l_decree_chain) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_DECREE_CHAIN_NOT_FOUND,
                        "Invalid '-decree_chain' parameter '%s', not found in net %s", l_decree_chain_str, l_net_str);
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_DECREE_CHAIN_NOT_FOUND;
                }
            } else {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_DECREE_CHAIN_REQUIRED,
                    "Decree requires parameter '-decree_chain'");
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_DECREE_CHAIN_REQUIRED;
            }
            
            // Parse decree subtype and TSD data
            dap_tsd_t *l_tsd = NULL;
            size_t l_total_tsd_size = 0;
            dap_list_t *l_tsd_list = NULL;
            
            int l_subtype = DECREE_SUBTYPE_NONE;
            const char *l_param_value_str = NULL;
            const char *l_param_addr_str = NULL;
            
            // FEE subtype
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_param_value_str)) {
                l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE;
                
                // Check for fee address
                if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_addr", &l_param_addr_str)) {
                    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t));
                    if (!l_tsd) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        dap_list_free_full(l_tsd_list, NULL);
                        return -1;
                    }
                    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET;
                    l_tsd->size = sizeof(dap_chain_addr_t);
                    dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_param_addr_str);
                    if (l_addr) {
                        memcpy(l_tsd->data, l_addr, sizeof(dap_chain_addr_t));
                        DAP_DELETE(l_addr);
                    }
                    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                    l_total_tsd_size += dap_tsd_size(l_tsd);
                } else if (dap_chain_addr_is_blank(&l_net->pub.fee_addr)) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_FEE_ADDR_REQUIRED,
                        "Use -to_addr parameter to set net fee address");
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_FEE_ADDR_REQUIRED;
                }
                
                // Fee value TSD
                l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, sizeof(dap_tsd_t) + sizeof(uint256_t));
                if (!l_tsd) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    dap_list_free_full(l_tsd_list, NULL);
                    return -1;
                }
                l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE;
                l_tsd->size = sizeof(uint256_t);
                *(uint256_t*)(l_tsd->data) = dap_uint256_scan_uninteger(l_param_value_str);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                l_total_tsd_size += dap_tsd_size(l_tsd);
                
            // OWNERS subtype (new certificates for network ownership)
            } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-new_certs", &l_param_value_str)) {
                l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS;
                
                dap_cert_t **l_new_certs = NULL;
                size_t l_new_certs_count = 0;
                dap_cert_parse_str_list(l_param_value_str, &l_new_certs, &l_new_certs_count);
                
                // Note: In master, they check dap_chain_net_get_net_decree(l_net)->min_num_of_owners
                // This is not available in for_update yet, so we skip that check
                
                size_t l_failed_certs = 0;
                for (size_t i = 0; i < l_new_certs_count; i++) {
                    dap_pkey_t *l_pkey = dap_cert_to_pkey(l_new_certs[i]);
                    if (!l_pkey) {
                        log_it(L_WARNING, "New cert [%zu] has no public key.", i);
                        l_failed_certs++;
                        continue;
                    }
                    l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER, l_pkey, 
                                           sizeof(dap_pkey_t) + (size_t)l_pkey->header.size);
                    DAP_DELETE(l_pkey);
                    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                    l_total_tsd_size += dap_tsd_size(l_tsd);
                }
                DAP_DELETE(l_new_certs);
                
                if (l_failed_certs) {
                    dap_list_free_full(l_tsd_list, NULL);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CERTS_INVALID,
                        "Some certificates have no public key");
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CERTS_INVALID;
                }
                
            // MIN_OWNERS subtype
            } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-signs_verify", &l_param_value_str)) {
                l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN;
                
                uint256_t l_new_num_of_owners = dap_uint256_scan_uninteger(l_param_value_str);
                if (IS_ZERO_256(l_new_num_of_owners)) {
                    log_it(L_WARNING, "The minimum number of owners can't be zero");
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_MIN_OWNERS_ZERO,
                        "The minimum number of owners can't be zero");
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_MIN_OWNERS_ZERO;
                }
                
                // Note: In master, they check against dap_chain_net_get_net_decree(l_net)->num_of_owners
                // This is not available in for_update yet, so we skip that check
                
                l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, sizeof(dap_tsd_t) + sizeof(uint256_t));
                if (!l_tsd) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    return -1;
                }
                l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER;
                l_tsd->size = sizeof(uint256_t);
                *(uint256_t*)(l_tsd->data) = l_new_num_of_owners;
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                l_total_tsd_size += dap_tsd_size(l_tsd);
                
            } else {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_SUBTYPE_REQUIRED,
                    "Decree subtype required. Use -fee, -new_certs, or -signs_verify");
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_SUBTYPE_REQUIRED;
            }
            
            // Check chain compatibility with subtype
            if (l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS ||
                l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN) {
                if (l_decree_chain->id.uint64 != l_chain->id.uint64) {
                    dap_list_free_full(l_tsd_list, NULL);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_SUBTYPE_NOT_SUPPORTED,
                        "Decree subtype '%s' not supported by chain '%s'",
                        dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_SUBTYPE_NOT_SUPPORTED;
                }
            } else if (l_decree_chain->id.uint64 == l_chain->id.uint64) {
                dap_list_free_full(l_tsd_list, NULL);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_SUBTYPE_NOT_SUPPORTED,
                    "Decree subtype '%s' not supported by chain '%s'",
                    dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_SUBTYPE_NOT_SUPPORTED;
            }
            
            // Create decree datum
            l_datum_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, 
                                            sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
            if (!l_datum_decree) {
                dap_list_free_full(l_tsd_list, NULL);
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return -1;
            }
            
            l_datum_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
            l_datum_decree->header.ts_created = dap_time_now();
            l_datum_decree->header.type = l_type;
            l_datum_decree->header.common_decree_params.net_id = l_net->pub.id;
            l_datum_decree->header.common_decree_params.chain_id = l_decree_chain->id;
            l_datum_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(l_net);
            l_datum_decree->header.sub_type = l_subtype;
            l_datum_decree->header.data_size = l_total_tsd_size;
            l_datum_decree->header.signs_size = 0;
            
            // Copy TSD data
            size_t l_data_tsd_offset = 0;
            for (dap_list_t *l_iter = dap_list_first(l_tsd_list); l_iter; l_iter = l_iter->next) {
                dap_tsd_t *l_b_tsd = (dap_tsd_t *)l_iter->data;
                size_t l_tsd_size = dap_tsd_size(l_b_tsd);
                memcpy((byte_t*)l_datum_decree->data_n_signs + l_data_tsd_offset, l_b_tsd, l_tsd_size);
                l_data_tsd_offset += l_tsd_size;
            }
            dap_list_free_full(l_tsd_list, NULL);
            
        } else if (l_type == DECREE_TYPE_SERVICE) {
            // Service decree type - not fully implemented in master either
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_SERVICE_NOT_IMPL,
                "Service decree type is not implemented yet");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_SERVICE_NOT_IMPL;
            
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_TYPE_REQUIRED,
                "Decree type required. Use 'create common' or 'create service'");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_TYPE_REQUIRED;
        }
        
        // Sign decree
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_datum_decree, 
                                                                   l_certs_count, &l_total_signs_success);
        
        if (!l_datum_decree || l_total_signs_success == 0) {
            DAP_DEL_Z(l_datum_decree);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_SIGN_FAILED,
                "Decree creation failed. Successful count of certificate signing is 0");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_SIGN_FAILED;
        }
        
        // Create datum and add to mempool
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
            l_datum_decree,
            sizeof(*l_datum_decree) + l_datum_decree->header.data_size + l_datum_decree->header.signs_size);
        DAP_DELETE(l_datum_decree);
        
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        
        dap_json_t *l_jobj_result = dap_json_object_new();
        dap_json_object_add_string(l_jobj_result, "status", l_key_str_out ? "placed" : "not placed");
        if (l_key_str_out) {
            dap_json_object_add_string(l_jobj_result, "hash", l_key_str_out);
            DAP_DELETE(l_key_str_out);
        }
        dap_json_array_add(a_json_arr_reply, l_jobj_result);
        break;
    }
    
    case DECREE_CMD_SIGN: {
        const char *l_datum_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
        
        if (!l_datum_hash_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_DATUM_REQUIRED,
                "Decree sign requires '-datum <datum_hash>' argument");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_DATUM_REQUIRED;
        }
        
        // Get chain
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
        if (l_chain_str) {
            l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
            if (!l_chain) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NOT_FOUND,
                    "Invalid '-chain' parameter '%s', not found in net %s", l_chain_str, l_net_str);
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NOT_FOUND;
            }
            if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NO_SUPPORT,
                    "Chain '%s' doesn't support decree", l_chain->name);
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NO_SUPPORT;
            }
        } else {
            l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
            if (!l_chain) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_NO_DECREE_CHAIN,
                    "Can't find chain with decree support");
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_NO_DECREE_CHAIN;
            }
        }
        
        // Get mempool group
        char *l_gdb_group_mempool = dap_chain_mempool_group_new(l_chain);
        if (!l_gdb_group_mempool) {
            l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_DECREE);
        }
        
        // Convert hash format
        char *l_datum_hash_hex_str = NULL;
        char *l_datum_hash_base58_str = NULL;
        if (!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
            l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
            l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
        } else {
            l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
            l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
        }
        
        const char *l_datum_hash_out_str = !dap_strcmp(l_hash_out_type, "hex") 
            ? l_datum_hash_hex_str : l_datum_hash_base58_str;
        
        log_it(L_DEBUG, "Requested to sign decree %s in gdb://%s with certs %s",
               l_datum_hash_hex_str, l_gdb_group_mempool, l_certs_str);
        
        // Get datum from mempool
        size_t l_datum_size = 0;
        dap_chain_datum_t *l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(
            l_gdb_group_mempool, l_datum_hash_hex_str, &l_datum_size, NULL, NULL);
        
        if (l_datum) {
            if (l_datum->header.type_id == DAP_CHAIN_DATUM_DECREE) {
                dap_chain_datum_decree_t *l_datum_decree = DAP_DUP_SIZE(
                    (dap_chain_datum_decree_t*)l_datum->data, l_datum->header.data_size);
                DAP_DELETE(l_datum);
                
                // Sign decree
                size_t l_total_signs_success = 0;
                if (l_certs_count)
                    l_datum_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_datum_decree, 
                                                                           l_certs_count, &l_total_signs_success);
                
                if (!l_datum_decree || l_total_signs_success == 0) {
                    DAP_DEL_MULTY(l_datum_hash_hex_str, l_datum_hash_base58_str, l_gdb_group_mempool);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_SIGN_FAILED,
                        "Decree signing failed. Successful count of certificate signing is 0");
                    return -DAP_CHAIN_NET_CLI_ERROR_DECREE_SIGN_FAILED;
                }
                
                size_t l_decree_size = dap_chain_datum_decree_get_size(l_datum_decree);
                l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, l_datum_decree, l_decree_size);
                DAP_DELETE(l_datum_decree);
                
                char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
                DAP_DELETE(l_datum);
                
                dap_json_t *l_jobj_result = dap_json_object_new();
                dap_json_object_add_string(l_jobj_result, "status", l_key_str_out ? "placed" : "not placed");
                if (l_key_str_out) {
                    dap_json_object_add_string(l_jobj_result, "hash", l_key_str_out);
                    DAP_DELETE(l_key_str_out);
                }
                dap_json_array_add(a_json_arr_reply, l_jobj_result);
                
            } else {
                DAP_DELETE(l_datum);
                DAP_DEL_MULTY(l_datum_hash_hex_str, l_datum_hash_base58_str, l_gdb_group_mempool);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_WRONG_DATUM_TYPE,
                    "Wrong datum type. Decree sign only works with decree datums");
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_WRONG_DATUM_TYPE;
            }
        } else {
            DAP_DEL_MULTY(l_datum_hash_hex_str, l_datum_hash_base58_str, l_gdb_group_mempool);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_DATUM_NOT_FOUND,
                "Can't find datum with hash '%s' in mempool of %s:%s",
                l_datum_hash_out_str, l_net->pub.name, l_chain->name);
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_DATUM_NOT_FOUND;
        }
        
        DAP_DEL_MULTY(l_datum_hash_hex_str, l_datum_hash_base58_str, l_gdb_group_mempool);
        break;
    }
    
    case DECREE_CMD_ANCHOR: {
        // Get chain for anchor
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
        if (l_chain_str) {
            l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
            if (!l_chain) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NOT_FOUND,
                    "Invalid '-chain' parameter '%s', not found in net %s", l_chain_str, l_net_str);
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NOT_FOUND;
            }
            if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NO_ANCHOR,
                    "Chain '%s' doesn't support anchors", l_chain->name);
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_CHAIN_NO_ANCHOR;
            }
        } else {
            l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR);
            if (!l_chain) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_NO_ANCHOR_CHAIN,
                    "Can't find chain with default anchor support");
                return -DAP_CHAIN_NET_CLI_ERROR_DECREE_NO_ANCHOR_CHAIN;
            }
        }
        
        // Get decree hash
        const char *l_datum_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
        if (!l_datum_hash_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_DATUM_REQUIRED,
                "Anchor creation requires '-datum <decree_hash>' parameter");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_DATUM_REQUIRED;
        }
        
        dap_hash_fast_t l_hash = {};
        dap_chain_hash_fast_from_str(l_datum_hash_str, &l_hash);
        
        // Create TSD with decree hash
        dap_tsd_t *l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH, 
                                           &l_hash, sizeof(dap_hash_fast_t));
        if (!l_tsd) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED,
                "Anchor creation failed. Memory allocation fail");
            return -DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        
        // Create anchor datum
        dap_chain_datum_anchor_t *l_datum_anchor = DAP_NEW_Z_SIZE(dap_chain_datum_anchor_t,
            sizeof(dap_chain_datum_anchor_t) + dap_tsd_size(l_tsd));
        if (!l_datum_anchor) {
            DAP_DELETE(l_tsd);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED,
                "Anchor creation failed. Memory allocation fail");
            return -DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        
        l_datum_anchor->header.data_size = dap_tsd_size(l_tsd);
        l_datum_anchor->header.ts_created = dap_time_now();
        memcpy(l_datum_anchor->data_n_sign, l_tsd, dap_tsd_size(l_tsd));
        DAP_DELETE(l_tsd);
        
        // Sign anchor
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_anchor = s_sign_anchor_in_cycle(l_certs, l_datum_anchor, 
                                                     l_certs_count, &l_total_signs_success);
        
        if (!l_datum_anchor || l_total_signs_success == 0) {
            DAP_DEL_Z(l_datum_anchor);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_SIGN_FAILED,
                "Anchor creation failed. Successful count of certificate signing is 0");
            return -DAP_CHAIN_NET_CLI_ERROR_DECREE_SIGN_FAILED;
        }
        
        // Create datum and add to mempool
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_ANCHOR,
            l_datum_anchor,
            sizeof(*l_datum_anchor) + l_datum_anchor->header.data_size + l_datum_anchor->header.signs_size);
        DAP_DELETE(l_datum_anchor);
        
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        
        dap_json_t *l_jobj_result = dap_json_object_new();
        dap_json_object_add_string(l_jobj_result, "status", l_key_str_out ? "placed" : "not placed");
        if (l_key_str_out) {
            dap_json_object_add_string(l_jobj_result, "hash", l_key_str_out);
            DAP_DELETE(l_key_str_out);
        }
        dap_json_array_add(a_json_arr_reply, l_jobj_result);
        break;
    }
    
    default:
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_DECREE_ACTION_REQUIRED,
            "Decree action required. Use: create, sign, or anchor");
        return -DAP_CHAIN_NET_CLI_ERROR_DECREE_ACTION_REQUIRED;
    }
    
    return 0;
}

/**
 * @brief CLI command handler for executing commands on remote nodes
 * @param a_argc Argument count
 * @param a_argv Argument values
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, negative error code on failure
 * 
 * Usage: exec_cmd -net <net_name> -addr <node_addr> -cmd <command,and,args,separated,by,commas>
 */
static int s_cli_exec_cmd(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    // Check if JSON-RPC module is initialized
    if (!dap_json_rpc_exec_cmd_inited()) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_NOT_INITED,
            "JSON-RPC module not initialized, check configs");
        return -DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_NOT_INITED;
    }
    
    const char *l_cmd_arg_str = NULL;
    const char *l_addr_str = NULL;
    const char *l_net_str = NULL;
    int arg_index = 1;
    
    // Parse arguments
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cmd", &l_cmd_arg_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    
    if (!l_cmd_arg_str || !l_addr_str || !l_net_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_MISSING_ARGS,
            "Command exec_cmd requires args: -cmd, -addr, -net");
        return -DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_MISSING_ARGS;
    }
    
    // Find network
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_NET_NOT_FOUND,
            "Can't find network '%s'", l_net_str);
        return -DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_NET_NOT_FOUND;
    }
    
    // Parse node address
    dap_chain_node_addr_t l_node_addr;
    if (dap_chain_node_addr_from_str(&l_node_addr, l_addr_str) != 0) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_INVALID_ADDR,
            "Invalid node address format: '%s'", l_addr_str);
        return -DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_INVALID_ADDR;
    }
    
    // Read node info
    dap_chain_node_info_t *l_node_info = dap_chain_node_info_read(l_net, &l_node_addr);
    if (!l_node_info) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_NODE_NOT_FOUND,
            "Can't find node with address: %s", l_addr_str);
        return -DAP_CHAIN_NET_CLI_ERROR_EXEC_CMD_NODE_NOT_FOUND;
    }
    
    // Prepare command string (replace commas with semicolons)
    char *l_cmd_str = dap_strdup(l_cmd_arg_str);
    for (int i = 0; l_cmd_str[i] != '\0'; i++) {
        if (l_cmd_str[i] == ',')
            l_cmd_str[i] = ';';
    }
    
    // Create JSON-RPC params
    dap_json_rpc_params_t *l_params = dap_json_rpc_params_create();
    dap_json_rpc_params_add_data(l_params, l_cmd_str, TYPE_PARAM_STRING);
    
    // Get command name (first part before ';')
    char **l_cmd_arr_str = dap_strsplit(l_cmd_str, ";", -1);
    const char *l_method = l_cmd_arr_str[0];
    
    // Create request
    int64_t l_id_response = dap_json_rpc_response_get_new_id();
    dap_json_rpc_request_t *l_request = dap_json_rpc_request_creation(l_method, l_params, l_id_response, a_version);
    
    // Send request to remote node
    dap_json_t *l_response = NULL;
    int l_ret = dap_json_rpc_request_send(l_node_info->ext_host, l_node_info->ext_port,
                                          NULL, NULL, l_request, &l_response, NULL);
    
    if (l_ret == 0 && l_response) {
        dap_json_array_add(a_json_arr_reply, l_response);
    } else {
        dap_json_t *l_jobj_result = dap_json_object_new();
        if (l_ret != 0) {
            dap_json_object_add_string(l_jobj_result, "status", "error");
            dap_json_object_add_string(l_jobj_result, "message", "No response from remote node");
        } else {
            dap_json_object_add_string(l_jobj_result, "status", "success");
            dap_json_object_add_string(l_jobj_result, "message", "Empty reply");
        }
        dap_json_array_add(a_json_arr_reply, l_jobj_result);
    }
    
    // Cleanup
    DAP_DELETE(l_cmd_str);
    dap_strfreev(l_cmd_arr_str);
    DAP_DELETE(l_node_info);
    dap_json_rpc_request_free(l_request);
    
    return l_ret;
}

/**
 * @brief CLI command handler for CPU statistics
 * @param a_argc Argument count
 * @param a_argv Argument values
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, negative error code on failure
 * 
 * Usage: stats cpu
 */
static int s_cli_stats(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    enum {
        STATS_CMD_NONE = 0,
        STATS_CMD_CPU
    };
    
    int arg_index = 1;
    int l_cmd = STATS_CMD_NONE;
    
    // Parse subcommand
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "cpu", NULL)) {
        l_cmd = STATS_CMD_CPU;
    }
    
    switch (l_cmd) {
    case STATS_CMD_CPU:
#if (defined DAP_OS_UNIX) || (defined _WIN32)
    {
        dap_cpu_monitor_init();
        dap_usleep(500000);
        
        dap_json_t *l_json_arr_cpu = dap_json_array_new();
        dap_cpu_stats_t l_cpu_stats = dap_cpu_get_stats();
        
        // Output per-core stats
        for (uint32_t i = 0; i < l_cpu_stats.cpu_cores_count; i++) {
            dap_json_t *l_json_cpu = dap_json_object_new();
            char *l_cpu_name = dap_strdup_printf("CPU-%d", i);
            char *l_cpu_load = dap_strdup_printf("%f%%", l_cpu_stats.cpus[i].load);
            dap_json_object_add_string(l_json_cpu, l_cpu_name, l_cpu_load);
            dap_json_array_add(l_json_arr_cpu, l_json_cpu);
            DAP_DELETE(l_cpu_name);
            DAP_DELETE(l_cpu_load);
        }
        
        // Output total stats
        dap_json_t *l_json_total = dap_json_object_new();
        char *l_total_load = dap_strdup_printf("%f%%", l_cpu_stats.cpu_summary.load);
        dap_json_object_add_string(l_json_total, a_version == 1 ? "Total" : "total", l_total_load);
        dap_json_array_add(l_json_arr_cpu, l_json_total);
        DAP_DELETE(l_total_load);
        
        dap_json_array_add(a_json_arr_reply, l_json_arr_cpu);
        return 0;
    }
#else
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_STATS_NOT_SUPPORTED,
            "CPU stats only supported on Linux or Windows");
        return -DAP_CHAIN_NET_CLI_ERROR_STATS_NOT_SUPPORTED;
#endif // DAP_OS_UNIX
        
    case STATS_CMD_NONE:
    default:
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_CLI_ERROR_STATS_WRONG_FORMAT,
            "Format of command: stats cpu");
        return -DAP_CHAIN_NET_CLI_ERROR_STATS_WRONG_FORMAT;
    }
    
    return 0;
}

/**
 * @brief Initialize net CLI commands
 * @return 0 on success, already initialized returns 0 silently
 */
int dap_chain_net_cli_init(void)
{
    // Guard against multiple initialization
    static bool s_initialized = false;
    if (s_initialized) {
        log_it(L_DEBUG, "Net CLI commands already initialized, skipping");
        return 0;
    }

    // Register error codes FIRST
    dap_chain_net_cli_error_codes_init();
    
    // Register node command
    dap_cli_server_cmd_add("node", com_node, NULL,
                           "Node operations",
                           -1, // auto ID
                           "add { -net <net_name> | -rpc [-port <port>] } | { -rpc -addr <node_address> -host <node_host> [-port <port>] }\n\n"
                                    "alias -addr <node_address> -alias <node_alias>\n\n"
                                    "balancer -net <net_name>\n\n"
                                    "ban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]\n\n"
                                    "banlist\n\n"
                                    "connections [-net <net_name>]\n"
                                    "connect -net <net_name> {-addr <node_address> | -alias <node_alias> | auto}\n\n"
                                    "del -net <net_name> {-addr <node_address> | -alias <node_alias>}\n\n"
                                    "dump { [-net <net_name> | -addr <node_address>] } | { -rpc [-addr <node_address>] }\n\n"
                                    "handshake -net <net_name> {-addr <node_address> | -alias <node_alias>}\n"
                                    "link {add | del}  -net <net_name> {-addr <node_address> | -alias <node_alias>} -link <node_address>\n\n"
                                    "list { -net <net_name> [-addr <node_address> | -alias <node_alias>] [-full] } | -rpc\n\n"
                                    "unban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]\n"
                                    );


    // Register net command
    dap_cli_server_cmd_add("net", s_cli_net, NULL,
                           "Network operations",
                           -1, // auto ID
        "net -net <net_name> <subcommand>\n"
        "  ca add {-cert <cert_name> | -hash <cert_hash>}\n"
            "\tAdd certificate to list of authority cetificates in GDB group\n"
        "  ca del -hash <cert_hash> [-H {hex | base58(default)}]\n"
            "\tDelete certificate from list of authority cetificates in GDB group by it's hash\n"
        "  ca list\n"
            "\tPrint list of authority cetificates from GDB group\n"
        "  get {status | fee | id}\n"
            "\tDisplays the current status, current fee or net id\n"
        "  [-mode {update | all}] go {online | offline | sync}\n"
            "\tFind and establish links and stay online\n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "  ledger reload\n"
            "\tPurge the cache of chain net ledger and recalculate it from chain file\n"
        "  link {list | add | del | info | disconnect_all}\n"
            "\tList, add, del, dump or establish links\n"
        "  poa_certs list\n"
            "\tPrint list of PoA cerificates for this network\n"
        "  stats tx [-from <from_time>] [-to <to_time>] [-prev_day <days>]\n"
            "\tTransactions statistics. Time format is <Year>-<Month>-<Day>_<Hours>:<Minutes>:<Seconds>\n"
        "  [-mode {update | all}] sync\n"
            "\tSynchronize network\n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net list [chains -net <net_name>]\n"
            "\tList all networks or list all chains in selected network\n");

    // Register help command
    dap_cli_server_cmd_add("help", s_cli_help, s_print_for_help,
                           "Display help for commands",
                           -1, // auto ID
                           "help [<command>]\n"
                           "\tObtain help for <command> or get the list of all commands\n");

    // Register ? as alias for help
    dap_cli_server_cmd_add("?", s_cli_help, s_print_for_help,
                           "Synonym for help",
                           -1, // auto ID
                           "? [<command>]\n"
                           "\tObtain help for <command> or get the list of all commands\n");

    // Register version command
    dap_cli_server_cmd_add("version", s_cli_version, NULL,
                           "Show version information",
                           -1, // auto ID
                           "version\n"
                           "\tReturn version number\n");

    // Register print_log command
    dap_cli_server_cmd_add("print_log", s_cli_print_log, s_print_for_print_log,
                           "Print log entries",
                           -1, // auto ID
                           "print_log ts_after <timestamp> limit <line_numbers>\n"
                           "\tPrint log entries from the node log file\n"
                           "\t\tts_after - Unix timestamp to start reading logs from\n"
                           "\t\tlimit - Maximum number of lines to return\n");

    // Register exit command
    dap_cli_server_cmd_add("exit", s_cli_exit, NULL,
                           "Stop application and exit",
                           -1, // auto ID
                           "exit\n"
                           "\tStop the node application and exit\n");

    // Register remove command
    dap_cli_server_cmd_add("remove", s_cli_remove, NULL,
                           "Delete chain files or global database",
                           -1, // auto ID
                           "remove -gdb\n"
                           "\tDelete global database (preserves node list)\n\n"
                           "remove -chains {-net <net_name> | -all}\n"
                           "\tDelete chain files for specific network or all networks\n"
                           "\t-net <net_name> - delete chains for specific network\n"
                           "\t-all - delete chains for ALL networks (use with caution!)\n\n"
                           "remove -gdb -chains -all\n"
                           "\tDelete both GDB and all chain files\n");

    // Register decree command
    dap_cli_server_cmd_add("decree", s_cli_decree, NULL,
                           "Decree operations",
                           -1, // auto ID
                           "decree create common -net <net_name> -certs <certs_name> -decree_chain <chain_name> [-chain <chain_name>] [-H {hex|base58}]\n"
                           "\t{-fee <value> [-to_addr <addr>] | -new_certs <certs_name> | -signs_verify <count>}\n"
                           "\tCreate common decree:\n"
                           "\t\t-fee <value> - set network fee (use -to_addr to set fee wallet)\n"
                           "\t\t-new_certs <certs_name> - set new network owners\n"
                           "\t\t-signs_verify <count> - set minimum signatures required\n\n"
                           "decree sign -net <net_name> -certs <certs_name> -datum <datum_hash> [-chain <chain_name>] [-H {hex|base58}]\n"
                           "\tSign existing decree in mempool\n\n"
                           "decree anchor -net <net_name> -certs <certs_name> -datum <decree_hash> [-chain <chain_name>] [-H {hex|base58}]\n"
                           "\tCreate anchor for decree to apply it to the network\n");

    // Register exec_cmd command
    dap_cli_server_cmd_add("exec_cmd", s_cli_exec_cmd, NULL,
                           "Execute command on remote node",
                           -1, // auto ID
                           "exec_cmd -net <net_name> -addr <node_addr> -cmd <command,and,all,args,separated,by,commas>\n"
                           "\tExecute command on a remote node via JSON-RPC\n"
                           "\t-net <net_name> - network name\n"
                           "\t-addr <node_addr> - target node address\n"
                           "\t-cmd <cmd> - command with arguments separated by commas\n");

    // Register stats command
    dap_cli_server_cmd_add("stats", s_cli_stats, NULL,
                           "Print statistics",
                           -1, // auto ID
                           "stats cpu\n"
                           "\tShow CPU usage statistics for all cores\n");

    s_initialized = true;
    log_it(L_NOTICE, "Net CLI commands registered (with error codes)");
    return 0;
}

void dap_chain_net_cli_deinit(void)
{
    log_it(L_INFO, "Net CLI commands unregistered");
}

// ============ HELPER FUNCTIONS FOR NET CLI ============

static void s_set_reply_text_node_status_json(dap_chain_net_t *a_net, dap_json_t *a_json_out, int a_version) {
    if (!a_net || !a_json_out)
        return;
    char l_id_buff[20]= { };
    sprintf(l_id_buff,"0x%016"DAP_UINT64_FORMAT_x, a_net->pub.id.uint64);
    dap_json_object_add_object(a_json_out, "net", dap_json_object_new_string(a_net->pub.name));
    dap_json_object_add_object(a_json_out, "id", dap_json_object_new_string(l_id_buff));
    dap_json_object_add_object(a_json_out, "native_ticker", dap_json_object_new_string(a_net->pub.native_ticker));
    dap_chain_node_addr_t l_cur_node_addr = { 0 };
    l_cur_node_addr.uint64 = dap_chain_net_get_cur_addr_int(a_net);
    dap_json_t *l_jobj_cur_node_addr;
    if(!l_cur_node_addr.uint64) {
        l_jobj_cur_node_addr = dap_json_object_new_string("not defined");
    } else {
        char *l_cur_node_addr_str = dap_strdup_printf(NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_cur_node_addr));
        l_jobj_cur_node_addr = dap_json_object_new_string(l_cur_node_addr_str);
        DAP_DELETE(l_cur_node_addr_str);
    }
    if (!l_jobj_cur_node_addr) {
        return ;
    }
    dap_json_object_add_object(a_json_out, "current_addr", l_jobj_cur_node_addr);
    if (dap_chain_net_get_state(a_net) != NET_STATE_OFFLINE && dap_chain_net_get_state(a_net) != NET_STATE_LOADING) {
        dap_json_t *l_jobj_links = dap_json_object_new();
        dap_json_t *l_jobj_active_links = dap_json_object_new_uint64(dap_link_manager_links_count(a_net->pub.id.uint64));
        dap_json_t *l_jobj_required_links = dap_json_object_new_uint64(dap_link_manager_required_links_count(a_net->pub.id.uint64));
        dap_json_object_add_object(l_jobj_links, "active", l_jobj_active_links);
        dap_json_object_add_object(l_jobj_links, "required", l_jobj_required_links);
        dap_json_object_add_object(a_json_out, "links", l_jobj_links);
    }
    if (a_net->pub.bridged_networks_count) {
        dap_json_t *l_bridget = dap_json_array_new();
        uint16_t l_bridget_count = 0;  // if can't get any info about bridget net
        for (uint16_t i = 0; i < a_net->pub.bridged_networks_count; ++i) {
            dap_chain_net_t *l_bridget_net = dap_chain_net_by_id(a_net->pub.bridged_networks[i]); 
            if (l_bridget_net) {
                dap_json_t *l_net_item = dap_json_object_new();
                sprintf(l_id_buff,"0x%016"DAP_UINT64_FORMAT_x, a_net->pub.bridged_networks[i].uint64);
                    
                dap_json_object_add_object(l_net_item, "name", dap_json_object_new_string(l_bridget_net->pub.name));
                dap_json_object_add_object(l_net_item, "id", dap_json_object_new_string(l_id_buff));
                dap_json_object_add_object(l_net_item, "native_ticker", dap_json_object_new_string(l_bridget_net->pub.native_ticker));
                dap_json_array_add(l_bridget, l_net_item);
                ++l_bridget_count;
            }
        }
        if (l_bridget_count)
            dap_json_object_add_object(a_json_out, "bridged_networks", l_bridget);
    }

    dap_json_t *l_json_sync_status = s_net_sync_status(a_net, a_version);
    dap_json_object_add_object(a_json_out, "processed", l_json_sync_status);

    dap_json_t *l_jobj_states = dap_json_object_new();
    dap_json_t *l_jobj_current_states = dap_json_object_new_string(dap_chain_net_state_to_str_user(a_net));
    dap_json_t *l_jobj_target_states = dap_json_object_new_string(dap_chain_net_state_to_str(dap_chain_net_get_target_state(a_net)));
    dap_json_object_add_object(l_jobj_states, "current", l_jobj_current_states);
    dap_json_object_add_object(l_jobj_states, "target", l_jobj_target_states);
    dap_json_object_add_object(a_json_out, "states", l_jobj_states);
}

void s_set_reply_text_node_status(dap_json_t *a_json_arr_reply, dap_chain_net_t * a_net){
    char* l_node_address_text_block = NULL;
    dap_chain_node_addr_t l_cur_node_addr = { 0 };
    l_cur_node_addr.uint64 = dap_chain_net_get_cur_addr_int(a_net);
    if(!l_cur_node_addr.uint64)
        l_node_address_text_block = dap_strdup_printf(", cur node address not defined");
    else
        l_node_address_text_block = dap_strdup_printf(", cur node address " NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_cur_node_addr));

    char* l_sync_current_link_text_block = NULL;
    if (dap_chain_net_get_state(a_net) != NET_STATE_OFFLINE)
        l_sync_current_link_text_block = dap_strdup_printf(", active links %zu from %u",
                                                           dap_link_manager_links_count(a_net->pub.id.uint64), 0);
    char *l_reply_str = dap_strdup_printf("Network \"%s\" has state %s (target state %s)%s%s",
                                      a_net->pub.name, dap_chain_net_get_state_name(dap_chain_net_get_state(a_net)),
                                      dap_chain_net_get_state_name(dap_chain_net_get_target_state(a_net)),
                                      (l_sync_current_link_text_block)? l_sync_current_link_text_block: "",
                                      l_node_address_text_block
                                      );
    dap_json_rpc_error_add(a_json_arr_reply, -1, l_reply_str);
    DAP_DELETE(l_reply_str);
    DAP_DELETE(l_sync_current_link_text_block);
    DAP_DELETE(l_node_address_text_block);
}
/**
 * @brief reload ledger
 * command cellframe-node-cli net -net <network_name> ledger reload
 * @param l_net
 * @return true
 * @return false
 */
void _s_print_chains(dap_json_t *a_obj_chain, dap_chain_t *a_chain) {
    if (!a_obj_chain || !a_chain)
        return;
    dap_json_object_add_string(a_obj_chain, "name", a_chain->name);
    dap_json_object_add_object(a_obj_chain, "consensus", 
                              dap_json_object_new_string(DAP_CHAIN_PVT(a_chain)->cs_name));

    if (a_chain->default_datum_types_count) {
        dap_json_t *l_jobj_default_types = dap_json_array_new();
        if (!l_jobj_default_types) return;
        for (uint16_t i = 0; i < a_chain->default_datum_types_count; i++) {
            dap_json_t *l_jobj_type_str = dap_json_object_new_string(dap_chain_type_to_str(
                    a_chain->default_datum_types[i]));
            if (!l_jobj_type_str) {
                dap_json_object_free(l_jobj_default_types);
                return;
            }
            dap_json_array_add(l_jobj_default_types, l_jobj_type_str);
        }
        dap_json_object_add_object(a_obj_chain, "default_types", l_jobj_default_types);
    }
}

/**
 * @brief
 * register net* command in cellframe-node-cli interface
 * @param argc arguments count
 * @param argv arguments value
 * @param arg_func
 * @param str_reply
 * @return
 */

// ============ MAIN NET CLI COMMAND ============
static int s_cli_net(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    dap_json_t *l_jobj_return = dap_json_object_new();
    if (!l_jobj_return) {
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_object_free(l_jobj_return);
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_HASH, "%s", "invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_HASH;

    }

    // command 'list'
    const char * l_list_cmd = NULL;

    if(dap_cli_server_cmd_find_option_val(argv, arg_index, dap_min(argc, arg_index + 1), "list", &l_list_cmd) != 0 ) {
        if (dap_strcmp(l_list_cmd,"chains")==0){
            const char * l_net_str = NULL;
            dap_chain_net_t* l_net = NULL;
            if (dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_str) && !l_net_str) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_PARAMETER_NET_REQUIRE, "%s", "Parameter '-net' require <net name>");
                return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_PARAMETER_NET_REQUIRE;
            }

            l_net = dap_chain_net_by_name(l_net_str);
            if (l_net_str && !l_net) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_WRONG_NET, "%s", "Wrong <net name>, use 'net list' "
                                                                         "command to display a list of available networks");
                return DAP_CHAIN_NET_JSON_RPC_WRONG_NET;
            }

            if (l_net){
                dap_json_t *l_jobj_net_name = dap_json_object_new_string(l_net->pub.name);
                dap_json_t *l_jobj_chains = dap_json_array_new();
                if (!l_jobj_net_name || !l_jobj_chains) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_object_free(l_jobj_net_name);
                    dap_json_object_free(l_jobj_chains);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_chain_t * l_chain = l_net->pub.chains;
                while (l_chain) {
                    dap_json_t *l_obj_chain = dap_json_object_new();
                    if (!l_obj_chain) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_object_free(l_jobj_net_name);
                        dap_json_object_free(l_jobj_chains);
                        dap_json_object_free(l_obj_chain);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    _s_print_chains(l_obj_chain, l_chain);
                    dap_json_array_add(l_jobj_chains, l_obj_chain);
                    l_chain = l_chain->next;
                }
                dap_json_object_add_object(l_jobj_return, "net", l_jobj_net_name);
                dap_json_object_add_object(l_jobj_return, "chains", l_jobj_chains);
            }else{
                dap_json_t *l_jobj_networks = dap_json_array_new();
                for (dap_chain_net_t *l_net = dap_chain_net_iterate(NULL); l_net; l_net = dap_chain_net_iterate(l_net)) {
                    dap_json_t *l_jobj_network = dap_json_object_new();
                    dap_json_t *l_jobj_chains = dap_json_array_new();
                    dap_json_t *l_jobj_network_name = dap_json_object_new_string(l_net->pub.name);
                    if (!l_jobj_network || !l_jobj_chains || !l_jobj_network_name) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_object_free(l_jobj_network);
                        dap_json_object_free(l_jobj_chains);
                        dap_json_object_free(l_jobj_network_name);
                        dap_json_object_free(l_jobj_networks);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    dap_json_object_add_object(l_jobj_network, "name", l_jobj_network_name);

                    dap_chain_t * l_chain = l_net->pub.chains;
                    while (l_chain) {
                        dap_json_t *l_jobj_chain = dap_json_object_new();
                        if (!l_jobj_chain) {
                            dap_json_object_free(l_jobj_return);
                            dap_json_object_free(l_jobj_network);
                            dap_json_object_free(l_jobj_chains);
                            dap_json_object_free(l_jobj_networks);
                            dap_json_rpc_allocation_error(a_json_arr_reply);
                            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                        }
                        _s_print_chains(l_jobj_chain, l_chain);
                        dap_json_array_add(l_jobj_chains, l_jobj_chain);
                        l_chain = l_chain->next;
                    }
                    dap_json_object_add_object(l_jobj_network, "chain", l_jobj_chains);
                    dap_json_array_add(l_jobj_networks, l_jobj_network);
                }
                dap_json_object_add_object(l_jobj_return, "networks", l_jobj_networks);
            }
        }else{
            // plug for wrong command arguments
            if (argc > 2) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_MANY_ARGUMENT_FOR_COMMAND_NET_LIST, "%s",
                                       "To many arguments for 'net list' command see help");
                return DAP_CHAIN_NET_JSON_RPC_MANY_ARGUMENT_FOR_COMMAND_NET_LIST;
            }

            dap_json_t *l_jobj_networks = dap_json_array_new();
            if (!l_jobj_networks) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            // show list of nets
            for (dap_chain_net_t *l_net = dap_chain_net_iterate(NULL); l_net; l_net = dap_chain_net_iterate(l_net)) {
                dap_json_t *l_jobj_network_name = dap_json_object_new_string(l_net->pub.name);
                dap_json_array_add(l_jobj_networks, l_jobj_network_name);
            }
            dap_json_object_add_object(l_jobj_return, "networks", l_jobj_networks);
        }
        dap_json_array_add(a_json_arr_reply, l_jobj_return);
        return 0;
    }

    int l_ret = dap_chain_net_parse_net_chain(a_json_arr_reply, &arg_index, argc, argv, NULL, &l_net,
                                                                       CHAIN_TYPE_INVALID);

    if ( l_net ) {
        const char *l_sync_str = NULL;
        const char *l_links_str = NULL;
        const char *l_go_str = NULL;
        const char *l_get_str = NULL;
        const char *l_stats_str = NULL;
        const char *l_ca_str = NULL;
        const char *l_ledger_str = NULL;
        const char *l_list_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "sync", &l_sync_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "link", &l_links_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "go", &l_go_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "get", &l_get_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "stats", &l_stats_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "ca", &l_ca_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "ledger", &l_ledger_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "poa_certs", &l_list_str);

        const char * l_sync_mode_str = "updates";
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-mode", &l_sync_mode_str);
        if ( !dap_strcmp(l_sync_mode_str,"all") )
            dap_chain_net_get_flag_sync_from_zero(l_net);
        if (l_stats_str) {
            char l_from_str_new[50], l_to_str_new[50];
            const char c_time_fmt[]="%Y-%m-%d_%H:%M:%S";
            struct tm l_from_tm = {}, l_to_tm = {};
            if (strcmp(l_stats_str,"tx") == 0) {
                const char *l_to_str = NULL;
                const char *l_from_str = NULL;
                const char *l_prev_day_str = NULL;
                // Read from/to time
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-from", &l_from_str);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-to", &l_to_str);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-prev_day", &l_prev_day_str);
                time_t l_ts_now = time(NULL);
                if (l_from_str) {
                    strptime( (char *)l_from_str, c_time_fmt, &l_from_tm );
                    if (l_to_str) {
                        strptime( (char *)l_to_str, c_time_fmt, &l_to_tm );
                    } else { // If not set '-to' - we set up current time
                        localtime_r(&l_ts_now, &l_to_tm);
                    }
                } else if (l_prev_day_str) {
                    localtime_r(&l_ts_now, &l_to_tm);
                    double l_days = strtod(l_prev_day_str, NULL);
                    l_ts_now -= (time_t)(l_days * 86400);
                    localtime_r(&l_ts_now, &l_from_tm );
                } else if ( l_from_str == NULL ) { // If not set '-from' we set up current time minus 60 seconds
                    localtime_r(&l_ts_now, &l_to_tm);
                    l_ts_now -= 86400;
                    localtime_r(&l_ts_now, &l_from_tm );
                }
                // Form timestamps from/to
                time_t l_from_ts = mktime(&l_from_tm);
                time_t l_to_ts = mktime(&l_to_tm);
                // Produce strings
                strftime(l_from_str_new, sizeof(l_from_str_new), c_time_fmt,&l_from_tm );
                strftime(l_to_str_new, sizeof(l_to_str_new), c_time_fmt,&l_to_tm );
                dap_json_t *l_jobj_stats = dap_json_object_new();
                if (!l_jobj_stats) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_t *l_jobj_from = dap_json_object_new_string(l_from_str_new);
                dap_json_t *l_jobj_to = dap_json_object_new_string(l_to_str_new);
                if (!l_jobj_from || !l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_object_free(l_jobj_stats);
                    dap_json_object_free(l_jobj_from);
                    dap_json_object_free(l_jobj_to);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_stats, "from", l_jobj_from);
                dap_json_object_add_object(l_jobj_stats, "to", l_jobj_to);
                log_it(L_INFO, "Calc TPS from %s to %s", l_from_str_new, l_to_str_new);
                uint64_t l_tx_count = dap_ledger_count_from_to ( l_net->pub.ledger, l_from_ts * 1000000000, l_to_ts * 1000000000);
                long double l_tpd = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) ((long double)(l_to_ts - l_from_ts) / 86400);
                char *l_tpd_str = dap_strdup_printf("%.3Lf", l_tpd);
                dap_json_t *l_jobj_tpd = dap_json_object_new_string(l_tpd_str);
                DAP_DELETE(l_tpd_str);
                dap_json_t *l_jobj_total = dap_json_object_new_uint64(l_tx_count);
                long double l_tps = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) (long double)(l_to_ts - l_from_ts);
                char *l_tps_str = dap_strdup_printf("%.3Lf", l_tps);
                dap_json_t *l_jobj_tps = dap_json_object_new_string(l_tps_str);
                DAP_DELETE(l_tps_str);
                if (!l_jobj_tpd || !l_jobj_total || !l_jobj_tps) {
                    dap_json_object_free(l_jobj_tps);
                    
                    dap_json_object_free(l_jobj_return);
                    dap_json_object_free(l_jobj_stats);
                    dap_json_object_free(l_jobj_from);
                    dap_json_object_free(l_jobj_to);
                    dap_json_object_free(l_jobj_tpd);
                    dap_json_object_free(l_jobj_total);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_stats, "transaction_per_sec", l_jobj_tps);
                dap_json_object_add_object(l_jobj_stats, "transaction_per_day", l_jobj_tpd);
                dap_json_object_add_object(l_jobj_stats, "total", l_jobj_total);
                dap_json_object_add_object(l_jobj_return, "transaction_statistics", l_jobj_stats);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_STATS, "%s",
                 "Subcommand 'stats' requires one of parameter: tx");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_STATS;
            }
        } else if ( l_go_str){
            dap_json_t *l_jobj_net = dap_json_object_new_string(l_net->pub.name);
            dap_json_t *l_jobj_current_status = dap_json_object_new_string(dap_chain_net_get_state_name(dap_chain_net_get_state(l_net)));
            if (!l_jobj_net || !l_jobj_current_status) {
                dap_json_object_free(l_jobj_return);
                dap_json_object_free(l_jobj_net);
                dap_json_object_free(l_jobj_current_status);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_json_object_add_object(l_jobj_return, "net", l_jobj_net);
            dap_json_object_add_object(l_jobj_return, "current", l_jobj_current_status);
            if ( strcmp(l_go_str,"online") == 0 ) {
                dap_json_t *l_jobj_to = dap_json_object_new_string(dap_chain_net_get_state_name(NET_STATE_ONLINE));
                if (!l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "to", l_jobj_to);
                if (dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE)) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START, "%s",
                                            "Can't change state of loading network\n");
                    return DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_go_str,"offline") == 0 ) {
                dap_json_t *l_jobj_to = dap_json_object_new_string(dap_chain_net_get_state_name(NET_STATE_OFFLINE));
                if (!l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "to", l_jobj_to);
                if ( dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE) ) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START, "%s",
                                            "Can't change state of loading network\n");
                    return DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_go_str, "sync") == 0) {
                dap_json_t *l_jobj_to = dap_json_object_new_string("resynchronizing");
                if (!l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "start", l_jobj_to);
                if (dap_chain_net_get_target_state(l_net) == NET_STATE_ONLINE)
                    l_ret = dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
                else
                    l_ret = dap_chain_net_state_go_to(l_net, NET_STATE_SYNC_CHAINS);
                if (l_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START, "%s",
                                            "Can't change state of loading network\n");
                    return DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_GO, "%s",
                                       "Subcommand 'go' requires one of parameters: online, offline, sync\n");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_GO;
            }
        } else if ( l_get_str){
            if ( strcmp(l_get_str,"status") == 0 ) {
                dap_json_t *l_jobj = dap_json_object_new();
                s_set_reply_text_node_status_json(l_net, l_jobj, a_version);
                if (!l_jobj) {
                    dap_json_object_free(l_jobj_return);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "status", l_jobj);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_get_str, "fee") == 0) {
                dap_json_t *l_jobj_fees = dap_json_object_new();
                if (!l_jobj_fees) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "fees", l_jobj_fees);
                dap_json_t *l_jobj_network_name = dap_json_object_new_string(l_net->pub.name);
                if (!l_jobj_network_name) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_fees, "network_name", l_jobj_network_name);
                // Network fee
                uint256_t l_network_fee = {};
                dap_chain_addr_t l_network_fee_addr = {};
                dap_chain_net_tx_get_fee(l_net->pub.id, &l_network_fee, &l_network_fee_addr);
                const char *l_network_fee_coins_str, *l_network_fee_balance_str =
                    dap_uint256_to_char(l_network_fee, &l_network_fee_coins_str);
                dap_json_t *l_jobj_network =  dap_json_object_new();
                if (!l_jobj_network) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_fees, "network_fee", l_jobj_network);
                dap_json_t *l_jobj_fee_coins = dap_json_object_new_string(l_network_fee_coins_str);
                if (!l_jobj_fee_coins) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "coins", l_jobj_fee_coins);
                dap_json_t *l_jobj_fee_balance = dap_json_object_new_string(l_network_fee_balance_str);
                if (!l_jobj_fee_balance) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "balance", l_jobj_fee_balance);
                dap_json_t *l_jobj_native_ticker = dap_json_object_new_string(l_net->pub.native_ticker);
                if (!l_jobj_native_ticker) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "ticker", l_jobj_native_ticker);
                dap_json_t *l_jobj_fee_addr = dap_json_object_new_string(dap_chain_addr_to_str_static(&l_network_fee_addr));
                if (!l_jobj_native_ticker) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "addr", l_jobj_fee_addr);
                dap_json_object_add_object(l_jobj_fees, "service_fees", dap_chain_srv_get_fees(l_net->pub.id));
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;

            } else if (strcmp(l_get_str,"id") == 0 ){
                dap_json_t *l_jobj_net_name = dap_json_object_new_string(l_net->pub.name);
                char *l_id_str = dap_strdup_printf("0x%016"DAP_UINT64_FORMAT_X, l_net->pub.id.uint64);
                dap_json_t *l_jobj_id = dap_json_object_new_string(l_id_str);
                DAP_DELETE(l_id_str);
                if (!l_jobj_net_name || !l_jobj_id) {
                    dap_json_object_free(l_jobj_net_name);
                    dap_json_object_free(l_jobj_id);
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "network", l_jobj_net_name);
                dap_json_object_add_object(l_jobj_return, "id", l_jobj_id);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS,
                                       "Unknown \"%s\" subcommand, net get commands.", l_get_str);
                return DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS;
            }
        } else if ( l_links_str ){
            if ( strcmp(l_links_str,"list") == 0 ) {
                dap_cluster_t *l_net_cluster = dap_cluster_by_mnemonim(l_net->pub.name);
                if (!l_net_cluster) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_GET_CLUSTER, "%s", "Failed to obtain a cluster for "
                                                                                       "the specified network.");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_GET_CLUSTER;
                }
                dap_json_t *l_jobj_links = dap_cluster_get_links_info_json(l_net_cluster);
                if (!l_jobj_links) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "links", l_jobj_links);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_links_str,"add") == 0 ) {
                dap_json_t *l_jobj_not_implemented = dap_json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "add", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_links_str,"del") == 0 ) {
                dap_json_t *l_jobj_not_implemented = dap_json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "del", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            }  else if ( strcmp(l_links_str,"info") == 0 ) {
                dap_json_t *l_jobj_not_implemented = dap_json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "info", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp (l_links_str,"disconnect_all") == 0 ){
                dap_chain_net_stop(l_net);
                dap_json_t *l_jobj_ret = dap_json_object_new_string("Stopped network");
                if (!l_jobj_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "message", l_jobj_ret);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            }else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_COMMAND_LINK, "%s",
                                       "Subcommand 'link' requires one of parameters: list, add, del, info, disconnect_all");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_COMMAND_LINK;
            }

        } else if( l_sync_str) {
            dap_json_t *l_jobj_state_machine = dap_json_object_new();
            dap_json_t *l_jobj_requested = dap_json_object_new_string("SYNC_ALL");
            dap_json_t *l_jobj_current = dap_json_object_new_string(dap_chain_net_get_state_name(dap_chain_net_get_state(l_net)));
            if (!l_jobj_state_machine || !l_jobj_current) {
                dap_json_object_free(l_jobj_state_machine);
                dap_json_object_free(l_jobj_current);
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_chain_net_sync(l_net);
            if (!l_jobj_requested) {
                dap_json_object_free(l_jobj_state_machine);
                dap_json_object_free(l_jobj_current);
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_json_object_add_object(l_jobj_state_machine, "current", l_jobj_current);
            dap_json_object_add_object(l_jobj_state_machine, "requested", l_jobj_requested);
            dap_json_object_add_object(l_jobj_return, "state_machine", l_jobj_state_machine);
            l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
        } else if (l_ca_str) {
            if (strcmp(l_ca_str, "add") == 0 ) {
                const char *l_cert_string = NULL, *l_hash_string = NULL;

                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_string);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);

                if (!l_cert_string && !l_hash_string) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_CA_ADD, "%s",
                                           "One of -cert or -hash parameters is mandatory");
                    return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_CA_ADD;
                }
                
                char *l_hash_hex_str = NULL;

                if (l_cert_string) {
                    dap_cert_t * l_cert = dap_cert_find_by_name(l_cert_string);
                    if (l_cert == NULL) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_ADD,
                                               "Can't find \"%s\" certificate", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_ADD;
                    }
                    if (l_cert->enc_key == NULL) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_KEY_IN_CERT_CA_ADD,
                                               "No key found in \"%s\" certificate", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_KEY_IN_CERT_CA_ADD;
                    }
                    // Get publivc key hash
                    size_t l_pub_key_size = 0;
                    uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_pub_key_size);;
                    if (l_pub_key == NULL) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_SERIALIZE_PUBLIC_KEY_CERT_CA_ADD,
                                               "Can't serialize public key of certificate \"%s\"", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_SERIALIZE_PUBLIC_KEY_CERT_CA_ADD;
                    }
                    dap_chain_hash_fast_t l_pkey_hash;
                    dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
                    DAP_DELETE(l_pub_key);
                    l_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
                    //l_hash_base58_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash);
                } else {
                    l_hash_hex_str = !dap_strncmp(l_hash_string, "0x", 2) || !dap_strncmp(l_hash_string, "0X", 2)
                        ? dap_strdup(l_hash_string)
                        : dap_enc_base58_to_hex_str_from_str(l_hash_string);
                }
                const char c = '1';
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    DAP_DELETE(l_hash_hex_str);
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_ADD, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_ADD;
                }
                if( l_hash_hex_str ){
                    l_ret = dap_global_db_set_sync(l_gdb_group_str, l_hash_hex_str, &c, sizeof(c), false );
                    DAP_DELETE(l_gdb_group_str);
                    if (l_ret) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE,
                                               "Can't save public key hash %s in database", l_hash_hex_str);
                        DAP_DELETE(l_hash_hex_str);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE;
                    } else
                        DAP_DELETE(l_hash_hex_str);
                } else{
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE, "%s",
                                           "Can't save NULL public key hash in database");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_ca_str, "list") == 0 ) {
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_LIST, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_LIST;
                }
                size_t l_objs_count;
                dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_str, &l_objs_count);
                DAP_DELETE(l_gdb_group_str);
                dap_json_t *l_jobj_list_ca = dap_json_array_new();
                if (!l_jobj_list_ca) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                for (size_t i = 0; i < l_objs_count; i++) {
                    dap_json_t *l_jobj_key = dap_json_object_new_string(l_objs[i].key);
                    if (!l_jobj_key) {
                        dap_json_object_free(l_jobj_list_ca);
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                }
                dap_global_db_objs_delete(l_objs, l_objs_count);
                if (dap_json_array_length(l_jobj_list_ca) > 0) {
                    dap_json_object_add_object(l_jobj_return, "ca_list", l_jobj_list_ca);
                } else {
                    dap_json_object_free(l_jobj_list_ca);
                    dap_json_t *l_jobj_str_ret = dap_json_object_new_string("No entries found");
                    if (!l_jobj_str_ret) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    dap_json_object_add_object(l_jobj_return, "ca_list", l_jobj_str_ret);
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_ca_str, "del") == 0 ) {
                const char *l_hash_string = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);
                if (!l_hash_string) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNKNOWN_HASH_CA_DEL, "%s",
                                           "Format should be 'net ca del -hash <hash string>");
                    return DAP_CHAIN_NET_JSON_RPC_UNKNOWN_HASH_CA_DEL;
                }
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_DEL, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_DEL;
                }
                char *l_ret_msg_str = dap_strdup_printf("Certificate %s has been deleted.", l_hash_string);
                dap_json_t *l_jobj_ret = dap_json_object_new_string(l_ret_msg_str);
                DAP_DELETE(l_ret_msg_str);
                if (l_jobj_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                l_ret = dap_global_db_del_sync(l_gdb_group_str, l_hash_string);
                DAP_DELETE(l_gdb_group_str);
                if (l_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_DEL, "%s",
                                           "Can't find certificate public key hash in database");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_DEL;
                }
                dap_json_object_free(l_jobj_return);
                dap_json_array_add(a_json_arr_reply, l_jobj_ret);
                return DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_COMMAND_CA, "%s",
                                       "Subcommand 'ca' requires one of parameter: add, list, del");
                return DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_COMMAND_CA;
            }
        } else if (l_ledger_str && !strcmp(l_ledger_str, "reload")) {
            int l_return_state = dap_chain_net_stop(l_net);
            sleep(1);   // wait to net going offline
            dap_chain_net_purge(l_net);
            if (l_return_state)
                dap_chain_net_start(l_net);
        } else if (l_list_str && !strcmp(l_list_str, "list")) {
            if (!l_net->pub.keys) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_NO_POA_CERTS_FOUND_POA_CERTS, "%s",
                                       "No PoA certs found for this network");
                return DAP_CHAIN_NET_JSON_RPC_NO_POA_CERTS_FOUND_POA_CERTS;
            }
            dap_json_t *l_jobj_pkeys = dap_json_array_new();
            if (!l_jobj_pkeys) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            for (dap_list_t *it = l_net->pub.keys; it; it = it->next) {
                dap_hash_fast_t l_pkey_hash;
                char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_pkey_get_hash(it->data, &l_pkey_hash);
                dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                dap_json_t *l_jobj_hash_key = dap_json_object_new_string(l_pkey_hash_str);
                if (!l_jobj_hash_key) {
                    dap_json_object_free(l_jobj_pkeys);
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_array_add(l_jobj_pkeys, l_jobj_hash_key);
            }
            if (dap_json_array_length(l_jobj_pkeys) > 0) {
                dap_json_object_add_object(l_jobj_return, "poa_certs", l_jobj_pkeys);
            } else {
                dap_json_object_free(l_jobj_pkeys);
                dap_json_t *l_jobj_info = dap_json_object_new_string("empty");
                if (!l_jobj_info) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_pkeys, "poa_certs", l_jobj_info);
            }
            l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS, "%s",
                                   "Command 'net' requires one of subcomands: sync, link, go, get, stats, ca, ledger");
            l_ret = DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS;
        }
    } else {
        dap_json_object_free(l_jobj_return);
        l_jobj_return = NULL;
    }
    if (l_jobj_return) {
        dap_json_array_add(a_json_arr_reply, l_jobj_return);
    }
    return  l_ret;
}


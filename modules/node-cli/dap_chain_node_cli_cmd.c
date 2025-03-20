/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif
#include <time.h>
#include "dap_common.h"
#include "dap_time.h"

#include "uthash.h"
#include "utlist.h"

#ifdef DAP_OS_UNIX
#include <dirent.h>
#endif

#include "dap_common.h"
#include "dap_time.h"
#include "dap_string.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_string.h"
#include "dap_cert.h"
#include "dap_cert_file.h"
#include "dap_file_utils.h"
#include "dap_enc_base58.h"
#include "dap_enc_ks.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_node.h"
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_net.h"
#include "dap_chain_net_balancer.h"
#include "dap_chain_cell.h"
#include "dap_enc_base64.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_global_db.h"
#include "dap_global_db_pkt.h"
#include "dap_chain_ch.h"
#include "dap_enc_base64.h"
#include "dap_chain_net_node_list.h"

#include "dap_json_rpc_errors.h"
#include "dap_http_ban_list_client.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_json_rpc.h"
#include "dap_json_rpc_request.h"
#include "dap_client_pvt.h"
#include "dap_notify_srv.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_policy.h"
#include "dap_time.h"

#define LOG_TAG "chain_node_cli_cmd"

int _cmd_mempool_add_ca(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_cert_t *a_cert, void **a_str_reply);
static void s_new_wallet_info_notify(const char *a_wallet_name); 
struct json_object *wallet_list_json_collect();

dap_chain_t *s_get_chain_with_datum(dap_chain_net_t *a_net, const char *a_datum_hash) {
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        char *l_gdb_mempool = dap_chain_mempool_group_new(l_chain);
        bool is_hash = dap_global_db_driver_is(l_gdb_mempool, a_datum_hash);
        DAP_DELETE(l_gdb_mempool);
        if (is_hash)
            return l_chain;
    }
    return NULL;
}

/**
 * @brief node_info_read_and_reply
 * Read node from base
 * @param a_net
 * @param a_address
 * @param a_str_reply
 * @return dap_chain_node_info_t*
 */
static dap_chain_node_info_t* node_info_read_and_reply(dap_chain_net_t * a_net, dap_chain_node_addr_t *a_address,
        json_object* a_json_arr_reply)
{
    dap_chain_node_info_t* l_res = dap_chain_node_info_read(a_net, a_address);
    if (!l_res && a_json_arr_reply)
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NODE_RECORD_CORRUPTED_ERR,
                                                        "Node record is corrupted or doesn't exist");
    return l_res;
}


/**
 * @brief node_info_save_and_reply
 * Save node to base
 * @param a_net
 * @param a_node_info
 * @param str_reply
 * @return true
 * @return false
 */
static int node_info_save_and_reply(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info, void **a_str_reply)
{
    return !a_node_info || !a_node_info->address.uint64
        ? dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid node address"), -1
        : dap_global_db_set_sync(a_net->pub.gdb_nodes, dap_stream_node_addr_to_str_static(a_node_info->address),
            (uint8_t*)a_node_info, dap_chain_node_info_get_size(a_node_info), false);
}


/**
 * @brief node_info_add_with_reply
 * Handler of command 'global_db node add'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 * @param a_net
 * @param a_node_info
 * @param a_alias_str
 * @param a_cell_str
 * @param a_ipv4_str
 * @param a_ipv6_str
 * @param a_str_reply
 * @return int
 */
static int node_info_add_with_reply(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info,
        const char *a_alias_str, const char *a_cell_str, const char *a_ip_str, void **a_str_reply)
{

    if(!a_node_info->address.uint64) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not found -addr parameter");
        return -1;
    }
    if(!a_cell_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not found -cell parameter");
        return -1;
    }

    if(a_alias_str) {
        // add alias
        if(!dap_chain_node_alias_register(a_net, a_alias_str, &a_node_info->address)) {
            log_it(L_WARNING, "can't save alias %s", a_alias_str);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "alias '%s' can't be mapped to addr=0x%"DAP_UINT64_FORMAT_U,
                    a_alias_str, a_node_info->address.uint64);
            return -1;
        }
    }

    return !node_info_save_and_reply(a_net, a_node_info, a_str_reply)
        ? dap_cli_server_cmd_set_reply_text(a_str_reply, "node added"), 0
        : -1;
}

/**
 * @brief s_node_info_list_with_reply Handler of command 'node dump'
 * @param a_net
 * @param a_addr
 * @param a_is_full
 * @param a_alias
 * @param a_json_arr_reply
 * @return int 0 Ok, -1 error
 */
static int s_node_info_list_with_reply(dap_chain_net_t *a_net, dap_chain_node_addr_t * a_addr, bool a_is_full,
        const char *a_alias, json_object* a_json_arr_reply)
{
    int l_ret = 0;

    if ((a_addr && a_addr->uint64) || a_alias) {
        dap_chain_node_addr_t *l_addr = a_alias
                ? dap_chain_node_alias_find(a_net, a_alias)
                : DAP_DUP(a_addr);

        if (!l_addr) {
            log_it(L_ERROR, "Node address with specified params not found");
            return -1;
        }

        // read node
        dap_chain_node_info_t *node_info_read = node_info_read_and_reply(a_net, l_addr, a_json_arr_reply);
        if(!node_info_read) {
            DAP_DEL_Z(l_addr);
            return -2;
        }

        // get aliases in form of string
        /*dap_string_t *aliases_string = dap_string_new(NULL);
        dap_list_t *list_aliases = get_aliases_by_name(a_net, l_addr);
        if(list_aliases)
        {
            dap_list_t *list = list_aliases;
            while(list)
            {
                const char *alias = (const char *) list->data;
                dap_string_append_printf(aliases_string, "\nalias %s", alias);
                list = dap_list_next(list);
            }
            dap_list_free_full(list_aliases, NULL);
        }
        else
            dap_string_append(aliases_string, "\nno aliases");



        const int hostlen = 128;
        char *host4 = (char*) alloca(hostlen);
        char *host6 = (char*) alloca(hostlen);
        struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = node_info_read->hdr.ext_addr_v4 };
        const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4, hostlen);

        struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = node_info_read->hdr.ext_addr_v6 };
        const char* str_ip6 = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), host6, hostlen);

        // get links in form of string
        dap_string_t *links_string = dap_string_new(NULL);
        for(unsigned int i = 0; i < node_info_read->hdr.links_number; i++) {
            dap_chain_node_addr_t link_addr = node_info_read->links[i];
            dap_string_append_printf(links_string, "\nlink%02d address : " NODE_ADDR_FP_STR, i,
                    NODE_ADDR_FP_ARGS_S(link_addr));
        }

        dap_string_append_printf(l_string_reply, "\n");
        char l_port_str[10];
        sprintf(l_port_str,"%d",node_info_read->hdr.ext_port);

        // set short reply with node param
        if(!a_is_full)
            dap_string_append_printf(l_string_reply,
                    "node address "NODE_ADDR_FP_STR"\tcell 0x%016"DAP_UINT64_FORMAT_x"\tipv4 %s\tport: %s\tnumber of links %u",
                    NODE_ADDR_FP_ARGS_S(node_info_read->hdr.address),
                    node_info_read->hdr.cell_id.uint64, str_ip4,
                    node_info_read->hdr.ext_port ? l_port_str : "default",
                    node_info_read->hdr.links_number);
        else
            // set full reply with node param
            dap_string_append_printf(l_string_reply,
                    "node address " NODE_ADDR_FP_STR "\ncell 0x%016"DAP_UINT64_FORMAT_x"\nipv4 %s\nipv6 %s\nport: %s%s\nlinks %u%s",
                    NODE_ADDR_FP_ARGS_S(node_info_read->hdr.address),
                    node_info_read->hdr.cell_id.uint64,
                    str_ip4, str_ip6,
                    node_info_read->hdr.ext_port ? l_port_str : "default",
                    aliases_string->str,
                    node_info_read->hdr.links_number, links_string->str);
        dap_string_free(aliases_string, true);
        dap_string_free(links_string, true);

        DAP_DELETE(l_addr);
        DAP_DELETE(node_info_read);*/ // TODO

    } else { // Dump list with !a_addr && !a_alias
        size_t l_nodes_count = 0;
        dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_net->pub.gdb_nodes, &l_nodes_count);

        if(!l_nodes_count || !l_objs) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR,
                "No records\n");
            dap_global_db_objs_delete(l_objs, l_nodes_count);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR;
        } else {
            json_object* json_node_list_obj = json_object_new_object();
            if (!json_node_list_obj) return json_object_put(json_node_list_obj), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
            json_object_object_add(json_node_list_obj, "got_nodes", json_object_new_uint64(l_nodes_count));
            json_object* json_node_list_arr = json_object_new_array();
            if (!json_node_list_arr) return json_object_put(json_node_list_obj), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
            json_object_object_add(json_node_list_obj, "NODES", json_node_list_arr);
            json_object_array_add(a_json_arr_reply, json_node_list_obj);

            for (size_t i = 0; i < l_nodes_count; i++) {
                dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t*)l_objs[i].value;
                if (dap_chain_node_addr_is_blank(&l_node_info->address)){
                    log_it(L_ERROR, "Node address is empty");
                    continue;
                }
                json_object* json_node_obj = json_object_new_object();
                if (!json_node_obj) return json_object_put(json_node_list_obj), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                char l_ts[DAP_TIME_STR_SIZE] = { '\0' };
                dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), l_objs[i].timestamp);

                char *l_addr = dap_strdup_printf(NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_node_info->address));
                json_object_object_add(json_node_obj, "address", json_object_new_string(l_addr));
                json_object_object_add(json_node_obj, "IPv4", json_object_new_string(l_node_info->ext_host));
                json_object_object_add(json_node_obj, "port", json_object_new_uint64(l_node_info->ext_port));
                json_object_object_add(json_node_obj, "timestamp", json_object_new_string(l_ts));
                json_object_array_add(json_node_list_arr, json_node_obj);
                DAP_DELETE(l_addr);

                // TODO make correct work with aliases
                /*dap_string_t *aliases_string = dap_string_new(NULL);

                for (size_t i = 0; i < l_data_size; i++) {
                    //dap_chain_node_addr_t addr_i;
                    dap_global_db_obj_t *l_obj = l_aliases_objs + i;
                    if (!l_obj)
                        break;
                    dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t *)l_obj->value;
                    if (l_addr && l_obj->value_len == sizeof(dap_chain_node_addr_t) &&
                            l_node_info->hdr.address.uint64 == l_addr->uint64) {
                        dap_string_append_printf(aliases_string, "\nalias %s", l_obj->key);
                    }
                }
                if (!l_data_size)
                    dap_string_append(aliases_string, "\nno aliases");

                // get links in form of string
                dap_string_t *links_string = dap_string_new(NULL);
                for(unsigned int i = 0; i < l_node_info->hdr.links_number; i++) {
                    dap_chain_node_addr_t link_addr = l_node_info->links[i];
                    dap_string_append_printf(links_string, "\nlink%02d address : " NODE_ADDR_FP_STR, i,
                            NODE_ADDR_FP_ARGS_S(link_addr));
                }

                if(i)
                    dap_string_append_printf(l_string_reply, "\n");
                char l_port_str[10];
                sprintf(l_port_str, "%d", l_node_info->hdr.ext_port);
                // set short reply with node param
                if(!a_is_full)
                    dap_string_append_printf(l_string_reply,
                            "node address "NODE_ADDR_FP_STR"\tcell 0x%016"DAP_UINT64_FORMAT_x"\tipv4 %s\tport: %s\tnumber of links %u",
                            NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address),
                            l_node_info->hdr.cell_id.uint64, str_ip4,
                            l_node_info->hdr.ext_port ? l_port_str : "default",
                            l_node_info->hdr.links_number);
                else
                    // set full reply with node param
                    dap_string_append_printf(l_string_reply,
                            "node address " NODE_ADDR_FP_STR "\ncell 0x%016"DAP_UINT64_FORMAT_x"\nipv4 %s\nipv6 %s\nport: %s%s\nlinks %u%s",
                            NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address),
                            l_node_info->hdr.cell_id.uint64,
                            str_ip4, str_ip6,
                            l_node_info->hdr.ext_port ? l_port_str : "default",
                            aliases_string->str,
                            l_node_info->hdr.links_number, links_string->str);
                dap_string_free(aliases_string, true);
                dap_string_free(links_string, true);*/
            }
            json_object_object_add(json_node_list_obj, "NODES", json_node_list_arr);
            json_object_array_add(a_json_arr_reply, json_node_list_obj);
        }
        dap_global_db_objs_delete(l_objs, l_nodes_count);
    }
    return l_ret;
}

/**
 * @brief com_global_db
 * global_db command
 * @param a_argc
 * @param a_argv
 * @param arg_func
 * @param a_str_reply
 * @return int
 * return 0 OK, -1 Err
 */
int com_global_db(int a_argc, char ** a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum {
        CMD_NONE, CMD_ADD, CMD_FLUSH, CMD_RECORD, CMD_WRITE, CMD_READ,
        CMD_DELETE, CMD_DROP, CMD_GET_KEYS, CMD_GROUP_LIST
    };
    int arg_index = 1;
    int cmd_name = CMD_NONE;
    // find 'cells' as first parameter only
    if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "flush", NULL))
        cmd_name = CMD_FLUSH;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "record", NULL))
            cmd_name = CMD_RECORD;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "write", NULL))
                cmd_name = CMD_WRITE;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "read", NULL))
                cmd_name = CMD_READ;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "delete", NULL))
                cmd_name = CMD_DELETE;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "drop_table", NULL))
                cmd_name = CMD_DROP;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "get_keys", NULL))
            cmd_name = CMD_GET_KEYS;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "group_list", NULL))
            cmd_name = CMD_GROUP_LIST;

    switch (cmd_name) {
    case CMD_FLUSH:
    {
        json_object* json_obj_flush = NULL;
        int res_flush = dap_global_db_flush_sync();
        switch (res_flush) {
        case 0:
            json_obj_flush = json_object_new_object();
            json_object_object_add(json_obj_flush, "command_status", json_object_new_string("Commit data base and filesystem caches to disk completed."));
            json_object_array_add(*a_json_arr_reply, json_obj_flush);
            break;
        case -1:
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_OPEN_DIR,
                                                        "Couldn't open db directory. Can't init cdb\n"
                                                        "Reboot the node.\n\n");
            break;
        case -2:
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_INIT_DB,
                                                        "Couldn't open db directory. Can't init cdb\n"
                                                        "Reboot the node.\n\n");
            break;
        case -3:
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_INIT_SQL,
                                                        "Can't init sqlite\n"
                                                        "Reboot the node.\n\n");
            break;
        default:
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_CAN_NOT_COMMIT_TO_DISK,
                                                        "Can't commit data base caches to disk completed.\n"
                                                        "Reboot the node.\n\n");
            break;
        }
        return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
    }
    case CMD_RECORD:
    {
        enum {
            SUMCMD_GET, SUMCMD_PIN, SUMCMD_UNPIN
        };
        if(!arg_index || a_argc < 3) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,"parameters are not valid");
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }
        int arg_index_n = ++arg_index;
        int l_subcmd;
        // Get value
        if((arg_index_n = dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "get", NULL))!= 0) {
            l_subcmd = SUMCMD_GET;
        }
        // Pin record
        else if((arg_index_n = dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "pin", NULL)) != 0) {
            l_subcmd = SUMCMD_PIN;
        }
        // Unpin record
        else if((arg_index_n = dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "unpin", NULL)) != 0) {
            l_subcmd = SUMCMD_UNPIN;
        }
        else{
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
                                            "Subcommand '%s' not recognized, available subcommands are 'get', 'pin' or 'unpin'", a_argv[2]);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }
        // read record from database
        const char *l_key = NULL;
        const char *l_group = NULL;
        // find key and group
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-key", &l_key);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group);
        size_t l_value_len = 0;
        bool l_is_pinned = false;
        dap_nanotime_t l_ts =0;
        uint8_t *l_value = dap_global_db_get_sync(l_group, l_key, &l_value_len, &l_is_pinned, &l_ts);
        if(!l_value || !l_value_len) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_FOUND,
                                            "Record not found\n\n");
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_FOUND;
        }
        json_object* json_obj_rec = json_object_new_object();
        int l_ret = 0;
        // prepare record information
        switch (l_subcmd) {
            case SUMCMD_GET: // Get value
            {
                char *l_value_str = DAP_NEW_Z_SIZE(char, l_value_len * 2 + 2);
                if(!l_value_str) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    DAP_DELETE(l_value);
                    json_object_put(json_obj_rec);
                    return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_MEMORY_ERR;
                }
                json_object_object_add(json_obj_rec, "command_status", json_object_new_string("Commit data base and filesystem caches to disk completed."));

                dap_bin2hex(l_value_str, l_value, l_value_len);
                json_object_object_add(json_obj_rec, "command_status", json_object_new_string("Record found"));
                json_object_object_add(json_obj_rec, "lenght_byte", json_object_new_uint64(l_value_len));
                json_object_object_add(json_obj_rec, "hash", json_object_new_string(dap_get_data_hash_str(l_value, l_value_len).s));
                json_object_object_add(json_obj_rec, "pinned", l_is_pinned ? json_object_new_string("Yes") : json_object_new_string("No") );
                json_object_object_add(json_obj_rec, "value", json_object_new_string(l_value_str));
                DAP_DELETE(l_value_str);
                break;
            }
            case SUMCMD_PIN: // Pin record
            {
                if(l_is_pinned){
                    json_object_object_add(json_obj_rec, "pinned_status", json_object_new_string("record already pinned"));
                    break;
                }
                if(dap_global_db_pin_sync( l_group, l_key) ==0 ){
                    json_object_object_add(json_obj_rec, "pinned_status", json_object_new_string("record successfully pinned"));
                }
                else{
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_PINED,
                                            "can't pin the record");
                    l_ret = -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_PINED;
                }
                break;
            }
            case SUMCMD_UNPIN: // Unpin record
            {
                if(!l_is_pinned) {
                    json_object_object_add(json_obj_rec, "unpinned_status", json_object_new_string("record already unpinned"));
                    break;
                }
                if(dap_global_db_unpin_sync(l_group,l_key) == 0 ) {
                    json_object_object_add(json_obj_rec, "unpinned_status", json_object_new_string("record successfully unpinned"));
                }
                else {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_UNPINED,
                                            "can't unpin the record");
                    l_ret = -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_UNPINED;
                }
                break;
            }
        }
        json_object_array_add(*a_json_arr_reply, json_obj_rec);
        DAP_DELETE(l_value);
        return l_ret;
    }
    case CMD_WRITE:
    {
        const char *l_group_str = NULL;
        const char *l_key_str = NULL;
        const char *l_value_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-key", &l_key_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_str);

        if (!l_group_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
                                            "%s requires parameter 'group' to be valid", a_argv[0]);

            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        if (!l_key_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
                                            "%s requires parameter 'key' to be valid", a_argv[0]);

            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        if (!l_value_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
                                            "%s requires parameter 'value' to be valid", a_argv[0]);

            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        if (!dap_global_db_set_sync(l_group_str, l_key_str, l_value_str, strlen(l_value_str) +1 , false)) {
            json_object* json_obj_write = json_object_new_object();
            json_object_object_add(json_obj_write, "write_status", json_object_new_string("Data has been successfully written to the database"));
            json_object_array_add(*a_json_arr_reply, json_obj_write);
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_WRITING_FILED,
                                            "Data writing is failed");
        }
    }
    case CMD_READ:
    {
        const char *l_group_str = NULL;
        const char *l_key_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-key", &l_key_str);

        if(!l_group_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
                                            "%s requires parameter 'group' to be valid", a_argv[0]);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        if(!l_key_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
                                            "%s requires parameter 'key' to be valid", a_argv[0]);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        size_t l_out_len = 0;
        dap_nanotime_t l_ts = 0;
        uint8_t *l_value_out = dap_global_db_get_sync(l_group_str, l_key_str, &l_out_len, NULL, &l_ts);
        /*if (!l_value_out || !l_out_len)
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Record with key %s in group %s not found", l_key_str, l_group_str);
            return -121;
        }*/
        json_object* json_obj_read = json_object_new_object();
        if (l_ts) {
            char l_ts_str[80] = { '\0' };
            dap_nanotime_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_ts);
            char *l_value_hexdump = dap_dump_hex(l_value_out, l_out_len);
            if (l_value_hexdump) {
                char *l_value_hexdump_new = dap_strdup_printf("\n%s", l_value_hexdump);
                json_object_object_add(json_obj_read, "group", json_object_new_string(l_group_str));
                json_object_object_add(json_obj_read, "key", json_object_new_string(l_key_str));
                json_object_object_add(json_obj_read, "time", json_object_new_string(l_ts_str));
                json_object_object_add(json_obj_read, "value_len", json_object_new_uint64(l_out_len));
                json_object_object_add(json_obj_read, "value_hex", json_object_new_string(l_value_hexdump_new));
                DAP_DELETE(l_value_hexdump_new);
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_TIME_NO_VALUE,
                                            "\n\"%s : %s\"\nTime: %s\nNo value\n",
                                                  l_group_str, l_key_str, l_ts_str);
            }
        } else if (dap_global_db_group_match_mask(l_group_str, "*.mempool") && !l_value_out) {
            // read hole value (error) in mempool
            dap_store_obj_t* l_read_obj = dap_global_db_get_raw_sync(l_group_str, l_key_str);
            if (!l_read_obj || !l_read_obj->value || !l_read_obj->value_len) {
               dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_TIME_NO_VALUE,
                                            "\n\"%s : %s\"\nNo value\n",
                                                  l_group_str, l_key_str);
            } else {
                json_object_object_add(json_obj_read, "group", json_object_new_string(l_group_str));
                json_object_object_add(json_obj_read, "key", json_object_new_string(l_key_str));
                json_object_object_add(json_obj_read, "error", json_object_new_string((char*)l_read_obj->value));
            }
            dap_store_obj_free_one(l_read_obj);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_RECORD_NOT_FOUND,
                                            "\nRecord \"%s : %s\" not found\n",
                                              l_group_str, l_key_str);
        }
        DAP_DELETE(l_value_out);
        json_object_array_add(*a_json_arr_reply, json_obj_read);
        return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
    }
    case CMD_DELETE:
    {
        const char *l_group_str = NULL;
        const char *l_key_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-key", &l_key_str);

        if(!l_group_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,
                                            "%s requires parameter 'group' to be valid", a_argv[0]);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        if(!l_key_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_NO_KEY_PROVIDED,
                                            "No key provided, entire table %s will be altered", l_group_str);

            size_t l_objs_count = 0;
            dap_global_db_obj_t* l_obj = dap_global_db_get_all_sync(l_group_str, &l_objs_count);

            if (!l_obj || !l_objs_count)
            {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_NO_DATA_IN_GROUP,
                                            "No data in group %s.", l_group_str);
                return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_NO_DATA_IN_GROUP;
            }
            size_t i, j = 0;
            for (i = 0; i < l_objs_count; ++i) {
                if (!l_obj[i].key)
                    continue;
                if (!dap_global_db_del_sync_ex(l_group_str, l_obj[i].key, DAP_GLOBAL_DB_MANUAL_DEL, strlen(DAP_GLOBAL_DB_MANUAL_DEL)+1)) {
                    ++j;
                }
            }
            dap_global_db_objs_delete(l_obj, l_objs_count);
            json_object* json_obj_del = json_object_new_object();
            json_object_object_add(json_obj_del, "removed_records", json_object_new_uint64(j));
            json_object_object_add(json_obj_del, "of_records", json_object_new_uint64(i));
            json_object_object_add(json_obj_del, "in_table", json_object_new_string(l_group_str));
            json_object_array_add(*a_json_arr_reply, json_obj_del);
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
        }

        if (!dap_global_db_del_sync_ex(l_group_str, l_key_str, DAP_GLOBAL_DB_MANUAL_DEL, strlen(DAP_GLOBAL_DB_MANUAL_DEL)+1)) {
            json_object* json_obj_del = json_object_new_object();
            json_object_object_add(json_obj_del, "record_key", json_object_new_string(l_key_str));
            json_object_object_add(json_obj_del, "group_name", json_object_new_string(l_group_str));
            json_object_object_add(json_obj_del, "status", json_object_new_string("deleted"));
            json_object_array_add(*a_json_arr_reply, json_obj_del);
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_DELETE_FAILD,
                                            "Record with key %s in group %s deleting failed", l_group_str, l_key_str);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_DELETE_FAILD;
        }
    }
    case CMD_DROP:
    {
        const char *l_group_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);

        if(!l_group_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,"%s requires parameter 'group' to be valid", a_argv[0]);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        if (!dap_global_db_erase_table_sync(l_group_str))
        {
            json_object* json_obj_drop = json_object_new_object();
            json_object_object_add(json_obj_drop, "dropped_table", json_object_new_string(l_group_str));
            json_object_array_add(*a_json_arr_reply, json_obj_drop);
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_DROP_FAILED,"Failed to drop table %s", l_group_str);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_DROP_FAILED;
        }
    }
    case CMD_GET_KEYS:
    {
        const char *l_group_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);

        if(!l_group_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,"%s requires parameter 'group' to be valid", a_argv[0]);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }

        size_t l_objs_count = 0;
        dap_store_obj_t *l_objs = dap_global_db_get_all_raw_sync(l_group_str, &l_objs_count);

        if (!l_objs || !l_objs_count)
        {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_NO_DATA_IN_GROUP,"No data in group %s.", l_group_str);
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_NO_DATA_IN_GROUP;
        }

        json_object* json_arr_keys = json_object_new_array();
        json_object* json_obj_keys = NULL;
        for(size_t i = 0; i < l_objs_count; i++) {
            char l_ts[64] = { '\0' };
            dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), l_objs[i].timestamp);
            json_obj_keys = json_object_new_object();
            json_object_object_add(json_obj_keys, "key", json_object_new_string(l_objs[i].key));
            json_object_object_add(json_obj_keys, "time", json_object_new_string(l_ts));
            json_object_object_add(json_obj_keys, "type", json_object_new_string(
                                       dap_store_obj_get_type(l_objs + i) == DAP_GLOBAL_DB_OPTYPE_ADD ?  "record" : "hole"));
            json_object_array_add(json_arr_keys, json_obj_keys);
        }
        dap_store_obj_free(l_objs, l_objs_count);

        json_object* json_keys_list = json_object_new_object();
        json_object_object_add(json_keys_list, "group_name", json_object_new_string(l_group_str));
        json_object_object_add(json_keys_list, "keys_list", json_arr_keys);
        json_object_array_add(*a_json_arr_reply, json_keys_list);
        return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
    }
    case CMD_GROUP_LIST: {
        json_object* json_group_list = json_object_new_object();
        dap_list_t *l_group_list = dap_global_db_driver_get_groups_by_mask("*");
        size_t l_count = 0;
        json_object* json_arr_group = json_object_new_array();
        json_object* json_obj_list = NULL;
        for (dap_list_t *l_list = l_group_list; l_list; l_list = dap_list_next(l_list), ++l_count) {
            json_obj_list = json_object_new_object();
            json_object_object_add(json_obj_list, (char*)l_list->data,
                                   json_object_new_uint64(dap_global_db_driver_count((char*)l_list->data, c_dap_global_db_driver_hash_blank, false)));
            json_object_array_add(json_arr_group, json_obj_list);
        }
        json_object_object_add(json_group_list, "group_list", json_arr_group);
        json_object_object_add(json_group_list, "total_count", json_object_new_uint64(l_count));
        json_object_array_add(*a_json_arr_reply, json_group_list);
        dap_list_free(l_group_list);
        return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_JSON_OK;
    }
    default:
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR,"parameters are not valid");
            return -DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
    }
}

static dap_tsd_t* s_chain_node_cli_com_node_create_tsd_addr(char **a_argv, int a_arg_start, int a_arg_end, void **a_str_reply, const char *a_specified_decree) {
    const char *l_ban_addr_str = NULL;
    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_start, a_arg_end, "-addr", &l_ban_addr_str)) {
        dap_stream_node_addr_t l_addr = {0};
        if (dap_stream_node_addr_from_str(&l_addr, l_ban_addr_str))
            return dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't convert the -addr option value to node address"), NULL;
        return dap_tsd_create_string(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING, l_ban_addr_str);
    } else if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_start, a_arg_end, "-host", &l_ban_addr_str))
        return dap_tsd_create_string(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST, l_ban_addr_str);
    else
        return dap_cli_server_cmd_set_reply_text(a_str_reply, "The -host or -addr option was not "
                                                       "specified to create a %s entry creation decree.", a_specified_decree), NULL;
}

static dap_tsd_t* s_chain_node_cli_com_node_create_tsd_addr_json(char **a_argv, int a_arg_start, int a_arg_end, json_object* a_json_arr_reply, const char *a_specified_decree) {
    const char *l_ban_addr_str = NULL;
    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_start, a_arg_end, "-addr", &l_ban_addr_str)) {
        dap_stream_node_addr_t l_addr = {0};
        if (dap_stream_node_addr_from_str(&l_addr, l_ban_addr_str)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_CANT_CONVERT_ADDR_VALUE_ERR,
                                   "Can't convert the -addr option value to node address");
            return NULL;
        }
        return dap_tsd_create_string(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING, l_ban_addr_str);
    } else if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_start, a_arg_end, "-host", &l_ban_addr_str))
        return dap_tsd_create_string(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST, l_ban_addr_str);
    else {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_HOST_OPTION_WASNOT_SPECIFIED_ERR,
                               "The -host or -addr option was not specified to create a %s entry creation decree.", a_specified_decree);
        return NULL;
    }
}

/**
 * Node command
 */
int com_node(int a_argc, char ** a_argv, void **a_str_reply)
{
    json_object ** a_json_arr_reply = (json_object **) a_str_reply;
    enum {
        CMD_NONE, CMD_ADD, CMD_DEL, CMD_ALIAS, CMD_HANDSHAKE, CMD_CONNECT, CMD_LIST, CMD_DUMP, CMD_CONNECTIONS, CMD_BALANCER,
        CMD_BAN, CMD_UNBAN, CMD_BANLIST
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "add", NULL)) {
        cmd_num = CMD_ADD;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "del", NULL)) {
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
        cmd_num = CMD_LIST;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "dump", NULL)) {
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
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_COMMAND_NOT_RECOGNIZED_ERR,
            "command %s not recognized", a_argv[1]);
        return -DAP_CHAIN_NODE_CLI_COM_NODE_COMMAND_NOT_RECOGNIZED_ERR;
    }
    const char *l_addr_str = NULL, *l_port_str = NULL, *alias_str = NULL;
    const char *l_cell_str = NULL, *l_link_str = NULL, *l_hostname = NULL;

    // find net
    dap_chain_net_t *l_net = NULL;

    int l_net_parse_val = dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, NULL, &l_net, CHAIN_TYPE_INVALID);
    if(l_net_parse_val < 0 && cmd_num != CMD_BANLIST) {
        if ((cmd_num != CMD_CONNECTIONS && cmd_num != CMD_DUMP) || l_net_parse_val == -102)
            return -11;
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
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_NODE_ADDR_ERR,
                "Can't parse node address %s", l_addr_str);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_NODE_ADDR_ERR;
        }
    }
    if (l_port_str) {
        dap_digit_from_string(l_port_str, &l_node_info->ext_port, sizeof(uint16_t));
        if (!l_node_info->ext_port) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_HOST_PORT_ERR,
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
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR,
                    "You have no access rights");
                return l_res;
            }
            // We're in authorized list, add directly
            struct sockaddr_storage l_verifier = { };
            if ( 0 > dap_net_parse_config_address(l_hostname, l_node_info->ext_host, &l_port, &l_verifier, NULL) ) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PARSE_HOST_STRING_ERR,
                    "Can't parse host string %s", l_hostname);
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PARSE_HOST_STRING_ERR;
            }
            if ( !l_node_info->ext_port && !(l_node_info->ext_port = l_port) ) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR,
                                       "Unspecified port");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR;
            }

            l_node_info->ext_host_len = dap_strlen(l_node_info->ext_host);
            l_res = dap_chain_node_info_save(l_net, l_node_info);

            if (l_res) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_ADDED_NOT_ERR,
                                       "Can't add node %s, error %d", l_addr_str, l_res);
            } else {
                json_object* json_obj_out = json_object_new_object();
                if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                json_object_object_add(json_obj_out, "successfully_added_node", json_object_new_string(l_addr_str));
                json_object_array_add(*a_json_arr_reply, json_obj_out);
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
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_INVALID_SERVER_ERR,
                                       "Invalid server IP address, check [server] section in cellframe-node.cfg");
                    return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_INVALID_SERVER_ERR;
                }
            }
            if (!l_port) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR,
                                       "Unspecified port");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR;
            } 
        }
        json_object* json_obj_out = NULL;
        switch ( l_res = dap_chain_net_node_list_request(l_net, l_port, true, 'a') )
        {
            case 1:
                json_obj_out = json_object_new_object();
                if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                json_object_object_add(json_obj_out, "status", json_object_new_string("Successfully added"));
                json_object_array_add(*a_json_arr_reply, json_obj_out);
                 return DAP_CHAIN_NODE_CLI_COM_NODE_OK;
            case 2: dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_NO_SERVER_ERR,
                                                                                                "No server");break;
            case 3: dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_DIDNT_ADD_ADDRESS_ERR,
                                                                "Didn't add your address node to node list");break;
            case 4: dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_CALCULATE_HASH_ERR,
                                                                       "Can't calculate hash for your addr");break;
            case 5: dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_DO_HANDSHAKE_ERR,
                                                                         "Can't do handshake for your node");break;
            case 6: dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_ALREADY_EXISTS_ERR,
                                                                                  "The node already exists");break;
            case 7: dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PROCESS_NODE_LIST_ERR,
                                                                     "Can't process node list HTTP request");break;
            default:dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PROCESS_REQUEST_ERR,
                                                                   "Can't process request, error %d", l_res);break;
            return l_res;
        }
    }

    case CMD_DEL: {
        // handler of command 'node del'
        if (l_addr_str) {
            if (!dap_chain_net_is_my_node_authorized(l_net)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_DELL_NO_ACCESS_RIGHTS_ERR,
                                        "You have no access rights");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_DELL_NO_ACCESS_RIGHTS_ERR;
            }
            int l_res = dap_chain_node_info_del(l_net, l_node_info);
            if (l_res)
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_DELL_CANT_DEL_NODE_ERR,
                                        "Can't delete node %s, error %d", l_addr_str, l_res);
            else {
                json_object* json_obj_out = json_object_new_object();
                if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                json_object_object_add(json_obj_out, "successfully_deleted_node", json_object_new_string(l_addr_str));
                json_object_array_add(*a_json_arr_reply, json_obj_out);
            }
            return l_res;
        }
        // Synchronous request, wait for reply
        int l_res = dap_chain_net_node_list_request(l_net, 0, true, 'r');
        json_object* json_obj_out = NULL;
        switch (l_res) {
            case 8: 
                json_obj_out = json_object_new_object();
                if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                json_object_object_add(json_obj_out, "status", json_object_new_string("Successfully deleted"));
                json_object_array_add(*a_json_arr_reply, json_obj_out); 
            return DAP_CHAIN_NODE_CLI_COM_NODE_OK;
            default: dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_DELL_CANT_PROCESS_REQUEST_ERR,
                                       "Can't process request, error %d", l_res);
            return l_res;
        }
    }

    case CMD_LIST:{
        // handler of command 'node dump'
        bool l_is_full = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-full", NULL);
        return s_node_info_list_with_reply(l_net, &l_node_addr, l_is_full, alias_str, *a_json_arr_reply);
    }
    case CMD_DUMP: {
        json_object* json_obj_out = json_object_new_object();
        if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        dap_string_t *l_string_reply = dap_chain_node_states_info_read(l_net, l_node_info->address);
        json_object_object_add(json_obj_out, "status_dump", json_object_new_string(l_string_reply->str));
        json_object_array_add(*a_json_arr_reply, json_obj_out);
        dap_string_free(l_string_reply, true);
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
                    json_object* json_obj_out = json_object_new_object();
                    if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
                    json_object_object_add(json_obj_out, "status_alias", json_object_new_string("alias mapped successfully"));
                    json_object_array_add(*a_json_arr_reply, json_obj_out);
                }
            }
            else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ADDR_NOT_FOUND_ERR,
                                                                "alias can't be mapped because -addr is not found");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ADDR_NOT_FOUND_ERR;
            }
        }
        else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ALIAS_NOT_FOUND_ERR,
                "alias can't be mapped because -alias is not found");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ALIAS_NOT_FOUND_ERR;
        }

        break;
        // make connect
    case CMD_CONNECT:
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECT_NOT_IMPLEMENTED_ERR,
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "no address found by alias");
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "addr not found");
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "no node is available");
                return -1;
            }
        }
        dap_chain_node_info_t *l_remote_node_info;
        dap_chain_node_client_t *l_node_client;
        int res;
        do {
            l_remote_node_info = node_info_read_and_reply(l_net, &l_node_addr, a_str_reply);
            if(!l_remote_node_info) {
                return -1;
            }
            // start connect
            l_node_client = dap_chain_node_client_connect_default_channels(l_net,l_remote_node_info);
            if(!l_node_client) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "can't connect");
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
            dap_cli_server_cmd_set_reply_text(a_str_reply, "no response from remote node(s)");
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
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Can't send sync chains request");
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
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: can't sync with node "NODE_ADDR_FP_STR,
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Can't send sync chains request");
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
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Node sync completed: Chains and gdb are synced");
        return 0;

    }
#endif
        // make handshake
    case CMD_HANDSHAKE: {
        // get address from alias if addr not defined
        if(alias_str && !l_node_addr.uint64) {
            dap_chain_node_addr_t *address_tmp = dap_chain_node_alias_find(l_net, alias_str);
            if(address_tmp) {
                l_node_addr = *address_tmp;
                DAP_DELETE(address_tmp);
            }
            else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR,
                                            "No address found by alias");
                return -DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR;
            }
        }
        l_node_addr = l_node_info->address;
        if(!l_node_addr.uint64) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR,
                                            "Addr not found");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR;
        }

        dap_chain_node_info_t *node_info = node_info_read_and_reply(l_net, &l_node_addr, *a_json_arr_reply);
        if(!node_info)
            return -6;
        int timeout_ms = 5000; //5 sec = 5000 ms
        // start handshake
        dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(l_net,node_info);
        if(!l_client) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_CANT_CONNECT_ERR,
                "Can't connect");
            DAP_DELETE(node_info);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_CANT_CONNECT_ERR;
        }
        // wait handshake
        int res = dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
        if (res) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_RESPONSE_ERR,
                                        "No response from node");
            // clean client struct
            // dap_chain_node_client_close_unsafe(l_client); del in s_go_stage_on_client_worker_unsafe
            DAP_DELETE(node_info);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_RESPONSE_ERR;
        }
        DAP_DELETE(node_info);
        dap_chain_node_client_close_unsafe(l_client);
        json_object* json_obj_out = json_object_new_object();
        if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        json_object_object_add(json_obj_out, "status_handshake", json_object_new_string("Connection established"));
        json_object_array_add(*a_json_arr_reply, json_obj_out);
    } break;

    case CMD_CONNECTIONS: {

        if (l_net) {
            dap_cluster_t *l_links_cluster = dap_cluster_by_mnemonim(l_net->pub.name);
            if (!l_links_cluster) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_NOT_FOUND_LINKS_ERR,
                                            "Not found links cluster for net %s", l_net->pub.name);
                break;
            }
            json_object *l_jobj_links = dap_cluster_get_links_info_json(l_links_cluster);
            json_object_array_add(*a_json_arr_reply, l_jobj_links);
        } else {
            const char *l_guuid_str = NULL;
            dap_cluster_t *l_cluster = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cluster", &l_guuid_str);
            if (l_guuid_str) {
                bool l_success = false;
                dap_guuid_t l_guuid = dap_guuid_from_hex_str(l_guuid_str, &l_success);
                if (!l_success) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_CANT_PARSE_CLUSTER_ERR,
                                                    "Can't parse cluster guid %s", l_guuid_str);
                    break;
                }
                l_cluster = dap_cluster_find(l_guuid);
                
                if (!l_cluster) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_NOT_FOUND_CLUSTER_ID_ERR,
                                                    "Not found cluster with ID %s", l_guuid_str);
                    break;
                }
            }
            json_object *l_jobj_links = dap_cluster_get_links_info_json(l_cluster);
            json_object_array_add(*a_json_arr_reply, l_jobj_links);
        }
    } break;

    case  CMD_BAN: {
        dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
        if(!l_chain) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_NETWORK_DOESNOT_SUPPORT_ERR,
                                        "Network %s does not support decrees.", l_net->pub.name);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_NETWORK_DOESNOT_SUPPORT_ERR;
        }
        const char * l_hash_out_type = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
        if(!l_hash_out_type)
            l_hash_out_type = "hex";
        if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_INVALID_PARAMETER_ERR,
                                        "invalid parameter -H, valid values: -H <hex | base58>");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_INVALID_PARAMETER_ERR;
        }
        const char *l_certs_str = NULL;
        size_t l_certs_count = 0;
        dap_cert_t **l_certs = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_REQUIRES_PARAMETER_ERR,
                                        "ban create requires parameter '-certs'");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_REQUIRES_PARAMETER_ERR;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
        if(!l_certs_count) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_LEAST_ONE_VALID_CERT_ERR,
                                        "decree create command request at least one valid certificate to sign the decree");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_LEAST_ONE_VALID_CERT_ERR;
        }
        dap_chain_datum_decree_t *l_decree = NULL;
        dap_tsd_t *l_addr_tsd = s_chain_node_cli_com_node_create_tsd_addr_json(a_argv, arg_index, a_argc, *a_json_arr_reply, "bun");
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
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_BAN_DECREE_CREATION_FAILED_ERR,
                                            "Decree creation failed. Successful count of certificate signing is 0");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_BAN_DECREE_CREATION_FAILED_ERR;
        }
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, l_decree,
                                                            sizeof(*l_decree) + l_decree->header.data_size +
                                                            l_decree->header.signs_size);
        DAP_DELETE(l_decree);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        json_object* json_obj_out = json_object_new_object();
        if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        json_object_object_add(json_obj_out, "datum_placed_status", l_key_str_out ? json_object_new_string(l_key_str_out) :
                                                                                    json_object_new_string("not placed"));
        json_object_array_add(*a_json_arr_reply, json_obj_out);
        DAP_DELETE(l_key_str_out);
    } break;

    case CMD_UNBAN: {
        dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
        if(!l_chain) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_NETWORK_DOES_NOT_SUPPORT_ERR,
                                            "Network %s does not support decrees.", l_net->pub.name);
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_NETWORK_DOES_NOT_SUPPORT_ERR;
        }
        const char * l_hash_out_type = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
        if(!l_hash_out_type)
            l_hash_out_type = "hex";
        if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_INVALID_PRAMETER_ERR,
                                        "invalid parameter -H, valid values: -H <hex | base58>");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_INVALID_PRAMETER_ERR;
        }
        const char *l_certs_str = NULL;
        size_t l_certs_count = 0;
        dap_cert_t **l_certs = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_REQUIRES_PARAMETER_CERT_ERR,
                                        "ban create requires parameter '-certs'");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_REQUIRES_PARAMETER_CERT_ERR;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
        if(!l_certs_count) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_LEAST_ONE_VALID_CERT_ERR,
                                        "decree create command request at least one valid certificate to sign the decree");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_LEAST_ONE_VALID_CERT_ERR;
        }
        dap_chain_datum_decree_t *l_decree = NULL;
        dap_tsd_t *l_addr_tsd = s_chain_node_cli_com_node_create_tsd_addr_json(a_argv, arg_index, a_argc, *a_json_arr_reply, "unbun");
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
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_DECREE_CREATION_FAILED_ERR,
                                                    "Decree creation failed. Successful count of certificate signing is 0");
            return -DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_DECREE_CREATION_FAILED_ERR;
        }
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, l_decree,
                                                            sizeof(*l_decree) + l_decree->header.data_size +
                                                            l_decree->header.signs_size);
        DAP_DELETE(l_decree);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        json_object* json_obj_out = json_object_new_object();
        if (!json_obj_out) return json_object_put(json_obj_out), DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR;
        json_object_object_add(json_obj_out, "datum_placed_status", l_key_str_out ? json_object_new_string(l_key_str_out) :
                                                                                    json_object_new_string("not placed"));
        json_object_array_add(*a_json_arr_reply, json_obj_out);
        DAP_DELETE(l_key_str_out);
    } break;

    case CMD_BANLIST: {
        json_object* json_obj_out = dap_http_ban_list_client_dump(NULL);
        json_object_array_add(*a_json_arr_reply, json_obj_out);
    } break;

    case CMD_BALANCER: {
        //balancer link list
        json_object *l_links_list = dap_chain_net_balancer_get_node_str(l_net);
        json_object_array_add(*a_json_arr_reply, l_links_list);
    } break;

    default:
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NODE_UNRECOGNISED_SUB_ERR,
                                    "Unrecognized subcommand '%s'", arg_index < a_argc ? a_argv[arg_index] : "(null)");
        break;
    }
    return 0;
}

/**
 * @brief com_version
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_version(int argc, char ** argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    (void) argc;
    (void) argv;
#ifndef DAP_VERSION
#pragma message "[!WRN!] DAP_VERSION IS NOT DEFINED. Manual override engaged."
#define DAP_VERSION "0.9-15"
#endif
    json_object* json_obj_out = json_object_new_object();
    char *l_vers = dap_strdup_printf("%s version "DAP_VERSION"\n", dap_get_appname());
    json_object_object_add(json_obj_out, "status", json_object_new_string(l_vers));
    DAP_DELETE(l_vers);
    json_object_array_add(*a_json_arr_reply, json_obj_out);
    return 0;
}


/**
 * @brief
 * Help command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_help(int a_argc, char **a_argv, void **a_str_reply)
{
    if (a_argc > 1) {
        log_it(L_DEBUG, "Help for command %s", a_argv[1]);
        dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find(a_argv[1]);
        if(l_cmd) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s:\n%s", l_cmd->doc, l_cmd->doc_ex);
            return 0;
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "command \"%s\" not recognized", a_argv[1]);
        }
        return -1;
    } else {
        // TODO Read list of commands & return it
        log_it(L_DEBUG, "General help requested");
        dap_string_t * l_help_list_str = dap_string_new(NULL);
        dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_get_first();
        while(l_cmd) {
            dap_string_append_printf(l_help_list_str, "%s:\t\t\t%s\n",
                    l_cmd->name, l_cmd->doc ? l_cmd->doc : "(undocumented command)");
            l_cmd = (dap_cli_cmd_t*) l_cmd->hh.next;
        }
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Available commands:\n\n%s\n",
                l_help_list_str->len ? l_help_list_str->str : "NO ANY COMMAND WERE DEFINED");
        dap_string_free(l_help_list_str, true);
        return 0;
    }
}

static void s_wallet_list(const char *a_wallet_path, json_object *a_json_arr_out, dap_chain_addr_t *a_addr){
    if (!a_wallet_path || !a_json_arr_out)
        return;
    const char *l_addr_str = NULL;
    dap_chain_addr_t * l_addr = NULL;
    DIR * l_dir = opendir(a_wallet_path);
    if(l_dir) {
        struct dirent * l_dir_entry = NULL;
        while( (l_dir_entry = readdir(l_dir)) ) {
            if (dap_strcmp(l_dir_entry->d_name, "..") == 0 || dap_strcmp(l_dir_entry->d_name, ".") == 0)
                continue;
            const char *l_file_name = l_dir_entry->d_name;
            size_t l_file_name_len = (l_file_name) ? strlen(l_file_name) : 0;
            unsigned int res = 0;
            json_object * json_obj_wall = json_object_new_object();
            if (!json_obj_wall)
                return;
            if ( (l_file_name_len > 8) && (!strcmp(l_file_name + l_file_name_len - 8, ".dwallet")) ) {
                char l_file_path_tmp[MAX_PATH] = {0};
                snprintf(l_file_path_tmp, sizeof(l_file_path_tmp) - 1, "%s/%s", a_wallet_path, l_file_name);
                dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_file_name, a_wallet_path, &res);

                if (l_wallet) {
                    if (a_addr) {
                        l_addr = dap_chain_wallet_get_addr(l_wallet, a_addr->net_id);
                        if (l_addr && dap_chain_addr_compare(l_addr, a_addr)) {
                            json_object_object_add(json_obj_wall, "wallet", json_object_new_string(l_file_name));
                            if(l_wallet->flags & DAP_WALLET$M_FL_ACTIVE)
                                json_object_object_add(json_obj_wall, "status", json_object_new_string("protected-active"));
                            else
                                json_object_object_add(json_obj_wall, "status", json_object_new_string("unprotected"));
                            json_object_object_add(json_obj_wall, "deprecated", json_object_new_string(
                                                        strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ? "true" : "false"));
                        }
                        else {
                            json_object_put(json_obj_wall);
                            dap_chain_wallet_close(l_wallet);
                            DAP_DEL_Z(l_addr);
                            continue;
                        }
                        DAP_DEL_Z(l_addr);
                        dap_chain_wallet_close(l_wallet);
                        json_object_array_add(a_json_arr_out, json_obj_wall);
                        break;
                    }
                    //l_addr = l_net ? dap_chain_wallet_get_addr(l_wallet, l_net->pub.id) : NULL;
                    // const char *l_addr_str = dap_chain_addr_to_str_static(l_addr);
                    json_object_object_add(json_obj_wall, "Wallet", json_object_new_string(l_file_name));
                    if(l_wallet->flags & DAP_WALLET$M_FL_ACTIVE)
                        json_object_object_add(json_obj_wall, "status", json_object_new_string("protected-active"));
                    else
                        json_object_object_add(json_obj_wall, "status", json_object_new_string("unprotected"));
                    json_object_object_add(json_obj_wall, "deprecated", json_object_new_string(
                            strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ? "true" : "false"));
                    //if (l_addr_str) {
                    //    json_object_object_add(json_obj_wall, "addr", json_object_new_string(l_addr_str));
                    // }
                    dap_chain_wallet_close(l_wallet);
                } else if (!a_addr){
                    json_object_object_add(json_obj_wall, "Wallet", json_object_new_string(l_file_name));
                    if(res==4)json_object_object_add(json_obj_wall, "status", json_object_new_string("protected-inactive"));
                    else if(res != 0)json_object_object_add(json_obj_wall, "status", json_object_new_string("invalid"));
                }
            } else if (a_addr) {
                json_object_put(json_obj_wall);
                continue;
            } else if ((l_file_name_len > 7) && (!strcmp(l_file_name + l_file_name_len - 7, ".backup"))) {
                json_object_object_add(json_obj_wall, "Wallet", json_object_new_string(l_file_name));
                json_object_object_add(json_obj_wall, "status", json_object_new_string("Backup"));
            }
            if (json_object_object_length(json_obj_wall)) 
                json_object_array_add(a_json_arr_out, json_obj_wall);
            else 
                json_object_put(json_obj_wall);
        }
        if (a_addr && (json_object_array_length(a_json_arr_out) == 0)) {
            json_object * json_obj_out = json_object_new_object();
            if (!json_obj_out) return;
            json_object_object_add(json_obj_out, "status", json_object_new_string("not found"));
            json_object_array_add(a_json_arr_out, json_obj_out);
        }
        closedir(l_dir);
    }
}

/**
 * @brief com_tx_wallet
 * Wallet info
 * com_tx_create command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_wallet(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    enum { CMD_NONE, CMD_WALLET_NEW, CMD_WALLET_LIST, CMD_WALLET_INFO, CMD_WALLET_ACTIVATE, CMD_WALLET_DEACTIVATE, CMD_WALLET_CONVERT, CMD_WALLET_OUTPUTS, CMD_WALLET_FIND };
    int l_arg_index = 1, l_rc, cmd_num = CMD_NONE;

    // find  add parameter ('alias' or 'handshake')
    if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "new", NULL))
        cmd_num = CMD_WALLET_NEW;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "list", NULL))
        cmd_num = CMD_WALLET_LIST;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "info", NULL))
        cmd_num = CMD_WALLET_INFO;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "activate", NULL))
        cmd_num = CMD_WALLET_ACTIVATE;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "deactivate", NULL))
        cmd_num = CMD_WALLET_DEACTIVATE;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "convert", NULL))
        cmd_num = CMD_WALLET_CONVERT;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "outputs", NULL))
        cmd_num = CMD_WALLET_OUTPUTS;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "find", NULL))
        cmd_num = CMD_WALLET_FIND;

    l_arg_index++;

    if(cmd_num == CMD_NONE) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
                "Format of command: wallet {new -w <wallet_name> | list | info [-addr <addr>]|[-w <wallet_name> -net <net_name>]}");
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR;        
    }

    const char *l_addr_str = NULL, *l_wallet_name = NULL, *l_net_name = NULL, *l_sign_type_str = NULL, *l_restore_str = NULL,
            *l_pass_str = NULL, *l_ttl_str = NULL, *l_file_path = NULL;

    // find wallet addr
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-password", &l_pass_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-sign", &l_sign_type_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-file", &l_file_path);

    // Check if wallet name has only digits and English letter
    if (l_wallet_name && !dap_isstralnum(l_wallet_name)){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
        "Wallet name must contains digits and aplhabetical symbols");
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    dap_chain_wallet_t *l_wallet = NULL;
    dap_chain_addr_t *l_addr = NULL;

    if(l_net_name && !l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
        "Not found net by name '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
    }
    json_object * json_obj_out = NULL;
    json_object * json_arr_out = json_object_new_array();
    if (!json_arr_out) {
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR;
    }
    switch (cmd_num) {
        // wallet list
        case CMD_WALLET_LIST:
            s_wallet_list(c_wallets_path, json_arr_out, NULL);
            if (json_object_array_length(json_arr_out) == 0) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR,
                    "Сouldn't find any wallets");
            }
            break;
        // wallet info
        case CMD_WALLET_INFO: {
            dap_ledger_t *l_ledger = NULL;
            if ((l_wallet_name && l_addr_str) || (!l_wallet_name && !l_addr_str)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
                "You should use either the -w or -addr option for the wallet info command.");
                json_object_put(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
            }
            if(l_wallet_name) {
                if(!l_net) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                           "Subcommand info requires parameter '-net'");
                    json_object_put(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
                l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
                l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id );
            } else {
                l_addr = dap_chain_addr_from_str(l_addr_str);
            }
            
            if (!l_addr || dap_chain_addr_is_blank(l_addr)){
                if (l_wallet) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CAN_NOT_GET_ADDR,
                                           "Wallet %s contains an unknown certificate type, the wallet address could not be calculated.", l_wallet_name);
                    dap_chain_wallet_close(l_wallet);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CAN_NOT_GET_ADDR;
                }
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR,
                                       "Wallet not found or addr not recognized");
                json_object_put(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR;
            } else {
                l_net = dap_chain_net_by_id(l_addr->net_id);
                if (l_net) {
                    l_ledger = l_net->pub.ledger;
                    l_net_name = l_net->pub.name;
                } else {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_ERR,
                                           "Can't find network id 0x%016"DAP_UINT64_FORMAT_X" from address %s",
                                           l_addr->net_id.uint64, l_addr_str);
                    json_object_put(json_arr_out);
                    DAP_DELETE(l_addr);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_ERR;
                }
            }
            json_object * json_obj_wall = json_object_new_object();
            const char *l_addr_str = dap_chain_addr_to_str_static((dap_chain_addr_t*) l_addr);
            if(l_wallet)
            {
                json_object_object_add(json_obj_wall, "sign", json_object_new_string(
                                                                  strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ?
                                                                  dap_chain_wallet_check_sign(l_wallet) : "correct"));
                json_object_object_add(json_obj_wall, "wallet", json_object_new_string(l_wallet->name));
            }
            json_object_object_add(json_obj_wall, "addr", l_addr_str ? json_object_new_string(l_addr_str) : json_object_new_string("-"));
            json_object_object_add(json_obj_wall, "network", l_net_name? json_object_new_string(l_net_name) : json_object_new_string("-"));

            size_t l_l_addr_tokens_size = 0;
            char **l_l_addr_tokens = NULL;
            dap_ledger_addr_get_token_ticker_all(l_ledger, l_addr, &l_l_addr_tokens, &l_l_addr_tokens_size);
            if (l_wallet) {
                //Get sign for wallet
                json_object *l_jobj_sings = NULL;
                dap_chain_wallet_internal_t *l_w_internal = DAP_CHAIN_WALLET_INTERNAL(l_wallet);
                if (l_w_internal->certs_count == 1) {
                    l_jobj_sings = json_object_new_string(
                        dap_sign_type_to_str(
                            dap_sign_type_from_key_type(l_w_internal->certs[0]->enc_key->type)));
                } else {
                    dap_string_t *l_str_signs = dap_string_new("");
                    for (size_t i = 0; i < l_w_internal->certs_count; i++) {
                        dap_string_append_printf(l_str_signs, "%s%s",
                                                 dap_sign_type_to_str(dap_sign_type_from_key_type(
                                                     l_w_internal->certs[i]->enc_key->type)),
                                                 ((i + 1) == l_w_internal->certs_count) ? "" : ", ");
                    }
                    l_jobj_sings = json_object_new_string(l_str_signs->str);
                    dap_string_free(l_str_signs, true);
                }
                json_object_object_add(json_obj_wall, "signs", l_jobj_sings);
            } else {
                json_object_object_add(json_obj_wall, "signs",
                                       json_object_new_string(dap_sign_type_to_str(l_addr->sig_type)));
            }
            if(l_l_addr_tokens_size <= 0)
                json_object_object_add(json_obj_wall, "balance", json_object_new_string("0"));
            json_object * j_arr_balance= json_object_new_array();
            for(size_t i = 0; i < l_l_addr_tokens_size; i++) {
                if(l_l_addr_tokens[i]) {
                    json_object * j_balance_data = json_object_new_object();
                    uint256_t l_balance = dap_ledger_calc_balance(l_ledger, l_addr, l_l_addr_tokens[i]);
                    const char *l_balance_coins, *l_balance_datoshi = dap_uint256_to_char(l_balance, &l_balance_coins);
                    json_object *l_jobj_token = json_object_new_object();
                    json_object *l_jobj_ticker = json_object_new_string(l_l_addr_tokens[i]);
                    const char *l_description =  dap_ledger_get_description_by_ticker(l_ledger, l_l_addr_tokens[i]);
                    json_object *l_jobj_description = l_description ? json_object_new_string(l_description)
                                                                    : json_object_new_null();
                    json_object_object_add(l_jobj_token, "ticker", l_jobj_ticker);
                    json_object_object_add(l_jobj_token, "description", l_jobj_description);
                    json_object_object_add(j_balance_data, "balance", json_object_new_string(""));
                    json_object_object_add(j_balance_data, "coins", json_object_new_string(l_balance_coins));
                    json_object_object_add(j_balance_data, "datoshi", json_object_new_string(l_balance_datoshi));
                    json_object_object_add(j_balance_data, "token", l_jobj_token);
                    json_object_array_add(j_arr_balance, j_balance_data);
                }
                DAP_DELETE(l_l_addr_tokens[i]);
            }
            json_object_object_add(json_obj_wall, "tokens", j_arr_balance);
            json_object_array_add(json_arr_out, json_obj_wall);
            DAP_DELETE(l_l_addr_tokens);
            DAP_DELETE(l_addr);

            if(l_wallet)
                dap_chain_wallet_close(l_wallet);
            break;
        }
        case CMD_WALLET_OUTPUTS: {
            if ((l_wallet_name && l_addr_str) || (!l_wallet_name && !l_addr_str)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
                "You should use either the -w or -addr option for the wallet info command.");
                json_object_put(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
            }
            if(l_wallet_name) {
                if(!l_net) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                            "Subcommand info requires parameter '-net'");
                    json_object_put(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
                l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
                if (!l_wallet){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                           "Can't find wallet (%s)", l_wallet_name);
                    json_object_put(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
                l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id );
                if (!l_addr){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                           "Can't get addr from wallet (%s)", l_wallet_name);
                    json_object_put(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
            } else {
                l_addr = dap_chain_addr_from_str(l_addr_str);
                if (!l_net)
                    l_net = dap_chain_net_by_id(l_addr->net_id);
                
                if(!l_net) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                            "Can't get net from wallet addr");
                    json_object_put(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
            }

            const char* l_token_tiker = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_tiker);
            if (!l_token_tiker){
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
                                           "Subcommand outputs requires parameter '-token'");
                    json_object_put(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR;
            }
            json_object * json_obj_wall = json_object_new_object();
            const char* l_value_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);

            dap_list_t *l_outs_list = NULL;

            uint256_t l_value_sum = uint256_0;
            if (l_value_str){
                uint256_t l_value_datoshi = dap_chain_balance_scan(l_value_str);
                l_outs_list = dap_chain_wallet_get_list_tx_outs_with_val(l_net->pub.ledger, l_token_tiker, l_addr, l_value_datoshi, &l_value_sum);
            } else {
                if (dap_chain_wallet_cache_tx_find_outs(l_net, l_token_tiker, l_addr, &l_outs_list, &l_value_sum))
                    l_outs_list = dap_ledger_get_list_tx_outs(l_net->pub.ledger, l_token_tiker, l_addr, &l_value_sum);
            }

            json_object_object_add(json_obj_wall, "wallet_addr", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
            const char *l_out_total_value_str = dap_chain_balance_datoshi_print(l_value_sum);
            const char *l_out_total_value_coins_str = dap_chain_balance_coins_print(l_value_sum);
            json_object_object_add(json_obj_wall, "total_value_coins", json_object_new_string(l_out_total_value_coins_str));
            json_object_object_add(json_obj_wall, "total_value_datoshi", json_object_new_string(l_out_total_value_str));
            DAP_DEL_Z(l_out_total_value_str);
            DAP_DEL_Z(l_out_total_value_coins_str);
            struct json_object *l_json_outs_arr = json_object_new_array();
            for (dap_list_t *l_temp = l_outs_list; l_temp; l_temp = l_temp->next){
                dap_chain_tx_used_out_item_t *l_item = l_temp->data;
                json_object* json_obj_item = json_object_new_object();
                const char *l_out_value_str = dap_chain_balance_datoshi_print(l_item->value);
                const char *l_out_value_coins_str = dap_chain_balance_coins_print(l_item->value);
                json_object_object_add(json_obj_item,"item_type", json_object_new_string("unspent_out"));
                json_object_object_add(json_obj_item,"value_coins", json_object_new_string(l_out_value_coins_str));
                json_object_object_add(json_obj_item,"value_datosi", json_object_new_string(l_out_value_str));
                json_object_object_add(json_obj_item,"prev_hash", json_object_new_string(dap_hash_fast_to_str_static(&l_item->tx_hash_fast)));  
                json_object_object_add(json_obj_item,"out_prev_idx", json_object_new_int64(l_item->num_idx_out));   
                json_object_array_add(l_json_outs_arr, json_obj_item);
                DAP_DEL_Z(l_out_value_str);
                DAP_DEL_Z(l_out_value_coins_str);
            }
            dap_list_free_full(l_outs_list, NULL);
            json_object_object_add(json_obj_wall, "outs", l_json_outs_arr);
            json_object_array_add(json_arr_out, json_obj_wall);
        } break;
        case CMD_WALLET_FIND: {
            if (l_addr_str) {
                l_addr = dap_chain_addr_from_str(l_addr_str);
                if (l_addr) {
                    if (l_file_path)
                        s_wallet_list(l_file_path, json_arr_out, l_addr);
                    else 
                        s_wallet_list(c_wallets_path, json_arr_out, l_addr);
                }                    
                else {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR,
                        "addr not recognized");
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR;
                }
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR,
                                                "You should use -addr option for the wallet find command.");
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR;
            }           
        } break;
        default: {
            if( !l_wallet_name ) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
                                       "Wallet name option <-w>  not defined");
                json_object_put(json_arr_out);
                return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
            }
            if( cmd_num != CMD_WALLET_DEACTIVATE && !l_pass_str && cmd_num != CMD_WALLET_NEW && cmd_num != CMD_WALLET_CONVERT ) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                       "Wallet password option <-password>  not defined");
                json_object_put(json_arr_out);
                return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR;
            }
            if ( cmd_num != CMD_WALLET_DEACTIVATE && l_pass_str && DAP_WALLET$SZ_PASS < strnlen(l_pass_str, DAP_WALLET$SZ_PASS + 1) ) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_TO_LONG_ERR,
                                       "Wallet's password is too long ( > %d)", DAP_WALLET$SZ_PASS);
                log_it(L_ERROR, "Wallet's password is too long ( > %d)", DAP_WALLET$SZ_PASS);
                json_object_put(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_TO_LONG_ERR;
            }
            switch (cmd_num) {
                case CMD_WALLET_ACTIVATE:
                case CMD_WALLET_DEACTIVATE: {
                    json_object * json_obj_wall = json_object_new_object();
                    const char *l_prefix = cmd_num == CMD_WALLET_ACTIVATE ? "" : "de";
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-ttl", &l_ttl_str);
                    l_rc = l_ttl_str ? strtoul(l_ttl_str, NULL, 10) : 60;

                    l_rc = cmd_num == CMD_WALLET_ACTIVATE
                            ? dap_chain_wallet_activate(l_wallet_name, strlen(l_wallet_name), NULL, l_pass_str, strlen(l_pass_str), l_rc)
                            : dap_chain_wallet_deactivate (l_wallet_name, strlen(l_wallet_name));

                    switch (l_rc) {
                    case 0:
                        json_object_object_add(json_obj_wall, "wallet_name", json_object_new_string(l_wallet_name));
                        json_object_object_add(json_obj_wall, "protection", cmd_num == CMD_WALLET_ACTIVATE ?
                        json_object_new_string("is activated") : json_object_new_string("is deactivated"));
                        // Notify about wallet
                        s_new_wallet_info_notify(l_wallet_name);
                        struct json_object *l_json_wallets = wallet_list_json_collect();
                        dap_notify_server_send(json_object_get_string(l_json_wallets));
                        json_object_put(l_json_wallets);
                        break;
                    case -EBUSY:
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR,
                                               "Error: wallet %s is already %sactivated\n", l_wallet_name, l_prefix);
                        break;
                    case -EAGAIN:
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                "Wrong password for wallet %s\n", l_wallet_name);
                        break;
                    case -101:
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                "Can't active unprotected wallet: %s\n", l_wallet_name);
                        break;
                    default: {
                        char l_buf[512] = { '\0' };
                        strerror_r(l_rc, l_buf, sizeof(l_buf) - 1);
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ACTIVE_ERR,
                                "Wallet %s %sactivation error %d : %s\n", l_wallet_name, l_prefix, l_rc, l_buf);
                        break;
                    }
                    }
                    json_object_array_add(json_arr_out, json_obj_wall);
                } break;
                // convert wallet
                case CMD_WALLET_CONVERT: {
                    bool l_remove_password = false;
                    if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-remove_password", NULL))
                        l_remove_password = true;
                    l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
                    if (!l_wallet) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                               "Can't open wallet");
                        json_object_put(json_arr_out);
                        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR;
                    } else if (l_wallet->flags & DAP_WALLET$M_FL_ACTIVE && !l_remove_password) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR,
                                               "Wallet can't be converted twice");
                        json_object_put(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR;
                    }
                    if (l_pass_str && !dap_check_valid_password(l_pass_str, dap_strlen(l_pass_str))) {
                        dap_json_rpc_error_add(*a_json_arr_reply,
                                               DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD,
                                               "Invalid characters used for password.");
                        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD;
                    }
                    // create wallet backup 
                    dap_chain_wallet_internal_t* l_file_name = DAP_CHAIN_WALLET_INTERNAL(l_wallet);
                    snprintf(l_file_name->file_name, sizeof(l_file_name->file_name), "%s/%s_%012lu%s", c_wallets_path, l_wallet_name, time(NULL),".backup");
                    if ( dap_chain_wallet_save(l_wallet, NULL) ) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR,
                                               "Can't create backup wallet file because of internal error");
                        json_object_put(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR;
                    }
                    if (l_remove_password) {  
                        if (dap_chain_wallet_deactivate(l_wallet_name, strlen(l_wallet_name))){
                            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR,
                                                "Can't deactivate wallet");
                            json_object_put(json_arr_out);
                            return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_DEACT_ERR;
                        }
                    } else if (!l_pass_str) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                       "Wallet password option <-password>  not defined");
                        json_object_put(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR;
                    }
                    // change to old filename
                    snprintf(l_file_name->file_name, sizeof(l_file_name->file_name), "%s/%s%s", c_wallets_path, l_wallet_name, ".dwallet");
                    if ( dap_chain_wallet_save(l_wallet, l_remove_password ? NULL : l_pass_str) ) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR,
                                               "Wallet is not converted because of internal error");
                        json_object_put(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR;
                    }
                    json_object * json_obj_wall = json_object_new_object();
                    log_it(L_INFO, "Wallet %s has been converted", l_wallet_name);
                    json_object_object_add(json_obj_wall, "sign_wallet", json_object_new_string(
                                                                              strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ?
                                                                              dap_chain_wallet_check_sign(l_wallet) : "correct"));
                    json_object_object_add(json_obj_wall, "wallet_name", json_object_new_string(l_wallet_name));
                    json_object_object_add(json_obj_wall, "status", json_object_new_string("successfully converted"));
                    dap_chain_wallet_close(l_wallet);
                    json_object_array_add(json_arr_out, json_obj_wall);
                    break;
                }
                // new wallet
                case CMD_WALLET_NEW: {
                    int l_restore_opt = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-restore", &l_restore_str);
                    int l_restore_legacy_opt = 0;
                    if (!l_restore_str)
                        l_restore_legacy_opt = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-restore_legacy", &l_restore_str);
                    // rewrite existing wallet
                    int l_is_force = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-force", NULL);

                    // check wallet existence
                    if (!l_is_force) {
                        char *l_file_name = dap_strdup_printf("%s/%s.dwallet", c_wallets_path, l_wallet_name);
                        FILE *l_exists = fopen(l_file_name, "rb");
                        DAP_DELETE(l_file_name);
                        if (l_exists) {
                            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR,"Wallet %s already exists",l_wallet_name);
                            fclose(l_exists);
                            json_object_put(json_arr_out);
                            return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR;
                        }
                    }

                    dap_sign_type_t l_sign_types[MAX_ENC_KEYS_IN_MULTYSIGN] = {0};
                    size_t l_sign_count = 0;
                    if (!l_sign_type_str) {
                        l_sign_types[0].type = SIG_TYPE_DILITHIUM;
                        l_sign_type_str = dap_sign_type_to_str(l_sign_types[0]);
                        l_sign_count = 1;
                    } else {
                        l_sign_types[0] = dap_sign_type_from_str(l_sign_type_str);
                        if (l_sign_types[0].type == SIG_TYPE_NULL){
                            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                   "'%s' unknown signature type, please use:\n%s",
                                                   l_sign_type_str, dap_sign_get_str_recommended_types());
                            json_object_put(json_arr_out);
                            return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR;
                        }
                        if (l_sign_types[0].type == SIG_TYPE_MULTI_CHAINED) {
                            int l_sign_index = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, l_sign_type_str, NULL);
                            l_sign_index++;
                            for (;l_sign_index && l_sign_index < a_argc; ++l_sign_index) {
                                l_sign_types[l_sign_count] = dap_sign_type_from_str(a_argv[l_sign_index]);
                                if (l_sign_types[l_sign_count].type == SIG_TYPE_NULL ||
                                    l_sign_types[l_sign_count].type == SIG_TYPE_MULTI_CHAINED) {
                                    break;
                                }
                                l_sign_count++;
                            }
                            if (l_sign_count < 2) {
                                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                      "You did not specify an additional signature after "
                                                      "sig_multi_chained. You must specify at least two more "
                                                      "signatures other than sig_multi_chained.\n"
                                                      "After sig_multi_chained, you must specify two more signatures "
                                                      "from the list:\n%s", dap_cert_get_str_recommended_sign());
                                json_object_put(json_arr_out);
                                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR;
                            }
                        } else {
                            l_sign_count = 1;
                        }
                    }
                    // Check unsupported tesla and bliss algorithm

                    for (size_t i = 0; i < l_sign_count; ++i) {
                        if (dap_sign_type_is_depricated(l_sign_types[i])) {
                            if (l_restore_opt || l_restore_legacy_opt) {
                                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                   "CAUTION!!! CAUTION!!! CAUTION!!!\nThe Bliss, Tesla and Picnic signatures are deprecated. We recommend you to create a new wallet with another available signature and transfer funds there.\n");
                                break;
                            } else {
                                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                   "This signature algorithm is no longer supported, please, use another variant");
                                json_object_put(json_arr_out);
                                return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR;
                            }
                        }
                    }

                    uint8_t *l_seed = NULL;
                    size_t l_seed_size = 0, l_restore_str_size = dap_strlen(l_restore_str);

                    if(l_restore_opt || l_restore_legacy_opt) {
                        if (l_restore_str_size > 3 && !dap_strncmp(l_restore_str, "0x", 2) && (!dap_is_hex_string(l_restore_str + 2, l_restore_str_size - 2) || l_restore_legacy_opt)) {
                            l_seed_size = (l_restore_str_size - 2) / 2;
                            l_seed = DAP_NEW_Z_SIZE(uint8_t, l_seed_size + 1);
                            if(!l_seed) {
                                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                                json_object_put(json_arr_out);
                                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR;
                            }
                            dap_hex2bin(l_seed, l_restore_str + 2, l_restore_str_size - 2);
                            if (l_restore_legacy_opt) {
                                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PROTECTION_ERR,
                                                       "CAUTION!!! CAUTION!!! CAUTION!!!\nYour wallet has a low level of protection. Please create a new wallet again with the option -restore\n");
                            }
                        } else {
                            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_HASH_ERR,
                                                   "Restored hash is invalid or too short, wallet is not created. Please use -restore 0x<hex_value> or -restore_legacy 0x<restore_string>");
                            json_object_put(json_arr_out);
                            return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_HASH_ERR;
                        }
                    }
                    // Checking that if a password is set, it contains only Latin characters, numbers and special characters, except for spaces.
                    if (l_pass_str && !dap_check_valid_password(l_pass_str, dap_strlen(l_pass_str))) {
                        dap_json_rpc_error_add(*a_json_arr_reply,
                                               DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD,
                                               "Invalid characters used for password.");
                        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD;
                    }

                    // Creates new wallet
                    l_wallet = dap_chain_wallet_create_with_seed_multi(l_wallet_name, c_wallets_path, l_sign_types, l_sign_count,
                            l_seed, l_seed_size, l_pass_str);
                    DAP_DELETE(l_seed);
                    if (!l_wallet) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INTERNAL_ERR,
                                               "Wallet is not created because of internal error. Check name or password length (max 64 chars)");
                        json_object_put(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INTERNAL_ERR;
                    }

                    json_object * json_obj_wall = json_object_new_object();
                    json_object_object_add(json_obj_wall, "wallet_name", json_object_new_string(l_wallet->name));
                    if (l_sign_count > 1) {
                        dap_string_t *l_signs_types_str = dap_string_new("sig_multi_chained, ");
                        for (size_t i = 0; i < l_sign_count; i++) {
                            dap_string_append_printf(l_signs_types_str, "%s%s",
                                                     dap_sign_type_to_str(l_sign_types[i]), (i+1) == l_sign_count ? "": ", ");
                        }
                        json_object_object_add(json_obj_wall, "sign_type", json_object_new_string(l_signs_types_str->str));
                        dap_string_free(l_signs_types_str, true);
                    } else
                        json_object_object_add(json_obj_wall, "sign_type", json_object_new_string(l_sign_type_str));
                    json_object_object_add(json_obj_wall, "status", json_object_new_string("successfully created"));

                    dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
                    if (l_net && l_addr)
                        json_object_object_add(json_obj_wall, "new_address", json_object_new_string(dap_chain_addr_to_str_static(l_addr)));
                    DAP_DEL_Z(l_addr);
                    json_object_array_add(json_arr_out, json_obj_wall);
                    dap_chain_wallet_close(l_wallet);
                    // Notify about wallet
                    s_new_wallet_info_notify(l_wallet_name);
                    struct json_object *l_json_wallets = wallet_list_json_collect();
                    dap_notify_server_send(json_object_get_string(l_json_wallets));
                    json_object_put(l_json_wallets);
                    break;
                }
            }
        }
    }

    if (json_arr_out) {
            json_object_array_add(*a_json_arr_reply, json_arr_out);
        } else {
            json_object_array_add(*a_json_arr_reply, json_object_new_string("empty"));
        }
    return 0;
}

/**
 * @brief s_values_parse_net_chain
 * @param argc
 * @param argv
 * @param str_reply
 * @param l_chain
 * @param l_net
 * @return
 */
int dap_chain_node_cli_cmd_values_parse_net_chain(int *a_arg_index, int a_argc, char **a_argv, void **a_str_reply,
        dap_chain_t **a_chain, dap_chain_net_t **a_net, dap_chain_type_t a_default_chain_type)
{
    const char *l_chain_str = NULL, *l_net_str = NULL;

    // Net name
    if(a_net)
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-net", &l_net_str);
    else
        return -100;

    // Select network
    if(!l_net_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-net'", a_argv[0]);
        return -101;
    }

    if(! (*a_net = dap_chain_net_by_name(l_net_str)) ) { // Can't find such network
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s can't find network \"%s\"", a_argv[0], l_net_str);
        return -102;
    }

    // Chain name
    if(a_chain) {
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-chain", &l_chain_str);

        // Select chain
        if(l_chain_str) {
            if ((*a_chain = dap_chain_net_get_chain_by_name(*a_net, l_chain_str)) == NULL) { // Can't find such chain
                dap_string_t *l_reply = dap_string_new("");
                    dap_string_append_printf(l_reply, "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                                      "Available chains:",
                                                      l_chain_str, l_net_str);
                    dap_chain_t *l_chain;
                    DL_FOREACH((*a_net)->pub.chains, l_chain) {
                        dap_string_append_printf(l_reply, "\n\t%s", l_chain->name);
                    }
                    char *l_str_reply = dap_string_free(l_reply, false);
                    return dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_reply), DAP_DELETE(l_str_reply), -103;
            }
        } else if (a_default_chain_type != CHAIN_TYPE_INVALID) {
            if ((*a_chain = dap_chain_net_get_default_chain_by_chain_type(*a_net, a_default_chain_type)) != NULL) {
                return 0;
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Unable to get the default chain of type %s for the network.",
                                                  dap_chain_type_to_str(a_default_chain_type));
                return -104;
            }
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-chain'", a_argv[0]);
            return -104;
        }
    }
    return 0;
}

/**
 * @brief s_com_mempool_list_print_for_chain
 *
 * @param a_net
 * @param a_chain
 * @param a_str_tmp
 * @param a_hash_out_type
 */
void s_com_mempool_list_print_for_chain(json_object* a_json_arr_reply, dap_chain_net_t * a_net, dap_chain_t * a_chain, const char * a_add,
                                        json_object *a_json_obj, const char *a_hash_out_type, bool a_fast, size_t a_limit, size_t a_offset) {
    dap_chain_addr_t *l_wallet_addr = dap_chain_addr_from_str(a_add);
    if (a_add && !l_wallet_addr) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_CONVERT_BASE58_TO_ADDR_WALLET, "Cannot convert "
                                                                                                 "string '%s' to binary address.\n", a_add);
        return;
    }
    if (l_wallet_addr && a_fast) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_FAST_AND_BASE58_ADDR,
                               "In fast mode, it is impossible to count the number of transactions and emissions "
                               "for a specific address. The -brief and -addr options are mutually exclusive.\n");
        DAP_DELETE(l_wallet_addr);
        return;
    }
    char * l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
    if(!l_gdb_group_mempool){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CAN_NOT_GET_MEMPOOL_GROUP,
                               "%s.%s: chain not found\n", a_net->pub.name, a_chain->name);
        return;
    }
    int l_removed = 0;
    json_object *l_obj_chain = json_object_new_object();
    json_object *l_obj_chain_name  = json_object_new_string(a_chain->name);
    if (!l_obj_chain_name || !l_obj_chain) {
        json_object_put(l_obj_chain);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    json_object_object_add(l_obj_chain, "name", l_obj_chain_name);
    dap_chain_mempool_filter(a_chain, &l_removed);
    json_object *l_jobj_removed = json_object_new_int(l_removed);
    if (!l_jobj_removed) {
        json_object_put(l_obj_chain);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    json_object_object_add(l_obj_chain, "removed", l_jobj_removed);
    size_t l_objs_count = 0;
    dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_count);
    json_object  *l_jobj_datums;
    size_t l_offset = a_offset;
    if (l_objs_count == 0 || l_objs_count < l_offset) {
        l_jobj_datums = json_object_new_null();
    } else {
        l_jobj_datums = json_object_new_array();
        if (!l_jobj_datums) {
            json_object_put(l_obj_chain);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }

        size_t l_arr_start = 0;
        if (l_offset) {
            l_arr_start = l_offset;
            json_object *l_jobj_offset = json_object_new_uint64(l_offset);
            json_object_object_add(l_obj_chain, "offset", l_jobj_offset);
        }
        size_t l_arr_end = l_objs_count;
        if (a_limit) {
            l_arr_end = l_offset + a_limit;
            if (l_arr_end > l_objs_count)
                l_arr_end = l_objs_count;
            json_object *l_jobj_limit = json_object_new_uint64(l_arr_end);
            json_object_object_add(l_obj_chain, "limit", l_jobj_limit);
        }
        for (size_t i = l_arr_start; i < l_arr_end; i++) {
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *) l_objs[i].value;
            if (!l_datum->header.data_size || (l_datum->header.data_size > l_objs[i].value_len)) {
                log_it(L_ERROR, "Trash datum in GDB %s.%s, key: %s data_size:%u, value_len:%zu",
                       a_net->pub.name, a_chain->name, l_objs[i].key, l_datum->header.data_size, l_objs[i].value_len);
                dap_global_db_del_sync(l_gdb_group_mempool, l_objs[i].key);
                continue;
            }
            dap_time_t l_ts_create = (dap_time_t) l_datum->header.ts_create;
            const char *l_datum_type = dap_chain_datum_type_id_to_str(l_datum->header.type_id);
            dap_hash_fast_t l_datum_real_hash = {0};
            dap_hash_fast_t l_datum_hash_from_key = {0};
            dap_chain_datum_calc_hash(l_datum, &l_datum_real_hash);
            dap_chain_hash_fast_from_str(l_objs[i].key, &l_datum_hash_from_key);
            char buff_time[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(buff_time, DAP_TIME_STR_SIZE, l_datum->header.ts_create);
            json_object *l_jobj_type = json_object_new_string(l_datum_type);
            json_object *l_jobj_hash = json_object_new_string(l_objs[i].key);
            json_object *l_jobj_ts_created = json_object_new_object();
            json_object *l_jobj_ts_created_time_stamp = json_object_new_uint64(l_ts_create);
            json_object *l_jobj_ts_created_str = json_object_new_string(buff_time);
            if (!l_jobj_type || !l_jobj_hash || !l_jobj_ts_created || !l_jobj_ts_created_str ||
                !l_jobj_ts_created_time_stamp) {
                json_object_put(l_jobj_type);
                json_object_put(l_jobj_hash);
                json_object_put(l_jobj_ts_created);
                json_object_put(l_jobj_ts_created_time_stamp);
                json_object_put(l_jobj_ts_created_str);
                json_object_put(l_jobj_datums);
                json_object_put(l_obj_chain);
                dap_global_db_objs_delete(l_objs, l_objs_count);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return;
            }
            json_object_object_add(l_jobj_ts_created, "time_stamp", l_jobj_ts_created_time_stamp);
            json_object_object_add(l_jobj_ts_created, "str", l_jobj_ts_created_str);
            json_object *l_jobj_datum = json_object_new_object();
            if (!l_jobj_datum) {
                json_object_put(l_jobj_type);
                json_object_put(l_jobj_hash);
                json_object_put(l_jobj_ts_created);
                json_object_put(l_jobj_ts_created_time_stamp);
                json_object_put(l_jobj_ts_created_str);
                json_object_put(l_jobj_datums);
                json_object_put(l_obj_chain);
                dap_global_db_objs_delete(l_objs, l_objs_count);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return;
            }
            if (!dap_hash_fast_compare(&l_datum_real_hash, &l_datum_hash_from_key)) {
                char *l_drh_str = dap_hash_fast_to_str_new(&l_datum_real_hash);
                char *l_wgn = dap_strdup_printf("Key field in DB %s does not match datum's hash %s\n",
                                                l_objs[i].key, l_drh_str);
                DAP_DELETE(l_drh_str);
                if (!l_wgn) {
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    json_object_put(l_jobj_datum);
                    json_object_put(l_obj_chain);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_hash);
                    json_object_put(l_jobj_ts_created);
                    json_object_put(l_jobj_datums);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                json_object *l_jobj_warning = json_object_new_string(l_wgn);
                DAP_DELETE(l_wgn);
                if (!l_jobj_warning) {
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    json_object_put(l_jobj_datum);
                    json_object_put(l_obj_chain);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_hash);
                    json_object_put(l_jobj_ts_created);
                    json_object_put(l_jobj_datums);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                json_object_object_add(l_jobj_datum, "warning", l_jobj_warning);
                json_object_array_add(l_jobj_datums, l_jobj_datum);
                continue;
            }
            json_object_object_add(l_jobj_datum, "hash", l_jobj_hash);
            json_object_object_add(l_jobj_datum, "type", l_jobj_type);
            json_object_object_add(l_jobj_datum, "created", l_jobj_ts_created);
            bool datum_is_accepted_addr = false;
            if (!a_fast) {
                switch (l_datum->header.type_id) {
                    case DAP_CHAIN_DATUM_TX: {
                        dap_chain_addr_t l_addr_from;
                        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *) l_datum->data;

                        int l_ledger_rc = DAP_LEDGER_CHECK_INVALID_ARGS;
                        const char *l_main_ticker = dap_ledger_tx_calculate_main_ticker(a_net->pub.ledger, l_tx,
                                                                                  &l_ledger_rc);
                        const char *l_ledger_rc_str = dap_ledger_check_error_str(l_ledger_rc);

                        json_object *l_jobj_main_ticker = json_object_new_string(
                                l_main_ticker ? l_main_ticker : "UNKNOWN");
                        json_object *l_jobj_ledger_rc = json_object_new_string(l_ledger_rc_str);

                        if (!l_jobj_main_ticker || !l_jobj_ledger_rc) {
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            dap_json_rpc_allocation_error(a_json_arr_reply);
                            return;
                        }

                        json_object_object_add(l_jobj_datum, "main_ticker", l_jobj_main_ticker);
                        json_object_object_add(l_jobj_datum, "ledger_rc", l_jobj_ledger_rc);

                        dap_chain_srv_uid_t uid;
                        char *service_name;
                        dap_chain_tx_tag_action_type_t action;
                        if (dap_ledger_deduct_tx_tag(a_net->pub.ledger, l_tx, &service_name, &uid, &action))
                        {
                            json_object_object_add(l_jobj_datum, "service", json_object_new_string(service_name));
                            json_object_object_add(l_jobj_datum, "action", json_object_new_string(dap_ledger_tx_action_str(action)));
                        }
                        else
                        {   
                            json_object_object_add(l_jobj_datum, "service", json_object_new_string("UNKNOWN"));
                            json_object_object_add(l_jobj_datum, "action", json_object_new_string("UNKNOWN"));
                        }
                        json_object_object_add(l_jobj_datum, "batching", json_object_new_string(!dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true"));

                        dap_list_t *l_list_in_ems = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_EMS, NULL);
                        dap_chain_tx_sig_t *l_sig = (dap_chain_tx_sig_t*)dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                        if (!l_sig) {
                            json_object *l_jobj_wgn = json_object_new_string(
                                    "An item with a type TX_ITEM_TYPE_SIG for the "
                                    "transaction was not found, the transaction may "
                                    "be corrupted.");
                            json_object_object_add(l_jobj_datum, "warning", l_jobj_wgn);
                            break;
                        }
                        dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign(l_sig);
                        dap_chain_addr_fill_from_sign(&l_addr_from, l_sign, a_net->pub.id);
                        if (l_wallet_addr && dap_chain_addr_compare(l_wallet_addr, &l_addr_from)) {
                            datum_is_accepted_addr = true;
                        }
                        dap_list_t *l_list_in_reward = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_REWARD, NULL);
                        if (l_list_in_reward) {
                            /*json_object *l_obj_in_reward_arary = json_object_new_array();
                            if (!l_obj_in_reward_arary) {
                                dap_list_free(l_list_in_reward);
                                json_object_put(l_jobj_datum);
                                json_object_put(l_jobj_datums);
                                json_object_put(l_obj_chain);
                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                dap_json_rpc_allocation_error(*a_json_arr_reply);
                                return;
                            }
                            for (dap_list_t *it = l_list_in_reward; it; it = it->next) {
                                dap_chain_tx_in_reward_t *l_in_reward = (dap_chain_tx_in_reward_t *) it->data;
                                char *l_block_hash = dap_chain_hash_fast_to_str_new(&l_in_reward->block_hash);
                                json_object *l_jobj_block_hash = json_object_new_string(l_block_hash);
                                if (!l_jobj_block_hash) {
                                    DAP_DELETE(l_block_hash);
                                    json_object_put(l_obj_in_reward_arary);
                                    dap_list_free(l_list_in_reward);
                                    json_object_put(l_jobj_datum);
                                    json_object_put(l_jobj_datums);
                                    json_object_put(l_obj_chain);
                                    dap_global_db_objs_delete(l_objs, l_objs_count);
                                    dap_json_rpc_allocation_error(*a_json_arr_reply);
                                    return;
                                }
                                json_object_array_add(l_obj_in_reward_arary, l_jobj_block_hash);
                                DAP_DELETE(l_block_hash);
                            }*/
                           dap_list_free(l_list_in_reward);
                        } else {
                            json_object *l_jobj_addr_from = json_object_new_string(dap_chain_addr_to_str_static(&l_addr_from));
                            if (!l_jobj_addr_from) {
                                json_object_put(l_jobj_datum);
                                json_object_put(l_jobj_datums);
                                json_object_put(l_obj_chain);
                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                dap_json_rpc_allocation_error(a_json_arr_reply);
                                return;
                            }
                            json_object_object_add(l_jobj_datum, "from", l_jobj_addr_from);
                        }
                        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
                        json_object *l_jobj_to_list = json_object_new_array();
                        json_object *l_jobj_change_list = json_object_new_array();
                        json_object *l_jobj_to_from_emi = json_object_new_array();
                        json_object *l_jobj_fee_list = json_object_new_array();
                        json_object *l_jobj_stake_lock_list = json_object_new_array();
                        json_object *l_jobj_xchange_list = json_object_new_array();
                        json_object *l_jobj_stake_pos_delegate_list = json_object_new_array();
                        json_object *l_jobj_pay_list = json_object_new_array();
                        json_object *l_jobj_tx_vote = json_object_new_array();
                        json_object *l_jobj_tx_voting = json_object_new_array();
                        if (!l_jobj_to_list || !l_jobj_change_list || !l_jobj_fee_list || !l_jobj_stake_lock_list ||
                            !l_jobj_xchange_list || !l_jobj_stake_pos_delegate_list || !l_jobj_pay_list) {
                            json_object_put(l_jobj_to_list);
                            json_object_put(l_jobj_change_list);
                            json_object_put(l_jobj_to_from_emi);
                            json_object_put(l_jobj_fee_list);
                            json_object_put(l_jobj_stake_lock_list);
                            json_object_put(l_jobj_xchange_list);
                            json_object_put(l_jobj_stake_pos_delegate_list);
                            json_object_put(l_jobj_pay_list);
                            json_object_put(l_jobj_tx_vote);
                            json_object_put(l_jobj_tx_voting);
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            dap_json_rpc_allocation_error(a_json_arr_reply);
                            return;
                        }
                        enum {
                            OUT_COND_TYPE_UNKNOWN,
                            OUT_COND_TYPE_PAY,
                            OUT_COND_TYPE_FEE,
                            OUT_COND_TYPE_STAKE_LOCK,
                            OUT_COND_TYPE_XCHANGE,
                            OUT_COND_TYPE_POS_DELEGATE
                        } l_out_cond_subtype = {0};
                        dap_list_t *l_vote_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_VOTE, NULL);
                        dap_list_t *l_voting_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_VOTING, NULL);
                        for (dap_list_t *it = l_list_out_items; it; it = it->next) {
                            dap_chain_addr_t *l_dist_addr = NULL;
                            uint256_t l_value = uint256_0;
                            const char *l_dist_token = NULL;
                            uint8_t l_type = *(uint8_t *) it->data;
                            switch (l_type) {
                                case TX_ITEM_TYPE_OUT: {
                                    l_value = ((dap_chain_tx_out_t *) it->data)->header.value;
                                    l_dist_token = l_main_ticker;
                                    l_dist_addr = &((dap_chain_tx_out_t *) it->data)->addr;
                                }
                                    break;
                                case TX_ITEM_TYPE_OUT_EXT: {
                                    l_value = ((dap_chain_tx_out_ext_t *) it->data)->header.value;
                                    l_dist_token = ((dap_chain_tx_out_ext_t *) it->data)->token;
                                    l_dist_addr = &((dap_chain_tx_out_ext_t *) it->data)->addr;
                                }
                                    break;
                                case TX_ITEM_TYPE_OUT_COND: {
                                    dap_chain_tx_out_cond_t *l_out_cond = (dap_chain_tx_out_cond_t *) it->data;
                                    l_value = ((dap_chain_tx_out_cond_t *) it->data)->header.value;
                                    switch (l_out_cond->header.subtype) {
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: {
                                            l_dist_token = a_net->pub.native_ticker;
                                            l_out_cond_subtype = OUT_COND_TYPE_FEE;
                                        }
                                            break;
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                                            l_dist_token = l_main_ticker;
                                            l_out_cond_subtype = OUT_COND_TYPE_STAKE_LOCK;
                                        }
                                            break;
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                                            l_dist_token = l_main_ticker;
                                            l_out_cond_subtype = OUT_COND_TYPE_XCHANGE;
                                        }
                                            break;
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                                            l_dist_token = l_main_ticker;
                                            l_out_cond_subtype = OUT_COND_TYPE_POS_DELEGATE;
                                        }
                                            break;
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                                            l_dist_token = l_main_ticker;
                                            l_out_cond_subtype = OUT_COND_TYPE_PAY;
                                        }
                                            break;
                                        default:
                                            break;
                                    }
                                }
                                    break;
                                default:
                                    break;
                            }
                            json_object *l_jobj_money = json_object_new_object();
                            if (!l_jobj_money) {
                                json_object_put(l_jobj_to_list);
                                json_object_put(l_jobj_change_list);
                                json_object_put(l_jobj_to_from_emi);
                                json_object_put(l_jobj_fee_list);
                                json_object_put(l_jobj_datum);
                                json_object_put(l_jobj_datums);
                                json_object_put(l_obj_chain);
                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                dap_json_rpc_allocation_error(a_json_arr_reply);
                                return;
                            }
                            const char *l_value_coins_str, *l_value_str = dap_uint256_to_char(l_value, &l_value_coins_str);
                            json_object_object_add(l_jobj_money, "value", json_object_new_string(l_value_str));
                            json_object_object_add(l_jobj_money, "coins", json_object_new_string(l_value_coins_str));
                            if (l_dist_token) {
                                json_object *l_jobj_token = json_object_new_string(l_dist_token);
                                if (!l_jobj_token) {
                                    json_object_put(l_jobj_to_list);
                                    json_object_put(l_jobj_change_list);
                                    json_object_put(l_jobj_to_from_emi);
                                    json_object_put(l_jobj_fee_list);
                                    json_object_put(l_jobj_money);
                                    json_object_put(l_jobj_datum);
                                    json_object_put(l_jobj_datums);
                                    json_object_put(l_obj_chain);
                                    dap_global_db_objs_delete(l_objs, l_objs_count);
                                    dap_json_rpc_allocation_error(a_json_arr_reply);
                                    return;
                                }
                                json_object_object_add(l_jobj_money, "token", l_jobj_token);
                            }

                            if (l_dist_addr) {
                                if (!datum_is_accepted_addr && l_wallet_addr) {
                                    datum_is_accepted_addr = dap_chain_addr_compare(l_wallet_addr, l_dist_addr);
                                }
                                json_object *l_jobj_f = json_object_new_object();
                                if (!l_jobj_f) {
                                    json_object_put(l_jobj_to_list);
                                    json_object_put(l_jobj_change_list);
                                    json_object_put(l_jobj_to_from_emi);
                                    json_object_put(l_jobj_fee_list);
                                    json_object_put(l_jobj_money);
                                    json_object_put(l_jobj_datum);
                                    json_object_put(l_jobj_datums);
                                    json_object_put(l_obj_chain);
                                    dap_global_db_objs_delete(l_objs, l_objs_count);
                                    dap_json_rpc_allocation_error(a_json_arr_reply);
                                    return;
                                }
                                json_object_object_add(l_jobj_f, "money", l_jobj_money);
                                if (dap_chain_addr_compare(&l_addr_from, l_dist_addr)) {
                                    bool l_in_from_emi = false;
                                    for (dap_list_t *it_ems = l_list_in_ems; it_ems; it_ems = it_ems->next) {
                                        dap_chain_tx_in_ems_t *l_in_ems = (dap_chain_tx_in_ems_t *) it_ems->data;
                                        if (!dap_strcmp(l_in_ems->header.ticker, l_dist_token)) {
                                            l_in_from_emi = true;
                                            dap_hash_fast_t l_ems_hash = l_in_ems->header.token_emission_hash;
                                            char l_ems_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                                            dap_hash_fast_to_str(&l_ems_hash, l_ems_hash_str,
                                                                 DAP_CHAIN_HASH_FAST_STR_SIZE);
                                            json_object *l_obj_ems_hash = json_object_new_string(l_ems_hash_str);
                                            if (!l_obj_ems_hash) {
                                                json_object_put(l_jobj_to_list);
                                                json_object_put(l_jobj_change_list);
                                                json_object_put(l_jobj_to_from_emi);
                                                json_object_put(l_jobj_fee_list);
                                                json_object_put(l_jobj_money);
                                                json_object_put(l_jobj_datum);
                                                json_object_put(l_jobj_datums);
                                                json_object_put(l_obj_chain);
                                                json_object_put(l_jobj_f);
                                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                                dap_json_rpc_allocation_error(a_json_arr_reply);
                                                return;
                                            }
                                            json_object_object_add(l_jobj_f, "token_emission_hash", l_obj_ems_hash);
                                            break;
                                        }
                                    }
                                    if (l_in_from_emi)
                                        json_object_array_add(l_jobj_to_from_emi, l_jobj_f);
                                    else
                                        json_object_array_add(l_jobj_change_list, l_jobj_f);
                                } else {
                                    json_object_object_add(l_jobj_f, "addr", json_object_new_string(dap_chain_addr_to_str_static(l_dist_addr)));
                                    json_object_array_add(l_jobj_to_list, l_jobj_f);
                                }
                            } else {
                                switch (l_out_cond_subtype) {
                                    case OUT_COND_TYPE_PAY:
                                        json_object_array_add(l_jobj_pay_list, l_jobj_money);
                                        break;
                                    case OUT_COND_TYPE_FEE:
                                        json_object_array_add(l_jobj_fee_list, l_jobj_money);
                                        break;
                                    case OUT_COND_TYPE_STAKE_LOCK:
                                        json_object_array_add(l_jobj_stake_lock_list, l_jobj_money);
                                        break;
                                    case OUT_COND_TYPE_XCHANGE:
                                        json_object_array_add(l_jobj_xchange_list, l_jobj_money);
                                        break;
                                    case OUT_COND_TYPE_POS_DELEGATE:
                                        json_object_array_add(l_jobj_stake_pos_delegate_list, l_jobj_money);
                                        break;
                                    default:
                                        log_it(L_ERROR,
                                               "An unknown subtype output was found in a transaction in the mempool list.");
                                        break;
                                }
                            }
                        }
                        for (dap_list_t *it = l_vote_list; it; it = it->next) {
                            dap_chain_tx_vote_t *l_vote = it->data;
                            json_object *l_jobj_vote = dap_chain_datum_tx_item_vote_to_json(l_vote);
                            dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_vote->voting_hash);
                            char *l_answer_text_str = l_tx ? dap_chain_datum_tx_voting_get_answer_text_by_idx(l_tx, l_vote->answer_idx) : NULL;
                            json_object *l_answer_text = json_object_new_string(l_answer_text_str ? l_answer_text_str : "{UNDEFINED}");
                            DAP_DEL_Z(l_answer_text_str);
                            json_object_object_add(l_jobj_vote, "answer_text", l_answer_text);
                            json_object_array_add(l_jobj_tx_vote, l_jobj_vote);
                        }
                        for (dap_list_t *it = l_voting_list; it; it = it->next) {
                            json_object *l_jobj_voting = dap_chain_datum_tx_item_voting_tsd_to_json(l_tx);
                            json_object_array_add(l_jobj_tx_voting, l_jobj_voting);
                        }
                        json_object_object_add(l_jobj_datum, "to", l_jobj_to_list);
                        json_object_object_add(l_jobj_datum, "change", l_jobj_change_list);
                        json_object_object_add(l_jobj_datum, "fee", l_jobj_fee_list);
                        json_object_array_length(l_jobj_pay_list) > 0 ?
                        json_object_object_add(l_jobj_datum, "srv_pay", l_jobj_pay_list) : json_object_put(
                                l_jobj_pay_list);
                        json_object_array_length(l_jobj_xchange_list) > 0 ?
                        json_object_object_add(l_jobj_datum, "srv_xchange", l_jobj_xchange_list) : json_object_put(
                                l_jobj_xchange_list);
                        json_object_array_length(l_jobj_stake_lock_list) > 0 ?
                        json_object_object_add(l_jobj_datum, "srv_stake_lock", l_jobj_stake_lock_list)
                                                                             : json_object_put(l_jobj_stake_lock_list);
                        json_object_array_length(l_jobj_stake_pos_delegate_list) > 0 ?
                        json_object_object_add(l_jobj_datum, "srv_stake_pos_delegate", l_jobj_stake_pos_delegate_list)
                                                                                     : json_object_put(
                                l_jobj_stake_pos_delegate_list);
                        json_object_array_length(l_jobj_to_from_emi) > 0 ?
                        json_object_object_add(l_jobj_datum, "from_emission", l_jobj_to_from_emi) : json_object_put(
                                l_jobj_to_from_emi);
                        json_object_array_length(l_jobj_tx_vote) > 0 ?
                        json_object_object_add(l_jobj_datum, "vote", l_jobj_tx_vote) : json_object_put(l_jobj_tx_vote);
                        json_object_array_length(l_jobj_tx_voting) > 0 ?
                        json_object_object_add(l_jobj_datum, "voting", l_jobj_tx_voting) : json_object_put(
                                l_jobj_tx_voting);
                        dap_list_free(l_list_out_items);
                        dap_list_free(l_vote_list);
                        dap_list_free(l_voting_list);
                    }
                        break;
                    case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
                        size_t l_emi_size = l_datum->header.data_size;
                        dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_read(l_datum->data,
                                                                                                &l_emi_size);
                        if (l_wallet_addr && l_emi && dap_chain_addr_compare(l_wallet_addr, &l_emi->hdr.address))
                            datum_is_accepted_addr = true;
                        DAP_DELETE(l_emi);
                        dap_chain_datum_dump_json(a_json_arr_reply, l_jobj_datum,l_datum,a_hash_out_type,a_net->pub.id, true);
                    }
                        break;
                    default:
                        dap_chain_datum_dump_json(a_json_arr_reply, l_jobj_datum,l_datum,a_hash_out_type,a_net->pub.id, true);
                }
            }
            if (l_wallet_addr) {
                if (datum_is_accepted_addr) {
                    json_object_array_add(l_jobj_datums, l_jobj_datum);
                } else
                    json_object_put(l_jobj_datum);
            } else
                json_object_array_add(l_jobj_datums, l_jobj_datum);
        }
    }

    json_object_object_add(l_obj_chain, "datums", l_jobj_datums);

    dap_global_db_objs_delete(l_objs, l_objs_count);
    char *l_nets_str = dap_strdup_printf("%s.%s: %zu", a_net->pub.name, a_chain->name, l_objs_count);
    json_object *l_object_total = json_object_new_string(l_nets_str);
    DAP_DELETE(l_nets_str);
    if (!l_object_total) {
        json_object_put(l_obj_chain);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    json_object_object_add(l_obj_chain, "total", l_object_total);

    json_object_array_add(a_json_obj, l_obj_chain);
    DAP_DELETE(l_gdb_group_mempool);
}

static int mempool_delete_for_chain(dap_chain_t *a_chain, const char * a_datum_hash_str, json_object **a_json_arr_reply) {
        char * l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
        uint8_t *l_data_tmp = dap_global_db_get_sync(l_gdb_group_mempool, a_datum_hash_str,
                                                     NULL, NULL, NULL);
        if (!l_data_tmp) {
            DAP_DELETE(l_gdb_group_mempool);
            return 1;
        }
        if (dap_global_db_del_sync(l_gdb_group_mempool, a_datum_hash_str) == 0) {
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_data_tmp);
            return 0;
        } else {
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_data_tmp);
            return 2;
        }
}

typedef enum cmd_mempool_delete_err_list{
    COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND
}cmd_mempool_delete_err_list_t;
/**
 * @brief _cmd_mempool_delete
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
int _cmd_mempool_delete(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    if (!a_net || !a_datum_hash) {
        dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT, "Net or datum hash not specified");
        return COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT;
    }
    int res = 0;
    json_object *l_jobj_ret = json_object_new_object();
    json_object *l_jobj_net = json_object_new_string(a_net->pub.name);
    json_object *l_jobj_chain = NULL;
    json_object *l_jobj_datum_hash = json_object_new_string(a_datum_hash);
    if (!a_chain) {
        dap_chain_t * l_chain = s_get_chain_with_datum(a_net, a_datum_hash);
        if (l_chain) {
            res = mempool_delete_for_chain(l_chain, a_datum_hash, a_json_arr_reply);
            l_jobj_chain = json_object_new_string(l_chain->name);
        } else {
            res = 1;
            l_jobj_chain = json_object_new_string("empty chain parameter");
        }
    } else {
        res = mempool_delete_for_chain(a_chain, a_datum_hash, a_json_arr_reply);
        l_jobj_chain = json_object_new_string(a_chain->name);
    }
    json_object_object_add(l_jobj_ret, "net", l_jobj_net);
    json_object_object_add(l_jobj_ret, "chain", l_jobj_chain);
    json_object_object_add(l_jobj_ret, "hash", l_jobj_datum_hash);
    json_object_object_add(l_jobj_ret, "action", json_object_new_string("delete"));
    json_object *l_jobj_ret_code = json_object_new_int(res);
    json_object_object_add(l_jobj_ret, "retCode", l_jobj_ret_code);
    json_object *l_jobj_status = NULL;
    if (!res) {
        l_jobj_status = json_object_new_string("deleted");
    } else if (res == 1) {
        l_jobj_status = json_object_new_string("datum not found");
    } else {
        l_jobj_status = json_object_new_string("datum was found but could not be deleted");
    }
    json_object_object_add(l_jobj_ret, "status", l_jobj_status);
    json_object_array_add(*a_json_arr_reply, l_jobj_ret);
    if (res) {
        return COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND;
    }
    return 0;
}


/**
 * @brief s_com_mempool_check_datum_in_chain
 * @param a_chain
 * @param a_datum_hash_str
 * @return boolean
 */
dap_chain_datum_t *s_com_mempool_check_datum_in_chain(dap_chain_t *a_chain, const char *a_datum_hash_str)
{
    if (!a_datum_hash_str)
        return NULL;
    char *l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
    uint8_t *l_data_tmp = dap_global_db_get_sync(l_gdb_group_mempool, a_datum_hash_str, NULL, NULL, NULL);
    DAP_DELETE(l_gdb_group_mempool);
    return (dap_chain_datum_t *)l_data_tmp;
}

typedef enum cmd_mempool_check_err_list {
    COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_CHAIN = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET,
    COM_MEMPOOL_CHECK_ERR_REQUIRES_DATUM_HASH,
    COM_MEMPOOL_CHECK_ERR_INCORRECT_HASH_STR,
    COM_MEMPOOL_CHECK_ERR_DATUM_NOT_FIND
}cmd_mempool_check_err_list_t;

/**
 * @brief _cmd_mempool_check
 * @param a_net
 * @param a_chain
 * @param a_datum_hash
 * @param a_hash_out_type
 * @param a_str_reply
 * @return int
 */
int _cmd_mempool_check(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, const char *a_hash_out_type, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;

    if (!a_net || !a_datum_hash) {
        dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET, "Error! Both -net <network_name> "
                                                                       "and -datum <data_hash> parameters are required.");
        return COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET;
    }
    dap_chain_datum_t *l_datum = NULL;
    char *l_chain_name = a_chain ? a_chain->name : NULL;
    bool l_found_in_chains = false;
    int l_ret_code = 0;
    dap_hash_fast_t l_atom_hash = {};
    // FIND in chain
    {
        //
        dap_hash_fast_t l_datum_hash;
        if (dap_chain_hash_fast_from_hex_str(a_datum_hash, &l_datum_hash)) {
            dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_CHECK_ERR_INCORRECT_HASH_STR,
                                    "Incorrect hash string %s", a_datum_hash);
            return COM_MEMPOOL_CHECK_ERR_INCORRECT_HASH_STR;
        }
        if (a_chain)
            l_datum = a_chain->callback_datum_find_by_hash(a_chain, &l_datum_hash, &l_atom_hash, &l_ret_code);
        else {
            dap_chain_t *it = NULL;
            DL_FOREACH(a_net->pub.chains, it) {
                l_datum = it->callback_datum_find_by_hash(it, &l_datum_hash, &l_atom_hash, &l_ret_code);
                if (l_datum) {
                    l_chain_name = it->name;
                    break;
                }
            }
        }
        if (l_datum)
            l_found_in_chains = true;
    }
    //  FIND in mempool
    if (!l_found_in_chains) {
        if (a_chain)
            l_datum = s_com_mempool_check_datum_in_chain(a_chain, a_datum_hash);
        else {
            dap_chain_t *it = NULL;
            DL_FOREACH(a_net->pub.chains, it) {
                l_datum = s_com_mempool_check_datum_in_chain(it, a_datum_hash);
                if (l_datum) {
                    l_chain_name = it->name;
                    break;
                }
            }
        }
    }
    json_object *l_jobj_datum = json_object_new_object();
    json_object *l_datum_hash = json_object_new_string(a_datum_hash);
    json_object *l_net_obj = json_object_new_string(a_net->pub.name);
    if (!l_jobj_datum || !l_datum_hash || !l_net_obj){
        json_object_put(l_jobj_datum);
        json_object_put(l_datum_hash);
        json_object_put(l_net_obj);
        dap_json_rpc_allocation_error(*a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object *l_chain_obj;
    if(l_chain_name) {
        l_chain_obj = json_object_new_string(l_chain_name);
        if (!l_chain_obj) {
            json_object_put(l_jobj_datum);
            json_object_put(l_datum_hash);
            json_object_put(l_net_obj);
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
    } else
        l_chain_obj = json_object_new_null();
    json_object_object_add(l_jobj_datum, "hash", l_datum_hash);
    json_object_object_add(l_jobj_datum, "net", l_net_obj);
    json_object_object_add(l_jobj_datum, "chain", l_chain_obj);
    json_object *l_find_bool;
    if (l_datum) {
        l_find_bool = json_object_new_boolean(TRUE);
        json_object *l_find_chain_or_mempool = json_object_new_string(l_found_in_chains ? "chain" : "mempool");
        if (!l_find_chain_or_mempool || !l_find_bool) {
            json_object_put(l_find_chain_or_mempool);
            json_object_put(l_find_bool);
            json_object_put(l_jobj_datum);
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_jobj_datum, "find", l_find_bool);
        json_object_object_add(l_jobj_datum, "source", l_find_chain_or_mempool);
        if (l_found_in_chains) {
            char l_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_atom_hash, l_atom_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            json_object *l_obj_atom = json_object_new_object();
            json_object *l_jobj_atom_hash = json_object_new_string(l_atom_hash_str);
            json_object *l_jobj_atom_err = json_object_new_string(dap_ledger_check_error_str(l_ret_code));
            if (!l_obj_atom || !l_jobj_atom_hash || !l_jobj_atom_err) {
                json_object_put(l_jobj_datum);
                json_object_put(l_obj_atom);
                json_object_put(l_jobj_atom_hash);
                json_object_put(l_jobj_atom_err);
                dap_json_rpc_allocation_error(*a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            json_object_object_add(l_obj_atom, "hash", l_jobj_atom_hash);
            json_object_object_add(l_obj_atom, "ledger_response_code", l_jobj_atom_err);
            json_object_object_add(l_jobj_datum, "atom", l_obj_atom);
        }        

        json_object *l_datum_obj_inf = json_object_new_object();
        dap_chain_datum_dump_json(*a_json_arr_reply, l_datum_obj_inf, l_datum, a_hash_out_type, a_net->pub.id, true);
        if (!l_datum_obj_inf) {
            if (!l_found_in_chains)
                DAP_DELETE(l_datum);
            json_object_put(l_jobj_datum);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_SERIALIZATION_DATUM_TO_JSON,
                                    "Failed to serialize datum to JSON.");
            return DAP_JSON_RPC_ERR_CODE_SERIALIZATION_DATUM_TO_JSON;
        }
        json_object_object_add(l_jobj_datum, "datum", l_datum_obj_inf);
        if (!l_found_in_chains)
            DAP_DELETE(l_datum);
        json_object_array_add(*a_json_arr_reply, l_jobj_datum);
        return 0;
    } else {
        l_find_bool = json_object_new_boolean(FALSE);
        if (!l_find_bool) {
            json_object_put(l_jobj_datum);
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_jobj_datum, "find", l_find_bool);
        json_object_array_add(*a_json_arr_reply, l_jobj_datum);
        return COM_MEMPOOL_CHECK_ERR_DATUM_NOT_FIND;
    }
}

typedef enum cmd_mempool_proc_list_error{
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_GET_DATUM_HASH_FROM_STR,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL

}cmd_mempool_proc_list_error_t;

/**
 * @brief _cmd_mempool_proc
 * process mempool datum
 * @param a_net
 * @param a_chain
 * @param a_datum_hash
 * @param a_str_reply
 * @return
 */
int _cmd_mempool_proc(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    // If full or light it doesnt work
    if(dap_chain_net_get_role(a_net).enums>= NODE_ROLE_FULL){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL,
                               "Need master node role or higher for network %s to process this command", a_net->pub.name);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL;
    }
    dap_chain_t *l_chain = !a_chain ? s_get_chain_with_datum(a_net, a_datum_hash) : a_chain;

    int ret = 0;
    char *l_gdb_group_mempool = dap_chain_mempool_group_new(l_chain);
    if (!l_gdb_group_mempool){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME,
                               "Failed to get mempool group name on network %s", a_net->pub.name);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME;
    }
    size_t l_datum_size=0;

    dap_chain_datum_t * l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(l_gdb_group_mempool, a_datum_hash,
                                                                             &l_datum_size, NULL, NULL );
    size_t l_datum_size2 = l_datum? dap_chain_datum_size( l_datum): 0;
    if (l_datum_size != l_datum_size2) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD, "Error! Corrupted datum %s, size by datum headers is %zd when in mempool is only %zd bytes",
                                            a_datum_hash, l_datum_size2, l_datum_size);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD;
    }
    if (!l_datum) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM,
                               "Error! Can't find datum %s", a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM;
    }
    dap_hash_fast_t l_datum_hash, l_real_hash;
    if (dap_chain_hash_fast_from_hex_str(a_datum_hash, &l_datum_hash)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM,
                               "Error! Can't convert datum hash string %s to digital form",
                               a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM;
    }
    dap_chain_datum_calc_hash(l_datum, &l_real_hash);
    if (!dap_hash_fast_compare(&l_datum_hash, &l_real_hash)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING,
                               "Error! Datum's real hash doesn't match datum's hash string %s",
                               a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING;
    }
    char buf[DAP_TIME_STR_SIZE];
    dap_time_t l_ts_create = (dap_time_t)l_datum->header.ts_create;
    const char *l_type = NULL;
    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type);
    json_object *l_jobj_res = json_object_new_object();
    json_object *l_jobj_datum = json_object_new_object();
    json_object *l_jobj_hash = json_object_new_string(a_datum_hash);
    json_object *l_jobj_type = json_object_new_string(l_type);
    json_object *l_jobj_ts_created = json_object_new_object();
    json_object *l_jobj_ts_created_time_stamp = json_object_new_uint64(l_ts_create);
    int l_res = dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_ts_create);
    if (l_res < 0 || !l_jobj_ts_created || !l_jobj_ts_created_time_stamp || !l_jobj_type ||
        !l_jobj_hash || !l_jobj_datum || !l_jobj_res) {
        json_object_put(l_jobj_res);
        json_object_put(l_jobj_datum);
        json_object_put(l_jobj_hash);
        json_object_put(l_jobj_type);
        json_object_put(l_jobj_ts_created);
        json_object_put(l_jobj_ts_created_time_stamp);
        dap_json_rpc_allocation_error(*a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object *l_jobj_ts_created_str = json_object_new_string(buf);
    json_object *l_jobj_data_size = json_object_new_uint64(l_datum->header.data_size);
    if (!l_jobj_ts_created_str || !l_jobj_data_size) {
        json_object_put(l_jobj_res);
        json_object_put(l_jobj_datum);
        json_object_put(l_jobj_hash);
        json_object_put(l_jobj_type);
        json_object_put(l_jobj_ts_created);
        json_object_put(l_jobj_ts_created_time_stamp);
        json_object_put(l_jobj_ts_created_str);
        json_object_put(l_jobj_data_size);
        dap_json_rpc_allocation_error(*a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object_object_add(l_jobj_datum, "hash", l_jobj_hash);
    json_object_object_add(l_jobj_datum, "type", l_jobj_type);
    json_object_object_add(l_jobj_ts_created, "time_stamp", l_jobj_ts_created_time_stamp);
    json_object_object_add(l_jobj_ts_created, "str", l_jobj_ts_created_str);
    json_object_object_add(l_jobj_datum, "ts_created", l_jobj_ts_created);
    json_object_object_add(l_jobj_datum, "data_size", l_jobj_data_size);
    json_object_object_add(l_jobj_res, "datum", l_jobj_datum);
    json_object *l_jobj_verify = json_object_new_object();
    if (!l_jobj_verify) {
        json_object_put(l_jobj_res);
        dap_json_rpc_allocation_error(*a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    int l_verify_datum = dap_chain_net_verify_datum_for_add(l_chain, l_datum, &l_datum_hash);
    if (l_verify_datum){
        json_object *l_jobj_verify_err = json_object_new_string(dap_chain_net_verify_datum_err_code_to_str(l_datum, l_verify_datum));
        json_object *l_jobj_verify_status = json_object_new_boolean(FALSE);
        if (!l_jobj_verify_status || !l_jobj_verify_err) {
            json_object_put(l_jobj_verify_status);
            json_object_put(l_jobj_verify_err);
            json_object_put(l_jobj_verify);
            json_object_put(l_jobj_res);
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_jobj_verify, "isProcessed", l_jobj_verify_status);
        json_object_object_add(l_jobj_verify, "error", l_jobj_verify_err);
        ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY;
    } else {
        if (l_chain->callback_add_datums) {
            if (l_chain->callback_add_datums(l_chain, &l_datum, 1) == 0) {
                json_object *l_jobj_verify_status = json_object_new_boolean(FALSE);
                if (!l_jobj_verify_status) {
                    json_object_put(l_jobj_verify_status);
                    json_object_put(l_jobj_verify);
                    json_object_put(l_jobj_res);
                    dap_json_rpc_allocation_error(*a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_verify, "isProcessed", l_jobj_verify_status);
                ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY;
            } else {
                json_object *l_jobj_verify_status = json_object_new_boolean(TRUE);
                if (!l_jobj_verify_status) {
                    json_object_put(l_jobj_verify);
                    json_object_put(l_jobj_res);
                    dap_json_rpc_allocation_error(*a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_verify, "isProcessed", l_jobj_verify_status);
                if (false) { //dap_global_db_del_sync(l_gdb_group_mempool, a_datum_hash)){
                    json_object *l_jobj_wrn_text = json_object_new_string("Can't delete datum from mempool!");
                    if (!l_jobj_wrn_text) {
                        json_object_put(l_jobj_verify);
                        json_object_put(l_jobj_res);
                        dap_json_rpc_allocation_error(*a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_verify, "warning", l_jobj_wrn_text);
                } else {
                    json_object *l_jobj_text = json_object_new_string("Removed datum from mempool.");
                    if (!l_jobj_text) {
                        json_object_put(l_jobj_verify);
                        json_object_put(l_jobj_res);
                        dap_json_rpc_allocation_error(*a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_verify, "notice", l_jobj_text);
                }
            }
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL, "Error! Can't move to no-concensus chains from mempool");
            ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL;
        }
    }
    DAP_DELETE(l_gdb_group_mempool);
    json_object_object_add(l_jobj_res, "verify", l_jobj_verify);
    json_object_array_add(*a_json_arr_reply, l_jobj_res);
    return ret;
}


/**
 * @breif _cmd_mempool_proc_all
 * @param a_net
 * @param a_chain
 * @param a_str_reply
 * @return
 */
int _cmd_mempool_proc_all(dap_chain_net_t *a_net, dap_chain_t *a_chain, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    if (!a_net || !a_chain) {
        dap_json_rpc_error_add(*a_json_arr_reply, -2, "The net and chain argument is not set");
        return -2;
    }

    json_object *l_ret = json_object_new_object();
    if (!l_ret){
        dap_json_rpc_allocation_error(*a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    if(!dap_chain_net_by_id(a_chain->net_id)) {
        char *l_warn_str = dap_strdup_printf("%s.%s: chain not found\n", a_net->pub.name,
                                             a_chain->name);
        if (!l_warn_str) {
            json_object_put(l_ret);
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object *l_warn_obj = json_object_new_string(l_warn_str);
        DAP_DELETE(l_warn_str);
        if (!l_warn_obj){
            json_object_put(l_ret);
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_ret, "warning", l_warn_obj);
    }

   dap_chain_node_mempool_process_all(a_chain, true);
    char *l_str_result = dap_strdup_printf("The entire mempool has been processed in %s.%s.",
                                           a_net->pub.name, a_chain->name);
    if (!l_str_result) {
        json_object_put(l_ret);
        dap_json_rpc_allocation_error(*a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object *l_obj_result = json_object_new_string(l_str_result);
    DAP_DEL_Z(l_str_result);
    if (!l_obj_result) {
        json_object_put(l_ret);
        dap_json_rpc_allocation_error(*a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object_object_add(l_ret, "result", l_obj_result);
    json_object_array_add(*a_json_arr_reply, l_obj_result);
    return 0;
}

typedef enum _cmd_mempool_dump_error_list{
    COM_DUMP_ERROR_LIST_CORRUPTED_SIZE = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_DUMP_ERROR_CAN_NOT_FIND_DATUM,
    COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION
}_cmd_mempool_dump_error_list_t;

int _cmd_mempool_dump_from_group(dap_chain_net_id_t a_net_id, const char *a_group_gdb, const char *a_datum_hash,
                                 const char *a_hash_out_type, json_object **a_json_arr_reply)
{
    size_t l_datum_size = 0;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(a_group_gdb, a_datum_hash,
                                                         &l_datum_size, NULL, NULL );
    size_t l_datum_size2 = l_datum? dap_chain_datum_size( l_datum): 0;
    if (l_datum_size != l_datum_size2) {
        dap_json_rpc_error_add(*a_json_arr_reply, COM_DUMP_ERROR_LIST_CORRUPTED_SIZE, "Error! Corrupted datum %s, size by datum headers "
                                                                   "is %zd when in mempool is only %zd bytes",
                                 a_datum_hash, l_datum_size2, l_datum_size);
        return COM_DUMP_ERROR_LIST_CORRUPTED_SIZE;
    }
    if (!l_datum) {
        dap_json_rpc_error_add(*a_json_arr_reply, COM_DUMP_ERROR_LIST_CORRUPTED_SIZE, "Error! Can't find datum %s in %s", a_datum_hash, a_group_gdb);
        return COM_DUMP_ERROR_CAN_NOT_FIND_DATUM;
    }

    json_object *l_jobj_datum = json_object_new_object();
    dap_chain_datum_dump_json(*a_json_arr_reply, l_jobj_datum, l_datum, a_hash_out_type, a_net_id, true);
    json_object_array_add(*a_json_arr_reply, l_jobj_datum);
    return 0;
}

int _cmd_mempool_dump(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, const char *a_hash_out_type, json_object **a_json_arr_reply)
{
    if (!a_net || !a_datum_hash || !a_hash_out_type) {
        dap_json_rpc_error_add(*a_json_arr_reply, COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION, "The following arguments are not set: network,"
                                                                         " datum hash, and output hash type. "
                                                                         "Functions required for operation.");
        return COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION;
    }
    if (a_chain) {
        char *l_group_mempool = dap_chain_mempool_group_new(a_chain);
        _cmd_mempool_dump_from_group(a_net->pub.id, l_group_mempool, a_datum_hash, a_hash_out_type, a_json_arr_reply);
        DAP_DELETE(l_group_mempool);
    } else {
        dap_chain_t *l_chain = NULL;
        DL_FOREACH(a_net->pub.chains, l_chain){
            char *l_group_mempool = dap_chain_mempool_group_new(l_chain);
            if (!_cmd_mempool_dump_from_group(a_net->pub.id, l_group_mempool, a_datum_hash, a_hash_out_type, a_json_arr_reply)){
                DAP_DELETE(l_group_mempool);
                break;
            }
            DAP_DELETE(l_group_mempool);
        }
    }
    return 0;
}

int com_mempool(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    int arg_index = 1;
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    enum _subcmd {SUBCMD_LIST, SUBCMD_PROC, SUBCMD_PROC_ALL, SUBCMD_DELETE, SUBCMD_ADD_CA, SUBCMD_CHECK, SUBCMD_DUMP,
            SUBCMD_COUNT};
    enum _subcmd l_cmd = 0;
    if (a_argv[1]) {
        if (!dap_strcmp(a_argv[1], "list")) {
            l_cmd = SUBCMD_LIST;
        } else if (!dap_strcmp(a_argv[1], "proc")) {
            l_cmd = SUBCMD_PROC;
        } else if (!dap_strcmp(a_argv[1], "proc_all")) {
            l_cmd = SUBCMD_PROC_ALL;
        } else if (!dap_strcmp(a_argv[1], "delete")) {
            l_cmd = SUBCMD_DELETE;
        } else if (!dap_strcmp(a_argv[1], "add_ca")) {
            l_cmd = SUBCMD_ADD_CA;
        } else if (!dap_strcmp(a_argv[1], "dump")) {
            l_cmd = SUBCMD_DUMP;
        } else if (!dap_strcmp(a_argv[1], "check")) {
            l_cmd = SUBCMD_CHECK;
        } else if (!dap_strcmp(a_argv[1], "count")) {
            l_cmd = SUBCMD_COUNT;
        } else {
            char *l_str_err = dap_strdup_printf("Invalid sub command specified. Sub command %s "
                                                           "is not supported.", a_argv[1]);
            if (!l_str_err) {
                dap_json_rpc_allocation_error(*a_json_arr_reply);
                return -1;
            }
            json_object *l_jobj_str_err = json_object_new_string(l_str_err);
            DAP_DELETE(l_str_err);
            if (!l_jobj_str_err) {
                dap_json_rpc_allocation_error(*a_json_arr_reply);
                return -1;
            }
            json_object_array_add(*a_json_arr_reply, l_jobj_str_err);
            return -2;
        }
    }
    int cmd_parse_status = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &arg_index, a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_INVALID);
    if (cmd_parse_status != 0){
        dap_json_rpc_error_add(*a_json_arr_reply, cmd_parse_status, "Request parsing error (code: %d)", cmd_parse_status);
            return cmd_parse_status;
    }
    const char *l_hash_out_type = "hex";
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    const char *l_datum_hash_in = NULL;
    char *l_datum_hash = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_in);
    if (l_datum_hash_in) {
        if(dap_strncmp(l_datum_hash_in, "0x", 2) && dap_strncmp(l_datum_hash_in, "0X", 2)) {
            l_datum_hash = dap_enc_base58_to_hex_str_from_str(l_datum_hash_in);
        } else
            l_datum_hash = dap_strdup(l_datum_hash_in);
        if (!l_datum_hash) {
            dap_json_rpc_error_add(*a_json_arr_reply, -4, "Can't convert hash string %s to hex string", l_datum_hash_in);
            return -4;
        }
    }
    int ret = -100;
    switch (l_cmd) {
        case SUBCMD_LIST: {
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, -5, "The command does not include the net parameter. Please specify the "
                                           "parameter something like this mempool list -net <net_name>");
                return -5;
            }
            json_object *obj_ret = json_object_new_object();
            json_object *obj_net = json_object_new_string(l_net->pub.name);
            if (!obj_ret || !obj_net) {
                json_object_put(obj_ret);
                json_object_put(obj_net);
                dap_json_rpc_allocation_error(*a_json_arr_reply);
                return -1;
            }
            json_object_object_add(obj_ret, "net", obj_net);
            const char *l_wallet_addr = NULL;
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_wallet_addr) && !l_wallet_addr) {
                json_object *l_jobj_err = json_object_new_string("Parameter '-addr' require <addr>");
                if (!l_jobj_err) {
                    dap_json_rpc_allocation_error(*a_json_arr_reply);
                    return -1;
                }
                json_object_array_add(*a_json_arr_reply, l_jobj_err);
                return -3;
            }
            json_object *l_jobj_chains = json_object_new_array();
            if (!l_jobj_chains) {
                json_object_put(obj_ret);
                dap_json_rpc_allocation_error(*a_json_arr_reply);
                return -1;
            }
            bool l_fast = (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "-brief") != -1) ? true : false;
            size_t l_limit = 0, l_offset = 0;
            const char *l_limit_str = NULL, *l_offset_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
            l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
            l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
            if(l_chain) {
                s_com_mempool_list_print_for_chain(*a_json_arr_reply, l_net, l_chain, l_wallet_addr, l_jobj_chains, l_hash_out_type, l_fast, l_limit, l_offset);
            } else {
                DL_FOREACH(l_net->pub.chains, l_chain) {
                    s_com_mempool_list_print_for_chain(*a_json_arr_reply, l_net, l_chain, l_wallet_addr, l_jobj_chains, l_hash_out_type, l_fast, l_limit, l_offset);
                }
            }
            json_object_object_add(obj_ret, "chains", l_jobj_chains);
            json_object_array_add(*a_json_arr_reply, obj_ret);
            ret = 0;
        } break;
        case SUBCMD_PROC: {
            ret = _cmd_mempool_proc(l_net, l_chain, l_datum_hash, a_str_reply);
        } break;
        case SUBCMD_PROC_ALL: {
            ret = _cmd_mempool_proc_all(l_net, l_chain, a_str_reply);
        } break;
        case SUBCMD_DELETE: {
            if (l_datum_hash) {
                ret = _cmd_mempool_delete(l_net, l_chain, l_datum_hash, a_str_reply);
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, -3, "Error! %s requires -datum <datum hash> option", a_argv[0]);
                ret = -3;
            }
        } break;
        case SUBCMD_ADD_CA: {
            const char *l_ca_name  = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-ca_name", &l_ca_name);
            if (!l_ca_name) {
                dap_json_rpc_error_add(*a_json_arr_reply, -3, "mempool add_ca requires parameter '-ca_name' to specify the certificate name");
                ret = -3;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_ca_name);
            if (!l_cert) {
                dap_json_rpc_error_add(*a_json_arr_reply, -4, "Cert with name '%s' not found.", l_ca_name);
                ret = -4;
            }
            ret = _cmd_mempool_add_ca(l_net, l_chain, l_cert, a_str_reply);
            DAP_DELETE(l_cert);
        } break;
        case SUBCMD_CHECK: {
            ret = _cmd_mempool_check(l_net, l_chain, l_datum_hash, l_hash_out_type, a_str_reply);
        } break;
        case SUBCMD_DUMP: {
            ret = _cmd_mempool_dump(l_net, l_chain, l_datum_hash, l_hash_out_type, a_json_arr_reply);
        } break;
        case SUBCMD_COUNT: {
            char *l_mempool_group;
            json_object *obj_ret = json_object_new_object();
            json_object *obj_net = json_object_new_string(l_net->pub.name);
            if (!obj_ret || !obj_net) {
                json_object_put(obj_ret);
                json_object_put(obj_net);
                dap_json_rpc_allocation_error(*a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            json_object_object_add(obj_ret, "net", obj_net);
            json_object *l_jobj_chains = json_object_new_array();
            if (!l_jobj_chains) {
                json_object_put(obj_ret);
                dap_json_rpc_allocation_error(*a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            if(l_chain) {
                l_mempool_group = dap_chain_mempool_group_new(l_chain);
                size_t l_objs_count = 0;
                dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_mempool_group, &l_objs_count);
                dap_global_db_objs_delete(l_objs, l_objs_count);
                DAP_DELETE(l_mempool_group);
                json_object *l_jobj_chain = json_object_new_object();
                json_object *l_jobj_chain_name = json_object_new_string(l_chain->name);
                json_object *l_jobj_count = json_object_new_uint64(l_objs_count);
                if (!l_jobj_chain || !l_jobj_chain_name || !l_jobj_count) {
                    json_object_put(l_jobj_chains);
                    json_object_put(l_jobj_chain);
                    json_object_put(l_jobj_chain_name);
                    json_object_put(l_jobj_count);
                    json_object_put(obj_ret);
                    dap_json_rpc_allocation_error(*a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_chain, "name", l_jobj_chain_name);
                json_object_object_add(l_jobj_chain, "count", l_jobj_count);
                json_object_array_add(l_jobj_chains, l_jobj_chain);
            } else {
                DL_FOREACH(l_net->pub.chains, l_chain) {
                    l_mempool_group = dap_chain_mempool_group_new(l_chain);
                    size_t l_objs_count = 0;
                    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_mempool_group, &l_objs_count);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    DAP_DELETE(l_mempool_group);
                    json_object *l_jobj_chain = json_object_new_object();
                    json_object *l_jobj_chain_name = json_object_new_string(l_chain->name);
                    json_object *l_jobj_count = json_object_new_uint64(l_objs_count);
                    if (!l_jobj_chain || !l_jobj_chain_name || !l_jobj_count) {
                        json_object_put(l_jobj_chains);
                        json_object_put(l_jobj_chain);
                        json_object_put(l_jobj_chain_name);
                        json_object_put(l_jobj_count);
                        json_object_put(obj_ret);
                        dap_json_rpc_allocation_error(*a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_chain, "name", l_jobj_chain_name);
                    json_object_object_add(l_jobj_chain, "count", l_jobj_count);
                    json_object_array_add(l_jobj_chains, l_jobj_chain);
                }
            }
            json_object_object_add(obj_ret, "chains", l_jobj_chains);
            json_object_array_add(*a_json_arr_reply, obj_ret);
            ret = 0;
        } break;
    }
    DAP_DEL_Z(l_datum_hash);
    return ret;
}

typedef enum _s_where_search{
    ALL,
    CHAINS,
    MEMPOOL
}_s_where_search_t;

void _cmd_find_type_decree_in_chain(json_object *a_out, dap_chain_t *a_chain, uint16_t a_decree_type, _s_where_search_t a_where, const char *a_hash_out_type) {
    json_object *l_common_decree_arr = json_object_new_array();
    json_object *l_service_decree_arr = json_object_new_array();
    if (a_where == ALL || a_where == CHAINS) {
        dap_chain_cell_t *l_cell, *l_iter_tmp;
        HASH_ITER(hh, a_chain->cells, l_cell, l_iter_tmp) {
            dap_chain_atom_iter_t *l_atom_iter = l_cell->chain->callback_atom_iter_create(l_cell->chain, l_cell->id,
                                                                                          NULL);
            dap_chain_atom_ptr_t l_atom;
            uint64_t l_atom_size = 0;
            for (l_atom = l_cell->chain->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size);
                 l_atom && l_atom_size;
                 l_atom = l_cell->chain->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size)) {
                size_t l_datum_count = 0;
                dap_chain_datum_t **l_datums = l_cell->chain->callback_atom_get_datums(l_atom, l_atom_size,
                                                                                       &l_datum_count);
                char l_buff_ts[50] = {'\0'};
                dap_time_to_str_rfc822(l_buff_ts, 50, l_atom_iter->cur_ts);
                for (size_t i = 0; i < l_datum_count; i++) {
                    dap_chain_datum_t *l_datum = l_datums[i];
                    if (l_datum[i].header.type_id != DAP_CHAIN_DATUM_DECREE) continue;
                    dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *) l_datum[i].data;
                    if (l_decree->header.sub_type == a_decree_type) {
                        json_object *l_jobj_atom = json_object_new_object();
                        json_object *l_jobj_atom_create = json_object_new_string(l_buff_ts);
                        json_object *l_jobj_atom_hash = json_object_new_string(
                                !dap_strcmp(a_hash_out_type, "base58") ?
                                dap_enc_base58_encode_hash_to_str_static(l_atom_iter->cur_hash) :
                                dap_hash_fast_to_str_static(l_atom_iter->cur_hash));
                        json_object_object_add(l_jobj_atom, "hash", l_jobj_atom_hash);
                        json_object_object_add(l_jobj_atom, "created", l_jobj_atom_create);
                        json_object *l_jobj_decree = json_object_new_object();
                        size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
                        dap_chain_datum_decree_dump_json(l_jobj_decree, l_decree, l_decree_size, a_hash_out_type);
                        json_object *l_obj_source = json_object_new_object();
                        json_object_object_add(l_obj_source, "atom", l_jobj_atom);
                        json_object_object_add(l_jobj_decree, "source", l_obj_source);
                        (l_decree->header.type == DAP_CHAIN_DATUM_DECREE_TYPE_COMMON) ?
                            json_object_array_add(l_common_decree_arr, l_jobj_decree) :
                            json_object_array_add(l_service_decree_arr, l_jobj_decree);
                    }
                }
            }
            l_cell->chain->callback_atom_iter_delete(l_atom_iter);
        }
    }
    if (a_where == ALL || a_where == MEMPOOL) {
        char *l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
        size_t l_mempool_count = 0;
        dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_mempool_count);
        for (size_t i = 0; i < l_mempool_count; i++) {
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *) (l_objs[i].value);
            if (l_datum->header.type_id != DAP_CHAIN_DATUM_DECREE) continue;
            dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *) l_datum->data;
            if (l_decree->header.sub_type == a_decree_type) {
                json_object *l_jobj_decree = json_object_new_object();
                size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
                dap_chain_datum_decree_dump_json(l_jobj_decree, l_decree, l_decree_size, a_hash_out_type);
                json_object_object_add(l_jobj_decree, "source", json_object_new_string("mempool"));
                (l_decree->header.type == DAP_CHAIN_DATUM_DECREE_TYPE_COMMON) ?
                json_object_array_add(l_common_decree_arr, l_jobj_decree) :
                json_object_array_add(l_service_decree_arr, l_jobj_decree);
            }
        }
        dap_global_db_objs_delete(l_objs, l_mempool_count);
    }
    json_object_object_add(a_out, "common", l_common_decree_arr);
    json_object_object_add(a_out, "service", l_service_decree_arr);
}

int cmd_find(int a_argc, char **a_argv, void **a_reply) {
    json_object **a_json_reply = (json_object **)a_reply;
    int arg_index = 1;
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    enum _subcmd {SUBCMD_DATUM, SUBCMD_ATOM, SUBCMD_DECREE};
    enum _subcmd l_cmd = 0;
    if (a_argv[1]) {
        if (!dap_strcmp(a_argv[1], "datum")) {
            l_cmd = SUBCMD_DATUM;
        } else if (!dap_strcmp(a_argv[1], "atom")) {
            l_cmd = SUBCMD_ATOM;
        } else if (!dap_strcmp(a_argv[1], "decree")) {
            l_cmd = SUBCMD_DECREE;
        } else {
            dap_json_rpc_error_add(*a_json_reply,DAP_CHAIN_NODE_CLI_FUND_ERR_UNKNOWN_SUBCMD,"Invalid sub command specified. Sub command %s "
                                                "is not supported.", a_argv[1]);
            return DAP_CHAIN_NODE_CLI_FUND_ERR_UNKNOWN_SUBCMD;
        }
    }
    int cmd_parse_status = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_reply, &arg_index, a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_INVALID);
    if (cmd_parse_status != 0){
        dap_json_rpc_error_add(*a_json_reply, cmd_parse_status, "Request parsing error (code: %d)", cmd_parse_status);
            return cmd_parse_status;
    }
    const char *l_hash_out_type = "hex";
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    switch (l_cmd) {
        case SUBCMD_DATUM: {
            const char *l_datum_hash = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_datum_hash);
            if (!l_datum_hash) {
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash);
                if (!l_datum_hash) {
                    dap_json_rpc_error_add(*a_json_reply, DAP_CHAIN_NODE_CLI_FIND_ERR_HASH_IS_NOT_SPECIFIED,
                                           "The hash of the datum is not specified.");
                    return DAP_CHAIN_NODE_CLI_FIND_ERR_HASH_IS_NOT_SPECIFIED;
                }
            }
            return _cmd_mempool_check(l_net, l_chain, l_datum_hash, l_hash_out_type, a_reply);
        } break;
        case SUBCMD_ATOM: {
            const char *l_atom_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_atom_hash_str);
            dap_hash_fast_t l_atom_hash = {0};
            if (!l_atom_hash_str) {
                dap_json_rpc_error_add(*a_json_reply, DAP_CHAIN_NODE_CLI_FIND_ERR_HASH_IS_NOT_SPECIFIED, "The hash of the atom is not specified.");
                return DAP_CHAIN_NODE_CLI_FIND_ERR_HASH_IS_NOT_SPECIFIED;
            }
            if (dap_chain_hash_fast_from_str(l_atom_hash_str, &l_atom_hash)) {
                dap_json_rpc_error_add(*a_json_reply, DAP_CHAIN_NODE_CLI_FIND_ERR_PARSE_HASH, "Failed to convert the value '%s' to a hash.", l_atom_hash_str);
                return DAP_CHAIN_NODE_CLI_FIND_ERR_PARSE_HASH;
            }
            json_object *l_obj_atom = json_object_new_object();
            json_object *l_obj_atom_hash = json_object_new_string(l_atom_hash_str);
            json_object_object_add(l_obj_atom, "hash", l_obj_atom_hash);
            dap_chain_atom_ptr_t l_atom_ptr = NULL;
            size_t l_atom_size = 0;
            if (l_chain) {
                l_atom_ptr = dap_chain_get_atom_by_hash(l_chain, &l_atom_hash, &l_atom_size);
            } else {
                for (l_chain = l_net->pub.chains ; l_chain; l_chain = l_chain->next){
                    l_atom_ptr = dap_chain_get_atom_by_hash(l_chain, &l_atom_hash, &l_atom_size);
                    if (l_atom_ptr) break;
                }
            }
            json_object *l_obj_source = NULL;
            json_object *l_jobj_find = NULL;
            if (l_atom_ptr) {
                l_obj_source = json_object_new_object();
                json_object *l_obj_net = json_object_new_string(l_net->pub.name);
                json_object *l_obj_chain = json_object_new_string(l_chain->name);
                json_object_object_add(l_obj_source, "net", l_obj_net);
                json_object_object_add(l_obj_source, "chain", l_obj_chain);
                l_jobj_find = json_object_new_boolean(TRUE);
                json_object_object_add(l_obj_atom, "source", l_obj_source);
                json_object_object_add(l_obj_atom, "dump", l_chain->callback_atom_dump_json(a_json_reply, l_chain, l_atom_ptr, l_atom_size, l_hash_out_type));
            } else {
                l_jobj_find = json_object_new_boolean(FALSE);
            }
            json_object_object_add(l_obj_atom, "find", l_jobj_find);
            json_object_array_add(*a_json_reply, l_obj_atom);
        } break;
        case SUBCMD_DECREE: {
            const char* l_type_decre_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-type", &l_type_decre_str);
            if (!l_type_decre_str){
                dap_json_rpc_error_add(*a_json_reply, DAP_CHIAN_NODE_CLI_FIND_ERR_SUBTYPE_DECREE_IS_NOT_SPECIFIED,
                                       "The type of decree you are looking for is not specified.");
                return DAP_CHIAN_NODE_CLI_FIND_ERR_SUBTYPE_DECREE_IS_NOT_SPECIFIED;
            }
            uint16_t l_subtype_decree = dap_chain_datum_decree_type_from_str(l_type_decre_str);
            if (!l_subtype_decree) {
                dap_json_rpc_error_add(*a_json_reply, DAP_CHAIN_NODE_CLI_FIND_ERR_UNKNOWN_SUBTYPE_DECREE,
                                       "There is no decree of type '%s'.", l_type_decre_str);
                return DAP_CHAIN_NODE_CLI_FIND_ERR_UNKNOWN_SUBTYPE_DECREE;
            }
            const char *l_with_type_str = NULL;
            const char *l_where_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-where", &l_where_str);
            _s_where_search_t l_where = ALL;
            if (l_where_str) {
                if (!dap_strcmp(l_where_str, "chains")) {
                    l_where = CHAINS;
                } else if (!dap_strcmp(l_where_str, "mempool")) {
                    l_where = MEMPOOL;
                } else {
                    dap_json_rpc_error_add(*a_json_reply, DAP_CHAIN_NODE_CLI_FIND_ERR_UNKNOWN_PARAMETR_WHERE,
                                       "'%s' is not a valid place to look. Use mempool or chains.",
                                           l_where_str);
                    return DAP_CHAIN_NODE_CLI_FIND_ERR_UNKNOWN_PARAMETR_WHERE;
                }
            }
            json_object *l_obj = json_object_new_object();
            json_object_object_add(l_obj, "type", json_object_new_string(l_type_decre_str));
            json_object *l_jobj_chains = json_object_new_object();
            if (l_chain) {
                json_object *l_jobj_data = json_object_new_object();
                _cmd_find_type_decree_in_chain(l_jobj_data, l_chain, l_subtype_decree, l_where, l_hash_out_type);
                json_object_object_add(l_jobj_chains, l_chain->name, l_jobj_data);
            } else {
                for (l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
                    json_object *l_jobj_data = json_object_new_object();
                    _cmd_find_type_decree_in_chain(l_jobj_data, l_chain, l_subtype_decree, l_where, l_hash_out_type);
                    json_object_object_add(l_jobj_chains, l_chain->name, l_jobj_data);
                }
            }
            json_object_object_add(l_obj, "chains", l_jobj_chains);
            json_object_array_add(*a_json_reply, l_obj);
        } break;
    }
    return DAP_CHAIN_NODE_CLI_FIND_OK;
}

typedef enum cmd_mempool_add_ca_error_list{
    COM_MEMPOOL_ADD_CA_ERROR_NET_NOT_FOUND = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_MEMPOOL_ADD_CA_ERROR_NO_CAINS_FOR_CA_DATUM_IN_NET,
    COM_MEMPOOL_ADD_CA_ERROR_REQUIRES_PARAMETER_CA_NAME,
    COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_FIND_CERTIFICATE,
    COM_MEMPOOL_ADD_CA_ERROR_CORRUPTED_CERTIFICATE_WITHOUT_KEYS,
    COM_MEMPOOL_ADD_CA_ERROR_CERTIFICATE_HAS_PRIVATE_KEY_DATA,
    COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE,
    COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_PLACE_CERTIFICATE
}cmd_mempool_add_ca_error_list_t;
/**
 * @brief _cmd_mempool_add_ca
 * @details Place public CA into the mempool
 * @param a_net
 * @param a_chain
 * @param a_cert
 * @param a_str_reply
 * @return
 */
int _cmd_mempool_add_ca(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_cert_t *a_cert, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    if (!a_net || !a_chain || !a_cert){
        dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_NET_NOT_FOUND, "The network or certificate attribute was not passed.");
        return COM_MEMPOOL_ADD_CA_ERROR_NET_NOT_FOUND;
    }
    dap_chain_t *l_chain = NULL;
    // Chech for chain if was set or not
    if (!a_chain){
       // If wasn't set - trying to auto detect
        l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_CA);
        if (!l_chain) { // If can't auto detect
            // clean previous error code
            dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_NO_CAINS_FOR_CA_DATUM_IN_NET,
                                   "No chains for CA datum in network \"%s\"", a_net->pub.name);
            return COM_MEMPOOL_ADD_CA_ERROR_NO_CAINS_FOR_CA_DATUM_IN_NET;
        }
    }
    if(!a_cert->enc_key){
        dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CORRUPTED_CERTIFICATE_WITHOUT_KEYS,
                               "Corrupted certificate \"%s\" without keys certificate", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CORRUPTED_CERTIFICATE_WITHOUT_KEYS;
    }

    if (a_cert->enc_key->priv_key_data_size || a_cert->enc_key->priv_key_data){
        dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CERTIFICATE_HAS_PRIVATE_KEY_DATA,
                               "Certificate \"%s\" has private key data. Please export public only key certificate without private keys", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CERTIFICATE_HAS_PRIVATE_KEY_DATA;
    }

    // Serialize certificate into memory
    uint32_t l_cert_serialized_size = 0;
    byte_t * l_cert_serialized = dap_cert_mem_save(a_cert, &l_cert_serialized_size);
    if(!l_cert_serialized){
        dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE,
                               "Can't serialize in memory certificate \"%s\"", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE;
    }
    // Now all the chechs passed, forming datum for mempool
    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CA, l_cert_serialized , l_cert_serialized_size);
    DAP_DELETE( l_cert_serialized);
    if(!l_datum){
        dap_json_rpc_error_add(*a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE,
                               "Can't produce datum from certificate \"%s\"", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    if (l_hash_str) {
        char *l_msg = dap_strdup_printf("Datum %s was successfully placed to mempool", l_hash_str);
        if (!l_msg) {
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object *l_obj_message = json_object_new_string(l_msg);
        DAP_DELETE(l_msg);
        DAP_DELETE(l_hash_str);
        if (!l_obj_message) {
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_array_add(*a_json_arr_reply, l_obj_message);
        return 0;
    } else {
        char *l_msg = dap_strdup_printf("Can't place certificate \"%s\" to mempool", a_cert->name);
        if (!l_msg) {
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object *l_obj_msg = json_object_new_string(l_msg);
        DAP_DELETE(l_msg);
        if (!l_obj_msg) {
            dap_json_rpc_allocation_error(*a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_array_add(*a_json_arr_reply, l_obj_msg);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_PLACE_CERTIFICATE;
    }
}

/**
 * @brief com_chain_ca_copy
 * @details copy public CA into the mempool
 * @param a_argc
 * @param a_argv
 * @param a_arg_func
 * @param a_str_reply
 * @return
 */
int com_chain_ca_copy( int a_argc,  char ** a_argv, void **a_str_reply)
{
    int l_argc = a_argc + 1;
    char **l_argv = DAP_NEW_Z_COUNT(char*, l_argc);
    l_argv[0] = "mempool";
    l_argv[1] = "add_ca";
    for (int i = 1; i < a_argc; i++)
        l_argv[i + 1] = a_argv[i];
    int ret = com_mempool(l_argc, l_argv, a_str_reply);
    DAP_DEL_Z(l_argv);
    return ret;
}


/**
 * @brief com_chain_ca_pub
 * @details place public CA into the mempool
 * @param a_argc
 * @param a_argv
 * @param a_arg_func
 * @param a_str_reply
 * @return
 */
int com_chain_ca_pub( int a_argc,  char ** a_argv, void **a_str_reply)
{
    json_object ** a_json_arr_reply = (json_object **) a_str_reply;
    int arg_index = 1;
    // Read params
    const char * l_ca_name = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-ca_name", &l_ca_name);
    dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &arg_index,a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_CA);

    dap_cert_t * l_cert = dap_cert_find_by_name( l_ca_name );
    if( l_cert == NULL ){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_FIND_CERT_ERR,
                                       "Can't find \"%s\" certificate", l_ca_name );
        return -DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_FIND_CERT_ERR;
    }


    if( l_cert->enc_key == NULL ){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CORRUPTED_CERT_ERR,
                                       "Corrupted certificate \"%s\" without keys certificate", l_ca_name );
        return -DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CORRUPTED_CERT_ERR;
    }

    // Create empty new cert
    dap_cert_t * l_cert_new = dap_cert_new(l_ca_name);
    if(!l_cert_new)
        return -9;
    l_cert_new->enc_key = dap_enc_key_new( l_cert->enc_key->type);
    if(!l_cert_new->enc_key) {
        DAP_DELETE(l_cert_new);
        return -10;
    }

    // Copy only public key
    l_cert_new->enc_key->pub_key_data = DAP_NEW_Z_SIZE(uint8_t,
                                                      l_cert_new->enc_key->pub_key_data_size =
                                                      l_cert->enc_key->pub_key_data_size );
    if(!l_cert_new->enc_key->pub_key_data) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_cert_new->enc_key);
        DAP_DELETE(l_cert_new);
        return -11;
    }
    memcpy(l_cert_new->enc_key->pub_key_data, l_cert->enc_key->pub_key_data,l_cert->enc_key->pub_key_data_size);

    // Serialize certificate into memory
    uint32_t l_cert_serialized_size = 0;
    byte_t * l_cert_serialized = dap_cert_mem_save( l_cert_new, &l_cert_serialized_size );
    if(!l_cert_serialized){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_SERIALIZE_MEMORY_CERT_ERR,
                                       "Can't serialize in memory certificate" );
        return -DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_SERIALIZE_MEMORY_CERT_ERR;
    }
    // Now all the chechs passed, forming datum for mempool
    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CA, l_cert_serialized , l_cert_serialized_size);
    DAP_DELETE(l_cert_serialized);
    if(!l_datum){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PRODUCE_CERT_ERR,
                                       "Can't serialize in memory certificate" );
        return -DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PRODUCE_CERT_ERR;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    if (l_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_OK,
                                       "Datum %s was successfully placed to mempool", l_hash_str);
        DAP_DELETE(l_hash_str);
        return 0;
    } else {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PLACE_CERT_ERR,
                                       "Can't place certificate \"%s\" to mempool", l_ca_name);
        return -DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PLACE_CERT_ERR;
    }
}

/* Decree section */

/**
 * @brief
 * sign data (datum_decree) by certificates (1 or more)
 * successful count of signes return in l_sign_counter
 * @param a_certs - array with certificates loaded from dcert file
 * @param a_datum_anchor - updated pointer for l_datum_token variable after realloc
 * @param a_certs_count - count of certificate
 * @param a_total_sign_count - counter of successful data signing operation
 * @return dap_chain_datum_anchor_t*
 */
static dap_chain_datum_anchor_t * s_sign_anchor_in_cycle(dap_cert_t ** a_certs, dap_chain_datum_anchor_t *a_datum_anchor,
                    size_t a_certs_count, size_t *a_total_sign_count)
{
    size_t l_cur_sign_offset = a_datum_anchor->header.data_size + a_datum_anchor->header.signs_size;
    size_t l_total_signs_size = a_datum_anchor->header.signs_size, l_total_sign_count = 0;

    for(size_t i = 0; i < a_certs_count; i++)
    {
        dap_sign_t * l_sign = dap_cert_sign(a_certs[i],  a_datum_anchor,
           sizeof(dap_chain_datum_anchor_t) + a_datum_anchor->header.data_size);

        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            dap_chain_datum_anchor_t *l_new_anchor
                = DAP_REALLOC_RET_VAL_IF_FAIL(a_datum_anchor, sizeof(dap_chain_datum_anchor_t) + l_cur_sign_offset + l_sign_size, NULL, l_sign);
            a_datum_anchor = l_new_anchor;
            memcpy((byte_t*)a_datum_anchor->data_n_sign + l_cur_sign_offset, l_sign, l_sign_size);
            l_total_signs_size += l_sign_size;
            l_cur_sign_offset += l_sign_size;
            a_datum_anchor->header.signs_size = l_total_signs_size;
            DAP_DELETE(l_sign);
            log_it(L_DEBUG,"<-- Signed with '%s'", a_certs[i]->name);
            l_total_sign_count++;
        }
    }
    *a_total_sign_count = l_total_sign_count;
    return a_datum_anchor;
}

// Decree commands handlers
int cmd_decree(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object ** a_json_arr_reply = (json_object **) a_str_reply;
    enum { CMD_NONE=0, CMD_CREATE, CMD_SIGN, CMD_ANCHOR, CMD_FIND, CMD_INFO };
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char * l_chain_str = NULL;
    const char * l_decree_chain_str = NULL;
    const char * l_certs_str = NULL;
    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;
    dap_chain_t * l_decree_chain = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_INVALID_PARAM_ERR,
                                            "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_COM_DECREE_INVALID_PARAM_ERR;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_REQUIRES_PARAM_NET_ERR,
                                            "command requires parameter '-net'");
        return -DAP_CHAIN_NODE_CLI_COM_DECREE_REQUIRES_PARAM_NET_ERR;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_REQUIRES_PARAM_NET_ERR,
                                            "command requires parameter '-net' to be valid chain network name");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_REQUIRES_PARAM_NET_ERR;
        }
    }

    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "create", NULL))
        l_cmd = CMD_CREATE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "sign", NULL))
        l_cmd = CMD_SIGN;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "anchor", NULL))
        l_cmd = CMD_ANCHOR;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "find", NULL))
        l_cmd = CMD_FIND;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "info", NULL))
        l_cmd = CMD_INFO;

    if (l_cmd != CMD_FIND && l_cmd != CMD_INFO) {
        // Public certifiacte of condition owner
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_REQUIRES_PARAM_CERT_ERR,
                                                                "decree create requires parameter '-certs'");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_REQUIRES_PARAM_CERT_ERR;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
    }

    switch (l_cmd)
    {
    case CMD_CREATE:{
        if(!l_certs_count) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_LEAST_VALID_CERT_ERR,
                                "decree create command requres at least one valid certificate to sign the decree");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_LEAST_VALID_CERT_ERR;
        }
        dap_chain_datum_decree_t *l_datum_decree = NULL;

        // Common decree create
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

        // Search chain
        if(l_chain_str) {
            if (!( l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str) )) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_INVALID_CHAIN_PARAM_ERR,
                                                            "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                                            "Available chain with decree support:\n\t\"%s\"\n",
                                        l_chain_str, l_net_str, dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)->name);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_INVALID_CHAIN_PARAM_ERR;
            } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)){ // check chain to support decree
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_CHAIN_DONT_SUPPORT_ERR,
                                                            "Chain %s don't support decree", l_chain->name);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_CHAIN_DONT_SUPPORT_ERR;
            }
        }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) == NULL) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_CANT_FIND_CHAIN_ERR,
                                                            "Can't find chain with decree support.");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_CANT_FIND_CHAIN_ERR;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-decree_chain", &l_decree_chain_str);

        // Search chain
        if(l_decree_chain_str) {
            if (!( l_decree_chain = dap_chain_net_get_chain_by_name(l_net, l_decree_chain_str) )) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_INVALID_CHAIN_PARAM_ERR,
                        "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                              "Available chains:", l_chain_str, l_net_str);
                    dap_chain_t *l_chain;
                    json_object* json_obj_out = json_object_new_object();
                    if (!json_obj_out) return dap_json_rpc_allocation_put_error(json_obj_out);
                    json_object* json_obj_chains = json_object_new_array();
                    if (!json_obj_chains) return dap_json_rpc_allocation_put_error(json_obj_out);
                    json_object_object_add(json_obj_out, "available_chains", json_obj_chains);
                    DL_FOREACH(l_net->pub.chains, l_chain) {
                        json_object* json_obj_chain = json_object_new_object();
                        if (!json_obj_chain) return dap_json_rpc_allocation_put_error(json_obj_out);
                        json_object_object_add(json_obj_chain, "chain", json_object_new_string(l_chain->name));
                        json_object_array_add(json_obj_chains, json_obj_chain);
                    }
                    json_object_array_add(*a_json_arr_reply, json_obj_out);                    
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_INVALID_CHAIN_PARAM_ERR;
            }
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_REQUIRES_PARAM_DECREE_CHAIN_ERR,
                                                        "decree requires parameter -decree_chain.");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_REQUIRES_PARAM_DECREE_CHAIN_ERR;
        }

        dap_tsd_t *l_tsd = NULL;
        dap_cert_t **l_new_certs = NULL;
        size_t l_new_certs_count = 0;
        dap_list_t *l_tsd_list = NULL;

        int l_subtype = 0;
        const char *l_param_value_str = NULL;
        const char *l_param_addr_str = NULL;
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_param_value_str)){
            l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE;
            if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_addr", &l_param_addr_str)){
                if (dap_chain_addr_is_blank(&l_net->pub.fee_addr)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NOT_FEE_PARAM_CHAIN_ERR,
                                                                    "Use -to_addr parameter to set net fee");
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NOT_FEE_PARAM_CHAIN_ERR;
                }
            } else {
                dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_param_addr_str);
                l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET, l_addr, sizeof(dap_chain_addr_t));
                if (!l_tsd) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    dap_list_free_full(l_tsd_list, NULL);
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_TSD_MEM_ALLOC_ERR;
                }
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                DAP_DELETE(l_addr);
            }

            uint256_t l_param_value = dap_uint256_scan_uninteger(l_param_value_str);
            l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE, &l_param_value, sizeof(l_param_value));
            if (!l_tsd) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_list_free_full(l_tsd_list, NULL);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_TSD_MEM_ALLOC_ERR;
            }
            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
        } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hardfork_from", &l_param_value_str)) {
            l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK;

            uint64_t l_param_value = strtoll(l_param_value_str, NULL, 10);
            if (!l_param_value && dap_strcmp(l_param_value_str, "0")) {
                log_it(L_ERROR, "Can't converts %s to atom number", l_param_value_str);
                return -100;
            }
            l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCK_NUM, &l_param_value, sizeof(l_param_value));
            if (!l_tsd) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_list_free_full(l_tsd_list, NULL);
                return -1;
            }
            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            uint16_t l_generation = l_chain->generation + 1;
            l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_GENERATION, &l_generation, sizeof(l_chain->generation));
            if (!l_tsd) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_list_free_full(l_tsd_list, NULL);
                return -1;
            }
            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

            const char *l_addr_pairs = NULL;
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr_pairs", &l_addr_pairs)) {
                char **l_addrs = dap_strsplit(l_addr_pairs, ",", 256);
                if (!l_addrs) {
                    dap_list_free_full(l_tsd_list, NULL);
                    log_it(L_ERROR, "Argument -addr_pairs require string <\"old_addr:new_addr\",\"old_addr1:new_addr1\"...>");
                    return -200;
                }
                json_object* l_json_arr_addrs = json_object_new_object();
                for (uint16_t i = 0; l_addrs[i]; i++) {
                    char ** l_addr_pair = dap_strsplit(l_addrs[i], ":", 256);
                    if (!l_addr_pair || !l_addr_pair[0] || !l_addr_pair[1])
                        continue;
                    json_object_object_add(l_json_arr_addrs, l_addr_pair[0], json_object_new_string(l_addr_pair[1]));
                }
                const char * l_addr_array_str = json_object_to_json_string(l_json_arr_addrs);
                l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CHANGED_ADDRS, l_addr_array_str, strlen(l_addr_array_str) + 1);
                if (!l_tsd) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    dap_list_free_full(l_tsd_list, NULL);
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_TSD_MEM_ALLOC_ERR;
                }
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            }

            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-trusted_addrs", &l_param_addr_str)) {
                char **l_addrs = dap_strsplit(l_param_addr_str, ",", 256);
                for (uint16_t i = 0; l_addrs[i]; i++) {
                    dap_stream_node_addr_t l_addr_cur;
                    if (dap_stream_node_addr_from_str(&l_addr_cur, l_addrs[i])) {
                        log_it(L_ERROR, "Can't convert %s to node addr", l_addrs[i]);
                        dap_list_free_full(l_tsd_list, NULL);
                        dap_strfreev(l_addrs);
                        return -5;
                    }
                    l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR, &l_addr_cur, sizeof(l_addr_cur));
                    if (!l_tsd) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        dap_list_free_full(l_tsd_list, NULL);
                        dap_strfreev(l_addrs);
                        return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_TSD_MEM_ALLOC_ERR;
                    }
                    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                }
                dap_strfreev(l_addrs);
            }

            if (dap_chain_net_srv_stake_hardfork_data_export(l_net, &l_tsd_list)) {
                log_it(L_ERROR, "Can't add stake delegate data to hardfork decree");
                dap_list_free_full(l_tsd_list, NULL);
                return -300;
            }
        } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hardfork_retry", &l_param_value_str)) {
            l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_RETRY;
            if (dap_chain_net_srv_stake_hardfork_data_export(l_net, &l_tsd_list)) {
                log_it(L_ERROR, "Can't add stake delegate data to hardfork decree");
                dap_list_free_full(l_tsd_list, NULL);
                return -300;
            }
        } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hardfork_complete", &l_param_value_str)) {
            l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_COMPLETE;
        } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-new_certs", &l_param_value_str)){
            l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS;
            dap_cert_parse_str_list(l_param_value_str, &l_new_certs, &l_new_certs_count);

            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            uint16_t l_min_signs = dap_ledger_decree_get_min_num_of_signers(l_net->pub.ledger);
            if (l_new_certs_count < l_min_signs) {
                log_it(L_WARNING,"Number of new certificates is less than minimum owner number.");
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_CERT_NUMBER_ERR;
            }

            size_t l_failed_certs = 0;
            for (size_t i = 0; i < l_new_certs_count; i++){
                dap_pkey_t *l_pkey = dap_cert_to_pkey(l_new_certs[i]);
                if(!l_pkey) {
                    log_it(L_WARNING,"New cert [%zu] have no public key.", i);
                    l_failed_certs++;
                    continue;
                }
                l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER, l_pkey, sizeof(dap_pkey_t) + (size_t)l_pkey->header.size);
                DAP_DELETE(l_pkey);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            }
            if(l_failed_certs)
            {
                dap_list_free_full(l_tsd_list, NULL);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_CERT_NO_PUB_KEY_ERR;
            }
        }else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-signs_verify", &l_param_value_str)) {
            l_subtype = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN;
            uint256_t l_new_num_of_owners = dap_uint256_scan_uninteger(l_param_value_str);
            if (IS_ZERO_256(l_new_num_of_owners)) {
                log_it(L_WARNING, "The minimum number of owners can't be zero");
                dap_list_free_full(l_tsd_list, NULL);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NO_OWNERS_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            uint256_t l_owners = GET_256_FROM_64(dap_ledger_decree_get_num_of_owners(l_net->pub.ledger));
            if (compare256(l_new_num_of_owners, l_owners) > 0) {
                log_it(L_WARNING, "The minimum number of owners is greater than the total number of owners.");
                dap_list_free_full(l_tsd_list, NULL);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_TO_MANY_OWNERS_ERR;
            }

            l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER, &l_new_num_of_owners, sizeof(l_new_num_of_owners));
            if (!l_tsd) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_list_free_full(l_tsd_list, NULL);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_MEM_ALOC_ERR;
            }
            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_SUBCOM_ERR,
                                                        "Decree subtype fail.");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_SUBCOM_ERR;
        }

        if (l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS ||
            l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN)
        {
            if (l_decree_chain->id.uint64 != l_chain->id.uint64){
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NOT_CHAIN_PARAM_ERR,
                                                    "Decree subtype %s not suppurted by chain %s",
                                                    dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NOT_CHAIN_PARAM_ERR;
            }
        } else if (l_decree_chain->id.uint64 == l_chain->id.uint64){
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NOT_CHAIN_PARAM_ERR,
                                                    "Decree subtype %s not suppurted by chain %s",
                                                    dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NOT_CHAIN_PARAM_ERR;
        }
        size_t l_total_tsd_size = dap_tsd_calc_list_size(l_tsd_list);
        l_datum_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
        l_datum_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
        l_datum_decree->header.ts_created = dap_time_now();
        l_datum_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
        l_datum_decree->header.common_decree_params.net_id = dap_chain_net_id_by_name(l_net_str);
        l_datum_decree->header.common_decree_params.chain_id = l_decree_chain->id;
        l_datum_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(l_net);
        l_datum_decree->header.sub_type = l_subtype;
        l_datum_decree->header.data_size = l_total_tsd_size;
        l_datum_decree->header.signs_size = 0;

        dap_tsd_fill_from_list(l_datum_decree->data_n_signs, l_tsd_list);
        dap_list_free_full(l_tsd_list, NULL);

        // Sign decree
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_datum_decree, l_certs_count, &l_total_signs_success);

        if (!l_datum_decree || l_total_signs_success == 0){
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NO_CERT_ERR,
                                        "Decree creation failed. Successful count of certificate signing is 0");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_CREATE_NO_CERT_ERR;
        }

        // Create datum
        dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                             l_datum_decree,
                                                             sizeof(*l_datum_decree) + l_datum_decree->header.data_size +
                                                             l_datum_decree->header.signs_size);
        DAP_DELETE(l_datum_decree);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        json_object* json_obj_status = json_object_new_object();
        if (!json_obj_status) return dap_json_rpc_allocation_put_error(json_obj_status);
        json_object_object_add(json_obj_status, "datum_status", l_key_str_out ? json_object_new_string(l_key_str_out) :
                                                                                json_object_new_string("not_placed"));
        json_object_array_add(*a_json_arr_reply, json_obj_status);
        break;
    }
    case CMD_SIGN:{
        if(!l_certs_count) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_NO_VALID_CERT_ERR,
                                            "decree sign command requres at least one valid certificate to sign");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_NO_VALID_CERT_ERR;
        }

        const char * l_datum_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
        if(l_datum_hash_str) {
            char * l_datum_hash_hex_str = NULL;
            char * l_datum_hash_base58_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
            // Search chain
            if(l_chain_str) {
                if (!( l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str) )) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_INVALID_CHAIN_PARAM_ERR,
                        "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                        "Available chain with decree support:\n\t\"%s\"\n",
                        l_chain_str, l_net_str,
                        dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)->name);
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_INVALID_CHAIN_PARAM_ERR;
                } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)){ // check chain to support decree
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CHAIN_DONT_SUPPORT_ERR,
                                                "Chain %s don't support decree", l_chain->name);
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CHAIN_DONT_SUPPORT_ERR;
                }
            } else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CANT_FIND_CHAIN_ERR,
                                                "Can't find chain with decree support.");
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CANT_FIND_CHAIN_ERR;
            }

            char * l_gdb_group_mempool = dap_chain_mempool_group_new(l_chain);
            if(!l_gdb_group_mempool) {
                l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_DECREE);
            }
            // datum hash may be in hex or base58 format
            if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
                l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
                l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
            } else {
                l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
                l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
            }

            const char *l_datum_hash_out_str;
            if(!dap_strcmp(l_hash_out_type,"hex"))
                l_datum_hash_out_str = l_datum_hash_hex_str;
            else
                l_datum_hash_out_str = l_datum_hash_base58_str;

            log_it(L_DEBUG, "Requested to sign decree creation %s in gdb://%s with certs %s",
                    l_gdb_group_mempool, l_datum_hash_hex_str, l_certs_str);

            dap_chain_datum_t * l_datum = NULL;
            size_t l_datum_size = 0;
            if((l_datum = (dap_chain_datum_t*) dap_global_db_get_sync(l_gdb_group_mempool,
                    l_datum_hash_hex_str, &l_datum_size, NULL, NULL )) != NULL) {
                // Check if its decree creation
                if(l_datum->header.type_id == DAP_CHAIN_DATUM_DECREE) {
                    dap_chain_datum_decree_t *l_datum_decree = DAP_DUP_SIZE((dap_chain_datum_decree_t*)l_datum->data, l_datum->header.data_size);    // for realloc
                    DAP_DELETE(l_datum);

                    // Sign decree
                    size_t l_total_signs_success = 0;
                    if (l_certs_count)
                        l_datum_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_datum_decree, l_certs_count, &l_total_signs_success);

                    if (!l_datum_decree || l_total_signs_success == 0){
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CREATION_ERR,
                                                    "Decree creation failed. Successful count of certificate signing is 0");
                        return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CREATION_ERR;
                    }
                    size_t l_decree_size = dap_chain_datum_decree_get_size(l_datum_decree);
                    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                                         l_datum_decree, l_decree_size);
                    DAP_DELETE(l_datum_decree);

                    char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
                    DAP_DELETE(l_datum);

                    json_object* json_obj_status = json_object_new_object();
                    if (!json_obj_status) return dap_json_rpc_allocation_put_error(json_obj_status);
                    json_object_object_add(json_obj_status, "datum_status", l_key_str_out ? json_object_new_string(l_key_str_out) :
                                                                                            json_object_new_string("not_placed"));
                    json_object_array_add(*a_json_arr_reply, json_obj_status);
                } else {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_WRONG_DATUM_TYPE_ERR,
                                            "Error! Wrong datum type. decree sign only decree datum");
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_WRONG_DATUM_TYPE_ERR;                    
                }
            } else{
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CANT_FIND_DATUM_ERR,
                    "decree sign can't find datum with %s hash in the mempool of %s:%s",
                    l_datum_hash_out_str,l_net? l_net->pub.name: "<undefined>",
                    l_chain?l_chain->name:"<undefined>");
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_CANT_FIND_DATUM_ERR;
            }
            DAP_DELETE(l_datum_hash_hex_str);
            DAP_DELETE(l_datum_hash_base58_str);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_NEED_SIGN_ERR,
                                            "decree sign need -datum <datum hash> argument");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_SIGN_NEED_SIGN_ERR;
        }
        break;
    }
    case CMD_ANCHOR:{
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

        // Search chain
        if(l_chain_str) {
            if (!( l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str) )) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_INVALID_CHAIN_PARAM_ERR,
                                            "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                            "Available chain with anchor support:\n\t\"%s\"\n",
                                            l_chain_str, l_net_str,
                                            dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)->name);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_INVALID_CHAIN_PARAM_ERR;
            } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)){ // check chain to support decree
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_CHAIN_DONT_SUPPORT_ERR,
                                            "Chain %s don't support decree", l_chain->name);
                return -DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_CHAIN_DONT_SUPPORT_ERR;
            }
        }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)) == NULL) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_CANT_FIND_CHAIN_ERR,
                                                        "Can't find chain with default anchor support.");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_CANT_FIND_CHAIN_ERR;
        }

        dap_chain_datum_anchor_t *l_datum_anchor = NULL;
        dap_hash_fast_t l_hash = {};
        const char * l_datum_hash_str = NULL;
        if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str))
        {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_NOT_DATUM_PARAM_ERR,
                                    "Anchor creation failed. Cmd decree create anchor must contain -datum parameter.");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_NOT_DATUM_PARAM_ERR;
        }
        if(l_datum_hash_str) {
            dap_chain_hash_fast_from_str(l_datum_hash_str, &l_hash);
        }

        // Pack data into TSD
        dap_tsd_t *l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH, &l_hash, sizeof(dap_hash_fast_t));
        if(!l_tsd)
        {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_MEMORY_ERR,
                                        "Anchor creation failed. Memory allocation fail.");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_MEMORY_ERR;
        }

        // Create anchor datum
        l_datum_anchor = DAP_NEW_Z_SIZE(dap_chain_datum_anchor_t, sizeof(dap_chain_datum_anchor_t) + dap_tsd_size(l_tsd));
        l_datum_anchor->header.data_size = dap_tsd_size(l_tsd);
        l_datum_anchor->header.ts_created = dap_time_now();
        memcpy(l_datum_anchor->data_n_sign, l_tsd, dap_tsd_size(l_tsd));

        DAP_DELETE(l_tsd);

        // Sign anchor
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_anchor = s_sign_anchor_in_cycle(l_certs, l_datum_anchor, l_certs_count, &l_total_signs_success);

        if (!l_datum_anchor || !l_total_signs_success) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_CERT_SIGN_ERR,
                                    "Anchor creation failed. Successful count of certificate signing is 0");
            return DAP_DELETE(l_datum_anchor), -DAP_CHAIN_NODE_CLI_COM_DECREE_ANCHOR_CERT_SIGN_ERR;
        }

        // Create datum
        dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_ANCHOR,
                                                             l_datum_anchor,
                                                             sizeof(*l_datum_anchor) + l_datum_anchor->header.data_size +
                                                             l_datum_anchor->header.signs_size);
        DAP_DELETE(l_datum_anchor);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        json_object* json_obj_status = json_object_new_object();
        if (!json_obj_status) return dap_json_rpc_allocation_put_error(json_obj_status);
        json_object_object_add(json_obj_status, "datum_status", l_key_str_out ? json_object_new_string(l_key_str_out) :
                                                                                json_object_new_string("not_placed"));
        json_object_array_add(*a_json_arr_reply, json_obj_status);
        break;
    }
    case CMD_FIND: {
        const char *l_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
        if (!l_hash_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_FIND_REQ_PARAM_HASH_ERR,
                                                            "Command 'decree find' requiers parameter '-hash'");
            return -DAP_CHAIN_NODE_CLI_COM_DECREE_FIND_REQ_PARAM_HASH_ERR;
        }
        dap_hash_fast_t l_datum_hash;
        if (dap_chain_hash_fast_from_hex_str(l_hash_str, &l_datum_hash) &&
                dap_chain_hash_fast_from_base58_str(l_hash_str, &l_datum_hash)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_FIND_REQ_PARAM_VALUE_ERR,
                                                            "Can't convert '-hash' parameter to numeric value");
                    return -DAP_CHAIN_NODE_CLI_COM_DECREE_FIND_REQ_PARAM_VALUE_ERR;
        }
        bool l_applied = false;
        dap_chain_datum_decree_t *l_decree = dap_ledger_decree_get_by_hash(l_net, &l_datum_hash, &l_applied);
        json_object* json_obj_status = json_object_new_object();
        if (!json_obj_status) return dap_json_rpc_allocation_put_error(json_obj_status);
        json_object_object_add(json_obj_status, "find_status", l_decree ? (l_applied ? json_object_new_string("applied") :
                                                                                       json_object_new_string("not_applied")) :
                                                                                json_object_new_string("not_found"));
        json_object_array_add(*a_json_arr_reply, json_obj_status);
    } break;
    case CMD_INFO: {
        json_object* json_obj_out = json_object_new_object();
        if (!json_obj_out) return dap_json_rpc_allocation_put_error(json_obj_out);
        json_object* json_obj_array = json_object_new_array();
        if (!json_obj_array) return dap_json_rpc_allocation_put_error(json_obj_out);
        json_object_object_add(json_obj_out, "owners", json_obj_array);
        const dap_list_t *l_decree_pkeys = dap_ledger_decree_get_owners_pkeys(l_net->pub.ledger);
        int i = 0;
        dap_hash_fast_t l_pkey_hash = {};
        for (const dap_list_t *it = l_decree_pkeys; it; it = it->next) {
            dap_pkey_t *l_pkey = it->data;
            dap_pkey_get_hash(l_pkey, &l_pkey_hash);
            json_object* json_obj_owner = json_object_new_object();
            if (!json_obj_owner) return dap_json_rpc_allocation_put_error(json_obj_out);
            json_object_object_add(json_obj_owner, "num", json_object_new_int(i));
            json_object_object_add(json_obj_owner, "pkey_hash", json_object_new_string(dap_hash_fast_to_str_static(&l_pkey_hash)));
            i++;
            json_object_array_add(json_obj_array, json_obj_owner);
        }
        json_object_object_add(json_obj_out, "owners_total", json_object_new_int(dap_ledger_decree_get_num_of_owners(l_net->pub.ledger)));
        json_object_object_add(json_obj_out, "min_owners", json_object_new_int(dap_ledger_decree_get_min_num_of_signers(l_net->pub.ledger)));
        json_object_array_add(*a_json_arr_reply, json_obj_out);
    } break;
    default:
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_DECREE_NOT_FOUND_COM_ERR,
                                    "Not found decree action. Use create, sign, anchor or find parameter");
        return -1;
    }

    return 0;
}

/**
 * @brief stats command
 *
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_stats(int argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum {
        CMD_NONE, CMD_STATS_CPU
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    // find  add parameter ('cpu')
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(argc, arg_index + 1), "cpu", NULL)) {
        cmd_num = CMD_STATS_CPU;
    }
    switch (cmd_num) {
    case CMD_NONE:
    default:
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_STATS_WRONG_FORMAT_ERR,
                        "format of command: stats cpu");
        return -DAP_CHAIN_NODE_CLI_COM_STATS_WRONG_FORMAT_ERR;
    case CMD_STATS_CPU:
#if (defined DAP_OS_UNIX) || (defined __WIN32)
    {
        dap_cpu_monitor_init();
        dap_usleep(500000);
        json_object* json_arr_cpu_out = json_object_new_array();
        char *l_str_delimiter;
        char *l_str_cpu_num;
        dap_cpu_stats_t s_cpu_stats = dap_cpu_get_stats();
        for (uint32_t n_cpu_num = 0; n_cpu_num < s_cpu_stats.cpu_cores_count; n_cpu_num++) {
            json_object* json_obj_cpu = json_object_new_object();
            l_str_cpu_num = dap_strdup_printf("CPU-%d", n_cpu_num);
            l_str_delimiter = dap_strdup_printf("%f%%", s_cpu_stats.cpus[n_cpu_num].load);
            json_object_object_add(json_obj_cpu, l_str_cpu_num, json_object_new_string(l_str_delimiter));
            json_object_array_add(json_arr_cpu_out, json_obj_cpu);
            DAP_DELETE(l_str_cpu_num);
            DAP_DELETE(l_str_delimiter);
        }
        json_object* json_obj_total = json_object_new_object();
        l_str_delimiter = dap_strdup_printf("%f%%", s_cpu_stats.cpu_summary.load);
        json_object_object_add(json_obj_total, "total", json_object_new_string(l_str_delimiter));
        json_object_array_add(json_arr_cpu_out, json_obj_total);
        DAP_DELETE(l_str_delimiter);
        json_object_array_add(*a_json_arr_reply, json_arr_cpu_out);
        break;
    }
#else
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_STATS_BAD_SYS_ERR,
                        "only Linux or Windows environment supported");
        return -1;
#endif // DAP_OS_UNIX
    }
    return DAP_CHAIN_NODE_CLI_COM_STATS_OK;
}

/**
 * @brief com_exit
 *
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_exit(int a_argc, char **a_argv, void **a_str_reply)
{
    UNUSED(a_argc);
    UNUSED(a_argv);
    UNUSED(a_str_reply);
    //dap_events_stop_all();
    exit(0);
    return 0;
}

/**
 * @brief cmd_gdb_export
 * action for cellframe-node-cli gdb_export command
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
int cmd_gdb_export(int a_argc, char **a_argv, void **a_str_reply)
{
    int arg_index = 1;
    const char *l_filename = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "filename", &l_filename);
    if (!l_filename) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "gdb_export requires parameter 'filename'");
        return -1;
    }
    const char *l_gdb_path = dap_config_get_item_str(g_config, "global_db", "path");
    if (!l_gdb_path) {
        log_it(L_ERROR, "Can't find gdb path in config file");
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find gdb path in the config file");
        return -1;
    }
    if (!opendir(l_gdb_path)) {
        log_it(L_ERROR, "Can't open db directory");
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't open db directory");
        return -1;
    }
    char l_path[MAX_PATH + 1];
    snprintf(l_path, sizeof(l_path), "%s/%s.json", l_gdb_path, l_filename);

    const char *l_groups_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-groups", &l_groups_str);
    char *l_group_str = NULL, *l_ctx = NULL;
    dap_list_t *l_parsed_groups_list = NULL;
    if (l_groups_str) {
        char *l_tmp_str = dap_strdup(l_groups_str);
        l_group_str = strtok_r(l_tmp_str, ",", &l_ctx);
        for (; l_group_str; l_group_str = strtok_r(NULL, ",", &l_ctx)) {
            l_parsed_groups_list = dap_list_prepend(l_parsed_groups_list, dap_strdup(l_group_str));
        }
        DAP_DEL_Z(l_tmp_str);
    }
    struct json_object *l_json = json_object_new_array();
    dap_list_t *l_groups_list = l_parsed_groups_list
            ? l_parsed_groups_list
            : dap_global_db_driver_get_groups_by_mask("*");
    for (dap_list_t *l_list = l_groups_list; l_list; l_list = dap_list_next(l_list)) {
        size_t l_store_obj_count = 0;
        char *l_group_name = (char *)l_list->data;

        dap_store_obj_t *l_store_obj = dap_global_db_get_all_raw_sync(l_group_name, &l_store_obj_count);

        if (!l_store_obj_count) {
            log_it(L_INFO, "Group %s is empty or not found", l_group_name);
            continue;
        } else {
            log_it(L_INFO, "Exporting group %s, number of records: %zu", l_group_name, l_store_obj_count);
        }

        struct json_object *l_json_group = json_object_new_array();
        struct json_object *l_json_group_inner = json_object_new_object();
        json_object_object_add(l_json_group_inner, "group", json_object_new_string(l_group_name));

        for (size_t i = 0; i < l_store_obj_count; ++i) {
            size_t l_out_size = DAP_ENC_BASE64_ENCODE_SIZE((int64_t)l_store_obj[i].value_len) + 1;
            dap_sign_t *l_sign = l_store_obj[i].sign;
            size_t l_sign_size = DAP_ENC_BASE64_ENCODE_SIZE(dap_sign_get_size(l_sign))+1;
            char *l_value_enc_str = DAP_NEW_Z_SIZE(char, l_out_size);
            char *l_sign_str = DAP_NEW_Z_SIZE(char, l_sign_size);
            if(!l_value_enc_str || !l_sign_str) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                DAP_DEL_Z(l_sign_str);
                DAP_DEL_Z(l_value_enc_str);
                return -1;
            }
            dap_enc_base64_encode(l_store_obj[i].value, l_store_obj[i].value_len, l_value_enc_str, DAP_ENC_DATA_TYPE_B64);
            dap_enc_base64_encode(l_sign, dap_sign_get_size(l_sign), l_sign_str, DAP_ENC_DATA_TYPE_B64);
            struct json_object *jobj = json_object_new_object();
            json_object_object_add(jobj, "key",     json_object_new_string(l_store_obj[i].key));
            json_object_object_add(jobj, "value",   json_object_new_string(l_value_enc_str));
            json_object_object_add(jobj, "value_len", json_object_new_int64((int64_t)l_store_obj[i].value_len));
            json_object_object_add(jobj, "flags", json_object_new_uint64((uint64_t)l_store_obj[i].flags));
            json_object_object_add(jobj, "sign", json_object_new_string(l_sign_str));
            json_object_object_add(jobj, "timestamp", json_object_new_int64((int64_t)l_store_obj[i].timestamp));
            json_object_object_add(jobj, "crc", json_object_new_uint64(l_store_obj[i].crc));
            json_object_array_add(l_json_group, jobj);

            DAP_DELETE(l_value_enc_str);
        }
        json_object_object_add(l_json_group_inner, "records", l_json_group);
        json_object_array_add(l_json, l_json_group_inner);
        dap_store_obj_free(l_store_obj, l_store_obj_count);
    }
    if (l_parsed_groups_list)
        dap_list_free_full(l_groups_list, NULL);
    if (json_object_to_file(l_path, l_json) == -1) {
#if JSON_C_MINOR_VERSION<15
        log_it(L_CRITICAL, "Couldn't export JSON to file, error code %d", errno );
        dap_cli_server_cmd_set_reply_text (a_str_reply, "Couldn't export JSON to file, error code %d", errno );
#else
        log_it(L_CRITICAL, "Couldn't export JSON to file, err '%s'", json_util_get_last_err());
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", json_util_get_last_err());
#endif
         json_object_put(l_json);
         return -1;
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Global DB export in file %s", l_path);
    json_object_put(l_json);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Global DB export in file %s", l_path);
    return 0;
}

/**
 * @brief cmd_gdb_import
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
int cmd_gdb_import(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    int arg_index = 1;
    const char *l_filename = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "filename", &l_filename);
    if (!l_filename) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GDB_IMPORT_REQUIRES_PARAMETER_FILENAME, 
                                                        "gdb_import requires parameter 'filename'");
        return -DAP_CHAIN_NODE_CLI_COM_GDB_IMPORT_REQUIRES_PARAMETER_FILENAME;
    }
    const char *l_gdb_path = dap_config_get_item_str(g_config, "global_db", "path");
    if (!l_gdb_path) {
        log_it(L_ERROR, "Can't find gdb path in config file");
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GDB_IMPORT_CANT_FIND_GDB_PATH_ERR, 
                                                        "Can't find gdb path in the config file");
        return -DAP_CHAIN_NODE_CLI_COM_GDB_IMPORT_CANT_FIND_GDB_PATH_ERR;
    }
    char l_path[MAX_PATH + 1];
    snprintf(l_path, sizeof(l_path), "%s/%s.json", l_gdb_path, l_filename);
    struct json_object *l_json = json_object_from_file(l_path);
    if (!l_json) {
#if JSON_C_MINOR_VERSION<15
        log_it(L_CRITICAL, "Import error occured: code %d", errno);
        dap_json_rpc_error_add(*a_json_arr_reply, "Import error occured: code %d",errno);
#else
        log_it(L_CRITICAL, "Import error occured: %s", json_util_get_last_err());
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GENERAL_ERR, 
                                                        "%s", json_util_get_last_err());
#endif
        return -1;
    }
    for (size_t i = 0, l_groups_count = json_object_array_length(l_json); i < l_groups_count; ++i) {
        struct json_object *l_group_obj = json_object_array_get_idx(l_json, i);
        if (!l_group_obj) {
            continue;
        }
        struct json_object *l_json_group_name = json_object_object_get(l_group_obj, "group");
        const char *l_group_name = json_object_get_string(l_json_group_name);
        // proc group name
        log_it(L_INFO, "Group %zu: %s", i, l_group_name);
        struct json_object *l_json_records = json_object_object_get(l_group_obj, "records");
        size_t l_records_count = json_object_array_length(l_json_records);
        dap_store_obj_t *l_group_store = DAP_NEW_Z_SIZE(dap_store_obj_t, l_records_count * sizeof(dap_store_obj_t));
        if(!l_group_store) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -1;
        }
        for (size_t j = 0; j < l_records_count; ++j) {
            struct json_object *l_record, *l_key, *l_value, *l_value_len, *l_ts;
            l_record = json_object_array_get_idx(l_json_records, j);
            l_key       = json_object_object_get(l_record, "key");
            l_value     = json_object_object_get(l_record, "value");
            size_t l_record_size = json_object_object_length(l_record);
            l_value_len = json_object_object_get(l_record, "value_len");
            l_ts        = json_object_object_get(l_record, "timestamp");
            l_group_store[j].key    = dap_strdup(json_object_get_string(l_key));
            if(!l_group_store[j].key) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_records_count = j;
                break;
            }
            l_group_store[j].group  = dap_strdup(l_group_name);
            if(!l_group_store[j].group) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_records_count = j;
                break;
            }
            dap_nanotime_t l_temp = json_object_get_int64(l_ts);
            l_group_store[j].timestamp = l_temp >> 32 ? l_temp : dap_nanotime_from_sec(l_temp);  // possibly legacy record
            l_group_store[j].value_len = (uint64_t)json_object_get_int64(l_value_len);

            const char *l_value_str = json_object_get_string(l_value);
            char *l_val = DAP_NEW_Z_SIZE(char, l_group_store[j].value_len);
            if(!l_val) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_records_count = j;
                break;
            }
            dap_enc_base64_decode(l_value_str, strlen(l_value_str), l_val, DAP_ENC_DATA_TYPE_B64);
            l_group_store[j].value  = (uint8_t*)l_val;
            if (l_record_size > 5) {
                json_object *l_jobj_crc = json_object_object_get(l_record, "crc");
                json_object *l_jobj_sign = json_object_object_get(l_record, "sign");
                json_object *l_jobj_flags = json_object_object_get(l_record, "flags");
                uint8_t l_flags = (uint8_t)json_object_get_uint64(l_jobj_flags);
                uint64_t l_crc = json_object_get_uint64(l_jobj_crc);
                const char *l_sign_str = json_object_get_string(l_jobj_sign);
                int l_len = dap_strlen(l_sign_str);
                dap_sign_t *l_sign = DAP_NEW_Z_SIZE(dap_sign_t, DAP_ENC_BASE64_DECODE_SIZE(l_len) + 1);
                size_t l_sign_decree_size = dap_enc_base64_decode(l_sign_str, l_len, l_sign, DAP_ENC_DATA_TYPE_B64);
                if (dap_sign_get_size(l_sign) != l_sign_decree_size) {
                    log_it(L_ERROR, "Can't reade signature from record with key %s", l_group_store[j].key);
                }
                l_group_store[j].sign = l_sign;
                l_group_store[j].flags = l_flags;
                l_group_store[j].crc = l_crc;
            } else {
                //Loading old record
                dap_cert_t *l_cert_record = dap_cert_find_by_name(DAP_STREAM_NODE_ADDR_CERT_NAME);
                l_group_store[j].sign = dap_store_obj_sign(&l_group_store[j], l_cert_record->enc_key, &l_group_store[j].crc);
            }
        }
        if (dap_global_db_driver_apply(l_group_store, l_records_count)) {
            log_it(L_CRITICAL, "An error occured on importing group %s...", l_group_name);
        } else {
            log_it(L_INFO, "Imported %zu records of group %s", l_records_count, l_group_name);
        }
        dap_store_obj_free(l_group_store, l_records_count);
    }
    json_object_put(l_json);
    return 0;
}

dap_list_t *s_go_all_nets_offline()
{
    dap_list_t *l_net_returns = NULL;
    for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
        if ( dap_chain_net_stop(it) )
            l_net_returns = dap_list_append(l_net_returns, it);
    }
    return l_net_returns;
}

typedef struct _pvt_net_nodes_list {
    dap_chain_net_t *net;
    dap_global_db_obj_t *group_nodes;
    size_t count_nodes;
} _pvt_net_nodes_list_t;

int cmd_remove(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    //default init
    const char		*return_message	=	NULL;
    const char		*l_gdb_path		=	NULL;
//    const char		*l_chains_path	=	NULL;
    const char		*l_net_str		=	NULL;
    dap_chain_net_t	*l_net			=	NULL;
    int 			all				=	0;

    //for enum
    uint8_t			error			=	0;
    uint8_t			successful		=	0;

    //enum for errors
    enum {
        GDB_FAIL_PATH				=	0x00000001,
        CHAINS_FAIL_PATH			=	0x00000002,
        COMMAND_NOT_CORRECT			=	0x00000004,
        NET_NOT_VALID				=	0x00000008
    };

    //enum for successful
    enum {
        REMOVED_GDB					=	0x00000001,
        REMOVED_CHAINS				=	0x00000002
    };

    //check path's from config file
    if (dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "-gdb") >= 0
    &&	(NULL == (l_gdb_path = dap_config_get_item_str(g_config, "global_db", "path")))){
        error |= GDB_FAIL_PATH;
    }
//    if (dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "-chains") >= 0
//    &&	(NULL == (l_chains_path = dap_config_get_item_str(g_config, "resources", "dap_chains_path")))) {
//        error |= CHAINS_FAIL_PATH;
//    }

    dap_list_t *l_net_returns = NULL;
    //perform deletion according to the specified parameters, if the path is specified
    if (l_gdb_path) {
        l_net_returns = s_go_all_nets_offline();
        dap_list_t *l_gdb_nodes_list = NULL;
        for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
            _pvt_net_nodes_list_t *l_gdb_groups = DAP_NEW(_pvt_net_nodes_list_t);
            if (!l_gdb_groups) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_list_free(l_net_returns);
                return -1;
            }
            l_gdb_groups->net = it;
            l_gdb_groups->group_nodes = dap_global_db_get_all_sync(l_gdb_groups->net->pub.gdb_nodes, &l_gdb_groups->count_nodes);
            l_gdb_nodes_list = dap_list_append(l_gdb_nodes_list, l_gdb_groups);
        }

        dap_list_t *l_group_list = dap_global_db_driver_get_groups_by_mask("*");
        for (dap_list_t *l_list = l_group_list; l_list; l_list = dap_list_next(l_list)) {
            dap_global_db_erase_table_sync((const char *)(l_list->data));
        }
        dap_list_free_full(l_group_list, NULL);
        uint32_t l_version = DAP_GLOBAL_DB_VERSION;
        if ( (error = dap_global_db_set_sync(DAP_GLOBAL_DB_LOCAL_GENERAL, "gdb_version", &l_version, sizeof(l_version), false)) )
            log_it(L_ERROR, "Can't add information about gdb_version");

        for (dap_list_t *ptr = l_gdb_nodes_list; ptr; ptr = dap_list_next(ptr)) {
            _pvt_net_nodes_list_t *l_tmp = (_pvt_net_nodes_list_t*)ptr->data;
            for (size_t i = 0; i < l_tmp->count_nodes; i++) {
                dap_global_db_obj_t l_obj = l_tmp->group_nodes[i];
                dap_global_db_set_sync(l_tmp->net->pub.gdb_nodes, l_obj.key, l_obj.value, l_obj.value_len, false);
            }
            dap_global_db_objs_delete(l_tmp->group_nodes, l_tmp->count_nodes);
        }
        dap_list_free_full(l_gdb_nodes_list, NULL);
        if (!error)
            successful |= REMOVED_GDB;
    }

    if (dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "-chains") != -1) {
        dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-net", &l_net_str);
        all = dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "-all");

        if	(NULL == l_net_str && all >= 0) {
            if (NULL == l_gdb_path)
                l_net_returns = s_go_all_nets_offline();
            for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
                dap_chain_net_purge(it);
            }
            if (!error)
                successful |= REMOVED_CHAINS;
        } else if (NULL != l_net_str && all < 0) {
            if (NULL != (l_net = dap_chain_net_by_name(l_net_str))) {
                if (NULL == l_gdb_path && dap_chain_net_stop(l_net))
                    l_net_returns = dap_list_append(l_net_returns, l_net);
            } else {
                error |= NET_NOT_VALID;
            }
            dap_chain_net_purge(l_net);
            if (!error)
                successful |= REMOVED_CHAINS;

        } else {
            error |= COMMAND_NOT_CORRECT;
        }
    }

    //handling errors
    if (error & GDB_FAIL_PATH
    ||	error & CHAINS_FAIL_PATH) {
        return_message = "The node configuration file does not specify the path to the database and/or chains.\n"
                         "Please check the cellframe-node.cfg file in the [resources] item for subitems:\n"
                         "dap_global_db_path=<PATH>\n"
                         "dap_chains_path=<PATH>";
    } else if (error & COMMAND_NOT_CORRECT) {
        return_message = "You need to make a decision whether to remove all chains or a chain from a specific network.\n"
                         "You cannot use two keys '-net' and '-all' at the same time.\n"
                         "Be careful, the '-all' option will delete ALL CHAINS and won't ask you for permission!";
    } else if (error & NET_NOT_VALID) {
        return_message = "The specified network was not found.\n"
                         "The list of available networks can be viewed using the command:"
                         "'net list'";
    }

    json_object* json_obj_out;
    char *l_out_mes;
    if (error) {
       dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_REMOVE_GENERAL_ERR, "Error when deleting, because:\n%s", return_message);
    }
    else if (successful) {
        json_obj_out = json_object_new_object();
        l_out_mes = dap_strdup_printf("Successful removal: %s", successful & REMOVED_GDB && successful & REMOVED_CHAINS ? "gdb, chains" : successful & REMOVED_GDB ? "gdb" : successful & REMOVED_CHAINS ? "chains" : "");
        json_object_object_add(json_obj_out, "status", json_object_new_string(l_out_mes));
        DAP_DELETE(l_out_mes);
        json_object_array_add(*a_json_arr_reply,json_obj_out);
    } else {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_REMOVE_NOTHING_TO_DEL_ERR, 
                                                    "Nothing to delete. Check if the command is correct.\nUse flags: -gdb or/and -chains [-net <net_name> | -all]\n"
                                                    "Be careful, the '-all' option will delete ALL CHAINS and won't ask you for permission!");
    }

    for (dap_list_t *it = l_net_returns; it; it = it->next)
        dap_chain_net_start((dap_chain_net_t *)it->data);
    dap_list_free(l_net_returns);

    return error;
}


/*
 * block code signer
 */
/*
 * enum for dap_chain_sign_file
 */
typedef enum {
    SIGNER_ALL_FLAGS             = 0x1f,
    SIGNER_FILENAME              = 1 << 0,   // flag - full filename
    SIGNER_FILENAME_SHORT        = 1 << 1,   // flag - filename without extension
    SIGNER_FILESIZE              = 1 << 2,   // flag - size of file
    SIGNER_DATE                  = 1 << 3,   // flag - date
    SIGNER_MIME_MAGIC            = 1 << 4,   // flag - mime magic
    SIGNER_COUNT                 = 5         // count flags
} dap_sign_signer_file_t;

static int s_sign_file(const char *a_filename, dap_sign_signer_file_t a_flags, const char *a_cert_name,
                       dap_sign_t **a_signed, dap_chain_hash_fast_t *a_hash);
static int s_signer_cmd(int a_arg_index, int a_argc, char **a_argv, void **a_str_reply);
static int s_check_cmd(int a_arg_index, int a_argc, char **a_argv, void **a_str_reply);
struct opts {
    char *name;
    uint32_t cmd;
};

#define BUILD_BUG(condition) ((void)sizeof(char[1-2*!!(condition)]))

int com_signer(int a_argc, char **a_argv, void **a_str_reply)
{
    enum {
        CMD_NONE, CMD_SIGN, CMD_CHECK
    };

    int arg_index = 1;
    int cmd_num = CMD_NONE;

    struct opts l_opts[] = {
    { "sign", CMD_SIGN },
    { "check", CMD_CHECK }
    };

    size_t l_len_opts = sizeof(l_opts) / sizeof(struct opts);
    for (size_t i = 0; i < l_len_opts; i++) {
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), l_opts[i].name, NULL)) {
            cmd_num = l_opts[i].cmd;
            break;
        }
    }

    if(cmd_num == CMD_NONE) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "command %s not recognized", a_argv[1]);
        return -1;
    }
    switch (cmd_num) {
    case CMD_SIGN:
        return s_signer_cmd(arg_index, a_argc, a_argv, a_str_reply);
        break;
    case CMD_CHECK:
        return s_check_cmd(arg_index, a_argc, a_argv, a_str_reply);
        break;
    }

    return -1;
}

static int s_get_key_from_file(const char *a_file, const char *a_mime, const char *a_cert_name, dap_sign_t **a_sign);

static int s_check_cmd(int a_arg_index, int a_argc, char **a_argv, void **a_str_reply)
{
    int l_ret = 0;

    enum {OPT_FILE, OPT_HASH, OPT_NET, OPT_MIME, OPT_CERT,
          OPT_COUNT};
    struct opts l_opts_check[] = {
    { "-file", OPT_FILE },
    { "-hash", OPT_HASH },
    { "-net", OPT_NET },
    { "-mime", OPT_MIME },
    { "-cert", OPT_CERT }
    };

    BUILD_BUG((sizeof(l_opts_check)/sizeof(struct opts)) != OPT_COUNT);

    char *l_str_opts_check[OPT_COUNT] = {0};
    for (int i = 0; i < OPT_COUNT; i++) {
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, l_opts_check[i].name, (const char **) &l_str_opts_check[i]);
    }

    if (!l_str_opts_check[OPT_CERT]) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s need to be selected", l_opts_check[OPT_CERT].name);
        return -1;
    }
    if (l_str_opts_check[OPT_HASH] && l_str_opts_check[OPT_FILE]) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "you can select is only one from (file or hash)");
        return -1;
    }

    dap_chain_net_t *l_network = dap_chain_net_by_name(l_str_opts_check[OPT_NET]);
    if (!l_network) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s network not found", l_str_opts_check[OPT_NET]);
        return -1;
    }


    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(l_network, CHAIN_TYPE_SIGNER);
    if (!l_chain) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Not found datum signer in network %s", l_str_opts_check[OPT_NET]);
        return -1;
    }
    int found = 0;

    dap_sign_t *l_sign = NULL;
    dap_chain_datum_t *l_datum = NULL;
    char *l_gdb_group = NULL;

    l_gdb_group = dap_chain_mempool_group_new(l_chain);
    if (!l_gdb_group) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Not found network group for chain: %s", l_chain->name);
        l_ret = -1;
        goto end;
    }

    dap_chain_hash_fast_t l_hash_tmp;

    if (l_str_opts_check[OPT_HASH]) {
        dap_chain_hash_fast_from_str(l_str_opts_check[OPT_HASH], &l_hash_tmp);
    }


    if (l_str_opts_check[OPT_FILE]) {
        if ( s_get_key_from_file(l_str_opts_check[OPT_FILE], l_str_opts_check[OPT_MIME], l_str_opts_check[OPT_CERT], &l_sign) ) {
            l_ret = -1;
            goto end;
        }

        l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_SIGNER, l_sign->pkey_n_sign, l_sign->header.sign_size);
        if (!l_datum) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "not created datum");
            l_ret = -1;
            goto end;
        }

        dap_chain_datum_calc_hash(l_datum, &l_hash_tmp);
    }

    dap_chain_atom_iter_t *l_iter = NULL;
    dap_chain_cell_t *l_cell_tmp = NULL;
    dap_chain_cell_t *l_cell = NULL;
    size_t l_atom_size = 0, l_datums_count = 0;

    HASH_ITER(hh, l_chain->cells, l_cell, l_cell_tmp) {
        l_iter = l_cell->chain->callback_atom_iter_create(l_cell->chain, l_cell->id, NULL);
        dap_chain_atom_ptr_t l_atom = l_cell->chain->callback_atom_find_by_hash(l_iter, &l_hash_tmp, &l_atom_size);
        dap_chain_datum_t **l_datums = l_cell->chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
        for (size_t i = 0; i < l_datums_count; i++) {
            dap_chain_datum_t *l_datum = l_datums[i];
            dap_hash_fast_t l_hash;
            dap_chain_datum_calc_hash(l_datum, &l_hash);
            if (!memcmp(l_hash_tmp.raw, l_hash.raw, DAP_CHAIN_HASH_FAST_SIZE)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "found!");
                found = 1;
                break;
            }
        }
        DAP_DEL_Z(l_datums);
        l_cell->chain->callback_atom_iter_delete(l_iter);
    }

end:

    DAP_DEL_Z(l_gdb_group);

    if (!found) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not found!");
    }

    return l_ret;
}

static char **s_parse_items(const char *a_str, char a_delimiter, int *a_count, const int a_only_digit)
{
    int l_count_temp = *a_count = 0;
    int l_len_str = strlen(a_str);
    if (l_len_str == 0) return NULL;
    char *s, *l_temp_str;
    s = l_temp_str = dap_strdup(a_str);

    int l_buf = 0;
    for (int i = 0; i < l_len_str; i++) {
        if (s[i] == a_delimiter && !l_buf) {
            s[i] = 0;
            continue;
        }
        if (s[i] == a_delimiter && l_buf) {
            s[i] = 0;
            l_buf = 0;
            continue;
        }
        if (!dap_is_alpha(s[i]) && l_buf) {
            s[i] = 0;
            l_buf = 0;
            continue;
        }
        if (!dap_is_alpha(s[i]) && !l_buf) {
            s[i] = 0;
            continue;
        }
        if (a_only_digit) {
            if (dap_is_digit(s[i])) {
                l_buf++;
                if (l_buf == 1) l_count_temp++;
                continue;
            }
        } else if (dap_is_alpha(s[i])) {
            l_buf++;
            if (l_buf == 1) l_count_temp++;
            continue;
        }
        if (!dap_is_alpha(s[i])) {
            l_buf = 0;
            s[i] = 0;
            continue;
        }
    }

    s = l_temp_str;
    if (l_count_temp == 0) {
        DAP_DELETE(l_temp_str);
        return NULL;
    }

    char **lines = DAP_CALLOC(l_count_temp, sizeof (void *));
    if (!lines) {
        log_it(L_ERROR, "Memoru allocation error in s_parse_items");
        DAP_DELETE(l_temp_str);
        return NULL;
    }
    for (int i = 0; i < l_count_temp; i++) {
        while (*s == 0) s++;
        lines[i] = strdup(s);
        s = strchr(s, '\0');
        s++;
    }

    DAP_DELETE(l_temp_str);
    *a_count = l_count_temp;
    return lines;
}

static int s_get_key_from_file(const char *a_file, const char *a_mime, const char *a_cert_name, dap_sign_t **a_sign)
{
    char **l_items_mime = NULL;
    int l_items_mime_count = 0;
    uint32_t l_flags_mime = 0;

    if (a_mime)
        l_items_mime = s_parse_items(a_mime, ',', &l_items_mime_count, 0);

    if (l_items_mime && l_items_mime_count > 0) {
        struct opts l_opts_flags[] = {
        { "SIGNER_ALL_FLAGS", SIGNER_ALL_FLAGS },
        { "SIGNER_FILENAME", SIGNER_FILENAME },
        { "SIGNER_FILENAME_SHORT", SIGNER_FILENAME_SHORT },
        { "SIGNER_FILESIZE", SIGNER_FILESIZE },
        { "SIGNER_DATE", SIGNER_DATE },
        { "SIGNER_MIME_MAGIC", SIGNER_MIME_MAGIC }
        };
        int l_len_opts_flags = sizeof(l_opts_flags) / sizeof (struct opts);
        for (int i = 0; i < l_len_opts_flags; i++) {
            for (int isub = 0; isub < l_items_mime_count; isub++) {
                if (!strncmp (l_opts_flags[i].name, l_items_mime[isub], strlen(l_items_mime[isub]) + 1)) {
                    l_flags_mime |= l_opts_flags[i].cmd;
                    break;
                }
            }
        }
        DAP_DEL_ARRAY(l_items_mime, l_items_mime_count);
    }
    DAP_DELETE(l_items_mime);
    if (l_flags_mime == 0)
        l_flags_mime = SIGNER_ALL_FLAGS;
    dap_chain_hash_fast_t l_hash;
    return s_sign_file(a_file, l_flags_mime, a_cert_name, a_sign, &l_hash);
}

static int s_signer_cmd(int a_arg_index, int a_argc, char **a_argv, void **a_str_reply)
{
    enum {
        OPT_FILE, OPT_MIME, OPT_NET, OPT_CHAIN, OPT_CERT,
        OPT_COUNT
    };
    struct opts l_opts_signer[] = {
    { "-file", OPT_FILE },
    { "-mime", OPT_MIME },
    { "-net", OPT_NET },
    { "-chain", OPT_CHAIN },
    { "-cert", OPT_CERT }
    };

    BUILD_BUG((sizeof(l_opts_signer)/sizeof(struct opts)) != OPT_COUNT);

    a_arg_index++;

    char *l_opts_sign[OPT_COUNT] = {0};
    for (int i = 0; i < OPT_COUNT; i++) {
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, l_opts_signer[i].name, (const char **) &l_opts_sign[i]);
    }

    if (!l_opts_sign[OPT_CERT])
        return dap_cli_server_cmd_set_reply_text(a_str_reply, "%s need to be selected", l_opts_signer[OPT_CERT].name), -1;

    dap_chain_net_t *l_network = dap_chain_net_by_name(l_opts_sign[OPT_NET]);
    if ( !l_network )
        return dap_cli_server_cmd_set_reply_text(a_str_reply, "%s network not found", l_opts_sign[OPT_NET]), -1;

    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_network, l_opts_sign[OPT_CHAIN]);
    if (!l_chain)
        return dap_cli_server_cmd_set_reply_text(a_str_reply, "%s chain not found", l_opts_sign[OPT_CHAIN]), -1;

    dap_sign_t *l_sign = NULL;
    if ( s_get_key_from_file(l_opts_sign[OPT_FILE], l_opts_sign[OPT_MIME], l_opts_sign[OPT_CERT], &l_sign) )
        return dap_cli_server_cmd_set_reply_text(a_str_reply, "%s cert not found", l_opts_sign[OPT_CERT]), -1;

    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_SIGNER, l_sign->pkey_n_sign, l_sign->header.sign_size);
    if (!l_datum)
        return dap_cli_server_cmd_set_reply_text(a_str_reply, "not created datum"), -1;
    dap_cli_server_cmd_set_reply_text(a_str_reply, "hash: %s", dap_get_data_hash_str(l_datum->data, l_datum->header.data_size).s);
    return DAP_DELETE(l_datum), l_chain->callback_add_datums(l_chain, &l_datum, 1);
}



/*
SIGNER_ALL_FLAGS             = 0 << 0,
SIGNER_FILENAME              = 1 << 0,   // flag - full filename
SIGNER_FILENAME_SHORT        = 1 << 1,   // flag - filename without extension
SIGNER_FILESIZE              = 1 << 2,   // flag - size of file
SIGNER_DATE                  = 1 << 3,   // flag - date
SIGNER_MIME_MAGIC            = 1 << 4,   // flag - mime magic
SIGNER_COUNT
*/

static char *s_strdup_by_index (const char *a_file, const int a_index);
static dap_tsd_t *s_alloc_metadata (const char *a_file, const int a_meta);
static uint8_t *s_concat_hash_and_mimetypes (dap_chain_hash_fast_t *a_chain, dap_list_t *a_meta_list, size_t *a_fullsize);

/*
 * dap_sign_file - sign a file with flags.
 * flags - (SIGNER_FILENAME, SIGNER_FILENAME_SHORT, SIGNER_FILESIZE, SIGNER_DATE, SIGNER_MIME_MAGIC) or SIGNER_ALL_FLAGS
 * example
 * int ret = dap_sign_file ("void.png", SIGNER_ALL_FLAGS); it's sign file with all mime types.
 * example
 * int ret = dap_sign_file ("void.png", SIGNER_FILENAME | SIGNER_FILESIZE | SIGNER_DATE);
 */
/**
 * @brief dap_chain_sign_file
 * @param a_chain
 * @param a_filename
 * @param a_flags
 * @return
 */
static int s_sign_file(const char *a_filename, dap_sign_signer_file_t a_flags, const char *a_cert_name,
                       dap_sign_t **a_signed, dap_chain_hash_fast_t *a_hash)
{
    size_t l_size = 0;
    char *l_buffer = dap_file_get_contents2(a_filename, &l_size);
    uint32_t l_shift = 1;
    int l_count_meta = 0;
    if (a_flags == SIGNER_ALL_FLAGS) {
        l_count_meta = SIGNER_COUNT;
        a_flags = SIGNER_FILENAME | SIGNER_FILENAME_SHORT | SIGNER_FILESIZE | SIGNER_DATE | SIGNER_MIME_MAGIC;
    }

    do {
        if (a_flags <= 0) break;

        for (int i = 0; i < SIGNER_COUNT; i++) {
            if (l_shift | a_flags) l_count_meta++;
            l_shift <<= 1;
        }
    } while (0);

    l_shift = 1;
    dap_list_t *l_std_list = NULL;

    for (int i = 0; i < l_count_meta; i++) {
        if (l_shift | a_flags) {
            dap_tsd_t *l_item = s_alloc_metadata(a_filename, l_shift & a_flags);
            if (l_item) {
                l_std_list = dap_list_append(l_std_list, l_item);
            }
        }
        l_shift <<= 1;
    }

    if (!dap_hash_fast(l_buffer, (size_t)l_size, a_hash)) {
        dap_list_free_full(l_std_list, NULL);
        DAP_DELETE(l_buffer);
        return -6;
    }

    size_t l_full_size_for_sign;
    uint8_t *l_data = s_concat_hash_and_mimetypes(a_hash, l_std_list, &l_full_size_for_sign);
    dap_list_free_full(l_std_list, NULL);
    if (!l_data) {
        DAP_DELETE(l_buffer);
        return -7;
    }
    dap_cert_t *l_cert = dap_cert_find_by_name(a_cert_name);
    if (!l_cert) {
        DAP_DELETE(l_buffer);
        return -8;
    }
    *a_signed = dap_sign_create(l_cert->enc_key, l_data, l_full_size_for_sign);
    if (*a_signed == NULL) {
        DAP_DELETE(l_buffer);
        return -9;
    }

    return DAP_DELETE(l_buffer), 0;
}

static byte_t *s_concat_meta (dap_list_t *a_meta, size_t *a_fullsize)
{
    if (a_fullsize)
        *a_fullsize = 0;

    int l_part = 256;
    int l_power = 1;
    byte_t *l_buf = DAP_CALLOC(l_part * l_power++, 1);
    if (!l_buf) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    size_t l_counter = 0;
    size_t l_part_power = l_part;
    int l_index = 0;

    for ( dap_list_t* l_iter = dap_list_first(a_meta); l_iter; l_iter = l_iter->next){
        if (!l_iter->data) continue;
        dap_tsd_t * l_tsd = (dap_tsd_t *) l_iter->data;
        l_index = l_counter;
        l_counter += strlen((char *)l_tsd->data);
        if (l_counter >= l_part_power) {
            l_part_power = l_part * l_power++;
            byte_t *l_buf_new = DAP_REALLOC_RET_VAL_IF_FAIL(l_buf, l_part_power, NULL, l_buf);
            l_buf = l_buf_new;
        }
        memcpy (&l_buf[l_index], l_tsd->data, strlen((char *)l_tsd->data));
    }

    if (a_fullsize)
        *a_fullsize = l_counter;

    return l_buf;
}

static uint8_t *s_concat_hash_and_mimetypes (dap_chain_hash_fast_t *a_chain_hash, dap_list_t *a_meta_list, size_t *a_fullsize)
{
    if (!a_fullsize) return NULL;
    byte_t *l_buf = s_concat_meta (a_meta_list, a_fullsize);
    if (!l_buf)
        return NULL;

    size_t l_len_meta_buf = *a_fullsize;
    *a_fullsize += sizeof (a_chain_hash->raw) + 1;
    uint8_t *l_fullbuf = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(uint8_t, *a_fullsize, NULL, l_buf);
    memcpy( dap_mempcpy(l_fullbuf, a_chain_hash->raw, sizeof(a_chain_hash->raw)), l_buf, l_len_meta_buf );
    DAP_DELETE(l_buf);

    return l_fullbuf;
}


static char *s_strdup_by_index (const char *a_file, const int a_index)
{
    char *l_buf = DAP_CALLOC(a_index + 1, 1);
    if (!l_buf) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    strncpy (l_buf, a_file, a_index);
    return l_buf;
}

static dap_tsd_t *s_alloc_metadata (const char *a_file, const int a_meta)
{
    switch (a_meta) {
        case SIGNER_FILENAME:
            return dap_tsd_create_string(SIGNER_FILENAME, a_file);
            break;
        case SIGNER_FILENAME_SHORT:
            {
                char *l_filename_short = NULL;
                if ((l_filename_short = strrchr(a_file, '.')) != 0) {
                    int l_index_of_latest_point = l_filename_short - a_file;
                    l_filename_short = s_strdup_by_index (a_file, l_index_of_latest_point);
                    if (!l_filename_short) return NULL;
                    dap_tsd_t *l_ret = dap_tsd_create_string(SIGNER_FILENAME_SHORT, l_filename_short);
                    free (l_filename_short);
                    return l_ret;
                }
            }
            break;
        case SIGNER_FILESIZE:
            {
                struct stat l_st;
                stat (a_file, &l_st);
                return dap_tsd_create_string(SIGNER_FILESIZE, dap_itoa(l_st.st_size));
            }
            break;
        case SIGNER_DATE:
            {
                struct stat l_st;
                stat (a_file, &l_st);
                char *l_ctime = ctime(&l_st.st_ctime);
                char *l = NULL;
                if ((l = strchr(l_ctime, '\n')) != 0) *l = 0;
                return dap_tsd_create_string(SIGNER_DATE, l_ctime);
            }
            break;
        #ifndef DAP_OS_ANDROID
        case SIGNER_MIME_MAGIC:
            {
                /*magic_t l_magic = magic_open(MAGIC_MIME);
                if (l_magic == NULL) return NULL;
                if (magic_load (l_magic, NULL)) {
                    magic_close(l_magic);
                    return NULL;
                }
                const char *l_str_magic_file = NULL;
                dap_tsd_t *l_ret = NULL;
                do {
                        l_str_magic_file = magic_file (l_magic, a_file);
                    if (!l_str_magic_file) break;
                    l_ret = dap_tsd_create_string(SIGNER_MIME_MAGIC, l_str_magic_file);
                } while (0);
                magic_close (l_magic);
                return l_ret;*/
                return dap_tsd_create_string(SIGNER_MIME_MAGIC, "application/octet-stream");
            }
            break;
        #endif
        default:
            return NULL;
    }
    return NULL;
}

struct json_object *wallet_list_json_collect(){
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class", json_object_new_string("WalletList"));
    struct json_object *l_j_wallets = json_object_new_array();
    s_wallet_list(dap_chain_wallet_get_path(g_config), l_j_wallets, NULL);
    json_object_object_add(l_json, "wallets", l_j_wallets);
    return l_json;
}


struct json_object *wallets_info_json_collect() {
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class", json_object_new_string("WalletsInfo"));
    struct json_object *l_json_wallets = json_object_new_object();
    struct json_object *l_wallet_list = wallet_list_json_collect();
    struct json_object *l_wallet_list_arr = json_object_object_get(l_wallet_list, "wallets");
    size_t l_count = json_object_array_length(l_wallet_list_arr);
    for (size_t i = 0; i < l_count; i++) {
        struct json_object *l_json_wallet = json_object_array_get_idx(l_wallet_list_arr, i),
                *l_json_wallet_name = json_object_object_get(l_json_wallet, "Wallet");
        if ( !l_json_wallet_name )
            continue;
        char *l_tmp = (char*)json_object_get_string(l_json_wallet_name), *l_dot_pos = strstr(l_tmp, ".dwallet"), tmp = '\0';
        if (l_dot_pos) {
            tmp = *l_dot_pos;
            *l_dot_pos = '\0';
        }
        json_object_object_add(l_json_wallets, l_tmp, dap_chain_wallet_info_to_json(l_tmp, dap_chain_wallet_get_path(g_config)));
        if (tmp)
            *l_dot_pos = tmp;
    }
    json_object_object_add(l_json, "wallets", l_json_wallets);
    json_object_put(l_wallet_list);
    return l_json;
}

void dap_notify_new_client_send_info(dap_events_socket_t *a_es, UNUSED_ARG void *a_arg) {
    struct json_object *l_json_nets = dap_chain_net_list_json_collect();
    dap_events_socket_write_f(a_es->worker, a_es->uuid, "%s\r\n", json_object_to_json_string(l_json_nets));
    json_object_put(l_json_nets);
    struct json_object *l_json_nets_info = dap_chain_nets_info_json_collect();
    dap_events_socket_write_f(a_es->worker, a_es->uuid, "%s\r\n", json_object_to_json_string(l_json_nets_info));
    json_object_put(l_json_nets_info);
    struct json_object *l_json_wallets = wallet_list_json_collect();
    dap_events_socket_write_f(a_es->worker, a_es->uuid, "%s\r\n", json_object_to_json_string(l_json_wallets));
    json_object_put(l_json_wallets);
    struct json_object *l_json_wallets_info = wallets_info_json_collect();
    dap_events_socket_write_f(a_es->worker, a_es->uuid, "%s\r\n", json_object_to_json_string(l_json_wallets_info));
    json_object_put(l_json_wallets_info);
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        struct json_object *l_json_net_states = dap_chain_net_states_json_collect(l_net);
        dap_events_socket_write_f(a_es->worker, a_es->uuid, "%s\r\n", json_object_to_json_string(l_json_net_states));
        json_object_put(l_json_net_states);
    }
}

static void s_new_wallet_info_notify(const char *a_wallet_name)
{
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class", json_object_new_string("WalletInfo"));
    struct json_object *l_json_wallet_info = json_object_new_object();
    json_object_object_add(l_json_wallet_info, a_wallet_name, dap_chain_wallet_info_to_json(a_wallet_name, dap_chain_wallet_get_path(g_config)));
    json_object_object_add(l_json, "wallet", l_json_wallet_info);
    dap_notify_server_send(json_object_get_string(l_json));
    json_object_put(l_json);
}

static void s_stage_connected_callback(dap_client_t* a_client, void * a_arg) {
    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    UNUSED(a_arg);
    if(l_node_client) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_ESTABLISHED;
        pthread_cond_signal(&l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);
    }
}

static void s_stage_connected_error_callback(dap_client_t* a_client, void * a_arg) {
    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    UNUSED(a_arg);
    if(l_node_client) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_ERROR;
        pthread_cond_signal(&l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);
    }
}

int com_exec_cmd(int argc, char **argv, void **reply) {
    json_object ** a_json_arr_reply = (json_object **) reply;
    if (!dap_json_rpc_exec_cmd_inited()) {
        dap_json_rpc_error_add(*a_json_arr_reply, -1, "Json-rpc module doesn't inited, check confings");
        return -1;
    }

    const char * l_cmd_arg_str = NULL, * l_addr_str = NULL, * l_net_str = NULL;
    int arg_index = 1;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cmd", &l_cmd_arg_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_str);
    if (!l_cmd_arg_str || ! l_addr_str || !l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, -2, "Command exec_cmd require args -cmd, -addr, -net");
        return -2;
    }
    dap_chain_net_t* l_net = NULL;
    l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net){
        dap_json_rpc_error_add(*a_json_arr_reply, -3, "Can't find net %s", l_net_str);
        return -3;
    }

    dap_json_rpc_params_t * params = dap_json_rpc_params_create();
    char *l_cmd_str = dap_strdup(l_cmd_arg_str);
    for(int i = 0; l_cmd_str[i] != '\0'; i++) {
        if (l_cmd_str[i] == ',')
            l_cmd_str[i] = ';';
    }
    dap_json_rpc_params_add_data(params, l_cmd_str, TYPE_PARAM_STRING);
    uint64_t l_id_response = dap_json_rpc_response_get_new_id();
    char ** l_cmd_arr_str = dap_strsplit(l_cmd_str, ";", -1);
    dap_json_rpc_request_t *l_request = dap_json_rpc_request_creation(l_cmd_arr_str[0], params, l_id_response);
    dap_strfreev(l_cmd_arr_str);
    dap_chain_node_addr_t l_node_addr;
    dap_chain_node_addr_from_str(&l_node_addr, l_addr_str);

    dap_chain_node_info_t *node_info = node_info_read_and_reply(l_net, &l_node_addr, NULL);
    if(!node_info) {
        log_it(L_DEBUG, "Can't find node with addr: %s", l_addr_str);
        dap_json_rpc_error_add(*a_json_arr_reply, -6, "Can't find node with addr: %s", l_addr_str);
        return -6;
    }
    int timeout_ms = 5000; //5 sec = 5000 ms
    dap_chain_node_client_t * l_node_client = dap_chain_node_client_create(l_net, node_info, NULL, NULL);

    //handshake
    l_node_client->client = dap_client_new(s_stage_connected_error_callback, l_node_client);
    l_node_client->client->_inheritor = l_node_client;
    dap_client_set_uplink_unsafe(l_node_client->client, &l_node_client->info->address, node_info->ext_host, node_info->ext_port);
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(l_node_client->client);
    dap_client_go_stage(l_node_client->client, STAGE_ENC_INIT, s_stage_connected_callback);
    //wait handshake
    int res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
    if (res) {
        log_it(L_ERROR, "No response from node");
        dap_json_rpc_error_add(*a_json_arr_reply, -8, "No reponse from node");
        dap_chain_node_client_close_unsafe(l_node_client);
        DAP_DEL_Z(node_info);
        return -8;
    }

    //send request
    json_object * l_response = NULL;
    dap_json_rpc_request_send(l_client_internal, l_request, &l_response);

    if (l_response) {
        json_object_array_add(*a_json_arr_reply, l_response);
    } else {
        json_object_array_add(*a_json_arr_reply, json_object_new_string("Empty reply"));
    }
    DAP_DEL_Z(node_info);
    dap_json_rpc_request_free(l_request);
    return 0;
}

int com_file(int a_argc, char ** a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum {
        CMD_NONE, CMD_PRINT, CMD_EXPORT, CMD_CLEAR_LOG
    };
    int l_arg_index = 1;

    int l_cmd_num = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "print", NULL)) {
        l_cmd_num = CMD_PRINT;
    }
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "export", NULL)) {
        l_cmd_num = CMD_EXPORT;
    }
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "clear_log", NULL)) {
        l_cmd_num = CMD_CLEAR_LOG;
    }

    const char * l_num_line_str = NULL, *l_path_str = NULL, * l_str_ts_after = NULL, * l_str_limit = NULL;
    bool l_log = false;
    int l_num_line = 0;
    long l_limit = 0;
    time_t l_ts_after = 0;
    if (l_cmd_num != CMD_CLEAR_LOG) {
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-num_line", &l_num_line_str);
        l_num_line = l_num_line_str ? atoi(l_num_line_str) : 0;

        if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-log", NULL) ){
            l_log = true;
        }

        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-ts_after", &l_str_ts_after);
        if (l_str_ts_after) {
            struct tm l_tm = { };
            strptime(l_str_ts_after, /* "[%x-%X" */ "%m/%d/%Y-%H:%M:%S", &l_tm);
            l_tm.tm_year += 2000;
            l_ts_after = mktime(&l_tm);
        }

        if (!l_num_line && l_ts_after<=0) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "Requires only one argument '-num_line' or '-ts_after'");
            return DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR;
        } else if (l_num_line) {
            if (l_num_line <= 0) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "Wrong line number %d", l_num_line);
                return DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR;
            }
        } else if (l_ts_after) {
            if(l_ts_after < 0) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "Requires valid parameter '-ts_after'");
                return DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR;
            }
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "Requires parameters '-num_line' or '-ts_after'");
            return DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR;
        }

        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-path", &l_path_str);
        if (!l_log && !l_path_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "Command file require '-log' or '-path' arguments");
            return DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR;
        }

        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_str_limit);
        l_limit = (l_str_limit) ? strtol(l_str_limit, 0, 10) : -1;
        if(l_str_limit && l_limit <= 0) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "requires valid parameter '-limit'");
            return -1;
        }
    }

    if (l_cmd_num == CMD_CLEAR_LOG)
        l_log =true;

    char l_file_full_path[MAX_PATH] = {'\0'};
    if (l_log) {
        const char * l_log_file_path = "var/log/cellframe-node.log";
        sprintf(l_file_full_path, "%s/%s", g_sys_dir_path, l_log_file_path);
    } else {
        strncpy(l_file_full_path, l_path_str, sizeof(l_file_full_path) - 1);
        l_file_full_path[sizeof(l_file_full_path) - 1] = '\0';
    }
    char * l_res = NULL;
    if (l_cmd_num != CMD_CLEAR_LOG) {
        if (l_num_line) {
            l_res = dap_log_get_last_n_lines(l_file_full_path, l_num_line);
        } else {
            l_res = dap_log_get_item(l_file_full_path, l_ts_after, l_limit);
        }
    }
    switch(l_cmd_num) {
        case CMD_PRINT : {
            if (l_res) {
                json_object_array_add(*a_json_arr_reply, json_object_new_string(l_res));
                DAP_DELETE(l_res);
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_SOURCE_FILE_ERR, "Can't open source file %s or wrong line number %d", l_file_full_path, l_num_line);
                return DAP_CHAIN_NODE_CLI_COM_FILE_SOURCE_FILE_ERR;
            }
            break;
        }
        case CMD_EXPORT: {
            const char * l_dest_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-dest", &l_dest_str);
            if (!l_dest_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "Command file require -log or -path arguments");
                return DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR;
            }
            int res = dap_log_export_string_to_file(l_res, l_dest_str);
            switch (res) {
                case 0: {
                    json_object_array_add(*a_json_arr_reply, json_object_new_string("Export success"));
                    break;
                }
                case -1: {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_SOURCE_FILE_ERR, "Can't open source file %s", l_file_full_path);
                    return DAP_CHAIN_NODE_CLI_COM_FILE_SOURCE_FILE_ERR;
                }
                case -2: {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_DEST_FILE_ERR, "Can't open dest file %s", l_file_full_path);
                    return DAP_CHAIN_NODE_CLI_COM_FILE_DEST_FILE_ERR;
                }
                case -3: {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_NUM_ERR, "Wrong line number %s", l_num_line);
                    return DAP_CHAIN_NODE_CLI_COM_FILE_NUM_ERR;
                }
                default:
                    break;
            }
            break;
        }
        case CMD_CLEAR_LOG: {
            int res = dap_log_clear_file(l_file_full_path);
            switch (res) {
                case 0: {
                    json_object_array_add(*a_json_arr_reply, json_object_new_string("Log file has been cleared"));
                    break;
                }
                case -1: {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_SOURCE_FILE_ERR, "Can't open log file %s", l_file_full_path);
                    return DAP_CHAIN_NODE_CLI_COM_FILE_SOURCE_FILE_ERR;
                }
                default:
                    break;
            }
            break;
        }
        default: {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_FILE_PARAM_ERR, "require 'print', 'export' or 'clear_log' args" );
        }
    }
    return 0;
}

static dap_chain_datum_decree_t *s_decree_policy_execute(dap_chain_net_t *a_net, dap_chain_policy_t *a_policy)
{
    dap_return_val_if_pass(!a_net || !a_policy, NULL);
    // create updating decree
    size_t l_total_tsd_size = sizeof(dap_tsd_t) + dap_chain_policy_get_size(a_policy);

    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if (!l_chain) {
        log_it(L_ERROR, "No chain supported decree datum type");
        return NULL;
    }

    dap_chain_datum_decree_t *l_decree = dap_chain_datum_decree_new(a_net->pub.id, l_chain->id, *dap_chain_net_get_cur_cell(a_net), l_total_tsd_size);
    if (!l_decree) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_POLICY;
    dap_tsd_write((byte_t*)l_decree->data_n_signs, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_POLICY_EXECUTE, a_policy, dap_chain_policy_get_size(a_policy));

    return l_decree;
}

// Put the decree to mempool
static char *s_decree_policy_put(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net)
{
    size_t l_decree_size = dap_chain_datum_decree_get_size(a_decree);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, a_decree, l_decree_size);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if (!l_chain) {
        log_it(L_ERROR, "No chain supported decree datum type");
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    return l_ret;
}

int com_policy(int argc, char **argv, void **reply) {
    json_object ** a_json_arr_reply = (json_object **) reply;
    char **l_deactivate_array = NULL;
    const char
        *l_num_str = NULL,
        *l_net_str = NULL,
        *l_deactivate_str = NULL,
        *l_chain_str = NULL,
        *l_ts_start_str = NULL,
        *l_block_start_str = NULL,
        *l_certs_str = NULL;
    size_t
        l_deactivate_count = 0,
        l_certs_count = 0;
    dap_cert_t **l_certs = NULL;
    uint64_t l_flags = 0;
    bool l_execute = false;

    enum { CMD_NONE = 0, CMD_ACTIVATE, CMD_DEACTIVATE, CMD_FIND, CMD_LIST };  
    int l_arg_index = 1;

    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(argv, 1, 2, "activate", NULL))
        l_cmd = CMD_ACTIVATE;
    else if (dap_cli_server_cmd_find_option_val(argv, 1, 2, "deactivate", NULL))
            l_cmd = CMD_DEACTIVATE;
    else if (dap_cli_server_cmd_find_option_val(argv, 1, 2, "find", NULL))
        l_cmd = CMD_FIND;
    else if (dap_cli_server_cmd_find_option_val(argv, 1, 2, "list", NULL))
        l_cmd = CMD_LIST;

    if (l_cmd == CMD_NONE) {
        dap_json_rpc_error_add(*a_json_arr_reply, -4, "Unknown subcommand");
        return -4;
    }

    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-net", &l_net_str);

    if (!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, -3, "Command policy require args -net");
        return -4;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net){
        dap_json_rpc_error_add(*a_json_arr_reply, -3, "Can't find net %s", l_net_str);
        return -4;
    }

    if (l_cmd == CMD_LIST) {
        json_object *l_answer = dap_chain_policy_list(l_net->pub.id.uint64);
        json_object_array_add(*a_json_arr_reply, l_answer);
        return 0;
    }

    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-num", &l_num_str);
    if (!l_num_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, -7, "Command policy require args -num");
        return -7;
    }

    void *l_policy_data = NULL;
    size_t l_data_size = 0;
    uint64_t l_policy_num = 0;
    int l_policy_type = -1;
    if (l_cmd == CMD_DEACTIVATE) {
        l_policy_type = DAP_CHAIN_POLICY_DEACTIVATE;
        l_deactivate_count = dap_str_symbol_count(l_num_str, ',') + 1;
        l_deactivate_array = dap_strsplit(l_num_str, ",", l_deactivate_count);
        l_data_size = sizeof(dap_chain_policy_deactivate_t) + l_deactivate_count * sizeof(uint32_t);
        l_policy_data = DAP_NEW_Z_SIZE(void, l_data_size);
        if (!l_policy_data) {
            dap_json_rpc_error_add(*a_json_arr_reply, -16, "%s", c_error_memory_alloc);
            dap_strfreev(l_deactivate_array);
            return -16;
        }
        ((dap_chain_policy_deactivate_t *)l_policy_data)->count = l_deactivate_count;
        for (size_t i = 0; i < l_deactivate_count; ++i) {
            l_policy_num = strtoull(l_deactivate_array[i], NULL, 10);
            if (!dap_chain_policy_num_is_valid(l_policy_num)) {
                dap_json_rpc_error_add(*a_json_arr_reply, -16, "Policy nums sould be less or equal than %u and not equal 0", dap_maxval((uint32_t)l_policy_num));
                dap_strfreev(l_deactivate_array);
                DAP_DELETE(l_policy_data);
                return -16;
            }
            ((dap_chain_policy_deactivate_t *)l_policy_data)->nums[i] = l_policy_num;
        }
        dap_strfreev(l_deactivate_array);
    } else {
        l_policy_num = strtoull(l_num_str, NULL, 10);
        if (!dap_chain_policy_num_is_valid(l_policy_num)) {
            dap_json_rpc_error_add(*a_json_arr_reply, -16, "Policy num sould be less or equal than %u and not equal 0", dap_maxval((uint32_t)l_policy_num));
            return -16;
        }
    }

    uint32_t l_last_num = dap_chain_policy_get_last_num(l_net->pub.id.uint64);

    if (l_cmd == CMD_FIND) {
        dap_chain_policy_t *l_policy = dap_chain_policy_find(l_policy_num, l_net->pub.id.uint64);
        json_object *l_answer = dap_chain_policy_json_collect(l_policy);
        if (l_answer) {
            json_object_object_add(l_answer, "active", json_object_new_string(dap_chain_policy_activated(((dap_chain_policy_activate_t *)(l_policy->data))->num, l_net->pub.id.uint64) ? "true" : "false"));
            json_object_array_add(*a_json_arr_reply, l_answer);
        } else {
            json_object_array_add(*a_json_arr_reply, json_object_new_string("Detailed information not exist"));
        }
        return 0;
    }

    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-chain", &l_chain_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-ts_start", &l_ts_start_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-block_start", &l_block_start_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-deactivate", &l_deactivate_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-certs", &l_certs_str);
    l_execute = dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "execute", NULL);

    if (l_execute) {
        if (!l_certs_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, -4, "Command 'execute' requires parameter -certs");
            DAP_DELETE(l_policy_data);
            return -4;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
        if (!l_certs || !l_certs_count) {
            dap_json_rpc_error_add(*a_json_arr_reply, -5, "Specified certificates not found");
            DAP_DELETE(l_policy_data);
            return -5;
        }
    }

    if (l_cmd == CMD_ACTIVATE) {
        if (l_policy_num == l_last_num) {
            dap_json_rpc_error_add(*a_json_arr_reply, -15, "Specified policy num already existed");
            return -15;
        }
        l_policy_type = DAP_CHAIN_POLICY_ACTIVATE;
        l_data_size = sizeof(dap_chain_policy_activate_t);
        l_policy_data = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(void, l_data_size, -5);
        dap_chain_policy_activate_t *l_policy_activate = (dap_chain_policy_activate_t *)l_policy_data;
        
        l_policy_activate->num = l_policy_num;
        if (l_ts_start_str) {
            l_policy_activate->ts_start = dap_time_from_str_custom(l_ts_start_str, "%d/%m/%y-%H:%M:%S");
            if (!l_policy_activate->ts_start) {
                dap_json_rpc_error_add(*a_json_arr_reply, -13, "Can't read ts_start \"%s\"", l_ts_start_str);
                DAP_DELETE(l_policy_activate);
                return -13;
            }
            l_flags = DAP_FLAG_ADD(l_flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS);
        }

        if (l_block_start_str)
            l_policy_activate->block_start = strtoull(l_block_start_str, NULL, 10);
        
        if (l_policy_activate->block_start) {
            if (!l_chain_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, -8, "Command policy create with -block_start require args -chain");
                DAP_DELETE(l_policy_activate);
                return -8;
            }
            dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
            if (!l_chain) {
                dap_json_rpc_error_add(*a_json_arr_reply, -9, "%s Chain not found", l_chain_str);
                DAP_DELETE(l_policy_activate);
                return -9;
            }
            l_policy_activate->chain_union.chain = l_chain;
            l_flags = DAP_FLAG_ADD(l_flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM);
        }
        if (!l_flags && l_policy_activate->num < l_last_num) {
            dap_json_rpc_error_add(*a_json_arr_reply, -16, "Specified policy already activated by CN-%u", l_last_num);
            DAP_DELETE(l_policy_activate);
            return -16;
        }
    }

    dap_chain_policy_t *l_policy = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_policy_t, l_data_size + sizeof(dap_chain_policy_t), -5, l_policy_data);
    l_policy->data_size = l_data_size;
    l_policy->version = DAP_CHAIN_POLICY_VERSION;
    l_policy->type = l_policy_type;
    l_policy->flags = l_flags;
    memcpy(l_policy->data, l_policy_data, l_policy->data_size);
    DAP_DELETE(l_policy_data);
    // if cmd none - only print preaparing result
    if (!l_execute) {
        json_object *l_answer = dap_chain_policy_json_collect(l_policy);
        char l_time[DAP_TIME_STR_SIZE] = {};
        dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, dap_time_now());
        json_object_object_add(l_answer, "current time", json_object_new_string(l_time));
        json_object_object_add(l_answer, "notification", json_object_new_string("It's policy draft, check and use 'execute' command to apply"));
        if (l_answer) {
            json_object_array_add(*a_json_arr_reply, l_answer);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, -11, "Policy draft creation failed");
            DAP_DELETE(l_policy);
            return -11;
        }
        DAP_DELETE(l_policy);
        return 0;
    }
    // change pointer to id to decree
    if (l_policy->type == DAP_CHAIN_POLICY_ACTIVATE && ((dap_chain_policy_activate_t *)(l_policy->data))->chain_union.chain) {
        ((dap_chain_policy_activate_t *)(l_policy->data))->chain_union.chain_id = ((dap_chain_policy_activate_t *)(l_policy->data))->chain_union.chain->id;
    }

    dap_chain_datum_decree_t *l_decree = s_decree_policy_execute(l_net, l_policy);
    DAP_DELETE(l_policy);
    size_t l_total_signs_success = 0;
    l_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_decree, l_certs_count, &l_total_signs_success);

    if (!l_decree || l_total_signs_success == 0){
        dap_json_rpc_error_add(*a_json_arr_reply, -11, "Decree creation failed. Successful count of certificate signing is 0");
            return -11;
    }

    char *l_decree_hash_str = NULL;;
    if (!(l_decree_hash_str = s_decree_policy_put(l_decree, l_net))) {
        dap_json_rpc_error_add(*a_json_arr_reply, -12, "Policy decree error");
        return -12;
    }
    DAP_DELETE(l_decree);

    char l_approve_str[128];
    snprintf(l_approve_str, sizeof(l_approve_str), "Policy decree %s successfully created", l_decree_hash_str);
    json_object_array_add(*a_json_arr_reply, json_object_new_string(l_approve_str));
    DAP_DELETE(l_decree_hash_str);

    return 0;
}

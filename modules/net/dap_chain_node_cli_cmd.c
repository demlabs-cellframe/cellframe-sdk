/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2019
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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#ifndef DAP_OS_ANDROID
#include <magic.h>
#endif
#include <sys/stat.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include "wepoll.h"
#else
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#endif
#include <pthread.h>
#include <iputils/iputils.h>

#include "uthash.h"
#include "utlist.h"
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
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_node.h"
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_chain_node_ping.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"

#ifndef _WIN32
#include "dap_chain_net_news.h"
#endif
#include "dap_chain_cell.h"


#include "dap_enc_base64.h"
#include "json.h"
#ifdef DAP_OS_UNIX
#include <dirent.h>
#endif

#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_global_db.h"
#include "dap_global_db_remote.h"

#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_enc_base64.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_node_list.h"
#include "dap_json_rpc_errors.h"
#include "dap_json_rpc_chain_datum.h"

#define LOG_TAG "chain_node_cli_cmd"

static void s_dap_chain_net_purge(dap_chain_net_t *a_net);
int _cmd_mempool_add_ca(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_cert_t *a_cert, void ** reply);

/**
 * @brief dap_chain_node_addr_t* dap_chain_node_addr_get_by_alias
 * Find in base addr by alias
 *
 * return addr, NULL if not found
 * @param a_net
 * @param a_alias
 * @return dap_chain_node_addr_t*
 */
dap_chain_node_addr_t* dap_chain_node_addr_get_by_alias(dap_chain_net_t * a_net, const char *a_alias)
{
    dap_chain_node_addr_t *l_addr = NULL;
    if(!a_alias)
        return NULL;
    const char *a_key = a_alias;
    size_t l_addr_size = 0;
    l_addr = (dap_chain_node_addr_t*) (void*) dap_global_db_get_sync(a_net->pub.gdb_nodes_aliases,a_key, &l_addr_size,NULL, NULL);
    if(l_addr_size != sizeof(dap_chain_node_addr_t)) {
        DAP_DELETE(l_addr);
        l_addr = NULL;
    }
    return l_addr;
}


/**
 * @brief dap_list_t* get_aliases_by_name Get the aliases by name object
 * Find in base alias by addr
 *
 * return list of addr, NULL if not found
 * @param l_net
 * @param a_addr
 * @return dap_list_t*
 */
static dap_list_t* get_aliases_by_name(dap_chain_net_t * l_net, dap_chain_node_addr_t *a_addr)
{
    if(!a_addr)
        return NULL;
    dap_list_t *list_aliases = NULL;
    size_t data_size = 0;
    // read all aliases
    dap_global_db_obj_t *objs = dap_global_db_get_all_sync(l_net->pub.gdb_nodes_aliases, &data_size);
    if(!objs || !data_size)
        return NULL;
    for(size_t i = 0; i < data_size; i++) {
        //dap_chain_node_addr_t addr_i;
        dap_global_db_obj_t *obj = objs + i;
        if(!obj)
            break;
        dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t*) (void*) obj->value;
        if(l_addr && obj->value_len == sizeof(dap_chain_node_addr_t) && a_addr->uint64 == l_addr->uint64) {
            list_aliases = dap_list_prepend(list_aliases, strdup(obj->key));
        }
    }
    dap_global_db_objs_delete(objs, data_size);
    return list_aliases;
}

/**
 * @brief dap_chain_node_addr_t* s_node_info_get_addr
 *
 * @param a_net
 * @param a_node_info
 * @param a_addr
 * @param a_alias_str
 * @return dap_chain_node_addr_t*
 */
static dap_chain_node_addr_t* s_node_info_get_addr(dap_chain_net_t * a_net, dap_chain_node_addr_t *a_addr, const char *a_alias_str)
{
    dap_chain_node_addr_t *l_address = a_alias_str
            ? dap_chain_node_addr_get_by_alias(a_net, a_alias_str)
            : a_addr && a_addr->uint64 ? DAP_DUP(a_addr) : NULL;
    if (!l_address)
        log_it(L_ERROR, "Node address with specified params not found");
    return l_address;
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
        char **a_str_reply)
{
    char *l_key = dap_chain_node_addr_to_hash_str(a_address);
    if(!l_key)
    {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "can't calculate hash of addr");
        return NULL;
    }
    size_t node_info_size = 0;
    dap_chain_node_info_t *node_info;
    // read node
    node_info = (dap_chain_node_info_t *) dap_global_db_get_sync(a_net->pub.gdb_nodes, l_key, &node_info_size, NULL, NULL);

    if(!node_info) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "node not found in base");
        DAP_DELETE(l_key);
        return NULL;
    }

    DAP_DELETE(l_key);
    return node_info;
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
static bool node_info_save_and_reply(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info, char **a_str_reply)
{
    if(!a_node_info || !a_node_info->hdr.address.uint64) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "node addr not found");
        return false;
    }
    char *a_key = dap_chain_node_addr_to_hash_str(&a_node_info->hdr.address);
    if(!a_key)
    {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "can't calculate hash for addr");
        return NULL;
    }
    //char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    size_t l_node_info_size = dap_chain_node_info_get_size(a_node_info);
    //dap_chain_node_info_t *l_node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, l_node_info_size);
    //memcpy(l_node_info, a_node_info, l_node_info_size );

    //size_t data_len_out = 0;
    //dap_chain_node_info_t *a_node_info1 = dap_global_db_gr_get(a_key, &data_len_out, a_net->pub.gdb_nodes);

    bool res = dap_global_db_set_sync(a_net->pub.gdb_nodes, a_key, (uint8_t *) a_node_info, l_node_info_size,
                                 false) == 0;

    //data_len_out = 0;
    //dap_chain_node_info_t *a_node_info2 = dap_global_db_gr_get(a_key, &data_len_out, a_net->pub.gdb_nodes);
    //DAP_DELETE(a_key);
    //DAP_DELETE(a_value);
    return res;
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
        const char *a_alias_str,
        const char *a_cell_str, const char *a_ipv4_str, const char *a_ipv6_str, char **a_str_reply)
{

    if(!a_node_info->hdr.address.uint64) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not found -addr parameter");
        return -1;
    }
    if(!a_cell_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not found -cell parameter");
        return -1;
    }
    if(a_ipv4_str)
        inet_pton(AF_INET, a_ipv4_str, &(a_node_info->hdr.ext_addr_v4));
    if(a_ipv6_str)
        inet_pton(AF_INET6, a_ipv6_str, &(a_node_info->hdr.ext_addr_v6));

    // check match addr to cell or no
    /*dap_chain_node_addr_t *addr = dap_chain_node_gen_addr(&node_info->hdr.cell_id);
     if(!dap_chain_node_check_addr(&node_info->hdr.address, &node_info->hdr.cell_id)) {
     set_reply_text(a_str_reply, "cell does not match addr");
     return -1;
     }*/
    if(a_alias_str) {
        // add alias
        if(!dap_chain_node_alias_register(a_net, a_alias_str, &a_node_info->hdr.address)) {
            log_it(L_WARNING, "can't save alias %s", a_alias_str);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "alias '%s' can't be mapped to addr=0x%"DAP_UINT64_FORMAT_U,
                    a_alias_str, a_node_info->hdr.address.uint64);
            return -1;
        }
    }

    // write to base
    if(!node_info_save_and_reply(a_net, a_node_info, a_str_reply))
        return -1;
    dap_cli_server_cmd_set_reply_text(a_str_reply, "node added");
    return 0;
}


/**
 * @brief node_info_del_with_reply
 * Handler of command 'global_db node add'
 * @param a_net
 * @param a_node_info
 * @param alias_str
 * @param str_reply str_reply[out] for reply
 * @return int
 * return 0 Ok, -1 error
 */
static int node_info_del_with_reply(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info, const char *alias_str,
        char **a_str_reply)
{
    if(!a_node_info->hdr.address.uint64 && !alias_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "addr not found");
        return -1;
    }
    // check, current node have this addr or no
    uint64_t l_cur_addr = dap_chain_net_get_cur_node_addr_gdb_sync(a_net->pub.name);
    if(l_cur_addr && l_cur_addr == a_node_info->hdr.address.uint64) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "current node cannot be deleted");
        return -1;
    }

    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = s_node_info_get_addr(a_net, &a_node_info->hdr.address, alias_str);
    if(!address) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "alias not found");
        return -1;
    }
    size_t l_nodes_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_net->pub.gdb_nodes, &l_nodes_count);
    if(l_nodes_count && l_objs)
    {
        for (size_t i = 0; i < l_nodes_count; i++) {
            dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t*)l_objs[i].value;
            if (!dap_chain_node_addr_not_null(&l_node_info->hdr.address)){
                log_it(L_ERROR, "Node address is NULL");
                continue;
            }
            if(l_node_info->hdr.address.uint64 == address->uint64)
            {
                if(l_node_info->hdr.owner_address.uint64 != l_cur_addr)
                {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Your node is not pinner");
                    return -1;
                }
                else
                {
                    break;
                }
            }
        }
    }
    else {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "can't find node in gdb");
        return -1;
    }

    char *a_key = dap_chain_node_addr_to_hash_str(address);
    if(a_key){
        // delete node
        int l_res = dap_global_db_del_sync(a_net->pub.gdb_nodes, a_key);
        if(l_res == 0) {
            // delete all aliases for node address
            {
                dap_list_t *list_aliases = get_aliases_by_name(a_net, address);
                dap_list_t *list = list_aliases;
                while(list)
                {
                    const char *alias = (const char *) list->data;
                    dap_chain_node_alias_delete(a_net, alias);
                    list = dap_list_next(list);
                }
                dap_list_free_full(list_aliases, NULL);
            }
            // set text response
            dap_cli_server_cmd_set_reply_text(a_str_reply, "node deleted");
        }
        else
            dap_cli_server_cmd_set_reply_text(a_str_reply, "node not deleted");
        DAP_DELETE(a_key);
        DAP_DELETE(address);
        return l_res;
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "addr to delete can't be defined");
    DAP_DELETE(address);
    return -1;
}


/**
 * @brief link_add_or_del_with_reply
 * Handler of command 'global_db node link'
 * cmd 'add' or 'del'
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 * @param a_net
 * @param a_node_info
 * @param cmd
 * @param a_alias_str
 * @param link
 * @param a_str_reply
 * @return int
 */
static int link_add_or_del_with_reply(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info, const char *cmd,
        const char *a_alias_str,
        dap_chain_node_addr_t *link, char **a_str_reply)
{
    if(!a_node_info->hdr.address.uint64 && !a_alias_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "addr not found");
        return -1;
    }
    if(!link->uint64) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "link not found");
        return -1;
    }
    // TODO check the presence of link in the node base
#ifdef DAP_CHAIN_NODE_CHECK_PRESENSE
        dap_cli_server_cmd_set_reply_text(a_str_reply, "node 0x%016llx not found in base", link->uint64);
        return -1;
#endif

    // find addr by alias or addr_str
    dap_chain_node_addr_t *l_address = s_node_info_get_addr(a_net, &a_node_info->hdr.address, a_alias_str);
    if(!l_address) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "alias not found");
        return -1;
    }

    dap_chain_node_info_t * l_node_info_read = node_info_read_and_reply(a_net, l_address, a_str_reply);
    size_t l_node_info_read_size = dap_chain_node_info_get_size(l_node_info_read);
    if(!l_node_info_read)
        return -1;

    int cmd_int = 0;
    if(!strcmp(cmd, "add"))
        cmd_int = 1;
    else if(!strcmp(cmd, "del"))
        cmd_int = 2;

    // find link in node_info_read
    int index_link = -1;
    for(size_t i = 0; i < l_node_info_read->hdr.links_number; i++) {
        if(l_node_info_read->links[i].uint64 == link->uint64) {
            // link already present
            index_link = (int) i;
            break;
        }
    }
    bool res_successful = false; // is successful whether add/del
    // add link
    if(cmd_int == 1) {
        if(index_link == -1) {
            l_node_info_read->hdr.links_number++;
            l_node_info_read_size = dap_chain_node_info_get_size(l_node_info_read);
            l_node_info_read = DAP_REALLOC(l_node_info_read, l_node_info_read_size);
            l_node_info_read->links[l_node_info_read->hdr.links_number-1] = *link;
            res_successful = true;
        }
    }
    // delete link
    else if(cmd_int == 2) {
        // move link list to one item prev
        if(index_link >= 0) {
            for(unsigned int j = (unsigned int) index_link; j < (l_node_info_read->hdr.links_number - 1); j++) {
                l_node_info_read->links[j] = l_node_info_read->links[j + 1];
            }
            l_node_info_read->hdr.links_number--;
            res_successful = true;
            l_node_info_read = DAP_REALLOC(l_node_info_read, l_node_info_read_size -= sizeof(*link));
        }
    }
    // save edited node_info
    if(res_successful) {
        bool res = true;  //node_info_save_and_reply(a_net, l_node_info_read, a_str_reply);
        if(res) {
            res_successful = true;
            if(cmd_int == 1)
                dap_cli_server_cmd_set_reply_text(a_str_reply, "link added");
            if(cmd_int == 2)
                dap_cli_server_cmd_set_reply_text(a_str_reply, "link deleted");
        }
        else {
            res_successful = false;
        }
    }
    else {
        if(cmd_int == 1) {
            if(index_link >= 0)
                dap_cli_server_cmd_set_reply_text(a_str_reply, "link not added because it is already present");
            else
                dap_cli_server_cmd_set_reply_text(a_str_reply, "link not added");
        }
        if(cmd_int == 2) {
            if(index_link == -1)
                dap_cli_server_cmd_set_reply_text(a_str_reply, "link not deleted because not found");
            else
                dap_cli_server_cmd_set_reply_text(a_str_reply, "link not deleted");
        }
    }

    DAP_DELETE(l_address);
    DAP_DELETE(l_node_info_read);
    if(res_successful)
        return 0;
    return -1;
}


/**
 * @brief node_info_dump_with_reply Handler of command 'node dump'
 * @param a_net
 * @param a_addr
 * @param a_is_full
 * @param a_alias
 * @param a_str_reply
 * @return int 0 Ok, -1 error
 */
static int node_info_dump_with_reply(dap_chain_net_t * a_net, dap_chain_node_addr_t * a_addr, bool a_is_full,
        const char *a_alias, char **a_str_reply)
{
    int l_ret = 0;
    dap_string_t *l_string_reply = dap_string_new("Node dump:\n");

    if ((a_addr && a_addr->uint64) || a_alias) {
        dap_chain_node_addr_t *l_addr = a_alias
                ? dap_chain_node_alias_find(a_net, a_alias)
                : DAP_DUP(a_addr);

        if (!l_addr) {
            log_it(L_ERROR, "Node address with specified params not found");
            return -1;
        }

        // read node
        dap_chain_node_info_t *node_info_read = node_info_read_and_reply(a_net, l_addr, a_str_reply);
        if(!node_info_read) {
            DAP_DEL_Z(l_addr);
            dap_string_free(l_string_reply, true);
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
            dap_string_append_printf(l_string_reply, "No records\n");
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_string_reply->str);
            dap_string_free(l_string_reply, true);
            dap_global_db_objs_delete(l_objs, l_nodes_count);
            return -1;
        } else {
            dap_string_append_printf(l_string_reply, "Got %zu nodes:\n", l_nodes_count);
            dap_string_append_printf(l_string_reply, "%-26s%-20s%-8s%-26s%s", "Address", "IPv4", "Port", "Pinner", "Timestamp\n");
            size_t l_data_size = 0;

            dap_global_db_obj_t *l_aliases_objs = dap_global_db_get_all_sync(a_net->pub.gdb_nodes_aliases, &l_data_size);
            for (size_t i = 0; i < l_nodes_count; i++) {
                dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t*)l_objs[i].value;
                if (!dap_chain_node_addr_not_null(&l_node_info->hdr.address)){
                    log_it(L_ERROR, "Node address is NULL");
                    continue;
                }
/*
                dap_chain_node_info_t *l_node_info_read = node_info_read_and_reply(a_net, &l_node_info->hdr.address, NULL);
                if (!l_node_info_read) {
                    log_it(L_ERROR, "Invalid node info object, remove it");
                    if (dap_global_db_del_sync(a_net->pub.gdb_nodes, l_objs[i].key) !=0 )
                        log_it(L_CRITICAL, "Can't remove node info object");
                    continue;
                } else
                    DAP_DELETE(l_node_info_read);
*/

                char l_node_ipv4_str[INET_ADDRSTRLEN]={ '\0' }, l_node_ipv6_str[INET6_ADDRSTRLEN]={ '\0' };
                inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_ipv4_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET6, &l_node_info->hdr.ext_addr_v6, l_node_ipv6_str, INET6_ADDRSTRLEN);
                char l_ts[128] = { '\0' };
                dap_gbd_time_to_str_rfc822(l_ts, sizeof(l_ts), l_objs[i].timestamp);

                dap_string_append_printf(l_string_reply, NODE_ADDR_FP_STR"    %-20s%-8d"NODE_ADDR_FP_STR"    %-32s\n",
                                         NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address),
                                         l_node_ipv4_str, l_node_info->hdr.ext_port,
                                         NODE_ADDR_FP_ARGS_S(l_node_info->hdr.owner_address),
                                         l_ts);

                // get aliases in form of string
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
            dap_global_db_objs_delete(l_aliases_objs, l_data_size);
        }
        dap_global_db_objs_delete(l_objs, l_nodes_count);
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_string_reply->str);
    dap_string_free(l_string_reply, true);
    return l_ret;
}

/**
 * @brief purge ledger, stake, decree, all chains and remove chain files
 * @param a_net
 */
void s_dap_chain_net_purge(dap_chain_net_t * a_net)
{
    if (!a_net)
        return;
    dap_chain_t *l_chain = NULL;
    dap_ledger_purge(a_net->pub.ledger, false);
    dap_chain_net_srv_stake_purge(a_net);
    dap_chain_net_decree_purge(a_net);
    DL_FOREACH(a_net->pub.chains, l_chain) {
        if (l_chain->callback_purge)
            l_chain->callback_purge(l_chain);
        if (l_chain->callback_set_min_validators_count)
            l_chain->callback_set_min_validators_count(l_chain, 0);
        const char *l_chains_rm_path = dap_chain_get_path(l_chain);
        dap_rm_rf(l_chains_rm_path);
        a_net->pub.fee_value = uint256_0;
        a_net->pub.fee_addr = c_dap_chain_addr_blank;
        dap_chain_load_all(l_chain);
    }
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
int com_global_db(int a_argc, char ** a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    enum {
        CMD_NONE, CMD_NAME_CELL, CMD_ADD, CMD_FLUSH, CMD_RECORD, CMD_WRITE, CMD_READ,
        CMD_DELETE, CMD_DROP, CMD_GET_KEYS, CMD_GROUP_LIST
    };
    int arg_index = 1;
    int cmd_name = CMD_NONE;
    // find 'cells' as first parameter only
    if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "cells", NULL))
        cmd_name = CMD_NAME_CELL;
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "flush", NULL))
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
    case CMD_NAME_CELL:
    {
        if(!arg_index || a_argc < 3) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "parameters are not valid");
            return -1;
        }
        dap_chain_t * l_chain = NULL;
        dap_chain_net_t * l_net = NULL;

        if(dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net) < 0)
            return -11;

        const char *l_cell_str = NULL, *l_chain_str = NULL;
        // find cell and chain
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cell", &l_cell_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

        // Check for chain
        if(!l_chain_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'chain' to be valid", a_argv[0]);
            return -12;
        }

        int arg_index_n = ++arg_index;
        // find command (add, delete, etc) as second parameter only
        int cmd_num = CMD_NONE;
        switch (cmd_name) {
            case CMD_NAME_CELL:
                if((arg_index_n = dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "add", NULL))
                        != 0) {
                    cmd_num = CMD_ADD;
                }
                dap_chain_cell_id_t l_cell_id = { {0} };
                if(l_cell_str) {
                    dap_digit_from_string(l_cell_str, (uint8_t*) &l_cell_id.raw, sizeof(l_cell_id.raw)); //DAP_CHAIN_CELL_ID_SIZE);
                }

                switch (cmd_num)
                {
                // add new node to global_db
                case CMD_ADD:
                    if(!arg_index || a_argc < 7) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameters");
                        return -1;
                    }
                    dap_chain_cell_t *l_cell = dap_chain_cell_create_fill(l_chain, l_cell_id);
                    int l_ret = (int)dap_chain_cell_file_update(l_cell);
                    if(l_ret > 0)
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "cell added successfully");
                    else
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "can't create file for cell 0x%016"DAP_UINT64_FORMAT_X" ( %s )",
                                l_cell->id.uint64,l_cell->file_storage_path);
                    dap_chain_cell_close(l_cell);
                    return l_ret;

                //case CMD_NONE:
                default:
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "command %s not recognized", a_argv[1]);
                    return -1;
                }
        }
    }
    case CMD_FLUSH:
    {
        int res_flush = dap_global_db_flush_sync();
        switch (res_flush) {
        case 0:
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Commit data base and filesystem caches to disk completed.\n\n");
            break;
        case -1:
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Couldn't open db directory. Can't init cdb\n"
                                                           "Reboot the node.\n\n");
            break;
        case -2:
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't init cdb\n"
                                                           "Reboot the node.\n\n");
            break;
        case -3:
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't init sqlite\n"
                                                           "Reboot the node.\n\n");
            break;
        default:
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't commit data base caches to disk completed.\n"
                                                           "Reboot the node.\n\n");
            break;
        }
        return 0;
    }
    case CMD_RECORD:
    {
        enum {
            SUMCMD_GET, SUMCMD_PIN, SUMCMD_UNPIN
        };
        if(!arg_index || a_argc < 3) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "parameters are not valid");
            return -1;
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
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand '%s' not recognized, available subcommands are 'get', 'pin' or 'unpin'", a_argv[2]);
            return -1;
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
        uint8_t *l_value =dap_global_db_get_sync(l_group, l_key, &l_value_len, &l_is_pinned, &l_ts);
        if(!l_value || !l_value_len) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Record not found\n\n");
            return -1;
        }

        int l_ret = 0;
        // prepare record information
        switch (l_subcmd) {
            case SUMCMD_GET: // Get value
            {
                char *l_hash_str;
                dap_get_data_hash_str_static(l_value, l_value_len, l_hash_str);
                char *l_value_str = DAP_NEW_Z_SIZE(char, l_value_len * 2 + 2);
                if(!l_value_str) {
                    log_it(L_CRITICAL, "Memory allocation error");
                    DAP_DELETE(l_value);
                    return -1;
                }
                size_t ret = dap_bin2hex(l_value_str, l_value, l_value_len);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Record found\n"
                        "lenght:\t%zu byte\n"
                        "hash:\t%s\n"
                        "pinned:\t%s\n"
                        "value:\t0x%s\n\n", l_value_len, l_hash_str, l_is_pinned ? "Yes" : "No", l_value_str);
                DAP_DELETE(l_value_str);
                break;
            }
            case SUMCMD_PIN: // Pin record
            {
                if(l_is_pinned){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "record already pinned");
                    break;
                }
                if(dap_global_db_set_sync( l_group, l_key, l_value, l_value_len,true ) ==0 ){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "record successfully pinned");
                }
                else{
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "can't pin the record");
                    l_ret = -2;
                }
                break;
            }
            case SUMCMD_UNPIN: // Unpin record
            {
                if(!l_is_pinned) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "record already unpinned");
                    break;
                }
                if(dap_global_db_set_sync(l_group,l_key, l_value, l_value_len, false) == 0 ) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "record successfully unpinned");
                }
                else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "can't unpin the record");
                    l_ret = -2;
                }
                break;
            }
        }
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

        if(!l_group_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'group' to be valid", a_argv[0]);
            return -120;
        }

        if(!l_key_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'key' to be valid", a_argv[0]);
            return -121;
        }

        if(!l_value_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'value' to be valid", a_argv[0]);
            return -122;
        }

        if (!dap_global_db_set_sync(l_group_str, l_key_str, l_value_str, strlen(l_value_str) +1 , false)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Data has been successfully written to the database");
            return 0;
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Data writing is failed");
            return -124;
        }

    }
    case CMD_READ:
    {
        const char *l_group_str = NULL;
        const char *l_key_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-key", &l_key_str);

        if(!l_group_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'group' to be valid", a_argv[0]);
            return -120;
        }

        if(!l_key_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'key' to be valid", a_argv[0]);
            return -122;
        }

        size_t l_out_len = 0;
        dap_nanotime_t l_ts = 0;
        uint8_t *l_value_out = dap_global_db_get_sync(l_group_str, l_key_str, &l_out_len, NULL, &l_ts);
        /*if (!l_value_out || !l_out_len)
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Record with key %s in group %s not found", l_key_str, l_group_str);
            return -121;
        }*/
        if (l_ts) {
            char l_ts_str[80] = { '\0' };
            dap_gbd_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_ts);
            char *l_value_hexdump = dap_dump_hex(l_value_out, l_out_len);
            if (l_value_hexdump) {

                dap_cli_server_cmd_set_reply_text(a_str_reply, "\n\"%s : %s\"\nTime: %s\nValue len: %zu\nValue hex:\n\n%s",
                                                  l_group_str, l_key_str, l_ts_str, l_out_len, l_value_hexdump);
                DAP_DELETE(l_value_hexdump);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "\n\"%s : %s\"\nTime: %s\nNo value\n",
                                                  l_group_str, l_key_str, l_ts_str);
            }
            DAP_DELETE(l_value_out);
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "\nRecord \"%s : %s\" not found\n",
                                              l_group_str, l_key_str);
        }


        return 0;
    }
    case CMD_DELETE:
    {
        const char *l_group_str = NULL;
        const char *l_key_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-key", &l_key_str);

        if(!l_group_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'group' to be valid", a_argv[0]);
            return -120;
        }

        if(!l_key_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "No key provided, entire table %s will be altered", l_group_str);
            size_t l_objs_count = 0;
            dap_global_db_obj_t* l_obj = dap_global_db_get_all_sync(l_group_str, &l_objs_count);

            if (!l_obj || !l_objs_count)
            {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "No data in group %s.", l_group_str);
                return -124;
            }
            size_t i, j = 0;
            for (i = 0; i < l_objs_count; ++i) {
                if (!l_obj[i].key)
                    continue;
                if (!dap_global_db_del_sync(l_group_str, l_obj[i].key)) {
                    ++j;
                }
            }
            dap_global_db_objs_delete(l_obj, l_objs_count);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Removed %lu of %lu records in table %s", j, i, l_group_str);
            return 0;
        }

        if (!dap_global_db_del(l_group_str, l_key_str, NULL, NULL)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Record with key %s in group %s was deleted successfuly", l_key_str, l_group_str);
            return 0;
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Record with key %s in group %s deleting failed", l_group_str, l_key_str);
            return -122;
        }
    }
    case CMD_DROP:
    {
        const char *l_group_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);

        if(!l_group_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'group' to be valid", a_argv[0]);
            return -120;
        }

        if (!dap_global_db_del_sync(l_group_str, NULL))
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Dropped table %s", l_group_str);
            return 0;
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Failed to drop table %s", l_group_str);
            return -122;
        }
    }
    case CMD_GET_KEYS:
    {
        const char *l_group_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);

        if(!l_group_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'group' to be valid", a_argv[0]);
            return -120;
        }

        size_t l_objs_count = 0;
        dap_global_db_obj_t* l_obj = dap_global_db_get_all_sync(l_group_str, &l_objs_count);

        if (!l_obj || !l_objs_count)
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "No data in group %s.", l_group_str);
            return -124;
        }

        dap_string_t *l_ret_str = dap_string_new(NULL);
        for(size_t i = 0; i < l_objs_count; i++) {
            char l_ts[64] = { '\0' };
            dap_gbd_time_to_str_rfc822(l_ts, sizeof(l_ts), l_obj[i].timestamp);
            dap_string_append_printf(l_ret_str, "\t%s, %s\n", l_obj[i].key, l_ts);
        }
        dap_global_db_objs_delete(l_obj, l_objs_count);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Keys list for group \"%s:\n\n%s\n", l_group_str, l_ret_str->str);
        dap_string_free(l_ret_str, true);
        return 0;
    }
    case CMD_GROUP_LIST: {
        dap_string_t *l_ret_str = dap_string_new(NULL);
        dap_list_t *l_group_list = dap_global_db_driver_get_groups_by_mask("*");
        size_t l_count = 0;
        for (dap_list_t *l_list = l_group_list; l_list; l_list = dap_list_next(l_list), ++l_count) {
            dap_string_append_printf(l_ret_str, "\t%-40s : %zu records\n", (char*)l_list->data, dap_global_db_driver_count((char*)l_list->data, 1));
        }
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Group list:\n%sTotal count: %zu\n", l_ret_str->str, l_count);
        dap_string_free(l_ret_str, true);
        dap_list_free(l_group_list);
        return 0;
    }
    default:
        dap_cli_server_cmd_set_reply_text(a_str_reply, "parameters are not valid");
        return -1;
    }
}

/**
 * Node command
 */
int com_node(int a_argc, char ** a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    enum {
        CMD_NONE, CMD_ADD, CMD_DEL, CMD_LINK, CMD_ALIAS, CMD_HANDSHAKE, CMD_CONNECT, CMD_DUMP, CMD_CONNECTIONS, CMD_BALANCER
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "add", NULL)) {
        cmd_num = CMD_ADD;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "del", NULL)) {
        cmd_num = CMD_DEL;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "link", NULL)) {
        cmd_num = CMD_LINK;
    }
    else
    // find  add parameter ('alias' or 'handshake')
    if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "handshake", NULL)) {
        cmd_num = CMD_HANDSHAKE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "connect", NULL)) {
        cmd_num = CMD_CONNECT;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "alias", NULL)) {
        cmd_num = CMD_ALIAS;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "dump", NULL)) {
        cmd_num = CMD_DUMP;
    }
    else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "connections", NULL)) {
        cmd_num = CMD_CONNECTIONS;
    }
    else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "balancer", NULL)){
        cmd_num = CMD_BALANCER;
    }
    arg_index++;
    if(cmd_num == CMD_NONE) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "command %s not recognized", a_argv[1]);
        return -1;
    }
    const char *l_addr_str = NULL, *alias_str = NULL;
    const char *l_cell_str = NULL, *l_link_str = NULL;

    // find net
    dap_chain_net_t *l_net = NULL;

    if(dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, NULL, &l_net) < 0)
        return -11;

    // find addr, alias
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-alias", &alias_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cell", &l_cell_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-link", &l_link_str);

    // struct to write to the global db
    dap_chain_node_addr_t l_node_addr = { 0 };
    dap_chain_node_addr_t l_link = { 0 };
    dap_chain_node_info_t *l_node_info = NULL;
    size_t l_node_info_size = sizeof(l_node_info->hdr) + sizeof(l_link);
    if(cmd_num >= CMD_ADD && cmd_num <= CMD_LINK) {
        l_node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, l_node_info_size);
        if (!l_node_info) {
            log_it(L_CRITICAL, "Memory allocation error");
            return -1;
        }
    }

    if(l_addr_str) {
        if(dap_chain_node_addr_from_str(&l_node_addr, l_addr_str) != 0) {
            dap_digit_from_string(l_addr_str, l_node_addr.raw, sizeof(l_node_addr.raw));
        }
        if(l_node_info)
            l_node_info->hdr.address = l_node_addr;
    }

    if(l_cell_str && l_node_info) {
        dap_digit_from_string(l_cell_str, l_node_info->hdr.cell_id.raw, sizeof(l_node_info->hdr.cell_id.raw)); //DAP_CHAIN_CELL_ID_SIZE);
    }
    if(l_link_str) {
        if(dap_chain_node_addr_from_str(&l_link, l_link_str) != 0) {
            dap_digit_from_string(l_link_str, l_link.raw, sizeof(l_link.raw));
        }
    }    
    switch (cmd_num)
    {
    case CMD_ADD:
    {
        int l_ret =0;
        dap_chain_node_info_t *l_link_node_request = DAP_NEW_Z( dap_chain_node_info_t);
        l_link_node_request->hdr.address.uint64 = dap_chain_net_get_cur_addr_int(l_net);        
        l_link_node_request->hdr.ext_port = dap_config_get_item_uint16_default(g_config,"server","listen_port_tcp",8079);
        uint32_t links_count = 0;
        size_t l_blocks_events = 0;
        links_count = dap_chain_net_get_downlink_count(l_net);
        l_link_node_request->hdr.links_number = links_count;
        dap_chain_t *l_chain;
        DL_FOREACH(l_net->pub.chains, l_chain) {
            if(l_chain->callback_count_atom)
                l_blocks_events += l_chain->callback_count_atom(l_chain);
        }
        l_link_node_request->hdr.blocks_events = l_blocks_events;
        // Synchronous request, wait for reply
        int res = dap_chain_net_node_list_request(l_net,l_link_node_request, true, 0); // CMD_ADD

        switch (res)
        {
            case 1:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Node addr successfully added to node list");
            break;
            case 2:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't connect to server");
            break;
            case 3:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Node addr NOT added");
            break;
            case 4:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't calculate hash for your addr");
            break;
            case 5:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't do handshake for your node");
            break;
            case 6:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "The node is already exists");
            break;
            case 10:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't process node list HTTP request");
            break;
            default:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Unknown error code: %d", res);
                break;
        }
        DAP_DELETE(l_link_node_request);
        DAP_DELETE(l_node_info);
        return l_ret;
        //break;
    }
    case CMD_DEL:
        // handler of command 'node del'
    {
        if(!l_addr_str)
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Addr can't be del because -addr is not found");
            return -1;
        }
        int l_ret = node_info_del_with_reply(l_net, l_node_info, alias_str, a_str_reply);

        DAP_DELETE(l_node_info);
        break;
    }
    case CMD_LINK:
        if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "add", NULL)) {
            // handler of command 'node link add -addr <node address> -link <node address>'
            int l_ret = link_add_or_del_with_reply(l_net, l_node_info, "add", alias_str, &l_link, a_str_reply);
            DAP_DELETE(l_node_info);
            return l_ret;
        }
        else if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, dap_min(a_argc, arg_index + 1), "del", NULL)) {
            // handler of command 'node link del -addr <node address> -link <node address>'
            int l_ret = link_add_or_del_with_reply(l_net, l_node_info, "del", alias_str, &l_link, a_str_reply);
            DAP_DELETE(l_node_info);
            return l_ret;
        }
        else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "command not recognize, supported format:\n"
                    "global_db node link <add|del] [-addr <node address>  | -alias <node alias>] -link <node address>");
            DAP_DELETE(l_node_info);
            return -1;
        }

    case CMD_DUMP: {
        // handler of command 'node dump'
        bool l_is_full = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-full", NULL);
        return node_info_dump_with_reply(l_net, &l_node_addr, l_is_full, alias_str, a_str_reply);
    }
        // add alias
    case CMD_ALIAS:
        if(alias_str) {
            if(l_addr_str) {
                // add alias
                if(!dap_chain_node_alias_register(l_net, alias_str, &l_node_addr))
                    log_it(L_WARNING, "can't save alias %s", alias_str);
                else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "alias mapped successfully");
                }
            }
            else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "alias can't be mapped because -addr is not found");
                return -1;
            }
        }
        else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "alias can't be mapped because -alias is not found");
            return -1;
        }

        break;
        // make connect
    case CMD_CONNECT: {
        // get address from alias if addr not defined
        if(alias_str && !l_node_addr.uint64) {
            dap_chain_node_addr_t *address_tmp = dap_chain_node_addr_get_by_alias(l_net, alias_str);
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
            dap_list_t *l_node_link_list = dap_chain_net_get_link_node_list(l_net, a_is_only_cur_cell);
            // get all nodes list if no links
            if(!l_node_link_list)
                l_node_list = dap_chain_net_get_node_list(l_net);
            else
                l_node_list = dap_list_concat(l_node_link_list, l_node_list);

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
                    dap_chain_node_client_close_mt(l_node_client);
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
            dap_chain_node_client_close_mt(l_node_client);
            //DAP_DELETE(l_remote_node_info);
            return -1;
        }

        log_it(L_NOTICE, "Stream connection established");
        dap_stream_ch_chain_sync_request_t l_sync_request = {};
         dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch_unsafe(l_node_client->client, DAP_STREAM_CH_ID);
         // fill begin id
         l_sync_request.id_start = 1;
         // fill current node address
         l_sync_request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);

        // if need to get current node address (feature-2630)
        if(!l_sync_request.node_addr.uint64 )
        {
            log_it(L_NOTICE, "Now get node addr");
            uint8_t l_ch_id = DAP_STREAM_CH_ID_NET;
            dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch_unsafe(l_node_client->client, l_ch_id);

            size_t res = dap_stream_ch_chain_net_pkt_write(l_ch_chain,
            DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE_REQUEST,
            //DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST,
            l_net->pub.id,
            NULL, 0);
            if(res == 0) {
                log_it(L_WARNING, "Can't send DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST packet");
                dap_chain_node_client_close_mt(l_node_client);
                DAP_DELETE(l_remote_node_info);
                return -1;
            }
            int timeout_ms = 15000; // 15 sec = 15 000 ms
            int l_res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_NODE_ADDR_LEASED, timeout_ms);
            switch (l_res) {
            case 0:
                if(l_node_client->cur_node_addr.uint64 != 0) {
                    log_it(L_INFO, "Node address leased");
                    l_sync_request.node_addr.uint64 = l_node_client->cur_node_addr.uint64;
                    
                    // save cur address
                    // already saved
                    // dap_db_set_cur_node_addr_exp(l_sync_request.node_addr.uint64, l_net->pub.name);
                }
                else
                    log_it(L_WARNING, "Node address leased wrong!");
                break;
            case -1:
                log_it(L_WARNING, "Timeout with addr leasing");
            default:
                if(l_res != -1)
                    log_it(L_WARNING, "Node address request error %d", l_res);
                /*dap_chain_node_client_close(l_node_client);
                DAP_DELETE(l_remote_node_info);
                return -1;*/
            }
        }
        log_it(L_NOTICE, "Now lets sync all");

        log_it(L_INFO, "Requested GLOBAL_DB syncronizatoin, %"DAP_UINT64_FORMAT_U":%"DAP_UINT64_FORMAT_U" period", l_sync_request.id_start,
                l_sync_request.id_end);
        // copy l_sync_request to current
        //dap_stream_ch_chain_t * l_s_ch_chain = DAP_STREAM_CH_CHAIN(l_ch_chain);
        //l_s_ch_chain->request_net_id.uint64 = l_net->pub.id.uint64;
        //l_s_ch_chain->request_cell_id.uint64 = l_chain_cell_id_null.uint64;
        //memcpy(&l_s_ch_chain->request, &l_sync_request, sizeof(l_sync_request));

        if(0 == dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB,
                l_net->pub.id.uint64, 0, 0, &l_sync_request,
                sizeof(l_sync_request))) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Can't send sync chains request");
            // clean client struct
            dap_chain_node_client_close_mt(l_node_client);
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
            dap_chain_node_client_close_mt(l_node_client);
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
            dap_stream_ch_chain_sync_request_t l_sync_request = {};
            dap_chain_hash_fast_t *l_hash = dap_chain_db_get_last_hash_remote(l_node_client->remote_node_addr.uint64, l_chain);
            if (l_hash) {
                l_sync_request.hash_from = *l_hash;
                DAP_DELETE(l_hash);
            }
            if(0 == dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS,
                    l_net->pub.id.uint64, l_chain->id.uint64, l_remote_node_info->hdr.cell_id.uint64, &l_sync_request,
                    sizeof(l_sync_request))) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Can't send sync chains request");
                // clean client struct
                dap_chain_node_client_close_mt(l_node_client);
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
        dap_chain_node_client_close_mt(l_node_client);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Node sync completed: Chains and gdb are synced");
        return 0;

    }
        // make handshake
    case CMD_HANDSHAKE: {
        // get address from alias if addr not defined
        if(alias_str && !l_node_addr.uint64) {
            dap_chain_node_addr_t *address_tmp = dap_chain_node_addr_get_by_alias(l_net, alias_str);
            if(address_tmp) {
                l_node_addr = *address_tmp;
                DAP_DELETE(address_tmp);
            }
            else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "No address found by alias");
                return -4;
            }
        }
        if(!l_node_addr.uint64) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Addr not found");
            return -5;
        }

        dap_chain_node_info_t *node_info = node_info_read_and_reply(l_net, &l_node_addr, a_str_reply);
        if(!node_info)
            return -6;
        int timeout_ms = 5000; //5 sec = 5000 ms
        // start handshake
        dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(l_net,node_info);
        if(!l_client) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't connect");
            DAP_DELETE(node_info);
            return -7;
        }
        // wait handshake
        int res = dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
        if (res) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "No response from node");
            // clean client struct
            dap_chain_node_client_close_mt(l_client);
            DAP_DELETE(node_info);
            return -8;
        }
        DAP_DELETE(node_info);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Connection established");
    }
    case CMD_CONNECTIONS: {
        char *l_reply = dap_chain_net_links_dump(l_net);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_reply);
        DAP_DELETE(l_reply);
    } break;
    case CMD_BALANCER: {
        //balancer link list
        size_t l_node_num = 0;
        dap_string_t * l_string_balanc = dap_string_new("\n");
        l_node_num = dap_list_length(l_net->pub.link_list);
        dap_string_append_printf(l_string_balanc, "Got %d records\n", (uint16_t)l_node_num);
        dap_string_append_printf(l_string_balanc, "%-26s%-20s%s", "Address", "IPv4", "downlinks\n");
        for(dap_list_t *ll = l_net->pub.link_list; ll; ll = ll->next)
        {
            dap_chain_node_info_t *l_node_link = (dap_chain_node_info_t*)ll->data;
            dap_string_append_printf(l_string_balanc, NODE_ADDR_FP_STR"    %-20s%u\n",
                                     NODE_ADDR_FP_ARGS_S(l_node_link->hdr.address),
                                     inet_ntoa(l_node_link->hdr.ext_addr_v4),
                                     l_node_link->hdr.links_number);
        }
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Balancer link list:\n %s \n",
                                          l_string_balanc->str);
        dap_string_free(l_string_balanc, true);
    }
        break;
    }
    return 0;
}


#ifndef DAP_OS_ANDROID
/**
 * @brief Traceroute command
 * return 0 OK, -1 Err
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_traceroute(int argc, char** argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
#ifdef DAP_OS_LINUX
    const char *addr = NULL;
    int hops = 0, time_usec = 0;
    if(argc > 1)
        addr = argv[1];
    iputils_set_verbose();
    int res = (addr) ? traceroute_util(addr, &hops, &time_usec) : -EADDRNOTAVAIL;
    if(res >= 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s hops=%d time=%.1lf ms", addr, hops,
                time_usec * 1. / 1000);
    }
    else {
        if(a_str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case 2:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr,
                        "Unknown traceroute module");
                break;
            case 3:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr, "first hop out of range");
                break;
            case 4:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr,
                        "max hops cannot be more than 255");
                break;
            case 5:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr,
                        "no more than 10 probes per hop");
                break;
            case 6:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr,
                        "bad wait specifications");
                break;
            case 7:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr, "too big packetlen ");
                break;
            case 8:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr,
                        "IP version mismatch in addresses specified");
                break;
            case 9:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr, "bad sendtime");
                break;
            case 10:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr, "init_ip_options");
                break;
            case 11:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr, "calloc");
                break;
            case 12:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr, "parse cmdline");
                break;
            case 13:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error: %s", addr,
                        "trace method's init failed");
                break;
            default:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "traceroute %s error(%d) %s", addr, res,
                        "trace not found");
            }
        }
    }
    return res;
#else
    UNUSED(argc);
    UNUSED(argv);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Not realized for your platform");
    return -1;
#endif
}



/**
 * @brief com_tracepath
 * Tracepath command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 * return 0 OK, -1 Err
 */
int com_tracepath(int argc, char** argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
#ifdef DAP_OS_LINUX
    const char *addr = NULL;
    int hops = 0, time_usec = 0;
    if(argc > 1)
        addr = argv[1];
    iputils_set_verbose();
    int res = (addr) ? tracepath_util(addr, &hops, &time_usec) : -EADDRNOTAVAIL;
    if(res >= 0) {
        if(a_str_reply)
            dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s hops=%d time=%.1lf ms", addr, hops,
                    time_usec * 1. / 1000);
    }
    else {
        if(a_str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case ESOCKTNOSUPPORT:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr, "Can't create socket");
                break;
            case 2:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_MTU_DISCOVER");
                break;
            case 3:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_RECVERR");
                break;
            case 4:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_HOPLIMIT");
                break;
            case 5:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IP_MTU_DISCOVER");
                break;
            case 6:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IP_RECVERR");
                break;
            case 7:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IP_RECVTTL");
                break;
            case 8:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr, "malloc");
                break;
            case 9:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_UNICAST_HOPS");
                break;
            case 10:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IP_TTL");
                break;
            default:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "tracepath %s error(%d) %s", addr, res, "trace not found");
            }
        }
    }
    return res;
#else
    UNUSED(argc);
    UNUSED(argv);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Not realized for your platform");
    return -1;
#endif
}


/**
 * @brief Ping command
 * return 0 OK, -1 Err
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_ping(int a_argc, char**a_argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
#ifdef DAP_OS_LINUX

    int n = 4,w = 0;
    if (a_argc < 2) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Host not specified");
        return -1;
    }
    const char *n_str = NULL;
    const char *w_str = NULL;
    int argc_host = 1;
    int argc_start = 1;
    argc_start = dap_cli_server_cmd_find_option_val(a_argv, argc_start, a_argc, "-n", &n_str);
    if(argc_start) {
        argc_host = argc_start + 1;
        n = (n_str) ? atoi(n_str) : 4;
    }
    else {
        argc_start = dap_cli_server_cmd_find_option_val(a_argv, argc_start, a_argc, "-c", &n_str);
        if(argc_start) {
            argc_host = argc_start + 1;
            n = (n_str) ? atoi(n_str) : 4;
        }
        else
        {
            argc_start = dap_cli_server_cmd_find_option_val(a_argv, argc_start, a_argc, "-w", &w_str);
            if(argc_start) {
                argc_host = argc_start + 1;
                n = 4;
                w = (w_str) ? atoi(w_str) : 5;
            }
        }
    }
    if(n <= 1)
        n = 1;
    const char *addr = a_argv[argc_host];
    iputils_set_verbose();
    ping_handle_t *l_ping_handle = ping_handle_create();
    int res = (addr) ? ping_util(l_ping_handle, addr, n, w) : -EADDRNOTAVAIL;
    DAP_DELETE(l_ping_handle);
    if(res >= 0) {
        if(a_str_reply)
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Ping %s time=%.1lf ms", addr, res * 1. / 1000);
    }
    else {
        if(a_str_reply) {
            switch (-res)
            {
            case EDESTADDRREQ:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Ping %s error: %s", addr, "Destination address required");
                break;
            case EADDRNOTAVAIL:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Ping %s error: %s", (addr) ? addr : "",
                        (addr) ? "Host not found" : "Host not defined");
                break;
            case EPFNOSUPPORT:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Ping %s error: %s", addr, "Unknown protocol family");
                break;
            default:
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Ping %s error(%d)", addr, -res);
            }
        }
    }
    return res;
#else
    UNUSED(a_argc);
    UNUSED(a_argv);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Not realized for your platform");
    return -1;
#endif
}
#endif /* !ANDROID (1582) */

/**
 * @brief com_version
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_version(int argc, char ** argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
    (void) argc;
    (void) argv;
#ifndef DAP_VERSION
#pragma message "[!WRN!] DAP_VERSION IS NOT DEFINED. Manual override engaged."
#define DAP_VERSION "0.9-15"
#endif
    dap_cli_server_cmd_set_reply_text(a_str_reply,
            "%s version %s\n", dap_get_appname(), DAP_VERSION );
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
int com_help(int a_argc, char **a_argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
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
int com_tx_wallet(int a_argc, char **a_argv, void **reply)
{
char ** a_str_reply = (char **) reply;
const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
enum { CMD_NONE, CMD_WALLET_NEW, CMD_WALLET_LIST, CMD_WALLET_INFO, CMD_WALLET_ACTIVATE, CMD_WALLET_DEACTIVATE, CMD_WALLET_CONVERT };
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

    l_arg_index++;

    if(cmd_num == CMD_NONE) {
        dap_cli_server_cmd_set_reply_text (a_str_reply,
                "Format of command: wallet {new -w <wallet_name> | list | info [-addr <addr>]|[-w <wallet_name> -net <net_name>]}");
        return -1;
    }

    const char *l_addr_str = NULL, *l_wallet_name = NULL, *l_net_name = NULL, *l_sign_type_str = NULL, *l_restore_str = NULL,
            *l_pass_str = NULL, *l_ttl_str = NULL;

    // find wallet addr
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-password", &l_pass_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-sign", &l_sign_type_str);

    // Check if wallet name has only digits and English letter
    if (l_wallet_name && !dap_isstralnum(l_wallet_name)){
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet name must contains digits and aplhabetical symbols");
        return -1;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    dap_string_t *l_string_ret = dap_string_new(NULL);
    dap_chain_wallet_t *l_wallet = NULL;
    dap_chain_addr_t *l_addr = NULL;

    if(l_net_name && !l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Not found net by name '%s'", l_net_name);
        return -1;
    }

    switch (cmd_num) {
        // wallet list
        case CMD_WALLET_LIST: {
            DIR * l_dir = opendir(c_wallets_path);
            if(l_dir) {
                struct dirent * l_dir_entry = NULL;

                while( (l_dir_entry = readdir(l_dir)) ) {
                    const char *l_file_name = l_dir_entry->d_name;
                    size_t l_file_name_len = (l_file_name) ? strlen(l_file_name) : 0;

                    if ( (l_file_name_len > 8) && (!strcmp(l_file_name + l_file_name_len - 8, ".dwallet")) ) {
                        char l_file_path_tmp[MAX_PATH] = {0};
                        snprintf(l_file_path_tmp, sizeof(l_file_path_tmp) - 1, "%s/%s", c_wallets_path, l_file_name);

                        l_wallet = dap_chain_wallet_open(l_file_name, c_wallets_path);

                        if (l_wallet) {
                            l_addr = l_net ? dap_chain_wallet_get_addr(l_wallet, l_net->pub.id) : NULL;
                            char *l_addr_str = dap_chain_addr_to_str(l_addr);

                            dap_string_append_printf(l_string_ret, "Wallet: %.*s%s %s\n", (int) l_file_name_len - 8, l_file_name,
                                (l_wallet->flags & DAP_WALLET$M_FL_ACTIVE) ? " (Active)" : "",
                                dap_chain_wallet_check_sign(l_wallet));

                            if (l_addr_str) {
                                dap_string_append_printf(l_string_ret, "addr: %s\n", (l_addr_str) ? l_addr_str : "-");
                                DAP_DELETE(l_addr_str);
                            }

                            dap_chain_wallet_close(l_wallet);

                        } else dap_string_append_printf(l_string_ret, "Wallet: %.*s (non-Active)\n", (int) l_file_name_len - 8, l_file_name);
                    } else if ((l_file_name_len > 7) && (!strcmp(l_file_name + l_file_name_len - 7, ".backup"))) {
                        dap_string_append_printf(l_string_ret, "Wallet: %.*s (Backup)\n", (int) l_file_name_len - 7, l_file_name);
                    }
                }
                closedir(l_dir);
            }
            break;
        }
        // wallet info
        case CMD_WALLET_INFO: {
            dap_ledger_t *l_ledger = NULL;
            if ((l_wallet_name && l_addr_str) || (!l_wallet_name && !l_addr_str)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "You should use either the -w or -addr option for the wallet info command.");
                dap_string_free(l_string_ret, true);
                return -1;
            }
            if(l_wallet_name) {
                if(!l_net) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand info requires parameter '-net'");
                    dap_string_free(l_string_ret, true);
                    return -1;
                }
                l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
                l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id );
            } else {
                l_addr = dap_chain_addr_from_str(l_addr_str);
            }
            
            if (!l_addr){
                if(l_wallet)
                    dap_chain_wallet_close(l_wallet);
                dap_string_free(l_string_ret, true);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet not found");
                return -1;
            } else {
                l_net = dap_chain_net_by_id(l_addr->net_id);
                if(l_net) {
                    l_ledger = l_net->pub.ledger;
                    l_net_name = l_net->pub.name;
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find network id 0x%016"DAP_UINT64_FORMAT_X" from address %s",
                                                    l_addr->net_id.uint64, l_addr_str);
                    dap_string_free(l_string_ret, true);
                    return -1;
                }
            }

            char *l_l_addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) l_addr);
            if (l_wallet)
                dap_string_append_printf(l_string_ret, "%swallet: %s\n", dap_chain_wallet_check_sign(l_wallet), l_wallet->name);
            dap_string_append_printf(l_string_ret, "addr: %s\n", (l_l_addr_str) ? l_l_addr_str : "-");
            dap_string_append_printf(l_string_ret, "network: %s\n", (l_net_name ) ? l_net_name : "-");

            size_t l_l_addr_tokens_size = 0;
            char **l_l_addr_tokens = NULL;
            dap_ledger_addr_get_token_ticker_all(l_ledger, l_addr, &l_l_addr_tokens, &l_l_addr_tokens_size);
            if(l_l_addr_tokens_size > 0)
                dap_string_append_printf(l_string_ret, "balance:\n");
            else
                dap_string_append_printf(l_string_ret, "balance: 0");

            for(size_t i = 0; i < l_l_addr_tokens_size; i++) {
                if(l_l_addr_tokens[i]) {
                    uint256_t l_balance = dap_ledger_calc_balance(l_ledger, l_addr, l_l_addr_tokens[i]);
                    char *l_balance_coins = dap_chain_balance_to_coins(l_balance);
                    char *l_balance_datoshi = dap_chain_balance_print(l_balance);
                    dap_string_append_printf(l_string_ret, "\t%s (%s) %s\n", l_balance_coins,
                            l_balance_datoshi, l_l_addr_tokens[i]);
                    if(i < l_l_addr_tokens_size - 1)
                        dap_string_append_printf(l_string_ret, "\n");
                    DAP_DELETE(l_balance_coins);
                    DAP_DELETE(l_balance_datoshi);

                }
                DAP_DELETE(l_l_addr_tokens[i]);
            }
            DAP_DELETE(l_l_addr_tokens);
            DAP_DELETE(l_l_addr_str);
            if(l_wallet)
                dap_chain_wallet_close(l_wallet);
            break;
        }
        default: {
            if( !l_wallet_name ) {
                dap_string_free(l_string_ret, true);
                return  dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet name option <-w>  not defined"), -EINVAL;
            }
            if( cmd_num != CMD_WALLET_DEACTIVATE && !l_pass_str && cmd_num != CMD_WALLET_NEW) {
                dap_string_free(l_string_ret, true);
                return  dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet password option <-password>  not defined"), -EINVAL;
            }
            if ( cmd_num != CMD_WALLET_DEACTIVATE && l_pass_str && DAP_WALLET$SZ_PASS < strnlen(l_pass_str, DAP_WALLET$SZ_PASS + 1) ) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet's password is too long ( > %d)", DAP_WALLET$SZ_PASS);
                log_it(L_ERROR, "Wallet's password is too long ( > %d)", DAP_WALLET$SZ_PASS);
                dap_string_free(l_string_ret, true);
                return -EINVAL;
            }
            switch (cmd_num) {
                case CMD_WALLET_ACTIVATE:
                case CMD_WALLET_DEACTIVATE: {
                    const char *l_prefix = cmd_num == CMD_WALLET_ACTIVATE ? "" : "de";
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-ttl", &l_ttl_str);
                    l_rc = l_ttl_str ? strtoul(l_ttl_str, NULL, 10) : 60;

                    l_rc = cmd_num == CMD_WALLET_ACTIVATE
                            ? dap_chain_wallet_activate(l_wallet_name, strlen(l_wallet_name), l_pass_str, strlen(l_pass_str), l_rc)
                            : dap_chain_wallet_deactivate (l_wallet_name, strlen(l_wallet_name));

                    switch (l_rc) {
                    case 0:
                        dap_string_append_printf(l_string_ret, "Wallet %s is %sactivated\n", l_wallet_name, l_prefix);
                        break;
                    case -EBUSY:
                        dap_string_append_printf(l_string_ret, "Error: wallet %s is already %sactivated\n", l_wallet_name, l_prefix);
                        break;
                    case -EAGAIN:
                        dap_string_append_printf(l_string_ret, "Error: wrong password for wallet %s\n", l_wallet_name);
                        break;
                    default: {
                        char l_buf[512] = { '\0' };
                        strerror_r(l_rc, l_buf, sizeof(l_buf) - 1);
                        dap_string_append_printf(l_string_ret, "Wallet %s %sactivation error %d : %s\n", l_wallet_name, l_prefix, l_rc, l_buf);
                        break;
                    }
                    }
                } break;
                // convert wallet
                case CMD_WALLET_CONVERT: {
                    l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
                    if (!l_wallet) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "wrong password");
                        return -1;
                    } else if (l_wallet->flags & DAP_WALLET$M_FL_ACTIVE) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet can't be converted twice");
                        dap_string_free(l_string_ret, true);
                        return  -1;
                    }
                    // create wallet backup 
                    dap_chain_wallet_internal_t* l_file_name = DAP_CHAIN_WALLET_INTERNAL(l_wallet);
                    snprintf(l_file_name->file_name, sizeof(l_file_name->file_name)  - 1, "%s/%s_%012lu%s", c_wallets_path, l_wallet_name, time(NULL),".backup");
                    if ( dap_chain_wallet_save(l_wallet, NULL) ) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create backup wallet file because of internal error");
                        dap_string_free(l_string_ret, true);
                        return  -1;
                    }
                    // change to old filename
                    snprintf(l_file_name->file_name, sizeof(l_file_name->file_name)  - 1, "%s/%s%s", c_wallets_path, l_wallet_name, ".dwallet");
                    if ( dap_chain_wallet_save(l_wallet, l_pass_str) ) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet is not converted because of internal error");
                        dap_string_free(l_string_ret, true);
                        return  -1;
                    }

                    log_it(L_INFO, "Wallet %s has been converted", l_wallet_name);
                    dap_string_append_printf(l_string_ret, "%sWallet: %s successfully converted\n", dap_chain_wallet_check_sign(l_wallet), l_wallet_name);
                    dap_chain_wallet_close(l_wallet);
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
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet %s already exists", l_wallet_name);
                            fclose(l_exists);
                            dap_string_free(l_string_ret, true);
                            return -1;
                        }
                    }

                    dap_sign_type_t l_sign_type;
                    if (!l_sign_type_str) {
                        l_sign_type.type = SIG_TYPE_DILITHIUM;
                        l_sign_type_str = dap_sign_type_to_str(l_sign_type);
                    } else {
                        l_sign_type = dap_sign_type_from_str(l_sign_type_str);
                        if (l_sign_type.type == SIG_TYPE_NULL){
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "Unknown signature type, please use:\n sig_picnic\n sig_dil\n sig_falcon\n sig_multi\n sig_multi2\n");
                            dap_string_free(l_string_ret, true);
                            return -1;
                        }
                    }

                    if (l_sign_type.type == SIG_TYPE_TESLA || l_sign_type.type == SIG_TYPE_BLISS || l_sign_type.type == SIG_TYPE_PICNIC) {
                        if ((l_sign_type.type == SIG_TYPE_BLISS || l_sign_type.type == SIG_TYPE_PICNIC) && (l_restore_opt || l_restore_legacy_opt)) {
                            dap_string_append_printf(l_string_ret, "CAUTION!!! CAUTION!!! CAUTION!!!\nThe Bliss, Tesla and Picnic signatures are deprecated. We recommend you to create a new wallet with another available signature and transfer funds there.\n");
                        } else {
                            dap_string_free(l_string_ret, true);
                            return  dap_cli_server_cmd_set_reply_text(a_str_reply, "This signature algorithm is no longer supported, please, use another variant"), -1;
                        }
                    }

                    uint8_t *l_seed = NULL;
                    size_t l_seed_size = 0, l_restore_str_size = dap_strlen(l_restore_str);

                    if(l_restore_opt || l_restore_legacy_opt) {
                        if (l_restore_str_size > 3 && !dap_strncmp(l_restore_str, "0x", 2) && (!dap_is_hex_string(l_restore_str + 2, l_restore_str_size - 2) || l_restore_legacy_opt)) {
                            l_seed_size = (l_restore_str_size - 2) / 2;
                            l_seed = DAP_NEW_Z_SIZE(uint8_t, l_seed_size);
                            if(!l_seed) {
                                log_it(L_CRITICAL, "Memory allocation error");
                                dap_string_free(l_string_ret, true);
                                return -1;
                            }
                            dap_hex2bin(l_seed, l_restore_str + 2, l_restore_str_size - 2);
                            if (l_restore_legacy_opt) {
                                dap_string_append_printf(l_string_ret, "CAUTION!!! CAUTION!!! CAUTION!!!\nYour wallet has a low level of protection. Please create a new wallet again with the option -restore\n");
                            }
                        } else {
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "Restored hash is invalid or too short, wallet is not created. Please use -restore 0x<hex_value> or -restore_legacy 0x<restore_string>");
                            dap_string_free(l_string_ret, true);
                            return -1;
                        }
                    }

                    // Creates new wallet
                    l_wallet = dap_chain_wallet_create_with_seed(l_wallet_name, c_wallets_path, l_sign_type,
                            l_seed, l_seed_size, l_pass_str);
                    DAP_DELETE(l_seed);
                    if (!l_wallet) {
                        dap_string_free(l_string_ret, true);
                        return  dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet is not created because of internal error. Check name or password length (max 64 chars)"), -1;
                    }

                    l_addr = l_net? dap_chain_wallet_get_addr(l_wallet,l_net->pub.id ) : NULL;

                    char *l_l_addr_str = l_addr ? dap_chain_addr_to_str(l_addr) : NULL;
                    dap_string_append_printf(l_string_ret, "Wallet: %s (type=%s) successfully created\n", l_wallet->name, l_sign_type_str);
                    if ( l_l_addr_str ) {
                        dap_string_append_printf(l_string_ret, "new address %s", l_l_addr_str);
                        DAP_DELETE(l_l_addr_str);
                    }
                    dap_chain_wallet_close(l_wallet);
                    break;
                }
            }
        }
    }

    *a_str_reply = dap_string_free(l_string_ret, false);
    return 0;
}


typedef enum dap_chain_node_cli_cmd_values_parse_net_chain_err_to_json {
    DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_INTERNAL_COMMAND_PROCESSING = 101,
    DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_STR_IS_NUL = 102,
    DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_NOT_FOUND = 103,
    DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CHAIN_NOT_FOUND = 104,
    DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CHAIN_STR_IS_NULL = 105,
    DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CONFIG_DEFAULT_DATUM = 106,
    DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_CONVERT_BASE58_TO_ADDR_WALLET = 107,
    DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_FAST_AND_BASE58_ADDR
} dap_chain_node_cli_cmd_values_parse_net_chain_err_to_json;
int dap_chain_node_cli_cmd_values_parse_net_chain_for_json(int *a_arg_index, int a_argc,
                                                           char **a_argv,
                                                           dap_chain_t **a_chain, dap_chain_net_t **a_net) {
    const char * l_chain_str = NULL;
    const char * l_net_str = NULL;

    // Net name
    if(a_net)
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-net", &l_net_str);
    else {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_INTERNAL_COMMAND_PROCESSING,
                               "Error in internal command processing.");
        return DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_INTERNAL_COMMAND_PROCESSING;
    }

    // Select network
    if(!l_net_str) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_STR_IS_NUL, "%s requires parameter '-net'", a_argv[0]);
        return DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_STR_IS_NUL;
    }

    if((*a_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
        char l_str_to_reply_chain[500] = {0};
        char *l_str_to_reply = NULL;
        sprintf(l_str_to_reply_chain, "%s can't find network \"%s\"\n", a_argv[0], l_net_str);
        l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
        dap_string_t* l_net_str = dap_cli_list_net();
        l_str_to_reply = dap_strcat2(l_str_to_reply,l_net_str->str);
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_NOT_FOUND, "%s can't find network \"%s\"\n%s", a_argv[0], l_net_str->str, l_str_to_reply);
        return DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_NOT_FOUND;
    }

    // Chain name
    if(a_chain) {
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-chain", &l_chain_str);

        // Select chain
        if(l_chain_str) {
            if ((*a_chain = dap_chain_net_get_chain_by_name(*a_net, l_chain_str)) == NULL) { // Can't find such chain
                char l_str_to_reply_chain[500] = {0};
                char *l_str_to_reply = NULL;
                sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                        a_argv[0], l_net_str, l_chain_str);
                l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                dap_chain_t * l_chain;
                dap_chain_net_t * l_chain_net = *a_net;
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chains:\n");
                DL_FOREACH(l_chain_net->pub.chains, l_chain) {
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                }
                dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CHAIN_NOT_FOUND, l_str_to_reply);
                return DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CHAIN_NOT_FOUND;
            }
        }
        else if (!strcmp(a_argv[0], "token_decl")  || !strcmp(a_argv[0], "token_decl_sign")) {
            if (	(*a_chain = dap_chain_net_get_default_chain_by_chain_type(*a_net, CHAIN_TYPE_TOKEN)) == NULL )
            {
                dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CONFIG_DEFAULT_DATUM, "%s requires parameter '-chain' or set default datum "
                                             "type in chain configuration file");
                return DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CONFIG_DEFAULT_DATUM;
            }
        }
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
int dap_chain_node_cli_cmd_values_parse_net_chain(int *a_arg_index, int a_argc, char **a_argv, char ** a_str_reply,
        dap_chain_t **a_chain, dap_chain_net_t **a_net)
{
    const char * l_chain_str = NULL;
    const char * l_net_str = NULL;

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

    if((*a_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s can't find network \"%s\"", a_argv[0], l_net_str);
        char l_str_to_reply_chain[500] = {0};
        char *l_str_to_reply = NULL;
        sprintf(l_str_to_reply_chain, "%s can't find network \"%s\"\n", a_argv[0], l_net_str);
        l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
        dap_string_t* l_net_str = dap_cli_list_net();
        l_str_to_reply = dap_strcat2(l_str_to_reply,l_net_str->str);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
        return -102;
    }

    // Chain name
    if(a_chain) {
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-chain", &l_chain_str);

        // Select chain
        if(l_chain_str) {
            if ((*a_chain = dap_chain_net_get_chain_by_name(*a_net, l_chain_str)) == NULL) { // Can't find such chain
                char l_str_to_reply_chain[500] = {0};
                char *l_str_to_reply = NULL;
                sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                        a_argv[0], l_net_str, l_chain_str);
                l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                dap_chain_t * l_chain;
                dap_chain_net_t * l_chain_net = *a_net;
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chains:\n");
                DL_FOREACH(l_chain_net->pub.chains, l_chain) {
                        l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                        l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                        l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                }
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                return -103;
            }
        }
        else if (	!strcmp(a_argv[0], "token_decl")
        ||			!strcmp(a_argv[0], "token_decl_sign")) {
            if (	(*a_chain = dap_chain_net_get_default_chain_by_chain_type(*a_net, CHAIN_TYPE_TOKEN)) == NULL )
            {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "%s requires parameter '-chain' or set default datum type in chain configuration file",
                                                  a_argv[0]);
                return -105;
            }
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-chain'", a_argv[0]);
            return -104;
        }
    }
    return 0;
}

/**
 * @brief
 * sign data (datum_token) by certificates (1 or more)
 * successful count of signes return in l_sign_counter
 * @param l_certs - array with certificates loaded from dcert file
 * @param l_datum_token - updated pointer for l_datum_token variable after realloc
 * @param l_certs_count - count of certificate
 * @param l_datum_data_offset - offset of datum
 * @param l_sign_counter - counter of successful data signing operation
 * @return dap_chain_datum_token_t*
 */
static dap_chain_datum_token_t * s_sign_cert_in_cycle(dap_cert_t ** l_certs, dap_chain_datum_token_t *l_datum_token, size_t l_certs_count,
            size_t *l_datum_signs_offset, uint16_t * l_sign_counter)
{
    if (!l_datum_signs_offset) {
        log_it(L_DEBUG,"l_datum_data_offset is NULL");
        return NULL;
    }

    size_t l_tsd_size = 0;
    if ((l_datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL) &&
            ((l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
            ||(l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)))
        l_tsd_size = l_datum_token->header_native_decl.tsd_total_size;
    if ((l_datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE) &&
            ((l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
             ||(l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE)))
        l_tsd_size = l_datum_token->header_native_update.tsd_total_size;
    uint16_t l_tmp_cert_sign_count = l_datum_token->signs_total;
    l_datum_token->signs_total = 0;

    for(size_t i = 0; i < l_certs_count; i++)
    {
        dap_sign_t * l_sign = dap_cert_sign(l_certs[i],  l_datum_token,
           sizeof(*l_datum_token) + l_tsd_size, 0);

        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            l_datum_token = DAP_REALLOC(l_datum_token, sizeof(*l_datum_token) + (*l_datum_signs_offset) + l_sign_size);
            memcpy(l_datum_token->data_n_tsd + *l_datum_signs_offset, l_sign, l_sign_size);
            *l_datum_signs_offset += l_sign_size;
            DAP_DELETE(l_sign);
            log_it(L_DEBUG,"<-- Signed with '%s'", l_certs[i]->name);
            (*l_sign_counter)++;
        }
    }
    l_datum_token->signs_total = l_tmp_cert_sign_count;

    return l_datum_token;
}

/**
 * @brief com_token_decl_sign
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_token_decl_sign(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    int arg_index = 1;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    const char * l_datum_hash_str = NULL;
    // Chain name
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
    if(l_datum_hash_str) {
        char *l_datum_hash_hex_str = NULL, *l_datum_hash_base58_str = NULL;
        const char * l_certs_str = NULL;
        dap_cert_t ** l_certs = NULL;
        size_t l_certs_count = 0;
        dap_chain_t * l_chain = NULL;
        dap_chain_net_t * l_net = NULL;

        dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net);
        if(!l_net)
            return -1;
        else {
            if(*a_str_reply) {
                DAP_DELETE(*a_str_reply);
                *a_str_reply = NULL;
            }
        }

        // Certificates thats will be used to sign currend datum token
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);

        // Load certs lists
        if (l_certs_str)
            dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);

        if(!l_certs_count) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "token_sign command requres at least one valid certificate to sign the basic transaction of emission");
            return -7;
        }

        char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(l_chain);
        if(!l_gdb_group_mempool) {
            l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);
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

        log_it(L_DEBUG, "Requested to sign token declaration %s in gdb://%s with certs %s",
                l_gdb_group_mempool, l_datum_hash_hex_str, l_certs_str);

        dap_chain_datum_t * l_datum = NULL;
        size_t l_datum_size = 0;
        size_t l_tsd_size = 0;
        if((l_datum = (dap_chain_datum_t*) dap_global_db_get_sync(l_gdb_group_mempool,
                l_datum_hash_hex_str, &l_datum_size, NULL, NULL )) != NULL) {

            // Check if its token declaration
            if(l_datum->header.type_id == DAP_CHAIN_DATUM_TOKEN_DECL ||
                l_datum->header.type_id == DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE) {
                dap_chain_datum_token_t *l_datum_token = DAP_DUP_SIZE(l_datum->data, l_datum->header.data_size);    // for realloc
                DAP_DELETE(l_datum);
                if ((l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)
                    ||  (l_datum_token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE))
                    l_tsd_size = l_datum_token->header_native_decl.tsd_total_size;
                // Check for signatures, are they all in set and are good enought?
                size_t l_signs_size = 0, i = 1;
                for (i = 1; i <= l_datum_token->signs_total; i++){
                    dap_sign_t *l_sign = (dap_sign_t *)(l_datum_token->data_n_tsd + l_tsd_size + l_signs_size);
                    if( dap_sign_verify(l_sign, l_datum_token, sizeof(*l_datum_token) - sizeof(uint16_t)) != 1) {
                        log_it(L_WARNING, "Wrong signature %zu for datum_token with key %s in mempool!", i, l_datum_hash_out_str);
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                "Datum %s with datum token has wrong signature %zu, break process and exit",
                                l_datum_hash_out_str, i);
                        DAP_DELETE(l_datum_token);
                        DAP_DELETE(l_gdb_group_mempool);
                        return -6;
                    }else{
                        log_it(L_DEBUG,"Sign %zu passed", i);
                    }
                    l_signs_size += dap_sign_get_size(l_sign);
                }

                log_it(L_DEBUG, "Datum %s with token declaration: %hu signatures are verified well (sign_size = %zu)",
                                 l_datum_hash_out_str, l_datum_token->signs_total, l_signs_size);

                // Sign header with all certificates in the list and add signs to the end of token update
                uint16_t l_sign_counter = 0;
                size_t l_data_size = l_tsd_size + l_signs_size;
                l_datum_token = s_sign_cert_in_cycle(l_certs, l_datum_token, l_certs_count, &l_data_size,
                                                            &l_sign_counter);
                l_datum_token->signs_total += l_sign_counter;
                size_t l_token_size = sizeof(*l_datum_token) + l_data_size;
                dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_DECL,
                                                                     l_datum_token, l_token_size);
                DAP_DELETE(l_datum_token);
                // Calc datum's hash
                l_datum_size = dap_chain_datum_size(l_datum);
                dap_chain_hash_fast_t l_key_hash = { };
                dap_hash_fast(l_datum->data, l_token_size, &l_key_hash);
                char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
                char * l_key_str_base58 = dap_enc_base58_encode_hash_to_str(&l_key_hash);
                const char *l_key_out_str = dap_strcmp(l_hash_out_type,"hex")
                        ? l_key_str_base58 : l_key_str;
                // Add datum to mempool with datum_token hash as a key
                if( dap_global_db_set_sync(l_gdb_group_mempool, l_key_str, l_datum, dap_chain_datum_size(l_datum), false) == 0) {

                    char* l_hash_str = l_datum_hash_hex_str;
                    // Remove old datum from pool
                    if( dap_global_db_del_sync(l_gdb_group_mempool, l_hash_str ) == 0) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                "datum %s is replacing the %s in datum pool",
                                l_key_out_str, l_datum_hash_out_str);
                        DAP_DELETE(l_key_str);
                        DAP_DELETE(l_key_str_base58);
                        DAP_DELETE(l_datum);
                        //DAP_DELETE(l_datum_token);
                        DAP_DELETE(l_gdb_group_mempool);
                        return 0;
                    } else {
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                "Warning! Can't remove old datum %s ( new datum %s added normaly in datum pool)",
                                l_datum_hash_out_str, l_key_out_str);
                        DAP_DELETE(l_key_str);
                        DAP_DELETE(l_key_str_base58);
                        DAP_DELETE(l_datum);
                        //DAP_DELETE(l_datum_token);
                        DAP_DELETE(l_gdb_group_mempool);
                        return 1;
                    }
                    DAP_DELETE(l_hash_str);
                    DAP_DELETE(l_key_str);
                    DAP_DELETE(l_key_str_base58);
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                            "Error! datum %s produced from %s can't be placed in mempool",
                            l_key_out_str, l_datum_hash_out_str);
                    DAP_DELETE(l_datum);
                    //DAP_DELETE(l_datum_token);
                    DAP_DELETE(l_gdb_group_mempool);
                    DAP_DELETE(l_key_str);
                    DAP_DELETE(l_key_str_base58);
                    return -2;
                }
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Error! Wrong datum type. token_decl_sign sign only token declarations datum");
                return -61;
            }
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "token_decl_sign can't find datum with %s hash in the mempool of %s:%s",l_datum_hash_out_str,l_net? l_net->pub.name: "<undefined>",
                    l_chain?l_chain->name:"<undefined>");
            return -5;
        }
        DAP_DELETE(l_datum_hash_hex_str);
        DAP_DELETE(l_datum_hash_base58_str);
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "token_decl_sign need -datum <datum hash> argument");
        return -2;
    }
    return 0;
}

static bool s_mempool_find_addr_ledger(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_prev_hash, dap_chain_addr_t *a_addr)
{
    dap_chain_datum_tx_t *l_tx;
    l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_tx_prev_hash);
    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL), *l_item;
    if(!l_list_out_items)
        return false;
    bool l_ret = false;
    DL_FOREACH(l_list_out_items, l_item) {
        //assert(l_list_out->data);
        dap_chain_addr_t *l_dst_addr = NULL;
        dap_chain_tx_item_type_t l_type = *(uint8_t*)l_item->data;
        switch (l_type) {
        case TX_ITEM_TYPE_OUT:
            l_dst_addr = &((dap_chain_tx_out_t*)l_item->data)->addr;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_dst_addr = &((dap_chain_tx_out_ext_t*)l_item->data)->addr;
            break;
        case TX_ITEM_TYPE_OUT_OLD:
            l_dst_addr = &((dap_chain_tx_out_old_t*)l_item->data)->addr;
        default:
            break;
        }
        if(l_dst_addr && !memcmp(l_dst_addr, a_addr, sizeof(dap_chain_addr_t))) {
            l_ret = true;
            break;
        }
    }
    dap_list_free(l_list_out_items);
    return l_ret;
}

/**
 * @brief s_com_mempool_list_print_for_chain
 *
 * @param a_net
 * @param a_chain
 * @param a_str_tmp
 * @param a_hash_out_type
 */
void s_com_mempool_list_print_for_chain(dap_chain_net_t * a_net, dap_chain_t * a_chain, const char * a_add, json_object *a_json_obj, const char *a_hash_out_type, bool a_fast) {
    dap_chain_addr_t *l_wallet_addr = dap_chain_addr_from_str(a_add);
    if (a_add && !l_wallet_addr) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_CONVERT_BASE58_TO_ADDR_WALLET, "Cannot convert "
                               "string '%s' to binary address.\n", a_add);
        return;
    }
    if (l_wallet_addr && a_fast) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_FAST_AND_BASE58_ADDR,
                               "In fast mode, it is impossible to count the number of transactions and emissions "
                               "for a specific address. The -brief and -addr options are mutually exclusive.\n");
        DAP_DELETE(l_wallet_addr);
        return;
    }
    char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    if(!l_gdb_group_mempool){
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CAN_NOT_GET_MEMPOOL_GROUP,
                               "%s.%s: chain not found\n", a_net->pub.name, a_chain->name);
        return;
    }
    int l_removed = 0;
    json_object *l_obj_chain = json_object_new_object();
    json_object *l_obj_chain_name  = json_object_new_string(a_chain->name);
    if (!l_obj_chain_name || !l_obj_chain) {
        json_object_put(l_obj_chain);
        dap_json_rpc_allocation_error;
        return;
    }
    json_object_object_add(l_obj_chain, "name", l_obj_chain_name);
    dap_chain_mempool_filter(a_chain, &l_removed);
    json_object *l_jobj_removed = json_object_new_int(l_removed);
    if (!l_jobj_removed) {
        json_object_put(l_obj_chain);
        dap_json_rpc_allocation_error;
        return;
    }
    json_object_object_add(l_obj_chain, "removed", l_jobj_removed);
    size_t l_objs_count = 0;
    size_t l_objs_addr = 0;
    dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_count);
    json_object  *l_jobj_datums;
    if (l_objs_count == 0) {
        l_jobj_datums = json_object_new_null();
    } else {
        l_jobj_datums = json_object_new_array();
        if (!l_jobj_datums) {
            json_object_put(l_obj_chain);
            dap_json_rpc_allocation_error;
            return;
        }
    }
    for(size_t i = 0; i < l_objs_count; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
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
        dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_datum_real_hash);
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_datum_hash_from_key);
        char buff_time[50];
        dap_time_to_str_rfc822(buff_time, 50, l_datum->header.ts_create);
        json_object *l_jobj_type = json_object_new_string(l_datum_type);
        json_object *l_jobj_hash = json_object_new_string(l_objs[i].key);
        json_object *l_jobj_ts_created = json_object_new_object();
        json_object *l_jobj_ts_created_time_stamp = json_object_new_uint64(l_ts_create);
        json_object *l_jobj_ts_created_str = json_object_new_string(buff_time);
        if (!l_jobj_type || !l_jobj_hash || !l_jobj_ts_created || !l_jobj_ts_created_str || !l_jobj_ts_created_time_stamp) {
            json_object_put(l_jobj_type);
            json_object_put(l_jobj_hash);
            json_object_put(l_jobj_ts_created);
            json_object_put(l_jobj_ts_created_time_stamp);
            json_object_put(l_jobj_ts_created_str);
            json_object_put(l_jobj_datums);
            json_object_put(l_obj_chain);
            dap_global_db_objs_delete(l_objs, l_objs_count);
            DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
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
            DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            return;
        }
        if (!dap_hash_fast_compare(&l_datum_real_hash, &l_datum_hash_from_key)){
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
                dap_json_rpc_allocation_error;
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
                dap_json_rpc_allocation_error;
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
                    
                    int l_ledger_rc = DAP_LEDGER_TX_CHECK_NULL_TX;
                    char *l_main_ticker = dap_ledger_tx_get_main_ticker(a_net->pub.ledger, l_tx, &l_ledger_rc);
                    char * l_ledger_rc_str = dap_ledger_tx_check_err_str(l_ledger_rc);
                    
                    json_object *l_jobj_main_ticker = json_object_new_string(l_main_ticker ? l_main_ticker : "UNKNOWN");
                    json_object *l_jobj_ledger_rc = json_object_new_string(l_ledger_rc_str);
                    
                    if (!l_jobj_main_ticker || !l_jobj_ledger_rc) {
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                            return;
                    }
                
                    json_object_object_add(l_jobj_datum, "main_ticker", l_jobj_main_ticker);
                    json_object_object_add(l_jobj_datum, "ledger_rc", l_jobj_ledger_rc);
                
                    dap_list_t *l_list_sig_item = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_SIG, NULL);
                    dap_list_t *l_list_in_ems = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_EMS, NULL);
                    if (!l_list_sig_item) {
                        json_object *l_jobj_wgn = json_object_new_string("An item with a type TX_ITEM_TYPE_SIG for the "
                                                                         "transaction was not found, the transaction may "
                                                                         "be corrupted.");
                        json_object_object_add(l_jobj_datum, "warning", l_jobj_wgn);
                        break;
                    }
                    dap_chain_tx_sig_t *l_sig = l_list_sig_item->data;
                    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_sig);
                    dap_chain_addr_fill_from_sign(&l_addr_from, l_sign, a_net->pub.id);
                    if (l_wallet_addr && dap_chain_addr_compare(l_wallet_addr, &l_addr_from)) {
                        datum_is_accepted_addr = true;
                    }
                    dap_list_free(l_list_sig_item);
                    char *l_addr_from_str = dap_chain_addr_to_str(&l_addr_from);
                    if (!l_addr_from_str) {
                        json_object_put(l_jobj_datum);
                        json_object_put(l_jobj_datums);
                        json_object_put(l_obj_chain);
                        dap_global_db_objs_delete(l_objs, l_objs_count);
                        DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                        return;
                    }
                    dap_list_t *l_list_in_reward = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_REWARD, NULL);
                    if (l_list_in_reward) {
                        json_object *l_obj_in_reward_arary = json_object_new_array();
                        if (!l_obj_in_reward_arary) {
                            dap_list_free(l_list_in_reward);
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
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
                                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                                return;
                            }
                            json_object_array_add(l_obj_in_reward_arary, l_jobj_block_hash);
                            DAP_DELETE(l_block_hash);
                        }
                    } else {
                        json_object *l_jobj_addr_from = json_object_new_string(l_addr_from_str);
                        if (!l_jobj_addr_from) {
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                            return;
                        }
                        json_object_object_add(l_jobj_datum, "from", l_jobj_addr_from);
                    }
                    DAP_DELETE(l_addr_from_str);
                    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
                    json_object *l_jobj_to_list = json_object_new_array();
                    json_object *l_jobj_change_list = json_object_new_array();
                    json_object *l_jobj_to_from_emi = json_object_new_array();
                    json_object *l_jobj_fee_list = json_object_new_array();
                    json_object *l_jobj_stake_lock_list = json_object_new_array();
                    json_object *l_jobj_xchange_list = json_object_new_array();
                    json_object *l_jobj_stake_pos_delegate_list = json_object_new_array();
                    json_object *l_jobj_pay_list = json_object_new_array();
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
                        json_object_put(l_jobj_datum);
                        json_object_put(l_jobj_datums);
                        json_object_put(l_obj_chain);
                        dap_global_db_objs_delete(l_objs, l_objs_count);
                        DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                        return;
                    }
                    enum {
                        OUT_COND_TYPE_UNKNOWN,
                        OUT_COND_TYPE_PAY,
                        OUT_COND_TYPE_FEE,
                        OUT_COND_TYPE_STAKE_LOCK,
                        OUT_COND_TYPE_XCHANGE,
                        OUT_COND_TYPE_POS_DELEGATE
                    }l_out_cond_subtype={0};
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
                                dap_chain_tx_out_cond_t *l_out_cond = (dap_chain_tx_out_cond_t*)it->data;
                                l_value = ((dap_chain_tx_out_cond_t *) it->data)->header.value;
                                switch (l_out_cond->header.subtype) {
                                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: {
                                        l_dist_token = a_net->pub.native_ticker;
                                        l_out_cond_subtype = OUT_COND_TYPE_FEE;
                                    } break;
                                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                                        l_dist_token = l_main_ticker;
                                        l_out_cond_subtype = OUT_COND_TYPE_STAKE_LOCK;
                                    } break;
                                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                                        l_dist_token = l_main_ticker;
                                        l_out_cond_subtype = OUT_COND_TYPE_XCHANGE;
                                    } break;
                                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                                        l_dist_token = l_main_ticker;
                                        l_out_cond_subtype = OUT_COND_TYPE_POS_DELEGATE;
                                    } break;
                                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                                        l_dist_token = l_main_ticker;
                                        l_out_cond_subtype = OUT_COND_TYPE_PAY;
                                    } break;
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
                            return;
                        }
                        char *l_value_str = dap_chain_balance_print(l_value);
                        if (!l_value_str) {
                            json_object_put(l_jobj_to_list);
                            json_object_put(l_jobj_change_list);
                            json_object_put(l_jobj_to_from_emi);
                            json_object_put(l_jobj_fee_list);
                            json_object_put(l_jobj_money);
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            return;
                        }
                        char *l_value_coins_str = dap_chain_balance_to_coins(l_value);
                        if (!l_value_coins_str) {
                            json_object_put(l_jobj_to_list);
                            json_object_put(l_jobj_change_list);
                            json_object_put(l_jobj_to_from_emi);
                            json_object_put(l_jobj_fee_list);
                            DAP_DELETE(l_value_str);
                            json_object_put(l_jobj_money);
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            return;
                        }
                        json_object *l_jobj_value = json_object_new_string(l_value_str);
                        if (!l_jobj_value) {
                            json_object_put(l_jobj_to_list);
                            json_object_put(l_jobj_change_list);
                            json_object_put(l_jobj_to_from_emi);
                            json_object_put(l_jobj_fee_list);
                            DAP_DELETE(l_value_str);
                            DAP_DELETE(l_value_coins_str);
                            json_object_put(l_jobj_money);
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            return;
                        }
                        json_object_object_add(l_jobj_money, "value", l_jobj_value);
                        json_object *l_jobj_value_coins = json_object_new_string(l_value_coins_str);
                        if (!l_jobj_value_coins) {
                            json_object_put(l_jobj_to_list);
                            json_object_put(l_jobj_change_list);
                            json_object_put(l_jobj_to_from_emi);
                            json_object_put(l_jobj_fee_list);
                            DAP_DELETE(l_value_str);
                            DAP_DELETE(l_value_coins_str);
                            json_object_put(l_jobj_money);
                            json_object_put(l_jobj_datum);
                            json_object_put(l_jobj_datums);
                            json_object_put(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            return;
                        }
                        json_object_object_add(l_jobj_money, "coins", l_jobj_value_coins);
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
                                DAP_DELETE(l_value_str);
                                DAP_DELETE(l_value_coins_str);
                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                                return;
                            }
                            json_object_object_add(l_jobj_money, "token", l_jobj_token);
                        }

                        if (l_dist_addr) {
                            char *l_addr_str = dap_chain_addr_to_str(l_dist_addr);
                            if (!l_addr_str) {
                                json_object_put(l_jobj_to_list);
                                json_object_put(l_jobj_change_list);
                                json_object_put(l_jobj_to_from_emi);
                                json_object_put(l_jobj_fee_list);
                                DAP_DELETE(l_value_str);
                                DAP_DELETE(l_value_coins_str);
                                json_object_put(l_jobj_money);
                                json_object_put(l_jobj_datum);
                                json_object_put(l_jobj_datums);
                                json_object_put(l_obj_chain);
                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                return;
                            }
                            json_object *l_jobj_addr = json_object_new_string(l_addr_str);
                            if (!l_jobj_addr) {
                                json_object_put(l_jobj_to_list);
                                json_object_put(l_jobj_change_list);
                                json_object_put(l_jobj_to_from_emi);
                                json_object_put(l_jobj_fee_list);
                                DAP_DELETE(l_value_str);
                                DAP_DELETE(l_value_coins_str);
                                DAP_DELETE(l_addr_str);
                                json_object_put(l_jobj_money);
                                json_object_put(l_jobj_datum);
                                json_object_put(l_jobj_datums);
                                json_object_put(l_obj_chain);
                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                return;
                            }
                            if (!datum_is_accepted_addr && l_wallet_addr) {
                                datum_is_accepted_addr = dap_chain_addr_compare(l_wallet_addr, l_dist_addr);
                            }
                            json_object *l_jobj_f = json_object_new_object();
                            if (!l_jobj_f) {
                                json_object_put(l_jobj_to_list);
                                json_object_put(l_jobj_change_list);
                                json_object_put(l_jobj_to_from_emi);
                                json_object_put(l_jobj_fee_list);
                                DAP_DELETE(l_value_str);
                                DAP_DELETE(l_value_coins_str);
                                DAP_DELETE(l_addr_str);
                                json_object_put(l_jobj_addr);
                                json_object_put(l_jobj_money);
                                json_object_put(l_jobj_datum);
                                json_object_put(l_jobj_datums);
                                json_object_put(l_obj_chain);
                                dap_global_db_objs_delete(l_objs, l_objs_count);
                                return;
                            }
                            json_object_object_add(l_jobj_f, "money", l_jobj_money);
                            if (dap_chain_addr_compare(&l_addr_from, l_dist_addr)) {
                                bool l_in_from_emi = false;
                                for (dap_list_t *it_ems = l_list_in_ems; it_ems; it_ems = it_ems->next) {
                                    dap_chain_tx_in_ems_t *l_in_ems = (dap_chain_tx_in_ems_t*)it_ems->data;
                                    if (!dap_strcmp(l_in_ems->header.ticker, l_dist_token)) {
                                        l_in_from_emi = true;
                                        dap_hash_fast_t l_ems_hash = l_in_ems->header.token_emission_hash;
                                        char l_ems_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                                        dap_hash_fast_to_str(&l_ems_hash, l_ems_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                                        json_object * l_obj_ems_hash = json_object_new_string(l_ems_hash_str);
                                        if (!l_obj_ems_hash) {
                                            json_object_put(l_jobj_to_list);
                                            json_object_put(l_jobj_change_list);
                                            json_object_put(l_jobj_to_from_emi);
                                            json_object_put(l_jobj_fee_list);
                                            DAP_DELETE(l_value_str);
                                            DAP_DELETE(l_value_coins_str);
                                            DAP_DELETE(l_addr_str);
                                            json_object_put(l_jobj_addr);
                                            json_object_put(l_jobj_money);
                                            json_object_put(l_jobj_datum);
                                            json_object_put(l_jobj_datums);
                                            json_object_put(l_obj_chain);
                                            json_object_put(l_jobj_f);
                                            dap_global_db_objs_delete(l_objs, l_objs_count);
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
                                json_object_object_add(l_jobj_f, "addr", l_jobj_addr);
                                json_object_array_add(l_jobj_to_list, l_jobj_f);
                            }
                            DAP_DELETE(l_addr_str);
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
                                    log_it(L_ERROR, "An unknown subtype output was found in a transaction in the mempool list.");
                                    break;
                            }
                        }
                        DAP_DELETE(l_value_str);
                        DAP_DELETE(l_value_coins_str);
                    }
                    json_object_object_add(l_jobj_datum, "to", l_jobj_to_list);
                    json_object_object_add(l_jobj_datum, "change", l_jobj_change_list);
                    json_object_object_add(l_jobj_datum, "fee", l_jobj_fee_list);
                    json_object_array_length(l_jobj_pay_list) > 0 ?
                    json_object_object_add(l_jobj_datum, "srv_pay", l_jobj_pay_list) : json_object_put(l_jobj_pay_list);
                    json_object_array_length(l_jobj_xchange_list) > 0 ?
                    json_object_object_add(l_jobj_datum, "srv_xchange", l_jobj_xchange_list) : json_object_put(l_jobj_xchange_list);
                    json_object_array_length(l_jobj_stake_lock_list) > 0 ?
                    json_object_object_add(l_jobj_datum, "srv_stake_lock", l_jobj_stake_lock_list) : json_object_put(l_jobj_stake_lock_list);
                    json_object_array_length(l_jobj_stake_pos_delegate_list) > 0 ?
                    json_object_object_add(l_jobj_datum, "srv_stake_pos_delegate", l_jobj_stake_pos_delegate_list) : json_object_put(l_jobj_stake_pos_delegate_list);
                    json_object_array_length(l_jobj_to_from_emi) > 0 ?
                    json_object_object_add(l_jobj_datum, "from_emission", l_jobj_to_from_emi) : json_object_put(l_jobj_to_from_emi);
                    dap_list_free(l_list_out_items);
                }
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
                    size_t l_emi_size = l_datum->header.data_size;
                    dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_read(l_datum->data, &l_emi_size);
                    if (l_wallet_addr && l_emi && dap_chain_addr_compare(l_wallet_addr, &l_emi->hdr.address))
                        datum_is_accepted_addr = true;
                    DAP_DELETE(l_emi);
                    json_object_object_add(l_jobj_datum, "data", dap_chain_datum_data_to_json(l_datum));
                }
                    break;
                default:
                    json_object_object_add(l_jobj_datum, "data", dap_chain_datum_data_to_json(l_datum));
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

    json_object_object_add(l_obj_chain, "datums", l_jobj_datums);
    
    dap_global_db_objs_delete(l_objs, l_objs_count);

    char l_net_chain_count_total[64] = {0};

    sprintf(l_net_chain_count_total, "%s.%s: %zu", a_net->pub.name, a_chain->name, l_objs_count);
    json_object * l_object_total = json_object_new_string(l_net_chain_count_total);
    if (!l_object_total) {
        json_object_put(l_obj_chain);
        dap_json_rpc_allocation_error;
        return;
    }
    json_object_object_add(l_obj_chain, "total", l_object_total);

    json_object_array_add(a_json_obj, l_obj_chain);
    DAP_DELETE(l_gdb_group_mempool);
}

static int mempool_delete_for_chain(dap_chain_t *a_chain, const char * a_datum_hash_str, json_object **a_json_reply) {
        char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
        uint8_t *l_data_tmp = dap_global_db_get_sync(l_gdb_group_mempool, a_datum_hash_str,
                                                     NULL, NULL, NULL);
        if(l_data_tmp && dap_global_db_del_sync(l_gdb_group_mempool, a_datum_hash_str) == 0) {
            char *l_msg_str = dap_strdup_printf("Datum %s deleted", a_datum_hash_str);
            json_object *l_msg = json_object_new_string(l_msg_str);
            DAP_DELETE(l_msg_str);
            if (!l_msg) {
                dap_json_rpc_allocation_error;
                DAP_DELETE(l_gdb_group_mempool);
                DAP_DELETE(l_data_tmp);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            json_object_array_add(*a_json_reply, l_msg);
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_data_tmp);
            return 0;
        } else {
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_data_tmp);
            return 1;
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
int _cmd_mempool_delete(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, void **reply)
{
    json_object ** a_json_reply = (json_object **) reply;
    if (!a_net || !a_datum_hash) {
        dap_json_rpc_error_add(COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT, "Net or datum hash not specified");
        return COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT;
    }
    int res = 0;
    if (!a_chain) {
        dap_chain_t * l_chain;
        DL_FOREACH(a_net->pub.chains, l_chain){
            res = mempool_delete_for_chain(l_chain, a_datum_hash, a_json_reply);
            if (res == 0) {
                break;
            }
        }
    } else {
        res = mempool_delete_for_chain(a_chain, a_datum_hash, a_json_reply);
    }
    if (res) {
        char *l_msg_str = dap_strdup_printf("Error! Can't find datum %s", a_datum_hash);
        if (!l_msg_str) {
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object *l_msg = json_object_new_string(l_msg_str);
        DAP_DELETE(l_msg_str);
        if (!l_msg) {
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_array_add(*a_json_reply, l_msg);
        return COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND;
    }
    return 0;
//    } else {
//        char *l_msg_str = dap_strdup_printf("Datum %s removed", a_datum_hash);
//        if (!l_msg_str) {
//            dap_json_rpc_allocation_error;
//            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
//        }
//        json_object *l_msg = json_object_new_string(l_msg_str);
//        DAP_DELETE(l_msg_str);
//        if (!l_msg) {
//            dap_json_rpc_allocation_error;
//            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
//        }
//        json_object_array_add(*a_json_reply, l_msg);
//        return 0;
//    }
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
    char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    if (!l_gdb_group_mempool)
        return NULL;
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
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
int _cmd_mempool_check(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, const char **a_hash_out_type, void ** reply) {
    json_object ** a_json_reply = (json_object **) reply;

    if (!a_net || !a_datum_hash) {
        dap_json_rpc_error_add(COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET, "Error! Both -net <network_name> "
                                                                       "and -datum <data_hash> parameters are required.");
        return COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET;
    }
    dap_chain_datum_t *l_datum = NULL;
    char *l_chain_name = a_chain ? a_chain->name : NULL;
    bool l_found_in_chains = false;
    int l_ret_code = 0;
    dap_hash_fast_t l_atom_hash = {};
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
    if (!l_datum) {
        l_found_in_chains = true;
        dap_hash_fast_t l_datum_hash;
        if (dap_chain_hash_fast_from_hex_str(a_datum_hash, &l_datum_hash)) {
            dap_json_rpc_error_add(COM_MEMPOOL_CHECK_ERR_INCORRECT_HASH_STR,
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
    }
    json_object *l_jobj_datum = json_object_new_object();
    json_object *l_datum_hash = json_object_new_string(a_datum_hash);
    json_object *l_net_obj = json_object_new_string(a_net->pub.name);
    if (!l_jobj_datum || !l_datum_hash || !l_net_obj){
        json_object_put(l_jobj_datum);
        json_object_put(l_datum_hash);
        json_object_put(l_net_obj);
        dap_json_rpc_allocation_error;
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object *l_chain_obj;
    if(l_chain_name) {
        l_chain_obj = json_object_new_string(l_chain_name);
        if (!l_chain_obj) {
            json_object_put(l_jobj_datum);
            json_object_put(l_datum_hash);
            json_object_put(l_net_obj);
            dap_json_rpc_allocation_error;
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
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_jobj_datum, "find", l_find_bool);
        json_object_object_add(l_jobj_datum, "source", l_find_chain_or_mempool);
        if (l_found_in_chains) {
            char l_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_atom_hash, l_atom_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            json_object *l_obj_atom = json_object_new_object();
            json_object *l_jobj_atom_hash = json_object_new_string(l_atom_hash_str);
            json_object *l_jobj_atom_err = json_object_new_string(dap_ledger_tx_check_err_str(l_ret_code));
            if (!l_obj_atom || !l_jobj_atom_hash || !l_jobj_atom_err) {
                json_object_put(l_jobj_datum);
                json_object_put(l_obj_atom);
                json_object_put(l_jobj_atom_hash);
                json_object_put(l_jobj_atom_err);
                dap_json_rpc_allocation_error;
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            json_object_object_add(l_obj_atom, "hash", l_jobj_atom_hash);
            json_object_object_add(l_obj_atom, "ledger_response_code", l_jobj_atom_err);
            json_object_object_add(l_jobj_datum, "atom", l_obj_atom);
        }
        json_object *l_datum_obj_inf = dap_chain_datum_to_json(l_datum);
        if (!l_datum_obj_inf) {
            if (!l_found_in_chains)
                DAP_DELETE(l_datum);
            json_object_put(l_jobj_datum);
            dap_json_rpc_error_add(DAP_JSON_RPC_ERR_CODE_SERIALIZATION_DATUM_TO_JSON,
                                    "Failed to serialize datum to JSON.");
            return DAP_JSON_RPC_ERR_CODE_SERIALIZATION_DATUM_TO_JSON;
        }
        if (!l_found_in_chains)
            DAP_DELETE(l_datum);
        json_object_array_add(*a_json_reply, l_jobj_datum);
        return 0;
    } else {
        l_find_bool = json_object_new_boolean(TRUE);
        if (!l_find_bool) {
            json_object_put(l_jobj_datum);
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_jobj_datum, "find", l_find_bool);
        json_object_array_add(*a_json_reply, l_jobj_datum);
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
 * process mempool datums
 * @param a_net
 * @param a_chain
 * @param a_datum_hash
 * @param reply
 * @return
 */
int _cmd_mempool_proc(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, void **reply)
{
    // If full or light it doesnt work
    if(dap_chain_net_get_role(a_net).enums>= NODE_ROLE_FULL){
        dap_json_rpc_error_add(DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL,
                               "Need master node role or higher for network %s to process this command", a_net->pub.name);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL;
    }

    int ret = 0;
    char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    if (!l_gdb_group_mempool){
        dap_json_rpc_error_add(DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME,
                               "Failed to get mempool group name on network %s", a_net->pub.name);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME;
    }
    size_t l_datum_size=0;

    dap_chain_datum_t * l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(l_gdb_group_mempool, a_datum_hash,
                                                                             &l_datum_size, NULL, NULL );
    size_t l_datum_size2 = l_datum? dap_chain_datum_size( l_datum): 0;
    if (l_datum_size != l_datum_size2) {
        dap_json_rpc_error_add(DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD, "Error! Corrupted datum %s, size by datum headers is %zd when in mempool is only %zd bytes",
                                            a_datum_hash, l_datum_size2, l_datum_size);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD;
    }
    if (!l_datum) {
        dap_json_rpc_error_add(DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM,
                               "Error! Can't find datum %s", a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM;
    }
    dap_hash_fast_t l_datum_hash, l_real_hash;
    if (dap_chain_hash_fast_from_hex_str(a_datum_hash, &l_datum_hash)) {
        dap_json_rpc_error_add(DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM,
                               "Error! Can't convert datum hash string %s to digital form",
                               a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM;
    }
    dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_real_hash);
    if (!dap_hash_fast_compare(&l_datum_hash, &l_real_hash)) {
        dap_json_rpc_error_add(DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING,
                               "Error! Datum's real hash doesn't match datum's hash string %s",
                               a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING;
    }
    dap_time_t l_ts_create = (dap_time_t)l_datum->header.ts_create;
    const char *l_type = NULL;
    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type);
    json_object *l_jobj_res = json_object_new_object();
    json_object *l_jobj_datum = json_object_new_object();
    json_object *l_jobj_hash = json_object_new_string(a_datum_hash);
    json_object *l_jobj_type = json_object_new_string(l_type);
    json_object *l_jobj_ts_created = json_object_new_object();
    json_object *l_jobj_ts_created_time_stamp = json_object_new_uint64(l_ts_create);
    if (!l_jobj_ts_created || !l_jobj_ts_created_time_stamp || !l_jobj_type ||
        !l_jobj_hash || !l_jobj_datum || !l_jobj_res) {
        json_object_put(l_jobj_res);
        json_object_put(l_jobj_datum);
        json_object_put(l_jobj_hash);
        json_object_put(l_jobj_type);
        json_object_put(l_jobj_ts_created);
        json_object_put(l_jobj_ts_created_time_stamp);
        dap_json_rpc_allocation_error;
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    char l_ts_created_str[27];
    dap_ctime_r(&l_ts_create, l_ts_created_str);
    json_object *l_jobj_ts_created_str = json_object_new_string(l_ts_created_str);
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
        dap_json_rpc_allocation_error;
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
        dap_json_rpc_allocation_error;
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    int l_verify_datum = dap_chain_net_verify_datum_for_add(a_chain, l_datum, &l_datum_hash);
    if (l_verify_datum){
        json_object *l_jobj_verify_err = json_object_new_string(dap_chain_net_verify_datum_err_code_to_str(l_datum, l_verify_datum));
        json_object *l_jobj_verify_status = json_object_new_boolean(FALSE);
        if (!l_jobj_verify_status || !l_jobj_verify_err) {
            json_object_put(l_jobj_verify_status);
            json_object_put(l_jobj_verify_err);
            json_object_put(l_jobj_verify);
            json_object_put(l_jobj_res);
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_jobj_verify, "isProcessed", l_jobj_verify_status);
        json_object_object_add(l_jobj_verify, "error", l_jobj_verify_err);
        ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY;
    } else {
        if (a_chain->callback_add_datums) {
            if (a_chain->callback_add_datums(a_chain, &l_datum, 1) == 0) {
                json_object *l_jobj_verify_status = json_object_new_boolean(FALSE);
                if (!l_jobj_verify_status) {
                    json_object_put(l_jobj_verify_status);
                    json_object_put(l_jobj_verify);
                    json_object_put(l_jobj_res);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_verify, "isProcessed", l_jobj_verify_status);
                ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY;
            } else {
                json_object *l_jobj_verify_status = json_object_new_boolean(TRUE);
                if (!l_jobj_verify_status) {
                    json_object_put(l_jobj_verify);
                    json_object_put(l_jobj_res);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_verify, "isProcessed", l_jobj_verify_status);
                if (dap_global_db_del_sync(l_gdb_group_mempool, a_datum_hash)){
                    json_object *l_jobj_wrn_text = json_object_new_string("Can't delete datum from mempool!");
                    if (!l_jobj_wrn_text) {
                        json_object_put(l_jobj_verify);
                        json_object_put(l_jobj_res);
                        dap_json_rpc_allocation_error;
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_verify, "warning", l_jobj_wrn_text);
                } else {
                    json_object *l_jobj_text = json_object_new_string("Removed datum from mempool.");
                    if (!l_jobj_text) {
                        json_object_put(l_jobj_verify);
                        json_object_put(l_jobj_res);
                        dap_json_rpc_allocation_error;
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_verify, "notice", l_jobj_text);
                }
            }
        } else {
            dap_json_rpc_error_add(DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL, "Error! Can't move to no-concensus chains from mempool");
            ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL;
        }
    }
    DAP_DELETE(l_gdb_group_mempool);
    json_object_object_add(l_jobj_res, "verify", l_jobj_verify);
    json_object_array_add(*reply, l_jobj_res);
    return ret;
}

/**
 * @breif _cmd_mempool_proc_all
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int _cmd_mempool_proc_all(dap_chain_net_t *a_net, dap_chain_t *a_chain, void **reply) {
    json_object ** a_json_reply = (json_object **) reply;
    if (!a_net || !a_chain) {
        dap_json_rpc_error_add(-2, "The net and chain argument is not set");
        return -2;
    }

    json_object *l_ret = json_object_new_object();
    if (!l_ret){
        dap_json_rpc_allocation_error;
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    if(!dap_chain_net_by_id(a_chain->net_id)) {
        char *l_warn_str = dap_strdup_printf("%s.%s: chain not found\n", a_net->pub.name,
                                             a_chain->name);
        if (!l_warn_str) {
            json_object_put(l_ret);
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object *l_warn_obj = json_object_new_string(l_warn_str);
        DAP_DELETE(l_warn_str);
        if (!l_warn_obj){
            json_object_put(l_ret);
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_object_add(l_ret, "warning", l_warn_obj);
    }

#ifdef DAP_TPS_TEST
    dap_chain_ledger_set_tps_start_time(a_net->pub.ledger);
#endif
    dap_chain_node_mempool_process_all(a_chain, true);
    char *l_str_result = dap_strdup_printf("The entire mempool has been processed in %s.%s.",
                                           a_net->pub.name, a_chain->name);
    if (!l_str_result) {
        json_object_put(l_ret);
        dap_json_rpc_allocation_error;
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object *l_obj_result = json_object_new_string(l_str_result);
    DAP_DEL_Z(l_str_result);
    if (!l_obj_result) {
        json_object_put(l_ret);
        dap_json_rpc_allocation_error;
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    json_object_object_add(l_ret, "result", l_obj_result);
    json_object_array_add(*a_json_reply, l_obj_result);
    return 0;
}

typedef enum _cmd_mempool_dump_error_list{
    COM_DUMP_ERROR_LIST_CORRUPTED_SIZE = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_DUMP_ERROR_CAN_NOT_FIND_DATUM,
    COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION
}_cmd_mempool_dump_error_list_t;

int _cmd_mempool_dump_from_group(dap_chain_net_id_t a_net_id, const char *a_group_gdb, const char *a_datum_hash,
                                 const char *a_hash_out_type, json_object **reply) {
    size_t l_datum_size = 0;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(a_group_gdb, a_datum_hash,
                                                         &l_datum_size, NULL, NULL );
    size_t l_datum_size2 = l_datum? dap_chain_datum_size( l_datum): 0;
    if (l_datum_size != l_datum_size2) {
        dap_json_rpc_error_add(COM_DUMP_ERROR_LIST_CORRUPTED_SIZE, "Error! Corrupted datum %s, size by datum headers "
                                                                   "is %zd when in mempool is only %zd bytes",
                                 a_datum_hash, l_datum_size2, l_datum_size);
        return COM_DUMP_ERROR_LIST_CORRUPTED_SIZE;
    }
    if (!l_datum) {
        char *l_msg_str = dap_strdup_printf("Error! Can't find datum %s in %s", a_datum_hash, a_group_gdb);
        if (!l_msg_str) {
            DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            return -1;
        }
        json_object *l_jobj_message = json_object_new_string(l_msg_str);
        return COM_DUMP_ERROR_CAN_NOT_FIND_DATUM;
    }
    json_object *l_jobj_datum = dap_chain_datum_to_json(l_datum);
    json_object_array_add(*reply, l_jobj_datum);
    return 0;
}

int _cmd_mempool_dump(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, const char *a_hash_out_type, json_object **reply) {
    if (!a_net || !a_datum_hash || !a_hash_out_type) {
        dap_json_rpc_error_add(COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION, "The following arguments are not set: network,"
                                                                         " datum hash, and output hash type. "
                                                                         "Functions required for operation.");
        return COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION;
    }
    if (a_chain) {
        char *l_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
        _cmd_mempool_dump_from_group(a_net->pub.id, l_group_mempool, a_datum_hash, a_hash_out_type, reply);
        DAP_DELETE(l_group_mempool);
    } else {
        dap_chain_t *l_chain = NULL;
        DL_FOREACH(a_net->pub.chains, l_chain){
            char *l_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
            if (!_cmd_mempool_dump_from_group(a_net->pub.id, l_group_mempool, a_datum_hash, a_hash_out_type, reply)){
                DAP_DELETE(l_group_mempool);
                break;
            }
            DAP_DELETE(l_group_mempool);
        }
    }
    return 0;
}

int com_mempool(int a_argc, char **a_argv, void **reply){
    int arg_index = 1;
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    enum _subcmd {SUBCMD_LIST, SUBCMD_PROC, SUBCMD_PROC_ALL, SUBCMD_DELETE, SUBCMD_ADD_CA, SUBCMD_CHECK, SUBCMD_DUMP, SUBCMD_COUNT};
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
            char *l_str_err = dap_strdup_printf("Invalid sub command specified. Ыub command %s "
                                                           "is not supported.", a_argv[1]);
            if (!l_str_err) {
                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                return -1;
            }
            json_object *l_jobj_str_err = json_object_new_string(l_str_err);
            DAP_DELETE(l_str_err);
            if (!l_jobj_str_err) {
                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                return -1;
            }
            json_object_array_add(*reply, l_jobj_str_err);
            return -2;
        }
    }
    dap_chain_node_cli_cmd_values_parse_net_chain_for_json(&arg_index, a_argc, a_argv, &l_chain, &l_net);
    if (!l_net) {
        return -3;
    }
    const char *l_hash_out_type = "hex";
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    const char *l_datum_hash_in = NULL;
    const char *l_datum_hash = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_in);
    if (l_datum_hash_in) {
        if(dap_strncmp(l_datum_hash_in, "0x", 2) && dap_strncmp(l_datum_hash_in, "0X", 2)) {
            l_datum_hash = dap_enc_base58_to_hex_str_from_str(l_datum_hash_in);
        } else
            l_datum_hash = dap_strdup(l_datum_hash_in);
    }
    int ret = -100;
    switch (l_cmd) {
        case SUBCMD_LIST: {
            if (!l_net) {
                dap_json_rpc_error_add(-5, "The command does not include the net parameter. Please specify the "
                                           "parameter something like this mempool list -net <net_name>");
                return -5;
            }
            json_object *obj_ret = json_object_new_object();
            json_object *obj_net = json_object_new_string(l_net->pub.name);
            if (!obj_ret || !obj_net) {
                json_object_put(obj_ret);
                json_object_put(obj_net);
                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                return -1;
            }
            json_object_object_add(obj_ret, "net", obj_net);
            const char *l_wallet_addr = NULL;
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_wallet_addr) && !l_wallet_addr) {
                json_object *l_jobj_err = json_object_new_string("Parameter '-addr' require <addr>");
                if (!l_jobj_err) {
                    DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    return -1;
                }
                json_object_array_add(*reply, l_jobj_err);
                return -3;
            }
            json_object *l_jobj_chains = json_object_new_array();
            if (!l_jobj_chains) {
                json_object_put(obj_ret);
                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                return -1;
            }
            bool l_fast = (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "-brief") != -1) ? true : false;
            if(l_chain) {
                s_com_mempool_list_print_for_chain(l_net, l_chain, l_wallet_addr, l_jobj_chains, l_hash_out_type, l_fast);
            } else {
                DL_FOREACH(l_net->pub.chains, l_chain) {
                    s_com_mempool_list_print_for_chain(l_net, l_chain, l_wallet_addr, l_jobj_chains, l_hash_out_type, l_fast);
                }
            }
            json_object_object_add(obj_ret, "chains", l_jobj_chains);
            json_object_array_add(*reply, obj_ret);
            ret = 0;
        } break;
        case SUBCMD_PROC: {
            ret = _cmd_mempool_proc(l_net, l_chain, l_datum_hash, reply);
        } break;
        case SUBCMD_PROC_ALL: {
            ret = _cmd_mempool_proc_all(l_net, l_chain, reply);
        } break;
        case SUBCMD_DELETE: {
            if (!l_chain) {
                dap_json_rpc_error_add(-2, "The chain parameter was not specified or was specified incorrectly.");
                ret = -2;
            }
            if (l_datum_hash) {
                ret = _cmd_mempool_delete(l_net, l_chain, l_datum_hash, reply);
            } else {
                dap_json_rpc_error_add(-3, "Error! %s requires -datum <datum hash> option", a_argv[0]);
                ret = -3;
            }
        } break;
        case SUBCMD_ADD_CA: {
            const char *l_ca_name  = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-ca_name", &l_ca_name);
            if (!l_ca_name) {
                dap_json_rpc_error_add(-3, "mempool add_ca requires parameter '-ca_name' to specify the certificate name");
                ret = -3;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_ca_name);
            if (!l_cert) {
                dap_json_rpc_error_add(-4, "Cert with name '%s' not found.", l_ca_name);
                ret = -4;
            }
            ret = _cmd_mempool_add_ca(l_net, l_chain, l_cert, reply);
        } break;
        case SUBCMD_CHECK: {
            ret = _cmd_mempool_check(l_net, l_chain, l_datum_hash, &l_hash_out_type, reply);
        } break;
        case SUBCMD_DUMP: {
            ret = _cmd_mempool_dump(l_net, l_chain, l_datum_hash, l_hash_out_type, (json_object**)reply);
        } break;
        case SUBCMD_COUNT: {
            char *l_mempool_group;
            json_object *obj_ret = json_object_new_object();
            json_object *obj_net = json_object_new_string(l_net->pub.name);
            if (!obj_ret || !obj_net) {
                json_object_put(obj_ret);
                json_object_put(obj_net);
                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                return -1;
            }
            json_object_object_add(obj_ret, "net", obj_net);
            json_object *l_jobj_chains = json_object_new_array();
            if (!l_jobj_chains) {
                json_object_put(obj_ret);
                DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                return -1;
            }
            if(l_chain) {
                l_mempool_group = dap_chain_net_get_gdb_group_mempool_new(l_chain);
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
                    DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_chain, "name", l_jobj_chain_name);
                json_object_object_add(l_jobj_chain, "count", l_jobj_count);
                json_object_array_add(l_jobj_chains, l_jobj_chain);
            } else {
                DL_FOREACH(l_net->pub.chains, l_chain) {
                    l_mempool_group = dap_chain_net_get_gdb_group_mempool_new(l_chain);
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
                        DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_chain, "name", l_jobj_chain_name);
                    json_object_object_add(l_jobj_chain, "count", l_jobj_count);
                    json_object_array_add(l_jobj_chains, l_jobj_chain);
                }
            }
            json_object_object_add(obj_ret, "chains", l_jobj_chains);
            json_object_array_add(*reply, obj_ret);
            ret = 0;
        } break;
    }
    DAP_DEL_Z(l_datum_hash);
    return ret;
}

/**
 * @brief
 *
 * @param a_tx_address
 * @param l_tsd_list
 * @param l_tsd_total_size
 * @param flag
 * @return dap_list_t*
 */
dap_list_t* s_parse_wallet_addresses(const char *a_tx_address, dap_list_t *l_tsd_list, size_t *l_tsd_total_size, uint32_t flag)
{
    if (!a_tx_address){
       log_it(L_DEBUG,"a_tx_address is null");
       return l_tsd_list;
    }

    char ** l_str_wallet_addr = NULL;
    l_str_wallet_addr = dap_strsplit(a_tx_address,",",0xffff);

    if (!l_str_wallet_addr){
       log_it(L_DEBUG,"Error in wallet addresses array parsing in tx_receiver_allowed parameter");
       return l_tsd_list;
    }

    while (l_str_wallet_addr && *l_str_wallet_addr){
        log_it(L_DEBUG,"Processing wallet address: %s", *l_str_wallet_addr);
        dap_chain_addr_t *addr_to = dap_chain_addr_from_str(*l_str_wallet_addr);
        if (addr_to){
            dap_tsd_t * l_tsd = dap_tsd_create(flag, addr_to, sizeof(dap_chain_addr_t));
            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            *l_tsd_total_size += dap_tsd_size(l_tsd);
        }else{
            log_it(L_DEBUG,"Error in wallet address parsing");
        }
        l_str_wallet_addr++;
    }

    return l_tsd_list;
}

typedef struct _dap_cli_token_additional_params {
    const char* flags;
    const char* delegated_token_from;
    const char* total_signs_valid;
    const char* datum_type_allowed;
    const char* datum_type_blocked;
    const char* tx_receiver_allowed;
    const char* tx_receiver_blocked;
    const char* tx_sender_allowed;
    const char* tx_sender_blocked;
    uint16_t    parsed_flags;
    size_t      tsd_total_size;
    byte_t      *parsed_tsd;
    size_t      parsed_tsd_size;
} dap_cli_token_additional_params;

typedef struct _dap_sdk_cli_params {
    const char *hash_out_type;
    const char *chain_str;
    const char *net_str;
    const char *ticker;
    const char *type_str;
    const char *certs_str;
    dap_chain_t *chain;
    dap_chain_net_t *net;
    uint16_t type;
    uint16_t subtype;
    uint16_t signs_total;
    uint16_t signs_emission;
    uint256_t total_supply;
    const char* decimals_str;
    dap_cli_token_additional_params ext;
} dap_sdk_cli_params, *pdap_sdk_cli_params;

static int s_parse_common_token_decl_arg(int a_argc, char ** a_argv, char ** a_str_reply, dap_sdk_cli_params* a_params, bool a_update_token)
{
    a_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-H", &a_params->hash_out_type);
    if(!a_params->hash_out_type)
        a_params->hash_out_type = "hex";
    if(dap_strcmp(a_params->hash_out_type,"hex") && dap_strcmp(a_params->hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    int l_arg_index = 0;
    int l_res = dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index, a_argc, a_argv, a_str_reply, &a_params->chain, &a_params->net);

    if(!a_params->net || !a_params->chain)
        return l_res;
    else {
        if(*a_str_reply) {
            DAP_DELETE(*a_str_reply);
            *a_str_reply = NULL;
        }
    }
    //net name
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &a_params->net_str);
    //chainname
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-chain", &a_params->chain_str);
    //token_ticker
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-token", &a_params->ticker);
    // Token type
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-type", &a_params->type_str);

    if (a_params->type_str) {
        if (strcmp(a_params->type_str, "private") == 0) {
            a_params->type = a_update_token ? DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE : DAP_CHAIN_DATUM_TOKEN_TYPE_DECL; // 256
            a_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE;
        } else if (strcmp(a_params->type_str, "CF20") == 0) {
            a_params->type = a_update_token ? DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE : DAP_CHAIN_DATUM_TOKEN_TYPE_DECL; // 256
            a_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
        } else if (strcmp(a_params->type_str, "private_simple") == 0 && !a_update_token) {
            a_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
            a_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE; // 256
        } else if (strcmp(a_params->type_str, "public_simple") == 0 && !a_update_token) {
            a_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
            a_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC; // 256
        } else if (!a_update_token) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Unknown token type %s was specified. Supported types:\n"
                        "   private_simple\n"
                        "   private\n"
                        "   CF20\n"
                        "Default token type is private_simple.\n", a_params->type_str);
            return -1;
        } else {
           dap_cli_server_cmd_set_reply_text(a_str_reply,
                           "Unknown token type %s was specified. Supported types:\n"
                       "   private\n"
                       "   CF20\n", a_params->type_str);
           return -1;
        }
    } else if (a_update_token) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,"update_token command requires parameter:\n-type <CF20 or private>");
        return -1;
    }


    // Certificates thats will be used to sign currend datum token
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-certs", &a_params->certs_str);
    // Signs number thats own emissioncan't find
    const char* l_signs_total_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-signs_total", &l_signs_total_str);
    // Signs total
    char* l_tmp = NULL;
    if(l_signs_total_str){
        if((a_params->signs_total = (uint16_t) strtol(l_signs_total_str, &l_tmp, 10)) == 0){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "'signs_total' parameter must be unsigned integer value that fits in 2 bytes");
            return -8;
        }
    }
    // Signs minimum number thats need to authorize the emission
    const char* l_signs_emission_str = NULL;
    l_tmp = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-signs_emission", &l_signs_emission_str);
    if (l_signs_emission_str){
        if((a_params->signs_emission = (uint16_t) strtol(l_signs_emission_str, &l_tmp, 10)) == 0){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                "%s requires parameter 'signs_emission' to be unsigned integer value that fits in 2 bytes", a_update_token ? "token_update" : "token_decl");
            return -6;
        }
    }
    // Total supply value
    const char* l_total_supply_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-total_supply", &l_total_supply_str);
    if (l_total_supply_str){
        a_params->total_supply = dap_chain_balance_scan(l_total_supply_str);
    } else if (!a_update_token) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "'-total_supply' must be unsigned integer value that fits in 32 bytes\n"
                                                       "If your token is type native (CF20) you can use value 0 for infinite total_supply.");
        return -4;
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "'-total_supply' must be unsigned integer value that fits in 32 bytes\n"
                                                       "You are update a token, be careful!\n"
                                                       "You can reset total_supply and make it infinite for native (CF20) tokens only, if set 0"
                                                       "for private tokens, you must specify the same or more total_supply.");
        return -4;
    }
    // Total supply value
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-decimals", &a_params->decimals_str);

    return 0;
}

static int s_parse_additional_token_decl_arg(int a_argc, char ** a_argv, char ** a_str_reply, dap_sdk_cli_params* a_params)
{
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-flags", &a_params->ext.flags);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-total_signs_valid", &a_params->ext.total_signs_valid);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-delegated_token_from", &a_params->ext.delegated_token_from);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-datum_type_allowed", &a_params->ext.datum_type_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-datum_type_blocked", &a_params->ext.datum_type_blocked);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_receiver_allowed", &a_params->ext.tx_receiver_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_receiver_blocked", &a_params->ext.tx_receiver_blocked);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_sender_allowed", &a_params->ext.tx_sender_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_receiver_allowed", &a_params->ext.tx_receiver_allowed);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-tx_sender_blocked", &a_params->ext.tx_sender_blocked);

    if (a_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE)
        return 0;

    dap_list_t *l_tsd_list = NULL;
    size_t l_tsd_total_size = 0;
    uint16_t l_flags = 0;
    char ** l_str_flags = NULL;
    a_params->ext.parsed_tsd_size = 0;

    if (a_params->ext.flags){   // Flags
         l_str_flags = dap_strsplit(a_params->ext.flags,",",0xffff );
         while (l_str_flags && *l_str_flags){
             uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_str_flags);
             if (l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                 dap_cli_server_cmd_set_reply_text(a_str_reply, "Flag can't be \"%s\"",*l_str_flags);
                 return -20;
             }
             l_flags |= l_flag; // if we have multiple flags
             l_str_flags++;
        }
    }
    a_params->ext.parsed_flags = l_flags;
    const char* l_new_certs_str = NULL;
    const char* l_remove_signs = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-new_certs", &l_new_certs_str);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-remove_certs", &l_remove_signs);
    const char *l_description_token  = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-description", &l_description_token);

    //Added remove signs
    if (l_remove_signs) {
        size_t l_added_tsd_size = 0;
        char *l_remove_signs_ptrs = NULL;
        char *l_remove_signs_dup = strdup(l_remove_signs);
        char *l_remove_signs_str = strtok_r(l_remove_signs_dup, ",", &l_remove_signs_ptrs);
        for (; l_remove_signs_str; l_remove_signs_str = strtok_r(NULL, ",", &l_remove_signs_ptrs)) {
            dap_hash_fast_t l_hf;
            if (dap_chain_hash_fast_from_str(l_remove_signs_str, &l_hf) == 0) {
                dap_tsd_t *l_hf_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE, &l_hf, sizeof(dap_hash_fast_t));
                size_t l_hf_tsd_size = dap_tsd_size(l_hf_tsd);
                l_tsd_list = dap_list_append(l_tsd_list, l_hf_tsd);
                l_added_tsd_size += l_hf_tsd_size;
            }
        }
        DAP_DELETE(l_remove_signs_dup);
        l_tsd_total_size += l_added_tsd_size;
    }
    //Added new certs
    dap_cert_t **l_new_certs = NULL;
    size_t l_new_certs_count = 0;
    if (l_new_certs_str) {
        dap_cert_parse_str_list(l_new_certs_str, &l_new_certs, &l_new_certs_count);
        for (size_t i = 0; i < l_new_certs_count; i++) {
            dap_pkey_t *l_pkey = dap_cert_to_pkey(l_new_certs[i]);
            if (!l_pkey) {
                log_it(L_ERROR, "Can't get pkey for cert: %s", l_new_certs[i]->name);
                continue;
            }
            size_t l_pkey_size = sizeof(dap_pkey_t) + l_pkey->header.size;
            dap_tsd_t *l_pkey_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD, l_pkey, l_pkey_size);
            size_t l_pkey_tsd_size = dap_tsd_size(l_pkey_tsd);
            l_tsd_list = dap_list_append(l_tsd_list, l_pkey_tsd);
            l_tsd_total_size += l_pkey_tsd_size;
            DAP_DELETE(l_pkey);
        }
        DAP_DEL_Z(l_new_certs);
    }
    if (l_description_token) {
        dap_tsd_t *l_desc_token = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION, l_description_token,
                                                 dap_strlen(l_description_token));//dap_tsd_create_string(DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION, l_description_token);
        l_tsd_list = dap_list_append(l_tsd_list, l_desc_token);
        l_tsd_total_size += dap_tsd_size(l_desc_token);
        a_params->ext.parsed_tsd_size += dap_tsd_size(l_desc_token);
    }
    size_t l_tsd_offset = 0;
    a_params->ext.parsed_tsd = DAP_NEW_SIZE(byte_t, l_tsd_total_size);
    if(l_tsd_total_size && !a_params->ext.parsed_tsd) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    for (dap_list_t *l_iter = dap_list_first(l_tsd_list); l_iter; l_iter = l_iter->next) {
        dap_tsd_t * l_tsd = (dap_tsd_t *) l_iter->data;
        if (!l_tsd){
            log_it(L_ERROR, "NULL tsd in list!");
            continue;
        }
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        memcpy(a_params->ext.parsed_tsd + l_tsd_offset, l_tsd, l_tsd_size);
        l_tsd_offset += l_tsd_size;
    }
    a_params->ext.tsd_total_size = l_tsd_total_size;

    return 0;
}

static int s_token_decl_check_params(int a_argc, char **a_argv, char **a_str_reply, dap_sdk_cli_params *a_params, bool a_update_token)
{
    int l_parse_params = s_parse_common_token_decl_arg(a_argc,a_argv,a_str_reply,a_params, a_update_token);
    if (l_parse_params)
        return l_parse_params;

    l_parse_params = s_parse_additional_token_decl_arg(a_argc,a_argv,a_str_reply,a_params);
    if (l_parse_params)
        return l_parse_params;

    //DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL uses decimals parameter
    if (a_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE
            ||	a_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE) {
        if(!a_params->decimals_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-decimals'", a_update_token ? "token_update" : "token_decl");
            return -3;
        } else if (dap_strcmp(a_params->decimals_str, "18")) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "%s support '-decimals' to be 18 only", a_update_token ? "token_update" : "token_decl");
            return -4;
        }
    } else if (	a_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE){
        //// check l_decimals in CF20 token TODO: At the moment the checks are the same.
        if(!a_params->decimals_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-decimals'", a_update_token ? "token_update" : "token_decl");
            return -3;
        } else if (dap_strcmp(a_params->decimals_str, "18")) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "%s support '-decimals' to be 18 only", a_update_token ? "token_update" : "token_decl");
            return -4;
        }
    }

    if (!a_params->signs_emission){
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-signs_emission'", a_update_token ? "token_update" : "token_decl");
        return -5;
    }

    if (!a_params->signs_total){
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-signs_total'", a_update_token ? "token_update" : "token_decl");
        return -7;
    }

    if(!a_params->ticker){
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter '-token'", a_update_token ? "token_update" : "token_decl");
        return -2;
    }

    // Check certs list
    if(!a_params->certs_str){
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s requires parameter 'certs'", a_update_token ? "token_update" : "token_decl");
        return -9;
    }
    return 0;
}

/**
 * @brief com_token_decl
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 * @details token_decl -net <net name> -chain <chain name> -token <token ticker> -total_supply <total supply> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list>\n"
 *  \t Declare new simple token for <netname>:<chain name> with ticker <token ticker>, maximum emission <total supply> and <signs for emission> from <signs total> signatures on valid emission\n"
 *  \t   Extended private token declaration\n"
 *  \t token_decl -net <net name> -chain <chain name> -token <token ticker> -type private -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...  [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
 *  \t   Declare new token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>"
 *  \t   and custom parameters list <Param 1>, <Param 2>...<Param N>."
 *  \n"
 *  ==Flags=="
 *  \t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
 *  \t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
 *  \t ALL_FROZEN:\t All permissions are temprorary frozen\n"
 *  \t ALL_UNFROZEN:\t Unfrozen permissions\n"
 *  \t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
 *  \t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
 *  \t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
    "\n"
    "==Params==\n"
    "General:\n"
    "\t -flags <value>:\t Set list of flags from <value> to token declaration\n"
    "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
    "\t -signs_valid <value>:\t Set valid signatures count's minimum\n"
    "\t -signs <value>:\t Add signature's pkey fingerprint to the list of owners\n"
    "\nDatum type allowed/blocked:\n"
    "\t -datum_type_allowed <value>:\t Allowed datum type(s)\n"
    "\t -datum_type_blocked <value>:\t Blocked datum type(s)\n"
    "\nTx receiver addresses allowed/blocked:\n"
    "\t -tx_receiver_allowed <value>:\t Allowed tx receiver(s)\n"
    "\t -tx_receiver_blocked <value>:\t Blocked tx receiver(s)\n"
    "\n Tx sender addresses allowed/blocked:\n"
    "\t -tx_sender_allowed <value>:\t Allowed tx sender(s)\n"
    "\t -tx_sender_blocked <value>:\t Blocked tx sender(s)\n"
    "\n"
 */
int com_token_decl(int a_argc, char ** a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    const char * l_ticker = NULL;
    uint256_t l_total_supply = {}; // 256
    uint16_t l_signs_emission = 0;
    uint16_t l_signs_total = 0;
    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;
    const char * l_hash_out_type = NULL;

    dap_sdk_cli_params* l_params = DAP_NEW_Z(dap_sdk_cli_params);

    if (!l_params) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }

    l_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE;

    int l_parse_params = s_token_decl_check_params(a_argc,a_argv,a_str_reply,l_params, false);
    if (l_parse_params) {
        DAP_DEL_Z(l_params);
        return l_parse_params;
    }

    dap_chain_datum_token_t * l_datum_token = NULL;
    size_t l_datum_data_offset = 0;

    // Load certs lists
    dap_cert_parse_str_list(l_params->certs_str, &l_certs, &l_certs_count);
    if(!l_certs_count){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "token_decl command requres at least one valid certificate to sign token");
        DAP_DEL_Z(l_params);
        return -10;
    }

    l_signs_emission = l_params->signs_emission;
    l_signs_total = l_params->signs_total;
    l_total_supply = l_params->total_supply;
    l_chain = l_params->chain;
    l_net = l_params->net;
    l_ticker = l_params->ticker;
    l_hash_out_type = l_params->hash_out_type;

    switch(l_params->subtype)
    {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
		{ // 256
            dap_list_t *l_tsd_list = NULL;
            size_t l_tsd_total_size = 0;
            uint16_t l_flags = 0;
            char ** l_str_flags = NULL;

            if (l_params->ext.flags){   // Flags
                 l_str_flags = dap_strsplit(l_params->ext.flags,",",0xffff );
                 while (l_str_flags && *l_str_flags){
                     uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_str_flags);
                     if (l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                         dap_cli_server_cmd_set_reply_text(a_str_reply, "Flag can't be \"%s\"",*l_str_flags);
                         DAP_DEL_Z(l_params);
                         return -20;
                     }
                     l_flags |= l_flag; // if we have multiple flags
                     l_str_flags++;
                }
            }
			if (l_params->ext.delegated_token_from){
				dap_chain_datum_token_t *l_delegated_token_from;
				if (NULL == (l_delegated_token_from = dap_ledger_token_ticker_check(l_net->pub.ledger, l_params->ext.delegated_token_from))) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,"To create a delegated token %s, can't find token by ticket %s", l_ticker, l_params->ext.delegated_token_from);
                    DAP_DEL_Z(l_params);
					return -91;
				}
				dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section;
                strcpy((char *)l_tsd_section.ticker_token_from, l_params->ext.delegated_token_from);
//				l_tsd_section.token_from = dap_hash_fast();
				l_tsd_section.emission_rate = dap_chain_coins_to_balance("0.001");//	TODO: 'm' 1:1000 tokens
				dap_tsd_t * l_tsd = dap_tsd_create_scalar(
														DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK, l_tsd_section);
				l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
				l_tsd_total_size+= dap_tsd_size(l_tsd);
			}
            if (l_params->ext.total_signs_valid){ // Signs valid
                uint16_t l_param_value = (uint16_t)atoi(l_params->ext.total_signs_valid);
                l_signs_total = l_param_value;
                dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                        DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID, l_param_value);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                l_tsd_total_size+= dap_tsd_size(l_tsd);
            }
            if (l_params->ext.datum_type_allowed){
                dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                        DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD, l_params->ext.datum_type_allowed);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                l_tsd_total_size+= dap_tsd_size(l_tsd);
            }
            if (l_params->ext.datum_type_blocked){
                dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                        DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD, l_params->ext.datum_type_blocked);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                l_tsd_total_size+= dap_tsd_size(l_tsd);
            }
            if (l_params->ext.tx_receiver_allowed)
                l_tsd_list = s_parse_wallet_addresses(l_params->ext.tx_receiver_allowed, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD);

            if (l_params->ext.tx_receiver_blocked)
                l_tsd_list = s_parse_wallet_addresses(l_params->ext.tx_receiver_blocked, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD);

            if (l_params->ext.tx_sender_allowed)
                l_tsd_list = s_parse_wallet_addresses(l_params->ext.tx_sender_allowed, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD);

            if (l_params->ext.tx_sender_blocked)
                l_tsd_list = s_parse_wallet_addresses(l_params->ext.tx_sender_blocked, l_tsd_list, &l_tsd_total_size, DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD);

            if (l_params->ext.parsed_tsd) {
                l_tsd_total_size += l_params->ext.parsed_tsd_size;
            }


            // Create new datum token
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t) + l_tsd_total_size);
            if (!l_datum_token) {
                log_it(L_CRITICAL, "Memory allocation error");
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Out of memory in com_token_decl");
                DAP_DEL_Z(l_params);
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->type = l_params->type;
            l_datum_token->subtype = l_params->subtype;
            if (l_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE) {
                log_it(L_DEBUG,"Prepared TSD sections for private token on %zd total size", l_params->ext.tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->header_private_decl.flags = l_params->ext.parsed_flags;
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_private_decl.tsd_total_size = l_tsd_total_size;
                l_datum_token->header_private_decl.decimals = atoi(l_params->decimals_str);
            } else { //DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL
                log_it(L_DEBUG,"Prepared TSD sections for CF20 token on %zd total size", l_params->ext.tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->header_native_decl.flags = l_params->ext.parsed_flags;
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_native_decl.tsd_total_size = l_tsd_total_size;
                l_datum_token->header_native_decl.decimals = atoi(l_params->decimals_str);
            }
            // Add TSD sections in the end
            for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
                dap_tsd_t * l_tsd = (dap_tsd_t *) l_iter->data;
                if (l_tsd == NULL){
                    log_it(L_ERROR, "NULL tsd in list!");
                    continue;
                }
                switch (l_tsd->type){
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
                    uint16_t l_t = 0;
                        log_it(L_DEBUG,"== TOTAL_SIGNS_VALID: %u",
                                _dap_tsd_get_scalar(l_tsd, &l_t) );
                    break;
                }
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD:
                        log_it(L_DEBUG,"== DATUM_TYPE_ALLOWED_ADD: %s",
                               dap_tsd_get_string_const(l_tsd) );
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                        log_it(L_DEBUG,"== TX_SENDER_ALLOWED_ADD: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                        log_it(L_DEBUG,"== TYPE_TX_SENDER_BLOCKED: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                        log_it(L_DEBUG,"== TX_RECEIVER_ALLOWED_ADD: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                        log_it(L_DEBUG,"== TX_RECEIVER_BLOCKED_ADD: binary data");
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD:
                        if(l_tsd->size >= sizeof(dap_pkey_t)){
                            char *l_hash_str;
                            dap_pkey_t *l_pkey = (dap_pkey_t*)l_tsd->data;
                            dap_hash_fast_t l_hf = {0};
                            if (!dap_pkey_get_hash(l_pkey, &l_hf)) {
                                log_it(L_DEBUG, "== total_pkeys_add: <WRONG CALCULATION FINGERPRINT>");
                            } else {
                                l_hash_str = dap_chain_hash_fast_to_str_new(&l_hf);
                                log_it(L_DEBUG, "== total_pkeys_add: %s", l_hash_str);
                                DAP_DELETE(l_hash_str);
                            }
                        } else
                            log_it(L_DEBUG,"== total_pkeys_add: <WRONG SIZE %u>", l_tsd->size);
                        break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION:
                        log_it(L_DEBUG, "== description: %s", l_tsd->data);
                        break;
                    default: log_it(L_DEBUG, "== 0x%04X: binary data %u size ",l_tsd->type, l_tsd->size );
                }
                size_t l_tsd_size = dap_tsd_size(l_tsd);
                memcpy(l_datum_token->data_n_tsd + l_datum_data_offset, l_tsd, l_tsd_size);
                l_datum_data_offset += l_tsd_size;
            }
            if (l_params->ext.parsed_tsd) {
                memcpy(l_datum_token->data_n_tsd + l_datum_data_offset,
                       l_params->ext.parsed_tsd,
                       l_params->ext.tsd_total_size);
                l_datum_data_offset += l_params->ext.tsd_total_size;
            }
            log_it(L_DEBUG, "%s token declaration '%s' initialized", l_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE ?
                            "Private" : "CF20", l_datum_token->ticker);
        }break;//end
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE: { // 256
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t));
            if (!l_datum_token) {
                log_it(L_CRITICAL, "Memory allocation error");
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Out of memory in com_token_decl");
                DAP_DEL_Z(l_params);
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL; // 256
            l_datum_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE; // 256
            snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
            l_datum_token->total_supply = l_total_supply;
            l_datum_token->signs_valid = l_signs_emission;
            l_datum_token->header_simple.decimals = atoi(l_params->decimals_str);
        }break;
        default:
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "Unknown token type");
            DAP_DEL_Z(l_params);
            return -8;
    }
    // If we have more certs than we need signs - use only first part of the list
    if(l_certs_count > l_signs_total)
        l_certs_count = l_signs_total;
    // Sign header with all certificates in the list and add signs to the end of TSD cetions
    uint16_t l_sign_counter = 0;
    l_datum_token = s_sign_cert_in_cycle(l_certs, l_datum_token, l_certs_count, &l_datum_data_offset, &l_sign_counter);
    l_datum_token->signs_total = l_sign_counter;

    // We skip datum creation opeartion, if count of signed certificates in s_sign_cert_in_cycle is 0.
    // Usually it happen, when certificate in token_decl or token_update command doesn't contain private data or broken
    if (!l_datum_token || l_datum_token->signs_total == 0){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "Token declaration failed. Successful count of certificate signing is 0");
            DAP_DEL_Z(l_params);
            return -9;
    }

    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_DECL,
                                                         l_datum_token,
                                                         sizeof(*l_datum_token) + l_datum_data_offset);
    DAP_DELETE(l_datum_token);
    size_t l_datum_size = dap_chain_datum_size(l_datum);

    // Calc datum's hash
    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_key_hash);
    char * l_key_str = !dap_strcmp(l_hash_out_type, "hex") ?
                dap_chain_hash_fast_to_str_new(&l_key_hash) :
                dap_enc_base58_encode_hash_to_str(&l_key_hash);

    // Add datum to mempool with datum_token hash as a key
    char *l_gdb_group_mempool = l_chain
            ? dap_chain_net_get_gdb_group_mempool_new(l_chain)
            : dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);
    if (!l_gdb_group_mempool) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "No suitable chain for placing token datum found");
        DAP_DEL_Z(l_key_str);
        DAP_DELETE(l_datum);
        DAP_DEL_Z(l_params);
        return -10;
    }
    bool l_placed = dap_global_db_set_sync(l_gdb_group_mempool, l_key_str, l_datum, l_datum_size, false) == 0;
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s with token %s is%s placed in datum pool",
                                      l_key_str, l_ticker, l_placed ? "" : " not");
    DAP_DEL_Z(l_key_str);
    DAP_DELETE(l_datum);
    DAP_DELETE(l_params);
    return l_placed ? 0 : -2;
}

/**
 * @brief com_token_decl_update
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 * @details token_update -net <net name> -chain <chain_name> -token <token ticker> [-type private] -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...  [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
 *  \t   Update token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>"
 *  \t   and custom parameters list <Param 1>, <Param 2>...<Param N>."
 *  \n"
 *  ==Flags=="
 *  \t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
 *  \t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
 *  \t ALL_FROZEN:\t All permissions are temprorary frozen\n"
 *  \t ALL_UNFROZEN:\t Unfrozen permissions\n"
 *  \t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
 *  \t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
 *  \t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
 *  \t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
    "\n"
    "==Params==\n"
    "General:\n"
    "\t -flags_set <value>:\t Set list of flags from <value> to token declaration\n"
    "\t -flags_unset <value>:\t Unset list of flags from <value> from token declaration\n"
    "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
    "\t -total_signs_valid <value>:\t Set valid signatures count's minimum\n"
    "\t -total_signs_add <value>:\t Add signature's pkey fingerprint to the list of owners\n"
    "\t -total_signs_remove <value>:\t Remove signature's pkey fingerprint from the owners\n"
    "\nDatum type allowed/blocked updates:\n"
    "\t -datum_type_allowed_add <value>:\t Add allowed datum type(s)\n"
    "\t -datum_type_allowed_remove <value>:\t Remove datum type(s) from allowed\n"
    "\t -datum_type_blocked_add <value>:\t Add blocked datum type(s)\n"
    "\t -datum_type_blocked_remove <value>:\t Remove datum type(s) from blocked\n"
    "\nTx receiver addresses allowed/blocked updates:\n"
    "\t -tx_receiver_allowed_add <value>:\t Add allowed tx receiver(s)\n"
    "\t -tx_receiver_allowed_remove <value>:\t Remove tx receiver(s) from allowed\n"
    "\t -tx_receiver_blocked_add <value>:\t Add blocked tx receiver(s)\n"
    "\t -tx_receiver_blocked_remove <value>:\t Remove tx receiver(s) from blocked\n"
    "\n Tx sender addresses allowed/blocked updates:\n"
    "\t -tx_sender_allowed_add <value>:\t Add allowed tx sender(s)\n"
    "\t -tx_sender_allowed_remove <value>:\t Remove tx sender(s) from allowed\n"
    "\t -tx_sender_blocked_add <value>:\t Add allowed tx sender(s)\n"
    "\t -tx_sender_blocked_remove <value>:\t Remove tx sender(s) from blocked\n"
    "\n"
 */
int com_token_update(int a_argc, char ** a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    const char * l_ticker = NULL;
    uint256_t l_total_supply = {}; // 256
    uint16_t l_signs_emission = 0;
    uint16_t l_signs_total = 0;
    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;
    const char * l_hash_out_type = NULL;

    dap_sdk_cli_params* l_params = DAP_NEW_Z(dap_sdk_cli_params);

    if (!l_params) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }

    l_params->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_params->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE;

    int l_parse_params = s_token_decl_check_params(a_argc,a_argv,a_str_reply,l_params, true);
    if (l_parse_params)
        return l_parse_params;

    dap_chain_datum_token_t * l_datum_token = NULL;
    size_t l_datum_data_offset = 0;

    // Load certs lists
    dap_cert_parse_str_list(l_params->certs_str, &l_certs, &l_certs_count);
    if(!l_certs_count){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                          "com_token_update command requres at least one valid certificate to sign token");
        return -10;
    }

    l_signs_emission = l_params->signs_emission;
    l_signs_total = l_params->signs_total;
    l_total_supply = l_params->total_supply;
    l_chain = l_params->chain;
    l_net = l_params->net;
    l_ticker = l_params->ticker;
    l_hash_out_type = l_params->hash_out_type;

    switch(l_params->subtype)
    {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
        { // 256
            // Create new datum token
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t) + l_params->ext.tsd_total_size);
            if (!l_datum_token) {
                log_it(L_CRITICAL, "Memory allocation error");
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->type = l_params->type;
            l_datum_token->subtype = l_params->subtype;
            if (l_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE) {
                log_it(L_DEBUG,"Prepared TSD sections for CF20 token on %zd total size", l_params->ext.tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->header_native_update.flags = l_params->ext.parsed_flags;
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_native_update.tsd_total_size = l_params->ext.tsd_total_size;
                l_datum_token->header_native_update.decimals = atoi(l_params->decimals_str);
                l_datum_data_offset = l_params->ext.tsd_total_size;
            } else { // if (l_params->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE) {
                log_it(L_DEBUG,"Prepared TSD sections for private token on %zd total size", l_params->ext.tsd_total_size);
                snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
                l_datum_token->header_private_update.flags = l_params->ext.parsed_flags;
                l_datum_token->total_supply = l_total_supply;
                l_datum_token->signs_valid = l_signs_emission;
                l_datum_token->header_private_update.tsd_total_size = l_params->ext.tsd_total_size;
                l_datum_token->header_private_update.decimals = atoi(l_params->decimals_str);
                l_datum_data_offset = l_params->ext.tsd_total_size;
            }
            // Add TSD sections in the end
            // Add TSD sections in the end
            if (l_params->ext.tsd_total_size) {
                memcpy(l_datum_token->data_n_tsd, l_params->ext.parsed_tsd, l_params->ext.parsed_tsd_size);
                DAP_DELETE(l_params->ext.parsed_tsd);
            }
            log_it(L_DEBUG, "%s token declaration update '%s' initialized", (	l_params->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE)	?
                                                                     "Private" : "CF20", l_datum_token->ticker);
        }break;//end
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE: { // 256
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t));
            if (!l_datum_token) {
                log_it(L_CRITICAL, "Memory allocation error");
                return -1;
            }
            l_datum_token->version = 2;
            l_datum_token->subtype = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
            l_datum_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE; // 256
            snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
            l_datum_token->total_supply = l_total_supply;
            l_datum_token->signs_valid = l_signs_emission;
            if (l_params->decimals_str)
                l_datum_token->header_simple.decimals = atoi(l_params->decimals_str);
        }break;
        default:
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "Unknown token type");
            return -8;
    }
    // If we have more certs than we need signs - use only first part of the list
    if(l_certs_count > l_signs_total)
        l_certs_count = l_signs_total;
    // Sign header with all certificates in the list and add signs to the end of TSD cetions
    uint16_t l_sign_counter = 0;
    l_datum_token = s_sign_cert_in_cycle(l_certs, l_datum_token, l_certs_count, &l_datum_data_offset, &l_sign_counter);
    l_datum_token->signs_total = l_sign_counter;

    // We skip datum creation opeartion, if count of signed certificates in s_sign_cert_in_cycle is 0.
    // Usually it happen, when certificate in token_decl or token_update command doesn't contain private data or broken
    if (!l_datum_token || l_datum_token->signs_total == 0){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                          "Token declaration update failed. Successful count of certificate signing is 0");
        return -9;
    }

    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_DECL,
                                                         l_datum_token,
                                                         sizeof(*l_datum_token) + l_datum_data_offset);
    DAP_DELETE(l_datum_token);
    size_t l_datum_size = dap_chain_datum_size(l_datum);

    // Calc datum's hash
    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_key_hash);
    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    char * l_key_str_out = dap_strcmp(l_hash_out_type, "hex") ?
                           dap_enc_base58_encode_hash_to_str(&l_key_hash) : dap_strdup(l_key_str);

    // Add datum to mempool with datum_token hash as a key
    char *l_gdb_group_mempool = l_chain
            ? dap_chain_net_get_gdb_group_mempool_new(l_chain)
            : dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);
    if (!l_gdb_group_mempool) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "No suitable chain for placing token datum found");
        DAP_DEL_Z(l_key_str);
        DAP_DEL_Z(l_key_str_out);
        DAP_DELETE(l_datum);
        return -10;
    }
    bool l_placed = !dap_global_db_set_sync(l_gdb_group_mempool, l_key_str, (uint8_t *)l_datum, l_datum_size, false);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s with 256bit token %s is%s placed in datum pool",
                                      l_key_str_out, l_ticker, l_placed ? "" : " not");
    DAP_DEL_Z(l_key_str);
    DAP_DEL_Z(l_key_str_out);
    DAP_DELETE(l_datum);
    DAP_DELETE(l_params);
    return l_placed ? 0 : -2;
}

/**
 * @brief com_token_emit
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_token_emit(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    int arg_index = 1;
    const char *str_tmp = NULL;
    //const char *str_fee = NULL;
    char *l_str_reply_tmp = NULL;
    uint256_t l_emission_value = {};
    //uint256_t l_fee_value = {};
    const char * l_ticker = NULL;

    const char * l_addr_str = NULL;

    const char * l_emission_hash_str = NULL;
    const char * l_emission_hash_str_remove = NULL;
    dap_chain_hash_fast_t l_emission_hash;
    dap_chain_datum_token_emission_t *l_emission = NULL;
    size_t l_emission_size;

    const char * l_certs_str = NULL;

    dap_cert_t ** l_certs = NULL;
    size_t l_certs_size = 0;

    const char * l_chain_emission_str = NULL;
    dap_chain_t * l_chain_emission = NULL;

    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,a_argc,a_argv,a_str_reply,NULL, &l_net);
    if( ! l_net) { // Can't find such network
        return -43;
    }
    // Token emission
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-emission", &l_emission_hash_str);

    // Emission certs
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);

    // Wallet address that recieves the emission
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);

    // Token ticker
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_ticker);

    if(!l_certs_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "token_emit requires parameter '-certs'");
        return -4;
    }
    dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_size);

    if(!l_certs_size) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "token_emit command requres at least one valid certificate to sign the basic transaction of emission");
        return -5;
    }
    const char *l_add_sign = NULL;
    dap_chain_addr_t *l_addr = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "sign", &l_add_sign);
    if (!l_add_sign) {      //Create the emission
        // Emission value
        if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-emission_value", &str_tmp)) {
            l_emission_value = dap_chain_balance_scan(str_tmp);
        }

        if (IS_ZERO_256(l_emission_value)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "token_emit requires parameter '-emission_value'");
            return -1;
        }

        if(!l_addr_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "token_emit requires parameter '-addr'");
            return -2;
        }

        if(!l_ticker) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "token_emit requires parameter '-token'");
            return -3;
        }

        l_addr = dap_chain_addr_from_str(l_addr_str);

        if(!l_addr) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "address \"%s\" is invalid", l_addr_str);
            return -4;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain_emission", &l_chain_emission_str);
        if(l_chain_emission_str) {
            if((l_chain_emission = dap_chain_net_get_chain_by_name(l_net, l_chain_emission_str)) == NULL) { // Can't find such chain
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                      "token_emit requires parameter '-chain_emission' to be valid chain name in chain net %s"
                                      " or set default datum type in chain configuration file", l_net->pub.name);
                return -45;
            }
        }
    } else {
        if (l_emission_hash_str) {
            DL_FOREACH(l_net->pub.chains, l_chain_emission) {
                l_emission = dap_chain_mempool_emission_get(l_chain_emission, l_emission_hash_str);
                if (l_emission){
                    l_emission_hash_str_remove = l_emission_hash_str;
                    break;
                }
            }
            if (!l_emission){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can' find emission with hash \"%s\" for token %s on network %s",
                                                  l_emission_hash_str, l_ticker, l_net->pub.name);
                return -32;
            }
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand 'sign' recuires parameter '-emission'");
            return -31;
        }
    }

    // Check, if network ID is same as ID in destination wallet address. If not - operation is cancelled.
    if (!dap_chain_addr_is_blank(l_addr) && l_addr->net_id.uint64 != l_net->pub.id.uint64) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "destination wallet network ID=0x%"DAP_UINT64_FORMAT_x
                                                       " and network ID=0x%"DAP_UINT64_FORMAT_x" is not equal."
                                                       " Please, change network name or wallet address",
                                                       l_addr->net_id.uint64, l_net->pub.id.uint64);
        DAP_DEL_Z(l_addr);
        DAP_DEL_Z(l_emission);
        return -3;
    }

    if(!l_ticker) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "token_emit requires parameter '-token'");
        DAP_DEL_Z(l_addr);
        return -3;
    }

    if (!l_add_sign) {
        if (!l_chain_emission) {
			if ( (l_chain_emission = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_EMISSION)) == NULL ) {
				DAP_DEL_Z(l_addr);
				dap_cli_server_cmd_set_reply_text(a_str_reply,
					"token_create requires parameter '-chain_emission' to be valid chain name in chain net %s or set default datum type in chain configuration file",
						 l_net->pub.name);
				return -50;
			}
        }
        // Create emission datum
        l_emission = dap_chain_datum_emission_create(l_emission_value, l_ticker, l_addr);
    }
    // Then add signs
    for(size_t i = 0; i < l_certs_size; i++)
        l_emission = dap_chain_datum_emission_add_sign(l_certs[i]->enc_key, l_emission);
    // Calc emission's hash
    l_emission_size = dap_chain_datum_emission_get_size((uint8_t *)l_emission);
    dap_hash_fast(l_emission, l_emission_size, &l_emission_hash);
    // Produce datum
    dap_chain_datum_t *l_datum_emission = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_EMISSION,
            l_emission,
            l_emission_size);
    // Delete token emission
    DAP_DEL_Z(l_emission);
    l_emission_hash_str = dap_chain_mempool_datum_add(l_datum_emission, l_chain_emission, l_hash_out_type);
    if (l_emission_hash_str)
        l_str_reply_tmp = dap_strdup_printf("Datum %s with 256bit emission is placed in datum pool", l_emission_hash_str);
    else
        l_str_reply_tmp = dap_strdup("Can't place emission datum in mempool, examine log files");
    DAP_DEL_Z(l_emission_hash_str);
    DAP_DEL_Z(l_datum_emission);

    //remove previous emission datum from mempool if have new signed emission datum
    if (l_emission_hash_str_remove) {
        char *l_gdb_group_mempool_emission = dap_chain_net_get_gdb_group_mempool_new(l_chain_emission);
        dap_global_db_del_sync(l_gdb_group_mempool_emission, l_emission_hash_str_remove);
        DAP_DEL_Z(l_gdb_group_mempool_emission);
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_reply_tmp);

    DAP_DEL_Z(l_certs);
    DAP_DEL_Z(l_str_reply_tmp);
    DAP_DEL_Z(l_addr);
    return 0;
}


/**
 * @brief com_tx_cond_create
 * Create transaction
 * com_tx_cond_create command
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return int
 */
int com_tx_cond_create(int a_argc, char ** a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    (void) a_argc;
    int arg_index = 1;
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    const char * l_token_ticker = NULL;
    const char * l_wallet_str = NULL;
    const char * l_cert_str = NULL;
    const char * l_value_datoshi_str = NULL;
    const char * l_value_fee_str = NULL;
    const char * l_net_name = NULL;
    const char * l_unit_str = NULL;
    const char * l_srv_uid_str = NULL;
    uint256_t l_value_datoshi = {};    
    uint256_t l_value_fee = {};
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    // Token ticker
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_ticker);
    // Wallet name - from
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    // Public certifiacte of condition owner
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_str);
    // value datoshi
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_datoshi_str);
    // fee
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_value_fee_str);
    // net
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // unit
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unit", &l_unit_str);
    // service
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);

    if(!l_token_ticker) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-token'");
        return -1;
    }
    if (!l_wallet_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-w'");
        return -2;
    }
    if (!l_cert_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-cert'");
        return -3;
    }
    if(!l_value_datoshi_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-value'");
        return -4;
    }
    if(!l_value_fee_str){
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-fee'");
        return -15;
    }
    if(!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-net'");
        return -5;
    }
    if(!l_unit_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-unit'");
        return -6;
    }

    if(!l_srv_uid_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-srv_uid'");
        return -7;
    }
    dap_chain_net_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find service UID %s ", l_srv_uid_str);
        return -8;
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = dap_chain_net_srv_price_unit_uid_from_str(l_unit_str);

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't recognize unit '%s'. Unit must look like {mb | kb | b | sec | day}",
                l_unit_str);
        return -9;
    }

    l_value_datoshi = dap_chain_balance_scan(l_value_datoshi_str);
    if(IS_ZERO_256(l_value_datoshi)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't recognize value '%s' as a number", l_value_datoshi_str);
        return -10;
    }

    l_value_fee = dap_chain_balance_scan(l_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't recognize value '%s' as a number", l_value_fee_str);
        return -16;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if(!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find net '%s'", l_net_name);
        return -11;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, c_wallets_path);
    const char* l_sign_str = "";
    if(!l_wallet) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't open wallet '%s'", l_wallet_str);
        return -12;
    } else {
        l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    }

    dap_cert_t *l_cert_cond = dap_cert_find_by_name(l_cert_str);
    if(!l_cert_cond) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find cert '%s'", l_cert_str);
        return -13;
    }

    dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
    dap_pkey_t *l_key_cond = dap_pkey_from_enc_key(l_cert_cond->enc_key);
    if (!l_key_cond) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Cert '%s' doesn't contain a valid public key", l_cert_str);
        return -14;
    }

    uint256_t l_value_per_unit_max = {};
    char *l_hash_str = dap_chain_mempool_tx_create_cond(l_net, l_key_from, l_key_cond, l_token_ticker,
                                                        l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                        l_srv_uid, l_value_fee, NULL, 0, l_hash_out_type);
    dap_chain_wallet_close(l_wallet);
    DAP_DELETE(l_key_cond);

    if (l_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%sConditional 256bit TX created succefully, hash = %s\n", l_sign_str, l_hash_str);
        DAP_DELETE(l_hash_str);
        return 0;
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create conditional 256bit TX\n");
    return -1;
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
 * @param reply
 * @return
 */
int _cmd_mempool_add_ca(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_cert_t *a_cert, void ** reply)
{
    json_object ** a_json_reply = (json_object **) reply;
    if (!a_net || !a_chain || !a_cert){
        dap_json_rpc_error_add(COM_MEMPOOL_ADD_CA_ERROR_NET_NOT_FOUND, "The network, chain or certificate attribute was not passed.");
        return COM_MEMPOOL_ADD_CA_ERROR_NET_NOT_FOUND;
    }
    dap_chain_t *l_chain = a_chain;
    // Chech for chain if was set or not
    if (!a_chain){
       // If wasn't set - trying to auto detect
        l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_CA);
        if (!l_chain) { // If can't auto detect
            // clean previous error code
            dap_json_rpc_error_add(COM_MEMPOOL_ADD_CA_ERROR_NO_CAINS_FOR_CA_DATUM_IN_NET,
                                   "No chains for CA datum in network \"%s\"", a_net->pub.name);
            return COM_MEMPOOL_ADD_CA_ERROR_NO_CAINS_FOR_CA_DATUM_IN_NET;
        }
    }
    if(!a_cert->enc_key){
        dap_json_rpc_error_add(COM_MEMPOOL_ADD_CA_ERROR_CORRUPTED_CERTIFICATE_WITHOUT_KEYS,
                               "Corrupted certificate \"%s\" without keys certificate", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CORRUPTED_CERTIFICATE_WITHOUT_KEYS;
    }

    if (a_cert->enc_key->priv_key_data_size || a_cert->enc_key->priv_key_data){
        dap_json_rpc_error_add(COM_MEMPOOL_ADD_CA_ERROR_CERTIFICATE_HAS_PRIVATE_KEY_DATA,
                               "Certificate \"%s\" has private key data. Please export public only key certificate without private keys", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CERTIFICATE_HAS_PRIVATE_KEY_DATA;
    }

    // Serialize certificate into memory
    uint32_t l_cert_serialized_size = 0;
    byte_t * l_cert_serialized = dap_cert_mem_save(a_cert, &l_cert_serialized_size);
    if(!l_cert_serialized){
        dap_json_rpc_error_add(COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE,
                               "Can't serialize in memory certificate \"%s\"", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE;
    }
    // Now all the chechs passed, forming datum for mempool
    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CA, l_cert_serialized , l_cert_serialized_size);
    DAP_DELETE( l_cert_serialized);
    if(!l_datum){
        dap_json_rpc_error_add(COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE,
                               "Can't produce datum from certificate \"%s\"", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    if (l_hash_str) {
        char *l_msg = dap_strdup_printf("Datum %s was successfully placed to mempool", l_hash_str);
        if (!l_msg) {
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object *l_obj_message = json_object_new_string(l_msg);
        DAP_DELETE(l_msg);
        DAP_DELETE(l_hash_str);
        if (!l_obj_message) {
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_array_add(*a_json_reply, l_obj_message);
        return 0;
    } else {
        char *l_msg = dap_strdup_printf("Can't place certificate \"%s\" to mempool", a_cert->name);
        if (!l_msg) {
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object *l_obj_msg = json_object_new_string(l_msg);
        DAP_DELETE(l_msg);
        if (!l_obj_msg) {
            dap_json_rpc_allocation_error;
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        json_object_array_add(*a_json_reply, l_obj_msg);
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
int com_chain_ca_copy( int a_argc,  char ** a_argv, void ** reply)
{
    int l_argc = a_argc + 1;
    char **l_argv = DAP_NEW_Z_COUNT(char*, l_argc);
    l_argv[0] = "mempool";
    l_argv[1] = "add_ca";
    for (int i = 1; i < a_argc; i++)
        l_argv[i + 1] = a_argv[i];
    int ret = com_mempool(l_argc, l_argv, reply);
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
int com_chain_ca_pub( int a_argc,  char ** a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    int arg_index = 1;
    // Read params
    const char * l_ca_name = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-ca_name", &l_ca_name);
    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,a_argc, a_argv, a_str_reply, &l_chain, &l_net);

    dap_cert_t * l_cert = dap_cert_find_by_name( l_ca_name );
    if( l_cert == NULL ){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Can't find \"%s\" certificate", l_ca_name );
        return -4;
    }


    if( l_cert->enc_key == NULL ){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Corrupted certificate \"%s\" without keys certificate", l_ca_name );
        return -5;
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
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_cert_new->enc_key);
        DAP_DELETE(l_cert_new);
        return -11;
    }
    memcpy(l_cert_new->enc_key->pub_key_data, l_cert->enc_key->pub_key_data,l_cert->enc_key->pub_key_data_size);

    // Serialize certificate into memory
    uint32_t l_cert_serialized_size = 0;
    byte_t * l_cert_serialized = dap_cert_mem_save( l_cert_new, &l_cert_serialized_size );
    if(!l_cert_serialized){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Can't serialize in memory certificate" );
        return -7;
    }
    // Now all the chechs passed, forming datum for mempool
    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CA, l_cert_serialized , l_cert_serialized_size);
    DAP_DELETE(l_cert_serialized);
    if(!l_datum){
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Can't produce datum from certificate");
        return -7;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    if (l_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Datum %s was successfully placed to mempool", l_hash_str);
        DAP_DELETE(l_hash_str);
        return 0;
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Can't place certificate \"%s\" to mempool", l_ca_name);
        return -8;
    }
}

static const char* s_json_get_text(struct json_object *a_json, const char *a_key)
{
    if(!a_json || !a_key)
        return NULL;
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json && json_object_is_type(l_json, json_type_string)) {
        // Read text
        return json_object_get_string(l_json);
    }
    return NULL;
}

static bool s_json_get_int64(struct json_object *a_json, const char *a_key, int64_t *a_out)
{
    if(!a_json || !a_key || !a_out)
        return false;
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json) {
        if(json_object_is_type(l_json, json_type_int)) {
            // Read number
            *a_out = json_object_get_int64(l_json);
            return true;
        }
    }
    return false;
}

static bool s_json_get_unit(struct json_object *a_json, const char *a_key, dap_chain_net_srv_price_unit_uid_t *a_out)
{
    const char *l_unit_str = s_json_get_text(a_json, a_key);
    if(!l_unit_str || !a_out)
        return false;
    dap_chain_net_srv_price_unit_uid_t l_unit = dap_chain_net_srv_price_unit_uid_from_str(l_unit_str);
    if(l_unit.enm == SERV_UNIT_UNDEFINED)
        return false;
    a_out->enm = l_unit.enm;
    return true;
}

static bool s_json_get_uint256(struct json_object *a_json, const char *a_key, uint256_t *a_out)
{
    const char *l_uint256_str = s_json_get_text(a_json, a_key);
    if(!a_out || !l_uint256_str)
        return false;
    uint256_t l_value = dap_chain_balance_scan(l_uint256_str);
    if(!IS_ZERO_256(l_value)) {
        memcpy(a_out, &l_value, sizeof(uint256_t));
        return true;
    }
    return false;
}

// service names: srv_stake, srv_vpn, srv_xchange
static bool s_json_get_srv_uid(struct json_object *a_json, const char *a_key_service_id, const char *a_key_service, uint64_t *a_out)
{
    uint64_t l_srv_id;
    if(!a_out)
        return false;
    // Read service id
    if(s_json_get_int64(a_json, a_key_service_id, (int64_t*) &l_srv_id)) {
        *a_out = l_srv_id;
        return true;
    }
    else {
        // Read service as name
        const char *l_service = s_json_get_text(a_json, a_key_service);
        if(l_service) {
            dap_chain_net_srv_t *l_srv = dap_chain_net_srv_get_by_name(l_service);
            if(!l_srv)
                return false;
            *a_out = l_srv->uid.uint64;
            return true;
        }
    }
    return false;
}

static dap_chain_wallet_t* s_json_get_wallet(struct json_object *a_json, const char *a_key)
{
    // From wallet
    const char *l_wallet_str = s_json_get_text(a_json, a_key);
    if(l_wallet_str) {
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_config_get_item_str_default(g_config, "resources", "wallets_path", NULL));
        return l_wallet;
    }
    return NULL;
}

static const dap_cert_t* s_json_get_cert(struct json_object *a_json, const char *a_key)
{
    const char *l_cert_name = s_json_get_text(a_json, a_key);
    if(l_cert_name) {
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
        return l_cert;
    }
    return NULL;
}

// Read pkey from wallet or cert
static dap_pkey_t* s_json_get_pkey(struct json_object *a_json)
{
    dap_pkey_t *l_pub_key = NULL;
    // From wallet
    dap_chain_wallet_t *l_wallet = s_json_get_wallet(a_json, "wallet");
    if(l_wallet) {
        l_pub_key = dap_chain_wallet_get_pkey(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
        if(l_pub_key) {
            return l_pub_key;
        }
    }
    // From cert
    const dap_cert_t *l_cert = s_json_get_cert(a_json, "cert");
    if(l_cert) {
        l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
    }
    return l_pub_key;
}


/**
 * @brief Create transaction from json file
 * com_tx_create command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_create_json(int a_argc, char ** a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    int l_arg_index = 1;
    int l_err_code = 0;
    const char *l_net_name = NULL; // optional parameter
    const char *l_chain_name = NULL; // optional parameter
    const char *l_json_file_path = NULL;
    const char *l_native_token = NULL;
    const char *l_main_token = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-json", &l_json_file_path);

    if(!l_json_file_path) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command requires one of parameters '-json <json file path>'");
        return -1;
    }
    // Open json file
    struct json_object *l_json = json_object_from_file(l_json_file_path);
    if(!l_json) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't open json file: %s", json_util_get_last_err());
        return -2;
    }
    if(!json_object_is_type(l_json, json_type_object)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Wrong json format");
        json_object_put(l_json);
        return -3;
    }

    
    // Read network from json file
    if(!l_net_name) {
        struct json_object *l_json_net = json_object_object_get(l_json, "net");
        if(l_json_net && json_object_is_type(l_json_net, json_type_string)) {
            l_net_name = json_object_get_string(l_json_net);
        }
        if(!l_net_name) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command requires parameter '-net' or set net in the json file");
            json_object_put(l_json);
            return -11;
        }
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    l_native_token = l_net->pub.native_ticker;
    if(!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Not found net by name '%s'", l_net_name);
        json_object_put(l_json);
        return -12;
    }

    // Read chain from json file
    if(!l_chain_name) {
        struct json_object *l_json_chain = json_object_object_get(l_json, "chain");
        if(l_json_chain && json_object_is_type(l_json_chain, json_type_string)) {
            l_chain_name = json_object_get_string(l_json_chain);
        }
    }
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    if(!l_chain) {
        l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    if(!l_chain) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Chain name '%s' not found, try use parameter '-chain' or set chain in the json file", l_chain_name);
        json_object_put(l_json);
        return -13;
    }


    // Read items from json file
    struct json_object *l_json_items = json_object_object_get(l_json, "items");
    size_t l_items_count = json_object_array_length(l_json_items);
    bool a = (l_items_count = json_object_array_length(l_json_items));
    if(!l_json_items || !json_object_is_type(l_json_items, json_type_array) || !(l_items_count = json_object_array_length(l_json_items))) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Wrong json format: not found array 'items' or array is empty");
        json_object_put(l_json);
        return -15;
    }

    log_it(L_ERROR, "Json TX: found %lu items", l_items_count);
    // Create transaction
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    if(!l_tx) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -16;
    }
    l_tx->header.ts_created = time(NULL);
    size_t l_items_ready = 0;
    size_t l_receipt_count = 0;
    dap_list_t *l_sign_list = NULL;// list 'sing' items
    dap_list_t *l_in_list = NULL;// list 'in' items
    dap_list_t *l_tsd_list = NULL;// list tsd sections
    uint256_t l_value_need = { };// how many tokens are needed in the 'out' item
    uint256_t l_value_need_fee = {};
    dap_string_t *l_err_str = dap_string_new("Errors: \n");
    // Creating and adding items to the transaction
    for(size_t i = 0; i < l_items_count; ++i) {
        struct json_object *l_json_item_obj = json_object_array_get_idx(l_json_items, i);
        if(!l_json_item_obj || !json_object_is_type(l_json_item_obj, json_type_object)) {
            continue;
        }
        struct json_object *l_json_item_type = json_object_object_get(l_json_item_obj, "type");
        if(!l_json_item_type && json_object_is_type(l_json_item_type, json_type_string)) {
            log_it(L_WARNING, "Item %zu without type", i);
            continue;
        }
        const char *l_item_type_str = json_object_get_string(l_json_item_type);
        dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_str_to_type(l_item_type_str);
        if(l_item_type == TX_ITEM_TYPE_UNKNOWN) {
            log_it(L_WARNING, "Item %zu has invalid type '%s'", i, l_item_type_str);
            continue;
        }

        log_it(L_DEBUG, "Json TX: process item %s", json_object_get_string(l_json_item_type));
        // Create an item depending on its type
        const uint8_t *l_item = NULL;
        switch (l_item_type) {
        case TX_ITEM_TYPE_IN: {
            // Save item obj for in
            l_in_list = dap_list_append(l_in_list, l_json_item_obj);
        }
            break;

        case TX_ITEM_TYPE_OUT:
        case TX_ITEM_TYPE_OUT_EXT: {
            // Read address and value
            uint256_t l_value = { };
            const char *l_json_item_addr_str = s_json_get_text(l_json_item_obj, "addr");
            bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
            if(l_is_value && l_json_item_addr_str) {
                dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_json_item_addr_str);
                if(l_addr && !IS_ZERO_256(l_value)) {
                    if(l_item_type == TX_ITEM_TYPE_OUT) {
                        // Create OUT item
                        dap_chain_tx_out_t *l_out_item = dap_chain_datum_tx_item_out_create(l_addr, l_value);
                        if (!l_out_item) {
                            dap_string_append_printf(l_err_str, "Failed to create transaction out. "
                                                                "There may not be enough funds in the wallet.\n");
                        }
                        l_item = (const uint8_t*) l_out_item;
                    }
                    else if(l_item_type == TX_ITEM_TYPE_OUT_EXT) {
                        // Read address and value
                        const char *l_token = s_json_get_text(l_json_item_obj, "token");
                        l_main_token = l_token;
                        if(l_token) {
                            // Create OUT_EXT item
                            dap_chain_tx_out_ext_t *l_out_ext_item = dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                            if (!l_out_ext_item) {
                                dap_string_append_printf(l_err_str, "Failed to create a out ext"
                                                                    "for a transaction. There may not be enough funds "
                                                                    "on the wallet or the wrong ticker token "
                                                                    "is indicated.\n");
                            }
                            l_item = (const uint8_t*) l_out_ext_item;
                        }
                        else {
                            log_it(L_WARNING, "Invalid 'out_ext' item %zu", i);
                            continue;
                        }
                    }
                    // Save value for using in In item
                    if(l_item) {
                        SUM_256_256(l_value_need, l_value, &l_value_need);
                    }
                } else {
                    if(l_item_type == TX_ITEM_TYPE_OUT) {
                        log_it(L_WARNING, "Invalid 'out' item %zu", i);
                    }
                    else if(l_item_type == TX_ITEM_TYPE_OUT_EXT) {
                        log_it(L_WARNING, "Invalid 'out_ext' item %zu", i);
                    }
                    dap_string_append_printf(l_err_str, "For item %zu of type 'out' or 'out_ext' the "
                                                        "string representation of the address could not be converted, "
                                                        "or the size of the output sum is 0.\n", i);
                    continue;
                }
            }
        }
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            // Read subtype of item
            const char *l_subtype_str = s_json_get_text(l_json_item_obj, "subtype");
            dap_chain_tx_out_cond_subtype_t l_subtype = dap_chain_tx_out_cond_subtype_from_str(l_subtype_str);
            switch (l_subtype) {

            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY:{
                uint256_t l_value = { };
                bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
                if(!l_is_value || IS_ZERO_256(l_value)) {
                    log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                uint256_t l_value_max_per_unit = { };
                l_is_value = s_json_get_uint256(l_json_item_obj, "value_max_per_unit", &l_value_max_per_unit);
                if(!l_is_value || IS_ZERO_256(l_value_max_per_unit)) {
                    log_it(L_ERROR, "Json TX: bad value_max_per_unit in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                dap_chain_net_srv_price_unit_uid_t l_price_unit;
                if(!s_json_get_unit(l_json_item_obj, "price_unit", &l_price_unit)) {
                    log_it(L_ERROR, "Json TX: bad price_unit in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                dap_chain_net_srv_uid_t l_srv_uid;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)){
                    // Default service DAP_CHAIN_NET_SRV_VPN_ID
                    l_srv_uid.uint64 = 0x0000000000000001;
                }

                // From "wallet" or "cert"
                dap_pkey_t *l_pkey = s_json_get_pkey(l_json_item_obj);
                if(!l_pkey) {
                    log_it(L_ERROR, "Json TX: bad pkey in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                const char *l_params_str = s_json_get_text(l_json_item_obj, "params");
                size_t l_params_size = dap_strlen(l_params_str);
                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_pay(l_pkey, l_srv_uid, l_value, l_value_max_per_unit,
                        l_price_unit, l_params_str, l_params_size);
                l_item = (const uint8_t*) l_out_cond_item;
                // Save value for using in In item
                if(l_item) {
                    SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    dap_string_append_printf(l_err_str, "Unable to create conditional out for transaction "
                                                        "can of type %s described in item %zu.\n", l_subtype_str, i);
                }
                DAP_DELETE(l_pkey);
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {

                dap_chain_net_srv_uid_t l_srv_uid;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)) {
                    // Default service DAP_CHAIN_NET_SRV_XCHANGE_ID
                    l_srv_uid.uint64 = 0x2;
                }
                dap_chain_net_t *l_net = dap_chain_net_by_name(s_json_get_text(l_json_item_obj, "net"));
                if(!l_net) {
                    log_it(L_ERROR, "Json TX: bad net in OUT_COND_SUBTYPE_SRV_XCHANGE");
                    break;
                }
                const char *l_token = s_json_get_text(l_json_item_obj, "token");
                if(!l_token) {
                    log_it(L_ERROR, "Json TX: bad token in OUT_COND_SUBTYPE_SRV_XCHANGE");
                    break;
                }
                uint256_t l_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                    log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_XCHANGE");
                    break;
                }
                //const char *l_params_str = s_json_get_text(l_json_item_obj, "params");
                //size_t l_params_size = dap_strlen(l_params_str);
                dap_chain_tx_out_cond_t *l_out_cond_item = NULL; //dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_srv_uid, l_net->pub.id, l_token, l_value, l_params_str, l_params_size);
                l_item = (const uint8_t*) l_out_cond_item;
                // Save value for using in In item
                if(l_item) {
                    SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    dap_string_append_printf(l_err_str, "Unable to create conditional out for transaction "
                                                        "can of type %s described in item %zu.\n", l_subtype_str, i);
                }
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE:{
                dap_chain_net_srv_uid_t l_srv_uid;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)) {
                    // Default service DAP_CHAIN_NET_SRV_STAKE_ID
                    l_srv_uid.uint64 = 0x13;
                }
                uint256_t l_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                    log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }
                uint256_t l_fee_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "fee", &l_fee_value) || IS_ZERO_256(l_fee_value)) {
                    break;
                }
                
                const char *l_signing_addr_str = s_json_get_text(l_json_item_obj, "signing_addr");
                dap_chain_addr_t *l_signing_addr = dap_chain_addr_from_str(l_signing_addr_str);
                if(!l_signing_addr) {
                {
                    log_it(L_ERROR, "Json TX: bad signing_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }
                dap_chain_node_addr_t l_signer_node_addr;
                const char *l_node_addr_str = s_json_get_text(l_json_item_obj, "node_addr");
                if(!l_node_addr_str || dap_chain_node_addr_from_str(&l_signer_node_addr, l_node_addr_str)) {
                    log_it(L_ERROR, "Json TX: bad node_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }
                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_srv_uid, l_value, l_signing_addr,
                                                                                                             &l_signer_node_addr, NULL, uint256_0);
                l_item = (const uint8_t*) l_out_cond_item;
                // Save value for using in In item
                if(l_item) {
                    SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    dap_string_append_printf(l_err_str, "Unable to create conditional out for transaction "
                                                        "can of type %s described in item %zu.\n", l_subtype_str, i);
                }
                }
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: {
                uint256_t l_value = { };
                bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
                if(!IS_ZERO_256(l_value)) {
                    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_fee(l_value);
                    l_item = (const uint8_t*) l_out_cond_item;
                    // Save value for using in In item
                    if(l_item) {
                        SUM_256_256(l_value_need_fee, l_value, &l_value_need_fee);
                    } else {
                        dap_string_append_printf(l_err_str, "Unable to create conditional out for transaction "
                                                            "can of type %s described in item %zu.\n", l_subtype_str, i);
                    }
                }
                else
                    log_it(L_ERROR, "Json TX: zero value in OUT_COND_SUBTYPE_FEE");
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED:
                log_it(L_WARNING, "Undefined subtype: '%s' of 'out_cond' item %zu ", l_subtype_str, i);
                    dap_string_append_printf(l_err_str, "Specified unknown sub type %s of conditional out "
                                                        "on item %zu.\n", l_subtype_str, i);
                break;
            }
        }

            break;
        case TX_ITEM_TYPE_SIG:{
            // Save item obj for sign
            l_sign_list = dap_list_append(l_sign_list,l_json_item_obj);
        }
            break;
        case TX_ITEM_TYPE_RECEIPT: {
            dap_chain_net_srv_uid_t l_srv_uid;
            if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)) {
                log_it(L_ERROR, "Json TX: bad service_id in TYPE_RECEIPT");
                break;
            }
            dap_chain_net_srv_price_unit_uid_t l_price_unit;
            if(!s_json_get_unit(l_json_item_obj, "price_unit", &l_price_unit)) {
                log_it(L_ERROR, "Json TX: bad price_unit in TYPE_RECEIPT");
                break;
            }
            int64_t l_units;
            if(!s_json_get_int64(l_json_item_obj, "units", &l_units)) {
                log_it(L_ERROR, "Json TX: bad units in TYPE_RECEIPT");
                break;
            }
            uint256_t l_value = { };
            if(!s_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                log_it(L_ERROR, "Json TX: bad value in TYPE_RECEIPT");
                break;
            }
            const char *l_params_str = s_json_get_text(l_json_item_obj, "params");
            size_t l_params_size = dap_strlen(l_params_str);
            dap_chain_datum_tx_receipt_t *l_receipt = dap_chain_datum_tx_receipt_create(l_srv_uid, l_price_unit, l_units, l_value, l_params_str, l_params_size);
            l_item = (const uint8_t*) l_receipt;
            if(l_item)
                l_receipt_count++;
            else {
                dap_string_append_printf(l_err_str, "Unable to create receipt out for transaction "
                                                    "described by item %zu.\n", i);
            }
        }
            break;
        case TX_ITEM_TYPE_TSD: {
            int64_t l_tsd_type;
            if(!s_json_get_int64(l_json_item_obj, "type_tsd", &l_tsd_type)) {
                log_it(L_ERROR, "Json TX: bad type_tsd in TYPE_TSD");
                break;
            }
            const char *l_tsd_data = s_json_get_text(l_json_item_obj, "data");
            if (!l_tsd_data) {
                log_it(L_ERROR, "Json TX: bad data in TYPE_TSD");
                break;
            }
            size_t l_data_size = dap_strlen(l_tsd_data);
            dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create((void*)l_tsd_data, (int)l_tsd_type, l_data_size);
            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
        }
            break;
            //case TX_ITEM_TYPE_PKEY:
                //break;
            //case TX_ITEM_TYPE_IN_EMS:
                //break;
            //case TX_ITEM_TYPE_IN_EMS_EXT:
                //break;
        }
        // Add item to transaction
        if(l_item) {
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_item);
            l_items_ready++;
            DAP_DELETE(l_item);
        }
    }
    
    dap_list_t *l_list;
    // Add In items
    l_list = l_in_list;
    while(l_list) {
        struct json_object *l_json_item_obj = (struct json_object*) l_list->data;
        // Read prev_hash and out_prev_idx
        const char *l_prev_hash_str = s_json_get_text(l_json_item_obj, "prev_hash");
        int64_t l_out_prev_idx;
        bool l_is_out_prev_idx = s_json_get_int64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx);
        // If prev_hash and out_prev_idx were read
        if(l_prev_hash_str && l_is_out_prev_idx) {
            dap_chain_hash_fast_t l_tx_prev_hash;
            if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                // Create IN item
                dap_chain_tx_in_t *l_in_item = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, (uint32_t) l_out_prev_idx);
                if (!l_in_item) {
                    dap_string_append_printf(l_err_str, "Unable to create in for transaction.\n");
                }
            } else {
                log_it(L_WARNING, "Invalid 'in' item, bad prev_hash %s", l_prev_hash_str);
                dap_string_append_printf(l_err_str, "Unable to create in for transaction. Invalid 'in' item, "
                                                    "bad prev_hash %s\n", l_prev_hash_str);
                // Go to the next item
                l_list = dap_list_next(l_list);
                continue;
            }
        }
        // Read addr_from
        else {
            const char *l_json_item_addr_str = s_json_get_text(l_json_item_obj, "addr_from");
            const char *l_json_item_token = s_json_get_text(l_json_item_obj, "token");
            l_main_token = l_json_item_token;
            dap_chain_addr_t *l_addr_from = NULL;
            if(l_json_item_addr_str) {
                l_addr_from = dap_chain_addr_from_str(l_json_item_addr_str);
                if (!l_addr_from) {
                    log_it(L_WARNING, "Invalid element 'in', unable to convert string representation of addr_from: '%s' "
                                      "to binary.", l_json_item_addr_str);
                    dap_string_append_printf(l_err_str, "Invalid element 'to', unable to convert string representation "
                                                        "of addr_from: '%s' to binary.\n", l_json_item_addr_str);
                    // Go to the next item
                    l_list = dap_list_next(l_list);
                    continue;
                }
            }
            else {
                log_it(L_WARNING, "Invalid 'in' item, incorrect addr_from: '%s'", l_json_item_addr_str ? l_json_item_addr_str : "[null]");
                dap_string_append_printf(l_err_str, "Invalid 'in' item, incorrect addr_from: '%s'\n",
                                         l_json_item_addr_str ? l_json_item_addr_str : "[null]");
                // Go to the next item
                l_list = dap_list_next(l_list);
                continue;
            }
            if(!l_json_item_token) {
                log_it(L_WARNING, "Invalid 'in' item, not found token name");
                dap_string_append_printf(l_err_str, "Invalid 'in' item, not found token name\n");
                // Go to the next item
                l_list = dap_list_next(l_list);
                continue;
            }
            if(IS_ZERO_256(l_value_need)) {
                log_it(L_WARNING, "Invalid 'in' item, not found value in out items");
                dap_string_append_printf(l_err_str, "Invalid 'in' item, not found value in out items\n");
                // Go to the next item
                l_list = dap_list_next(l_list);
                continue;
            }
            if(l_addr_from)
            {
                // find the transactions from which to take away coins
                dap_list_t *l_list_used_out = NULL;
                dap_list_t *l_list_used_out_fee = NULL;
                uint256_t l_value_transfer = { }; // how many coins to transfer
                uint256_t l_value_transfer_fee = { }; // how many coins to transfer
                //SUM_256_256(a_value, a_value_fee, &l_value_need);
                uint256_t l_value_need_check = {};
                if (!dap_strcmp(l_native_token, l_main_token)) {
                    SUM_256_256(l_value_need_check, l_value_need, &l_value_need_check);
                    SUM_256_256(l_value_need_check, l_value_need_fee, &l_value_need_check);
                    l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_net->pub.ledger, l_json_item_token,
                                                                                             l_addr_from, l_value_need_check, &l_value_transfer);
                    if(!l_list_used_out) {
                        log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                        dap_string_append_printf(l_err_str, "Can't create in transaction. Not enough funds in previous tx "
                                                            "to transfer\n");
                        // Go to the next item
                        l_list = dap_list_next(l_list);
                        continue;
                    }
                } else {
                    //CHECK value need
                    l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_net->pub.ledger, l_json_item_token,
                                                                                             l_addr_from, l_value_need, &l_value_transfer);
                    if(!l_list_used_out) {
                        log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                        dap_string_append_printf(l_err_str, "Can't create in transaction. Not enough funds in previous tx "
                                                            "to transfer\n");
                        // Go to the next item
                        l_list = dap_list_next(l_list);
                        continue;
                    }
                    //CHECK value fee
                    l_list_used_out_fee = dap_ledger_get_list_tx_outs_with_val(l_net->pub.ledger, l_native_token,
                                                                                     l_addr_from, l_value_need_fee, &l_value_transfer_fee);
                    if(!l_list_used_out_fee) {
                        log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                        dap_string_append_printf(l_err_str, "Can't create in transaction. Not enough funds in previous tx "
                                                            "to transfer\n");
                        // Go to the next item
                        l_list = dap_list_next(l_list);
                        continue;
                    }
                }
                // add 'in' items
                uint256_t l_value_got = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
                assert(EQUAL_256(l_value_got, l_value_transfer));
                if (l_list_used_out_fee) {
                    uint256_t l_value_got_fee = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out_fee);
                    assert(EQUAL_256(l_value_got_fee, l_value_transfer_fee));
                    dap_list_free_full(l_list_used_out_fee, free);
                    // add 'out' item for coin fee back
                    uint256_t  l_value_back;
                    SUBTRACT_256_256(l_value_got_fee, l_value_need_fee, &l_value_back);
                    if (!IS_ZERO_256(l_value_back)) {
                        dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_native_token);
                    }
                } else {
                    SUM_256_256(l_value_need, l_value_need_fee, &l_value_need);
                }
                dap_list_free_full(l_list_used_out, free);
                if(!IS_ZERO_256(l_value_got)) {
                    l_items_ready++;

                    // add 'out' item for coin back
                    uint256_t l_value_back;
                    SUBTRACT_256_256(l_value_got, l_value_need, &l_value_back);
                    if(!IS_ZERO_256(l_value_back)) {
                        dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back);
                    }
                }
            }
        }
        // Go to the next 'in' item
        l_list = dap_list_next(l_list);
    }
    dap_list_free(l_in_list);


    
    // Add TSD section
    l_list = l_tsd_list;
    while(l_list) {
        dap_chain_datum_tx_add_item(&l_tx, l_list->data);
        l_items_ready++;
        l_list = dap_list_next(l_list);
    }
    dap_list_free(l_tsd_list);


    // Add signs
    l_list = l_sign_list;
    while(l_list) {

        struct json_object *l_json_item_obj = (struct json_object*) l_list->data;

        dap_enc_key_t * l_enc_key  = NULL;
        
        //get wallet or cert
        dap_chain_wallet_t *l_wallet = s_json_get_wallet(l_json_item_obj, "wallet");
        const dap_cert_t *l_cert = s_json_get_cert(l_json_item_obj, "cert");

        //wallet goes first
        if (l_wallet) {
            l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);

        } else if (l_cert && l_cert->enc_key) {
            l_enc_key = l_cert->enc_key;
        }
        else{
		dap_string_append_printf(l_err_str, "Can't create sign for transactions.\n");
            log_it(L_ERROR, "Json TX: Item sign has no wallet or cert of they are invalid ");
            l_list = dap_list_next(l_list);
            continue;
        }

        if(l_enc_key && dap_chain_datum_tx_add_sign_item(&l_tx, l_enc_key) > 0) {
            l_items_ready++;
        } else {
            log_it(L_ERROR, "Json TX: Item sign has invalid enc_key.");
            l_list = dap_list_next(l_list);
            continue;
        }

        if (l_wallet)
            dap_chain_wallet_close(l_wallet);    

    
        l_list = dap_list_next(l_list);
    }

    dap_list_free(l_sign_list);
    json_object_put(l_json);

    if(l_items_ready<l_items_count) {
        if(!l_items_ready)
            dap_cli_server_cmd_set_reply_text(a_str_reply, "No valid items found to create a transaction");
        else
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create transaction, because only %zu items out of %zu are valid",l_items_ready,l_items_count);
        DAP_DELETE(l_tx);
        return -30;
    }

    // Pack transaction into the datum
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
    DAP_DELETE(l_tx);

    // Add transaction to mempool
    char *l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool_new(l_chain);// get group name for mempool
    char *l_tx_hash_str;
    dap_get_data_hash_str_static(l_datum_tx->data, l_datum_tx->header.data_size, l_tx_hash_str);
    bool l_placed = !dap_global_db_set(l_gdb_group_mempool_base_tx,l_tx_hash_str, l_datum_tx, l_datum_tx_size, false, NULL, NULL);

    DAP_DEL_Z(l_datum_tx);
    DAP_DELETE(l_gdb_group_mempool_base_tx);
    if(!l_placed) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add transaction to mempool");
        return -90;
    }
    // Completed successfully
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Transaction %s with %zu items created and added to mempool successfully", l_tx_hash_str, l_items_ready);
    return l_err_code;
}

/**
 * @brief Create transaction
 * com_tx_create command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_create(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    int arg_index = 1;
//    int cmd_num = 1;
//    const char *value_str = NULL;
    const char *addr_base58_to = NULL;
    const char *str_tmp = NULL;
    const char * l_from_wallet_name = NULL;
    const char * l_wallet_fee_name = NULL;
    const char * l_token_ticker = NULL;
    const char * l_net_name = NULL;
    const char * l_chain_name = NULL;
    const char * l_emission_chain_name = NULL;
    const char * l_tx_num_str = NULL;
    const char *l_emission_hash_str = NULL;
    const char *l_cert_str = NULL;
    dap_cert_t *l_cert = NULL;
    dap_enc_key_t *l_priv_key = NULL;
    dap_chain_hash_fast_t l_emission_hash = {};
    size_t l_tx_num = 0;
    dap_chain_wallet_t * l_wallet_fee = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    dap_chain_net_t * l_net = dap_chain_net_by_name(l_net_name);
    if (l_net == NULL) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not found net by name '%s'", l_net_name);
        return -7;
    }

    uint256_t l_value = {};
    uint256_t l_value_fee = {};
    dap_chain_addr_t *l_addr_to = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_wallet", &l_from_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-wallet_fee", &l_wallet_fee_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_emission", &l_emission_hash_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain_emission", &l_emission_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx_num", &l_tx_num_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_str);

    if(l_tx_num_str)
        l_tx_num = strtoul(l_tx_num_str, NULL, 10);

    // Validator's fee
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &str_tmp))
        l_value_fee = dap_chain_balance_scan(str_tmp);
    if (IS_ZERO_256(l_value_fee) && (!l_emission_hash_str || (str_tmp && strcmp(str_tmp, "0")))) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                "tx_create requires parameter '-fee' to be valid uint256");
        return -5;
    }

    if((!l_from_wallet_name && !l_emission_hash_str)||(l_from_wallet_name && l_emission_hash_str)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_create requires one of parameters '-from_wallet' or '-from_emission'");
        return -1;
    }

    if(!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_create requires parameter '-net'");
        return -6;
    }

    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);

    dap_chain_t *l_emission_chain = NULL;
    if (l_emission_hash_str) {
        if (dap_chain_hash_fast_from_str(l_emission_hash_str, &l_emission_hash)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_create requires parameter '-from_emission' "
                                                         "to be valid string containing hash in hex or base58 format");
            return -3;
        }
        if (l_emission_chain_name) {
            l_emission_chain = dap_chain_net_get_chain_by_name(l_net, l_emission_chain_name);
        } else {
            l_emission_chain = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_EMISSION);
        }
        if (!l_emission_chain) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_create requires parameter '-chain_emission' "
                                                         "to be a valid chain name or set default datum type in chain configuration file");
            return -9;
        }

        if (l_wallet_fee_name){
            l_wallet_fee = dap_chain_wallet_open(l_wallet_fee_name, c_wallets_path);
            if (!l_wallet_fee) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet %s does not exist", l_wallet_fee_name);
                return -12;
            }
            l_priv_key = dap_chain_wallet_get_key(l_wallet_fee, 0);
        } else if (l_cert_str) {
            l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Certificate %s is invalid", l_cert_str);
                return -5;
            }
            l_priv_key = l_cert->enc_key;
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "tx_create requires parameter '-cert' or '-wallet_fee' for create base tx for emission");
            return -10;
        }
    } else {
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_ticker);
        if (!l_token_ticker) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_create requires parameter '-token'");
            return -3;
        }
        if (!dap_ledger_token_ticker_check(l_net->pub.ledger, l_token_ticker)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Ticker '%s' is not declared on network '%s'.",
                                              l_token_ticker, l_net_name);
            return -16;
        }
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_addr", &addr_base58_to);
        if (!addr_base58_to) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_create requires parameter '-to_addr'");
            return -2;
        }
        l_addr_to = dap_chain_addr_from_str(addr_base58_to);
        if(!l_addr_to) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "destination address is invalid");
            return -11;
        }
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &str_tmp))
            l_value = dap_chain_balance_scan(str_tmp);
        if (IS_ZERO_256(l_value)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_create requires parameter '-value' to be valid uint256 value");
            return -4;
        }
    }

    dap_chain_t *l_chain = NULL;
    if (l_chain_name) {
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    } else {
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_TX);
    }

    if(!l_chain) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not found chain name '%s', try use parameter '-chain' or set default datum type in chain configuration file",
                l_chain_name);
        return -8;
    }

    dap_string_t *l_string_ret = dap_string_new(NULL);
    int l_ret = 0;
    if (l_emission_hash_str) {
        char *l_tx_hash_str = NULL;
        if (!l_priv_key) {
            dap_string_append_printf(l_string_ret, "No private key defined for creating the underlying "
                                                   "transaction no '-wallet_fee' or '-cert' parameter specified.");
            l_ret = -10;
        }
        l_tx_hash_str = dap_chain_mempool_base_tx_create(l_chain, &l_emission_hash, l_emission_chain->id,
                                                         uint256_0, NULL, NULL, // Get this params from emission itself
                                                         l_priv_key, l_hash_out_type, l_value_fee);
        if (l_tx_hash_str) {
            dap_string_append_printf(l_string_ret, "\nDatum %s with 256bit TX is placed in datum pool\n", l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
        } else {
            dap_string_append_printf(l_string_ret, "\nCan't place TX datum in mempool, examine log files\n");
            l_ret = -15;
        }
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_string_ret->str);
        dap_string_free(l_string_ret, true);
        DAP_DELETE(l_addr_to);
        if (l_wallet_fee)
            dap_chain_wallet_close(l_wallet_fee);
        return l_ret;        
    }

    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_from_wallet_name, c_wallets_path);

    if(!l_wallet) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "wallet %s does not exist", l_from_wallet_name);
        return -9;
    } else
        dap_string_append(l_string_ret, dap_chain_wallet_check_sign(l_wallet));

    const dap_chain_addr_t *addr_from = (const dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);

    if(!addr_from) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "source address is invalid");
        return -10;
    }

    if (l_addr_to->net_id.uint64 != l_net->pub.id.uint64 && !dap_chain_addr_is_blank(l_addr_to)) {
        bool l_found = false;
        for (dap_list_t *it = l_net->pub.bridged_networks; it; it = it->next) {
            if (((dap_chain_net_id_t *)it->data)->uint64 == l_addr_to->net_id.uint64) {
                l_found = true;
                break;
            }
        }
        if (!l_found) {
            dap_string_t *l_allowed_list = dap_string_new("");
            dap_string_append_printf(l_allowed_list, "0x%016"DAP_UINT64_FORMAT_X, l_net->pub.id.uint64);
            for (dap_list_t *it = l_net->pub.bridged_networks; it; it = it->next)
                dap_string_append_printf(l_allowed_list, ", 0x%016"DAP_UINT64_FORMAT_X, ((dap_chain_net_id_t *)it->data)->uint64);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Destination network ID=0x%"DAP_UINT64_FORMAT_x
                                                           " is unreachable. List of available network IDs:\n%s"
                                                           " Please, change network name or wallet address",
                                              l_addr_to->net_id.uint64, l_allowed_list->str);
            dap_string_free(l_allowed_list, true);
            return -13;
        }
    }

    if(l_tx_num){
        l_ret = dap_chain_mempool_tx_create_massive(l_chain, dap_chain_wallet_get_key(l_wallet, 0), addr_from,
                                                  l_addr_to, l_token_ticker, l_value, l_value_fee, l_tx_num);

        dap_string_append_printf(l_string_ret, "transfer=%s\n",
                (l_ret == 0) ? "Ok" : (l_ret == -2) ? "False, not enough funds for transfer" : "False");
    } else {
        char *l_tx_hash_str = dap_chain_mempool_tx_create(l_chain, dap_chain_wallet_get_key(l_wallet, 0), addr_from, l_addr_to,
                                                                  l_token_ticker, l_value, l_value_fee, l_hash_out_type);
        if (l_tx_hash_str) {
            dap_string_append_printf(l_string_ret, "transfer=Ok\ntx_hash = %s\n",l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
        } else {
            dap_string_append_printf(l_string_ret, "transfer=False\n");
            l_ret = -14;
        }
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_string_ret->str);
    dap_string_free(l_string_ret, true);

    DAP_DELETE(l_addr_to);
    dap_chain_wallet_close(l_wallet);
    return l_ret;
}


/**
 * @brief com_tx_verify
 * Verifing transaction
 * tx_verify command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_verify(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    const char * l_tx_hash_str = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;
    int l_arg_index = 1;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if(!l_tx_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "tx_verify requires parameter '-tx'");
        return -1;
    }
    dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net);
    if (!l_net || !l_chain) {
        return -2;
    } else if (a_str_reply && *a_str_reply) {
        DAP_DELETE(*a_str_reply);
        *a_str_reply = NULL;
    }
    dap_hash_fast_t l_tx_hash;
    char *l_hex_str_from58 = NULL;
    if (dap_chain_hash_fast_from_hex_str(l_tx_hash_str, &l_tx_hash)) {
        l_hex_str_from58 = dap_enc_base58_to_hex_str_from_str(l_tx_hash_str);
        if (dap_chain_hash_fast_from_hex_str(l_hex_str_from58, &l_tx_hash)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid tx hash format, need hex or base58");
            return -3;
        }
    }
    size_t l_tx_size = 0;
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(l_chain);
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)
            dap_global_db_get_sync(l_gdb_group, l_hex_str_from58 ? l_hex_str_from58 : l_tx_hash_str, &l_tx_size, NULL, NULL );
    DAP_DEL_Z(l_hex_str_from58);
    if (!l_tx) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified tx not found");
        return -3;
    }
    int l_ret = dap_ledger_tx_add_check(l_net->pub.ledger, l_tx, l_tx_size, &l_tx_hash);
    if (l_ret) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified tx verify fail with return code=%d", l_ret);
        return -4;
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified tx verified successfully");
    return 0;
}

static const char *s_com_tx_history_decl_err_str[] = {
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR",
    [DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR] = "DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR",
};

char *dap_chain_node_cli_com_tx_history_err(int a_code) {
    return (a_code >= DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK) && (a_code < DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN)
            ? (char*)s_com_tx_history_decl_err_str[(s_com_tx_history_err_t)a_code]
            : dap_itoa(a_code);
}

/**
 * @brief com_tx_history
 * tx_history command
 * Transaction history for an address
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return int
 */
int com_tx_history(int a_argc, char ** a_argv, void ** reply)
{
    json_object ** json_arr_reply = (json_object **) reply;
    int arg_index = 1;
    const char *l_addr_base58 = NULL;
    const char *l_wallet_name = NULL;
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;
    const char *l_tx_hash_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;

    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_base58);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);

    bool l_is_tx_all = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);

    if (!l_addr_base58 && !l_wallet_name && !l_tx_hash_str && !l_is_tx_all) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx_history requires parameter '-addr' or '-w' or '-tx'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    if (!l_net_str && !l_addr_base58&& !l_is_tx_all) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx_history requires parameter '-net' or '-addr'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    dap_chain_hash_fast_t l_tx_hash;
    if (l_tx_hash_str && dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash) < 0) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR, "tx hash not recognized");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR;
    }
    // Select chain network
    if (!l_addr_base58 && l_net_str) {
        l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) { // Can't find such network
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR,
                                    "tx_history requires parameter '-net' to be valid chain network name");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR;
        }
    }
    // Get chain address
    dap_chain_addr_t *l_addr = NULL;
    if (l_addr_base58) {
        if (l_tx_hash_str) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR,
                                                        "Incompatible params '-addr' & '-tx'");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR;
        }
        l_addr = dap_chain_addr_from_str(l_addr_base58);
        if (!l_addr) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR,
                                                        "Wallet address not recognized");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR;
        }
        if (l_net) {
            if (l_net->pub.id.uint64 != l_addr->net_id.uint64) {
                dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR,
                                        "Network ID with '-net' param and network ID with '-addr' param are different");
                DAP_DELETE(l_addr);
                return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR;
            }
        } else
            l_net = dap_chain_net_by_id(l_addr->net_id);
    }
    const char* l_sign_str = "";
    if (l_wallet_name) {
        const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
        if (l_wallet) {
            l_sign_str = dap_chain_wallet_check_sign(l_wallet);
            dap_chain_addr_t *l_addr_tmp = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
            if (l_addr) {
                if (!dap_chain_addr_compare(l_addr, l_addr_tmp)) {
                    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR,
                                            "Address with '-addr' param and address with '-w' param are different");
                    DAP_DELETE(l_addr);
                    DAP_DELETE(l_addr_tmp);
                    return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR;
                }
                DAP_DELETE(l_addr_tmp);
            } else
                l_addr = l_addr_tmp;
            dap_chain_wallet_close(l_wallet);
        } else {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR,
                                    "The wallet %s is not activated or it doesn't exist", l_wallet_name);
            DAP_DELETE(l_addr);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR;
        }
    }
    // Select chain, if any
    if (!l_net) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR, "Could not determine the network from which to "
                                                       "extract data for the tx_history command to work.");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR;
    }
    if (l_chain_str)
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);

    if(!l_chain) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR,
                                "tx_history requires parameter '-chain' to be valid chain name in chain net %s."
                                " You can set default datum type in chain configuration file", l_net_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR;
    }
    // response
    json_object * json_obj_out = NULL;
    if (l_tx_hash_str) {
         // history tx hash
        json_obj_out = dap_db_history_tx(&l_tx_hash, l_chain, l_hash_out_type, l_net);
        if (!json_obj_out) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR,
                                    "something went wrong in tx_history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR;
        }
    } else if (l_addr) {
        // history addr and wallet
        char *l_addr_str = dap_chain_addr_to_str(l_addr);
        json_obj_out = dap_db_history_addr(l_addr, l_chain, l_hash_out_type, l_addr_str);
        if (!json_obj_out) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR,
                                    "something went wrong in tx_history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR;
        }
    } else if (l_is_tx_all) {
        // history all
        json_object * json_obj_summary = json_object_new_object();
        if (!json_obj_summary) {
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR;
        }

        json_object* json_arr_history_all = dap_db_history_tx_all(l_chain, l_net, l_hash_out_type, json_obj_summary);
        if (!json_arr_history_all) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR,
                                    "something went wrong in tx_history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR;
        }

        json_object_array_add(*json_arr_reply, json_arr_history_all);
        json_object_array_add(*json_arr_reply, json_obj_summary);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    }

    if (json_obj_out) {
        json_object_array_add(*json_arr_reply, json_obj_out);
    } else {
        json_object_array_add(*json_arr_reply, json_object_new_string("empty"));
    }

    return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
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
int com_stats(int argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
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
        dap_cli_server_cmd_set_reply_text(a_str_reply, "format of command: stats cpu");
        return -1;
    case CMD_STATS_CPU:
#if (defined DAP_OS_UNIX) || (defined __WIN32)
    {
        dap_cpu_monitor_init();
        dap_usleep(500000);
        char *l_str_reply_prev = DAP_NEW_Z_SIZE(char, 1);
        char *l_str_delimiter;
        dap_cpu_stats_t s_cpu_stats = dap_cpu_get_stats();
        for (uint32_t n_cpu_num = 0; n_cpu_num < s_cpu_stats.cpu_cores_count; n_cpu_num++) {
            if ((n_cpu_num % 4 == 0) && (n_cpu_num != 0)) {
                l_str_delimiter = dap_strdup_printf("\n");
            } else if (n_cpu_num == s_cpu_stats.cpu_cores_count - 1) {
                l_str_delimiter = DAP_NEW_Z_SIZE(char, 1);
            } else {
                l_str_delimiter = dap_strdup_printf(" ");
            }
            *a_str_reply = dap_strdup_printf("%sCPU-%d: %f%%%s", l_str_reply_prev, n_cpu_num, s_cpu_stats.cpus[n_cpu_num].load, l_str_delimiter);
            DAP_DELETE(l_str_reply_prev);
            DAP_DELETE(l_str_delimiter);
            l_str_reply_prev = *a_str_reply;
        }
        *a_str_reply = dap_strdup_printf("%s\nTotal: %f%%", l_str_reply_prev, s_cpu_stats.cpu_summary.load);
        DAP_DELETE(l_str_reply_prev);
        break;
    }
#else
        dap_cli_server_cmd_set_reply_text(a_str_reply, "only Linux or Windows environment supported");
        return -1;
#endif // DAP_OS_UNIX
    }
    return 0;
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
int com_exit(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    UNUSED(a_argc);
    UNUSED(a_argv);
    UNUSED(a_str_reply);
    //dap_events_stop_all();
    exit(0);
    return 0;
}


/**
 * @brief com_print_log Print log info
 * print_log [ts_after <timestamp >] [limit <line numbers>]
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_print_log(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    int arg_index = 1;
    const char * l_str_ts_after = NULL;
    const char * l_str_limit = NULL;
    int64_t l_ts_after = 0;
    long l_limit = 0;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "ts_after", &l_str_ts_after);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "limit", &l_str_limit);

    l_ts_after = (l_str_ts_after) ? strtoll(l_str_ts_after, 0, 10) : -1;
    l_limit = (l_str_limit) ? strtol(l_str_limit, 0, 10) : -1;

    if(l_ts_after < 0 || !l_str_ts_after) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "requires valid parameter 'l_ts_after'");
        return -1;
    }
    if(l_limit <= 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "requires valid parameter 'limit'");
        return -1;
    }

    // get logs from list
    char *l_str_ret = dap_log_get_item(l_ts_after, (int) l_limit);
    if(!l_str_ret) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "no logs");
        return -1;
    }
    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_ret);
    DAP_DELETE(l_str_ret);
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
int cmd_gdb_export(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
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
    char l_path[dap_min(strlen(l_gdb_path) + strlen(l_filename) + 12, (size_t)MAX_PATH)];
    memset(l_path, '\0', sizeof(l_path));
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
        pdap_store_obj_t l_store_obj = dap_global_db_get_all_raw_sync(l_group_name,0, &l_store_obj_count);
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
            char *l_value_enc_str = DAP_NEW_Z_SIZE(char, l_out_size);
            if(!l_value_enc_str) {
                log_it(L_CRITICAL, "Memory allocation error");
                return -1;
            }
            dap_enc_base64_encode(l_store_obj[i].value, l_store_obj[i].value_len, l_value_enc_str, DAP_ENC_DATA_TYPE_B64);
            struct json_object *jobj = json_object_new_object();
            json_object_object_add(jobj, "id",      json_object_new_int64((int64_t)l_store_obj[i].id));
            json_object_object_add(jobj, "key",     json_object_new_string(l_store_obj[i].key));
            json_object_object_add(jobj, "value",   json_object_new_string(l_value_enc_str));
            json_object_object_add(jobj, "value_len", json_object_new_int64((int64_t)l_store_obj[i].value_len));
            json_object_object_add(jobj, "timestamp", json_object_new_int64((int64_t)l_store_obj[i].timestamp));
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
int cmd_gdb_import(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
    int arg_index = 1;
    const char *l_filename = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "filename", &l_filename);
    if (!l_filename) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "gdb_import requires parameter 'filename'");
        return -1;
    }
    const char *l_gdb_path = dap_config_get_item_str(g_config, "global_db", "path");
    if (!l_gdb_path) {
        log_it(L_ERROR, "Can't find gdb path in config file");
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find gdb path in the config file");
        return -1;
    }
    char l_path[strlen(l_gdb_path) + strlen(l_filename) + 12];
    memset(l_path, '\0', sizeof(l_path));
    snprintf(l_path, sizeof(l_path), "%s/%s.json", l_gdb_path, l_filename);
    struct json_object *l_json = json_object_from_file(l_path);
    if (!l_json) {
#if JSON_C_MINOR_VERSION<15
        log_it(L_CRITICAL, "Import error occured: code %d", errno);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Import error occured: code %d",errno);
#else
        log_it(L_CRITICAL, "Import error occured: %s", json_util_get_last_err());
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", json_util_get_last_err());
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
        pdap_store_obj_t l_group_store = DAP_NEW_Z_SIZE(dap_store_obj_t, l_records_count * sizeof(dap_store_obj_t));
        if(!l_group_store) {
            log_it(L_CRITICAL, "Memory allocation error");
            return -1;
        }
        for (size_t j = 0; j < l_records_count; ++j) {
            struct json_object *l_record, *l_id, *l_key, *l_value, *l_value_len, *l_ts;
            l_record = json_object_array_get_idx(l_json_records, j);
            l_id        = json_object_object_get(l_record, "id");
            l_key       = json_object_object_get(l_record, "key");
            l_value     = json_object_object_get(l_record, "value");
            l_value_len = json_object_object_get(l_record, "value_len");
            l_ts        = json_object_object_get(l_record, "timestamp");
            //
            l_group_store[j].id     = (uint64_t)json_object_get_int64(l_id);
            l_group_store[j].key    = dap_strdup(json_object_get_string(l_key));
            l_group_store[j].group  = dap_strdup(l_group_name);
            dap_nanotime_t l_temp = json_object_get_int64(l_ts);
            l_group_store[j].timestamp = l_temp >> 32 ? l_temp : l_temp << 32; // possibly legacy record
            l_group_store[j].value_len = (uint64_t)json_object_get_int64(l_value_len);
            l_group_store[j].type   = 'a';
            const char *l_value_str = json_object_get_string(l_value);
            char *l_val = DAP_NEW_Z_SIZE(char, l_group_store[j].value_len);
            if(!l_val) {
                log_it(L_CRITICAL, "Memory allocation error");
                l_records_count = j;
                break;
            }
            dap_enc_base64_decode(l_value_str, strlen(l_value_str), l_val, DAP_ENC_DATA_TYPE_B64);
            l_group_store[j].value  = (uint8_t*)l_val;
        }
        if (dap_global_db_driver_apply(l_group_store, l_records_count)) {
            log_it(L_CRITICAL, "An error occured on importing group %s...", l_group_name);
        } else {
            log_it(L_INFO, "Imported %zu records of group %s", l_records_count, l_group_name);
        }
        //dap_store_obj_free(l_group_store, l_records_count);
    }
    json_object_put(l_json);
    return 0;
}

dap_list_t *s_go_all_nets_offline()
{
    dap_list_t *l_net_returns = NULL;
    uint16_t l_net_count;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {    // Shutdown all networks
        if (dap_chain_net_stop(l_net_list[i]))
            l_net_returns = dap_list_append(l_net_returns, l_net_list[i]);
    }
    sleep(2);   // waiting for networks to go offline
    return l_net_returns;
}

typedef struct _pvt_net_aliases_list{
    dap_chain_net_t *net;
    dap_global_db_obj_t *group_aliases;
    size_t count_aliases;
    dap_global_db_obj_t *group_nodes;
    size_t count_nodes;
}_pvt_net_aliases_list_t;

int cmd_remove(int a_argc, char **a_argv, void ** reply)
{
    char ** a_str_reply = (char **) reply;
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
        uint16_t l_net_count;
        dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
        dap_list_t *l_gdb_aliases_list = NULL;
        for (uint16_t i = 0; i < l_net_count; i++) {
            size_t l_aliases_count = 0;
            _pvt_net_aliases_list_t *l_gdb_groups = DAP_NEW(_pvt_net_aliases_list_t);
            if (!l_gdb_groups) {
                log_it(L_CRITICAL, "Memory allocation error");
                dap_list_free(l_net_returns);
                return -1;
            }
            l_gdb_groups->net = l_net_list[i];
            l_gdb_groups->group_aliases = dap_global_db_get_all_sync(l_gdb_groups->net->pub.gdb_nodes_aliases, &l_gdb_groups->count_aliases);
            l_gdb_groups->group_nodes = dap_global_db_get_all_sync(l_gdb_groups->net->pub.gdb_nodes, &l_gdb_groups->count_nodes);
            l_gdb_aliases_list = dap_list_append(l_gdb_aliases_list, l_gdb_groups);
        }
        dap_global_db_deinit();
        const char *l_gdb_driver = dap_config_get_item_str_default(g_config, "global_db", "driver", "mdbx");
        char *l_gdb_rm_path = dap_strdup_printf("%s/gdb-%s", l_gdb_path, l_gdb_driver);
        dap_rm_rf(l_gdb_rm_path);
        DAP_DELETE(l_gdb_rm_path);
        dap_global_db_init(l_gdb_path, l_gdb_driver);
        for (dap_list_t *ptr = l_gdb_aliases_list; ptr; ptr = dap_list_next(ptr)) {
            _pvt_net_aliases_list_t *l_tmp = (_pvt_net_aliases_list_t*)ptr->data;
            for (size_t i = 0; i < l_tmp->count_aliases; i++) {
                dap_global_db_obj_t l_obj = l_tmp->group_aliases[i];
                dap_global_db_set_sync(l_tmp->net->pub.gdb_nodes_aliases, l_obj.key, l_obj.value, l_obj.value_len, false);
            }
            dap_global_db_objs_delete(l_tmp->group_aliases, l_tmp->count_aliases);
            for (size_t i = 0; i < l_tmp->count_nodes; i++) {
                dap_global_db_obj_t l_obj = l_tmp->group_nodes[i];
                dap_global_db_set_sync(l_tmp->net->pub.gdb_nodes, l_obj.key, l_obj.value, l_obj.value_len, false);
            }
            dap_global_db_objs_delete(l_tmp->group_nodes, l_tmp->count_nodes);
        }
        dap_list_free_full(l_gdb_aliases_list, NULL);
        if (!error)
            successful |= REMOVED_GDB;
    }

    if (dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "-chains") != -1) {
        dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-net", &l_net_str);
        all = dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "-all");

        if	(NULL == l_net_str && all >= 0) {
            if (NULL == l_gdb_path)
                l_net_returns = s_go_all_nets_offline();
            uint16_t l_net_count;
            dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
            for (uint16_t i = 0; i < l_net_count; i++) {
                s_dap_chain_net_purge(l_net_list[i]);
            }
            if (!error)
                successful |= REMOVED_CHAINS;

        } else if	(NULL != l_net_str && all < 0) {
            if (NULL != (l_net = dap_chain_net_by_name(l_net_str))) {
                if (NULL == l_gdb_path && dap_chain_net_stop(l_net))
                    l_net_returns = dap_list_append(l_net_returns, l_net);
            } else {
                error |= NET_NOT_VALID;
            }
            s_dap_chain_net_purge(l_net);
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

    if (error) {
       dap_cli_server_cmd_set_reply_text(a_str_reply, "Error when deleting, because:\n%s", return_message);
    }
    else if (successful) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Successful removal: %s %s", successful & REMOVED_GDB ? "gdb" : "-", successful & REMOVED_CHAINS ? "chains" : "-");
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Nothing to delete. Check if the command is correct.\nUse flags: -gdb or/and -chains [-net <net_name> | -all]\n"
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
static int s_signer_cmd(int a_arg_index, int a_argc, char **a_argv, char **a_str_reply);
static int s_check_cmd(int a_arg_index, int a_argc, char **a_argv, char **a_str_reply);
struct opts {
    char *name;
    uint32_t cmd;
};

#define BUILD_BUG(condition) ((void)sizeof(char[1-2*!!(condition)]))

int com_signer(int a_argc, char **a_argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
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

static int s_check_cmd(int a_arg_index, int a_argc, char **a_argv, char **a_str_reply)
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

    l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(l_chain);
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
        l_ret = s_get_key_from_file(l_str_opts_check[OPT_FILE], l_str_opts_check[OPT_MIME], l_str_opts_check[OPT_CERT], &l_sign);
        if (!l_ret) {
            l_ret = -1;
            goto end;
        }

        l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_SIGNER, l_sign->pkey_n_sign, l_sign->header.sign_size);
        if (!l_datum) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "not created datum");
            l_ret = -1;
            goto end;
        }

        dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_hash_tmp);
    }

    dap_chain_atom_iter_t *l_iter = NULL;
    dap_chain_cell_t *l_cell_tmp = NULL;
    dap_chain_cell_t *l_cell = NULL;
    size_t l_atom_size = 0, l_datums_count = 0;

    HASH_ITER(hh, l_chain->cells, l_cell, l_cell_tmp) {
        l_iter = l_cell->chain->callback_atom_iter_create(l_cell->chain, l_cell->id, 0);
        dap_chain_atom_ptr_t l_atom = l_cell->chain->callback_atom_find_by_hash(l_iter, &l_hash_tmp, &l_atom_size);
        dap_chain_datum_t **l_datums = l_cell->chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
        for (size_t i = 0; i < l_datums_count; i++) {
            dap_chain_datum_t *l_datum = l_datums[i];
            dap_hash_fast_t l_hash;
            dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_hash);
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

    return 0;
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



    if (a_mime) {
        l_items_mime = s_parse_items(a_mime, ',', &l_items_mime_count, 0);
    }

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

        /* free l_items_mime */
        for (int i = 0; i < l_items_mime_count; i++) {
            if (l_items_mime[i]) DAP_DELETE(l_items_mime[i]);
        }
        DAP_DELETE(l_items_mime);
        l_items_mime_count = 0;
    }
    if (l_flags_mime == 0) l_flags_mime = SIGNER_ALL_FLAGS;

    dap_chain_hash_fast_t l_hash;


    int l_ret = s_sign_file(a_file, l_flags_mime, a_cert_name, a_sign, &l_hash);

    if (l_items_mime)
        DAP_DELETE(l_items_mime);
    return l_ret;
}

static int s_signer_cmd(int a_arg_index, int a_argc, char **a_argv, char **a_str_reply)
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

    if (!l_opts_sign[OPT_CERT]) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s need to be selected", l_opts_signer[OPT_CERT].name);
        return -1;
    }

    dap_chain_net_t *l_network = dap_chain_net_by_name(l_opts_sign[OPT_NET]);
    if (!l_network) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s network not found", l_opts_sign[OPT_NET]);
        return -1;
    }

    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_network, l_opts_sign[OPT_CHAIN]);
    if (!l_chain) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s chain not found", l_opts_sign[OPT_CHAIN]);
        return -1;
    }

    int l_ret = 0;
    dap_sign_t *l_sign = NULL;
    dap_chain_datum_t *l_datum = NULL;

    l_ret = s_get_key_from_file(l_opts_sign[OPT_FILE], l_opts_sign[OPT_MIME], l_opts_sign[OPT_CERT], &l_sign);
    if (!l_ret) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s cert not found", l_opts_sign[OPT_CERT]);
        return -1;
    }

    l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_SIGNER, l_sign->pkey_n_sign, l_sign->header.sign_size);
    if (!l_datum) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "not created datum");
        return -1;
    }

    l_ret = l_chain->callback_add_datums(l_chain, &l_datum, 1);

    char *l_key_str;
    dap_get_data_hash_str_static(l_datum->data, l_datum->header.data_size, l_key_str);
    dap_cli_server_cmd_set_reply_text(a_str_reply, "hash: %s", l_key_str);
    DAP_DELETE(l_datum);
    return l_ret;
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
    uint32_t l_shift = 1;
    int l_count_meta = 0;
    int l_index_meta = 0;
    char *l_buffer = NULL;

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

    size_t l_file_content_size;
    if (!dap_file_get_contents(a_filename, &l_buffer, &l_file_content_size)) return 0;

    l_shift = 1;
    dap_list_t *l_std_list = NULL;


    for (int i = 0; i < l_count_meta; i++) {
        if (l_shift | a_flags) {
            dap_tsd_t *l_item = s_alloc_metadata(a_filename, l_shift & a_flags);
            if (l_item) {
                l_std_list = dap_list_append(l_std_list, l_item);
                l_index_meta++;
            }
        }
        l_shift <<= 1;
    }

    dap_cert_t *l_cert = dap_cert_find_by_name(a_cert_name);
    if (!l_cert) {
        DAP_DELETE(l_buffer);
        return 0;
    }

    if (!dap_hash_fast(l_buffer, l_file_content_size, a_hash)) {
        DAP_DELETE(l_buffer);
        return 0;
    }

    size_t l_full_size_for_sign;
    uint8_t *l_data = s_concat_hash_and_mimetypes(a_hash, l_std_list, &l_full_size_for_sign);
    if (!l_data) {
        DAP_DELETE(l_buffer);
        return 0;
    }
    *a_signed = dap_sign_create(l_cert->enc_key, l_data, l_full_size_for_sign, 0);
    if (*a_signed == NULL) {
        DAP_DELETE(l_buffer);
        return 0;
    }

    DAP_DELETE(l_buffer);
    return 1;
}

static byte_t *s_concat_meta (dap_list_t *a_meta, size_t *a_fullsize)
{
    if (a_fullsize)
        *a_fullsize = 0;

    int l_part = 256;
    int l_power = 1;
    byte_t *l_buf = DAP_CALLOC(l_part * l_power++, 1);
    if (!l_buf) {
        log_it(L_CRITICAL, "Memory allocation error");
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
            l_buf = (byte_t *) DAP_REALLOC(l_buf, l_part_power);
            if (!l_buf) {
                log_it(L_CRITICAL, "Memory allocation error");
                return NULL;
            }
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
    if (!l_buf) return (uint8_t *) l_buf;

    size_t l_len_meta_buf = *a_fullsize;
    *a_fullsize += sizeof (a_chain_hash->raw) + 1;
    uint8_t *l_fullbuf = DAP_CALLOC(*a_fullsize, 1);
    if (!l_fullbuf) {
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_buf);
        return NULL;
    }
    uint8_t *l_s = l_fullbuf;

    memcpy(l_s, a_chain_hash->raw, sizeof(a_chain_hash->raw));
    l_s += sizeof (a_chain_hash->raw);
    memcpy(l_s, l_buf, l_len_meta_buf);
    DAP_DELETE(l_buf);

    return l_fullbuf;
}


static char *s_strdup_by_index (const char *a_file, const int a_index)
{
    char *l_buf = DAP_CALLOC(a_index + 1, 1);
    if (!l_buf) {
        log_it(L_CRITICAL, "Memory allocation error");
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
                char l_size[513];
                snprintf(l_size, 513, "%ld", l_st.st_size);
                return dap_tsd_create_string(SIGNER_FILESIZE, l_size);
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
                magic_t l_magic = magic_open(MAGIC_MIME);
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
                return l_ret;

            }
            break;
        #endif
        default:
            return NULL;
    }
    return NULL;
}


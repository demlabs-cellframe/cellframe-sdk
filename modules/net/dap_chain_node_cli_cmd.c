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

#include "iputils/iputils.h"

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
#include "dap_chain_node.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_remote.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_chain_node_ping.h"
#include "dap_chain_net_srv.h"
#ifndef _WIN32
#include "dap_chain_net_news.h"
#endif
#include "dap_chain_cell.h"


#include "dap_enc_base64.h"
#include <json-c/json.h>
#ifdef DAP_OS_UNIX
#include <dirent.h>
#endif

#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_enc_base64.h"

#define LOG_TAG "chain_node_cli_cmd"


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
    l_addr = (dap_chain_node_addr_t*) (void*) dap_chain_global_db_gr_get(a_key, &l_addr_size,
            a_net->pub.gdb_nodes_aliases);
    if(l_addr_size != sizeof(dap_chain_node_addr_t)) {
        DAP_DELETE(l_addr);
        l_addr = NULL;
    }
//    DAP_DELETE(addr_str);
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
    dap_global_db_obj_t *objs = dap_chain_global_db_gr_load(l_net->pub.gdb_nodes_aliases, &data_size);
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
    dap_chain_global_db_objs_delete(objs, data_size);
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
    dap_chain_node_addr_t *l_address = NULL;
    if(a_alias_str && !a_addr->uint64) {
        l_address = dap_chain_node_addr_get_by_alias(a_net, a_alias_str);
    }
    if(a_addr->uint64) {
        l_address = DAP_NEW(dap_chain_node_addr_t);
        l_address->uint64 = a_addr->uint64;
    }
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
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't calculate hash of addr");
        return NULL;
    }
    size_t node_info_size = 0;
    dap_chain_node_info_t *node_info;
    // read node
    node_info = (dap_chain_node_info_t *) dap_chain_global_db_gr_get(l_key, &node_info_size, a_net->pub.gdb_nodes);

    if(!node_info) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "node not found in base");
        DAP_DELETE(l_key);
        return NULL;
    }
    /* if(!node_info->hdr.ext_port)
        node_info->hdr.ext_port = 8079; */
    size_t node_info_size_must_be = dap_chain_node_info_get_size(node_info);
    if(node_info_size_must_be != node_info_size) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "node has bad size in base=%u (must be %u)", node_info_size,
                node_info_size_must_be);
        DAP_DELETE(node_info);
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
static bool node_info_save_and_reply(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info, char **str_reply)
{
    if(!a_node_info || !a_node_info->hdr.address.uint64) {
        dap_chain_node_cli_set_reply_text(str_reply, "node addr not found");
        return false;
    }
    char *a_key = dap_chain_node_addr_to_hash_str(&a_node_info->hdr.address);
    if(!a_key)
    {
        dap_chain_node_cli_set_reply_text(str_reply, "can't calculate hash for addr");
        return NULL;
    }
    //char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    size_t l_node_info_size = dap_chain_node_info_get_size(a_node_info);
    //dap_chain_node_info_t *l_node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, l_node_info_size);
    //memcpy(l_node_info, a_node_info, l_node_info_size );

    //size_t data_len_out = 0;
    //dap_chain_node_info_t *a_node_info1 = dap_chain_global_db_gr_get(a_key, &data_len_out, a_net->pub.gdb_nodes);

    bool res = dap_chain_global_db_gr_set(a_key, (uint8_t *) a_node_info, l_node_info_size, a_net->pub.gdb_nodes);

    //data_len_out = 0;
    //dap_chain_node_info_t *a_node_info2 = dap_chain_global_db_gr_get(a_key, &data_len_out, a_net->pub.gdb_nodes);
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
        dap_chain_node_cli_set_reply_text(a_str_reply, "not found -addr parameter");
        return -1;
    }
    if(!a_cell_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "not found -cell parameter");
        return -1;
    }
    if(a_ipv4_str)
        inet_pton(AF_INET, a_ipv4_str, &(a_node_info->hdr.ext_addr_v4));
    if(a_ipv6_str)
        inet_pton(AF_INET6, a_ipv6_str, &(a_node_info->hdr.ext_addr_v6));

    // check match addr to cell or no
    /*dap_chain_node_addr_t *addr = dap_chain_node_gen_addr(&node_info->hdr.cell_id);
     if(!dap_chain_node_check_addr(&node_info->hdr.address, &node_info->hdr.cell_id)) {
     set_reply_text(str_reply, "cell does not match addr");
     return -1;
     }*/
    if(a_alias_str) {
        // add alias
        if(!dap_chain_node_alias_register(a_net, a_alias_str, &a_node_info->hdr.address)) {
            log_it(L_WARNING, "can't save alias %s", a_alias_str);
            dap_chain_node_cli_set_reply_text(a_str_reply, "alias '%s' can't be mapped to addr=0x%lld",
                    a_alias_str, a_node_info->hdr.address.uint64);
            return -1;
        }
    }

    // write to base
    bool res = node_info_save_and_reply(a_net, a_node_info, a_str_reply);
    if(res)
        dap_chain_node_cli_set_reply_text(a_str_reply, "node added");
    else
        return -1;
    if(res)
        return 0;
    return -1;
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
        char **str_reply)
{
    if(!a_node_info->hdr.address.uint64 && !alias_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "addr not found");
        return -1;
    }
    // check, current node have this addr or no
    uint64_t l_cur_addr = dap_db_get_cur_node_addr(a_net->pub.name);
    if(l_cur_addr && l_cur_addr == a_node_info->hdr.address.uint64) {
        dap_chain_node_cli_set_reply_text(str_reply, "current node cannot be deleted");
        return -1;
    }

    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = s_node_info_get_addr(a_net, &a_node_info->hdr.address, alias_str);
    if(!address) {
        dap_chain_node_cli_set_reply_text(str_reply, "alias not found");
        return -1;
    }
    char *a_key = dap_chain_node_addr_to_hash_str(address);
    if(a_key)
    {
        // delete node
        bool res = dap_chain_global_db_gr_del(dap_strdup(a_key), a_net->pub.gdb_nodes);
        if(res) {
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
                dap_list_free_full(list_aliases, (dap_callback_destroyed_t) free);
            }
            // set text response
            dap_chain_node_cli_set_reply_text(str_reply, "node deleted");
        }
        else
            dap_chain_node_cli_set_reply_text(str_reply, "node not deleted");
        DAP_DELETE(a_key);
        DAP_DELETE(address);
        if(res)
            return 0;
        return -1;
    }
    dap_chain_node_cli_set_reply_text(str_reply, "addr to delete can't be defined");
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
        dap_chain_node_cli_set_reply_text(a_str_reply, "addr not found");
        return -1;
    }
    if(!link->uint64) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "link not found");
        return -1;
    }
    // TODO check the presence of link in the node base
#ifdef DAP_CHAIN_NODE_CHECK_PRESENSE
        dap_chain_node_cli_set_reply_text(a_str_reply, "node 0x%016llx not found in base", link->uint64);
        return -1;
#endif

    // find addr by alias or addr_str
    dap_chain_node_addr_t *l_address = s_node_info_get_addr(a_net, &a_node_info->hdr.address, a_alias_str);
    if(!l_address) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "alias not found");
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
            memcpy(&(l_node_info_read->links[l_node_info_read->hdr.links_number-1]), link, sizeof(dap_chain_node_addr_t));
            res_successful = true;
        }
    }
    // delete link
    else if(cmd_int == 2) {
        // move link list to one item prev
        if(index_link >= 0) {
            for(unsigned int j = (unsigned int) index_link; j < (l_node_info_read->hdr.links_number - 1); j++) {
                memcpy(&(l_node_info_read->links[j]), &(l_node_info_read->links[j + 1]), sizeof(dap_chain_node_addr_t));
            }
            l_node_info_read->hdr.links_number--;
            res_successful = true;
            l_node_info_read = DAP_REALLOC(l_node_info_read, l_node_info_read_size -= sizeof(*link));
        }
    }
    // save edited node_info
    if(res_successful) {
        bool res = node_info_save_and_reply(a_net, l_node_info_read, a_str_reply);
        if(res) {
            res_successful = true;
            if(cmd_int == 1)
                dap_chain_node_cli_set_reply_text(a_str_reply, "link added");
            if(cmd_int == 2)
                dap_chain_node_cli_set_reply_text(a_str_reply, "link deleted");
        }
        else {
            res_successful = false;
        }
    }
    else {
        if(cmd_int == 1) {
            if(index_link >= 0)
                dap_chain_node_cli_set_reply_text(a_str_reply, "link not added because it is already present");
            else
                dap_chain_node_cli_set_reply_text(a_str_reply, "link not added");
        }
        if(cmd_int == 2) {
            if(index_link == -1)
                dap_chain_node_cli_set_reply_text(a_str_reply, "link not deleted because not found");
            else
                dap_chain_node_cli_set_reply_text(a_str_reply, "link not deleted");
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
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 * @param a_net 
 * @param a_addr 
 * @param a_is_full 
 * @param a_alias 
 * @param a_str_reply 
 * @return int 
 */
static int node_info_dump_with_reply(dap_chain_net_t * a_net, dap_chain_node_addr_t * a_addr, bool a_is_full,
        const char *a_alias, char **a_str_reply)
{
    int l_ret = 0;
    dap_string_t *l_string_reply = dap_string_new("Node dump:");

    if((a_addr && a_addr->uint64) || a_alias) {
        dap_chain_node_addr_t *l_addr = NULL;
        if(a_addr && a_addr->uint64) {
            l_addr = DAP_NEW(dap_chain_node_addr_t);
            l_addr->uint64 = a_addr->uint64;
        } else if(a_alias) {
            l_addr = dap_chain_node_alias_find(a_net, a_alias);
        }
        if(!l_addr) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "addr not valid");
            dap_string_free(l_string_reply, true);
            return -1;
        }
        // read node
        dap_chain_node_info_t *node_info_read = node_info_read_and_reply(a_net, l_addr, a_str_reply);
        if(!node_info_read) {
            DAP_DELETE(l_addr);
            dap_string_free(l_string_reply, true);
            return -2;
        }

        // get aliases in form of string
        dap_string_t *aliases_string = dap_string_new(NULL);
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
            dap_list_free_full(list_aliases, (dap_callback_destroyed_t) free);
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
        DAP_DELETE(node_info_read);

    } else { // Dump list with !a_addr && !a_alias
        dap_global_db_obj_t *l_objs = NULL;
        size_t l_nodes_count = 0;
        dap_string_append(l_string_reply, "\n");
        // read all node
        l_objs = dap_chain_global_db_gr_load(a_net->pub.gdb_nodes, &l_nodes_count);

        if(!l_nodes_count || !l_objs) {
            dap_string_append_printf(l_string_reply, "No records\n");
            dap_chain_node_cli_set_reply_text(a_str_reply, l_string_reply->str);
            dap_string_free(l_string_reply, true);
            dap_chain_global_db_objs_delete(l_objs, l_nodes_count);
            return -1;
        } else {
            dap_string_append_printf(l_string_reply, "Got %zu records:\n", l_nodes_count);
            for(size_t i = 0; i < l_nodes_count; i++) {
                dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t *) l_objs[i].value;
                // read node
                dap_chain_node_info_t *node_info_read = node_info_read_and_reply(a_net, &l_node_info->hdr.address, NULL);
                if (!node_info_read)
                    continue;
                const int hostlen = 128;
                char *host4 = (char*) alloca(hostlen);
                char *host6 = (char*) alloca(hostlen);
                struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = node_info_read->hdr.ext_addr_v4 };
                const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4, hostlen);

                struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = node_info_read->hdr.ext_addr_v6 };
                const char* str_ip6 = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), host6, hostlen);

                // get aliases in form of string
                dap_string_t *aliases_string = dap_string_new(NULL);
                dap_list_t *list_aliases = get_aliases_by_name(a_net, &node_info_read->hdr.address);
                if(list_aliases)
                {
                    dap_list_t *list = list_aliases;
                    while(list)
                    {
                        const char *alias = (const char *) list->data;
                        dap_string_append_printf(aliases_string, "\nalias %s", alias);
                        list = dap_list_next(list);
                    }
                    dap_list_free_full(list_aliases, (dap_callback_destroyed_t) free);
                }
                else
                    dap_string_append(aliases_string, "\nno aliases");

                // get links in form of string
                dap_string_t *links_string = dap_string_new(NULL);
                for(unsigned int i = 0; i < node_info_read->hdr.links_number; i++) {
                    dap_chain_node_addr_t link_addr = node_info_read->links[i];
                    dap_string_append_printf(links_string, "\nlink%02d address : " NODE_ADDR_FP_STR, i,
                            NODE_ADDR_FP_ARGS_S(link_addr));
                }

                if(i)
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
                DAP_DELETE(node_info_read);
            }
        }
        dap_chain_global_db_objs_delete(l_objs, l_nodes_count);
    }
    dap_chain_node_cli_set_reply_text(a_str_reply, l_string_reply->str);
    dap_string_free(l_string_reply, true);
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
int com_global_db(int a_argc, char ** a_argv, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_NAME_CELL, CMD_ADD, CMD_FLUSH
    };
    int arg_index = 1;
    int cmd_name = CMD_NONE;
    // find 'cells' as first parameter only
    if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "cells", NULL))
        cmd_name = CMD_NAME_CELL;
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "flush", NULL))
        cmd_name = CMD_FLUSH;
    switch (cmd_name) {
    case CMD_NAME_CELL:
    {
        if(!arg_index || a_argc < 3) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "parameters are not valid");
            return -1;
        }
        dap_chain_t * l_chain = NULL;
        dap_chain_net_t * l_net = NULL;

        if(dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net) < 0)
            return -11;

        const char *l_cell_str = NULL, *l_chain_str = NULL;
        // find cell and chain
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-cell", &l_cell_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

        // Check for chain
        if(!l_chain_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "%s requires parameter 'chain' to be valid");
            return -12;
        }

        int arg_index_n = ++arg_index;
        // find command (add, delete, etc) as second parameter only
        int cmd_num = CMD_NONE;
        switch (cmd_name) {
            case CMD_NAME_CELL:
                if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "add", NULL))
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
                        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameters");
                        return -1;
                    }
                    dap_chain_cell_t *l_cell = dap_chain_cell_create_fill(l_chain, l_cell_id);
                    int l_ret = dap_chain_cell_file_update(l_cell);
                    if(l_ret > 0)
                        dap_chain_node_cli_set_reply_text(a_str_reply, "cell added successfully");
                    else
                        dap_chain_node_cli_set_reply_text(a_str_reply, "can't create file for cell 0x%016X ( %s )",
                                l_cell->id.uint64,l_cell->file_storage_path);
                    dap_chain_cell_close(l_cell);
                    return l_ret;

                //case CMD_NONE:
                default:
                    dap_chain_node_cli_set_reply_text(a_str_reply, "command %s not recognized", a_argv[1]);
                    return -1;
                }
        }
    }
    case CMD_FLUSH:
    {
        int res_flush = dap_chain_global_db_flush();
        switch (res_flush) {
        case 0:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Commit data base and filesystem caches to disk completed.\n\n");
            break;
        case -1:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Couldn't open db directory. Can't init cdb\n"
                                                           "Reboot the node.\n\n");
            break;
        case -2:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't init cdb\n"
                                                           "Reboot the node.\n\n");
            break;
        case -3:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't init sqlite\n"
                                                           "Reboot the node.\n\n");
            break;
        default:
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't commit data base caches to disk completed.\n"
                                                           "Reboot the node.\n\n");
            break;
        }
        return 0;
    }
    default:
        dap_chain_node_cli_set_reply_text(a_str_reply, "parameters are not valid");
        return -1;
    }
    return  -555;
}

/**
 * Node command
 */
int com_node(int a_argc, char ** a_argv, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_ADD, CMD_DEL, CMD_LINK, CMD_ALIAS, CMD_HANDSHAKE, CMD_CONNECT, CMD_DUMP
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "add", NULL)) {
        cmd_num = CMD_ADD;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "del", NULL)) {
        cmd_num = CMD_DEL;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "link", NULL)) {
        cmd_num = CMD_LINK;
    }
    else
    // find  add parameter ('alias' or 'handshake')
    if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "handshake", NULL)) {
        cmd_num = CMD_HANDSHAKE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "connect", NULL)) {
        cmd_num = CMD_CONNECT;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "alias", NULL)) {
        cmd_num = CMD_ALIAS;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "dump", NULL)) {
        cmd_num = CMD_DUMP;
    }
    arg_index++;
    if(cmd_num == CMD_NONE) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "command %s not recognized", a_argv[1]);
        return -1;
    }
    const char *l_addr_str = NULL, *l_port_str = NULL, *alias_str = NULL;
    const char *l_cell_str = NULL, *l_link_str = NULL, *a_ipv4_str = NULL, *a_ipv6_str = NULL;

    // find net
    dap_chain_net_t *l_net = NULL;

    if(dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, NULL, &l_net) < 0)
        return -11;

    // find addr, alias
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-port", &l_port_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-alias", &alias_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-cell", &l_cell_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-ipv4", &a_ipv4_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-ipv6", &a_ipv6_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-link", &l_link_str);

    // struct to write to the global db
    dap_chain_node_addr_t l_node_addr = { 0 };
    dap_chain_node_addr_t l_link = { 0 };
    dap_chain_node_info_t *l_node_info = NULL;
    size_t l_node_info_size = sizeof(l_node_info->hdr) + sizeof(l_link);
    if(cmd_num >= CMD_ADD && cmd_num <= CMD_LINK)
        l_node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, l_node_info_size);

    if(l_addr_str) {
        if(dap_chain_node_addr_from_str(&l_node_addr, l_addr_str) != 0) {
            dap_digit_from_string(l_addr_str, l_node_addr.raw, sizeof(l_node_addr.raw));
        }
        if(l_node_info)
            memcpy(&l_node_info->hdr.address, &l_node_addr, sizeof(dap_chain_node_addr_t));
    }
    if(l_port_str) {
        uint16_t l_node_port = 0;
        dap_digit_from_string(l_port_str, &l_node_port, sizeof(uint16_t));
        if(l_node_info)
            l_node_info->hdr.ext_port = l_node_port;
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
        if(!arg_index || a_argc < 8) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameters");
            DAP_DELETE(l_node_info);
            return -1;
        }
        // handler of command 'node add'
        int l_ret = node_info_add_with_reply(l_net, l_node_info, alias_str, l_cell_str, a_ipv4_str, a_ipv6_str,
                a_str_reply);
        DAP_DELETE(l_node_info);
        return l_ret;
        //break;

    case CMD_DEL:
        // handler of command 'node del'
    {
        int l_ret = node_info_del_with_reply(l_net, l_node_info, alias_str, a_str_reply);
        DAP_DELETE(l_node_info);
        return l_ret;
    }
    case CMD_LINK:
        if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "add", NULL)) {
            // handler of command 'node link add -addr <node address> -link <node address>'
            int l_ret = link_add_or_del_with_reply(l_net, l_node_info, "add", alias_str, &l_link, a_str_reply);
            DAP_DELETE(l_node_info);
            return l_ret;
        }
        else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "del", NULL)) {
            // handler of command 'node link del -addr <node address> -link <node address>'
            int l_ret = link_add_or_del_with_reply(l_net, l_node_info, "del", alias_str, &l_link, a_str_reply);
            DAP_DELETE(l_node_info);
            return l_ret;
        }
        else {
            dap_chain_node_cli_set_reply_text(a_str_reply, "command not recognize, supported format:\n"
                    "global_db node link <add|del] [-addr <node address>  | -alias <node alias>] -link <node address>");
            DAP_DELETE(l_node_info);
            return -1;
        }

    case CMD_DUMP: {
        // handler of command 'node dump'
        bool l_is_full = dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-full", NULL);
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
                    dap_chain_node_cli_set_reply_text(a_str_reply, "alias mapped successfully");
                }
            }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "alias can't be mapped because -addr is not found");
                return -1;
            }
        }
        else {
            dap_chain_node_cli_set_reply_text(a_str_reply, "alias can't be mapped because -alias is not found");
            return -1;
        }

        break;
        // make connect
    case CMD_CONNECT: {
        // get address from alias if addr not defined
        if(alias_str && !l_node_addr.uint64) {
            dap_chain_node_addr_t *address_tmp = dap_chain_node_addr_get_by_alias(l_net, alias_str);
            if(address_tmp) {
                memcpy(&l_node_addr, address_tmp, sizeof(*address_tmp));
                DAP_DELETE(address_tmp);
            }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "no address found by alias");
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
            l_is_auto = dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "auto", NULL);
            if(!l_is_auto) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "addr not found");
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
                dap_chain_node_cli_set_reply_text(a_str_reply, "no node is available");
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
            l_node_client = dap_chain_node_client_connect(l_net,l_remote_node_info);
            if(!l_node_client) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "can't connect");
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
            dap_list_free_full(l_node_list, free);
        }



        if(res) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "no response from remote node(s)");
            log_it(L_WARNING, "No response from remote node(s): err code %d", res);
            // clean client struct
            dap_chain_node_client_close(l_node_client);
            //DAP_DELETE(l_remote_node_info);
            return -1;
        }

        log_it(L_NOTICE, "Stream connection established");
        dap_stream_ch_chain_sync_request_t l_sync_request = {};
         dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch_unsafe(l_node_client->client, dap_stream_ch_chain_get_id());
         // fill begin id
         l_sync_request.id_start = 1;
         // fill current node address
         l_sync_request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);

        // if need to get current node address (feature-2630)
        if(!l_sync_request.node_addr.uint64 )
        {
            log_it(L_NOTICE, "Now get node addr");
            uint8_t l_ch_id = dap_stream_ch_chain_net_get_id();
            dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch_unsafe(l_node_client->client, l_ch_id);

            int l_res = dap_chain_node_client_set_callbacks( l_node_client->client, l_ch_id);

            size_t res = dap_stream_ch_chain_net_pkt_write(l_ch_chain,
            DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE_REQUEST,
            //DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST,
            l_net->pub.id,
            NULL, 0);
            if(res == 0) {
                log_it(L_WARNING, "Can't send DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST packet");
                dap_chain_node_client_close(l_node_client);
                DAP_DELETE(l_remote_node_info);
                return -1;
            }
            int timeout_ms = 15000; // 15 sec = 15 000 ms
            l_res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_NODE_ADDR_LEASED, timeout_ms);
            switch (l_res) {
            case 0:
                if(l_node_client->cur_node_addr.uint64 != 0) {

                    l_sync_request.node_addr.uint64 = l_node_client->cur_node_addr.uint64;
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
            /*                if(0 == dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST,
             l_net->pub.id, l_chain_id_null, l_chain_cell_id_null, &l_sync_request,
             sizeof(l_sync_request))) {
             dap_chain_node_cli_set_reply_text(a_str_reply, "Error: Cant send sync chains request");
             // clean client struct
             dap_chain_node_client_close(l_node_client);
             DAP_DELETE(l_remote_node_info);
             return -1;
             }
            dap_stream_ch_set_ready_to_write(l_ch_chain, true);
            // wait for finishing of request
            timeout_ms = 120000; // 20 min = 1200 sec = 1 200 000 ms
            // TODO add progress info to console
            res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);
            */

        }
        log_it(L_NOTICE, "Now lets sync all");

        dap_chain_id_t l_chain_id_null = { { 0 } };
        dap_chain_cell_id_t l_chain_cell_id_null = { { 0 } };
        l_chain_id_null.uint64 = l_net->pub.id.uint64;
        l_chain_cell_id_null.uint64 = dap_chain_net_get_cur_cell(l_net) ? dap_chain_net_get_cur_cell(l_net)->uint64 : 0;

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
            dap_chain_node_cli_set_reply_text(a_str_reply, "Error: Can't send sync chains request");
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
            dap_chain_node_cli_set_reply_text(a_str_reply, "Error: can't sync with node "NODE_ADDR_FP_STR,
                                            NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
            dap_chain_node_client_close(l_node_client);
            DAP_DELETE(l_remote_node_info);
            log_it(L_WARNING, "Gdb synced err -2");
            return -2;

        }
        // flush global_db
        dap_chain_global_db_flush();
        log_it(L_INFO, "Gdb synced Ok");

        // Requesting chains
        dap_chain_t *l_chain = NULL;
        DL_FOREACH(l_net->pub.chains, l_chain)
        {
            // reset state NODE_CLIENT_STATE_SYNCED
            dap_chain_node_client_reset(l_node_client);
            // send request
            dap_stream_ch_chain_sync_request_t l_sync_request = {};
            dap_chain_hash_fast_t *l_hash = dap_db_get_last_hash_remote(l_node_client->remote_node_addr.uint64, l_chain);
            if (l_hash) {
                memcpy(&l_sync_request.hash_from, l_hash, sizeof(*l_hash));
                DAP_DELETE(l_hash);
            }
            if(0 == dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS,
                    l_net->pub.id.uint64, l_chain->id.uint64, l_remote_node_info->hdr.cell_id.uint64, &l_sync_request,
                    sizeof(l_sync_request))) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Error: Can't send sync chains request");
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
        dap_chain_node_cli_set_reply_text(a_str_reply, "Node sync completed: Chains and gdb are synced");
        return 0;

    }
        // make handshake
    case CMD_HANDSHAKE: {
        // get address from alias if addr not defined
        if(alias_str && !l_node_addr.uint64) {
            dap_chain_node_addr_t *address_tmp = dap_chain_node_addr_get_by_alias(l_net, alias_str);
            if(address_tmp) {
                memcpy(&l_node_addr, address_tmp, sizeof(*address_tmp));
                DAP_DELETE(address_tmp);
            }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "No address found by alias");
                return -4;
            }
        }
        if(!l_node_addr.uint64) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Addr not found");
            return -5;
        }

        dap_chain_node_info_t *node_info = node_info_read_and_reply(l_net, &l_node_addr, a_str_reply);
        if(!node_info)
            return -6;
        int timeout_ms = 5000; //5 sec = 5000 ms
        // start handshake
        dap_chain_node_client_t *client = dap_chain_node_client_connect(l_net,node_info);
        if(!client) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't connect");
            DAP_DELETE(node_info);
            return -7;
        }
        // wait handshake
        int res = dap_chain_node_client_wait(client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
        if (res) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "No response from node");
            // clean client struct
            dap_chain_node_client_close(client);
            DAP_DELETE(node_info);
            return -8;
        }
        DAP_DELETE(node_info);

        //Add new established connection in the list
        int ret = dap_chain_node_client_list_add(&l_node_addr, client);
        switch (ret)
        {
        case -1:
            dap_chain_node_client_close(client);
            dap_chain_node_cli_set_reply_text(a_str_reply, "Connection established, but not saved");
            return -9;
        case -2:
            dap_chain_node_client_close(client);
            dap_chain_node_cli_set_reply_text(a_str_reply, "Connection already present");
            return -10;
        }
        dap_chain_node_cli_set_reply_text(a_str_reply, "Connection established");
    }
        break;
    }
    return 0;
}


/**
 * @brief Traceroute command
 * return 0 OK, -1 Err
 * @param argc 
 * @param argv 
 * @param arg_func 
 * @param str_reply 
 * @return int 
 */
int com_traceroute(int argc, char** argv, char **str_reply)
{
#ifdef DAP_OS_LINUX
    const char *addr = NULL;
    int hops = 0, time_usec = 0;
    if(argc > 1)
        addr = argv[1];
    iputils_set_verbose();
    int res = (addr) ? traceroute_util(addr, &hops, &time_usec) : -EADDRNOTAVAIL;
    if(res >= 0) {
        dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s hops=%d time=%.1lf ms", addr, hops,
                time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case 2:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr,
                        "Unknown traceroute module");
                break;
            case 3:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr, "first hop out of range");
                break;
            case 4:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr,
                        "max hops cannot be more than 255");
                break;
            case 5:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr,
                        "no more than 10 probes per hop");
                break;
            case 6:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr,
                        "bad wait specifications");
                break;
            case 7:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr, "too big packetlen ");
                break;
            case 8:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr,
                        "IP version mismatch in addresses specified");
                break;
            case 9:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr, "bad sendtime");
                break;
            case 10:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr, "init_ip_options");
                break;
            case 11:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr, "calloc");
                break;
            case 12:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr, "parse cmdline");
                break;
            case 13:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error: %s", addr,
                        "trace method's init failed");
                break;
            default:
                dap_chain_node_cli_set_reply_text(str_reply, "traceroute %s error(%d) %s", addr, res,
                        "trace not found");
            }
        }
    }
    return res;
#else
    UNUSED(argc);
    UNUSED(argv);
    dap_chain_node_cli_set_reply_text(str_reply, "Not realized for your platform");
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
int com_tracepath(int argc, char** argv, char **str_reply)
{
#ifdef DAP_OS_LINUX
    const char *addr = NULL;
    int hops = 0, time_usec = 0;
    if(argc > 1)
        addr = argv[1];
    iputils_set_verbose();
    int res = (addr) ? tracepath_util(addr, &hops, &time_usec) : -EADDRNOTAVAIL;
    if(res >= 0) {
        if(str_reply)
            dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s hops=%d time=%.1lf ms", addr, hops,
                    time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case ESOCKTNOSUPPORT:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't create socket");
                break;
            case 2:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_MTU_DISCOVER");
                break;
            case 3:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_RECVERR");
                break;
            case 4:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_HOPLIMIT");
                break;
            case 5:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IP_MTU_DISCOVER");
                break;
            case 6:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IP_RECVERR");
                break;
            case 7:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IP_RECVTTL");
                break;
            case 8:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr, "malloc");
                break;
            case 9:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr,
                        "Can't setsockopt IPV6_UNICAST_HOPS");
                break;
            case 10:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IP_TTL");
                break;
            default:
                dap_chain_node_cli_set_reply_text(str_reply, "tracepath %s error(%d) %s", addr, res, "trace not found");
            }
        }
    }
    return res;
#else
    UNUSED(argc);
    UNUSED(argv);
    dap_chain_node_cli_set_reply_text(str_reply, "Not realized for your platform");
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
int com_ping(int argc, char** argv, char **str_reply)
{
#ifdef DAP_OS_LINUX

    int n = 4;
    if(argc < 2) {
        dap_chain_node_cli_set_reply_text(str_reply, "host not specified");
        return -1;
    }
    const char *n_str = NULL;
    int argc_host = 1;
    int argc_start = 1;
    argc_start = dap_chain_node_cli_find_option_val(argv, argc_start, argc, "-n", &n_str);
    if(argc_start) {
        argc_host = argc_start + 1;
        n = (n_str) ? atoi(n_str) : 4;
    }
    else {
        argc_start = dap_chain_node_cli_find_option_val(argv, argc_start, argc, "-c", &n_str);
        if(argc_start) {
            argc_host = argc_start + 1;
            n = (n_str) ? atoi(n_str) : 4;
        }
    }
    if(n <= 1)
        n = 1;
    const char *addr = argv[argc_host];
    iputils_set_verbose();
    ping_handle_t *l_ping_handle = ping_handle_create();
    int res = (addr) ? ping_util(l_ping_handle, addr, n) : -EADDRNOTAVAIL;
    DAP_DELETE(l_ping_handle);
    if(res >= 0) {
        if(str_reply)
            dap_chain_node_cli_set_reply_text(str_reply, "ping %s time=%.1lf ms", addr, res * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EDESTADDRREQ:
                dap_chain_node_cli_set_reply_text(str_reply, "ping %s error: %s", addr, "Destination address required");
                break;
            case EADDRNOTAVAIL:
                dap_chain_node_cli_set_reply_text(str_reply, "ping %s error: %s", (addr) ? addr : "",
                        (addr) ? "Host not found" : "Host not defined");
                break;
            case EPFNOSUPPORT:
                dap_chain_node_cli_set_reply_text(str_reply, "ping %s error: %s", addr, "Unknown protocol family");
                break;
            default:
                dap_chain_node_cli_set_reply_text(str_reply, "ping %s error(%d)", addr, -res);
            }
        }
    }
    return res;
#else
    UNUSED(argc);
    UNUSED(argv);
    dap_chain_node_cli_set_reply_text(str_reply, "Not realized for your platform");
    return -1;
#endif
}

/**
 * @brief com_version
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_version(int argc, char ** argv, char **str_reply)
{
    (void) argc;
    (void) argv;
#ifndef DAP_VERSION
#pragma message "[!WRN!] DAP_VERSION IS NOT DEFINED. Manual override engaged."
#define DAP_VERSION 0.9-15
#endif
    dap_chain_node_cli_set_reply_text(str_reply,
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
int com_help(int argc, char ** argv, char **str_reply)
{
    if(argc > 1) {
        log_it(L_DEBUG, "Help for command %s", argv[1]);
        dap_chain_node_cmd_item_t *l_cmd = dap_chain_node_cli_cmd_find(argv[1]);
        if(l_cmd) {
            dap_chain_node_cli_set_reply_text(str_reply, "%s:\n%s", l_cmd->doc, l_cmd->doc_ex);
            return 0;
        } else {
            dap_chain_node_cli_set_reply_text(str_reply, "command \"%s\" not recognized", argv[1]);
        }
        return -1;
    } else {
        // TODO Read list of commands & return it
        log_it(L_DEBUG, "General help requested");
        dap_string_t * l_help_list_str = dap_string_new(NULL);
        dap_chain_node_cmd_item_t *l_cmd = dap_chain_node_cli_cmd_get_first();
        while(l_cmd) {
            dap_string_append_printf(l_help_list_str, "%s:\t\t\t%s\n",
                    l_cmd->name, l_cmd->doc ? l_cmd->doc : "(undocumented command)");
            l_cmd = (dap_chain_node_cmd_item_t*) l_cmd->hh.next;
        }
        dap_chain_node_cli_set_reply_text(str_reply,
                "Available commands:\n\n%s\n",
                l_help_list_str->len ? l_help_list_str->str : "NO ANY COMMAND WERE DEFINED");
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
int com_tx_wallet(int argc, char ** argv, char **str_reply)
{
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    // Get address of wallet
    enum {
        CMD_NONE, CMD_WALLET_NEW, CMD_WALLET_LIST, CMD_WALLET_INFO
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    // find  add parameter ('alias' or 'handshake')
    if(dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "new", NULL)) {
        cmd_num = CMD_WALLET_NEW;
    }
    else if(dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "list", NULL)) {
        cmd_num = CMD_WALLET_LIST;
    }
    else if(dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "info", NULL)) {
        cmd_num = CMD_WALLET_INFO;
    }
    arg_index++;
    if(cmd_num == CMD_NONE) {
        dap_chain_node_cli_set_reply_text(str_reply,
                "Format of command: wallet [new -w <wallet_name> | list | info [<-addr <addr>]|[-w <wallet_name> -net <net_name>]");
        return -1;
    }

    dap_chain_node_addr_t address;
    memset(&address, 0, sizeof(dap_chain_node_addr_t));
    const char *l_addr_str = NULL, *l_wallet_name = NULL, *l_net_name = NULL, *l_sign_type_str = NULL, *l_restore_str = NULL;
    // find wallet addr
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-addr", &l_addr_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-w", &l_wallet_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-net", &l_net_name);

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name( l_net_name) : NULL;

    dap_string_t *l_string_ret = dap_string_new(NULL);
    switch (cmd_num) {
    // new wallet
    case CMD_WALLET_NEW: {
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-sign", &l_sign_type_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-restore", &l_restore_str);
        // rewrite existing wallet
        int l_is_force = dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-force", NULL);

        if(!l_wallet_name) {
            dap_chain_node_cli_set_reply_text(str_reply, "Wallet name option <-w>  not defined");
            return -1;
        }
        // check wallet existence
        if(!l_is_force) {
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
            if(l_wallet) {
                dap_chain_node_cli_set_reply_text(str_reply, "Wallet already exists");
                dap_chain_wallet_close(l_wallet);
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
                dap_chain_node_cli_set_reply_text(str_reply, "Unknown signature type");
                return -1;
            }
        }

        uint8_t *l_seed = NULL;
        size_t l_seed_size = 0;
        size_t l_restore_str_size = dap_strlen(l_restore_str);
        if(l_restore_str && l_restore_str_size > 2 && !dap_strncmp(l_restore_str, "0x", 2)) {
            l_seed_size = (l_restore_str_size - 2) / 2;
            l_seed = DAP_NEW_SIZE(uint8_t, l_seed_size);
            if(!dap_hex2bin(l_seed, l_restore_str + 2, l_restore_str_size - 2)){
                DAP_DELETE(l_seed);
                l_seed = NULL;
                l_seed_size = 0;
                dap_chain_node_cli_set_reply_text(str_reply, "Resrote hash is invalid, wallet is not created");
                return -1;
            }
        }
        // Creates new wallet
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_create_with_seed(l_wallet_name, c_wallets_path, l_sign_type,
                l_seed, l_seed_size);
        dap_chain_addr_t *l_addr = l_net? dap_chain_wallet_get_addr(l_wallet,l_net->pub.id ) : NULL;
        if(!l_wallet) {
            dap_chain_node_cli_set_reply_text(str_reply, "Wallet is not created besause of internal error");
            return -1;
        }
        char *l_addr_str = l_addr? dap_chain_addr_to_str(l_addr) : NULL;
        dap_string_append_printf(l_string_ret, "Wallet '%s' (type=%s) successfully created\n", l_wallet->name, l_sign_type_str);
        if ( l_addr_str ) {
            dap_string_append_printf(l_string_ret, "new address %s", l_addr_str);
            DAP_DELETE(l_addr_str);
        }
        dap_chain_wallet_close(l_wallet);
    }
        break;
        // wallet list
    case CMD_WALLET_LIST: {
        DIR * l_dir = opendir(c_wallets_path);
        if(l_dir) {
            struct dirent * l_dir_entry;
            while((l_dir_entry = readdir(l_dir)) != NULL) {
                const char *l_file_name = l_dir_entry->d_name;
                size_t l_file_name_len = (l_file_name) ? strlen(l_file_name) : 0;
                if((l_file_name_len > 8) && (strcmp(l_file_name + l_file_name_len - 8, ".dwallet") == 0)) {
                    char *l_file_path_tmp = dap_strdup_printf("%s/%s", c_wallets_path, l_file_name);
                    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(l_file_path_tmp);
                    if(l_wallet) {
                        dap_chain_addr_t *l_addr = l_net? dap_chain_wallet_get_addr(l_wallet, l_net->pub.id) : NULL;
                        char *l_addr_str = dap_chain_addr_to_str(l_addr);
                        dap_string_append_printf(l_string_ret, "\nwallet: %s\n", l_wallet->name);
                        if ( l_addr_str){
                            dap_string_append_printf(l_string_ret, "addr: %s\n", (l_addr_str) ? l_addr_str : "-");
                            DAP_DELETE(l_addr_str);
                        }
                        dap_chain_wallet_close(l_wallet);
                    }
                    DAP_DELETE(l_file_path_tmp);
                }
            }
            closedir(l_dir);
        }
    }
        break;

        // wallet info
    case CMD_WALLET_INFO: {
        dap_chain_wallet_t *l_wallet = NULL;
        dap_chain_addr_t *l_addr = NULL;

        if(l_wallet_name) {
            l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
            if ( l_net )
                l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id );
        }
        if(!l_addr && l_addr_str)
            l_addr = dap_chain_addr_from_str(l_addr_str);

        dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name((const char *) l_net_name);
        if(!l_net_name && !l_addr ) {
            dap_chain_node_cli_set_reply_text(str_reply, "wallet info requires parameter 'net'");
            return -1;
        }
        else if (! l_addr){
            if((l_ledger = dap_chain_ledger_by_net_name(l_net_name)) == NULL) {
                dap_chain_node_cli_set_reply_text(str_reply, "not found net by name '%s'", l_net_name);
                return -1;
            }
        }else{
            l_net = dap_chain_net_by_id(l_addr->net_id);
            if (l_net){
            l_ledger = l_net->pub.ledger;
                l_net_name = l_net->pub.name;
            }else{
                dap_chain_node_cli_set_reply_text(str_reply, "Can't find network id 0x%08X from address %s", l_addr->net_id.uint64,
                                                  l_addr_str);
                return -1;

            }
        }

        if(l_addr) {
            char *l_addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) l_addr);
            if(l_wallet)
                dap_string_append_printf(l_string_ret, "wallet: %s\n", l_wallet->name);
            dap_string_append_printf(l_string_ret, "addr: %s\n", (l_addr_str) ? l_addr_str : "-");
            dap_string_append_printf(l_string_ret, "network: %s\n", (l_net_name ) ? l_net_name : "-");

            size_t l_addr_tokens_size = 0;
            char **l_addr_tokens = NULL;
            dap_chain_ledger_addr_get_token_ticker_all_fast(l_ledger, l_addr, &l_addr_tokens, &l_addr_tokens_size);
            if(l_addr_tokens_size > 0)
                dap_string_append_printf(l_string_ret, "balance:\n");
            else
                dap_string_append_printf(l_string_ret, "balance: 0");
            for(size_t i = 0; i < l_addr_tokens_size; i++) {
                if(l_addr_tokens[i]) {
                    uint128_t l_balance = dap_chain_ledger_calc_balance(l_ledger, l_addr, l_addr_tokens[i]);
                    char *l_balance_coins = dap_chain_balance_to_coins(l_balance);
                    char *l_balance_datoshi = dap_chain_balance_print(l_balance);
                    dap_string_append_printf(l_string_ret, "\t%s (%s) %s\n", l_balance_coins,
                            l_balance_datoshi, l_addr_tokens[i]);
                    if(i < l_addr_tokens_size - 1)
                        dap_string_append_printf(l_string_ret, "\n");
                    DAP_DELETE(l_balance_coins);
                    DAP_DELETE(l_balance_datoshi);

                }
                DAP_DELETE(l_addr_tokens[i]);
            }
            DAP_DELETE(l_addr_tokens);
            DAP_DELETE(l_addr_str);
            if(l_wallet)
                dap_chain_wallet_close(l_wallet);
        }
        else {
            if(l_wallet)
                dap_chain_wallet_close(l_wallet);
            dap_string_free(l_string_ret, true);
            dap_chain_node_cli_set_reply_text(str_reply, "wallet not found");
            return -1;
        }
    }
        break;
    }

    *str_reply = dap_string_free(l_string_ret, false);
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
int dap_chain_node_cli_cmd_values_parse_net_chain(int *a_arg_index, int argc, char ** argv, char ** a_str_reply,
        dap_chain_t ** a_chain, dap_chain_net_t ** a_net)
{
    const char * l_chain_str = NULL;
    const char * l_net_str = NULL;

    // Net name
    if(a_net)
        dap_chain_node_cli_find_option_val(argv, *a_arg_index, argc, "-net", &l_net_str);
    else
        return -100;

    // Select network
    if(!l_net_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "%s requires parameter '-net'", argv[0]);
        return -101;
    }

    if((*a_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
        dap_chain_node_cli_set_reply_text(a_str_reply, "%s can't find network \"%s\"", argv[0], l_net_str);
        return -102;
    }

    // Chain name
    if(a_chain) {
        dap_chain_node_cli_find_option_val(argv, *a_arg_index, argc, "-chain", &l_chain_str);

        // Select chain
        if(l_chain_str) {
            if((*a_chain = dap_chain_net_get_chain_by_name(*a_net, l_chain_str)) == NULL) { // Can't find such chain
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "%s requires parameter '-chain' to be valid chain name in chain net %s",
                        argv[0], l_net_str);
                return -103;
            }
        }
        else {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "%s requires parameter '-chain'", argv[0]);
            return -104;
        }
    }
    return 0;

}

/**
 * @brief com_token_decl_sign
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_token_decl_sign(int argc, char ** argv, char ** a_str_reply)
{
    int arg_index = 1;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    const char * l_datum_hash_str = NULL;
    // Chain name
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
    if(l_datum_hash_str) {
        char * l_datum_hash_hex_str = NULL;
        char * l_datum_hash_base58_str = NULL;
        const char * l_certs_str = NULL;
        dap_cert_t ** l_certs = NULL;
        size_t l_certs_count = 0;
        dap_chain_t * l_chain = NULL;
        dap_chain_net_t * l_net = NULL;

        dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, argc, argv, a_str_reply, &l_chain, &l_net);
        if(!l_net)
            return -1;
        else {
            if(*a_str_reply) {
                DAP_DELETE(*a_str_reply);
                *a_str_reply = NULL;
            }
        }

        // Certificates thats will be used to sign currend datum token
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-certs", &l_certs_str);

        // Load certs lists
        if (l_certs_str)
            dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);

        if(!l_certs_count) {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "token_sign command requres at least one valid certificate to sign the basic transaction of emission");
            return -7;
        }

        char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
        if(!l_gdb_group_mempool) {
            l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);
        }
        // datum hash may be in hex or base58 format
        if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
            l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
            l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
        }
        else {
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
        if((l_datum = (dap_chain_datum_t*) dap_chain_global_db_gr_get(
                l_datum_hash_hex_str, &l_datum_size, l_gdb_group_mempool)) != NULL) {

            // Check if its token declaration
            if(l_datum->header.type_id == DAP_CHAIN_DATUM_TOKEN_DECL) {
                dap_chain_datum_token_t * l_datum_token = (dap_chain_datum_token_t *) l_datum->data;
                size_t l_datum_token_size = l_datum->header.data_size;
                if (l_datum_token->header_private.signs_valid == l_datum_token->header_private.signs_total) {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Datum %s with datum token has all signs on board. Can't add anything to it", l_datum_hash_out_str);
                    DAP_DELETE(l_datum);
                    DAP_DELETE(l_gdb_group_mempool);
                    return -7;
                }
                // Check for signatures, are they all in set and are good enought?
                size_t l_signs_size = 0, i = 1;
                do {
                    dap_sign_t *l_sign = (dap_sign_t *)l_datum_token->data_n_tsd + l_signs_size;
                    if( dap_sign_verify(l_sign, l_datum_token, sizeof(l_datum_token->header_private)) != 1) {
                        log_it(L_WARNING, "Wrong signature %zu for datum_token with key %s in mempool!", i, l_datum_hash_out_str);
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "Datum %s with datum token has wrong signature %zu, break process and exit",
                                l_datum_hash_out_str, i);
                        DAP_DELETE(l_datum);
                        DAP_DELETE(l_gdb_group_mempool);
                        return -6;
                    }else{
                        log_it(L_DEBUG,"Sign %zu passed", i);
                    }
                    l_signs_size += dap_sign_get_size(l_sign);
                } while (i++ <= l_datum_token->header_private.signs_valid);
                log_it(L_DEBUG, "Datum %s with token declaration: %hu signatures are verified well (sign_size = %zu)",
                                 l_datum_hash_out_str, l_datum_token->header_private.signs_valid, l_signs_size);

                if (l_datum_token->header_private.signs_total >= l_datum_token->header_private.signs_valid + l_certs_count) {
                    // Copy TSD sections to new location
                    size_t l_tsd_size = l_datum_token_size - l_signs_size;
                    uint8_t *l_token_tsd = DAP_NEW_SIZE(uint8_t, l_tsd_size);
                    memcpy(l_token_tsd, l_datum_token->data_n_tsd + l_signs_size, l_tsd_size);
                    size_t l_offset = l_signs_size;
                    for(size_t i = 0; i < l_certs_count; i++) {
                        // Add signs to token
                        dap_sign_t * l_sign = dap_sign_create(l_certs[i]->enc_key,
                                l_datum_token,
                                sizeof(l_datum_token->header_private), 0);
                        size_t l_sign_size = dap_sign_get_size(l_sign);

                        l_signs_size += l_sign_size;
                        l_datum_size += l_sign_size;
                        l_datum_token_size += l_sign_size;

                        if ( (l_datum = DAP_REALLOC(l_datum, l_datum_size)) != NULL ) {
                            // add place for new signatures
                            l_datum_token = (dap_chain_datum_token_t*) l_datum->data;
                            l_datum->header.data_size = l_datum_token_size;
                            memcpy(l_datum_token->data_n_tsd + l_offset, l_sign, l_sign_size);
                            log_it(L_DEBUG, "Added datum token declaration sign with cert %s (new size %zu)",
                                   l_certs[i]->name , l_datum_size);
                            DAP_DELETE(l_sign);

                            l_offset += l_sign_size;
                        } else{
                            log_it(L_ERROR, "Can't allocate more memory for datum token");
                            return -81;
                        }
                    }
                    // Return TSD sections to its place
                    memcpy(l_datum_token->data_n_tsd + l_signs_size, l_token_tsd, l_tsd_size);
                    DAP_DELETE(l_token_tsd);

                    // Recalc hash, string and place new datum

                    // Calc datum's hash
                    dap_chain_hash_fast_t l_key_hash={0};
                    dap_hash_fast(l_datum, l_datum_size, &l_key_hash);
                    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
                    char * l_key_str_base58 = dap_enc_base58_encode_hash_to_str(&l_key_hash);
                    const char * l_key_out_str;
                    if(!dap_strcmp(l_hash_out_type,"hex"))
                        l_key_out_str = l_key_str;
                    else
                        l_key_out_str = l_key_str_base58;

                    // Add datum to mempool with datum_token hash as a key
                    if(dap_chain_global_db_gr_set(dap_strdup(l_key_str), (uint8_t *) l_datum, l_datum_size, l_gdb_group_mempool)) {

                        char* l_hash_str = l_datum_hash_hex_str;
                        // Remove old datum from pool
                        if( dap_chain_global_db_gr_del( dap_strdup(l_hash_str) , l_gdb_group_mempool)) {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "datum %s produced from %s is replacing the %s in datum pool",
                                    l_key_out_str, l_datum_hash_out_str, l_datum_hash_out_str);

                            DAP_DELETE(l_datum);
                            //DAP_DELETE(l_datum_token);
                            DAP_DELETE(l_gdb_group_mempool);
                            return 0;
                        } else {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "Warning! Can't remove old datum %s ( new datum %s added normaly in datum pool)",
                                    l_datum_hash_out_str, l_key_out_str);
                            DAP_DELETE(l_datum);
                            //DAP_DELETE(l_datum_token);
                            DAP_DELETE(l_gdb_group_mempool);
                            return 1;
                        }
                        DAP_DELETE(l_hash_str);
                        DAP_DELETE(l_key_str);
                        DAP_DELETE(l_key_str_base58);
                    }
                    else {
                        dap_chain_node_cli_set_reply_text(a_str_reply,
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
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Error! Not enought place for new signature (%hu is left when we need %hu signatures)",
                            l_datum_token->header_private.signs_total - l_datum_token->header_private.signs_valid, l_certs_count);
                    return -6;
                }
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "Error! Wrong datum type. token_decl_sign sign only token declarations datum");
                return -61;
            }
        } else {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "token_decl_sign can't find datum with %s hash in the mempool of %s:%s",l_datum_hash_out_str,l_net? l_net->pub.name: "<undefined>",
                    l_chain?l_chain->name:"<undefined>");
            return -5;
        }
        DAP_DELETE(l_datum_hash_hex_str);
        DAP_DELETE(l_datum_hash_base58_str);
    } else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_decl_sign need datum <datum hash> argument");
        return -2;
    }
}

/**
 * @brief s_com_mempool_list_print_for_chain
 * 
 * @param a_net 
 * @param a_chain 
 * @param a_str_tmp 
 * @param a_hash_out_type 
 */
void s_com_mempool_list_print_for_chain(dap_chain_net_t * a_net, dap_chain_t * a_chain, dap_string_t * a_str_tmp, const char *a_hash_out_type){
    char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(a_chain);
    if(!l_gdb_group_mempool){
        dap_string_append_printf(a_str_tmp, "%s.%s: chain not found\n", a_net->pub.name, a_chain->name);
    }else{
        size_t l_objs_size = 0;
        dap_global_db_obj_t * l_objs = dap_chain_global_db_gr_load(l_gdb_group_mempool, &l_objs_size);
        if(l_objs_size > 0)
            dap_string_append_printf(a_str_tmp, "%s.%s: Found %zu records :\n", a_net->pub.name, a_chain->name,
                    l_objs_size);
        else
            dap_string_append_printf(a_str_tmp, "%s.%s: Not found records\n", a_net->pub.name, a_chain->name);
        for(size_t i = 0; i < l_objs_size; i++) {
            dap_chain_datum_t * l_datum = (dap_chain_datum_t*) l_objs[i].value;
            time_t l_ts_create = (time_t) l_datum->header.ts_create;
            if (!l_datum->header.data_size || (l_datum->header.data_size > l_objs[i].value_len)) {
                //log_it(L_ERROR, "Trash datum in GDB %s.%s, key: %s", a_net->pub.name, a_chain->name, l_objs[i].key);
                continue;
            }
            char buf[50] = {[0]='\0'};
            dap_hash_fast_t l_data_hash;
            char l_data_hash_str[70] = {[0]='\0'};
            dap_hash_fast(l_datum->data,l_datum->header.data_size,&l_data_hash);
            dap_hash_fast_to_str(&l_data_hash,l_data_hash_str,sizeof (l_data_hash_str)-1);
            const char *l_type = NULL;
            DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type)
            dap_string_append_printf(a_str_tmp, "hash %s: type_id=%s  data_size=%u data_hash=%s ts_create=%s", // \n included in timestamp
                    l_objs[i].key, l_type,
                    l_datum->header.data_size, l_data_hash_str, dap_ctime_r(&l_ts_create, buf));
            dap_chain_net_dump_datum(a_str_tmp, l_datum, a_hash_out_type);
        }
        dap_chain_global_db_objs_delete(l_objs, l_objs_size);
    }

    DAP_DELETE(l_gdb_group_mempool);
}

/**
 * @brief com_token_decl_list
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_mempool_list(int argc, char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = "hex";
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, argc, argv, a_str_reply, &l_chain, &l_net);
    if(!l_net)
        return -1;
    else {
        if(*a_str_reply) {
            DAP_DELETE(*a_str_reply);
            *a_str_reply = NULL;
        }
    }

    if(l_net) {
        dap_string_t * l_str_tmp = dap_string_new(NULL);

        if(l_chain)
            s_com_mempool_list_print_for_chain(l_net, l_chain, l_str_tmp, l_hash_out_type);
        else
            DL_FOREACH(l_net->pub.chains, l_chain)
                    s_com_mempool_list_print_for_chain(l_net, l_chain, l_str_tmp, l_hash_out_type);

        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
        dap_string_free(l_str_tmp, false);

        return 0;
    } else {
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Error! Need both -net <network name> and -chain <chain name> params\n");
        return -2;
    }
}

/**
 * @brief com_mempool_delete
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
int com_mempool_delete(int argc, char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    if(dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, argc, argv, a_str_reply, &l_chain, &l_net) != 0) {
        //dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Need both -net <network name> and -chain <chain name> params\n");
        return -1;
    }

    if(l_chain && l_net) {  // UNUSED(l_net)
        const char * l_datum_hash_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
        if(l_datum_hash_str) {
            char *l_datum_hash_hex_str;
            char *l_datum_hash_base58_str;
            // datum hash may be in hex or base58 format
            if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
                l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
                l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
            }
            else {
                l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
                l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
            }
            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
            uint8_t *l_data_tmp = l_datum_hash_hex_str ? dap_chain_global_db_gr_get(dap_strdup(l_datum_hash_hex_str), NULL, l_gdb_group_mempool) : NULL;
            if(l_data_tmp && dap_chain_global_db_gr_del(dap_strdup(l_datum_hash_hex_str), l_gdb_group_mempool)) {
                if(!dap_strcmp(l_hash_out_type,"hex"))
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Datum %s deleted", l_datum_hash_hex_str);
                else
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Datum %s deleted", l_datum_hash_base58_str);
                return 0;
            } else {
                if(!dap_strcmp(l_hash_out_type,"hex"))
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Can't find datum %s", l_datum_hash_hex_str);
                else
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Can't find datum %s", l_datum_hash_base58_str);
                return -4;
            }
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_data_tmp);
            DAP_DELETE(l_datum_hash_hex_str);
            DAP_DELETE(l_datum_hash_base58_str);
        } else {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Error! %s requires -datum <datum hash> option", argv[0]);
            return -3;
        }
    } else {
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Error! Need both -net <network name> and -chain <chain name> params\n");
        return -2;
    }
}

/**
 * @brief com_mempool_proc
 * process mempool datums
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
int com_mempool_proc(int argc, char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, argc, argv, a_str_reply, &l_chain, &l_net);
    if (!l_net || !l_chain)
        return -1;

    if(*a_str_reply) {
        DAP_DELETE(*a_str_reply);
        *a_str_reply = NULL;
    }

    char * l_gdb_group_mempool = NULL, *l_gdb_group_mempool_tmp;
    l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
    l_gdb_group_mempool_tmp = l_gdb_group_mempool;

    // If full or light it doesnt work
    if(dap_chain_net_get_role(l_net).enums>= NODE_ROLE_FULL){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Need master node role or higher for network %s to process this command", l_net->pub.name);
        return -1;
    }

    const char * l_datum_hash_str = NULL;
    int ret = 0;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
    if(l_datum_hash_str) {
        char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
        dap_string_t * l_str_tmp = dap_string_new(NULL);
        size_t l_datum_size=0;
        const char *l_datum_hash_out_str;
        char *l_datum_hash_hex_str;
        char *l_datum_hash_base58_str;
        // datum hash may be in hex or base58 format
        if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
            l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
            l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
        }
        else {
            l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
            l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
        }
        if(!dap_strcmp(l_hash_out_type,"hex"))
            l_datum_hash_out_str = l_datum_hash_hex_str;
        else
            l_datum_hash_out_str = l_datum_hash_base58_str;

        dap_chain_datum_t * l_datum = l_datum_hash_hex_str ? (dap_chain_datum_t*) dap_chain_global_db_gr_get(l_datum_hash_hex_str,
                                                                                       &l_datum_size, l_gdb_group_mempool) : NULL;
        size_t l_datum_size2= l_datum? dap_chain_datum_size( l_datum): 0;
        if (l_datum_size != l_datum_size2 ){
            ret = -8;
            dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Corrupted datum %s, size by datum headers is %zd when in mempool is only %zd bytes",
                                              l_datum_size2, l_datum_size);
        }else{
            if(l_datum) {
                char buf[50];
                time_t l_ts_create = (time_t) l_datum->header.ts_create;
                const char *l_type = NULL;
                DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type);
                dap_string_append_printf(l_str_tmp, "hash %s: type_id=%s ts_create=%s data_size=%u\n",
                        l_datum_hash_out_str, l_type,
                        dap_ctime_r(&l_ts_create, buf), l_datum->header.data_size);
                int l_verify_datum= dap_chain_net_verify_datum_for_add( l_net, l_datum) ;
                if (l_verify_datum != 0){
                    dap_string_append_printf(l_str_tmp, "Error! Datum doesn't pass verifications (code %d) examine node log files",
                                             l_verify_datum);
                    ret = -9;
                }else{
                    if (l_chain->callback_add_datums){
                        if (l_chain->callback_add_datums(l_chain, &l_datum, 1) ==0 ){
                            dap_string_append_printf(l_str_tmp, "Error! Datum doesn't pass verifications, examine node log files");
                            ret = -6;
                        }else{
                            dap_string_append_printf(l_str_tmp, "Datum processed well. ");
                            if (!dap_chain_global_db_gr_del( dap_strdup(l_datum_hash_hex_str), l_gdb_group_mempool)){
                                dap_string_append_printf(l_str_tmp, "Warning! Can't delete datum from mempool!");
                            }else
                                dap_string_append_printf(l_str_tmp, "Removed datum from mempool.");
                        }
                    }else{
                        dap_string_append_printf(l_str_tmp, "Error! Can't move to no-concensus chains from mempool");
                        ret = -1;
                    }
                }
                dap_string_append_printf(l_str_tmp, "\n");
                dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
                dap_string_free(l_str_tmp, true);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Can't find datum %s", l_datum_hash_str);
                ret = -4;
            }
        }
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DELETE(l_datum_hash_hex_str);
        DAP_DELETE(l_datum_hash_base58_str);
    } else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Error! %s requires -datum <datum hash> option", argv[0]);
        ret = -5;
    }
    return  ret;
}


/**
 * @brief com_token_decl_update
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 * @details token_update -net <net name> -chain <chain name> -token <token ticker> [-type private] -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...  [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
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
int com_token_update(int a_argc, char ** a_argv, char ** a_str_reply)
{
    int l_arg_index = 1;

    const char * l_type_str = NULL;
    uint16_t l_type = DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE;

    const char * l_ticker = NULL;

    uint16_t l_signs_total = 0;

    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net))
        return -1;
    // Token ticker
    l_arg_index=dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_ticker);
    // Check for ticker
    if(!l_ticker) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_update requires parameter 'token'");
        return -2;
    }

    // Token type
    l_arg_index=dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-type", &l_type_str);

    if (!l_type_str || !strcmp(l_type_str, "private")) {
        l_type = DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE;
    } else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_update can't accept type \"%s\"", l_type_str);
        return -22;
    }

    dap_chain_datum_token_t * l_datum_token_update = NULL;
    size_t l_datum_data_offset = 0;

    switch(l_type){
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:{
            dap_list_t *l_tsd_list = NULL;
            size_t l_tsd_total_size = 0;
            l_arg_index++;
            while (l_arg_index<a_argc-1){
                char * l_arg_param=  a_argv[l_arg_index+1];
                if ( strcmp( a_argv[l_arg_index],"-flags_set" )==0){   // Flags
                     char ** l_str_flags = NULL;
                     l_str_flags = dap_strsplit( l_arg_param,",",0xffff );
                     uint16_t l_flags = 0;
                     while (l_str_flags && *l_str_flags){
                         uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_str_flags);
                         if ( l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                             dap_chain_node_cli_set_reply_text(a_str_reply, "Flag can't be \"%s\"",*l_str_flags);
                             return -20;
                         }
                         l_flags |= (1<<l_flag);
                         l_str_flags++;
                     }
                     // Add flags as set_flags TDS section
                     dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                             DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS, l_flags);
                     dap_list_append( l_tsd_list, l_tsd);
                     l_tsd_total_size+= dap_tsd_size( l_tsd);

                }else if ( strcmp( a_argv[l_arg_index],"-flags_unset" )==0){   // Flags
                    char ** l_str_flags = NULL;
                    l_str_flags = dap_strsplit( l_arg_param,",",0xffff );
                    uint16_t l_flags = 0;
                    while (l_str_flags && *l_str_flags ){
                        uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_str_flags);
                        if ( l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Flag can't be \"%s\"",*l_str_flags);
                            return -20;
                        }
                        l_flags |= l_flag;
                        l_str_flags++;
                    }
                    // Add flags as unset_flags TDS section
                    dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS, l_flags);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);

               }else if ( strcmp( a_argv[l_arg_index],"-signs" )==0){
                    dap_cert_parse_str_list(l_arg_param, &l_certs, &l_certs_count);
                    if(!l_certs_count) {
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "token_update command requres at least one valid certificate to sign the basic transaction of emission");
                        return -10;
                    }
                } else if ( strcmp( a_argv[l_arg_index],"-total_supply" )==0){ // Total supply
                    uint128_t l_param_value = dap_chain_balance_scan(l_arg_param);
                    dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY, l_param_value);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-total_signs_valid" )==0){ // Signs valid
                    uint16_t l_param_value = (uint16_t)atoi(l_arg_param);
                    l_signs_total = l_param_value;
                    dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID, l_param_value);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-datum_type_allowed_add" )==0){ // Datum type allowed add
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-datum_type_allowed_remove" )==0){ // Datum type allowed remove
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-datum_type_blocked_add" )==0){ // Datum type blocked add
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-datum_type_blocked_remove" )==0){ // Datum type blocked remove
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_receiver_allowed_add" )==0){ // TX Receiver add
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_receiver_allowed_remove" )==0){ // TX Receiver remove
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_receiver_blocked_add" )==0){ // TX Receiver blocked add
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_receiver_blocked_remove" )==0){ // TX Receiver blocked remove
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_sender_allowed_add" )==0){ // TX Sender allowed add
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_sender_allowed_remove" )==0){ // TX Sender allowed remove
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_sender_blocked_add" )==0){  // TX Sender blocked add
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_sender_blocked_remove" )==0){  // TX Sender blocked remove
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                } else if (strcmp( a_argv[l_arg_index], "-chain") && strcmp( a_argv[l_arg_index], "-net") &&
                           strcmp( a_argv[l_arg_index], "-token") && !strcmp( a_argv[l_arg_index], "-type")) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Unknown param \"%s\"",a_argv[l_arg_index]);
                    return -20;
                }
                l_arg_index+=2;
            }

            if (!l_tsd_total_size) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "No valid params to update");
                return -21;
            }

            // If we have more certs than we need signs - use only first part of the list
            if(l_certs_count > l_signs_total)
                l_certs_count = l_signs_total;

            // Create new datum token
            l_datum_token_update = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t)+l_tsd_total_size ) ;
            l_datum_token_update->type = DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE;
            dap_snprintf(l_datum_token_update->ticker, sizeof(l_datum_token_update->ticker), "%s", l_ticker);
            l_datum_token_update->header_private_update.tsd_total_size = l_tsd_total_size;

            // Sign header with all certificates in the list and add signs to the end of token update
            // Important:
            for(size_t i = 0; i < l_certs_count; i++) {
                dap_sign_t * l_sign = dap_cert_sign(l_certs[i],
                        l_datum_token_update,
                        sizeof(l_datum_token_update->header_private),
                        0);
                size_t l_sign_size = dap_sign_get_size(l_sign);
                l_datum_token_update = DAP_REALLOC(l_datum_token_update, sizeof(dap_chain_datum_token_t) +l_tsd_total_size + l_datum_data_offset + l_sign_size);
                memcpy(l_datum_token_update->data_n_tsd + l_datum_data_offset, l_sign, l_sign_size);
                l_datum_data_offset += l_sign_size;
                DAP_DELETE(l_sign);
            }

            // Add TSD sections in the end
            for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
                dap_tsd_t * l_tsd = (dap_tsd_t *) l_iter->data;
                size_t l_tsd_size = dap_tsd_size( l_tsd);
                memcpy(l_datum_token_update->data_n_tsd + l_datum_data_offset, l_tsd, l_tsd_size);
                l_datum_data_offset += l_tsd_size;
            }


        }break;

        default:
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "Unknown token type");
            return -8;
    }

    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE, l_datum_token_update,
            sizeof(l_datum_token_update->header_private) + l_datum_data_offset);
    size_t l_datum_size = dap_chain_datum_size(l_datum);

    // Calc datum's hash
    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(l_datum, l_datum_size, &l_key_hash);
    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    char * l_key_str_base58 = dap_enc_base58_encode_hash_to_str(&l_key_hash);

    // Add datum to mempool with datum_token_update hash as a key
    char * l_gdb_group_mempool;
    if(l_chain) {
        l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
    }
    else {
        l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);

    }
    if(dap_chain_global_db_gr_set(dap_strdup(l_key_str), (uint8_t *) l_datum, l_datum_size, l_gdb_group_mempool)) {
        if(!dap_strcmp(l_hash_out_type,"hex"))
            dap_chain_node_cli_set_reply_text(a_str_reply, "datum %s with token update %s is placed in datum pool ", l_key_str, l_ticker);
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "datum %s with token update %s is placed in datum pool ", l_key_str_base58, l_ticker);
        DAP_DELETE(l_datum);
        DAP_DELETE(l_datum_token_update);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DELETE(l_key_str);
        DAP_DELETE(l_key_str_base58);
        return 0;
    }
    else {
        if(!dap_strcmp(l_hash_out_type,"hex"))
            dap_chain_node_cli_set_reply_text(a_str_reply, "datum tx %s is not placed in datum pool ", l_key_str);
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "datum tx %s is not placed in datum pool ", l_key_str_base58);
        DAP_DELETE(l_datum);
        DAP_DELETE(l_datum_token_update);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DELETE(l_key_str);
        DAP_DELETE(l_key_str_base58);
        return -2;
    }
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
int com_token_decl(int a_argc, char ** a_argv, char ** a_str_reply)
{
    int l_arg_index = 1;

    const char * l_type_str = NULL;
    uint16_t l_type = DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE;

    const char * l_ticker = NULL;

    const char * l_total_supply_str = NULL;
    uint64_t l_total_supply = 0;

    const char * l_signs_emission_str = NULL;
    uint16_t l_signs_emission = 0;

    const char * l_signs_total_str = NULL;
    uint16_t l_signs_total = 0;

    const char * l_certs_str = NULL;

    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net);
    if(!l_net)
        return -1;
    else {
        if(*a_str_reply) {
            DAP_DELETE(*a_str_reply);
            *a_str_reply = NULL;
        }
    }
    // Token ticker
    l_arg_index=dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_ticker);
    // Check for ticker
    if(!l_ticker) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_decl requires parameter 'token'");
        return -2;
    }

    // Token type
    l_arg_index=dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-type", &l_type_str);

    if (l_type_str) {
        if (strcmp( l_type_str, "private") == 0){
            l_type = DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL;
        }else if (strcmp( l_type_str, "private_simple") == 0){
            l_type = DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE;
        }else if (strcmp( l_type_str, "public_simple") == 0){
            l_type = DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC;
        }
    }

    dap_chain_datum_token_t * l_datum_token = NULL;
    size_t l_datum_data_offset = 0;

    switch(l_type){
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:{
            dap_list_t *l_tsd_list = dap_list_alloc();
            size_t l_tsd_total_size = 0;
            uint16_t l_flags = 0;
            char ** l_str_flags = NULL;
            l_arg_index++;
            while (l_arg_index<a_argc-1){
                char * l_arg_param=  a_argv[l_arg_index+1];
                if ( strcmp(a_argv[l_arg_index],"-flags" )==0){   // Flags
                     l_str_flags = dap_strsplit( l_arg_param,",",0xffff );
                     while (l_str_flags && *l_str_flags){
                         uint16_t l_flag = dap_chain_datum_token_flag_from_str(*l_str_flags);
                         if ( l_flag == DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED ){
                             dap_chain_node_cli_set_reply_text(a_str_reply, "Flag can't be \"%s\"",*l_str_flags);
                             return -20;
                         }
                         l_flags |= (1<<l_flag);
                         l_str_flags++;
                     }
                } else if ( strcmp( a_argv[l_arg_index],"-total_supply" )==0){ // Total supply
                    uint128_t l_param_value = dap_chain_balance_scan(l_arg_param);
                    dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY, l_param_value);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-total_signs_valid" )==0){ // Signs valid
                    uint16_t l_param_value = (uint16_t)atoi(l_arg_param);
                    l_signs_total = l_param_value;
                    dap_tsd_t * l_tsd = dap_tsd_create_scalar(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID, l_param_value);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-signs" )==0){
                    dap_cert_parse_str_list(l_arg_param, &l_certs, &l_certs_count);
                    if(!l_certs_count) {
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "token_decl command requres at least one valid certificate to sign the basic transaction of emission");
                        return -10;
                    }
                }else if ( strcmp( a_argv[l_arg_index],"-datum_type_allowed" )==0){
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-datum_type_blocked" )==0){
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_receiver_allowed" )==0){
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_receiver_blocked" )==0){
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_sender_allowed" )==0){
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else if ( strcmp( a_argv[l_arg_index],"-tx_sender_blocked" )==0){
                    dap_tsd_t * l_tsd = dap_tsd_create_string(
                                                            DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD, l_arg_param);
                    dap_list_append( l_tsd_list, l_tsd);
                    l_tsd_total_size+= dap_tsd_size( l_tsd);
                }else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Unknown param \"%s\"",a_argv[l_arg_index]);
                    return -20;
                }
                l_arg_index+=2;
            }


            // If we have more certs than we need signs - use only first part of the list
            if(l_certs_count > l_signs_total)
                l_certs_count = l_signs_total;

            log_it(L_DEBUG,"Prepeared TSD sections on %zd total size", l_tsd_total_size);
            // Create new datum token
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t)+l_tsd_total_size ) ;
            l_datum_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL;
            dap_snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
            l_datum_token->header_private_decl.flags = l_flags;
            log_it(L_DEBUG,"Token declaration '%s' initialized", l_datum_token->ticker);

            // Sign header with all certificates in the list and add signs to the end of ticker declaration
            // Important:
            for(size_t i = 0; i < l_certs_count; i++) {
                dap_sign_t * l_sign = dap_cert_sign(l_certs[i],
                        l_datum_token,
                        sizeof(l_datum_token->header_private),
                        0);
                size_t l_sign_size = dap_sign_get_size(l_sign);
                l_datum_token = DAP_REALLOC(l_datum_token, sizeof(dap_chain_datum_token_t) +l_tsd_total_size + l_datum_data_offset + l_sign_size);
                memcpy(l_datum_token->data_n_tsd + l_datum_data_offset, l_sign, l_sign_size);
                l_datum_data_offset += l_sign_size;
                DAP_DELETE(l_sign);
                log_it(L_DEBUG,"<-- Signed with '%s'", l_certs[i]->name);
            }

            // Add TSD sections in the end
            for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
                dap_tsd_t * l_tsd = (dap_tsd_t *) l_iter->data;
                if (l_tsd == NULL){
                    log_it(L_ERROR, "NULL tsd in list!");
                    continue;
                }
                switch (l_tsd->type){
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: {
                        char *l_balance = dap_chain_balance_print(dap_tsd_get_scalar(l_tsd, uint128_t));
                        log_it(L_DEBUG,"== TOTAL_SUPPLY: %s", l_balance);
                        DAP_DELETE(l_balance);
                    }
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID:
                        log_it(L_DEBUG,"== TOTAL_SIGNS_VALID: %u",
                                dap_tsd_get_scalar(l_tsd,uint16_t) );
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD:
                        log_it(L_DEBUG,"== DATUM_TYPE_ALLOWED_ADD: %s",
                               dap_tsd_get_string_const(l_tsd) );
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                        log_it(L_DEBUG,"== TX_SENDER_ALLOWED_ADD: %s",
                                dap_tsd_get_string_const(l_tsd) );
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                        log_it(L_DEBUG,"== TX_SENDER_BLOCKED_ADD: %s",
                                dap_tsd_get_string_const(l_tsd) );
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                        log_it(L_DEBUG,"== TX_RECEIVER_ALLOWED_ADD: %s",
                                dap_tsd_get_string_const(l_tsd) );
                    break;
                    case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                        log_it(L_DEBUG,"== TX_RECEIVER_BLOCKED_ADD: %s",
                                dap_tsd_get_string_const(l_tsd) );
                    break;
                    default: log_it(L_DEBUG, "== 0x%04X: binary data %u size ",l_tsd->type, l_tsd->size );
                }
                size_t l_tsd_size = dap_tsd_size( l_tsd);
                memcpy(l_datum_token->data_n_tsd + l_datum_data_offset, l_tsd, l_tsd_size);
                l_datum_token->header_private_decl.tsd_total_size += l_tsd_size;
                l_datum_data_offset += l_tsd_size;
            }


        }break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:{
            // Total supply value
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-total_supply", &l_total_supply_str);


            // Certificates thats will be used to sign currend datum token
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-certs", &l_certs_str);

            // Signs number thats own emissioncan't find
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-signs_total", &l_signs_total_str);

            // Signs minimum number thats need to authorize the emission
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-signs_emission", &l_signs_emission_str);


            if(!l_total_supply_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "token_create requires parameter '-total_supply'");
                return -3;
            } else {
                char * l_tmp = NULL;
                if((l_total_supply = strtoull(l_total_supply_str, &l_tmp, 10)) == 0) {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "token_create requires parameter '-total_supply' to be unsigned integer value that fits in 8 bytes");
                    return -4;
                }
            }



            // Signs emission
            if(!l_signs_emission_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "token_create requires parameter '-signs_emission'");
                return -5;
            } else {
                char * l_tmp = NULL;
                if((l_signs_emission = (uint16_t) strtol(l_signs_emission_str, &l_tmp, 10)) == 0) {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "token_create requires parameter 'signs_emission' to be unsigned integer value that fits in 2 bytes");
                    return -6;
                }
            }

            // Signs total
            if(!l_signs_total_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "token_decl requires parameter 'signs_total'");
                return -7;
            } else {
                char * l_tmp = NULL;
                if((l_signs_total = (uint16_t) strtol(l_signs_total_str, &l_tmp, 10)) == 0) {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "token_create requires parameter 'signs_total' to be unsigned integer value that fits in 2 bytes");
                    return -8;
                }
            }

            // Check certs list
            if(!l_certs_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "token_decl requires parameter 'certs'");
                return -9;
            }

            // Load certs lists
            dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
            if(!l_certs_count) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "token_decl command requres at least one valid certificate to sign the basic transaction of emission");
                return -10;
            }

            // If we have more certs than we need signs - use only first part of the list
            if(l_certs_count > l_signs_total)
                l_certs_count = l_signs_total;

            // Create new datum token
            l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t));
            l_datum_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE;
            dap_snprintf(l_datum_token->ticker, sizeof(l_datum_token->ticker), "%s", l_ticker);
            l_datum_token->header_private.total_supply = l_total_supply;
            l_datum_token->header_private.signs_total = l_signs_total;
            l_datum_token->header_private.signs_valid = l_signs_emission;

            // Sign header with all certificates in the list and add signs to the end of ticker declaration
            // Important:
            for(size_t i = 0; i < l_certs_count; i++) {
                dap_sign_t * l_sign = dap_cert_sign(l_certs[i],
                        l_datum_token,
                        sizeof(l_datum_token->header_private),
                        0);
                size_t l_sign_size = dap_sign_get_size(l_sign);
                l_datum_token = DAP_REALLOC(l_datum_token, sizeof(dap_chain_datum_token_t) + l_datum_data_offset + l_sign_size);
                memcpy(l_datum_token->data_n_tsd + l_datum_data_offset, l_sign, l_sign_size);
                l_datum_data_offset += l_sign_size;
                DAP_DELETE(l_sign);
            }
        }break;
        default:
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "Unknown token type");
            return -8;
    }

    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_DECL, l_datum_token,
            sizeof(*l_datum_token) + l_datum_data_offset);
    size_t l_datum_size = dap_chain_datum_size(l_datum);

    // Calc datum's hash
    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(l_datum, l_datum_size, &l_key_hash);
    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    char * l_key_str_base58 = dap_enc_base58_encode_hash_to_str(&l_key_hash);

    // Add datum to mempool with datum_token hash as a key
    char * l_gdb_group_mempool;
    if(l_chain) {
        l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
    }
    else {
        l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TOKEN);

    }
    int l_ret = 0;
    if(dap_chain_global_db_gr_set(dap_strdup(l_key_str), (uint8_t *) l_datum, l_datum_size, l_gdb_group_mempool)) {
        if(!dap_strcmp(l_hash_out_type,"hex"))
            dap_chain_node_cli_set_reply_text(a_str_reply, "datum %s with token %s is placed in datum pool ", l_key_str, l_ticker);
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "datum %s with token %s is placed in datum pool ", l_key_str_base58, l_ticker);
    }
    else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "datum tx %s is not placed in datum pool ", l_key_str_base58);
        DAP_DELETE(l_datum);
        l_ret = -2;
    }
    return l_ret;
}

/**
 * @brief com_token_emit
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
int com_token_emit(int a_argc, char ** a_argv, char ** a_str_reply)
{
    int arg_index = 1;
    const char *str_tmp = NULL;
    char *str_reply_tmp = NULL;
    uint64_t l_emission_value = 0;

    const char * l_ticker = NULL;

    const char * l_addr_str = NULL;

    const char * l_emission_hash_str = NULL;
    char * l_emission_hash_str_new = NULL;
    dap_chain_hash_fast_t l_emission_hash={0};
    dap_chain_datum_token_emission_t * l_emission = NULL;
    char * l_emission_hash_str_base58 = NULL;

    const char * l_certs_str = NULL;

    dap_cert_t ** l_certs = NULL;
    size_t l_certs_size = 0;

    const char * l_chain_emission_str = NULL;
    dap_chain_t * l_chain_emission = NULL;

    const char * l_chain_base_tx_str = NULL;
    dap_chain_t * l_chain_base_tx = NULL;

    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,a_argc,a_argv,a_str_reply,NULL, &l_net);
    if( ! l_net) { // Can't find such network
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "token_create requires parameter '-net' to be valid chain network name");
        return -43;
    }

    // Wallet address that recieves the emission
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-emission", &l_emission_hash_str);

    // Wallet address that recieves the emission
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);

    // Wallet address that recieves the emission
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);

    // Token ticker
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-token", &l_ticker);

    // Token emission
    if(dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-emission_value", &str_tmp)) {
        l_emission_value = strtoull(str_tmp, NULL, 10);
    }

    if(!l_emission_value) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_emit requires parameter '-emission_value'");
        return -1;
    }

    if(!l_addr_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_emit requires parameter '-addr'");
        return -2;
    }

    if(!l_ticker) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_emit requires parameter '-token'");
        return -3;
    }

    if(!l_certs_str && !l_emission_hash_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_emit requires parameter '-certs' or '-emission' ");
        return -4;
    }


    if (l_emission_hash_str){// Load emission
        l_emission_hash_str_base58 = dap_enc_base58_encode_hash_to_str(&l_emission_hash);
        if (dap_chain_hash_fast_from_str( l_emission_hash_str,&l_emission_hash) == 0 ){
            l_emission = dap_chain_ledger_token_emission_find(l_net->pub.ledger,l_ticker,&l_emission_hash);
            if (! l_emission){
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can' find emission with hash \"%s\" for token %s on network %s",
                                                  l_emission_hash_str, l_ticker, l_net->pub.name);
                return -32;
            }
        }else{
            dap_chain_node_cli_set_reply_text(a_str_reply, "Hash \"%s\" for parameter '-emission' is invalid", l_emission_hash_str);
            return -31;
        }
    }else if (l_certs_str){ // Load certs
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_size);

        if(!l_certs_size) {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "token_emit command requres at least one valid certificate to sign the basic transaction of emission");
            return -5;
        }
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-chain_emission", &l_chain_emission_str);
        if(l_chain_emission_str) {
            if((l_chain_emission = dap_chain_net_get_chain_by_name(l_net, l_chain_emission_str)) == NULL) { // Can't find such chain
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "token_create requires parameter '-chain_emission' to be valid chain name in chain net %s",
                        l_net->pub.name);
                return -45;
            }
        }
    }



    dap_chain_addr_t * l_addr = dap_chain_addr_from_str(l_addr_str);

    if(!l_addr) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "address \"%s\" is invalid", l_addr_str);
        return -4;
    }

    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-chain_base_tx", &l_chain_base_tx_str);

    if(l_chain_base_tx_str) {
        if((l_chain_base_tx = dap_chain_net_get_chain_by_name(l_net, l_chain_base_tx_str)) == NULL) { // Can't find such chain
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "token_create requires parameter '-chain_base_tx' to be valid chain name in chain net %s", l_net->pub.name);
            DAP_DELETE(l_addr);
            return -47;
        }
    }

    // Get groups for the chains
    char *l_gdb_group_mempool_base_tx;

    if(l_chain_base_tx) {
        l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool(l_chain_base_tx);
    }
    else {
        l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    //char * l_gdb_group_mempool_emission = dap_chain_net_get_gdb_group_mempool(l_chain_emission);
    //char * l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool(l_chain_base_tx);

    // Create emission datum
    // then create datum in memory
    if(!l_emission){
        char * l_gdb_group_mempool_emission;
        if(l_chain_emission) {
            l_gdb_group_mempool_emission = dap_chain_net_get_gdb_group_mempool(l_chain_emission);
        }
        else {
            l_gdb_group_mempool_emission = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_EMISSION);
        }
        size_t l_emission_size = sizeof(l_emission->hdr) +
                sizeof(l_emission->data.type_auth.signs_count);

        l_emission = DAP_NEW_Z_SIZE(dap_chain_datum_token_emission_t, l_emission_size);
        strncpy(l_emission->hdr.ticker, l_ticker, sizeof(l_emission->hdr.ticker) - 1);
        l_emission->hdr.value = l_emission_value;
        l_emission->hdr.type = DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH;
        memcpy(&l_emission->hdr.address, l_addr, sizeof(l_emission->hdr.address));
        // Then add signs
        size_t l_offset = 0;
        for(size_t i = 0; i < l_certs_size; i++) {
            dap_sign_t * l_sign = dap_cert_sign(l_certs[i], &l_emission->hdr,
                    sizeof(l_emission->hdr), 0);
            size_t l_sign_size = dap_sign_get_size(l_sign);
            l_emission_size += l_sign_size;
            l_emission = DAP_REALLOC(l_emission, l_emission_size);
            memcpy(l_emission->data.type_auth.signs + l_offset, l_sign, l_sign_size);
            l_offset += l_sign_size;
            DAP_DELETE(l_sign);
        }

        // Produce datum
        dap_chain_datum_t * l_datum_emission = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_EMISSION,
                l_emission,
                l_emission_size);
        size_t l_datum_emission_size = sizeof(l_datum_emission->header) + l_datum_emission->header.data_size;

        // Calc token's hash
        //dap_chain_hash_fast_t l_emission_hash;
        dap_hash_fast(l_emission, l_emission_size, &l_emission_hash);
        l_emission_hash_str = l_emission_hash_str_new = dap_chain_hash_fast_to_str_new(&l_emission_hash);
        l_emission_hash_str_base58 = dap_enc_base58_encode_hash_to_str(&l_emission_hash);

        // Delete token emission
        DAP_DEL_Z(l_emission);
//    // Calc datum's hash
//    dap_chain_hash_fast_t l_datum_emission_hash;
//    dap_hash_fast(l_datum_emission, l_datum_emission_size, (uint8_t*) &l_datum_emission_hash);
//    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_datum_emission_hash);

        // Add to mempool emission token
        if(dap_chain_global_db_gr_set(dap_strdup(l_emission_hash_str_new), (uint8_t *) l_datum_emission, l_datum_emission_size
                , l_gdb_group_mempool_emission)) {
            if(!dap_strcmp(l_hash_out_type,"hex"))
                str_reply_tmp = dap_strdup_printf("datum emission %s is placed in datum pool ", l_emission_hash_str_new);
            else
                str_reply_tmp = dap_strdup_printf("datum emission %s is placed in datum pool ", l_emission_hash_str_base58);
        }
        else {
            if(!dap_strcmp(l_hash_out_type,"hex"))
                dap_chain_node_cli_set_reply_text(a_str_reply, "datum emission %s is not placed in datum pool ", l_emission_hash_str_new);
            else
                dap_chain_node_cli_set_reply_text(a_str_reply, "datum emission %s is not placed in datum pool ", l_emission_hash_str_base58);
            DAP_DEL_Z(l_emission_hash_str_new);
            l_emission_hash_str = NULL;
            DAP_DEL_Z(l_emission_hash_str_base58);
            DAP_DEL_Z(l_datum_emission);
            return -1;
        }
        l_datum_emission = NULL;
        l_emission = NULL;
    }

    // create first transaction (with tx_token)
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    dap_chain_hash_fast_t l_tx_prev_hash = { 0 };
    // create items
    dap_chain_tx_token_t *l_tx_token = dap_chain_datum_tx_item_token_create(&l_emission_hash, l_ticker);
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, 0);
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(l_addr, l_emission_value);

    // pack items to transaction
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_tx_token);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);

    // Base tx don't need signature items but let it be
    if (l_certs){
        // Sign all that we have with certs
        for(size_t i = 0; i < l_certs_size; i++) {
            if(dap_chain_datum_tx_add_sign_item(&l_tx, l_certs[i]->enc_key) < 0) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "No private key for certificate=%s",
                        l_certs[i]->name);
                DAP_DELETE(l_addr);
                return -3;
            }
        }
    }

    if (l_certs)
        DAP_DEL_Z(l_certs);

    DAP_DEL_Z(l_tx_token);
    DAP_DEL_Z(l_in);
    DAP_DEL_Z(l_out);

    DAP_DEL_Z(l_emission_hash_str_new);
    l_emission_hash_str = NULL;
    DAP_DEL_Z(l_emission_hash_str_base58);

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);

    // Pack transaction into the datum
    dap_chain_datum_t * l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);

    // use l_tx hash for compatible with utho hash
    //dap_hash_fast(l_tx, l_tx_size, &l_key_hash); //dap_hash_fast(l_datum_tx, l_datum_tx_size, &l_key_hash);
    // calc datum hash
    dap_chain_hash_fast_t l_datum_tx_hash;
    dap_hash_fast(l_datum_tx, l_datum_tx_size,  &l_datum_tx_hash);
    char * l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_datum_tx_hash);
    char * l_tx_hash_str_base58 = dap_enc_base58_encode_hash_to_str(&l_datum_tx_hash);
    DAP_DEL_Z(l_tx);

    // Add to mempool tx token
    if(dap_chain_global_db_gr_set(dap_strdup(l_tx_hash_str), l_datum_tx, l_datum_tx_size
            , l_gdb_group_mempool_base_tx)) {
        if(!dap_strcmp(l_hash_out_type,"hex"))
            dap_chain_node_cli_set_reply_text(a_str_reply, "%s\ndatum tx %s is placed in datum pool ", str_reply_tmp, l_tx_hash_str);
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "%s\ndatum tx %s is placed in datum pool ", str_reply_tmp, l_tx_hash_str_base58);
        DAP_DEL_Z(l_tx_hash_str);
        DAP_DEL_Z(l_tx_hash_str_base58);
    } else {
        if(!dap_strcmp(l_hash_out_type,"hex"))
            dap_chain_node_cli_set_reply_text(a_str_reply, "%s\ndatum tx %s is not placed in datum pool ", str_reply_tmp, l_emission_hash_str);
        else
            dap_chain_node_cli_set_reply_text(a_str_reply, "%s\ndatum tx %s is not placed in datum pool ", str_reply_tmp, l_tx_hash_str_base58);
        DAP_DEL_Z(l_tx_hash_str);
        DAP_DEL_Z(l_tx_hash_str_base58);

        return -2;
    }
    DAP_DELETE(str_reply_tmp);
    DAP_DELETE(l_addr);
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
int com_tx_cond_create(int a_argc, char ** a_argv, char **a_str_reply)
{
    (void) a_argc;
    int arg_index = 1;
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    const char * l_token_ticker = NULL;
    const char * l_wallet_from_str = NULL;
    const char * l_wallet_to_str = NULL; //l_addr_to_str
    const char * l_value_datoshi_str = NULL;
    const char * l_net_name = NULL;
    const char * l_unit_str = NULL;
    const char * l_service_str = NULL;
    uint64_t l_value_datoshi = 0;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    // Token ticker
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_ticker);
    // Wallet name - from
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-wallet_f", &l_wallet_from_str);
    // Wallet address - to
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-wallet_t", &l_wallet_to_str);
    // value datoshi
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_datoshi_str);
    // net
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // unit
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-unit", &l_unit_str);
    // service
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-service", &l_service_str);

    if(!l_token_ticker) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-token'");
        return -1;
    }
    if(!l_wallet_from_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-wallet_f'");
        return -2;
    }
    if(!l_wallet_to_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-wallet_t'");
        return -3;
    }
    if(!l_value_datoshi_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-value'");
        return -4;
    }

    if(!l_net_name) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-net'");
        return -5;
    }
    if(!l_unit_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-unit={mb|kb|b|sec|day}'");
        return -6;
    }
    if(!l_service_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_cond_create requires parameter '-service={vpn}'");
        return -7;
    }
    dap_chain_net_srv_uid_t l_srv_uid = {};
    if(!dap_strcmp(l_service_str, "vpn"))
        l_srv_uid.uint64 = 0x0000000000000001;
    //dap_chain_addr_t *addr_to = dap_chain_addr_from_str(l_addr_to_str);
    if(!l_srv_uid.uint64) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't recognize service='%s' unit must look like {vpn}",
                l_service_str);
        return -8;
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = SERV_UNIT_UNDEFINED };
    if(!dap_strcmp(l_unit_str, "mb"))
        l_price_unit.enm = SERV_UNIT_MB;
    else if(!dap_strcmp(l_unit_str, "sec"))
        l_price_unit.enm = SERV_UNIT_SEC;
    else if(!dap_strcmp(l_unit_str, "day"))
        l_price_unit.enm = SERV_UNIT_DAY;
    else if(!dap_strcmp(l_unit_str, "kb"))
        l_price_unit.enm = SERV_UNIT_KB;
    else if(!dap_strcmp(l_unit_str, "b"))
        l_price_unit.enm = SERV_UNIT_B;

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't recognize unit='%s' unit must look like {mb|kb|b|sec|day}",
                l_unit_str);
        return -9;
    }

    l_value_datoshi = strtoll(l_value_datoshi_str, NULL, 10);
    if(!l_value_datoshi) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't recognize value='%s' as a number", l_value_datoshi_str);
        return -10;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if(!l_net) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't find net '%s'", l_net_name);
        return -11;
    }
    dap_chain_wallet_t *l_wallet_from = dap_chain_wallet_open(l_wallet_from_str, c_wallets_path);
    if(!l_wallet_from) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't open wallet '%s'", l_wallet_from);
        return -12;
    }
    dap_chain_wallet_t *l_wallet_cond = dap_chain_wallet_open(l_wallet_to_str, c_wallets_path);
    if(!l_wallet_to_str) {
        dap_chain_wallet_close(l_wallet_from);
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't open wallet '%s'", l_wallet_to_str);
        return -13;
    }
    dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet_from, 0);
    dap_enc_key_t *l_key_cond = dap_chain_wallet_get_key(l_wallet_cond, 0);


    // where to take coins for service
    const dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(l_wallet_from, l_net->pub.id);
    // who will be use service, usually the same address (addr_from)
    //const dap_chain_addr_t *l_addr_cond = dap_chain_wallet_get_addr(l_wallet_cond, l_net->pub.id);


/*    //dap_chain_net_srv_abstract_t l_cond;
//    dap_chain_net_srv_abstract_set(&l_cond, SERV_CLASS_PERMANENT, SERV_ID_VPN, l_value, SERV_UNIT_MB,
//            "test vpn service");
//    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name((const char *) c_net_name);

    int res = dap_chain_mempool_tx_create_cond(NULL, l_key, l_key_cond, addr_from,
            addr_cond,
            NULL, l_token_ticker, l_value, 0, (const void*) &l_cond, sizeof(dap_chain_net_srv_abstract_t));
*/

    dap_chain_hash_fast_t *l_tx_cond_hash = dap_chain_mempool_tx_create_cond(l_net, l_key_from, l_key_cond, l_addr_from, l_token_ticker,
            l_value_datoshi, 0, l_price_unit, l_srv_uid, 0, NULL, 0);

    dap_chain_wallet_close(l_wallet_from);
    dap_chain_wallet_close(l_wallet_cond);

    char *l_hash_str;
    if(!dap_strcmp(l_hash_out_type, "hex")) {
        l_hash_str = l_tx_cond_hash ? dap_chain_hash_fast_to_str_new(l_tx_cond_hash) : NULL;
    }
    else {
        l_hash_str = l_tx_cond_hash ? dap_enc_base58_encode_hash_to_str(l_tx_cond_hash) : NULL;
    }

    /*dap_chain_node_cli_set_reply_text(str_reply, "cond create=%s\n",
            (res == 0) ? "Ok" : (res == -2) ? "False, not enough funds for service fee" : "False");
    return res;*/

    int l_ret;
    // example: cond create succefully hash=0x4AA303EB7C10430C0AAC42F399D265BC7DD09E3983E088E02B8CED38DA22EDA9
    if(l_hash_str){
        dap_chain_node_cli_set_reply_text(a_str_reply, "cond create succefully hash=%s\n", l_hash_str);
        l_ret = 0;
    }
    else{
        dap_chain_node_cli_set_reply_text(a_str_reply, "cond can't create\n");
        l_ret = -1;
    }

    DAP_DELETE(l_hash_str);
    return  l_ret;
}

/**
 * @brief com_mempool_add_ca
 * @details Place public CA into the mempool
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
int com_mempool_add_ca(int a_argc,  char ** a_argv, char ** a_str_reply)
{
    int arg_index = 1;

    // Read params
    const char * l_ca_name = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;

    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-ca_name", &l_ca_name);
    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,a_argc, a_argv, a_str_reply, &l_chain, &l_net);
    if ( l_net == NULL ){
        return -1;
    } else if (a_str_reply && *a_str_reply) {
        DAP_DELETE(*a_str_reply);
        *a_str_reply = NULL;
    }

    // Chech for chain if was set or not
    if ( l_chain == NULL){
       // If wasn't set - trying to auto detect
        l_chain = dap_chain_net_get_chain_by_chain_type( l_net, CHAIN_TYPE_CA );
        if (l_chain == NULL) { // If can't auto detect
            // clean previous error code
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "No chains for CA datum in network \"%s\"", l_net->pub.name );
            return -2;
        }
    }
    // Check if '-ca_name' wasn't specified
    if (l_ca_name == NULL){
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "mempool_add_ca_public requires parameter '-ca_name' to specify the certificate name");
        return -3;
    }

    // Find certificate with specified key
    dap_cert_t * l_cert = dap_cert_find_by_name( l_ca_name );
    if( l_cert == NULL ){
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Can't find \"%s\" certificate", l_ca_name );
        return -4;
    }
    if( l_cert->enc_key == NULL ){
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Corrupted certificate \"%s\" without keys certificate", l_ca_name );
        return -5;
    }

    if ( l_cert->enc_key->priv_key_data_size || l_cert->enc_key->priv_key_data){
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Certificate \"%s\" has private key data. Please export public only key certificate without private keys", l_ca_name );
        return -6;
    }

    // Serialize certificate into memory
    uint32_t l_cert_serialized_size = 0;
    byte_t * l_cert_serialized = dap_cert_mem_save( l_cert, &l_cert_serialized_size );
    if( l_cert_serialized == NULL){
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Can't serialize in memory certificate \"%s\"", l_ca_name );
        return -7;
    }
    // Now all the chechs passed, forming datum for mempool
    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CA, l_cert_serialized , l_cert_serialized_size);
    DAP_DELETE( l_cert_serialized);
    if( l_datum == NULL){
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Can't produce datum from certificate \"%s\"", l_ca_name );
        return -7;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum,l_chain);
    if (l_hash_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Datum %s was successfully placed to mempool", l_hash_str);
        DAP_DELETE(l_hash_str);
        return 0;
    } else {
        dap_chain_node_cli_set_reply_text(a_str_reply,
                "Can't place certificate \"%s\" to mempool", l_ca_name);
        DAP_DELETE( l_datum );
        return -8;
    }
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
int com_tx_create(int argc, char ** argv, char **str_reply)
{
    int arg_index = 1;
//    int cmd_num = 1;
//    const char *value_str = NULL;
    const char *addr_base58_to = NULL;
    const char *addr_base58_fee = NULL;
    const char *str_tmp = NULL;
    const char * l_from_wallet_name = NULL;
    const char * l_token_ticker = NULL;
    const char * l_net_name = NULL;
    const char * l_chain_name = NULL;
    const char * l_tx_num_str = NULL;
    size_t l_tx_num = 0;

    uint64_t value = 0;
    uint64_t value_fee = 0;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-from_wallet", &l_from_wallet_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-to_addr", &addr_base58_to);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-token", &l_token_ticker);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-chain", &l_chain_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-tx_num", &l_tx_num_str);

    if(l_tx_num_str)
        l_tx_num = strtoul(l_tx_num_str, NULL, 10);

    if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-fee", &addr_base58_fee)) {
        if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-value_fee", &str_tmp)) {
            value_fee = strtoull(str_tmp, NULL, 10);
        }
    }
    if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-value", &str_tmp)) {
        value = strtoull(str_tmp, NULL, 10);
    }
    if(!l_from_wallet_name) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter '-from_wallet'");
        return -1;
    }
    if(!addr_base58_to) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter '-to_addr'");
        return -1;
    }
    if(!value) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter '-value'");
        return -1;
    }
    if(addr_base58_fee && !value_fee) {
        dap_chain_node_cli_set_reply_text(str_reply,
                "tx_create requires parameter '-value_fee' if '-fee' is specified");
        return -1;
    }

    if(!l_net_name) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter '-net'");
        return -1;
    }
    dap_chain_net_t * l_net = dap_chain_net_by_name(l_net_name);
    dap_ledger_t *l_ledger = l_net ? l_net->pub.ledger : NULL;
    if(l_net == NULL || (l_ledger = dap_chain_ledger_by_net_name(l_net_name)) == NULL) {
        dap_chain_node_cli_set_reply_text(str_reply, "not found net by name '%s'", l_net_name);
        return -1;
    }

    /*    if(!l_chain_name) {
     dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter '-chain'");
     return -1;
     }*/
    dap_chain_t * l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    if(!l_chain) {
        l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    if(!l_chain) {
        dap_chain_node_cli_set_reply_text(str_reply, "not found chain name '%s', try use parameter '-chain'",
                l_chain_name);
        return -1;
    }

    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_from_wallet_name, c_wallets_path);

    if(!l_wallet) {
        dap_chain_node_cli_set_reply_text(str_reply, "wallet %s does not exist", l_from_wallet_name);
        return -1;
    }
    const dap_chain_addr_t *addr_from = (const dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
    dap_chain_addr_t *addr_to = dap_chain_addr_from_str(addr_base58_to);
    dap_chain_addr_t *addr_fee = dap_chain_addr_from_str(addr_base58_fee);

    if(!addr_from) {
        dap_chain_node_cli_set_reply_text(str_reply, "source address is invalid");
        return -1;
    }
    if(!addr_to) {
        dap_chain_node_cli_set_reply_text(str_reply, "destination address is invalid");
        return -1;
    }
    if(addr_base58_fee && !addr_fee) {
        dap_chain_node_cli_set_reply_text(str_reply, "fee address is invalid");
        return -1;
    }

    dap_string_t *string_ret = dap_string_new(NULL);
    //g_string_printf(string_ret, "from=%s\nto=%s\nval=%lld\nfee=%s\nval_fee=%lld\n\n",
    //        addr_base58_from, addr_base58_to, value, addr_base58_fee, value_fee);
    int res = 0;
    if(l_tx_num){
        res = dap_chain_mempool_tx_create_massive(l_chain, dap_chain_wallet_get_key(l_wallet, 0), addr_from,
                               addr_to, addr_fee,
                               l_token_ticker, value, value_fee, l_tx_num);

        dap_string_append_printf(string_ret, "transfer=%s\n",
                (res == 0) ? "Ok" : (res == -2) ? "False, not enough funds for transfer" : "False");
    }else{
        dap_hash_fast_t * l_tx_hash = dap_chain_mempool_tx_create(l_chain, dap_chain_wallet_get_key(l_wallet, 0), addr_from, addr_to,
                addr_fee,
                l_token_ticker, value, value_fee);
        if (l_tx_hash){
            char l_tx_hash_str[80]={[0]='\0'};
            dap_chain_hash_fast_to_str(l_tx_hash,l_tx_hash_str,sizeof (l_tx_hash_str)-1);
            dap_string_append_printf(string_ret, "transfer=Ok\ntx_hash=%s\n",l_tx_hash_str);
            DAP_DELETE(l_tx_hash);
        }else{
            dap_string_append_printf(string_ret, "transfer=False\n");
            res = -1;
        }

    }

    dap_chain_node_cli_set_reply_text(str_reply, string_ret->str);
    dap_string_free(string_ret, false);

    DAP_DELETE(addr_to);
    DAP_DELETE(addr_fee);
    dap_chain_wallet_close(l_wallet);
    return res;
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
int com_tx_verify(int a_argc, char **a_argv, char **a_str_reply)
{
    const char * l_tx_hash_str = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;
    int l_arg_index = 1;

    dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if(!l_tx_hash_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_verify requires parameter '-tx'");
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
    if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash) < 0) {
        l_hex_str_from58 = dap_enc_base58_to_hex_str_from_str(l_tx_hash_str);
        if (!l_hex_str_from58) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Invalid tx hash format, need hex or base58");
            return -3;
        }
    }
    size_t l_tx_size = 0;
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool(l_chain);
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)
            dap_chain_global_db_gr_get(l_hex_str_from58 ? l_hex_str_from58 : l_tx_hash_str, &l_tx_size, l_gdb_group);
    if (!l_tx) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Specified tx not found");
        return -3;
    }
    if (dap_chain_ledger_tx_add_check(l_net->pub.ledger, l_tx)) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Specified tx verify fail!");
        return -4;
    }
    dap_chain_node_cli_set_reply_text(a_str_reply, "Specified tx verified successfully");
    return 0;
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
int com_tx_history(int a_argc, char ** a_argv, char **a_str_reply)
{
    int arg_index = 1;
    const char *l_addr_base58 = NULL;
    const char *l_wallet_name = NULL;
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;
    const char *l_tx_hash_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_base58);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);

    if(!l_addr_base58 && !l_wallet_name && !l_tx_hash_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_history requires parameter '-addr' or '-w' or '-tx'");
        return -1;
    }

    // Select chain network
    if(!l_net_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_history requires parameter '-net'");
        return -2;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "tx_history requires parameter '-net' to be valid chain network name");
            return -3;
        }
    }
    //Select chain emission
    if(!l_chain_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "tx_history requires parameter '-chain'");
        return -4;
    } else {
        if((l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str)) == NULL) { // Can't find such chain
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "tx_history requires parameter '-chain' to be valid chain name in chain net %s",
                    l_net_str);
            return -5;
        }
    }
    //char *l_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
    //const char *l_chain_group = dap_chain_gdb_get_group(l_chain);

    dap_chain_hash_fast_t l_tx_hash;
    if(l_tx_hash_str) {
        if(dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash) < 0) {
            l_tx_hash_str = NULL;
            dap_chain_node_cli_set_reply_text(a_str_reply, "tx hash not recognized");
            return -1;
        }
//        char hash_str[99];
//        dap_chain_hash_fast_to_str(&l_tx_hash, hash_str,99);
//        int gsdgsd=523;
    }
    dap_chain_addr_t *l_addr = NULL;
    // if need addr
    if(!l_tx_hash_str) {
        if(l_wallet_name) {
            const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
            dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
            if(l_wallet) {
                dap_chain_addr_t *l_addr_tmp = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
                l_addr = DAP_NEW_SIZE(dap_chain_addr_t, sizeof(dap_chain_addr_t));
                memcpy(l_addr, l_addr_tmp, sizeof(dap_chain_addr_t));
                dap_chain_wallet_close(l_wallet);
            }
        }
        if(!l_addr && l_addr_base58) {
            l_addr = dap_chain_addr_from_str(l_addr_base58);
        }
        if(!l_addr && !l_tx_hash_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "wallet address not recognized");
            return -1;
        }
    }

    char *l_str_out = l_tx_hash_str ?
                                      dap_db_history_tx(&l_tx_hash, l_chain, l_hash_out_type) :
                                      dap_db_history_addr(l_addr, l_chain, l_hash_out_type);

    char *l_str_ret = NULL;
    if(l_tx_hash_str) {
        l_str_ret = dap_strdup_printf("history for tx hash %s:\n%s", l_tx_hash_str,
                l_str_out ? l_str_out : " empty");
    }
    else if(l_addr) {
        char *l_addr_str = dap_chain_addr_to_str(l_addr);
        l_str_ret = dap_strdup_printf("history for addr %s:\n%s", l_addr_str,
                l_str_out ? l_str_out : " empty");
        DAP_DELETE(l_addr_str);
    }
    dap_chain_node_cli_set_reply_text(a_str_reply, l_str_ret);
    DAP_DELETE(l_str_out);
    DAP_DELETE(l_str_ret);
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
int com_stats(int argc, char ** argv, char **str_reply)
{
    enum {
        CMD_NONE, CMD_STATS_CPU
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    // find  add parameter ('cpu')
    if (dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "cpu", NULL)) {
        cmd_num = CMD_STATS_CPU;
    }
    switch (cmd_num) {
    case CMD_NONE:
    default:
        dap_chain_node_cli_set_reply_text(str_reply, "format of command: stats cpu");
        return -1;
    case CMD_STATS_CPU:
#if (defined DAP_OS_UNIX) || (defined __WIN32)
    {
        dap_cpu_monitor_init();
        dap_usleep(500000);
        char *str_reply_prev = dap_strdup_printf("");
        char *str_delimiter;
        dap_cpu_stats_t s_cpu_stats = dap_cpu_get_stats();
        for (uint32_t n_cpu_num = 0; n_cpu_num < s_cpu_stats.cpu_cores_count; n_cpu_num++) {
            if ((n_cpu_num % 4 == 0) && (n_cpu_num != 0)) {
                str_delimiter = dap_strdup_printf("\n");
            } else if (n_cpu_num == s_cpu_stats.cpu_cores_count - 1) {
                str_delimiter = dap_strdup_printf("");
            } else {
                str_delimiter = dap_strdup_printf(" ");
            }
            *str_reply = dap_strdup_printf("%sCPU-%d: %f%%%s", str_reply_prev, n_cpu_num, s_cpu_stats.cpus[n_cpu_num].load, str_delimiter);
            DAP_DELETE(str_reply_prev);
            DAP_DELETE(str_delimiter);
            str_reply_prev = *str_reply;
        }
        *str_reply = dap_strdup_printf("%s\nTotal: %f%%", str_reply_prev, s_cpu_stats.cpu_summary.load);
        DAP_DELETE(str_reply_prev);
        break;
    }
#else
        dap_chain_node_cli_set_reply_text(str_reply, "only Linux or Windows environment supported");
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
int com_exit(int argc, char ** argv, char **str_reply)
{
    UNUSED(argc);
    UNUSED(argv);
    UNUSED(str_reply);
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
int com_print_log(int argc, char ** argv, char **str_reply)
{
    int arg_index = 1;
    const char * l_str_ts_after = NULL;
    const char * l_str_limit = NULL;
    int64_t l_ts_after = 0;
    long l_limit = 0;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "ts_after", &l_str_ts_after);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "limit", &l_str_limit);

    l_ts_after = (l_str_ts_after) ? strtoll(l_str_ts_after, 0, 10) : -1;
    l_limit = (l_str_limit) ? strtol(l_str_limit, 0, 10) : -1;

    if(l_ts_after < 0 || !l_str_ts_after) {
        dap_chain_node_cli_set_reply_text(str_reply, "requires valid parameter 'l_ts_after'");
        return -1;
    }
    if(!l_limit) {
        dap_chain_node_cli_set_reply_text(str_reply, "requires valid parameter 'limit'");
        return -1;
    }

    // get logs from list
    char *l_str_ret = dap_log_get_item(l_ts_after, (int) l_limit);
    if(!l_str_ret) {
        dap_chain_node_cli_set_reply_text(str_reply, "no logs");
        return -1;
    }
    dap_chain_node_cli_set_reply_text(str_reply, l_str_ret);
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
int cmd_gdb_export(int argc, char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    const char *l_filename = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "filename", &l_filename);
    if (!l_filename) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "gdb_export requires parameter 'filename'");
        return -1;
    }
    const char *l_db_path = dap_config_get_item_str(g_config, "resources", "dap_global_db_path");

    // NB! [TEMPFIX] Temporarily backward-compatible until migration to new databases locations (after updates)
    const char *l_db_driver = dap_config_get_item_str(g_config, "resources", "dap_global_db_driver");
    char l_db_concat[80];
    dap_sprintf(l_db_concat, "%s/gdb-%s", l_db_path, l_db_driver);

    struct dirent *d;
    DIR *dir = opendir(l_db_concat);
    if (!dir) {
        // External "if" to check out old or new path.
        log_it(L_WARNING, "Probably db directory is in old path. Checking out.");
        dir = opendir(l_db_path);
        if (!dir) {
            log_it(L_ERROR, "Can't open db directory");
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't open db directory");
            return -1;
        }
    }
    char l_path[strlen(l_db_path) + strlen(l_filename) + 12];
    memset(l_path, '\0', sizeof(l_path));
    dap_snprintf(l_path, sizeof(l_path), "%s/%s.json", l_db_path, l_filename);
    /*FILE *l_json_file = fopen(l_path, "a");
    if (!l_json_file) {
        log_it(L_ERROR, "Can't open file %s", l_path);
        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't open specified file");
        return -1;
    }*/
    struct json_object *l_json = json_object_new_array();
    for (d = readdir(dir); d; d = readdir(dir)) {
        if (!dap_strcmp(d->d_name, ".") || !dap_strcmp(d->d_name, "..")) {
            continue;
        }
        size_t l_data_size = 0;
        pdap_store_obj_t l_data = dap_chain_global_db_obj_gr_get(NULL, &l_data_size, d->d_name);
        log_it(L_INFO, "Exporting group %s, number of records: %zu", d->d_name, l_data_size);
        if (!l_data_size) {
            continue;
        }

        struct json_object *l_json_group = json_object_new_array();
        struct json_object *l_json_group_inner = json_object_new_object();
        json_object_object_add(l_json_group_inner, "group", json_object_new_string(d->d_name));

        for (size_t i = 0; i < l_data_size; ++i) {
            size_t l_out_size = DAP_ENC_BASE64_ENCODE_SIZE((int64_t)l_data[i].value_len) + 1;
            char *l_value_enc_str = DAP_NEW_Z_SIZE(char, l_out_size);
            //size_t l_enc_size = dap_enc_base64_encode(l_data[i].value, l_data[i].value_len, l_value_enc_str, DAP_ENC_DATA_TYPE_B64);

            struct json_object *jobj = json_object_new_object();
            json_object_object_add(jobj, "id",      json_object_new_int64((int64_t)l_data[i].id));
            json_object_object_add(jobj, "key",     json_object_new_string(l_data[i].key));
            json_object_object_add(jobj, "value",   json_object_new_string(l_value_enc_str));
            json_object_object_add(jobj, "value_len", json_object_new_int64((int64_t)l_data[i].value_len));
            json_object_object_add(jobj, "timestamp", json_object_new_int64((int64_t)l_data[i].timestamp));
            json_object_array_add(l_json_group, jobj);

            DAP_FREE(l_value_enc_str);
        }
        json_object_object_add(l_json_group_inner, "records", l_json_group);
        json_object_array_add(l_json, l_json_group_inner);
        dap_store_obj_free(l_data, l_data_size);
    }
    if (json_object_to_file(l_path, l_json) == -1) {
#if JSON_C_MINOR_VERSION<15
        log_it(L_CRITICAL, "Couldn't export JSON to file, error code %d", errno );
        dap_chain_node_cli_set_reply_text (a_str_reply, "Couldn't export JSON to file, error code %d", errno );
#else
        log_it(L_CRITICAL, "Couldn't export JSON to file, err '%s'", json_util_get_last_err());
        dap_chain_node_cli_set_reply_text(a_str_reply, json_util_get_last_err());
#endif
         json_object_put(l_json);
         return -1;
    }
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
int cmd_gdb_import(int argc, char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    const char *l_filename = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "filename", &l_filename);
    if (!l_filename) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "gdb_import requires parameter 'filename'");
        return -1;
    }
    const char *l_db_path = dap_config_get_item_str(g_config, "resources", "dap_global_db_path");
    char l_path[strlen(l_db_path) + strlen(l_filename) + 12];
    memset(l_path, '\0', sizeof(l_path));
    dap_snprintf(l_path, sizeof(l_path), "%s/%s.json", l_db_path, l_filename);
    struct json_object *l_json = json_object_from_file(l_path);
    if (!l_json) {
#if JSON_C_MINOR_VERSION<15
        log_it(L_CRITICAL, "Import error occured: code %d", errno);
        dap_chain_node_cli_set_reply_text(a_str_reply, "Import error occured: code %d",errno);
#else
        log_it(L_CRITICAL, "Import error occured: %s", json_util_get_last_err());
        dap_chain_node_cli_set_reply_text(a_str_reply, json_util_get_last_err());
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
            l_group_store[j].timestamp = json_object_get_int64(l_ts);
            l_group_store[j].value_len = (uint64_t)json_object_get_int64(l_value_len);
            l_group_store[j].type   = 'a';
            //const char *l_value_str = json_object_get_string(l_value);
            char *l_val = DAP_NEW_Z_SIZE(char, l_group_store[j].value_len);
            //size_t l_dec_size = dap_enc_base64_decode(l_value_str, strlen(l_value_str), l_val, DAP_ENC_DATA_TYPE_B64);
            l_group_store[j].value  = (uint8_t*)l_val;
        }
        if (dap_chain_global_db_driver_appy(l_group_store, l_records_count)) {
            log_it(L_CRITICAL, "An error occured on importing group %s...", l_group_name);
        }
        //dap_store_obj_free(l_group_store, l_records_count);
    }
    json_object_put(l_json);
    return 0;
}
